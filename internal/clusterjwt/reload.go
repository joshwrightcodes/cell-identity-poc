package clusterjwt

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	envspec "github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// specFile is the key of the signed spec in the records directory.
const specFile = "spec-envelope.json"

// snapshot is the record set that one load accepted.
type snapshot struct {
	records map[string]record.Cell
	digests map[string]string
	spec    envspec.Revision
}

func emptySnapshot() *snapshot {
	return &snapshot{records: map[string]record.Cell{}, digests: map[string]string{}}
}

// keepOf returns the snapshot that holds the records of base, or no record when base is nil.
func keepOf(base *state) *snapshot {
	s := emptySnapshot()
	if base != nil {
		s.records, s.digests = maps.Clone(base.records), maps.Clone(base.digests)
	}
	return s
}

// startReload starts the reload goroutine on the first call with a positive interval.
func (p *Plugin) startReload(every time.Duration) {
	if every <= 0 || !p.started.CompareAndSwap(false, true) {
		return
	}
	tick := p.tick
	if tick == nil {
		tick = time.NewTicker(every).C
	}
	stop := p.stop
	go func() {
		for {
			select {
			case <-tick:
				p.reload()
			case <-stop:
				return
			}
		}
	}()
}

// reload loads the records again and swaps them into the state. A Configure that lands between the
// load and the swap wins, and the reload retries once from the state that Configure stored. A failure
// to read the directory keeps the state.
func (p *Plugin) reload() {
	if p.afterReload != nil {
		defer p.afterReload()
	}
	for attempt := 0; attempt < 2; attempt++ {
		cur := p.st.Load()
		if cur == nil {
			return
		}
		snap, err := p.load(cur, cur, true)
		if err != nil {
			p.log.Error("records_unreadable", "reason", err.Error())
			return
		}
		if p.afterLoad != nil {
			p.afterLoad()
		}
		if maps.Equal(snap.digests, cur.digests) {
			return
		}
		next := *cur
		next.records, next.digests = snap.records, snap.digests
		if p.st.CompareAndSwap(cur, &next) {
			p.logReloaded(cur, snap)
			return
		}
	}
	p.log.Warn("reload_superseded", "reason", "Configure replaced the state during two reloads")
}

func (p *Plugin) logReloaded(old *state, snap *snapshot) {
	var added, changed, dropped int
	for name, d := range snap.digests {
		switch od, ok := old.digests[name]; {
		case !ok:
			added++
		case od != d:
			changed++
		}
	}
	for name := range old.digests {
		if _, ok := snap.digests[name]; !ok {
			dropped++
		}
	}
	cells := slices.Sorted(maps.Keys(snap.digests))
	p.log.Info("records reloaded", "spec_epoch", snap.spec.Epoch, "spec_counter", snap.spec.Counter,
		"records", len(snap.records), "added", added, "changed", changed, "dropped", dropped, "cells", cells)
}

// resolveDir returns the directory that one load reads. A ConfigMap volume holds a ..data link to the
// current version, so the load resolves that link once and reads every file from the version it names.
func resolveDir(dir string) (string, error) {
	data := filepath.Join(dir, "..data")
	switch _, err := os.Lstat(data); {
	case err == nil:
		return filepath.EvalSymlinks(data)
	case errors.Is(err, fs.ErrNotExist):
		return dir, nil
	default:
		return "", err
	}
}

// errNotSmallFile means a path is not a regular file of acceptable size, or a link to one that
// does not resolve. Reading such a path could block or cost memory, so the load never opens it.
var errNotSmallFile = errors.New("not a regular file of acceptable size")

// readSmall reads a regular file of acceptable size. A link is followed.
func readSmall(path string) ([]byte, error) {
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() || fi.Size() > maxRecordFileLen {
		return nil, errNotSmallFile
	}
	return os.ReadFile(path)
}

// load reads the spec and the record files of cfg.dir and returns the records that pass every check.
// base holds the records to keep when a file or the spec cannot be used. When commit is set, load
// raises the marks of the plugin, and it never lowers them.
//
// An absent spec gives no record. A spec that does not verify, names another environment or sits
// below the spec mark leaves the records of base as they are. A record counts only when its spec
// entry has the same name, revision and digest, it is not below the mark of its cell, and it does not
// share a revision with another record or a retired mark. An indexed cell without an accepted record
// keeps the record of base, and a cell that the spec no longer indexes drops out.
func (p *Plugin) load(cfg, base *state, commit bool) (*snapshot, error) {
	dir, err := resolveDir(cfg.dir)
	if err != nil {
		return nil, fmt.Errorf("read records_dir: %w", err)
	}
	if p.afterResolve != nil {
		p.afterResolve()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read records_dir: %w", err)
	}

	p.markMu.Lock()
	defer p.markMu.Unlock()
	seen := map[string]bool{}
	if commit {
		defer func() { p.noted = seen }()
	}
	// note logs a refusal once, until a load stops reporting it.
	note := func(level func(string, ...any), msg, file string, kv ...any) {
		key := msg + "|" + file
		seen[key] = true
		if !commit || !p.noted[key] {
			level(msg, append([]any{"file", file}, kv...)...)
		}
	}

	specPath := filepath.Join(dir, specFile)
	if _, err := os.Lstat(specPath); errors.Is(err, fs.ErrNotExist) {
		note(p.log.Warn, "spec_absent", specFile)
		return emptySnapshot(), nil
	}
	raw, err := readSmall(specPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", specFile, err)
	}
	sp, _, err := envspec.Verify(raw, cfg.keys)
	switch {
	case err != nil:
		note(p.log.Error, "spec_invalid", specFile, "reason", err.Error())
		return keepOf(base), nil
	case sp.Env != cfg.env:
		note(p.log.Error, "spec_env_mismatch", specFile, "spec_env", sp.Env)
		return keepOf(base), nil
	case sp.Revision.Compare(p.specMark) < 0:
		note(p.log.Warn, "spec_older_ignored", specFile, "spec_epoch", sp.Revision.Epoch, "spec_counter", sp.Revision.Counter,
			"mark_epoch", p.specMark.Epoch, "mark_counter", p.specMark.Counter)
		return keepOf(base), nil
	}

	marks, retired := maps.Clone(p.marks), maps.Clone(p.retired)
	if marks == nil {
		marks, retired = map[string]envspec.Revision{}, map[string]bool{}
	}
	for _, e := range sp.Cells {
		if e.Revision.Compare(marks[e.Name]) > 0 {
			marks[e.Name] = e.Revision
			delete(retired, e.Name)
		}
	}
	for _, r := range sp.Retired {
		if r.Revision.Compare(marks[r.Name]) >= 0 {
			marks[r.Name] = r.Revision
			retired[r.Name] = true
		}
	}

	out := emptySnapshot()
	out.spec = sp.Revision
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, recordSuffix) {
			continue
		}
		data, err := readSmall(filepath.Join(dir, name))
		if err != nil {
			reason := "unreadable"
			if errors.Is(err, errNotSmallFile) {
				reason = errNotSmallFile.Error()
			}
			note(p.log.Warn, "skipped record file", name, "reason", reason)
			continue
		}
		rec, payload, err := record.VerifyWithPayload(data, cfg.keys)
		switch {
		case err != nil:
			note(p.log.Error, "record file failed verification", name, "file_cell", strings.TrimSuffix(name, recordSuffix), "reason", err.Error())
			continue
		case rec.Env != cfg.env:
			note(p.log.Warn, "skipped record file", name, "reason", "other environment", "record_env", rec.Env)
			continue
		case !cellNameRE.MatchString(rec.Name):
			note(p.log.Warn, "skipped record file", name, "reason", "cell name is not a DNS label")
			continue
		}
		if err := sp.CheckRecord(rec.Name, rec, payload); err != nil {
			msg := "record_mismatch"
			if errors.Is(err, envspec.ErrUnindexed) {
				msg = "record_unindexed"
			}
			note(p.log.Warn, msg, name, "cell", rec.Name, "reason", err.Error())
			continue
		}
		rev, digest := envspec.RecordRevision(rec), envspec.RecordDigest(payload)
		mark := marks[rec.Name]
		switch c := rev.Compare(mark); {
		case c < 0:
			note(p.log.Warn, "record_older_ignored", name, "cell", rec.Name, "epoch", rev.Epoch, "counter", rev.Counter,
				"mark_epoch", mark.Epoch, "mark_counter", mark.Counter)
			continue
		case c == 0 && retired[rec.Name]:
			note(p.log.Warn, "record_retired", name, "cell", rec.Name, "epoch", rev.Epoch, "counter", rev.Counter)
			continue
		}
		if base != nil {
			if cur, ok := base.records[rec.Name]; ok && envspec.RecordRevision(cur) == rev && base.digests[rec.Name] != digest {
				note(p.log.Error, "record_conflict", name, "cell", rec.Name, "epoch", rev.Epoch, "counter", rev.Counter)
				continue
			}
		}
		out.records[rec.Name], out.digests[rec.Name] = rec, digest
	}
	if base != nil {
		for _, e := range sp.Cells {
			if _, ok := out.records[e.Name]; ok {
				continue
			}
			if cur, ok := base.records[e.Name]; ok {
				out.records[e.Name], out.digests[e.Name] = cur, base.digests[e.Name]
			}
		}
	}
	if commit {
		p.marks, p.retired, p.specMark = marks, retired, sp.Revision
	}
	return out, nil
}
