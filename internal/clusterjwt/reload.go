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

// maxLogText is the longest unsigned text that a log line carries.
const maxLogText = 256

// errMarksWrite means the plugin could not save raised marks.
var errMarksWrite = errors.New("marks file not saved")

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

// Close stops the reload goroutine and its ticker.
func (p *Plugin) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		p.tickMu.Lock()
		defer p.tickMu.Unlock()
		if p.ticker != nil {
			p.ticker.Stop()
		}
	})
	return nil
}

// applyInterval puts the reload interval of a Configure into effect. The goroutine starts at the
// first positive interval. A later value resets the ticker, and 0s stops the polling.
func (p *Plugin) applyInterval(every time.Duration) {
	p.tickMu.Lock()
	defer p.tickMu.Unlock()
	select {
	case <-p.done:
		return
	default:
	}
	p.tickEvery.Store(int64(every))
	if p.tick == nil {
		switch {
		case p.ticker != nil && every == 0:
			p.ticker.Stop()
		case p.ticker != nil:
			p.ticker.Reset(every)
		case every > 0:
			p.ticker = time.NewTicker(every)
		}
	}
	if every == 0 || p.started {
		return
	}
	p.started = true
	tick := p.tick
	if tick == nil {
		tick = p.ticker.C
	}
	p.loops.Add(1)
	go p.loop(tick)
}

func (p *Plugin) loop(tick <-chan time.Time) {
	defer p.loops.Add(-1)
	for {
		select {
		case <-tick:
			if p.tickEvery.Load() > 0 {
				p.reload()
			}
		case <-p.stop:
			return
		case <-p.done:
			return
		}
	}
}

// clip shortens the string values of a log line, because they can carry text that no key signed.
func clip(kv []any) []any {
	out := make([]any, len(kv))
	for i, v := range kv {
		if s, ok := v.(string); ok && len(s) > maxLogText {
			v = strings.ToValidUTF8(s[:maxLogText], "") + "..."
		}
		out[i] = v
	}
	return out
}

func clipString(s string) string {
	return clip([]any{s})[0].(string)
}

// logLimited logs a fault that repeats on every tick, once for each window and reason.
func (p *Plugin) logLimited(level func(string, ...any), msg, reason string, kv ...any) {
	// The key holds only the message: the reason can carry text that changes on each attempt.
	_, ok, suppressed, _ := p.lim.Allow(msg)
	if !ok {
		return
	}
	kv = append(kv, "reason", reason)
	if suppressed > 0 {
		kv = append(kv, "suppressed", suppressed)
	}
	level(msg, clip(kv)...)
}

// reload loads the records again and swaps them into the state. A Configure that lands between the
// load and the swap wins, and the reload retries once from the state that Configure stored. A failure
// to read the directory, or to save raised marks, keeps the state.
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
			msg := "records_unreadable"
			if errors.Is(err, errMarksWrite) {
				msg = "marks_unwritable"
			}
			p.logLimited(p.log.Error, msg, err.Error())
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
	p.logLimited(p.log.Warn, "reload_superseded", "Configure replaced the state during two reloads")
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

// rawFile is one record file as read from disk, before any check.
type rawFile struct {
	name string
	data []byte
	err  error
}

// rawLoad is the content of one version of the records directory.
type rawLoad struct {
	specAbsent bool
	spec       []byte
	files      []rawFile
}

// readVersion reads the spec and every record file from one version of the directory. It holds no
// lock, so a path that blocks the read cannot block a Configure.
func (p *Plugin) readVersion(dir string) (*rawLoad, error) {
	dir, err := resolveDir(dir)
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
	raw := &rawLoad{}
	specPath := filepath.Join(dir, specFile)
	if _, err := os.Lstat(specPath); errors.Is(err, fs.ErrNotExist) {
		raw.specAbsent = true
	} else if raw.spec, err = readSmall(specPath); err != nil {
		return nil, fmt.Errorf("read %s: %w", specFile, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), recordSuffix) {
			continue
		}
		data, err := readSmall(filepath.Join(dir, e.Name()))
		raw.files = append(raw.files, rawFile{name: e.Name(), data: data, err: err})
	}
	return raw, nil
}

// load reads the spec and the record files of cfg.dir and returns the records that pass every check.
// base holds the records to keep when the spec cannot be used, or when a cell has no new record that
// is at least as new as its entry. When commit is set, load raises the marks of the plugin and saves
// them, and it never lowers them.
//
// An absent spec gives no record. A spec that does not verify, names another environment or sits
// below the spec mark leaves the records of base as they are. A record counts only when its spec
// entry has the same name, revision and digest, it is not below the mark of its cell, and it does not
// share a revision with another record or a retired mark. A cell that the spec indexes and that has no
// accepted record keeps its record from base only while that record is not below the entry. A cell
// that the spec no longer indexes drops out. An unreadable marks file gives no record.
func (p *Plugin) load(cfg, base *state, commit bool) (*snapshot, error) {
	raw, err := p.readVersion(cfg.dir)
	if err != nil {
		return nil, err
	}

	p.markMu.Lock()
	defer p.markMu.Unlock()
	seen := map[string]bool{}
	if commit {
		defer func() { p.noted = seen }()
	}
	// note logs a refusal once, until a load stops reporting it or its reason changes.
	note := func(level func(string, ...any), msg, file string, kv ...any) {
		reason := ""
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i] == "reason" {
				reason, _ = kv[i+1].(string)
			}
		}
		key := msg + "|" + file + "|" + clipString(reason)
		seen[key] = true
		if !commit || !p.noted[key] {
			level(msg, clip(append([]any{"file", file}, kv...))...)
		}
	}

	if commit && !p.ensureMarks(cfg, note) {
		return emptySnapshot(), nil
	}
	base = p.aboveMarks(base)
	if raw.specAbsent {
		note(p.log.Warn, "spec_absent", specFile)
		return emptySnapshot(), nil
	}
	sp, _, err := envspec.Verify(raw.spec, cfg.keys)
	switch {
	case err != nil:
		note(p.log.Error, "spec_invalid", specFile, "reason", err.Error())
		return keepOf(base), nil
	case sp.Env != cfg.env:
		note(p.log.Error, "spec_env_mismatch", specFile, "spec_env", sp.Env)
		return keepOf(base), nil
	case sp.Revision.Compare(p.specMark) < 0:
		note(p.log.Warn, "spec_older_ignored", specFile, "spec_epoch", sp.Revision.Epoch, "spec_counter", sp.Revision.Counter,
			"mark_epoch", p.specMark.Epoch, "mark_counter", p.specMark.Counter, "mark_source", p.markSource())
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
	for _, f := range raw.files {
		name := f.name
		if f.err != nil {
			reason := "unreadable"
			if errors.Is(f.err, errNotSmallFile) {
				reason = errNotSmallFile.Error()
			}
			note(p.log.Warn, "skipped record file", name, "reason", reason)
			continue
		}
		rec, payload, err := record.VerifyWithPayload(f.data, cfg.keys)
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
	for _, e := range sp.Cells {
		if _, ok := out.records[e.Name]; ok {
			continue
		}
		if base != nil {
			// The kept record must be the one that the entry names, or a newer one.
			cur, ok := base.records[e.Name]
			c := envspec.RecordRevision(cur).Compare(e.Revision)
			if ok && (c > 0 || (c == 0 && base.digests[e.Name] == e.RecordSHA256)) {
				out.records[e.Name], out.digests[e.Name] = cur, base.digests[e.Name]
				continue
			}
		}
		note(p.log.Warn, "record_missing", e.Name+recordSuffix, "cell", e.Name, "epoch", e.Revision.Epoch, "counter", e.Revision.Counter)
	}
	if commit {
		if err := p.saveMarks(cfg, marks, retired, sp.Revision); err != nil {
			narrowed, held := narrow(base, out)
			if narrowed == nil {
				return nil, err
			}
			p.logLimited(p.log.Error, "marks_unwritable", err.Error())
			if !held {
				// Nothing waits, so the process keeps the raised marks and refuses a replay. The file
				// stays behind until a save succeeds.
				p.marks, p.retired, p.specMark, p.marksDirty = marks, retired, sp.Revision, true
			}
			return narrowed, nil
		}
		p.marks, p.retired, p.specMark = marks, retired, sp.Revision
	}
	return out, nil
}

// markSource names where the spec mark comes from, for the log of a refused spec.
func (p *Plugin) markSource() string {
	if p.marksPath == "" {
		return "memory"
	}
	return "marks_file " + p.marksPath
}

// aboveMarks returns base without the records that the persisted marks refuse: a record below the mark
// of its cell, or at the mark of a retired cell. A Configure or reload that read its base before another
// load raised the marks would otherwise serve them again. The caller holds markMu.
func (p *Plugin) aboveMarks(base *state) *state {
	if base == nil {
		return nil
	}
	var drop []string
	for name, rec := range base.records {
		c := envspec.RecordRevision(rec).Compare(p.marks[name])
		if c < 0 || (c == 0 && p.retired[name]) {
			drop = append(drop, name)
		}
	}
	if len(drop) == 0 {
		return base
	}
	out := *base
	out.records, out.digests = maps.Clone(base.records), maps.Clone(base.digests)
	for _, name := range drop {
		delete(out.records, name)
		delete(out.digests, name)
	}
	return &out
}

// narrow keeps the part of a load that cannot admit anything new, for the case that the marks cannot
// be saved: a record that stays as it is, a revoked record, and a dropped cell. A cell whose new record
// would admit something keeps its record from base. held reports that such a cell exists. It returns
// nil when base is nil, because then the whole load admits.
func narrow(base *state, out *snapshot) (res *snapshot, held bool) {
	if base == nil {
		return nil, false
	}
	res = emptySnapshot()
	res.spec = out.spec
	for name, rec := range out.records {
		d := out.digests[name]
		if bd, ok := base.digests[name]; (ok && bd == d) || rec.Revoked {
			res.records[name], res.digests[name] = rec, d
			continue
		}
		held = true
		if b, ok := base.records[name]; ok {
			res.records[name], res.digests[name] = b, base.digests[name]
		}
	}
	return res, held
}
