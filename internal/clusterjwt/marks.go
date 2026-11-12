package clusterjwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"

	envspec "github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// marksDoc is the content of the marks file.
type marksDoc struct {
	Spec    envspec.Revision            `json:"spec"`
	Cells   map[string]envspec.Revision `json:"cells"`
	Retired []string                    `json:"retired"`
}

func (d marksDoc) validate() error {
	if d.Spec.Epoch < 1 || d.Spec.Counter < 1 {
		return errors.New("spec mark needs an epoch and a counter of at least 1")
	}
	for name, rev := range d.Cells {
		if !envspec.ValidName(name) || rev.Epoch < 1 || rev.Counter < 1 {
			return fmt.Errorf("mark of cell %q is not valid", name)
		}
	}
	for _, name := range d.Retired {
		if _, ok := d.Cells[name]; !ok {
			return fmt.Errorf("retired cell %q has no mark", name)
		}
	}
	return nil
}

func readMarks(path string) (marksDoc, error) {
	f, err := os.Open(path)
	if err != nil {
		return marksDoc{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRecordFileLen+1))
	if err != nil {
		return marksDoc{}, err
	}
	if len(data) > maxRecordFileLen {
		return marksDoc{}, errors.New("marks file is too large")
	}
	var d marksDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return marksDoc{}, fmt.Errorf("decode marks: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return marksDoc{}, errors.New("decode marks: trailing data")
	}
	return d, d.validate()
}

// ensureMarks loads the marks file at the first call that has a path, before the first load serves
// anything. It reports false when the file exists and cannot be used, so the caller serves no record
// until an operator acts. An absent file is a first start. An empty path keeps the marks in memory.
// The caller holds markMu.
func (p *Plugin) ensureMarks(path string, note func(func(string, ...any), string, string, ...any)) bool {
	if p.marksReady {
		if path != p.marksPath {
			note(p.log.Warn, "marks_file_ignored", path, "reason", "the marks file is set by the first Configure")
		}
		return true
	}
	if path == "" {
		p.marksReady, p.marksPath = true, ""
		if !p.marksWarned {
			p.marksWarned = true
			p.log.Warn("marks_memory_only", "reason", "marks_file is empty, so a restart forgets the marks")
		}
		return true
	}
	doc, err := readMarks(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		p.marksReady, p.marksPath, p.marksDirty = true, path, true
		return true
	case err != nil:
		note(p.log.Error, "marks_unreadable", path, "reason", err.Error())
		return false
	}
	p.marksReady, p.marksPath = true, path
	p.specMark = doc.Spec
	p.marks = maps.Clone(doc.Cells)
	if p.marks == nil {
		p.marks = map[string]envspec.Revision{}
	}
	p.retired = map[string]bool{}
	for _, name := range doc.Retired {
		p.retired[name] = true
	}
	return true
}

// saveMarks writes the marks before the caller adopts them, so a state that serves attestation never
// has a mark that a restart could lose. The sequence is a temporary file with mode 0600, a sync, a
// rename and a sync of the directory. It writes only when a mark changed. The caller holds markMu.
func (p *Plugin) saveMarks(marks map[string]envspec.Revision, retired map[string]bool, spec envspec.Revision) error {
	if p.marksPath == "" {
		return nil
	}
	if !p.marksDirty && spec == p.specMark && maps.Equal(marks, p.marks) && maps.Equal(retired, p.retired) {
		return nil
	}
	doc := marksDoc{Spec: spec, Cells: marks, Retired: slices.Sorted(maps.Keys(retired))}
	if err := writeFileAtomic(p.marksPath, doc); err != nil {
		return fmt.Errorf("%w: %v", errMarksWrite, err)
	}
	p.marksDirty = false
	return nil
}

func writeFileAtomic(path string, doc marksDoc) (err error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".marks-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
