package bundle

import (
	"bytes"
	"errors"
	"fmt"

	"sigs.k8s.io/yaml"
)

// ErrNotCanonical means that manifests are not in the canonical form.
var ErrNotCanonical = errors.New("manifests are not in the canonical form")

var docSeparator = []byte("---\n")

// Canonical writes objects in the one form that the applier accepts. Each object is the sorted
// block-style YAML of sigs.k8s.io/yaml.Marshal, and the objects are joined by a line of three
// dashes, with no separator before the first object. The form is plain UTF-8 with no comment,
// byte order mark, carriage return, anchor, tag or flow-style document, so every YAML and JSON
// reader sees the same objects. A publisher canonicalises the render before it packs and signs it.
func Canonical(objs []map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	for i, o := range objs {
		b, err := yaml.Marshal(o)
		if err != nil {
			return nil, fmt.Errorf("encode object %d: %w", i, err)
		}
		if i > 0 {
			buf.Write(docSeparator)
		}
		buf.Write(b)
	}
	return buf.Bytes(), nil
}

// CheckCanonical returns an error that wraps ErrNotCanonical unless body is the output of Canonical.
func CheckCanonical(body []byte) error {
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return fmt.Errorf("%w: no final line break", ErrNotCanonical)
	}
	var objs []map[string]any
	var chunk []byte
	flush := func() error {
		var m map[string]any
		if err := yaml.Unmarshal(chunk, &m); err != nil || m == nil {
			return fmt.Errorf("%w: a document is not an object", ErrNotCanonical)
		}
		objs = append(objs, m)
		chunk = nil
		return nil
	}
	for _, line := range bytes.SplitAfter(body, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if bytes.Equal(line, docSeparator) {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		chunk = append(chunk, line...)
	}
	if err := flush(); err != nil {
		return err
	}
	want, err := Canonical(objs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotCanonical, err)
	}
	if !bytes.Equal(want, body) {
		return fmt.Errorf("%w: the bytes differ from their canonical encoding", ErrNotCanonical)
	}
	return nil
}
