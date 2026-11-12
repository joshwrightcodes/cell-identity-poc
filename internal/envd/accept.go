// Package envd pulls the signed spec and records of one environment from the management plane,
// verifies them, keeps them in a ConfigMap and reports its status.
package envd

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// MaxRecordBytes is the largest record envelope that Accept stores.
const MaxRecordBytes = 64 << 10

// MaxLoggedBytes bounds each string from an unverified source that Refused keeps for a log line.
const MaxLoggedBytes = 256

// clip cuts s to at most MaxLoggedBytes bytes of valid UTF-8.
func clip(s string) string {
	if len(s) <= MaxLoggedBytes {
		return s
	}
	return strings.ToValidUTF8(s[:MaxLoggedBytes], "")
}

// Code is the outward reason of every refusal.
const Code = mgmtapi.ReasonSpecInvalid

// Refused is the error of a bundle that envd does not accept. Reason is one of the detail reasons of
// package mgmtapi. Cell names the cell of a record failure, and Revision is the revision of the
// spec when the spec itself verified.
type Refused struct {
	Reason   string
	Cell     string
	Revision spec.Revision
	Detail   string
}

func (r *Refused) Error() string {
	s := Code + ": " + r.Reason
	if r.Cell != "" {
		s += " (cell " + r.Cell + ")"
	}
	if r.Detail != "" {
		s += ": " + r.Detail
	}
	return s
}

// State is what envd has accepted: the signed spec, one signed record for each cell in it, and the
// highest revision ever seen for each cell, from the cells and the retired list of every spec.
type State struct {
	Revision     spec.Revision
	SpecSHA256   string
	SpecEnvelope []byte
	Records      map[string][]byte
	Cells        map[string]record.Cell
	Marks        map[string]spec.Revision
}

// Empty returns the state of a first start.
func Empty() *State {
	return &State{
		Records: map[string][]byte{},
		Cells:   map[string]record.Cell{},
		Marks:   map[string]spec.Revision{},
	}
}

// Accept checks the bundle against cur and returns the state that follows from it. It returns cur
// and false when the bundle holds the spec that cur already has. A refusal is a *Refused. Accept
// never changes cur.
func Accept(cur *State, b mgmtapi.SpecBundle, env string, keys []ed25519.PublicKey) (*State, bool, error) {
	if cur == nil {
		cur = Empty()
	}
	s, payload, err := spec.Verify(b.Spec, keys)
	if err != nil {
		reason := mgmtapi.ReasonPayloadInvalid
		if errors.Is(err, record.ErrSignature) {
			reason = mgmtapi.ReasonSignatureInvalid
		}
		return nil, false, &Refused{Reason: reason, Detail: clip(err.Error())}
	}
	refuse := func(reason, cell, format string, args ...any) error {
		return &Refused{Reason: reason, Cell: clip(cell), Revision: s.Revision, Detail: clip(fmt.Sprintf(format, args...))}
	}
	if s.Env != env {
		return nil, false, refuse(mgmtapi.ReasonEnvMismatch, "", "spec env %q, want %q", s.Env, env)
	}
	digest := spec.RecordDigest(payload)
	switch s.Revision.Compare(cur.Revision) {
	case -1:
		return nil, false, refuse(mgmtapi.ReasonRevisionOld, "", "spec revision %v is below %v", s.Revision, cur.Revision)
	case 0:
		if digest == cur.SpecSHA256 {
			return cur, false, nil
		}
		return nil, false, refuse(mgmtapi.ReasonRevisionConflict, "", "another spec at revision %v", s.Revision)
	}

	retired := make(map[string]spec.Revision, len(s.Retired))
	for _, r := range s.Retired {
		retired[r.Name] = r.Revision
	}
	listed := make(map[string]bool, len(s.Cells))
	for _, e := range s.Cells {
		listed[e.Name] = true
	}
	for name, mark := range cur.Marks {
		if r, ok := retired[name]; ok {
			if r.Compare(mark) < 0 {
				return nil, false, refuse(mgmtapi.ReasonSpecInvalid, name, "retired mark %v is below the mark %v", r, mark)
			}
		} else if !listed[name] {
			return nil, false, refuse(mgmtapi.ReasonSpecInvalid, name, "cell has a mark %v and is in neither list", mark)
		}
	}

	cells := make(map[string]record.Cell, len(s.Cells))
	records := make(map[string][]byte, len(s.Cells))
	for _, e := range s.Cells {
		raw, ok := b.Records[e.Name]
		if !ok {
			return nil, false, refuse(mgmtapi.ReasonRecordInvalid, e.Name, "bundle has no record")
		}
		if len(raw) > MaxRecordBytes {
			return nil, false, refuse(mgmtapi.ReasonRecordInvalid, e.Name, "record envelope has %d bytes, the limit is %d", len(raw), MaxRecordBytes)
		}
		c, recPayload, err := record.VerifyWithPayload(raw, keys)
		if err != nil {
			return nil, false, refuse(mgmtapi.ReasonRecordInvalid, e.Name, "%v", err)
		}
		if err := s.CheckRecord(e.Name, c, recPayload); err != nil {
			return nil, false, refuse(mgmtapi.ReasonRecordInvalid, e.Name, "%v", err)
		}
		cells[e.Name] = c
		records[e.Name] = slices.Clone(raw)
	}
	for name := range b.Records {
		if _, ok := cells[name]; !ok {
			return nil, false, refuse(mgmtapi.ReasonRecordUnindexed, name, "bundle has a record that the spec does not index")
		}
	}

	for _, e := range s.Cells {
		mark, seen := cur.Marks[e.Name]
		if !seen {
			continue
		}
		switch e.Revision.Compare(mark) {
		case -1:
			return nil, false, refuse(mgmtapi.ReasonRecordOld, e.Name, "record revision %v is below its mark %v", e.Revision, mark)
		case 0:
			held, present := cur.Records[e.Name]
			if !present {
				return nil, false, refuse(mgmtapi.ReasonRecordOld, e.Name, "record revision %v equals the mark of a retired cell", e.Revision)
			}
			_, heldPayload, err := record.VerifyWithPayload(held, keys)
			if err != nil {
				return nil, false, fmt.Errorf("current state is inconsistent: record of cell %q: %w", e.Name, err)
			}
			if spec.RecordDigest(heldPayload) != e.RecordSHA256 {
				return nil, false, refuse(mgmtapi.ReasonRecordConflict, e.Name, "another record at revision %v", e.Revision)
			}
		}
	}

	invalidated := 0
	for name, old := range cur.Cells {
		if old.Revoked {
			continue
		}
		if now, ok := cells[name]; !ok || now.Revoked {
			invalidated++
		}
	}
	if invalidated > 1 {
		return nil, false, refuse(mgmtapi.ReasonTooManyInvalidated, "", "%d cells become invalid at once", invalidated)
	}

	marks := make(map[string]spec.Revision, len(cur.Marks)+len(s.Cells))
	for k, v := range cur.Marks {
		marks[k] = v
	}
	raise := func(name string, rev spec.Revision) {
		if rev.Compare(marks[name]) > 0 {
			marks[name] = rev
		}
	}
	for _, e := range s.Cells {
		raise(e.Name, e.Revision)
	}
	for _, r := range s.Retired {
		raise(r.Name, r.Revision)
	}
	return &State{
		Revision:     s.Revision,
		SpecSHA256:   digest,
		SpecEnvelope: slices.Clone(b.Spec),
		Records:      records,
		Cells:        cells,
		Marks:        marks,
	}, true, nil
}
