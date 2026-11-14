package mgmt

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// reconcile applies the intent to the state. A bound cell that left the intent becomes a pending
// drop, and a cell whose subjects changed gets a new record in one revision.
func (p *Plane) reconcile(t *txn) error {
	var gone []string
	for _, name := range sortedKeys(t.st.Cells) {
		if _, ok := p.cellIn(t.st, name); !ok {
			gone = append(gone, name)
		}
	}
	if !slices.Equal(gone, t.st.PendingDrops) && (len(gone) > 0 || len(t.st.PendingDrops) > 0) {
		t.st.PendingDrops = gone
		t.dirty = true
	}
	if t.st.Served != 0 {
		return nil
	}
	if p.stepIndexStale(t) {
		if err := t.revise(); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(t.st.Cells) {
		ic, ok := p.cellIn(t.st, name)
		if !ok || slices.Equal(t.st.Cells[name].Subjects, sortedSubjects(ic.Subjects)) {
			continue
		}
		if err := t.revise(); err != nil {
			return err
		}
		if err := t.signCell(name); err != nil {
			return err
		}
	}
	return nil
}

// dropNext drops the first pending cell that is still out of the intent, in one revision. It runs
// only while the signed revision is the one that envd reported as applied, checked under the mutex,
// so two reports of one revision release one drop.
func (p *Plane) dropNext(applied spec.Revision) error {
	return p.commit(func(t *txn) error {
		if t.st.Last != applied || applied.Compare(t.st.DropRevision) < 0 {
			return nil
		}
		for len(t.st.PendingDrops) > 0 {
			name := t.st.PendingDrops[0]
			cs := t.st.Cells[name]
			if _, in := p.cellIn(t.st, name); in || cs == nil {
				t.st.PendingDrops = t.st.PendingDrops[1:]
				t.dirty = true
				continue
			}
			if err := t.revise(); err != nil {
				return err
			}
			t.st.PendingDrops = t.st.PendingDrops[1:]
			t.st.DropRevision = t.rev
			t.st.Retired[name] = cs.Record
			delete(t.st.Cells, name)
			delete(t.records, name)
			return nil
		}
		return nil
	})
}

// stepIndexStale reports whether the steps that the state holds differ from the steps that the
// newest signed spec indexes, for example after a cell left the catalog.
func (p *Plane) stepIndexStale(t *txn) bool {
	var have map[string]json.RawMessage
	if l := t.st.latest(); l != nil {
		have = l.Bundle.Steps
	}
	want := 0
	for name, r := range t.st.Requests {
		if _, in := p.cellIn(t.st, name); !in || !r.Step.open() {
			continue
		}
		want++
		if !bytes.Equal(have[name], r.Step.Envelope) {
			return true
		}
	}
	return want != len(have)
}
