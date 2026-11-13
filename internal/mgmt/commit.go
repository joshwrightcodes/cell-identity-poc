package mgmt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// txn is one change under the mutex. It works on a clone of the current state.
type txn struct {
	p       *Plane
	st      *State
	now     time.Time
	key     ed25519.PrivateKey
	records map[string]json.RawMessage
	rev     spec.Revision
	revised bool
	reset   bool
	dirty   bool
	after   []func()
	onFail  []func()
}

func (p *Plane) commit(fn func(*txn) error) error {
	changed, err := p.commitTxn(fn)
	if err == nil && changed {
		p.notifyRecords()
	}
	return err
}

// notifyRecords hands the served records to Config.OnRecords. It reads the current snapshot, so a
// callback that runs late still publishes the newest records. It runs outside the commit mutex.
func (p *Plane) notifyRecords() {
	if p.cfg.OnRecords == nil || !p.ready.Load() {
		return
	}
	p.cbmu.Lock()
	defer p.cbmu.Unlock()
	cur := p.snap.Load()
	p.cfg.OnRecords(p.Records(), slices.Clone(cur.pub))
}

// sameRecords reports whether two bundles hold the same record envelopes.
func sameRecords(a, b *Signed) bool {
	var ra, rb map[string]json.RawMessage
	if a != nil {
		ra = a.Bundle.Records
	}
	if b != nil {
		rb = b.Bundle.Records
	}
	return maps.EqualFunc(ra, rb, func(x, y json.RawMessage) bool { return bytes.Equal(x, y) })
}

// commitTxn runs one change under the mutex. It reports whether the served records changed.
func (p *Plane) commitTxn(fn func(*txn) error) (changed bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.snap.Load()
	t := &txn{p: p, st: cur.st.clone(), now: p.cfg.Now(), key: p.key, records: map[string]json.RawMessage{}}
	defer func() {
		if err != nil {
			for _, f := range t.onFail {
				f()
			}
		}
	}()
	if l := cur.st.latest(); l != nil {
		maps.Copy(t.records, l.Bundle.Records)
	}
	if err = fn(t); err != nil {
		return false, err
	}
	switch {
	case t.revised:
		if err = t.seal(); err != nil {
			return false, err
		}
	case t.dirty:
	default:
		for _, f := range t.after {
			f()
		}
		return false, nil
	}
	t.st.Seq++
	if err = p.cfg.Store.Save(t.st); err != nil {
		return false, fmt.Errorf("save state: %w", err)
	}
	changed = !sameRecords(cur.st.served(), t.st.served()) || !bytes.Equal(cur.pub, t.key.Public().(ed25519.PublicKey))
	p.key = t.key
	p.snap.Store(&snapshot{st: t.st, pub: t.key.Public().(ed25519.PublicKey)})
	p.noteLag()
	for _, f := range t.after {
		f()
	}
	return changed, nil
}

// revise starts a new spec revision. It refuses while a restore is active, unless the change is a
// key rotation.
func (t *txn) revise() error {
	if t.revised {
		return nil
	}
	if t.st.Served != 0 && !t.reset {
		return refuse(mgmtapi.ReasonRestoreActive, "")
	}
	switch {
	case t.st.Last.Epoch == 0:
		t.rev = spec.Revision{Epoch: 1, Counter: 1}
	case t.reset:
		t.rev = spec.Revision{Epoch: t.st.Last.Epoch + 1, Counter: 1}
	default:
		t.rev = spec.Revision{Epoch: t.st.Last.Epoch, Counter: t.st.Last.Counter + 1}
	}
	t.revised = true
	return nil
}

// signCell signs the record of a bound cell at the new revision. Subjects come from the intent
// while the cell is in it.
func (t *txn) signCell(name string) error {
	cs := t.st.Cells[name]
	if cs == nil {
		return fmt.Errorf("cell %q is not bound", name)
	}
	if ic, ok := t.p.intent[name]; ok {
		cs.Subjects = sortedSubjects(ic.Subjects)
	}
	env, err := record.Sign(record.Cell{
		Name: name, Env: t.p.cfg.Intent.Env, Issuer: cs.Issuer, JWKS: cs.JWKS, Subjects: cs.Subjects,
		Epoch: t.rev.Epoch, Counter: t.rev.Counter,
	}, t.key)
	if err != nil {
		return err
	}
	if len(env) > maxRecordBytes {
		return refuse(mgmtapi.ReasonKeysUntrusted, "record_too_large")
	}
	t.records[name] = env
	cs.Record = t.rev
	return nil
}

// seal signs the spec, adds the bundle to the history and trims it.
func (t *txn) seal() error {
	pubs := []ed25519.PublicKey{t.key.Public().(ed25519.PublicKey)}
	s := spec.Spec{Env: t.p.cfg.Intent.Env, Revision: t.rev, Cells: []spec.Entry{}, Retired: []spec.Retired{}}
	records := make(map[string]json.RawMessage, len(t.st.Cells))
	total := 0
	for _, name := range sortedKeys(t.st.Cells) {
		raw, ok := t.records[name]
		if !ok {
			return fmt.Errorf("cell %q has no signed record", name)
		}
		c, payload, err := record.VerifyWithPayload(raw, pubs)
		if err != nil {
			return fmt.Errorf("record of %q: %w", name, err)
		}
		s.Cells = append(s.Cells, spec.Entry{Name: name, Revision: spec.RecordRevision(c), RecordSHA256: spec.RecordDigest(payload)})
		records[name] = raw
		if total += len(raw); total > maxBundleBytes {
			return refuse(mgmtapi.ReasonKeysUntrusted, "bundle_too_large")
		}
	}
	for _, name := range sortedKeys(t.st.Retired) {
		s.Retired = append(s.Retired, spec.Retired{Name: name, Revision: t.st.Retired[name]})
	}
	env, err := spec.Sign(s, t.key)
	if err != nil {
		return err
	}
	t.st.Last = t.rev
	if t.reset {
		t.st.History = nil
	}
	t.st.History = append(t.st.History, Signed{Revision: t.rev, Bundle: mgmtapi.SpecBundle{Spec: env, Records: records}})
	if n := len(t.st.History); n > t.p.cfg.HistoryLen {
		t.st.History = slices.Clone(t.st.History[n-t.p.cfg.HistoryLen:])
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resignAll re-signs every record and the spec at the first revision of the next epoch.
func (p *Plane) resignAll(fp string) func(*txn) error {
	return func(t *txn) error {
		t.reset = true
		t.st.Served = 0
		t.st.KeySHA256 = fp
		if err := t.revise(); err != nil {
			return err
		}
		for _, name := range sortedKeys(t.st.Cells) {
			if err := t.signCell(name); err != nil {
				return err
			}
		}
		return t.resignOps()
	}
}

func (t *txn) expectSeq(expect *uint64) error {
	if expect != nil && t.st.Seq != *expect {
		return refuse(mgmtapi.ReasonConflict, fmt.Sprintf("state version is %d, not %d", t.st.Seq, *expect))
	}
	return nil
}
