package envd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const testEnv = "dev"

func rev(e, c uint64) spec.Revision { return spec.Revision{Epoch: e, Counter: c} }

// fx signs the specs and records of one test.
type fx struct {
	t    *testing.T
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	jwks json.RawMessage
}

func newFx(t *testing.T) *fx {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cellPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := jose.JSONWebKey{Key: cellPub, KeyID: "k1", Algorithm: "EdDSA", Use: "sig"}
	raw, err := k.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []json.RawMessage{raw}})
	return &fx{t: t, priv: priv, pub: pub, jwks: jwks}
}

func (f *fx) keys() []ed25519.PublicKey { return []ed25519.PublicKey{f.pub} }

func (f *fx) cell(name string, r spec.Revision, revoked bool) record.Cell {
	return record.Cell{
		Name: name, Env: testEnv, Issuer: "https://" + name + ".example", JWKS: f.jwks,
		Subjects: []record.Subject{{Namespace: "ns", ServiceAccount: "sa"}},
		Revoked:  revoked, Epoch: r.Epoch, Counter: r.Counter,
	}
}

// item is one cell of a bundle: the signed record and the entry that indexes it.
type item struct {
	name  string
	env   []byte
	entry spec.Entry
}

func (f *fx) item(c record.Cell) item {
	f.t.Helper()
	env, err := record.Sign(c, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	_, payload, err := record.VerifyWithPayload(env, f.keys())
	if err != nil {
		f.t.Fatal(err)
	}
	return item{name: c.Name, env: env, entry: spec.Entry{Name: c.Name, Revision: spec.RecordRevision(c), RecordSHA256: spec.RecordDigest(payload)}}
}

func (f *fx) signSpec(env string, r spec.Revision, items []item, retired []spec.Retired) []byte {
	f.t.Helper()
	s := spec.Spec{Env: env, Revision: r, Retired: retired}
	slices.SortFunc(items, func(a, b item) int { return compareStr(a.entry.Name, b.entry.Name) })
	for _, it := range items {
		s.Cells = append(s.Cells, it.entry)
	}
	raw, err := spec.Sign(s, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func compareStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (f *fx) bundle(r spec.Revision, items []item, retired []spec.Retired) mgmtapi.SpecBundle {
	f.t.Helper()
	b := mgmtapi.SpecBundle{Spec: f.signSpec(testEnv, r, items, retired), Records: map[string]json.RawMessage{}}
	for _, it := range items {
		b.Records[it.name] = it.env
	}
	return b
}

// base is the current state of most tests: spec (1,5) with cells a, b, c and retired cell r at (1,3).
func (f *fx) base() (*State, []item) {
	f.t.Helper()
	items := []item{
		f.item(f.cell("a", rev(1, 2), false)),
		f.item(f.cell("b", rev(1, 3), false)),
		f.item(f.cell("c", rev(1, 4), false)),
	}
	st, changed, err := Accept(Empty(), f.bundle(rev(1, 5), items, []spec.Retired{{Name: "r", Revision: rev(1, 3)}}), testEnv, f.keys())
	if err != nil || !changed {
		f.t.Fatalf("base: changed=%v err=%v", changed, err)
	}
	return st, items
}

func cloneState(s *State) *State {
	c := &State{Revision: s.Revision, SpecSHA256: s.SpecSHA256, SpecEnvelope: slices.Clone(s.SpecEnvelope),
		Records: map[string][]byte{}, Cells: map[string]record.Cell{}, Marks: map[string]spec.Revision{}}
	for k, v := range s.Records {
		c.Records[k] = slices.Clone(v)
	}
	for k, v := range s.Cells {
		v.JWKS = slices.Clone(v.JWKS)
		v.Subjects = slices.Clone(v.Subjects)
		c.Cells[k] = v
	}
	for k, v := range s.Marks {
		c.Marks[k] = v
	}
	return c
}

func TestAcceptFirstSpec(t *testing.T) {
	f := newFx(t)
	items := []item{f.item(f.cell("a", rev(1, 1), false)), f.item(f.cell("b", rev(1, 2), true))}
	b := f.bundle(rev(1, 3), items, []spec.Retired{{Name: "r", Revision: rev(1, 2)}})
	st, changed, err := Accept(Empty(), b, testEnv, f.keys())
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if st.Revision != rev(1, 3) {
		t.Errorf("revision %v", st.Revision)
	}
	_, payload, _ := spec.Verify(b.Spec, f.keys())
	if st.SpecSHA256 != spec.RecordDigest(payload) {
		t.Errorf("spec digest %q", st.SpecSHA256)
	}
	if string(st.SpecEnvelope) != string(b.Spec) {
		t.Error("spec envelope differs")
	}
	if len(st.Records) != 2 || string(st.Records["a"]) != string(items[0].env) {
		t.Errorf("records %v", st.Records)
	}
	if len(st.Cells) != 2 || st.Cells["b"].Revoked != true {
		t.Errorf("cells %v", st.Cells)
	}
	wantMarks := map[string]spec.Revision{"a": rev(1, 1), "b": rev(1, 2), "r": rev(1, 2)}
	if !reflect.DeepEqual(st.Marks, wantMarks) {
		t.Errorf("marks %v, want %v", st.Marks, wantMarks)
	}
}

func TestAcceptUnchangedIsNoop(t *testing.T) {
	f := newFx(t)
	items := []item{f.item(f.cell("a", rev(1, 1), false))}
	b := f.bundle(rev(1, 2), items, nil)
	cur, _, err := Accept(Empty(), b, testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	before := cloneState(cur)
	next, changed, err := Accept(cur, b, testEnv, f.keys())
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !reflect.DeepEqual(next, before) || !reflect.DeepEqual(cur, before) {
		t.Fatal("state changed")
	}
}

// strip removes the signatures of an envelope.
func strip(t *testing.T, env []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	m["signatures"] = []any{}
	out, _ := json.Marshal(m)
	return out
}

// tamper changes the signed payload of an envelope and keeps its signature.
func tamper(t *testing.T, env []byte, edit func(payload []byte) []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	p, err := base64.StdEncoding.DecodeString(m["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	m["payload"] = base64.StdEncoding.EncodeToString(edit(p))
	out, _ := json.Marshal(m)
	return out
}

func TestAcceptRefuses(t *testing.T) {
	f := newFx(t)
	other := newFx(t)
	cur, items := f.base()
	next := rev(1, 6)
	same := func() []item { return slices.Clone(items) }
	with := func(name string, it item) []item {
		out := []item{}
		for _, x := range same() {
			if x.name != name {
				out = append(out, x)
			}
		}
		return append(out, it)
	}
	without := func(names ...string) []item {
		out := []item{}
		for _, x := range same() {
			if !slices.Contains(names, x.name) {
				out = append(out, x)
			}
		}
		return out
	}
	retiredBase := []spec.Retired{{Name: "r", Revision: rev(1, 3)}}

	cases := []struct {
		name   string
		reason string
		bundle func() mgmtapi.SpecBundle
	}{
		{"unsigned", mgmtapi.ReasonSignatureInvalid, func() mgmtapi.SpecBundle {
			b := f.bundle(next, same(), retiredBase)
			b.Spec = strip(t, b.Spec)
			return b
		}},
		{"tampered", mgmtapi.ReasonSignatureInvalid, func() mgmtapi.SpecBundle {
			b := f.bundle(next, same(), retiredBase)
			b.Spec = tamper(t, b.Spec, func(p []byte) []byte { return slices.Concat([]byte(" "), p) })
			return b
		}},
		{"foreign_key", mgmtapi.ReasonSignatureInvalid, func() mgmtapi.SpecBundle {
			b := f.bundle(next, same(), retiredBase)
			b.Spec = other.signSpec(testEnv, next, same(), retiredBase)
			return b
		}},
		{"record_as_spec", mgmtapi.ReasonPayloadInvalid, func() mgmtapi.SpecBundle {
			b := f.bundle(next, same(), retiredBase)
			b.Spec = items[0].env
			return b
		}},
		{"other_env", mgmtapi.ReasonEnvMismatch, func() mgmtapi.SpecBundle {
			b := f.bundle(next, same(), retiredBase)
			b.Spec = f.signSpec("prod", next, same(), retiredBase)
			return b
		}},
		{"revision_old", mgmtapi.ReasonRevisionOld, func() mgmtapi.SpecBundle {
			return f.bundle(rev(1, 4), same(), retiredBase)
		}},
		{"revision_conflict", mgmtapi.ReasonRevisionConflict, func() mgmtapi.SpecBundle {
			return f.bundle(rev(1, 5), same(), []spec.Retired{{Name: "r", Revision: rev(1, 4)}})
		}},
		{"record_missing", mgmtapi.ReasonRecordInvalid, func() mgmtapi.SpecBundle {
			b := f.bundle(next, same(), retiredBase)
			delete(b.Records, "a")
			return b
		}},
		{"record_digest", mgmtapi.ReasonRecordInvalid, func() mgmtapi.SpecBundle {
			it := items[0]
			it.entry.RecordSHA256 = items[1].entry.RecordSHA256
			return f.bundle(next, with("a", it), retiredBase)
		}},
		{"record_name", mgmtapi.ReasonRecordInvalid, func() mgmtapi.SpecBundle {
			it := f.item(f.cell("z", rev(1, 2), false))
			it.name, it.entry.Name = "a", "a"
			return f.bundle(next, with("a", it), retiredBase)
		}},
		{"record_env", mgmtapi.ReasonRecordInvalid, func() mgmtapi.SpecBundle {
			c := f.cell("a", rev(1, 2), false)
			c.Env = "prod"
			return f.bundle(next, with("a", f.item(c)), retiredBase)
		}},
		{"record_revision", mgmtapi.ReasonRecordInvalid, func() mgmtapi.SpecBundle {
			it := f.item(f.cell("a", rev(1, 5), false))
			it.entry.Revision = rev(1, 6)
			return f.bundle(next, with("a", it), retiredBase)
		}},
		{"record_extra", mgmtapi.ReasonRecordUnindexed, func() mgmtapi.SpecBundle {
			b := f.bundle(next, same(), retiredBase)
			b.Records["zzz"] = f.item(f.cell("zzz", rev(1, 6), false)).env
			return b
		}},
		{"record_old", mgmtapi.ReasonRecordOld, func() mgmtapi.SpecBundle {
			return f.bundle(next, with("a", f.item(f.cell("a", rev(1, 1), false))), retiredBase)
		}},
		{"record_old_after_retire", mgmtapi.ReasonRecordOld, func() mgmtapi.SpecBundle {
			return f.bundle(next, append(same(), f.item(f.cell("r", rev(1, 2), false))), nil)
		}},
		{"record_equal_retired_mark", mgmtapi.ReasonRecordOld, func() mgmtapi.SpecBundle {
			return f.bundle(next, append(same(), f.item(f.cell("r", rev(1, 3), false))), nil)
		}},
		{"record_conflict", mgmtapi.ReasonRecordConflict, func() mgmtapi.SpecBundle {
			c := f.cell("a", rev(1, 2), false)
			c.Issuer = "https://elsewhere.example"
			return f.bundle(next, with("a", f.item(c)), retiredBase)
		}},
		{"too_many_invalidated_revoked", mgmtapi.ReasonTooManyInvalidated, func() mgmtapi.SpecBundle {
			its := with("a", f.item(f.cell("a", next, true)))
			for i := range its {
				if its[i].name == "b" {
					its[i] = f.item(f.cell("b", next, true))
				}
			}
			return f.bundle(next, its, retiredBase)
		}},
		{"too_many_invalidated_dropped", mgmtapi.ReasonTooManyInvalidated, func() mgmtapi.SpecBundle {
			return f.bundle(next, without("a", "b"), []spec.Retired{{Name: "a", Revision: rev(1, 2)}, {Name: "b", Revision: rev(1, 3)}, {Name: "r", Revision: rev(1, 3)}})
		}},
		{"too_many_invalidated_mixed", mgmtapi.ReasonTooManyInvalidated, func() mgmtapi.SpecBundle {
			its := with("a", f.item(f.cell("a", next, true)))
			its = slices.DeleteFunc(its, func(x item) bool { return x.name == "b" })
			return f.bundle(next, its, []spec.Retired{{Name: "b", Revision: rev(1, 3)}, {Name: "r", Revision: rev(1, 3)}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := cloneState(cur)
			got, changed, err := Accept(cur, tc.bundle(), testEnv, f.keys())
			var r *Refused
			if !errors.As(err, &r) {
				t.Fatalf("err = %v, want a refusal", err)
			}
			if r.Reason != tc.reason {
				t.Errorf("reason %q, want %q (%v)", r.Reason, tc.reason, err)
			}
			if got != nil || changed {
				t.Errorf("got state %v, changed %v", got, changed)
			}
			if !reflect.DeepEqual(cur, before) {
				t.Error("Accept changed cur")
			}
		})
	}

	t.Run("one_revoked", func(t *testing.T) {
		before := cloneState(cur)
		st, changed, err := Accept(cur, f.bundle(next, with("a", f.item(f.cell("a", next, true))), retiredBase), testEnv, f.keys())
		if err != nil || !changed || !st.Cells["a"].Revoked || st.Revision != next {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if !reflect.DeepEqual(cur, before) {
			t.Error("Accept changed cur")
		}
	})
	t.Run("readd_above_mark", func(t *testing.T) {
		st, changed, err := Accept(cur, f.bundle(next, append(same(), f.item(f.cell("r", next, false))), nil), testEnv, f.keys())
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if st.Marks["r"] != next || len(st.Cells) != 4 {
			t.Errorf("marks %v cells %d", st.Marks, len(st.Cells))
		}
	})
}
