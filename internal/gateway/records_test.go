package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

func rev(e, c uint64) spec.Revision { return spec.Revision{Epoch: e, Counter: c} }

// signer signs specs and records under one key.
type signer struct {
	t    *testing.T
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	jwks json.RawMessage
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cellPub, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, err := (jose.JSONWebKey{Key: cellPub, KeyID: "k1", Algorithm: "EdDSA", Use: "sig"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []json.RawMessage{raw}})
	return &signer{t: t, priv: priv, pub: pub, jwks: jwks}
}

func (g *signer) keys() []ed25519.PublicKey { return []ed25519.PublicKey{g.pub} }

type bundle struct {
	spec    []byte
	records map[string]json.RawMessage
}

// bundle signs one record per name at rev r, a spec at revision sr, and the retired list.
func (g *signer) bundle(sr spec.Revision, cells map[string]spec.Revision, retired ...spec.Retired) bundle {
	g.t.Helper()
	b := bundle{records: map[string]json.RawMessage{}}
	sp := spec.Spec{Env: "dev", Revision: sr, Retired: retired}
	for _, name := range []string{"dev-cell-1", "dev-cell-2", "dev-cell-3"} {
		r, ok := cells[name]
		if !ok {
			continue
		}
		c := record.Cell{Name: name, Env: "dev", Issuer: "https://" + name + ".example", JWKS: g.jwks,
			Subjects: []record.Subject{{Namespace: "ns", ServiceAccount: "sa"}}, Epoch: r.Epoch, Counter: r.Counter}
		env, err := record.Sign(c, g.priv)
		if err != nil {
			g.t.Fatal(err)
		}
		_, payload, err := record.VerifyWithPayload(env, g.keys())
		if err != nil {
			g.t.Fatal(err)
		}
		b.records[name] = env
		sp.Cells = append(sp.Cells, spec.Entry{Name: name, Revision: r, RecordSHA256: spec.RecordDigest(payload)})
	}
	env, err := spec.Sign(sp, g.priv)
	if err != nil {
		g.t.Fatal(err)
	}
	b.spec = env
	return b
}

func (f *fixture) apply(g *signer, b bundle) error {
	return f.s.ApplySync(context.Background(), b.spec, b.records, g.keys())
}

func TestRecordsMarksNeverDrop(t *testing.T) {
	f := newFixture(t)
	g := newSigner(t)
	ctx := context.Background()
	if err := f.apply(g, g.bundle(rev(1, 5), map[string]spec.Revision{"dev-cell-1": rev(1, 3), "dev-cell-2": rev(1, 5)})); err != nil {
		t.Fatal(err)
	}
	c, ok := f.s.Cell(ctx, "dev-cell-1")
	if !ok || c.Name != "dev-cell-1" || c.Counter != 3 {
		t.Fatalf("cell %+v, %v", c, ok)
	}
	// Cell 2 retires at its mark; its record leaves the store, its mark stays.
	if err := f.apply(g, g.bundle(rev(1, 6), map[string]spec.Revision{"dev-cell-1": rev(1, 6)}, spec.Retired{Name: "dev-cell-2", Revision: rev(1, 5)})); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.s.Cell(ctx, "dev-cell-2"); ok {
		t.Fatal("a retired cell still has a record")
	}
	// A cell comes back below its mark: refused, and the store keeps its state.
	err := f.apply(g, g.bundle(rev(1, 7), map[string]spec.Revision{"dev-cell-1": rev(1, 6), "dev-cell-2": rev(1, 4)}))
	if !errors.Is(err, ErrRecordOld) {
		t.Fatalf("record below its mark: %v", err)
	}
	// The same revision as the mark, with no record held, is refused too.
	if err := f.apply(g, g.bundle(rev(1, 7), map[string]spec.Revision{"dev-cell-1": rev(1, 6), "dev-cell-2": rev(1, 5)})); !errors.Is(err, ErrRecordOld) {
		t.Fatalf("record at the mark of a retired cell: %v", err)
	}
	// An older spec is refused, and another spec at the same revision too.
	if err := f.apply(g, g.bundle(rev(1, 5), map[string]spec.Revision{"dev-cell-1": rev(1, 3)})); !errors.Is(err, ErrSpecOld) {
		t.Fatalf("older spec: %v", err)
	}
	if err := f.apply(g, g.bundle(rev(1, 6), map[string]spec.Revision{"dev-cell-1": rev(1, 5)})); !errors.Is(err, ErrSpecConflict) {
		t.Fatalf("same spec revision, other content: %v", err)
	}
	st, _ := f.s.Stats(ctx)
	if st.RecordOld != 2 || st.Records["dev-cell-1"] != rev(1, 6) || len(st.Records) != 1 || !st.RecordOldAt.Equal(t0) {
		t.Fatalf("stats %+v", st)
	}
	f.reopen()
	err = f.apply(g, g.bundle(rev(1, 8), map[string]spec.Revision{"dev-cell-1": rev(1, 2)}))
	if !errors.Is(err, ErrRecordOld) {
		t.Fatalf("marks after reopen: %v", err)
	}
	// Another record at the held revision is a conflict.
	f2 := newSigner(t)
	f2.pub, f2.priv = g.pub, g.priv
	b := g.bundle(rev(1, 8), map[string]spec.Revision{"dev-cell-1": rev(1, 6)})
	if err := f.apply(g, b); err != nil {
		t.Fatalf("the same revision and digest again: %v", err)
	}
	other := f2.bundle(rev(1, 9), map[string]spec.Revision{"dev-cell-1": rev(1, 6)})
	if err := f.apply(g, other); !errors.Is(err, ErrRecordConflict) {
		t.Fatalf("another record at the mark: %v", err)
	}
}

func TestRecordsRequireIndex(t *testing.T) {
	f := newFixture(t)
	g := newSigner(t)
	ctx := context.Background()
	b := g.bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-1": rev(1, 2)})
	extra := g.bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-1": rev(1, 2), "dev-cell-3": rev(1, 1)})
	// A record that the spec does not index.
	b.records["dev-cell-3"] = extra.records["dev-cell-3"]
	if err := f.apply(g, b); !errors.Is(err, ErrRecordUnindexed) {
		t.Fatalf("unindexed record: %v", err)
	}
	// A record at another revision than its entry.
	b = g.bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-1": rev(1, 2)})
	b.records["dev-cell-1"] = g.bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-1": rev(1, 1)}).records["dev-cell-1"]
	if err := f.apply(g, b); !errors.Is(err, spec.ErrMismatch) {
		t.Fatalf("record that differs from its entry: %v", err)
	}
	// A missing record, a record under the wrong name and a record signed by another key.
	missing := g.bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-1": rev(1, 2)})
	delete(missing.records, "dev-cell-1")
	if err := f.apply(g, missing); !errors.Is(err, ErrRecordMissing) {
		t.Fatalf("missing record: %v", err)
	}
	renamed := g.bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-1": rev(1, 2), "dev-cell-2": rev(1, 2)})
	renamed.records["dev-cell-1"], renamed.records["dev-cell-2"] = renamed.records["dev-cell-2"], renamed.records["dev-cell-1"]
	if err := f.apply(g, renamed); !errors.Is(err, spec.ErrMismatch) {
		t.Fatalf("swapped records: %v", err)
	}
	forged := newSigner(t).bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-1": rev(1, 2)})
	if err := f.apply(g, bundle{spec: forged.spec, records: forged.records}); !errors.Is(err, record.ErrSignature) {
		t.Fatalf("spec of another key: %v", err)
	}
	if _, ok := f.s.Cell(ctx, "dev-cell-1"); ok {
		t.Fatal("a refused sync left a record behind")
	}
	if err := f.apply(g, g.bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-1": rev(1, 2)})); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.s.Cell(ctx, "dev-cell-1"); !ok {
		t.Fatal("record not stored")
	}
	big := g.bundle(rev(1, 3), map[string]spec.Revision{"dev-cell-1": rev(1, 3)})
	big.records["dev-cell-1"] = json.RawMessage(strings.Repeat(" ", MaxRecordBytes+1))
	if err := f.apply(g, big); err == nil {
		t.Fatal("an oversized record was accepted")
	}
}

func TestRecordsResetOnKeyChange(t *testing.T) {
	f := newFixture(t)
	g := newSigner(t)
	ctx := context.Background()
	if err := f.apply(g, g.bundle(rev(1, 9), map[string]spec.Revision{"dev-cell-1": rev(1, 9)})); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.logs.String(), "state_reset") {
		t.Fatal("the first sync logged a reset")
	}
	// The management plane is rebuilt: a new key signs lower revisions. The marks reset.
	h := newSigner(t)
	if err := f.apply(h, h.bundle(rev(1, 2), map[string]spec.Revision{"dev-cell-2": rev(1, 2)})); err != nil {
		t.Fatalf("sync under a new key: %v", err)
	}
	if !strings.Contains(f.logs.String(), `"msg":"state_reset"`) {
		t.Fatalf("no state_reset log: %s", f.logs.String())
	}
	if _, ok := f.s.Cell(ctx, "dev-cell-1"); ok {
		t.Fatal("a record of the old key survived")
	}
	if c, ok := f.s.Cell(ctx, "dev-cell-2"); !ok || c.Counter != 2 {
		t.Fatalf("new record %+v, %v", c, ok)
	}
	if err := f.apply(h, h.bundle(rev(1, 3), map[string]spec.Revision{"dev-cell-2": rev(1, 1)})); !errors.Is(err, ErrRecordOld) {
		t.Fatalf("marks under the new key: %v", err)
	}
}

func TestCellInfoNonces(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, _, ok := f.s.CellInfo(ctx, cell1); ok {
		t.Fatal("unknown cell found")
	}
	a := mgmtapi.CellInfo{Name: cell1, Nonce: "n1", NonceExpiresAt: t0, Bound: true}
	if err := f.s.SetCells(ctx, []mgmtapi.CellInfo{a, {Name: cell2, Nonce: "m1"}}); err != nil {
		t.Fatal(err)
	}
	l, p, ok := f.s.CellInfo(ctx, cell1)
	if !ok || l.Nonce != "n1" || p.Nonce != "" || !l.Bound || !l.NonceExpiresAt.Equal(t0) {
		t.Fatalf("first set: %+v %+v %v", l, p, ok)
	}
	b := a
	b.Nonce = "n2"
	if err := f.s.SetCells(ctx, []mgmtapi.CellInfo{b}); err != nil {
		t.Fatal(err)
	}
	if l, p, _ = f.s.CellInfo(ctx, cell1); l.Nonce != "n2" || p.Nonce != "n1" {
		t.Fatalf("after rotation: %+v %+v", l, p)
	}
	if err := f.s.SetCells(ctx, []mgmtapi.CellInfo{b}); err != nil {
		t.Fatal(err)
	}
	if l, p, _ = f.s.CellInfo(ctx, cell1); l.Nonce != "n2" || p.Nonce != "n1" {
		t.Fatalf("same nonce again must keep the previous one: %+v %+v", l, p)
	}
	if _, _, ok := f.s.CellInfo(ctx, cell2); ok {
		t.Fatal("a cell that left the list is still known")
	}
	if err := f.s.MarkSynced(ctx, t0.Add(5)); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.s.Stats(ctx); !st.SyncedAt.Equal(t0.Add(5)) {
		t.Fatalf("synced at %v", st.SyncedAt)
	}
}
