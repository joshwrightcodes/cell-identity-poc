package mgmt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

var demoArgs = json.RawMessage(`{"line":"hello"}`)

func TestCreateOpSignsAndServes(t *testing.T) {
	r, _ := boundRig(t)
	o, env := r.newOp(cell1)
	if len(o.ID) != 32 || o.Env != "dev" || o.Cell != cell1 || o.Kind != op.KindDemoAppend || o.Version != 1 {
		t.Fatalf("operation %+v", o)
	}
	if got := o.ExpiresAt.Sub(o.IssuedAt); got != 10*time.Minute {
		t.Fatalf("default ttl %v", got)
	}
	back, _, err := op.Verify(env, []ed25519.PublicKey{r.plane.PublicKey()})
	if err != nil || back.ID != o.ID || !back.ExpiresAt.Equal(o.ExpiresAt) || string(back.Args) != string(demoArgs) {
		t.Fatalf("verify: %+v, %v", back, err)
	}
	st := r.opState(o.ID)
	if st.Cell != cell1 || !slices.Equal(st.Envelopes, []string{op.EnvelopeSHA256(env)}) || !st.Served || st.Final != "" {
		t.Fatalf("op state %+v", st)
	}
	if b := r.plane.OpenOps(); len(b.Ops) != 1 || string(b.Ops[0]) != string(env) {
		t.Fatalf("open ops %v", b.Ops)
	}
	r.restart(nil)
	if b := r.plane.OpenOps(); len(b.Ops) != 1 || string(b.Ops[0]) != string(env) {
		t.Fatal("the operation did not survive a restart")
	}
	if c := cellStatus(r.status(), cell1); c.OpenOps != 1 || c.ExpiredOps != 0 {
		t.Fatalf("status %+v", c)
	}
}

// keyEpoch is State.Last.Epoch at the time of signing. A reset or a lost state starts again at
// epoch 1 under a new key and loses every open operation, so a lower epoch never meets a queued
// envelope of the same ID.
func TestKeyEpochIsLastEpochOfTheState(t *testing.T) {
	r, _ := boundRig(t)
	o1, _ := r.newOp(cell1)
	if o1.KeyEpoch != 1 || r.opState(o1.ID).KeyEpoch != 1 {
		t.Fatalf("keyEpoch %d at epoch 1", o1.KeyEpoch)
	}
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	o2, _ := r.newOp(cell1)
	if o2.KeyEpoch != 2 || r.plane.snap.Load().st.Last.Epoch != 2 {
		t.Fatalf("keyEpoch %d after a rotation", o2.KeyEpoch)
	}
	// A lost state starts at epoch 1 under a new key and holds no operation.
	if err := os.Remove(filepath.Join(r.dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	r.restart(nil)
	if len(r.plane.OpenOps().Ops) != 0 || r.plane.snap.Load().st.Last.Epoch != 1 {
		t.Fatal("a lost state kept operations")
	}
}

func TestCreateOpRefusesUnbound(t *testing.T) {
	r, _ := boundRig(t)
	ctx := t.Context()
	if _, _, err := r.plane.CreateOp(ctx, cell2, op.KindDemoAppend, demoArgs, 0, true); ReasonOf(err) != mgmtapi.ReasonNotBound {
		t.Fatalf("unbound cell: %v", err)
	}
	if _, _, err := r.plane.CreateOp(ctx, "dev-cell-9", op.KindDemoAppend, demoArgs, 0, true); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("unknown cell: %v", err)
	}
	if _, _, err := r.plane.CreateOp(ctx, cell1, "other.kind", demoArgs, 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, _, err := r.plane.CreateOp(ctx, cell1, op.KindDemoAppend, json.RawMessage(`{"line":""}`), 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Fatalf("empty line: %v", err)
	}
	if len(r.plane.snap.Load().st.Ops) != 0 {
		t.Fatal("a refused operation was recorded")
	}
}

func TestCreateOpTTLBounds(t *testing.T) {
	r, _ := boundRig(t)
	for _, c := range []struct {
		ttl time.Duration
		ok  bool
	}{
		{0, true}, {time.Second, true}, {time.Hour, true},
		{999 * time.Millisecond, false}, {time.Hour + time.Second, false}, {-time.Minute, false},
	} {
		o, _, err := r.plane.CreateOp(t.Context(), cell1, op.KindDemoAppend, demoArgs, c.ttl, true)
		switch {
		case c.ok && err != nil:
			t.Errorf("ttl %v: %v", c.ttl, err)
		case !c.ok && ReasonOf(err) != mgmtapi.ReasonPayloadInvalid:
			t.Errorf("ttl %v: %v, want payload_invalid", c.ttl, err)
		case c.ok && c.ttl != 0 && o.ExpiresAt.Sub(o.IssuedAt) != c.ttl:
			t.Errorf("ttl %v gave %v", c.ttl, o.ExpiresAt.Sub(o.IssuedAt))
		}
	}
}

func TestOpenCap256(t *testing.T) {
	r, _ := boundRig(t)
	var first op.Operation
	var firstEnv []byte
	for i := range MaxOpenOps {
		o, env, err := r.plane.CreateOp(t.Context(), cell1, op.KindDemoAppend, demoArgs, 0, true)
		if err != nil {
			t.Fatalf("op %d: %v", i, err)
		}
		if i == 0 {
			first, firstEnv = o, env
		}
	}
	if _, _, err := r.plane.CreateOp(t.Context(), cell1, op.KindDemoAppend, demoArgs, 0, true); ReasonOf(err) != mgmtapi.ReasonRateLimited {
		t.Fatalf("the 257th operation: %v", err)
	}
	want(t, r.one(r.resultItem(resultFor(first, firstEnv, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	if _, _, err := r.plane.CreateOp(t.Context(), cell1, op.KindDemoAppend, demoArgs, 0, true); err != nil {
		t.Fatalf("after one closed: %v", err)
	}
}

func TestCreateOpSignOnlyNotServed(t *testing.T) {
	r, _ := boundRig(t)
	o, env, err := r.plane.CreateOp(t.Context(), cell1, op.KindDemoAppend, demoArgs, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.plane.OpenOps().Ops) != 0 {
		t.Fatal("a sign-only operation is served")
	}
	if st := r.opState(o.ID); st.Served || len(st.Envelopes) != 1 {
		t.Fatalf("state %+v", st)
	}
	want(t, r.one(r.resultItem(resultFor(o, env, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
}

func TestOpenOpsDropsFinalAndExpired(t *testing.T) {
	r, _ := boundRig(t)
	done, doneEnv := r.newOp(cell1)
	short, _, err := r.plane.CreateOp(t.Context(), cell1, op.KindDemoAppend, demoArgs, 2*time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	keep, _ := r.newOp(cell1)
	want(t, r.one(r.resultItem(resultFor(done, doneEnv, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	if r.isOpen(done.ID) || !r.isOpen(short.ID) || !r.isOpen(keep.ID) {
		t.Fatal("a final operation is served, or an open one is not")
	}
	r.clk.Advance(2*time.Second + 59*time.Second)
	if !r.isOpen(short.ID) {
		t.Fatal("an operation within 60 s of its expiry left the list")
	}
	if !r.opState(short.ID).ExpiredAt.IsZero() {
		t.Fatal("ExpiredAt is set inside the grace time")
	}
	r.clk.Advance(2 * time.Second)
	if r.isOpen(short.ID) || !r.isOpen(keep.ID) {
		t.Fatal("an operation past ExpiresAt+60 s is served, or an open one is not")
	}
	if r.opState(short.ID).ExpiredAt.IsZero() {
		t.Fatal("ExpiredAt is not set")
	}
	if c := cellStatus(r.status(), cell1); c.OpenOps != 1 || c.ExpiredOps != 1 {
		t.Fatalf("status open %d expired %d", c.OpenOps, c.ExpiredOps)
	}
	// A late result still closes the expired operation.
	late, _ := decodeOpUnverified(r.opState(short.ID).Envelope)
	want(t, r.one(r.resultItem(resultFor(late, r.opState(short.ID).Envelope, op.OutcomeExpired), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
}

func TestOpenOpsCarriesNonces(t *testing.T) {
	r, _ := boundRig(t)
	b := r.plane.OpenOps()
	if len(b.Cells) != 2 || b.Cells[0].Name != cell1 || b.Cells[1].Name != cell2 {
		t.Fatalf("cells %+v", b.Cells)
	}
	if !b.Cells[0].Bound || b.Cells[1].Bound {
		t.Fatalf("bound flags %+v", b.Cells)
	}
	for _, c := range b.Cells {
		if err := r.plane.nonces.Check(c.Name, c.Nonce); err != nil {
			t.Fatalf("nonce of %s: %v", c.Name, err)
		}
		if !c.NonceExpiresAt.After(r.clk.Now()) {
			t.Fatalf("nonce of %s expires at %v", c.Name, c.NonceExpiresAt)
		}
	}
	if again := r.plane.OpenOps(); again.Cells[0].Nonce == b.Cells[0].Nonce {
		t.Fatal("two pulls gave one nonce")
	}
	if b.Ops == nil {
		t.Fatal("Ops is nil, and encodes as null")
	}
}

func TestCloseOpAbandoned(t *testing.T) {
	r, _ := boundRig(t)
	o, env, err := r.plane.CreateOp(t.Context(), cell1, op.KindDemoAppend, demoArgs, 5*time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.plane.CloseOp(t.Context(), o.ID); !errors.Is(err, ErrOpNotExpired) {
		t.Fatalf("close before expiry: %v", err)
	}
	if err := r.plane.CloseOp(t.Context(), strings.Repeat("0", 32)); !errors.Is(err, ErrOpUnknown) {
		t.Fatalf("close of an unknown operation: %v", err)
	}
	r.clk.Advance(6 * time.Second)
	if err := r.plane.CloseOp(t.Context(), o.ID); err != nil {
		t.Fatal(err)
	}
	if st := r.opState(o.ID); st.Final != OpAbandoned || st.Result != nil {
		t.Fatalf("state %+v", st)
	}
	if r.isOpen(o.ID) {
		t.Fatal("an abandoned operation is served")
	}
	if err := r.plane.CloseOp(t.Context(), o.ID); !errors.Is(err, ErrOpFinal) {
		t.Fatalf("second close: %v", err)
	}
	// An operation that has a final result is not abandoned.
	done, doneEnv := r.newOp(cell1)
	want(t, r.one(r.resultItem(resultFor(done, doneEnv, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	r.clk.Advance(time.Hour)
	if err := r.plane.CloseOp(t.Context(), done.ID); !errors.Is(err, ErrOpFinal) {
		t.Fatalf("close of a final operation: %v", err)
	}
	// A result that arrives after the close keeps the abandoned state.
	want(t, r.one(r.resultItem(resultFor(o, env, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeDuplicate, "", "")
	if r.opState(o.ID).Final != OpAbandoned {
		t.Fatal("a late result replaced abandoned")
	}
}

func TestOpHistoryDropsOldestFinalFirst(t *testing.T) {
	st := newState("fp")
	add := func(id, final string) {
		st.Ops[id] = &OpState{Final: final}
		st.OpOrder = append(st.OpOrder, id)
	}
	add("open-oldest", "")
	for i := range OpHistory + 1 {
		add(fmt.Sprintf("final-%03d", i), op.OutcomeApplied)
	}
	trimOps(st)
	if len(st.OpOrder) != OpHistory || len(st.Ops) != OpHistory {
		t.Fatalf("%d ids, %d ops", len(st.OpOrder), len(st.Ops))
	}
	if st.Ops["open-oldest"] == nil || st.Ops["final-000"] != nil || st.Ops["final-001"] != nil || st.Ops["final-002"] == nil {
		t.Fatal("the oldest open operation went before the oldest final one")
	}
}

func TestStateLoadsWithoutOps(t *testing.T) {
	r, _ := boundRig(t)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(r.stateBytes(), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "ops")
	delete(m, "opOrder")
	delete(m, "stagedKeySHA256")
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(r.dir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := r.store.Load()
	if err != nil || st == nil || st.Ops == nil || len(st.Ops) != 0 {
		t.Fatalf("load: %+v, %v", st, err)
	}
	r.restart(nil)
	o, _ := r.newOp(cell1)
	if r.opState(o.ID).Cell != cell1 {
		t.Fatal("no operation after loading an old state")
	}
	st2 := *r.plane.snap.Load().st
	st2.OpOrder = []string{"missing"}
	if err := st2.validate(); err == nil {
		t.Fatal("an order that names a missing operation validates")
	}
}

func TestStageKeyIdempotent(t *testing.T) {
	r, _ := boundRig(t)
	k1, err := r.plane.StageKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	k2, err := r.plane.StageKey(t.Context())
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("second call: %v, %v", k2, err)
	}
	path := filepath.Join(r.dir, "ed25519.next.key")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("next key file: %v, %v", info, err)
	}
	if got := r.status().StagedKey; got != fingerprint(k1) {
		t.Fatalf("status staged key %q", got)
	}
	if k1.Equal(r.plane.PublicKey()) {
		t.Fatal("the staged key is the signing key")
	}
	seq := r.plane.snapshotSeq()
	if _, err := r.plane.StageKey(t.Context()); err != nil || r.plane.snapshotSeq() != seq {
		t.Fatal("a repeated stage saved the state")
	}
	r.restart(nil)
	if k3, err := r.plane.StageKey(t.Context()); err != nil || !k3.Equal(k1) {
		t.Fatalf("after a restart: %v, %v", k3, err)
	}
	// The staged key becomes the signing key, and the stage is empty again.
	pub, err := r.plane.RotateKey(t.Context())
	if err != nil || !pub.Equal(k1) {
		t.Fatalf("rotate used %v, %v; want the staged key", pub, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) || r.status().StagedKey != "" {
		t.Fatalf("the staged key stayed after the rotation: %v", err)
	}
	if k4, err := r.plane.StageKey(t.Context()); err != nil || k4.Equal(k1) {
		t.Fatalf("a new stage returned the old key: %v", err)
	}
	r.verifySpec()
}

func TestStagedKeyTrustedOnlyWhenTheStateNamesIt(t *testing.T) {
	r, _ := boundRig(t)
	stray, _ := os.ReadFile(filepath.Join(r.dir, "ed25519.key"))
	next := filepath.Join(r.dir, "ed25519.next.key")
	t.Run("file_the_state_does_not_name", func(t *testing.T) {
		if err := os.WriteFile(next, stray, 0o400); err != nil {
			t.Fatal(err)
		}
		r.restart(nil)
		if _, err := os.Stat(next); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("an unnamed staged key stayed in place")
		}
		if m, _ := filepath.Glob(next + ".stale-*"); len(m) != 1 {
			t.Fatalf("moved aside: %v", m)
		}
		pub, err := r.plane.StageKey(t.Context())
		if err != nil || pub.Equal(r.plane.PublicKey()) {
			t.Fatalf("stage returned the stray key: %v", err)
		}
	})
	t.Run("lost_state", func(t *testing.T) {
		staged, _ := r.plane.StageKey(t.Context())
		if err := os.Remove(filepath.Join(r.dir, "state.json")); err != nil {
			t.Fatal(err)
		}
		r.restart(nil)
		if _, err := os.Stat(next); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a staged key of a lost state stayed in place")
		}
		pub, err := r.plane.RotateKey(t.Context())
		if err != nil || pub.Equal(staged) {
			t.Fatalf("rotate committed the key of the lost state: %v", err)
		}
	})
	t.Run("state_names_a_missing_file", func(t *testing.T) {
		if _, err := r.plane.StageKey(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(next); err != nil {
			t.Fatal(err)
		}
		r.restart(nil)
		if r.status().StagedKey != "" {
			t.Fatal("the state still names a staged key with no file")
		}
	})
}

func TestRotateKeyResignsOpenOps(t *testing.T) {
	r, _ := boundRig(t)
	a1, e1 := r.newOp(cell1)
	a2, e2 := r.newOp(cell1)
	done, doneEnv := r.newOp(cell1)
	want(t, r.one(r.resultItem(resultFor(done, doneEnv, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	oldPub := r.plane.PublicKey()
	if _, err := r.plane.StageKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	newPub, err := r.plane.RotateKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	bundle := r.plane.OpenOps()
	if len(bundle.Ops) != 2 {
		t.Fatalf("%d open ops after the rotation", len(bundle.Ops))
	}
	for i, a := range []op.Operation{a1, a2} {
		got, _, err := op.Verify(bundle.Ops[i], []ed25519.PublicKey{newPub})
		if err != nil || got.ID != a.ID || !got.ExpiresAt.Equal(a.ExpiresAt) || !got.IssuedAt.Equal(a.IssuedAt) {
			t.Fatalf("op %d under the new key: %+v, %v", i, got, err)
		}
		if got.KeyEpoch != 2 || got.KeyEpoch <= a.KeyEpoch {
			t.Fatalf("keyEpoch %d after %d", got.KeyEpoch, a.KeyEpoch)
		}
		if _, _, err := op.Verify(bundle.Ops[i], []ed25519.PublicKey{oldPub}); err == nil {
			t.Fatal("the re-signed envelope verifies under the old key")
		}
		if st := r.opState(a.ID); len(st.Envelopes) != 2 || st.KeyEpoch != 2 {
			t.Fatalf("op state %+v", st)
		}
	}
	if st := r.opState(done.ID); len(st.Envelopes) != 1 || op.EnvelopeSHA256(st.Envelope) != op.EnvelopeSHA256(doneEnv) {
		t.Fatal("a final operation was signed again")
	}
	// Both digests close it.
	want(t, r.one(r.resultItem(resultFor(a1, e1, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	want(t, r.one(r.resultItem(resultFor(a2, bundle.Ops[1], op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	_ = e2
}

func TestRotateKeyWithoutStageResignsOps(t *testing.T) {
	r, _ := boundRig(t)
	a, _ := r.newOp(cell1)
	newPub, err := r.plane.RotateKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := op.Verify(r.plane.OpenOps().Ops[0], []ed25519.PublicKey{newPub})
	if err != nil || got.ID != a.ID {
		t.Fatalf("%+v, %v", got, err)
	}
	// A key file replaced from outside takes the same path.
	_, key, _ := ed25519.GenerateKey(nil)
	if err := WriteKey(filepath.Join(r.dir, "ed25519.key"), key); err != nil {
		t.Fatal(err)
	}
	r.restart(nil)
	if _, _, err := op.Verify(r.plane.OpenOps().Ops[0], []ed25519.PublicKey{r.plane.PublicKey()}); err != nil {
		t.Fatalf("after a key change at start: %v", err)
	}
}

type recordCalls struct {
	mu    sync.Mutex
	calls []map[string]json.RawMessage
	pubs  []ed25519.PublicKey
}

func (c *recordCalls) on(recs map[string]json.RawMessage, pub ed25519.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, recs)
	c.pubs = append(c.pubs, pub)
}

func (c *recordCalls) n() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

func TestOnRecordsCalledAfterCommit(t *testing.T) {
	var rc recordCalls
	r := newRig(t)
	ts := &toggleStore{Store: r.store}
	r.store = ts
	r.mod = func(c *Config) { c.OnRecords = rc.on }
	r.restart(nil)
	if rc.n() != 1 {
		t.Fatalf("%d calls after NewPlane, want 1", rc.n())
	}
	base := rc.n()
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	if rc.n() != base+1 {
		t.Fatalf("calls after a bind: %d", rc.n()-base)
	}
	last := rc.calls[len(rc.calls)-1]
	if _, ok := last[cell1]; !ok || !rc.pubs[len(rc.pubs)-1].Equal(r.plane.PublicKey()) {
		t.Fatalf("callback arguments: %v", last)
	}
	// A change that moves no record calls nothing.
	r.clk.Advance(61 * time.Second)
	if res, _ := r.plane.KeyCheck(t.Context(), cell1); res != CheckUnchanged {
		t.Fatalf("check %v", res)
	}
	if _, _, err := r.plane.CreateOp(t.Context(), cell1, op.KindDemoAppend, demoArgs, 0, true); err != nil {
		t.Fatal(err)
	}
	if rc.n() != base+1 {
		t.Fatal("a commit that changed no record called the hook")
	}
	// A failed save calls nothing.
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], newSigner(t, "kid-b"))
	ts.fail.Store(true)
	if _, err := r.plane.KeyCheck(t.Context(), cell1); err == nil {
		t.Fatal("a failed save did not fail the check")
	}
	if rc.n() != base+1 {
		t.Fatal("a failed save called the hook")
	}
	ts.fail.Store(false)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUpdated || rc.n() != base+2 {
		t.Fatalf("after the retry: %v, %v, %d calls", res, err, rc.n()-base)
	}
	// A restore changes the served records.
	if err := r.plane.Restore(1); err != nil {
		t.Fatal(err)
	}
	if rc.n() != base+3 {
		t.Fatalf("restore: %d calls", rc.n()-base)
	}
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	if rc.n() != base+4 {
		t.Fatalf("rotate: %d calls", rc.n()-base)
	}
}

func TestSeqGuardKeyCheckIsManual(t *testing.T) {
	r, _ := boundRig(t)
	calls := r.keys.count(cell1)
	if res, err := r.plane.IfSeq(r.plane.snapshotSeq()).KeyCheck(t.Context(), cell1); err != nil || res != CheckUnchanged {
		t.Fatalf("%v, %v", res, err)
	}
	if r.keys.count(cell1) != calls+1 {
		t.Fatal("a guarded check read the cache; the admin check is manual")
	}
}

func TestRunChecksUsesPeriodicSource(t *testing.T) {
	r, _ := boundRig(t)
	r.mod = func(c *Config) { c.CheckEvery = 10 * time.Second }
	r.restart(nil)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckUnchanged {
		t.Fatalf("warm check: %v, %v", res, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.plane.RunChecks(ctx) }()
	calls := r.keys.count(cell1)
	r.clk.Advance(11 * time.Second)
	r.ticks <- r.clk.Now()
	r.ticks <- r.clk.Now()
	if got := r.keys.count(cell1); got != calls {
		t.Fatalf("a periodic check within the cache time made %d fetches", got-calls)
	}
	if c := cellStatus(r.status(), cell1); c.CheckedAt.IsZero() {
		t.Fatal("no check ran")
	}
	cancel()
	<-done
}
