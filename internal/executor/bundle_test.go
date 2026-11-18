package executor

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

type applyCall struct {
	opID, target string
	attestation  []byte
}

// fakeApplier returns the scripted answers in order, and the last one again after that.
type fakeApplier struct {
	mu      sync.Mutex
	answers []fakeAnswer
	calls   []applyCall
	status  *op.BundleStatus
	statErr error
}

type fakeAnswer struct {
	out bundleapply.Outcome
	err error
}

func (f *fakeApplier) Apply(_ context.Context, opID, target string, att []byte) (bundleapply.Outcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, applyCall{opID, target, att})
	a := f.answers[min(len(f.calls), len(f.answers))-1]
	return a.out, a.err
}

func (f *fakeApplier) Status(context.Context) (*op.BundleStatus, error) { return f.status, f.statErr }

func (f *fakeApplier) called() []applyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]applyCall(nil), f.calls...)
}

// bundleExecutor returns an executor whose bundle.apply effect runs the fake.
func (r *rig) bundleExecutor(podUID string, f *fakeApplier) *Executor {
	e := r.executor(podUID)
	e.cfg.Kinds[op.KindBundleApply] = applyBundle(f)
	e.bundle = f
	return e
}

const attestation = `{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`

func TestExecuteFinalRecorded(t *testing.T) {
	r := newRig(t)
	runs := 0
	e := r.executor("uid-a")
	e.cfg.Kinds[testKind] = func(context.Context, *Executor, op.Operation) error {
		runs++
		return &Final{Outcome: op.OutcomeRefused, Reason: op.ReasonVersionOld, Detail: "version_conflict"}
	}
	o := r.operation(testKind, `{}`)
	env := r.sign(o)
	res := e.Execute(ctx, env, fence(1, 1))
	if res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonVersionOld || res.Detail != "version_conflict" || res.OpID != o.ID {
		t.Fatalf("result = %+v", res)
	}
	rec := r.record(o.ID)
	if rec.State != stateApplied || rec.Result == nil || rec.Result.Outcome != op.OutcomeRefused || rec.Result.Detail != "version_conflict" {
		t.Fatalf("record = %+v", rec)
	}
	if c := e.Counts(); c.Refused != 1 || c.Applied != 0 {
		t.Errorf("counts = %+v", c)
	}
	again := e.Execute(ctx, env, fence(1, 2))
	if again.Outcome != op.OutcomeAlreadyApplied || runs != 1 {
		t.Fatalf("second = %+v after %d runs", again, runs)
	}
	pending, err := e.Pending(ctx)
	if err != nil || len(pending) != 1 || pending[0].Reason != op.ReasonVersionOld || pending[0].Detail != "version_conflict" {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
}

func TestExecuteFinalWithInvalidDetail(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	e.cfg.Kinds[testKind] = func(context.Context, *Executor, op.Operation) error {
		return &Final{Outcome: op.OutcomeRefused, Reason: op.ReasonPayloadInvalid, Detail: "bad detail\n"}
	}
	res := e.Execute(ctx, r.sign(r.operation(testKind, `{}`)), fence(1, 1))
	if res.Outcome != op.OutcomeRefused || res.Detail != "" {
		t.Fatalf("result = %+v", res)
	}
}

func TestBundleEffectApplied(t *testing.T) {
	r := newRig(t)
	f := &fakeApplier{answers: []fakeAnswer{{out: bundleapply.Outcome{Outcome: op.OutcomeApplied}}}}
	e := r.bundleExecutor("uid-a", f)
	o := r.operation(op.KindBundleApply, attestation)
	res := e.Execute(ctx, r.sign(o), fence(1, 1))
	if res.Outcome != op.OutcomeApplied || res.Reason != "" {
		t.Fatalf("result = %+v", res)
	}
	calls := f.called()
	if len(calls) != 1 || calls[0].opID != o.ID || calls[0].target != "cell-1" || string(calls[0].attestation) != attestation {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestBundleEffectRefusal(t *testing.T) {
	cases := map[string]bundleapply.Outcome{
		"component_not_allowed": {Outcome: op.OutcomeRefused, Reason: op.ReasonComponentNotAllowed, Detail: "kind"},
		"policy_blocks_planes":  {Outcome: op.OutcomeRefused, Reason: op.ReasonPolicyBlocksPlanes, Detail: "cell-system/plane-celld-store"},
		"version_old":           {Outcome: op.OutcomeRefused, Reason: op.ReasonVersionOld},
		"digest_mismatch":       {Outcome: op.OutcomeRefused, Reason: op.ReasonDigestMismatch, Detail: "root"},
		"already_applied":       {Outcome: op.OutcomeAlreadyApplied},
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			f := &fakeApplier{answers: []fakeAnswer{{out: out}}}
			e := r.bundleExecutor("uid-a", f)
			o := r.operation(op.KindBundleApply, attestation)
			res := e.Execute(ctx, r.sign(o), fence(1, 1))
			if res.Outcome != out.Outcome || res.Reason != out.Reason || res.Detail != out.Detail {
				t.Fatalf("result = %+v, want %+v", res, out)
			}
			if rec := r.record(o.ID); rec.State != stateApplied || rec.Result == nil || rec.Result.Reason != out.Reason {
				t.Fatalf("record = %+v", rec)
			}
		})
	}
}

func TestBundleEffectOnlyBundleOps(t *testing.T) {
	r := newRig(t)
	f := &fakeApplier{answers: []fakeAnswer{{out: bundleapply.Outcome{Outcome: op.OutcomeApplied}}}}
	e := r.bundleExecutor("uid-a", f)
	if res := e.Execute(ctx, r.sign(r.operation(op.KindDemoAppend, `{"line":"x"}`)), fence(1, 1)); res.Outcome != op.OutcomeApplied {
		t.Fatalf("demo = %+v", res)
	}
	if res := e.Execute(ctx, r.sign(r.operation("bundle.other", attestation)), fence(1, 2)); res.Reason != op.ReasonKindUnknown {
		t.Fatalf("other kind = %+v", res)
	}
	if n := len(f.called()); n != 0 {
		t.Fatalf("the engine ran %d times for an operation of another kind", n)
	}
}

func TestBundleKindOnlyWithApplier(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	res := e.Execute(ctx, r.sign(r.operation(op.KindBundleApply, attestation)), fence(1, 1))
	if res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonKindUnknown {
		t.Fatalf("without an applier = %+v", res)
	}
	a := bundleapply.New(bundleapply.Config{Role: "cell", Env: "dev", Target: "cell-1", State: &bundleapply.ConfigMapStore{
		Client: r.client, Namespace: DefaultNamespace, Name: "bundle-state"}})
	with := r.executor("uid-b", func(c *Config) { c.Bundle = a; c.Kinds = nil })
	if _, ok := with.cfg.Kinds[op.KindBundleApply]; !ok {
		t.Fatal("New did not add bundle.apply")
	}
	if _, ok := with.cfg.Kinds[op.KindDemoAppend]; !ok {
		t.Fatal("New dropped demo.append")
	}
	given := map[string]Effect{op.KindDemoAppend: applyDemoAppend}
	r.executor("uid-c", func(c *Config) { c.Bundle = a; c.Kinds = given })
	if _, ok := given[op.KindBundleApply]; ok {
		t.Error("New changed the map of the caller")
	}
}

func TestBundleEffectRealEngineRefusal(t *testing.T) {
	r := newRig(t)
	a := bundleapply.New(bundleapply.Config{Role: "cell", Env: "dev", Target: "cell-1",
		Keys:  func() []crypto.PublicKey { return []crypto.PublicKey{r.pub} },
		State: &bundleapply.ConfigMapStore{Client: r.client, Namespace: DefaultNamespace, Name: "bundle-state"}})
	e := r.executor("uid-a", func(c *Config) { c.Bundle = a })
	res := e.Execute(ctx, r.sign(r.operation(op.KindBundleApply, `{"not":"an envelope"}`)), fence(1, 1))
	if res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonPayloadInvalid {
		t.Fatalf("result = %+v", res)
	}
}

func TestBundleEffectArgsTooLarge(t *testing.T) {
	r := newRig(t)
	f := &fakeApplier{answers: []fakeAnswer{{out: bundleapply.Outcome{Outcome: op.OutcomeApplied}}}}
	e := r.bundleExecutor("uid-a", f)
	big := `{"x":"` + strings.Repeat("a", op.MaxBundleArgsBytes) + `"}`
	res := e.Execute(ctx, r.sign(r.operation(op.KindBundleApply, big)), fence(1, 1))
	if res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonPayloadInvalid {
		t.Fatalf("result = %+v", res)
	}
	if n := len(f.called()); n != 0 {
		t.Fatalf("the engine ran %d times", n)
	}
}

func TestBundleEffectRolledBack(t *testing.T) {
	r := newRig(t)
	out := bundleapply.Outcome{Outcome: op.OutcomeRolledBack, Reason: op.ReasonUnhealthy, Detail: "timeout:root:Synced/Progressing"}
	f := &fakeApplier{answers: []fakeAnswer{{out: out}}}
	e := r.bundleExecutor("uid-a", f)
	o := r.operation(op.KindBundleApply, attestation)
	env := r.sign(o)
	res := e.Execute(ctx, env, fence(1, 1))
	if res.Outcome != op.OutcomeRolledBack || res.Reason != op.ReasonUnhealthy || res.Detail != out.Detail {
		t.Fatalf("result = %+v", res)
	}
	if !op.IsFinal(res.Outcome) {
		t.Error("rolled_back is not final")
	}
	if rec := r.record(o.ID); rec.State != stateApplied || rec.Result == nil || rec.Result.Outcome != op.OutcomeRolledBack {
		t.Fatalf("record = %+v", rec)
	}
	if again := e.Execute(ctx, env, fence(1, 2)); again.Outcome != op.OutcomeAlreadyApplied {
		t.Fatalf("second = %+v", again)
	}
	if n := len(f.called()); n != 1 {
		t.Fatalf("the engine ran %d times", n)
	}
}

func TestBundleEffectRetry(t *testing.T) {
	for name, fault := range map[string]error{
		"lock held": bundleapply.ErrLockHeld,
		"mirror":    errors.New("read component platform from the mirror: not found"),
		"canceled":  context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			f := &fakeApplier{answers: []fakeAnswer{{err: fault}, {out: bundleapply.Outcome{Outcome: op.OutcomeApplied}}}}
			e := r.bundleExecutor("uid-a", f)
			o := r.operation(op.KindBundleApply, attestation)
			env := r.sign(o)
			res := e.Execute(ctx, env, fence(1, 1))
			if res.Outcome != op.OutcomeLeaseLost || res.Reason != ReasonEffectFailed {
				t.Fatalf("first = %+v", res)
			}
			if rec := r.record(o.ID); rec.State != stateClaimed || rec.Result != nil {
				t.Fatalf("record = %+v, want the claim with no result", rec)
			}
			if pending, _ := e.Pending(ctx); len(pending) != 0 {
				t.Fatalf("pending = %+v", pending)
			}
			r.clock.Advance(leaseTerm + time.Second)
			res = e.Execute(ctx, env, fence(1, 2))
			if res.Outcome != op.OutcomeApplied {
				t.Fatalf("repeat = %+v", res)
			}
			calls := f.called()
			if len(calls) != 2 || calls[0].opID != o.ID || calls[1].opID != o.ID {
				t.Fatalf("calls = %+v", calls)
			}
		})
	}
}

func TestBundleEnvelopeForOtherTarget(t *testing.T) {
	r := newRig(t)
	f := &fakeApplier{answers: []fakeAnswer{{out: bundleapply.Outcome{Outcome: op.OutcomeApplied}}}}
	e := r.bundleExecutor("uid-a", f)
	o := r.operation(op.KindBundleApply, attestation)
	o.Cell = "dev-cp"
	res := e.Execute(ctx, r.sign(o), fence(1, 1))
	if res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonWrongTarget {
		t.Fatalf("result = %+v", res)
	}
	if n := len(f.called()); n != 0 {
		t.Fatalf("the engine ran %d times", n)
	}
	if n := len(r.records()); n != 0 {
		t.Fatalf("%d records", n)
	}
}

func TestBundleSetForOtherTarget(t *testing.T) {
	r := newRig(t)
	f := &fakeApplier{answers: []fakeAnswer{{out: bundleapply.Outcome{Outcome: op.OutcomeRefused, Reason: op.ReasonPayloadInvalid, Detail: "target"}}}}
	e := r.bundleExecutor("uid-a", f)
	res := e.Execute(ctx, r.sign(r.operation(op.KindBundleApply, attestation)), fence(1, 1))
	if res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonWrongTarget || res.Detail != "target" {
		t.Fatalf("result = %+v", res)
	}
}

func TestStatusCarriesBundle(t *testing.T) {
	r := newRig(t)
	store := &bundleapply.ConfigMapStore{Client: r.client, Namespace: DefaultNamespace, Name: "bundle-state", MadeBy: "celld"}
	st := bundleapply.State{Source: "signed", Version: bundle.Version{Epoch: 2, Counter: 7}, State: "healthy",
		Root: bundleapply.Root{Digest: "sha256:" + strings.Repeat("a", 64), Manifest: []byte("{}")}}
	if err := store.Write(ctx, st, ""); err != nil {
		t.Fatal(err)
	}
	a := bundleapply.New(bundleapply.Config{Role: "cell", Env: "dev", Target: "cell-1", State: store})
	e := r.executor("uid-1", func(c *Config) { c.Bundle = a })
	got := NewStatus("cell-1", "p", "u", "v", func() time.Time { return time.Time{} }, e)()
	want := op.BundleStatus{Version: st.Version, RootDigest: st.Root.Digest, State: "healthy", AllowSHA256: bundle.AllowSHA256()}
	if got.Bundle == nil || *got.Bundle != want {
		t.Fatalf("bundle = %+v, want %+v", got.Bundle, want)
	}
	if want.AllowSHA256 == "" {
		t.Error("the allow-list hash is empty")
	}

	plain := NewStatus("cell-1", "p", "u", "v", func() time.Time { return time.Time{} }, r.executor("uid-2"))()
	if plain.Bundle != nil {
		t.Errorf("bundle = %+v without an applier", plain.Bundle)
	}
	f := &fakeApplier{statErr: errors.New("read bundle state: boom")}
	broken := NewStatus("cell-1", "p", "u", "v", func() time.Time { return time.Time{} }, r.bundleExecutor("uid-3", f))()
	if broken.Bundle != nil {
		t.Errorf("bundle = %+v after a failed read", broken.Bundle)
	}
}
