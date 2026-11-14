package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

var ctx = context.Background()

func fence(e, c uint64) op.Fence { return op.Fence{Epoch: e, Counter: c} }

func TestExecuteApplies(t *testing.T) {
	r := newRig(t)
	o := r.operation(op.KindDemoAppend, `{"line":"hello"}`)
	env := r.sign(o)
	res := r.executor("uid-a").Execute(ctx, env, fence(1, 1))
	if res.Outcome != op.OutcomeApplied || res.OpID != o.ID || res.EnvelopeSHA256 != op.EnvelopeSHA256(env) {
		t.Fatalf("result = %+v", res)
	}
	if res.Cell != "cell-1" || res.Pod != "celld-uid-a" || res.Fence != fence(1, 1) {
		t.Errorf("result fields = %+v", res)
	}
	log := mustGet(t, r, demoLogName)
	if got := log.Data[demoLogKey]; got != o.ID+" hello" {
		t.Errorf("log = %q", got)
	}
	if rec := r.record(o.ID); rec.State != stateApplied || rec.Holder != "uid-a" || rec.Result == nil {
		t.Errorf("record = %+v", rec)
	}
}

func TestExecuteTwiceAlreadyApplied(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	env := r.sign(r.operation(testKind, `{}`))
	if res := e.Execute(ctx, env, fence(1, 1)); res.Outcome != op.OutcomeApplied {
		t.Fatalf("first = %+v", res)
	}
	res := e.Execute(ctx, env, fence(1, 2))
	if res.Outcome != op.OutcomeAlreadyApplied || res.EnvelopeSHA256 != op.EnvelopeSHA256(env) || res.Fence != fence(1, 2) || res.Pod != "celld-uid-a" || !res.At.Equal(r.clock.Now()) {
		t.Fatalf("second = %+v", res)
	}
	if n := r.cnt.count(); n != 1 {
		t.Fatalf("count = %d", n)
	}
	if err := e.MarkReported(ctx, res.OpID); err != nil {
		t.Fatal(err)
	}
	if res := e.Execute(ctx, env, fence(1, 3)); res.Outcome != op.OutcomeAlreadyApplied {
		t.Fatalf("after reported = %+v", res)
	}
	if n := r.cnt.count(); n != 1 {
		t.Fatalf("count = %d", n)
	}
}

func TestTakeoverWaitsForLease(t *testing.T) {
	r := newRig(t)
	a, b := r.executor("uid-a"), r.executor("uid-b")
	env := r.sign(r.operation(testKind, `{}`))
	stopped := errors.New("stop")
	a.cfg.Kinds[testKind] = func(context.Context, *Executor, op.Operation) error { return stopped }
	if res := a.Execute(ctx, env, fence(1, 1)); res.Outcome != op.OutcomeLeaseLost {
		t.Fatalf("a = %+v", res)
	}
	r.clock.Advance(leaseTerm - time.Second)
	res := b.Execute(ctx, env, fence(1, 2))
	if res.Outcome != op.OutcomeLeaseLost || res.Reason != op.ReasonLeaseLost {
		t.Fatalf("b = %+v", res)
	}
	if n := r.cnt.count(); n != 0 {
		t.Fatalf("count = %d", n)
	}
}

func TestExecutorTakeoverAppliesOnce(t *testing.T) {
	r := newRig(t)
	a, b := r.executor("uid-a"), r.executor("uid-b")
	env := r.sign(r.operation(testKind, `{}`))
	var bRes op.Result
	a.afterClaim = func() {
		r.clock.Advance(61 * time.Second)
		bRes = b.Execute(ctx, env, fence(1, 2))
		a.afterClaim = nil
	}
	aRes := a.Execute(ctx, env, fence(1, 1))
	if bRes.Outcome != op.OutcomeApplied {
		t.Fatalf("b = %+v", bRes)
	}
	if aRes.Outcome != op.OutcomeLeaseLost || aRes.Reason != op.ReasonLeaseLost {
		t.Fatalf("a = %+v", aRes)
	}
	if n := r.cnt.count(); n != 1 {
		t.Fatalf("count = %d", n)
	}
}

func TestExecuteClaimsBeforeEffect(t *testing.T) {
	r := newRig(t)
	env := r.sign(r.operation(testKind, `{}`))
	var seen storedRecord
	var id string
	e := r.executor("uid-a")
	e.cfg.Kinds[testKind] = func(_ context.Context, _ *Executor, o op.Operation) error {
		id = o.ID
		seen = r.record(o.ID)
		return nil
	}
	e.Execute(ctx, env, fence(2, 7))
	if id == "" || seen.State != stateClaimed || seen.Fence != fence(2, 7) || seen.Holder != "uid-a" {
		t.Fatalf("record in effect = %+v", seen)
	}
	if !seen.LeaseUntil.Equal(r.clock.Now().Add(60 * time.Second)) {
		t.Errorf("leaseUntil = %s", seen.LeaseUntil)
	}
}

func TestExecutorCrashAfterEffect(t *testing.T) {
	r := newRig(t)
	o := r.operation(op.KindDemoAppend, `{"line":"once"}`)
	env := r.sign(o)
	a := r.executor("uid-a")
	real := a.cfg.Kinds[op.KindDemoAppend]
	a.cfg.Kinds[op.KindDemoAppend] = func(c context.Context, e *Executor, o op.Operation) error {
		if err := real(c, e, o); err != nil {
			return err
		}
		return errors.New("crash")
	}
	if res := a.Execute(ctx, env, fence(1, 1)); res.Outcome != op.OutcomeLeaseLost {
		t.Fatalf("a = %+v", res)
	}
	if got := mustGet(t, r, demoLogName).Data[demoLogKey]; got != o.ID+" once" {
		t.Fatalf("log = %q", got)
	}
	r.clock.Advance(61 * time.Second)
	if rec := r.record(o.ID); rec.State != stateClaimed || !r.clock.Now().After(rec.LeaseUntil) {
		t.Fatalf("record = %+v", rec)
	}
	res := r.executor("uid-b").Execute(ctx, env, fence(1, 2))
	if res.Outcome != op.OutcomeApplied {
		t.Fatalf("b = %+v", res)
	}
	if got := mustGet(t, r, demoLogName).Data[demoLogKey]; got != o.ID+" once" {
		t.Fatalf("log after takeover = %q", got)
	}
}

func TestConcurrentExecutorsOneEffect(t *testing.T) {
	for i := 0; i < 20; i++ {
		r := newRig(t)
		env := r.sign(r.operation(testKind, `{}`))
		a, b := r.executor("uid-a"), r.executor("uid-b")
		var wg sync.WaitGroup
		for j, e := range []*Executor{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.Execute(ctx, env, fence(1, uint64(j+1)))
			}()
		}
		wg.Wait()
		if n := r.cnt.count(); n != 1 {
			t.Fatalf("round %d: count = %d", i, n)
		}
	}
}

func TestLeaseRenewedDuringEffect(t *testing.T) {
	r := newRig(t)
	env := r.sign(r.operation(testKind, `{}`))
	e := r.executor("uid-a")
	e.renewEvery = 5 * time.Millisecond
	var before, after time.Time
	e.cfg.Kinds[testKind] = func(_ context.Context, _ *Executor, o op.Operation) error {
		before = r.record(o.ID).LeaseUntil
		r.clock.Advance(30 * time.Second)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if after = r.record(o.ID).LeaseUntil; after.After(before) {
				return nil
			}
			time.Sleep(5 * time.Millisecond)
		}
		return errors.New("lease not renewed")
	}
	if res := e.Execute(ctx, env, fence(1, 1)); res.Outcome != op.OutcomeApplied {
		t.Fatalf("result = %+v", res)
	}
	if got := after.Sub(before); got != 30*time.Second {
		t.Errorf("lease moved by %s", got)
	}
}

func TestExecuteCountsResults(t *testing.T) {
	r := newRig(t)
	reader, meter := testMeter()
	e := r.executor("uid-a", func(c *Config) { c.Meter = meter })
	e.Execute(ctx, r.sign(r.operation(testKind, `{}`)), fence(1, 1))
	e.Execute(ctx, r.sign(r.operation("nope", `{}`)), fence(1, 2))
	got := collect(t, reader, "celld.ops.results")
	if got["applied/"] != 1 || got["refused/kind_unknown"] != 1 {
		t.Fatalf("counts = %v", got)
	}
}

func TestPreEffectRefusesExpiredLease(t *testing.T) {
	r := newRig(t)
	a, b := r.executor("uid-a"), r.executor("uid-b")
	env := r.sign(r.operation(testKind, `{}`))
	a.afterClaim = func() { r.clock.Advance(61 * time.Second) }
	res := a.Execute(ctx, env, fence(1, 1))
	if res.Outcome != op.OutcomeLeaseLost || res.Reason != op.ReasonLeaseLost {
		t.Fatalf("a = %+v", res)
	}
	if n := r.cnt.count(); n != 0 {
		t.Fatalf("effect ran %d times on an expired lease", n)
	}
	if res := b.Execute(ctx, env, fence(1, 2)); res.Outcome != op.OutcomeApplied {
		t.Fatalf("b = %+v", res)
	}
	if n := r.cnt.count(); n != 1 {
		t.Fatalf("count = %d", n)
	}
}

func TestPreEffectRenewsLease(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	o := r.operation(testKind, `{}`)
	var inEffect time.Time
	e.afterClaim = func() { r.clock.Advance(59 * time.Second) }
	e.cfg.Kinds[testKind] = func(_ context.Context, _ *Executor, o op.Operation) error {
		inEffect = r.record(o.ID).LeaseUntil
		return nil
	}
	e.Execute(ctx, r.sign(o), fence(1, 1))
	if want := r.clock.Now().Add(leaseTerm); !inEffect.Equal(want) {
		t.Fatalf("leaseUntil in effect = %s, want %s", inEffect, want)
	}
}

func seedExpiredClaim(t *testing.T, r *rig, id string, f op.Fence) {
	t.Helper()
	seedRecord(t, r, id, storedRecord{
		State: stateClaimed, Fence: f, Holder: "uid-x",
		LeaseUntil: r.clock.Now().Add(-time.Second), UpdatedAt: r.clock.Now().Add(-time.Minute),
	})
}

// TestTakeoverConflict lands a takeover by pod A between the read and the update of pod B. The
// update of pod B must fail on resourceVersion.
func TestTakeoverConflict(t *testing.T) {
	r := newRig(t)
	o := r.operation(testKind, `{}`)
	env := r.sign(o)
	seedExpiredClaim(t, r, o.ID, fence(1, 1))
	a, b := r.executor("uid-a"), r.executor("uid-b")
	b.beforeTakeover = func() {
		b.beforeTakeover = nil
		a.Execute(ctx, env, fence(1, 2))
	}
	res := b.Execute(ctx, env, fence(1, 3))
	if res.Outcome != op.OutcomeLeaseLost {
		t.Fatalf("b = %+v", res)
	}
	if n := r.cnt.count(); n != 1 {
		t.Fatalf("count = %d", n)
	}
	if rec := r.record(o.ID); rec.State != stateApplied || rec.Holder != "uid-a" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestConcurrentTakeoverOneEffect(t *testing.T) {
	for i := 0; i < 20; i++ {
		r := newRig(t)
		o := r.operation(testKind, `{}`)
		env := r.sign(o)
		seedExpiredClaim(t, r, o.ID, fence(1, 1))
		var wg sync.WaitGroup
		for j, uid := range []string{"uid-a", "uid-b"} {
			e := r.executor(uid)
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.Execute(ctx, env, fence(1, uint64(j+2)))
			}()
		}
		wg.Wait()
		if n := r.cnt.count(); n != 1 {
			t.Fatalf("round %d: count = %d", i, n)
		}
	}
}

func TestTakeoverNeedsHigherFence(t *testing.T) {
	for _, f := range []op.Fence{fence(1, 5), fence(1, 2), fence(0, 9)} {
		r := newRig(t)
		o := r.operation(testKind, `{}`)
		seedExpiredClaim(t, r, o.ID, fence(1, 5))
		res := r.executor("uid-b").Execute(ctx, r.sign(o), f)
		if res.Outcome != op.OutcomeLeaseLost || res.Fence != f {
			t.Fatalf("fence %v: %+v", f, res)
		}
		if n := r.cnt.count(); n != 0 {
			t.Fatalf("fence %v: count = %d", f, n)
		}
		if rec := r.record(o.ID); rec.Holder != "uid-x" {
			t.Fatalf("fence %v: record = %+v", f, rec)
		}
	}
}

// TestFinishAfterLostClaim: the lease of pod A passes during its effect and pod B takes over and
// applies. The finish of pod A must leave the record of pod B.
func TestFinishAfterLostClaim(t *testing.T) {
	r := newRig(t)
	a, b := r.executor("uid-a"), r.executor("uid-b")
	o := r.operation(testKind, `{}`)
	env := r.sign(o)
	a.cfg.Kinds[testKind] = func(c context.Context, _ *Executor, _ op.Operation) error {
		r.clock.Advance(61 * time.Second)
		b.Execute(ctx, env, fence(1, 2))
		return nil
	}
	res := a.Execute(ctx, env, fence(1, 1))
	if res.Outcome != op.OutcomeLeaseLost {
		t.Fatalf("a = %+v", res)
	}
	rec := r.record(o.ID)
	if rec.State != stateApplied || rec.Holder != "uid-b" || rec.Result == nil || rec.Result.Pod != "celld-uid-b" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestLostLeaseCancelsEffect(t *testing.T) {
	r := newRig(t)
	a, b := r.executor("uid-a"), r.executor("uid-b")
	env := r.sign(r.operation(testKind, `{}`))
	a.renewEvery = 5 * time.Millisecond
	cancelled := false
	a.cfg.Kinds[testKind] = func(c context.Context, _ *Executor, _ op.Operation) error {
		r.clock.Advance(61 * time.Second)
		b.Execute(ctx, env, fence(1, 2))
		select {
		case <-c.Done():
			cancelled = true
		case <-time.After(5 * time.Second):
		}
		return c.Err()
	}
	if res := a.Execute(ctx, env, fence(1, 1)); res.Outcome != op.OutcomeLeaseLost {
		t.Fatalf("a = %+v", res)
	}
	if !cancelled {
		t.Fatal("the effect context stayed open after the lease was lost")
	}
}

func TestAppliedAnswersAfterExpiry(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	o := r.operation(testKind, `{}`)
	env := r.sign(o)
	if res := e.Execute(ctx, env, fence(1, 1)); res.Outcome != op.OutcomeApplied {
		t.Fatalf("first = %+v", res)
	}
	r.clock.Advance(time.Hour)
	res := e.Execute(ctx, env, fence(1, 2))
	if res.Outcome != op.OutcomeAlreadyApplied || res.OpID != o.ID {
		t.Fatalf("after expiry = %+v", res)
	}
	other := r.operation(testKind, `{}`)
	other.IssuedAt, other.ExpiresAt = r.clock.Now().Add(-time.Hour), r.clock.Now().Add(-time.Minute)
	if res := e.Execute(ctx, r.sign(other), fence(1, 3)); res.Outcome != op.OutcomeExpired {
		t.Fatalf("unknown expired op = %+v", res)
	}
}

func TestCounts(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := op.Sign(r.operation(testKind, `{}`), otherPriv)
	elsewhere := r.operation(testKind, `{}`)
	elsewhere.Cell = "cell-2"
	unknown := r.operation("nope", `{}`)
	for i, env := range [][]byte{
		r.sign(r.operation(testKind, `{}`)), forged, r.sign(elsewhere), r.sign(unknown),
	} {
		e.Execute(ctx, env, fence(1, uint64(i+1)))
	}
	if got := e.Counts(); got != (Counts{Applied: 1, Refused: 3, ForgedSeen: 2}) {
		t.Fatalf("counts = %+v", got)
	}
}

// A lease whose fence epoch is far above the clock would lock the cell out of the stream, because the
// gateway refuses a hello that reports it. The cell refuses the lease and writes no record.
func TestExecuteRefusesFenceFarAhead(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	o := r.operation(testKind, `{}`)
	env := r.sign(o)
	for _, epoch := range []uint64{1 << 62, uint64(r.clock.Now().Unix()) + op.MaxFenceAhead + 1} {
		res := e.Execute(ctx, env, op.Fence{Epoch: epoch, Counter: 1})
		if res.Outcome != op.OutcomeLeaseLost || res.Reason != ReasonFenceRange {
			t.Fatalf("epoch %d: %+v", epoch, res)
		}
		if n := len(r.records()); n != 0 || r.cnt.count() != 0 {
			t.Fatalf("epoch %d: %d records and %d effects, want none", epoch, n, r.cnt.count())
		}
	}
	// The bound itself is allowed.
	at := op.Fence{Epoch: uint64(r.clock.Now().Unix()) + op.MaxFenceAhead, Counter: 1}
	if res := e.Execute(ctx, env, at); res.Outcome != op.OutcomeApplied {
		t.Fatalf("at the bound: %+v", res)
	}
}

// A record that already holds a fence above the bound does not reach the hello, so the cell can
// open a stream again.
func TestLastFenceSkipsFenceFarAhead(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	good := r.operation(testKind, `{}`)
	if res := e.Execute(ctx, r.sign(good), fence(5, 2)); res.Outcome != op.OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	high := op.Fence{Epoch: uint64(r.clock.Now().Unix()) + op.MaxFenceAhead, Counter: 9}
	if res := e.Execute(ctx, r.sign(r.operation(testKind, `{}`)), high); res.Outcome != op.OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	if last, err := e.lastFence(ctx); err != nil || last != high {
		t.Fatalf("lastFence %+v, %v; want %+v", last, err, high)
	}
	r.clock.Advance(-48 * time.Hour)
	if last, err := e.lastFence(ctx); err != nil || last != fence(5, 2) {
		t.Fatalf("lastFence %+v, %v after the clock moved back; want the lower fence", last, err)
	}
}
