package executor

import (
	"context"
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
	if res.Outcome != op.OutcomeAlreadyApplied || res.EnvelopeSHA256 != op.EnvelopeSHA256(env) {
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
	r.clock.Advance(op.MaxSkew - time.Second)
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
	r.cnt = &counter{}
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
