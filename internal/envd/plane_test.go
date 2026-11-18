package envd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const planeCluster = "dev-cp"

type planeCall struct {
	opID, target string
	att          []byte
}

type planeAnswer struct {
	out bundleapply.Outcome
	err error
}

// fakeEngine answers each Apply from a queue and can hold an Apply until release is closed.
type fakeEngine struct {
	mu      sync.Mutex
	answers []planeAnswer
	calls   []planeCall
	release chan struct{}
	started chan struct{}
	status  *op.BundleStatus
}

func (e *fakeEngine) Apply(ctx context.Context, opID, target string, att []byte) (bundleapply.Outcome, error) {
	e.mu.Lock()
	e.calls = append(e.calls, planeCall{opID, target, bytes.Clone(att)})
	var a planeAnswer
	if len(e.answers) > 0 {
		a, e.answers = e.answers[0], e.answers[1:]
	} else {
		a.out = bundleapply.Outcome{Outcome: op.OutcomeApplied}
	}
	rel, started := e.release, e.started
	e.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if rel != nil {
		select {
		case <-rel:
		case <-ctx.Done():
			return bundleapply.Outcome{}, ctx.Err()
		}
	}
	return a.out, a.err
}

func (e *fakeEngine) Status(context.Context) (*op.BundleStatus, error) { return e.status, nil }

func (e *fakeEngine) called() []planeCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]planeCall(nil), e.calls...)
}

type planeRig struct {
	t      *testing.T
	f      *fx
	eng    *fakeEngine
	clk    *clock
	logs   *syncBuffer
	plane  *Plane
	status *op.BundleStatus
	// keyFn gives the keys of the plane; a test swaps it to model a failed read or a rotation.
	keyFn func() []crypto.PublicKey
}

func mustPlane(t *testing.T, cfg PlaneConfig) *Plane {
	t.Helper()
	p, err := NewPlane(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newPlaneRig(t *testing.T) *planeRig {
	t.Helper()
	f := newFx(t)
	st := &op.BundleStatus{Version: bundle.Version{Epoch: 1, Counter: 3}, RootDigest: "sha256:" + strings.Repeat("a", 64), State: "healthy", AllowSHA256: strings.Repeat("b", 64)}
	r := &planeRig{t: t, f: f, eng: &fakeEngine{status: st}, clk: newClock(0), logs: &syncBuffer{}, status: st}
	r.keyFn = func() []crypto.PublicKey { return []crypto.PublicKey{f.pub} }
	r.plane = mustPlane(t, PlaneConfig{Env: testEnv, Cluster: planeCluster, Applier: r.eng, Now: r.clk.Now, Log: newLog(r.logs),
		Keys: func() []crypto.PublicKey { return r.keyFn() }})
	return r
}

func (r *planeRig) operation(mod func(*op.Operation)) op.Operation {
	now := r.clk.Now()
	o := op.Operation{ID: op.NewID(), Env: testEnv, Cell: planeCluster, Kind: op.KindBundleApply, Version: 1, KeyEpoch: 1,
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Args: json.RawMessage(`{"payloadType":"application/vnd.in-toto+json"}`)}
	if mod != nil {
		mod(&o)
	}
	return o
}

func (r *planeRig) sign(o op.Operation) []byte {
	r.t.Helper()
	env, err := op.Sign(o, r.f.priv)
	if err != nil {
		r.t.Fatal(err)
	}
	return env
}

// offer hands the envelope to the plane and waits for the apply goroutine.
func (r *planeRig) offer(env []byte) {
	r.t.Helper()
	r.plane.Offer(r.t.Context(), env)
	r.plane.wait()
}

// awaitStart waits until the engine has begun an Apply.
func (r *planeRig) awaitStart() {
	r.t.Helper()
	select {
	case <-r.eng.started:
	case <-time.After(5 * time.Second):
		r.t.Fatal("the engine did not start")
	}
}

func (r *planeRig) result() *op.Result {
	r.t.Helper()
	res, _ := r.plane.Report()
	return res
}

func TestPlaneBundleApplied(t *testing.T) {
	r := newPlaneRig(t)
	o := r.operation(nil)
	env := r.sign(o)
	r.offer(env)
	res, st := r.plane.Report()
	if res == nil || res.Outcome != op.OutcomeApplied || res.OpID != o.ID || res.Cell != planeCluster || res.Reason != "" {
		t.Fatalf("result = %+v", res)
	}
	if res.EnvelopeSHA256 != op.EnvelopeSHA256(env) || !res.At.Equal(r.clk.Now()) {
		t.Errorf("digest or time: %+v", res)
	}
	if st == nil || *st != *r.status {
		t.Errorf("status = %+v", st)
	}
	calls := r.eng.called()
	if len(calls) != 1 || calls[0].opID != o.ID || calls[0].target != planeCluster || string(calls[0].att) != string(o.Args) {
		t.Fatalf("engine calls = %+v", calls)
	}
}

func TestPlaneBundleVersionOld(t *testing.T) {
	r := newPlaneRig(t)
	r.eng.answers = []planeAnswer{{out: bundleapply.Outcome{Outcome: op.OutcomeRefused, Reason: op.ReasonVersionOld}}}
	o := r.operation(nil)
	r.offer(r.sign(o))
	res := r.result()
	if res == nil || res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonVersionOld || res.OpID != o.ID {
		t.Fatalf("result = %+v", res)
	}
}

func TestPlaneBundleWrongTarget(t *testing.T) {
	t.Run("operation names another cluster", func(t *testing.T) {
		r := newPlaneRig(t)
		o := r.operation(func(o *op.Operation) { o.Cell = "dev-cell-1" })
		r.offer(r.sign(o))
		res := r.result()
		if res == nil || res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonWrongTarget || res.OpID != o.ID {
			t.Fatalf("result = %+v", res)
		}
		if n := len(r.eng.called()); n != 0 {
			t.Fatalf("the engine ran %d times", n)
		}
	})
	t.Run("set names another cluster", func(t *testing.T) {
		r := newPlaneRig(t)
		r.eng.answers = []planeAnswer{{out: bundleapply.Outcome{Outcome: op.OutcomeRefused, Reason: op.ReasonPayloadInvalid, Detail: "target"}}}
		r.offer(r.sign(r.operation(nil)))
		res := r.result()
		if res == nil || res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonWrongTarget || res.Detail != "target" {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestPlaneBundleUnsigned(t *testing.T) {
	r := newPlaneRig(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	o := r.operation(nil)
	env, err := op.Sign(o, other)
	if err != nil {
		t.Fatal(err)
	}
	r.offer(env)
	res := r.result()
	if res == nil || res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonSignatureInvalid || res.OpID != "" || res.PeekedID != o.ID {
		t.Fatalf("result = %+v", res)
	}
	r2 := newPlaneRig(t)
	r2.offer([]byte(`{"not":"an envelope"}`))
	if res := r2.result(); res == nil || res.Reason != op.ReasonPayloadInvalid {
		t.Fatalf("garbage: %+v", res)
	}
	if n := len(r.eng.called()) + len(r2.eng.called()); n != 0 {
		t.Fatalf("the engine ran %d times", n)
	}
}

func TestPlaneBundleExpired(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		r := newPlaneRig(t)
		o := r.operation(func(o *op.Operation) {
			o.IssuedAt = r.clk.Now().Add(-20 * time.Minute)
			o.ExpiresAt = r.clk.Now().Add(-10 * time.Minute)
		})
		r.offer(r.sign(o))
		res := r.result()
		if res == nil || res.Outcome != op.OutcomeExpired || res.OpID != o.ID {
			t.Fatalf("result = %+v", res)
		}
		if n := len(r.eng.called()); n != 0 {
			t.Fatalf("the engine ran %d times", n)
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		r := newPlaneRig(t)
		o := r.operation(func(o *op.Operation) {
			o.IssuedAt = r.clk.Now().Add(5 * time.Minute)
			o.ExpiresAt = r.clk.Now().Add(15 * time.Minute)
		})
		r.offer(r.sign(o))
		res := r.result()
		if res == nil || res.Outcome != op.OutcomeLeaseLost || res.Reason != op.ReasonLeaseLost || res.Detail != "clock" || op.IsFinal(res.Outcome) {
			t.Fatalf("result = %+v", res)
		}
		if n := len(r.eng.called()); n != 0 {
			t.Fatalf("the engine ran %d times", n)
		}
		r.clk.now = r.clk.now.Add(5 * time.Minute)
		r.offer(r.sign(o))
		if res := r.result(); res == nil || res.Outcome != op.OutcomeApplied {
			t.Fatalf("after the clock passes the issue time: %+v", res)
		}
	})
	t.Run("skew inside the limit", func(t *testing.T) {
		r := newPlaneRig(t)
		o := r.operation(func(o *op.Operation) { o.IssuedAt = r.clk.Now().Add(op.MaxSkew) })
		r.offer(r.sign(o))
		if res := r.result(); res == nil || res.Outcome != op.OutcomeApplied {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestPlaneBundleRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mod    func(*op.Operation)
		reason string
	}{
		"other kind":        {func(o *op.Operation) { o.Kind = op.KindDemoAppend; o.Args = json.RawMessage(`{"line":"x"}`) }, op.ReasonKindUnknown},
		"other environment": {func(o *op.Operation) { o.Env = "prod" }, op.ReasonEnvMismatch},
		"args too large": {func(o *op.Operation) {
			o.Args = json.RawMessage(`{"x":"` + strings.Repeat("a", op.MaxBundleArgsBytes) + `"}`)
		}, op.ReasonPayloadInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			r := newPlaneRig(t)
			r.offer(r.sign(r.operation(tc.mod)))
			res := r.result()
			if res == nil || res.Outcome != op.OutcomeRefused || res.Reason != tc.reason {
				t.Fatalf("result = %+v", res)
			}
			if n := len(r.eng.called()); n != 0 {
				t.Fatalf("the engine ran %d times", n)
			}
		})
	}
}

func TestPlaneBundleOneInFlight(t *testing.T) {
	r := newPlaneRig(t)
	r.eng.release = make(chan struct{})
	r.eng.started = make(chan struct{}, 4)
	first, second := r.operation(nil), r.operation(nil)
	r.plane.Offer(t.Context(), r.sign(first))
	r.awaitStart()
	r.plane.Offer(t.Context(), r.sign(second))
	r.plane.Offer(t.Context(), r.sign(first))
	if res := r.result(); res != nil {
		t.Fatalf("result before the apply ends: %+v", res)
	}
	close(r.eng.release)
	r.plane.wait()
	calls := r.eng.called()
	if len(calls) != 1 || calls[0].opID != first.ID {
		t.Fatalf("engine calls = %+v", calls)
	}
	if res := r.result(); res == nil || res.OpID != first.ID {
		t.Fatalf("result = %+v", res)
	}
	r.offer(r.sign(second))
	if res := r.result(); res == nil || res.OpID != second.ID {
		t.Fatalf("after the second offer: %+v", res)
	}
	if n := len(r.eng.called()); n != 2 {
		t.Fatalf("engine calls = %d", n)
	}
}

func TestPlaneBundleReportRepeats(t *testing.T) {
	r := newPlaneRig(t)
	o := r.operation(nil)
	env := r.sign(o)
	r.offer(env)
	first := r.result()
	for range 3 {
		r.offer(env)
		got := r.result()
		if got == nil || *got != *first {
			t.Fatalf("result = %+v, want %+v", got, first)
		}
	}
	if n := len(r.eng.called()); n != 1 {
		t.Fatalf("the engine ran %d times", n)
	}
	r.offer(nil)
	if res, _ := r.plane.Report(); res != nil {
		t.Fatalf("result after the operation closed: %+v", res)
	}
}

func TestPlaneBundleRetriesFault(t *testing.T) {
	r := newPlaneRig(t)
	r.eng.answers = []planeAnswer{{err: bundleapply.ErrLockHeld}, {out: bundleapply.Outcome{Outcome: op.OutcomeApplied}}}
	env := r.sign(r.operation(nil))
	r.offer(env)
	if res := r.result(); res != nil {
		t.Fatalf("a fault became a result: %+v", res)
	}
	r.offer(env)
	if res := r.result(); res == nil || res.Outcome != op.OutcomeApplied {
		t.Fatalf("result = %+v", res)
	}
	if n := len(r.eng.called()); n != 2 {
		t.Fatalf("engine calls = %d", n)
	}
}

func TestPlaneBundleKeepsResultWhileApplyRuns(t *testing.T) {
	r := newPlaneRig(t)
	r.eng.release = make(chan struct{})
	r.eng.started = make(chan struct{}, 1)
	env := r.sign(r.operation(nil))
	r.plane.Offer(t.Context(), env)
	r.awaitStart()
	r.plane.Offer(t.Context(), nil)
	close(r.eng.release)
	r.plane.wait()
	if res := r.result(); res == nil || res.Outcome != op.OutcomeApplied {
		t.Fatalf("result = %+v", res)
	}
}

func TestPlaneBundleStatusFault(t *testing.T) {
	r := newPlaneRig(t)
	r.eng.status = nil
	r.offer(r.sign(r.operation(nil)))
	res, st := r.plane.Report()
	if res == nil || st != nil {
		t.Fatalf("result %+v status %+v", res, st)
	}
}

// A repeated refusal of the same envelope does not run again.
func TestPlaneBundleRefusalRepeats(t *testing.T) {
	r := newPlaneRig(t)
	env := r.sign(r.operation(func(o *op.Operation) { o.Cell = "dev-cell-1" }))
	r.offer(env)
	first := r.result()
	r.clk.now = r.clk.now.Add(time.Minute)
	r.offer(env)
	if got := r.result(); got == nil || *got != *first {
		t.Fatalf("result = %+v, want %+v", got, first)
	}
}

func TestPlaneOpNotForwarded(t *testing.T) {
	r := newRig(t, 2)
	pr := newPlaneRig(t)
	pr.f = r.f
	pr.plane = mustPlane(t, PlaneConfig{Env: testEnv, Cluster: planeCluster, Applier: pr.eng, Now: r.clk.Now, Log: newLog(r.logs),
		Keys: func() []crypto.PublicKey { return []crypto.PublicKey{r.f.pub} }})
	planeOp := pr.operation(nil)
	cellOp := pr.operation(func(o *op.Operation) { o.Cell = "dev-cell-1"; o.Args = json.RawMessage(`{"line":"x"}`) })
	planeEnv, cellEnv := pr.sign(planeOp), pr.sign(cellOp)
	r.mgmt.set(func(m *fakeMgmt) {
		m.ops = mgmtapi.OpsBundle{Ops: []json.RawMessage{planeEnv, cellEnv}, PlaneBundle: planeEnv}
	})
	r.cfg.Cluster, r.cfg.Plane = planeCluster, pr.plane
	r.run()
	syncs, _ := r.gw.seen()
	if len(syncs) == 0 {
		t.Fatal("the gateway saw no sync")
	}
	for _, s := range syncs {
		if len(s.Ops) != 1 || !bytes.Equal(s.Ops[0], cellEnv) {
			t.Fatalf("gateway ops = %s", s.Ops)
		}
	}
	if n := r.logs.count("plane_op_not_forwarded"); n == 0 {
		t.Errorf("no plane_op_not_forwarded line in %v", r.logs.lines())
	}
}

func TestPlaneOpsKeepForwardedWithoutPlane(t *testing.T) {
	r := newRig(t, 1)
	pr := newPlaneRig(t)
	cellEnv := pr.sign(pr.operation(func(o *op.Operation) { o.Cell = "dev-cell-1" }))
	r.mgmt.set(func(m *fakeMgmt) { m.ops = mgmtapi.OpsBundle{Ops: []json.RawMessage{cellEnv}} })
	r.cfg.Cluster, r.cfg.Plane = planeCluster, pr.plane
	r.run()
	syncs, _ := r.gw.seen()
	if len(syncs) != 1 || len(syncs[0].Ops) != 1 {
		t.Fatalf("syncs = %+v", syncs)
	}
}

func TestStatusReportPlaneKeys(t *testing.T) {
	r := newRig(t, 3)
	pr := newPlaneRig(t)
	pr.plane = mustPlane(t, PlaneConfig{Env: testEnv, Cluster: planeCluster, Applier: pr.eng, Now: r.clk.Now, Log: newLog(io.Discard),
		Keys: func() []crypto.PublicKey { return []crypto.PublicKey{r.f.pub} }})
	pr.f = r.f
	o := pr.operation(nil)
	env := pr.sign(o)
	r.mgmt.set(func(m *fakeMgmt) { m.ops = mgmtapi.OpsBundle{PlaneBundle: env} })
	r.cfg.Cluster, r.cfg.Plane = planeCluster, pr.plane
	r.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		pr.plane.wait()
		return r.clk.Sleep(ctx, d)
	}
	r.run()
	reps := r.mgmt.reports()
	if len(reps) != 3 {
		t.Fatalf("reports = %d", len(reps))
	}
	last := reps[2]
	if last.PlaneBundle == nil || last.PlaneBundle.OpID != o.ID || last.PlaneBundle.Outcome != op.OutcomeApplied {
		t.Fatalf("planeBundle = %+v", last.PlaneBundle)
	}
	if last.PlaneBundleStatus == nil || last.PlaneBundleStatus.State != "healthy" {
		t.Fatalf("planeBundleStatus = %+v", last.PlaneBundleStatus)
	}
	raw, _ := json.Marshal(last)
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keys)
	if keys["planeBundle"] == nil || keys["planeBundleStatus"] == nil {
		t.Errorf("keys = %v", keys)
	}
	// An envd with no plane reports neither key.
	plain := newRig(t, 1)
	plain.run()
	raw, _ = json.Marshal(plain.mgmt.reports()[0])
	if strings.Contains(string(raw), "planeBundle") {
		t.Errorf("plain report = %s", raw)
	}
}

func TestPlaneBundleSignatureRefusalRechecks(t *testing.T) {
	t.Run("keys fail to load at first", func(t *testing.T) {
		r := newPlaneRig(t)
		r.keyFn = func() []crypto.PublicKey { return nil }
		env := r.sign(r.operation(nil))
		r.offer(env)
		if res := r.result(); res == nil || res.Reason != op.ReasonSignatureInvalid {
			t.Fatalf("first result = %+v", res)
		}
		r.keyFn = func() []crypto.PublicKey { return []crypto.PublicKey{r.f.pub} }
		r.offer(env)
		if res := r.result(); res == nil || res.Outcome != op.OutcomeApplied {
			t.Fatalf("second result = %+v", res)
		}
	})
	t.Run("key rotates", func(t *testing.T) {
		r := newPlaneRig(t)
		old, _, _ := ed25519.GenerateKey(rand.Reader)
		r.keyFn = func() []crypto.PublicKey { return []crypto.PublicKey{old} }
		env := r.sign(r.operation(nil))
		r.offer(env)
		if res := r.result(); res == nil || res.Reason != op.ReasonSignatureInvalid {
			t.Fatalf("first result = %+v", res)
		}
		r.keyFn = func() []crypto.PublicKey { return []crypto.PublicKey{r.f.pub} }
		r.offer(env)
		if res := r.result(); res == nil || res.Outcome != op.OutcomeApplied {
			t.Fatalf("second result = %+v", res)
		}
	})
}

func TestNewPlaneRefusesMissingParts(t *testing.T) {
	keys := func() []crypto.PublicKey { return nil }
	if _, err := NewPlane(PlaneConfig{Env: testEnv, Cluster: planeCluster, Applier: &fakeEngine{}}); err == nil {
		t.Error("nil Keys accepted")
	}
	if _, err := NewPlane(PlaneConfig{Env: testEnv, Cluster: planeCluster, Keys: keys}); err == nil {
		t.Error("nil Applier accepted")
	}
	if _, err := NewPlane(PlaneConfig{Env: testEnv, Cluster: planeCluster, Keys: keys, Applier: &fakeEngine{}}); err != nil {
		t.Errorf("complete config: %v", err)
	}
}

func TestPlaneBundleLogsRepeatedFaultOnce(t *testing.T) {
	const msg = "plane bundle apply did not finish"
	r := newPlaneRig(t)
	fault := errors.New("mirror down")
	r.eng.answers = []planeAnswer{{err: fault}, {err: fault}, {err: fault}, {err: errors.New("store down")}, {err: fault}}
	env := r.sign(r.operation(func(o *op.Operation) { o.ExpiresAt = o.IssuedAt.Add(time.Hour) }))
	for range 3 {
		r.offer(env)
		r.clk.now = r.clk.now.Add(10 * time.Second)
	}
	if n := r.logs.count(msg); n != 1 {
		t.Fatalf("after three equal faults: %d lines", n)
	}
	r.offer(env)
	if n := r.logs.count(msg); n != 2 {
		t.Fatalf("after another fault: %d lines", n)
	}
	r.clk.now = r.clk.now.Add(2 * time.Minute)
	r.offer(env)
	if n := r.logs.count(msg); n != 3 {
		t.Fatalf("after the window: %d lines", n)
	}
}
