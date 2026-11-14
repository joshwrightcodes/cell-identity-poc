package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

var itemSeq atomic.Int64

// item builds a report item whose token covers the body bytes. mod changes the claims.
func (r *rig) item(cell, kind string, body any, sig *kubetoken.Signer, mod func(*kubetoken.Claims)) mgmtapi.ReportItem {
	r.t.Helper()
	b := []byte(marshal(r.t, body))
	c := kubetoken.Claims{
		Issuer: r.keys.issuer(cell), Namespace: celld.Namespace, ServiceAccount: celld.ServiceAccount,
		PodName: "celld-0", PodUID: "pod-uid", NodeName: "node-1",
		Audience: []string{proof.ReportAudience(cell, kind, b)}, IssuedAt: r.clk.Now(),
	}
	if mod != nil {
		mod(&c)
	}
	return mgmtapi.ReportItem{ID: fmt.Sprintf("item-%d", itemSeq.Add(1)), Cell: cell, Kind: kind, Body: b, Token: sig.Token(r.t, c)}
}

// resultFor builds the body of a result that celld would send for the envelope env of o.
func resultFor(o op.Operation, env []byte, outcome string) op.Result {
	return op.Result{
		OpID: o.ID, Cell: o.Cell, Pod: "celld-0", Outcome: outcome, Fence: op.Fence{Epoch: 1, Counter: 1},
		At: time.Now(), EnvelopeSHA256: op.EnvelopeSHA256(env),
	}
}

func (r *rig) resultItem(res op.Result, sig *kubetoken.Signer) mgmtapi.ReportItem {
	r.t.Helper()
	it := r.item(res.Cell, "result", res, sig, nil)
	it.OpID = res.OpID
	return it
}

func (r *rig) one(it mgmtapi.ReportItem) mgmtapi.ItemOutcome {
	r.t.Helper()
	out := r.plane.Reports(r.t.Context(), mgmtapi.ReportBatch{Items: []mgmtapi.ReportItem{it}}).Outcomes
	if len(out) != 1 {
		r.t.Fatalf("%d outcomes for one item", len(out))
	}
	return out[0]
}

func (r *rig) newOp(cell string) (op.Operation, []byte) {
	r.t.Helper()
	o, env, err := r.plane.CreateOp(r.t.Context(), cell, op.KindDemoAppend, json.RawMessage(`{"line":"hello"}`), 0, true)
	if err != nil {
		r.t.Fatalf("CreateOp: %v", err)
	}
	return o, env
}

func (r *rig) opState(id string) OpState {
	r.t.Helper()
	o := r.plane.snap.Load().st.Ops[id]
	if o == nil {
		r.t.Fatalf("no state for op %s", id)
	}
	return *o
}

func (r *rig) isOpen(id string) bool {
	for _, raw := range r.plane.OpenOps().Ops {
		if o, err := decodeOpUnverified(raw); err == nil && o.ID == id {
			return true
		}
	}
	return false
}

func want(t *testing.T, got mgmtapi.ItemOutcome, outcome, reason, detail string) {
	t.Helper()
	if got.Outcome != outcome || got.Reason != reason || got.Detail != detail {
		t.Fatalf("outcome %+v, want %s/%s/%s", got, outcome, reason, detail)
	}
}

func counterByAttr(t *testing.T, reader *sdkmetric.ManualReader, name string, attrs ...attribute.KeyValue) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if m.Name != name || !ok {
				continue
			}
			for _, p := range sum.DataPoints {
				match := true
				for _, a := range attrs {
					if v, ok := p.Attributes.Value(a.Key); !ok || v != a.Value {
						match = false
					}
				}
				if match {
					total += p.Value
				}
			}
		}
	}
	return total
}

// boundRig returns a rig with both cells bound and a meter reader.
func boundRig(t *testing.T, cells ...string) (*rig, *sdkmetric.ManualReader) {
	t.Helper()
	reader, meter := testMeter()
	r := newRig(t)
	r.mod = func(c *Config) { c.Meter = meter }
	r.restart(nil)
	if len(cells) == 0 {
		cells = []string{cell1}
	}
	for _, c := range cells {
		r.mustBind(c, r.signers[c], mgmtapi.StatusBound)
	}
	return r, reader
}

func TestReportsResultAccepted(t *testing.T) {
	r, _ := boundRig(t)
	o, env := r.newOp(cell1)
	first := resultFor(o, env, op.OutcomeApplied)
	first.Fence = op.Fence{Epoch: 7, Counter: 3}
	want(t, r.one(r.resultItem(first, r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	if r.isOpen(o.ID) {
		t.Fatal("the operation is still served after its final result")
	}
	want(t, r.one(r.resultItem(first, r.signers[cell1])), mgmtapi.OutcomeDuplicate, "", "")
	later := resultFor(o, env, op.OutcomeAlreadyApplied)
	want(t, r.one(r.resultItem(later, r.signers[cell1])), mgmtapi.OutcomeDuplicate, "", "")
	st := r.opState(o.ID)
	if st.Final != op.OutcomeApplied || st.Result == nil || st.Result.Outcome != op.OutcomeApplied || st.Result.Fence != first.Fence {
		t.Fatalf("the later result replaced the first: %+v", st)
	}
	if st.ResultAt.IsZero() {
		t.Fatal("no result time")
	}
	if got := cellStatus(r.status(), cell1).LastResultAt; !got.Equal(st.ResultAt) {
		t.Fatalf("lastResultAt %v, want %v", got, st.ResultAt)
	}
}

func TestReportsResultMustMatchOp(t *testing.T) {
	setup := func(t *testing.T) (*rig, *sdkmetric.ManualReader, op.Operation, []byte) {
		r, reader := boundRig(t, cell1, cell2)
		o, env := r.newOp(cell1)
		return r, reader, o, env
	}
	finish := func(t *testing.T, r *rig, reader *sdkmetric.ManualReader, o op.Operation, env []byte, forged mgmtapi.ItemOutcome, cell string) {
		t.Helper()
		want(t, forged, mgmtapi.OutcomeForgedSeen, "", "")
		if st := r.opState(o.ID); st.Final != "" || st.Result != nil {
			t.Fatalf("a forged result changed the operation: %+v", st)
		}
		if !r.isOpen(o.ID) {
			t.Fatal("the operation left the open list")
		}
		if got := counterByAttr(t, reader, "mgmtd.report.items", attribute.String("outcome", mgmtapi.OutcomeForgedSeen)); got != 1 {
			t.Fatalf("forged_seen counter %d, want 1", got)
		}
		if ring := r.plane.ForgedSeen(cell); len(ring) != 1 || ring[0].PeekedID != o.ID {
			t.Fatalf("ring %+v", ring)
		}
		if n := r.logs.count("forged_seen"); n != 1 {
			t.Fatalf("%d forged_seen log lines", n)
		}
		if cellStatus(r.status(), cell).ForgedSeen != 1 {
			t.Fatal("status does not count the forged result")
		}
		want(t, r.one(r.resultItem(resultFor(o, env, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
		if r.opState(o.ID).Final != op.OutcomeApplied {
			t.Fatal("the genuine result did not close the operation")
		}
	}
	t.Run("other_cell", func(t *testing.T) {
		r, reader, o, env := setup(t)
		res := resultFor(o, env, op.OutcomeRefused)
		res.Cell, res.Reason = cell2, op.ReasonWrongTarget
		finish(t, r, reader, o, env, r.one(r.resultItem(res, r.signers[cell2])), cell2)
	})
	t.Run("other_envelope", func(t *testing.T) {
		r, reader, o, env := setup(t)
		other := o
		other.Args = json.RawMessage(`{"line":"forged"}`)
		_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
		forgedEnv, err := op.Sign(other, otherKey)
		if err != nil {
			t.Fatal(err)
		}
		finish(t, r, reader, o, env, r.one(r.resultItem(resultFor(o, forgedEnv, op.OutcomeApplied), r.signers[cell1])), cell1)
	})
	t.Run("unverified_refusal", func(t *testing.T) {
		r, reader, o, env := setup(t)
		res := op.Result{PeekedID: o.ID, Cell: cell1, Outcome: op.OutcomeRefused, Reason: op.ReasonSignatureInvalid, EnvelopeSHA256: op.EnvelopeSHA256(env)}
		finish(t, r, reader, o, env, r.one(r.resultItem(res, r.signers[cell1])), cell1)
	})
}

func TestForgedRingKeepsTwenty(t *testing.T) {
	r, _ := boundRig(t)
	o, env := r.newOp(cell1)
	for i := range 25 {
		res := op.Result{PeekedID: o.ID, Cell: cell1, Outcome: op.OutcomeRefused, Reason: op.ReasonSignatureInvalid, EnvelopeSHA256: op.EnvelopeSHA256(env), Fence: op.Fence{Counter: uint64(i)}}
		want(t, r.one(r.resultItem(res, r.signers[cell1])), mgmtapi.OutcomeForgedSeen, "", "")
	}
	if n := len(r.plane.ForgedSeen(cell1)); n != 20 {
		t.Fatalf("ring holds %d", n)
	}
	if cellStatus(r.status(), cell1).ForgedSeen != 25 {
		t.Fatal("status lost the total")
	}
}

func TestResultForUnknownOp(t *testing.T) {
	r, _ := boundRig(t)
	o, env := r.newOp(cell1)
	o.ID = strings.Repeat("ab", 16)
	before := r.stateBytes()
	want(t, r.one(r.resultItem(resultFor(o, env, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeUnknownOp, "", "")
	if string(r.stateBytes()) != string(before) {
		t.Fatal("a result for an unknown operation changed the state")
	}
}

func TestReportResultBodyRules(t *testing.T) {
	r, _ := boundRig(t)
	o, env := r.newOp(cell1)
	good := resultFor(o, env, op.OutcomeApplied)
	for name, mutate := range map[string]func(*op.Result){
		"local_outcome": func(x *op.Result) { x.Outcome = op.OutcomeLeaseLost },
		"bad_op_id":     func(x *op.Result) { x.OpID = "X\nY" },
	} {
		t.Run(name, func(t *testing.T) {
			x := good
			mutate(&x)
			got := r.one(r.resultItem(x, r.signers[cell1]))
			if got.Outcome != mgmtapi.OutcomeRefused || got.Reason != mgmtapi.ReasonPayloadInvalid {
				t.Fatalf("outcome %+v", got)
			}
		})
	}
	t.Run("unknown_member", func(t *testing.T) {
		it := r.item(cell1, "result", map[string]any{"opId": o.ID, "cell": cell1, "outcome": "applied", "extra": 1}, r.signers[cell1], nil)
		got := r.one(it)
		want(t, got, mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "body")
	})
	t.Run("body_cell_differs_from_item", func(t *testing.T) {
		x := good
		x.Cell = cell2
		it := r.item(cell1, "result", x, r.signers[cell1], nil)
		want(t, r.one(it), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "cell")
	})
	t.Run("item_op_id_differs_from_body", func(t *testing.T) {
		other, otherEnv := r.newOp(cell1)
		it := r.resultItem(resultFor(other, otherEnv, op.OutcomeApplied), r.signers[cell1])
		it.OpID = o.ID // the gateway keys the final outcome on this ID, and the body closes the other op
		want(t, r.one(it), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "op_id")
		if r.opState(other.ID).Final != "" || r.opState(o.ID).Final != "" {
			t.Fatal("a result with two different op IDs closed an operation")
		}
	})
	// proof.Verify returns the claims and does not compare the pod, so the plane compares it.
	t.Run("pod_differs_from_token", func(t *testing.T) {
		x := good
		x.Pod = "celld-9"
		want(t, r.one(r.resultItem(x, r.signers[cell1])), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "pod")
		if r.opState(o.ID).Final != "" {
			t.Fatal("a result from another pod closed the operation")
		}
	})
	t.Run("pod_matches_token", func(t *testing.T) {
		want(t, r.one(r.resultItem(good, r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	})
}

func TestReportProofRefusals(t *testing.T) {
	r, _ := boundRig(t)
	other := newSigner(t, "kid-1") // another key under the kid of cell1
	body := op.Status{Cell: cell1, Pod: "celld-0", PodUID: "pod-uid", Seq: 1, At: r.clk.Now()}
	status := func(mod func(*kubetoken.Claims), sig *kubetoken.Signer) mgmtapi.ReportItem {
		return r.item(cell1, "status", body, sig, mod)
	}
	cases := []struct {
		name           string
		item           func() mgmtapi.ReportItem
		reason, detail string
	}{
		{"missing_token", func() mgmtapi.ReportItem {
			it := status(nil, r.signers[cell1])
			it.Token = ""
			return it
		}, mgmtapi.ReasonProofMissing, ""},
		{"foreign_key_unbound_cell", func() mgmtapi.ReportItem {
			b := op.Status{Cell: cell2, Pod: "celld-0", PodUID: "pod-uid", Seq: 1, At: r.clk.Now()}
			return r.item(cell2, "status", b, newSigner(t, "foreign"), nil)
		}, mgmtapi.ReasonNotBound, ""},
		{"other_body", func() mgmtapi.ReportItem {
			it := status(nil, r.signers[cell1])
			it.Body = json.RawMessage(strings.Replace(string(it.Body), `"seq":1`, `"seq":2`, 1))
			return it
		}, mgmtapi.ReasonProofInvalid, "wrong_audience"},
		{"other_kind", func() mgmtapi.ReportItem {
			it := status(nil, r.signers[cell1])
			it.Kind = "result"
			return it
		}, mgmtapi.ReasonProofInvalid, "wrong_audience"},
		{"same_kid_other_key", func() mgmtapi.ReportItem { return status(nil, other) }, mgmtapi.ReasonProofInvalid, "bad_signature"},
		{"same_key_other_issuer", func() mgmtapi.ReportItem {
			return status(func(c *kubetoken.Claims) { c.Issuer = "https://elsewhere.test" }, r.signers[cell1])
		}, mgmtapi.ReasonProofInvalid, "issuer_mismatch"},
		{"argocd_subject", func() mgmtapi.ReportItem {
			return status(func(c *kubetoken.Claims) { c.Namespace, c.ServiceAccount = agent.Namespace, agent.ServiceAccount }, r.signers[cell1])
		}, mgmtapi.ReasonProofInvalid, "subject_mismatch"},
		{"unbound_token", func() mgmtapi.ReportItem {
			return status(func(c *kubetoken.Claims) { c.Unbound = true }, r.signers[cell1])
		}, mgmtapi.ReasonProofInvalid, "not_pod_bound"},
		{"body_cell_mismatch", func() mgmtapi.ReportItem {
			b := op.Status{Cell: cell2, Pod: "celld-0", PodUID: "pod-uid", Seq: 1, At: r.clk.Now()}
			return r.item(cell1, "status", b, r.signers[cell1], nil)
		}, mgmtapi.ReasonPayloadInvalid, "cell"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := r.stateBytes()
			want(t, r.one(c.item()), mgmtapi.OutcomeRefused, c.reason, c.detail)
			if string(r.stateBytes()) != string(before) {
				t.Fatal("a refused item changed the state bytes")
			}
		})
	}
	t.Run("unknown_cell", func(t *testing.T) {
		it := status(nil, r.signers[cell1])
		it.Cell = "dev-cell-9"
		want(t, r.one(it), mgmtapi.OutcomeRefused, mgmtapi.ReasonCellUnknown, "")
	})
	t.Run("unknown_kind", func(t *testing.T) {
		it := status(nil, r.signers[cell1])
		it.Kind = "other"
		want(t, r.one(it), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "kind")
	})
	t.Run("last_refusal_in_status", func(t *testing.T) {
		if lr := cellStatus(r.status(), cell1).LastRefusal; lr == nil || lr.Kind == "" || lr.Reason == "" {
			t.Fatalf("lastRefusal %+v", lr)
		}
	})
}

func TestReportsRetryOnExpiredToken(t *testing.T) {
	r, _ := boundRig(t)
	o, env := r.newOp(cell1)
	res := resultFor(o, env, op.OutcomeApplied)
	old := r.item(cell1, "result", res, r.signers[cell1], func(c *kubetoken.Claims) {
		c.IssuedAt, c.Lifetime = r.clk.Now().Add(-11*time.Minute), 10*time.Minute
	})
	old.OpID = o.ID
	got := r.one(old)
	want(t, got, mgmtapi.OutcomeRetry, mgmtapi.ReasonProofInvalid, "token_expired")
	if r.opState(o.ID).Final != "" || !r.isOpen(o.ID) {
		t.Fatal("an expired token closed the operation")
	}
	want(t, r.one(r.resultItem(res, r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
}

func TestReportsRetryOnUnknownKid(t *testing.T) {
	for name, sig := range map[string]*kubetoken.Signer{
		"rogue_key":       newSigner(t, "kid-rogue"),
		"other_cell_keys": newSigner(t, "kid-cell-2-own"),
	} {
		t.Run(name, func(t *testing.T) {
			r, reader := boundRig(t)
			r.clk.Advance(61 * time.Second)
			body := op.Status{Cell: cell1, Pod: "celld-0", PodUID: "pod-uid", Seq: 1, At: r.clk.Now()}
			calls := r.keys.count(cell1)
			got := r.one(r.item(cell1, "status", body, sig, nil))
			want(t, got, mgmtapi.OutcomeRetry, mgmtapi.ReasonProofInvalid, "unknown_kid")
			r.plane.Wait()
			if n := r.keys.count(cell1) - calls; n != 1 {
				t.Fatalf("the unknown kid queued %d fetches, want 1", n)
			}
			if c := cellStatus(r.status(), cell1); c.LastHintCheck == "" || c.HintAt.IsZero() {
				t.Fatalf("status shows no hint check: %+v", c)
			}
			// A second item in the same minute queues no second check.
			r.one(r.item(cell1, "status", body, sig, nil))
			r.plane.Wait()
			if n := r.keys.count(cell1) - calls; n != 1 {
				t.Fatalf("a second item made %d fetches in all", n)
			}
			if n := counterByAttr(t, reader, "mgmtd.report.retry_unknown_kid", attribute.String("cell", cell1)); n != 2 {
				t.Fatalf("retry_unknown_kid %d, want 2", n)
			}
		})
	}
}

func TestReportStatusRules(t *testing.T) {
	r, _ := boundRig(t)
	send := func(b op.Status, mod func(*kubetoken.Claims)) mgmtapi.ItemOutcome {
		return r.one(r.item(cell1, "status", b, r.signers[cell1], mod))
	}
	st := func(seq uint64) op.Status {
		return op.Status{Cell: cell1, Pod: "celld-0", PodUID: "pod-uid", Seq: seq, At: r.clk.Now(), Unreported: 3, OldestUnreportedAt: r.clk.Now().Add(-time.Minute), Records: 9}
	}
	t.Run("accepted", func(t *testing.T) {
		want(t, send(st(1), nil), mgmtapi.OutcomeAccepted, "", "")
		c := cellStatus(r.status(), cell1)
		if !c.LastStatusAt.Equal(r.clk.Now()) || c.LastStatusPod != "celld-0" || c.Unreported != 3 || c.Records != 9 || c.OldestUnreportedAt.IsZero() {
			t.Fatalf("status %+v", c)
		}
	})
	t.Run("stale_at", func(t *testing.T) {
		b := st(2)
		b.At = r.clk.Now().Add(-2*time.Minute - time.Second)
		want(t, send(b, nil), mgmtapi.OutcomeRefused, mgmtapi.ReasonStale, "at")
		b.At = r.clk.Now().Add(-2 * time.Minute)
		want(t, send(b, nil), mgmtapi.OutcomeAccepted, "", "")
	})
	t.Run("at_in_the_future", func(t *testing.T) {
		b := st(3)
		b.At = r.clk.Now().Add(5 * time.Minute)
		want(t, send(b, nil), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "at_future")
	})
	t.Run("seq_goes_back", func(t *testing.T) {
		want(t, send(st(5), nil), mgmtapi.OutcomeAccepted, "", "")
		want(t, send(st(4), nil), mgmtapi.OutcomeRefused, mgmtapi.ReasonStale, "seq")
		want(t, send(st(5), nil), mgmtapi.OutcomeDuplicate, "", "")
		want(t, send(st(6), nil), mgmtapi.OutcomeAccepted, "", "")
	})
	t.Run("pod_name_differs_from_token", func(t *testing.T) {
		b := st(7)
		b.Pod = "celld-9"
		want(t, send(b, nil), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "pod")
	})
	t.Run("pod_uid_differs_from_token", func(t *testing.T) {
		b := st(7)
		b.PodUID = "other-uid"
		want(t, send(b, nil), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "pod")
	})
	t.Run("ninth_pod_evicts_oldest", func(t *testing.T) {
		for i := range 9 {
			uid := fmt.Sprintf("uid-%d", i)
			b := op.Status{Cell: cell1, Pod: "pod-" + uid, PodUID: uid, Seq: 10, At: r.clk.Now().Add(time.Duration(i) * time.Second)}
			want(t, send(b, func(c *kubetoken.Claims) { c.PodName, c.PodUID = b.Pod, uid }), mgmtapi.OutcomeAccepted, "", "")
		}
		r.plane.rmu.Lock()
		n := len(r.plane.rt.cells[cell1].pods)
		r.plane.rmu.Unlock()
		if n != 8 {
			t.Fatalf("%d pods kept, want 8", n)
		}
		// The evicted pod has no sequence left, so a lower one is taken again. The newest pod keeps its own.
		old := op.Status{Cell: cell1, Pod: "pod-uid-0", PodUID: "uid-0", Seq: 1, At: r.clk.Now()}
		claim := func(name, uid string) func(*kubetoken.Claims) {
			return func(c *kubetoken.Claims) { c.PodName, c.PodUID = name, uid }
		}
		newest := op.Status{Cell: cell1, Pod: "pod-uid-8", PodUID: "uid-8", Seq: 1, At: r.clk.Now()}
		want(t, send(newest, claim("pod-uid-8", "uid-8")), mgmtapi.OutcomeRefused, mgmtapi.ReasonStale, "seq")
		want(t, send(old, claim("pod-uid-0", "uid-0")), mgmtapi.OutcomeAccepted, "", "")
	})
}

func TestReportBindItem(t *testing.T) {
	r, _ := boundRig(t)
	bindItem := func(cell string, nonce string, sig *kubetoken.Signer) mgmtapi.ReportItem {
		req := mgmtapi.BindRequest{Nonce: nonce, Token: r.token(cell, nonce, sig, nil)}
		return mgmtapi.ReportItem{ID: fmt.Sprintf("b-%d", itemSeq.Add(1)), Cell: cell, Kind: "bind", Body: json.RawMessage(marshal(t, req))}
	}
	nonceOf := func(cell string) string {
		for _, c := range r.plane.OpenOps().Cells {
			if c.Name == cell {
				return c.Nonce
			}
		}
		t.Fatalf("no nonce for %s", cell)
		return ""
	}
	n := nonceOf(cell2)
	it := bindItem(cell2, n, r.signers[cell2])
	got := r.one(it)
	if got.Outcome != mgmtapi.OutcomeAccepted || got.Bind == nil || got.Bind.Status != mgmtapi.StatusBound {
		t.Fatalf("bind item %+v", got)
	}
	if !cellStatus(r.status(), cell2).Bound {
		t.Fatal("the bind item did not bind the cell")
	}
	// The same request sent again, under another item ID, gets the stored outcome.
	resend := it
	resend.ID = "resend"
	again := r.one(resend)
	if again.Outcome != mgmtapi.OutcomeAccepted || again.Bind == nil || again.Bind.Status != mgmtapi.StatusBound || again.ID != "resend" {
		t.Fatalf("resent bind item %+v", again)
	}
	// The same nonce with another token is refused, even under the first item ID.
	req2 := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell2, n, r.signers[cell2], func(c *kubetoken.Claims) { c.PodName = "celld-9" })}
	other := mgmtapi.ReportItem{ID: it.ID, Cell: cell2, Kind: "bind", Body: json.RawMessage(marshal(t, req2))}
	refusedAgain := r.one(other)
	want(t, refusedAgain, mgmtapi.OutcomeRefused, mgmtapi.ReasonNonceInvalid, "consumed")
	if refusedAgain.RequestID == "" {
		t.Fatal("a refused bind item has no request ID")
	}
	badBody := mgmtapi.ReportItem{ID: "x", Cell: cell1, Kind: "bind", Body: json.RawMessage(`{"nonce":1}`)}
	want(t, r.one(badBody), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "body")
	unknown := bindItem(cell1, nonceOf(cell1), r.signers[cell1])
	unknown.Cell = "dev-cell-9"
	want(t, r.one(unknown), mgmtapi.OutcomeRefused, mgmtapi.ReasonCellUnknown, "")
}

func TestBindItemDeadlineAnswersRetry(t *testing.T) {
	old := bindItemTimeout
	bindItemTimeout = 50 * time.Millisecond
	t.Cleanup(func() { bindItemTimeout = old })
	r, _ := boundRig(t)
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), cell2
	r.keys.mu.Unlock()
	t.Cleanup(func() {
		r.keys.mu.Lock()
		defer r.keys.mu.Unlock()
		if r.keys.gate != nil {
			close(r.keys.gate)
			r.keys.gate = nil
		}
	})
	n := r.nonce(cell2)
	req := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell2, n, r.signers[cell2], nil)}
	slow := mgmtapi.ReportItem{ID: "slow", Cell: cell2, Kind: "bind", Body: json.RawMessage(marshal(t, req))}
	st := func(seq uint64) mgmtapi.ReportItem {
		return r.item(cell1, "status", op.Status{Cell: cell1, Pod: "celld-0", PodUID: "pod-uid", Seq: seq, At: r.clk.Now()}, r.signers[cell1], nil)
	}
	start := time.Now()
	out := r.plane.Reports(t.Context(), mgmtapi.ReportBatch{Items: []mgmtapi.ReportItem{st(1), slow, st(2)}}).Outcomes
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the batch took %v", time.Since(start))
	}
	want(t, out[0], mgmtapi.OutcomeAccepted, "", "")
	want(t, out[1], mgmtapi.OutcomeRetry, mgmtapi.ReasonIssuerUnavailable, "key_source")
	want(t, out[2], mgmtapi.OutcomeAccepted, "", "")
}

func TestReportItemsIndependent(t *testing.T) {
	r, _ := boundRig(t)
	o1, e1 := r.newOp(cell1)
	o2, e2 := r.newOp(cell1)
	o3, e3 := r.newOp(cell1)
	good := func(o op.Operation, e []byte) mgmtapi.ReportItem {
		return r.resultItem(resultFor(o, e, op.OutcomeApplied), r.signers[cell1])
	}
	bad := good(o2, e2)
	bad.Token = ""
	items := []mgmtapi.ReportItem{
		good(o1, e1), bad,
		{ID: "k", Cell: cell1, Kind: "weird"},
		r.item(cell1, "status", op.Status{Cell: cell1, Pod: "celld-0", PodUID: "pod-uid", Seq: 1, At: r.clk.Now()}, r.signers[cell1], nil),
		good(o3, e3),
	}
	seq := r.plane.snap.Load().st.Seq
	out := r.plane.Reports(t.Context(), mgmtapi.ReportBatch{Items: items}).Outcomes
	want(t, out[0], mgmtapi.OutcomeAccepted, "", "")
	want(t, out[1], mgmtapi.OutcomeRefused, mgmtapi.ReasonProofMissing, "")
	want(t, out[2], mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "kind")
	want(t, out[3], mgmtapi.OutcomeAccepted, "", "")
	want(t, out[4], mgmtapi.OutcomeAccepted, "", "")
	for i, it := range items {
		if out[i].ID != it.ID {
			t.Fatalf("outcome %d has ID %q, want %q", i, out[i].ID, it.ID)
		}
	}
	if got := r.plane.snap.Load().st.Seq; got != seq+1 {
		t.Fatalf("the batch saved the state %d times, want once", got-seq)
	}
	if r.opState(o2.ID).Final != "" || r.opState(o1.ID).Final == "" || r.opState(o3.ID).Final == "" {
		t.Fatal("the items were not independent")
	}
}

func TestResultsInOneBatchCloseOnce(t *testing.T) {
	r, _ := boundRig(t)
	o, e := r.newOp(cell1)
	it := r.resultItem(resultFor(o, e, op.OutcomeApplied), r.signers[cell1])
	second := r.resultItem(resultFor(o, e, op.OutcomeExpired), r.signers[cell1])
	out := r.plane.Reports(t.Context(), mgmtapi.ReportBatch{Items: []mgmtapi.ReportItem{it, second}}).Outcomes
	want(t, out[0], mgmtapi.OutcomeAccepted, "", "")
	want(t, out[1], mgmtapi.OutcomeDuplicate, "", "")
	if r.opState(o.ID).Final != op.OutcomeApplied {
		t.Fatal("the second result of a batch replaced the first")
	}
}

type toggleStore struct {
	Store
	fail atomic.Bool
}

func (f *toggleStore) Save(st *State) error {
	if f.fail.Load() {
		return fmt.Errorf("disk full")
	}
	return f.Store.Save(st)
}

func TestResultsRetryWhenTheSaveFails(t *testing.T) {
	r, _ := boundRig(t)
	fs := &toggleStore{Store: r.store}
	r.store = fs
	r.restart(nil)
	o, e := r.newOp(cell1)
	fs.fail.Store(true)
	want(t, r.one(r.resultItem(resultFor(o, e, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeRetry, "store", "")
	if r.opState(o.ID).Final != "" {
		t.Fatal("a failed save closed the operation")
	}
	fs.fail.Store(false)
	want(t, r.one(r.resultItem(resultFor(o, e, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
}

func TestHintRunsKeyCheck(t *testing.T) {
	r, _ := boundRig(t)
	r.clk.Advance(61 * time.Second)
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], newSigner(t, "kid-b"))
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), cell1
	gate := r.keys.gate
	r.keys.mu.Unlock()
	done := make(chan struct{})
	go func() {
		r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 2), KeyHints: []mgmtapi.KeyHint{{Cell: cell1, At: r.clk.Now()}}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Report waited for the hint check")
	}
	close(gate)
	r.plane.Wait()
	c := cellStatus(r.status(), cell1)
	if c.LastHintCheck != string(CheckKeysUpdated) || !slices.Contains(c.Kids, "kid-b") {
		t.Fatalf("hint check %q, kids %v", c.LastHintCheck, c.Kids)
	}
}

func TestHintFromGatewayHello(t *testing.T) {
	r, _ := boundRig(t)
	r.clk.Advance(61 * time.Second)
	calls := r.keys.count(cell1)
	r.plane.Report(mgmtapi.StatusReport{Gateway: &mgmtapi.GatewayStatus{KeyHints: []mgmtapi.KeyHint{{Cell: cell1}}}})
	r.plane.Wait()
	if r.keys.count(cell1) != calls+1 {
		t.Fatalf("a gateway hint made %d fetches", r.keys.count(cell1)-calls)
	}
}

func TestHintCheckDoesNotStartGap(t *testing.T) {
	r, _ := boundRig(t)
	r.clk.Advance(61 * time.Second)
	r.plane.Report(mgmtapi.StatusReport{KeyHints: []mgmtapi.KeyHint{{Cell: cell1}}})
	r.plane.Wait()
	if got := cellStatus(r.status(), cell1).LastHintCheck; got != string(CheckUnchanged) {
		t.Fatalf("hint check %q", got)
	}
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], newSigner(t, "kid-b"))
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUpdated {
		t.Fatalf("update right after a hint check: %v, %v", res, err)
	}
}

func TestHintFloodBoundedFetches(t *testing.T) {
	r, reader := boundRig(t)
	r.clk.Advance(61 * time.Second)
	calls := r.keys.count(cell1)
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			r.plane.Report(mgmtapi.StatusReport{KeyHints: []mgmtapi.KeyHint{{Cell: cell1}}, Gateway: &mgmtapi.GatewayStatus{KeyHints: []mgmtapi.KeyHint{{Cell: cell1}}}})
		})
	}
	wg.Wait()
	r.plane.Wait()
	if got := r.keys.count(cell1) - calls; got != 1 {
		t.Fatalf("a flood of hints made %d fetches, want 1", got)
	}
	if got := counterByAttr(t, reader, "mgmtd.keycheck.results", attribute.String("via", ViaHint)); got != 1 {
		t.Fatalf("a flood of hints ran %d checks, want 1", got)
	}
	r.clk.Advance(61 * time.Second)
	r.plane.Report(mgmtapi.StatusReport{KeyHints: []mgmtapi.KeyHint{{Cell: cell1}}})
	r.plane.Wait()
	if got := r.keys.count(cell1) - calls; got != 2 {
		t.Fatalf("after 60 s: %d fetches, want 2", got)
	}
}

func TestHintIgnoresUnboundAndUnknown(t *testing.T) {
	r, _ := boundRig(t)
	r.clk.Advance(61 * time.Second)
	before := r.keys.total()
	r.plane.Report(mgmtapi.StatusReport{KeyHints: []mgmtapi.KeyHint{{Cell: cell2}, {Cell: "dev-cell-9"}, {Cell: cell3}}})
	r.plane.Wait()
	if r.keys.total() != before {
		t.Fatal("a hint for an unbound or unknown cell fetched keys")
	}
	if c := cellStatus(r.status(), cell2); !c.HintAt.IsZero() || c.LastHintCheck != "" {
		t.Fatalf("status %+v", c)
	}
}

func TestReportKeepsDroppedAt(t *testing.T) {
	r, _ := boundRig(t)
	t0 := r.clk.Now()
	r.plane.Report(mgmtapi.StatusReport{Gateway: &mgmtapi.GatewayStatus{Epoch: 10, Dropped: 2}})
	if st := r.status(); !st.DroppedAt.IsZero() || !st.EpochChangedAt.IsZero() {
		t.Fatalf("the first report counted as a rise: %+v", st)
	}
	r.clk.Advance(10 * time.Second)
	r.plane.Report(mgmtapi.StatusReport{Gateway: &mgmtapi.GatewayStatus{Epoch: 10, Dropped: 3}})
	rose := t0.Add(10 * time.Second)
	if st := r.status(); !st.DroppedAt.Equal(rose) || !st.EpochChangedAt.IsZero() {
		t.Fatalf("dropped at %v", st.DroppedAt)
	}
	r.clk.Advance(10 * time.Second)
	r.plane.Report(mgmtapi.StatusReport{Gateway: &mgmtapi.GatewayStatus{Epoch: 11, Dropped: 3}})
	st := r.status()
	if !st.DroppedAt.Equal(rose) {
		t.Fatalf("an unchanged count moved droppedAt to %v", st.DroppedAt)
	}
	if !st.EpochChangedAt.Equal(rose.Add(10 * time.Second)) {
		t.Fatalf("epochChangedAt %v", st.EpochChangedAt)
	}
	if st.Gateway == nil || st.Gateway.Epoch != 11 {
		t.Fatalf("gateway %+v", st.Gateway)
	}
	// A time from the gateway wins when it is later.
	gw := rose.Add(15 * time.Second)
	r.plane.Report(mgmtapi.StatusReport{Gateway: &mgmtapi.GatewayStatus{Epoch: 11, Dropped: 4, DroppedAt: gw}})
	if got := r.status().DroppedAt; !got.Equal(gw) {
		t.Fatalf("droppedAt %v, want %v", got, gw)
	}
}

func TestConcurrentReportsAndBinds(t *testing.T) {
	r, _ := boundRig(t)
	const n = 12
	type pair struct {
		o op.Operation
		e []byte
	}
	ops := make([]pair, n)
	for i := range ops {
		ops[i].o, ops[i].e = r.newOp(cell1)
	}
	var wg sync.WaitGroup
	binds := make(chan mgmtapi.ItemOutcome, 4)
	for i := range n {
		wg.Go(func() {
			it := r.resultItem(resultFor(ops[i].o, ops[i].e, op.OutcomeApplied), r.signers[cell1])
			st := r.item(cell1, "status", op.Status{Cell: cell1, Pod: fmt.Sprintf("p%d", i), PodUID: fmt.Sprintf("u%d", i), Seq: 1, At: r.clk.Now()}, r.signers[cell1],
				func(c *kubetoken.Claims) { c.PodName, c.PodUID = fmt.Sprintf("p%d", i), fmt.Sprintf("u%d", i) })
			r.plane.Reports(context.Background(), mgmtapi.ReportBatch{Items: []mgmtapi.ReportItem{it, st}})
			r.plane.OpenOps()
			_ = r.plane.Status()
		})
	}
	for range 4 {
		nonce := r.nonce(cell2)
		req := mgmtapi.BindRequest{Nonce: nonce, Token: r.token(cell2, nonce, r.signers[cell2], nil)}
		bi := mgmtapi.ReportItem{ID: "b", Cell: cell2, Kind: "bind", Body: json.RawMessage(marshal(t, req))}
		wg.Go(func() {
			binds <- r.plane.Reports(context.Background(), mgmtapi.ReportBatch{Items: []mgmtapi.ReportItem{bi}}).Outcomes[0]
		})
	}
	wg.Wait()
	close(binds)
	for o := range binds {
		if o.Outcome != mgmtapi.OutcomeAccepted || o.Bind == nil {
			t.Fatalf("bind outcome %+v", o)
		}
	}
	for _, p := range ops {
		if r.opState(p.o.ID).Final != op.OutcomeApplied {
			t.Fatalf("op %s is not final", p.o.ID)
		}
	}
	if !cellStatus(r.status(), cell2).Bound {
		t.Fatal("cell2 is not bound")
	}
}

func TestBindItemRepeatedAfterNonceTTL(t *testing.T) {
	r, _ := boundRig(t)
	n := r.nonce(cell2)
	req := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell2, n, r.signers[cell2], nil)}
	it := mgmtapi.ReportItem{ID: "a", Cell: cell2, Kind: "bind", Body: json.RawMessage(marshal(t, req))}
	if got := r.one(it); got.Outcome != mgmtapi.OutcomeAccepted {
		t.Fatalf("%+v", got)
	}
	r.clk.Advance(3 * time.Minute)
	it.ID = "b"
	if got := r.one(it); got.Outcome != mgmtapi.OutcomeRefused {
		t.Fatalf("a stored outcome outlived the nonce: %+v", got)
	}
}

func slowBindRig(t *testing.T, itemTimeout, budget time.Duration) *rig {
	t.Helper()
	oi, ob := bindItemTimeout, bindBatchBudget
	bindItemTimeout, bindBatchBudget = itemTimeout, budget
	t.Cleanup(func() { bindItemTimeout, bindBatchBudget = oi, ob })
	r := newRig(t, cell1, cell2, cell3)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), ""
	r.keys.mu.Unlock()
	t.Cleanup(func() {
		r.keys.mu.Lock()
		defer r.keys.mu.Unlock()
		if r.keys.gate != nil {
			close(r.keys.gate)
			r.keys.gate = nil
		}
	})
	return r
}

func (r *rig) bindItem(cell string) mgmtapi.ReportItem {
	n := r.nonce(cell)
	req := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell, n, r.signers[cell], nil)}
	return mgmtapi.ReportItem{ID: fmt.Sprintf("b-%d", itemSeq.Add(1)), Cell: cell, Kind: "bind", Body: json.RawMessage(marshal(r.t, req))}
}

func TestBindItemsOfOneBatchAreBounded(t *testing.T) {
	r := slowBindRig(t, 300*time.Millisecond, time.Second)
	o, e := r.newOp(cell1)
	var items []mgmtapi.ReportItem
	for range 4 {
		items = append(items, r.bindItem(cell2))
	}
	for range 4 {
		items = append(items, r.bindItem(cell3))
	}
	items = append(items, r.resultItem(resultFor(o, e, op.OutcomeApplied), r.signers[cell1]))
	start := time.Now()
	out := r.plane.Reports(t.Context(), mgmtapi.ReportBatch{Items: items}).Outcomes
	if d := time.Since(start); d > 1300*time.Millisecond {
		t.Fatalf("the batch took %v, want at most the budget plus one item deadline", d)
	}
	for i, it := range items[:8] {
		want(t, out[i], mgmtapi.OutcomeRetry, mgmtapi.ReasonIssuerUnavailable, out[i].Detail)
		if out[i].ID != it.ID {
			t.Fatalf("outcome %d has ID %q", i, out[i].ID)
		}
	}
	want(t, out[8], mgmtapi.OutcomeAccepted, "", "")
	for _, c := range []string{cell2, cell3} {
		if n := r.keys.count(c); n != 1 {
			t.Fatalf("%s: %d fetches for four bind items, want 1", c, n)
		}
	}
}

func TestBindBatchBudgetStopsFetches(t *testing.T) {
	r := slowBindRig(t, 5*time.Second, 100*time.Millisecond)
	items := []mgmtapi.ReportItem{r.bindItem(cell2), r.bindItem(cell3)}
	start := time.Now()
	out := r.plane.Reports(t.Context(), mgmtapi.ReportBatch{Items: items}).Outcomes
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the batch took %v", d)
	}
	want(t, out[0], mgmtapi.OutcomeRetry, mgmtapi.ReasonIssuerUnavailable, out[0].Detail)
	want(t, out[1], mgmtapi.OutcomeRetry, mgmtapi.ReasonIssuerUnavailable, out[1].Detail)
	if r.keys.count(cell3) != 0 {
		t.Fatal("a bind item after the budget fetched keys")
	}
}

func TestReportsRetryReasonsAreConstants(t *testing.T) {
	r, _ := boundRig(t)
	fs := &toggleStore{Store: r.store}
	r.store = fs
	r.restart(nil)
	o, e := r.newOp(cell1)
	fs.fail.Store(true)
	got := r.one(r.resultItem(resultFor(o, e, op.OutcomeApplied), r.signers[cell1]))
	want(t, got, mgmtapi.OutcomeRetry, mgmtapi.ReasonStore, "")
}
