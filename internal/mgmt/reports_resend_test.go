package mgmt

import (
	"crypto/ed25519"
	"log/slog"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/joshwrightcodes/cell-identity-poc/internal/executor"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

// Pod A applies an operation and pod B resends the stored result. The management plane takes the
// resend, because the result names the pod that sends it.
func TestReportsResendFromAnotherPod(t *testing.T) {
	r, _ := boundRig(t)
	o, env := r.newOp(cell1)
	client := fake.NewClientset()
	exec := func(pod, uid string) *executor.Executor {
		return executor.New(executor.Config{
			Cell: cell1, Env: "dev", Pod: pod, PodUID: uid, Client: client, Now: r.clk.Now,
			Keys: []ed25519.PublicKey{r.plane.PublicKey()}, Log: slog.New(slog.DiscardHandler),
		})
	}
	a, b := exec("celld-a", "uid-a"), exec("celld-b", "uid-b")
	if res := a.Execute(r.t.Context(), env, op.Fence{Epoch: 1, Counter: 1}); res.Outcome != op.OutcomeApplied {
		t.Fatalf("apply on pod A: %+v", res)
	}
	pending, err := b.Pending(r.t.Context())
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending on pod B: %+v, %v", pending, err)
	}
	it := r.item(cell1, "result", pending[0], r.signers[cell1], func(c *kubetoken.Claims) { c.PodName, c.PodUID = "celld-b", "uid-b" })
	it.OpID = o.ID
	want(t, r.one(it), mgmtapi.OutcomeAccepted, "", "")
	if st := r.opState(o.ID); st.Final != op.OutcomeApplied {
		t.Fatalf("final = %q, want applied", st.Final)
	}
}
