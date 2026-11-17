package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/joshwrightcodes/cell-identity-poc/internal/executor"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

// An emergency rotation signs an operation with a key that celld has not loaded yet. The real executor trusts only the old key and
// refuses the envelope. The gateway holds the row instead of dropping it, and when celld rolls and trusts the new key, the next claim
// applies the operation once.
func TestOpUnderNewKeyAppliesAfterCelldRolls(t *testing.T) {
	e := newGwEnv(t)
	start := time.Now()
	var skew atomic.Int64
	e.st.now = func() time.Time { return start.Add(time.Duration(skew.Load())) }
	_, addr := e.serveStream(StreamConfig{})
	e.enqueue(1, cell1) // signed by e.g.priv, the new key

	oldPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset()
	run := func(pod string, keys ...ed25519.PublicKey) (*executor.Executor, func()) {
		ex := executor.New(executor.Config{
			Cell: cell1, Env: "dev", Pod: "celld-" + pod, PodUID: pod, Namespace: executor.DefaultNamespace,
			Keys: keys, Client: client, Log: slog.New(slog.DiscardHandler),
		})
		tokens := func(_ context.Context, audience string) (string, error) {
			return e.kt.Token(t, kubetoken.Claims{Issuer: "https://" + cell1 + ".example", Namespace: testNS, ServiceAccount: testSA,
				PodName: "celld-" + pod, PodUID: pod, NodeName: "node", Audience: []string{audience}}), nil
		}
		svid := e.ca.SVID(t, "spiffe://"+testTD+"/cell/"+cell1+"/celld")
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			done <- executor.RunStream(ctx, executor.StreamConfig{
				Cell: cell1, Upstream: addr, TLS: executor.StreamTLS(staticSource{svid}, e.ca.Bundle(), e.gwID),
				SVIDUpdates: make(chan struct{}), Tokens: tokens, Exec: ex,
				Status: executor.NewStatus(cell1, "celld-"+pod, pod, "test", func() time.Time { return time.Now().Add(time.Hour) }, ex),
				Log:    slog.New(slog.DiscardHandler),
			})
		}()
		return ex, func() { cancel(); <-done }
	}

	// The old pod refuses the envelope: the row stays, and no result of the operation reaches the outbox.
	old, stopOld := run("old", oldPub)
	waitUntil(t, "the old pod to claim and refuse the operation", func() bool {
		row, _ := e.st.QueueEntries(t.Context(), cell1)
		return len(row) == 1 && row[0].Claims >= 1
	})
	stopOld()
	if n, _ := old.Count(t.Context()); n != 0 {
		t.Fatalf("the old pod recorded %d operations, want none", n)
	}
	if d, _ := e.st.Depth(t.Context(), cell1); d != 1 {
		t.Fatalf("queue depth %d after the refusal, want the row held", d)
	}
	items, err := e.st.Peek(t.Context(), 10, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		// The refusal is a result with no operation ID, which mgmtd counts as a forged item. It closes no operation.
		if it.Kind == gwapi.KindResult && it.OpID != "" {
			t.Fatalf("the refusal put a result of an operation into the outbox: %+v", it)
		}
	}

	// celld rolls and trusts the new key. The hold passes, and the next claim applies the operation once.
	skew.Store(int64(ForgedHold + time.Second))
	fresh, stopFresh := run("fresh", e.g.pub)
	defer stopFresh()
	waitUntil(t, "the new pod to apply the operation", func() bool {
		n, _ := fresh.Count(t.Context())
		return n == 1
	})
	waitUntil(t, "the row to end", func() bool {
		d, _ := e.st.Depth(t.Context(), cell1)
		return d == 0
	})
	var applied int
	items, _ = e.st.Peek(t.Context(), 10, 1<<20)
	for _, it := range items {
		if it.Kind == gwapi.KindResult && it.OpID == opID(1) {
			applied++
		}
	}
	if applied != 1 {
		t.Fatalf("%d results of the operation in the outbox, want 1", applied)
	}
}
