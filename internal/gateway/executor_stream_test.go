package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/joshwrightcodes/cell-identity-poc/internal/executor"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

// The real executor.RunStream talks to the real StreamHandler over TLS: claim, apply, result, ack of
// the item, and the final frame that ends the record. Each side is otherwise tested only against a
// fake of the other.
func TestExecutorStreamAgainstTheGatewayHandler(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	env := e.enqueue(1, cell1)

	client := fake.NewClientset()
	ex := executor.New(executor.Config{
		Cell: cell1, Env: "dev", Pod: "celld-pod-a", PodUID: "pod-a", Namespace: executor.DefaultNamespace,
		Keys: []ed25519.PublicKey{e.g.pub}, Client: client, Log: slog.New(slog.DiscardHandler),
	})
	var mu sync.Mutex
	minted := map[string]bool{}
	tokens := func(_ context.Context, audience string) (string, error) {
		mu.Lock()
		minted[audience] = true
		mu.Unlock()
		return e.kt.Token(t, kubetoken.Claims{Issuer: "https://" + cell1 + ".example", Namespace: testNS, ServiceAccount: testSA,
			PodName: "celld-pod-a", PodUID: "pod-a", NodeName: "node", Audience: []string{audience}}), nil
	}
	svid := e.ca.SVID(t, "spiffe://"+testTD+"/cell/"+cell1+"/celld")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- executor.RunStream(ctx, executor.StreamConfig{
			Cell: cell1, Upstream: addr, TLS: executor.StreamTLS(staticSource{svid}, e.ca.Bundle(), e.gwID),
			SVIDUpdates: make(chan struct{}), Tokens: tokens, Exec: ex,
			Status: executor.NewStatus(cell1, "celld-pod-a", "pod-a", "test", func() time.Time { return time.Now().Add(time.Hour) }, ex),
			Log:    slog.New(slog.DiscardHandler),
		})
	}()
	defer func() { cancel(); <-done }()

	// The gateway holds the result of the op in its outbox.
	var item gwapi.OutItem
	waitUntil(t, "the result in the outbox", func() bool {
		items, err := e.st.Peek(t.Context(), 10, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if it.Kind == gwapi.KindResult {
				item = it
				return true
			}
		}
		return false
	})
	if item.OpID != opID(1) || item.Cell != cell1 {
		t.Fatalf("outbox item %+v", item)
	}
	var res op.Result
	if err := json.Unmarshal(item.Body, &res); err != nil {
		t.Fatal(err)
	}
	if res.Outcome != op.OutcomeApplied || res.OpID != opID(1) || res.Pod != "celld-pod-a" || res.EnvelopeSHA256 != op.EnvelopeSHA256(env) {
		t.Fatalf("result %+v", res)
	}
	if res.Fence.Epoch == 0 || res.Fence.Counter == 0 {
		t.Fatalf("the result carries no fence: %+v", res.Fence)
	}
	mu.Lock()
	covered := minted[proof.ReportAudience(cell1, gwapi.KindResult, item.Body)]
	mu.Unlock()
	if !covered || item.Token == "" {
		t.Fatal("the item token does not cover the body that the gateway holds")
	}
	// The row is done, and the op ran once.
	if d, _ := e.st.Depth(t.Context(), cell1); d != 0 {
		t.Fatalf("queue depth %d after the result", d)
	}
	if n, _ := ex.Count(t.Context()); n != 1 {
		t.Fatalf("%d records", n)
	}
	if p, _ := ex.Pending(t.Context()); len(p) != 1 {
		t.Fatalf("%d pending results before the verdict, want 1", len(p))
	}

	// The management plane accepts the result. The gateway forwards a final frame, and celld ends the record.
	if err := e.st.Ack(t.Context(), []mgmtapi.ItemOutcome{{ID: string(item.ID), Outcome: mgmtapi.OutcomeAccepted}}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the record to be reported", func() bool {
		p, _ := ex.Pending(t.Context())
		return len(p) == 0
	})
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
