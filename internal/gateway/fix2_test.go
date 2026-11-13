package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// A revocation that commits between the record check and the claim gives no lease.
func TestStreamClaimRaceWithRevocation(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{})
	h.beforeClaim = func() { e.applyRevoked(2, true) }
	e.enqueue(1, cell1)
	c := e.join(addr, cell1, "uid-a")
	c.send(gwapi.Frame{Type: gwapi.TypeClaim})
	for {
		f, err := c.recv(frameWait)
		if err != nil {
			t.Fatalf("no refusal: %v", err)
		}
		if f.Type == gwapi.TypeLease {
			t.Fatalf("a lease after the revocation committed: %+v", f)
		}
		if f.Type == gwapi.TypeRefused && f.Reason == gwapi.ReasonCellRevoked {
			return
		}
	}
}

func TestClaimLiveChecksTheRecord(t *testing.T) {
	e := newGwEnv(t)
	ctx := context.Background()
	e.enqueue(1, cell1)
	e.enqueue(2, "dev-cell-3")
	if l, err := e.st.ClaimLive(ctx, cell1, "p"); err != nil || l == nil {
		t.Fatalf("live cell: %+v, %v", l, err)
	}
	if _, err := e.st.ClaimLive(ctx, "dev-cell-3", "p"); !errors.Is(err, ErrCellNotLive) {
		t.Fatalf("a cell without a record: %v", err)
	}
	e.applyRevoked(2, true)
	e.enqueue(3, cell1)
	if l, err := e.st.ClaimLive(ctx, cell1, "p"); !errors.Is(err, ErrCellNotLive) || l != nil {
		t.Fatalf("a revoked cell: %+v, %v", l, err)
	}
	if n, _ := e.st.Depth(ctx, cell1); n != 2 {
		t.Fatalf("depth %d: a refused claim must not change the queue", n)
	}
}

// The 1 s tick alone ends a quiet stream of a revoked cell.
func TestStreamTickEndsQuietStreamOfRevokedCell(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	c := e.join(addr, cell1, "uid-a")
	e.applyRevoked(2, true)
	f, err := c.recv(2500 * time.Millisecond)
	if err != nil || f.Type != gwapi.TypeRefused || f.Reason != gwapi.ReasonCellRevoked {
		t.Fatalf("frame %+v, %v", f, err)
	}
}

// A displacement victim must hold a status item.
func TestOutboxDisplacementVictimHoldsAStatus(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.s.maxBytes = 3000
	f.appendItem(item(gwapi.KindResult, cell1, opID(1), 1000))
	f.appendItem(item(gwapi.KindResult, cell1, opID(2), 1000))
	keep := f.appendItem(item(gwapi.KindStatus, "dev-cell-3", "", 400))
	res, err := f.s.Append(ctx, item(gwapi.KindResult, cell2, opID(3), 400))
	if err != nil {
		t.Fatalf("a result with a displaceable status item in the outbox: %v", err)
	}
	got, _ := f.s.Peek(ctx, 20, 1<<20)
	have := map[gwapi.ItemID]bool{}
	for _, it := range got {
		have[it.ID] = true
	}
	if !have[res] || have[keep] || len(got) != 3 {
		t.Fatalf("outbox %d items; result stored %v, status kept %v", len(got), have[res], have[keep])
	}
}

// O-1: the atomic copy follows the stored epoch after concurrent raises.
func TestRaiseEpochConcurrentKeepsTheCopy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	base := f.s.Epoch()
	for round := uint64(0); round < 300; round++ {
		var wg sync.WaitGroup
		for k := uint64(1); k <= 2; k++ {
			wg.Go(func() { _ = f.s.RaiseEpoch(ctx, op.Fence{Epoch: base + round*10 + k}) })
		}
		wg.Wait()
		var stored int64
		if err := f.s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'epoch'`).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if uint64(stored) != f.s.Epoch() {
			t.Fatalf("round %d: stored epoch %d, copy %d", round, stored, f.s.Epoch())
		}
	}
}

// N-1: a flush error under telemetry.Handler reaches the stream, so a retry is not forgotten.
func TestStreamFlushErrorKeepsRetry(t *testing.T) {
	e := newGwEnv(t)
	h := NewStreamHandler(e.st, StreamConfig{})
	ctx := context.Background()
	id, err := e.st.Append(ctx, resultItem(cell1, opID(2)))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Ack(ctx, []mgmtapi.ItemOutcome{{ID: string(id), Outcome: mgmtapi.OutcomeRetry}}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	srv := httptest.NewUnstartedServer(telemetry.Handler(sdktrace.NewTracerProvider().Tracer("t"), "x", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		w.WriteHeader(http.StatusOK)
		_ = rc.Flush()
		<-r.Context().Done() // the client reset the stream
		o := out{w: w, rc: rc}
		_, err := h.forward(context.Background(), cell1, 0, o.send)
		result <- err
	})))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.NextProtos = []string{"h2"}
	_ = tls.VersionTLS13
	rctx, cancel := context.WithCancel(ctx)
	req, _ := http.NewRequestWithContext(rctx, http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	resp.Body.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("forward reported success for a frame that the HTTP/2 layer refused")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not run")
	}
	var again []gwapi.Frame
	if _, err := h.forward(ctx, cell1, 0, func(f gwapi.Frame) error { again = append(again, f); return nil }); err != nil || len(again) != 1 || again[0].Type != gwapi.TypeRetry {
		t.Fatalf("the retry is gone after a failed flush: %+v, %v", again, err)
	}
}
