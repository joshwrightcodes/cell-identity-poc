package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gateway"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// The loop prunes at the period that it gets, and the period keeps an outcome for at most a minute
// longer than the retention of the store.
func TestPruneLoopRemovesOldOutcomes(t *testing.T) {
	if pruneEvery > time.Minute {
		t.Fatalf("pruneEvery %v, want at most a minute", pruneEvery)
	}
	var offset atomic.Int64
	base := time.Now()
	now := func() time.Time { return base.Add(time.Duration(offset.Load())) }
	st, err := gateway.Open(t.Context(), filepath.Join(t.TempDir(), "queue.db"), gwapi.NewNotifier(), now, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	id, err := st.Append(t.Context(), gwapi.Item{Kind: gwapi.KindResult, Cell: "dev-cell-1", OpID: "", Body: json.RawMessage(`{}`), Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Ack(t.Context(), []mgmtapi.ItemOutcome{{ID: string(id), Outcome: mgmtapi.OutcomeAccepted}}); err != nil {
		t.Fatal(err)
	}
	offset.Store(int64(gateway.OutcomeRetention + time.Second))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { pruneLoop(ctx, st, slog.New(slog.DiscardHandler), 10*time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, found, err := st.Outcome(t.Context(), "dev-cell-1", id); err == nil && !found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the loop did not prune the old outcome")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
