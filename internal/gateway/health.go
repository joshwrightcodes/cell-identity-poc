package gateway

import (
	"context"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/metric"
)

const healthTimeout = 3 * time.Second

// NewHealthHandler serves /healthz and /livez. /healthz answers 200 only when the store answers
// one write and the SVID has loaded. /livez answers 200 while the process runs.
func NewHealthHandler(st *Store, svidReady func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if svidReady == nil || !svidReady() {
			http.Error(w, "svid not loaded", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
		defer cancel()
		if err := st.Healthy(ctx); err != nil {
			http.Error(w, "store not healthy", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

// RegisterGauges registers cellgw.queue.depth and cellgw.streams (attribute cell) and
// cellgw.outbox.items. streams may be nil.
func RegisterGauges(m metric.Meter, st *Store, streams func() map[string]int) error {
	depth, err := m.Int64ObservableGauge("cellgw.queue.depth", metric.WithDescription("Operations queued, by cell"))
	if err != nil {
		return err
	}
	open, err := m.Int64ObservableGauge("cellgw.streams", metric.WithDescription("Open celld streams, by cell"))
	if err != nil {
		return err
	}
	outbox, err := m.Int64ObservableGauge("cellgw.outbox.items", metric.WithDescription("Items in the outbox"))
	if err != nil {
		return err
	}
	_, err = m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		ctx, cancel := context.WithTimeout(ctx, healthTimeout)
		defer cancel()
		stats, err := st.Stats(ctx)
		if err != nil {
			return err
		}
		for cell, n := range stats.Queued {
			o.ObserveInt64(depth, int64(n), metric.WithAttributes(cellAttr(cell)))
		}
		o.ObserveInt64(outbox, int64(stats.OutboxItems))
		if streams != nil {
			for cell, n := range streams() {
				o.ObserveInt64(open, int64(n), metric.WithAttributes(cellAttr(cell)))
			}
		}
		return nil
	}, depth, open, outbox)
	return err
}
