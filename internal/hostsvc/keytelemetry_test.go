package hostsvc

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

func sumFor(t *testing.T, rm metricdata.ResourceMetrics, name, key, value string) int64 {
	t.Helper()
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is not an int64 sum", name)
			}
			for _, dp := range sum.DataPoints {
				if key == "" {
					total += dp.Value
				} else if v, ok := dp.Attributes.Value(attribute.Key(key)); ok && v.AsString() == value {
					total += dp.Value
				}
			}
		}
	}
	return total
}

func TestKeyHandlerEmitsSpansAndMetrics(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	clock := newFakeClock()
	l := &lookups{}
	cache := NewKeyCache(l.facts, KeyTTL, KeyMaxInFlight, clock.Now)
	h, err := NewInstrumentedKeyHandler(cache, knownCells, newDiscardLogger(), tp.Tracer("t"), mp.Meter("m"))
	if err != nil {
		t.Fatal(err)
	}
	path := mgmtapi.KeysPath("dev-cell-1")
	get(h, http.MethodGet, path)                      // miss
	get(h, http.MethodGet, path)                      // hit
	get(h, http.MethodGet, path)                      // hit
	get(h, http.MethodGet, mgmtapi.KeysPath("rogue")) // unknown cluster
	get(h, http.MethodPost, path)                     // method
	l.err = errors.New("docker is down")
	clock.Advance(2 * KeyTTL)
	get(h, http.MethodGet, path) // failed lookup

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for outcome, want := range map[string]int64{"served": 3, "unknown_cluster": 1, "method_not_allowed": 1, "lookup_failed": 1} {
		if got := sumFor(t, rm, "hostsvc.key.requests", "outcome", outcome); got != want {
			t.Errorf("requests with outcome %s = %d, want %d", outcome, got, want)
		}
	}
	if got := sumFor(t, rm, "hostsvc.key.cache.hits", "", ""); got != 2 {
		t.Errorf("cache hits = %d, want 2", got)
	}
	if ok, bad := sumFor(t, rm, "hostsvc.key.lookups", "result", "ok"), sumFor(t, rm, "hostsvc.key.lookups", "result", "error"); ok != 1 || bad != 1 {
		t.Errorf("lookups ok = %d, error = %d, want 1 and 1", ok, bad)
	}
	spans := rec.Ended()
	if len(spans) != 6 {
		t.Fatalf("%d spans, want 6", len(spans))
	}
	var failed int
	for _, s := range spans {
		if s.Name() != "hostsvc.keys" {
			t.Errorf("span name = %q", s.Name())
		}
		for _, a := range s.Attributes() {
			if a.Key == "outcome" && a.Value.AsString() == "lookup_failed" {
				failed++
				if s.Status().Code.String() != "Error" {
					t.Errorf("failed span status = %v", s.Status())
				}
			}
		}
	}
	if failed != 1 {
		t.Errorf("%d spans with outcome lookup_failed, want 1", failed)
	}
}
