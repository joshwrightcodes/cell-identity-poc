package executor

import (
	"context"
	"crypto/tls"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

func testMeter() (*sdkmetric.ManualReader, metric.Meter) {
	reader := sdkmetric.NewManualReader()
	return reader, sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
}

// collect returns the counter values keyed "outcome/reason".
func collect(t *testing.T, reader *sdkmetric.ManualReader, name string) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				o, _ := dp.Attributes.Value("outcome")
				rs, _ := dp.Attributes.Value("reason")
				out[o.AsString()+"/"+rs.AsString()] += dp.Value
			}
		}
	}
	return out
}

func gaugeValue(t *testing.T, reader *sdkmetric.ManualReader, name string) float64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				g := m.Data.(metricdata.Gauge[float64])
				if len(g.DataPoints) != 1 {
					t.Fatalf("%s has %d points", name, len(g.DataPoints))
				}
				return g.DataPoints[0].Value
			}
		}
	}
	t.Fatalf("no metric %s", name)
	return 0
}

type testClock struct{ ns atomic.Int64 }

func (c *testClock) Now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// The age counts from the start before the first frame, rises while no frame arrives, and is 0
// after a frame.
func TestCelldUpstreamAge(t *testing.T) {
	reader, meter := testMeter()
	clk := &testClock{}
	clk.ns.Store(time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC).UnixNano())
	cfg, err := StreamConfig{
		Cell: "cell-1", Upstream: "gw.test:8450", Meter: meter, Now: clk.Now,
		Exec: &Executor{}, Status: func() op.Status { return op.Status{} },
		TLS:    func() (*tls.Config, error) { return nil, nil },
		Tokens: func(context.Context, string) (string, error) { return "", nil },
	}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if got := gaugeValue(t, reader, "celld.upstream.age"); got != 0 {
		t.Fatalf("age %v at the start", got)
	}
	clk.advance(90 * time.Second)
	if got := gaugeValue(t, reader, "celld.upstream.age"); got != 90 {
		t.Fatalf("age %v before the first frame, want 90 since the start", got)
	}

	pr, pw := io.Pipe()
	defer pw.Close()
	l := newLoop(cfg, t.Context(), io.Discard, gwapi.NewDecoder(pr))
	defer func() { _ = pr.Close(); _ = pw.Close(); l.finish() }()
	if err := gwapi.Encode(pw, gwapi.Frame{Type: gwapi.TypePong}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.frames:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop read no frame")
	}
	if got := gaugeValue(t, reader, "celld.upstream.age"); got != 0 {
		t.Fatalf("age %v right after a frame, want 0", got)
	}
	clk.advance(45 * time.Second)
	if got := gaugeValue(t, reader, "celld.upstream.age"); got != 45 {
		t.Fatalf("age %v, want 45 since the frame", got)
	}
}
