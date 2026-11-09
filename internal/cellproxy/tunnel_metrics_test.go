package cellproxy

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// metricValue returns the value of the int64 point of name whose attributes hold every value in
// want, and whether there is one.
func metricValue(t *testing.T, reader *sdkmetric.ManualReader, name string, want map[string]string) (int64, bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	match := func(set attribute.Set) bool {
		for k, v := range want {
			got, ok := set.Value(attribute.Key(k))
			if !ok || got.Emit() != v {
				return false
			}
		}
		return true
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch d := m.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, p := range d.DataPoints {
					if match(p.Attributes) {
						return p.Value, true
					}
				}
			case metricdata.Sum[int64]:
				for _, p := range d.DataPoints {
					if match(p.Attributes) {
						return p.Value, true
					}
				}
			}
		}
	}
	return 0, false
}

// waitMetric waits up to 5 seconds for the point of name with want to have value v.
func waitMetric(t *testing.T, reader *sdkmetric.ManualReader, name string, want map[string]string, v int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, ok := metricValue(t, reader, name, want)
		if ok && got == v {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s%v is %d (present %v), want %d", name, want, got, ok, v)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTunnelMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tm, err := NewTunnelMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv := signerKey(t)
	reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub}, priv, cell("dev-cell-1", false), cell("dev-cell-2", false)))
	if err != nil {
		t.Fatal(err)
	}
	h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 300 * time.Millisecond, cells: []string{"dev-cell-1", "dev-cell-2"}, registry: reg, metrics: tm})
	const up, connects, refused, responses = "cell_proxy.tunnel.up", "cell_proxy.tunnel.connects", "cell_proxy.tunnel.refused_requests", "cell_proxy.tunnel.responses"

	waitMetric(t, reader, up, map[string]string{"side": "hub", "cell": "dev-cell-1"}, 0)
	waitMetric(t, reader, up, map[string]string{"side": "hub", "cell": "dev-cell-2"}, 0)

	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	waitMetric(t, reader, up, map[string]string{"side": "hub", "cell": "dev-cell-1"}, 1)
	waitMetric(t, reader, up, map[string]string{"side": "cell", "upstream": h.server}, 1)
	waitMetric(t, reader, connects, map[string]string{"side": "hub", "cell": "dev-cell-1", "result": "accepted", "replaced": "false"}, 1)
	waitMetric(t, reader, connects, map[string]string{"side": "cell", "result": "connected"}, 1)

	code, body := h.get(t, "/api/v1/nodes")
	assertDenied(t, code, body)
	waitMetric(t, reader, refused, map[string]string{"side": "cell", "reason": "request_not_allowed"}, 1)
	waitMetric(t, reader, responses, map[string]string{"side": "hub", "cell": "dev-cell-1", "status": "403"}, 1)

	if code, body := getURL(t, h.hubURLs["dev-cell-2"]+"/api/v1/pods", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("dev-cell-2: status %d, body %s", code, body)
	}
	waitMetric(t, reader, refused, map[string]string{"side": "hub", "cell": "dev-cell-2", "reason": "upstream_unavailable"}, 1)

	h.accepted.dropAll()
	waitMetric(t, reader, up, map[string]string{"side": "cell", "upstream": h.server}, 0)
	h.waitTunnels(t, 2, 5*time.Second)
	waitMetric(t, reader, connects, map[string]string{"side": "cell", "result": "connected"}, 2)
}
