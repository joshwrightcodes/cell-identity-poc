package mgmt

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func testMeter() (*sdkmetric.ManualReader, metric.Meter) {
	reader := sdkmetric.NewManualReader()
	return reader, sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
}

// collect flattens the metrics to "name/result" keys. A metric with no result attribute has the key
// "name/".
func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	val := func(set attribute.Set) string {
		v, _ := set.Value("result")
		return v.AsString()
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, p := range d.DataPoints {
					out[m.Name+"/"+val(p.Attributes)] += p.Value
				}
			case metricdata.Gauge[int64]:
				for _, p := range d.DataPoints {
					out[m.Name+"/"+val(p.Attributes)] = p.Value
				}
			}
		}
	}
	return out
}

// cellStates reads the series of mgmtd.cell.state as "cell/valid/revoked/reason" keys.
func cellStates(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	return cellStatesOf(rm)
}

func cellStatesOf(rm metricdata.ResourceMetrics) map[string]int64 {
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok || m.Name != "mgmtd.cell.state" {
				continue
			}
			for _, p := range g.DataPoints {
				get := func(k string) string {
					v, _ := p.Attributes.Value(attribute.Key(k))
					return v.Emit()
				}
				out[get("cell")+"/"+get("valid")+"/"+get("revoked")+"/"+get("reason")] = p.Value
			}
		}
	}
	return out
}

// valueOf returns the value of the attribute-less gauge name in rm.
func valueOf(rm metricdata.ResourceMetrics, name string) int64 {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if g, ok := m.Data.(metricdata.Gauge[int64]); ok && m.Name == name && len(g.DataPoints) == 1 {
				return g.DataPoints[0].Value
			}
		}
	}
	return -1
}
