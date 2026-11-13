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
