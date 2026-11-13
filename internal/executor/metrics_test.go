package executor

import (
	"testing"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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
