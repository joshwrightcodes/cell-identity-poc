package e2e

// The OTLP builder of the synthetic series of the M15 alert test. This file has no build tag, so the pure test at its end runs with no
// cluster (go test -run TestM15SyntheticNames ./test/e2e/). The push through curl is in m15_alerts_test.go.

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/dashboards"
)

// m15Synth is one synthetic series. Instrument is the OTel name of an instrument of the catalogue, or the Prometheus name of a third-party
// metric. Resource holds resource attributes (platform.cell and k8s.cluster.name are promoted to labels), and Attrs holds data point
// attributes. Every series also gets the resource attribute service.name=m15-synthetic, which the panels and the variables leave out.
type m15Synth struct {
	Instrument string
	Value      float64
	Resource   map[string]string
	Attrs      map[string]string
}

// m15Instrument looks the metric up in the catalogue and returns its OTel name, kind and unit.
func m15Instrument(name string) (kind, unit string, ok bool) {
	for _, m := range dashboards.Catalogue {
		if m.Instrument == name || (m.ThirdParty && m.Prom == name) {
			return m.Kind, m.Unit, true
		}
	}
	return "", "", false
}

func m15KV(m map[string]string) []*commonpb.KeyValue {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []*commonpb.KeyValue
	for _, k := range keys {
		out = append(out, &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: m[k]}}})
	}
	return out
}

// m15Request encodes the series as one OTLP metrics request. A counter is a cumulative sum that started at start, and a gauge is a gauge.
func m15Request(series []m15Synth, start, now time.Time) ([]byte, error) {
	req := &colmetrics.ExportMetricsServiceRequest{}
	for _, s := range series {
		kind, unit, ok := m15Instrument(s.Instrument)
		if !ok {
			return nil, fmt.Errorf("the catalogue has no metric %q", s.Instrument)
		}
		res := map[string]string{"service.name": dashboards.SyntheticService}
		for k, v := range s.Resource {
			res[k] = v
		}
		dp := &metricspb.NumberDataPoint{
			Attributes:        m15KV(s.Attrs),
			StartTimeUnixNano: uint64(start.UnixNano()),
			TimeUnixNano:      uint64(now.UnixNano()),
			Value:             &metricspb.NumberDataPoint_AsDouble{AsDouble: s.Value},
		}
		m := &metricspb.Metric{Name: s.Instrument, Unit: unit}
		switch kind {
		case dashboards.KindGauge:
			m.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{dp}}}
		case dashboards.KindCounter:
			m.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{
				DataPoints: []*metricspb.NumberDataPoint{dp}, IsMonotonic: true,
				AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
			}}
		default:
			return nil, fmt.Errorf("the metric %q has the kind %q, which the builder does not write", s.Instrument, kind)
		}
		req.ResourceMetrics = append(req.ResourceMetrics, &metricspb.ResourceMetrics{
			Resource:     &resourcepb.Resource{Attributes: m15KV(res)},
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{m}}},
		})
	}
	return proto.Marshal(req)
}

func TestM15SyntheticNames(t *testing.T) {
	want := map[string]string{
		"celld.svid.remaining": "celld_svid_remaining_seconds", "celld.svid.lifetime": "celld_svid_lifetime_seconds",
		"celld.upstream.age": "celld_upstream_age_seconds", "trust.ca.not_after": "trust_ca_not_after_seconds",
		"cluster_jwt.attestations": "cluster_jwt_attestations_total", "bundle.apply.outcomes": "bundle_apply_outcomes_total",
		"cellproxy.gateway.attribute.overwrites": "cellproxy_gateway_attribute_overwrites_total", "cell_proxy.tunnel.up": "cell_proxy_tunnel_up",
		"otelcol_exporter_queue_size": "otelcol_exporter_queue_size", "otelcol_exporter_queue_capacity": "otelcol_exporter_queue_capacity",
	}
	for instrument, prom := range want {
		kind, unit, ok := m15Instrument(instrument)
		if !ok {
			t.Errorf("the catalogue has no %s", instrument)
			continue
		}
		if got := dashboards.PromName(instrument, kind, unit)[0]; got != prom && instrument != prom {
			t.Errorf("%s becomes %s, want %s", instrument, got, prom)
		}
	}
	now := time.Now()
	body, err := m15Request([]m15Synth{
		{Instrument: "celld.upstream.age", Value: 200, Resource: map[string]string{"platform.cell": "m15-ab"}},
		{Instrument: "cluster_jwt.attestations", Value: 20, Resource: map[string]string{"k8s.cluster.name": "dev-cp"}, Attrs: map[string]string{"result": "refused"}},
	}, now.Add(-time.Minute), now)
	if err != nil || len(body) == 0 {
		t.Fatalf("encode: %d bytes, %v", len(body), err)
	}
	var back colmetrics.ExportMetricsServiceRequest
	if err := proto.Unmarshal(body, &back); err != nil || len(back.ResourceMetrics) != 2 {
		t.Fatalf("decode: %v, %d resources", err, len(back.ResourceMetrics))
	}
	if _, err := m15Request([]m15Synth{{Instrument: "no.such.metric"}}, now, now); err == nil {
		t.Error("an unknown metric gave no error")
	}
}
