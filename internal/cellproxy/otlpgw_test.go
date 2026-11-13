package cellproxy

import (
	"bytes"
	stdgzip "compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	otelID1     = "spiffe://dev.env.poc.internal/cell/dev-cell-1/otel"
	cpOtelID    = "spiffe://dev.env.poc.internal/cp/otel"
	otelPattern = `^spiffe://dev\.env\.poc\.internal/(cell/[a-z0-9-]+|cp)/otel$`
)

func mustSource(t *testing.T, id string) Source {
	t.Helper()
	s, err := parse(id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func str(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func integer(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}}
}

// attrMap gives each key and its values as strings, "int:<n>" for an integer.
func attrMap(attrs []*commonpb.KeyValue) map[string][]string {
	m := map[string][]string{}
	for _, kv := range attrs {
		v := kv.GetValue().GetStringValue()
		if _, ok := kv.GetValue().GetValue().(*commonpb.AnyValue_IntValue); ok {
			v = "int:" + strconv.FormatInt(kv.GetValue().GetIntValue(), 10)
		}
		m[kv.GetKey()] = append(m[kv.GetKey()], v)
	}
	return m
}

func wantAttrs(t *testing.T, got []*commonpb.KeyValue, want map[string]string) {
	t.Helper()
	m := attrMap(got)
	w := map[string][]string{}
	for k, v := range want {
		w[k] = []string{v}
	}
	if !maps.EqualFunc(m, w, slices.Equal) {
		t.Fatalf("attributes are %v, want %v", m, w)
	}
}

func cellAttrs(cell string) map[string]string {
	return map[string]string{"k8s.cluster.name": cell, "platform.plane": "cell", "deployment.environment.name": "dev", "platform.cell": cell}
}

func TestSourceAttributes(t *testing.T) {
	cases := map[string]map[string]string{
		otelID1:  cellAttrs("dev-cell-1"),
		cpOtelID: {"k8s.cluster.name": "dev-cp", "platform.plane": "environment", "deployment.environment.name": "dev"},
	}
	for id, want := range cases {
		t.Run(id, func(t *testing.T) {
			if got := SourceAttributes(mustSource(t, id)); !maps.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestResetResourceCountsChanges(t *testing.T) {
	r := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		str("service.name", "collector"), str("k8s.cluster.name", "dev-cell-2"), str("platform.plane", "cell"),
		str("deployment.environment.name", "dev"), str("platform.cell", "dev-cell-2"),
	}}
	changed := ResetResource(r, mustSource(t, otelID1))
	want := cellAttrs("dev-cell-1")
	want["service.name"] = "collector"
	wantAttrs(t, r.Attributes, want)
	if !slices.Equal(changed, []string{"k8s.cluster.name", "platform.cell"}) {
		t.Fatalf("changed is %v, want [k8s.cluster.name platform.cell]", changed)
	}
}

func TestResetResourceSetsAbsentKeysSilently(t *testing.T) {
	r := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("service.name", "collector")}}
	changed := ResetResource(r, mustSource(t, otelID1))
	want := cellAttrs("dev-cell-1")
	want["service.name"] = "collector"
	wantAttrs(t, r.Attributes, want)
	if len(changed) != 0 {
		t.Fatalf("changed is %v, want none", changed)
	}
}

// TestResetResourceEdgeCases runs each resource through the gateway reset of a logs request,
// because only the holder of a nil resource can give it a new one.
func TestResetResourceEdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		in      *resourcepb.Resource
		changed []string
	}{
		{"nil resource", nil, nil},
		{"duplicate keys with the verified value", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			str("k8s.cluster.name", "dev-cell-1"), str("k8s.cluster.name", "dev-cell-1"),
		}}, nil},
		{"duplicate keys with another value", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			str("k8s.cluster.name", "dev-cell-1"), str("k8s.cluster.name", "dev-cell-2"),
		}}, []string{"k8s.cluster.name"}},
		{"integer platform.plane", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{integer("platform.plane", 1)}}, []string{"platform.plane"}},
		{"underscore form of platform.cell", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			str("platform.cell", "dev-cell-1"), str("platform_cell", "dev-cell-2"),
		}}, []string{"platform.cell"}},
		{"underscore form with the verified value", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			str("platform_cell", "dev-cell-1"),
		}}, []string{"platform.cell"}},
		{"upper case Platform.Cell", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			str("Platform.Cell", "dev-cell-2"),
		}}, []string{"platform.cell"}},
		{"map platform={cell}", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			kvl("platform", str("cell", "dev-cell-2")),
		}}, []string{"platform.cell"}},
		{"map k8s={cluster={name}}", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			kvl("k8s", kvl("cluster", str("name", "dev-cell-2"))),
		}}, []string{"k8s.cluster.name"}},
		{"leading separator _platform={cell}", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			kvl("_platform", str("cell", "dev-cell-2")),
		}}, []string{"platform.cell"}},
		{"trailing separator platform={cell_}", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			kvl("platform", str("cell_", "dev-cell-2")),
		}}, []string{"platform.cell"}},
		{"both ends .platform.cell_", &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			str(".platform.cell_", "dev-cell-2"),
		}}, []string{"platform.cell"}},
	}
	src := mustSource(t, otelID1)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rl := &logspb.ResourceLogs{Resource: c.in}
			ows := resetLogs(&collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{rl}}, src)
			if rl.Resource == nil {
				t.Fatal("the resource is still nil")
			}
			wantAttrs(t, rl.Resource.Attributes, cellAttrs("dev-cell-1"))
			var changed []string
			for _, o := range ows {
				if o.Level != LevelResource {
					t.Fatalf("overwrite %+v is not at the resource level", o)
				}
				changed = append(changed, o.Attribute)
			}
			if !slices.Equal(changed, c.changed) {
				t.Fatalf("changed is %v, want %v", changed, c.changed)
			}
		})
	}
}

func TestEnvironmentSenderLosesCellAttribute(t *testing.T) {
	r := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		str("k8s.cluster.name", "dev-cp"), str("platform.plane", "environment"),
		str("deployment.environment.name", "dev"), str("platform.cell", "dev-cell-1"),
	}}
	changed := ResetResource(r, mustSource(t, cpOtelID))
	wantAttrs(t, r.Attributes, map[string]string{"k8s.cluster.name": "dev-cp", "platform.plane": "environment", "deployment.environment.name": "dev"})
	if !slices.Equal(changed, []string{"platform.cell"}) {
		t.Fatalf("changed is %v, want [platform.cell]", changed)
	}
}

func mapValue(kvs ...*commonpb.KeyValue) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: kvs}}}
}

// kvl is an attribute whose value is a map.
func kvl(k string, kvs ...*commonpb.KeyValue) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: mapValue(kvs...)}
}

// arr is an attribute whose value is an array.
func arr(k string, vs ...*commonpb.AnyValue) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: vs}}}}
}

// spoofSets builds nested attribute sets that each hold spoofed source keys and other keys, and
// remembers each set so the test can check it after the strip. In the flat form the source keys
// are attribute keys. In the map form they are entries of map values, also in an array.
type spoofSets struct {
	maps bool
	sets []*[]*commonpb.KeyValue
	want []Overwrite
}

func (s *spoofSets) attrs(level string) []*commonpb.KeyValue {
	if !s.maps {
		s.want = append(s.want, Overwrite{Level: level, Attribute: "platform.cell"}, Overwrite{Level: level, Attribute: "k8s.cluster.name"})
		return []*commonpb.KeyValue{str("platform_cell", "dev-cell-2"), str("keep", "yes"), str("k8s.cluster.name", "dev-cell-2")}
	}
	s.want = append(s.want, Overwrite{Level: level, Attribute: "platform.cell"}, Overwrite{Level: level, Attribute: "k8s.cluster.name"},
		Overwrite{Level: level, Attribute: "deployment.environment.name"})
	return []*commonpb.KeyValue{
		kvl("platform", str("cell", "dev-cell-2")),
		str("keep", "yes"),
		kvl("k8s", kvl("cluster", str("name", "dev-cell-2")), str("version", "1.37")),
		arr("deployment", mapValue(str("environment.name", "prod"))),
	}
}

func (s *spoofSets) track(p *[]*commonpb.KeyValue) { s.sets = append(s.sets, p) }

// checkMaps checks a set of the map form: platform is gone, k8s keeps only version, and the array
// element of deployment is an empty map.
func checkMaps(t *testing.T, attrs []*commonpb.KeyValue) {
	t.Helper()
	var keys []string
	for _, kv := range attrs {
		keys = append(keys, kv.GetKey())
		switch kv.GetKey() {
		case "k8s":
			inner := kv.GetValue().GetKvlistValue().GetValues()
			if len(inner) != 1 || inner[0].GetKey() != "version" {
				t.Fatalf("k8s is %v, want only version", kv.GetValue())
			}
		case "deployment":
			elems := kv.GetValue().GetArrayValue().GetValues()
			if len(elems) != 1 || len(elems[0].GetKvlistValue().GetValues()) != 0 {
				t.Fatalf("deployment is %v, want one empty map", kv.GetValue())
			}
		}
	}
	if !slices.Equal(keys, []string{"keep", "k8s", "deployment"}) {
		t.Fatalf("keys are %v, want [keep k8s deployment]", keys)
	}
}

func (s *spoofSets) check(t *testing.T, deleted []Overwrite) {
	t.Helper()
	for _, p := range s.sets {
		if s.maps {
			checkMaps(t, *p)
		} else {
			wantAttrs(t, *p, map[string]string{"keep": "yes"})
		}
	}
	sortOverwrites := func(o []Overwrite) []Overwrite {
		o = slices.Clone(o)
		slices.SortFunc(o, func(a, b Overwrite) int { return strings.Compare(a.Level+a.Attribute, b.Level+b.Attribute) })
		return o
	}
	if got, want := sortOverwrites(deleted), sortOverwrites(s.want); !slices.Equal(got, want) {
		t.Fatalf("deleted is %v, want %v", got, want)
	}
}

func spoofedLogs(s *spoofSets) *collogspb.ExportLogsServiceRequest {
	scope := &commonpb.InstrumentationScope{Name: "s", Attributes: s.attrs(LevelScope)}
	rec := &logspb.LogRecord{Attributes: s.attrs(LevelRecord)}
	s.track(&scope.Attributes)
	s.track(&rec.Attributes)
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{Scope: scope, LogRecords: []*logspb.LogRecord{rec}}},
	}}}
}

func spoofedTraces(s *spoofSets) *coltracepb.ExportTraceServiceRequest {
	scope := &commonpb.InstrumentationScope{Name: "s", Attributes: s.attrs(LevelScope)}
	ev := &tracepb.Span_Event{Name: "e", Attributes: s.attrs(LevelRecord)}
	link := &tracepb.Span_Link{Attributes: s.attrs(LevelRecord)}
	span := &tracepb.Span{Name: "span", Attributes: s.attrs(LevelRecord), Events: []*tracepb.Span_Event{ev}, Links: []*tracepb.Span_Link{link}}
	for _, p := range []*[]*commonpb.KeyValue{&scope.Attributes, &span.Attributes, &ev.Attributes, &link.Attributes} {
		s.track(p)
	}
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		ScopeSpans: []*tracepb.ScopeSpans{{Scope: scope, Spans: []*tracepb.Span{span}}},
	}}}
}

func spoofedMetrics(s *spoofSets) *colmetricspb.ExportMetricsServiceRequest {
	scope := &commonpb.InstrumentationScope{Name: "s", Attributes: s.attrs(LevelScope)}
	s.track(&scope.Attributes)
	exemplar := func() []*metricspb.Exemplar {
		e := &metricspb.Exemplar{FilteredAttributes: s.attrs(LevelDatapoint)}
		s.track(&e.FilteredAttributes)
		return []*metricspb.Exemplar{e}
	}
	number := &metricspb.NumberDataPoint{Attributes: s.attrs(LevelDatapoint), Exemplars: exemplar()}
	sum := &metricspb.NumberDataPoint{Attributes: s.attrs(LevelDatapoint), Exemplars: exemplar()}
	hist := &metricspb.HistogramDataPoint{Attributes: s.attrs(LevelDatapoint), Exemplars: exemplar()}
	exp := &metricspb.ExponentialHistogramDataPoint{Attributes: s.attrs(LevelDatapoint), Exemplars: exemplar()}
	summary := &metricspb.SummaryDataPoint{Attributes: s.attrs(LevelDatapoint)}
	for _, p := range []*[]*commonpb.KeyValue{&number.Attributes, &sum.Attributes, &hist.Attributes, &exp.Attributes, &summary.Attributes} {
		s.track(p)
	}
	gauge := &metricspb.Metric{Name: "g", Metadata: s.attrs(LevelRecord), Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{number}}}}
	s.track(&gauge.Metadata)
	return &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		ScopeMetrics: []*metricspb.ScopeMetrics{{Scope: scope, Metrics: []*metricspb.Metric{
			gauge,
			{Name: "s", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: []*metricspb.NumberDataPoint{sum}}}},
			{Name: "h", Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{DataPoints: []*metricspb.HistogramDataPoint{hist}}}},
			{Name: "e", Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{DataPoints: []*metricspb.ExponentialHistogramDataPoint{exp}}}},
			{Name: "q", Data: &metricspb.Metric_Summary{Summary: &metricspb.Summary{DataPoints: []*metricspb.SummaryDataPoint{summary}}}},
		}}},
	}}}
}

func TestGatewayStripsNestedSourceAttributes(t *testing.T) {
	cases := map[string]func(*spoofSets) any{
		"logs":    func(s *spoofSets) any { return spoofedLogs(s) },
		"spans":   func(s *spoofSets) any { return spoofedTraces(s) },
		"metrics": func(s *spoofSets) any { return spoofedMetrics(s) },
	}
	for name, build := range cases {
		for _, maps := range []bool{false, true} {
			form := "flat"
			if maps {
				form = "map"
			}
			t.Run(name+" "+form, func(t *testing.T) {
				s := &spoofSets{maps: maps}
				req := build(s)
				s.check(t, StripNestedSource(req))
			})
		}
	}
}

func TestMeshLabelsCollapseOtherForms(t *testing.T) {
	cases := []struct {
		name    string
		in      []*commonpb.KeyValue
		changed []string
	}{
		{"duplicate with the same value", []*commonpb.KeyValue{str("source_cluster", "dev-cell-1"), str("source_cluster", "dev-cell-1")}, nil},
		{"duplicate with another value", []*commonpb.KeyValue{str("source_cluster", "dev-cell-1"), str("source_cluster", "dev-cell-2")}, []string{"source_cluster"}},
		{"other form source.cluster", []*commonpb.KeyValue{str("source_cluster", "dev-cell-1"), str("source.cluster", "dev-cell-2")}, []string{"source_cluster"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &metricspb.NumberDataPoint{Attributes: c.in}
			rm := &metricspb.ResourceMetrics{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
				Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{p}}},
			}}}}}
			changed := ResetMeshLabels(rm, mustSource(t, otelID1))
			wantAttrs(t, p.Attributes, map[string]string{"source_cluster": "dev-cell-1"})
			if !slices.Equal(changed, c.changed) {
				t.Fatalf("changed is %v, want %v", changed, c.changed)
			}
		})
	}
}

func TestMeshLabelsReset(t *testing.T) {
	type pointSet = func(attrs []*commonpb.KeyValue) (*metricspb.Metric, func() []*commonpb.KeyValue)
	types := map[string]pointSet{
		"gauge": func(a []*commonpb.KeyValue) (*metricspb.Metric, func() []*commonpb.KeyValue) {
			p := &metricspb.NumberDataPoint{Attributes: a}
			return &metricspb.Metric{Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{p}}}}, func() []*commonpb.KeyValue { return p.Attributes }
		},
		"sum": func(a []*commonpb.KeyValue) (*metricspb.Metric, func() []*commonpb.KeyValue) {
			p := &metricspb.NumberDataPoint{Attributes: a}
			return &metricspb.Metric{Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: []*metricspb.NumberDataPoint{p}}}}, func() []*commonpb.KeyValue { return p.Attributes }
		},
		"histogram": func(a []*commonpb.KeyValue) (*metricspb.Metric, func() []*commonpb.KeyValue) {
			p := &metricspb.HistogramDataPoint{Attributes: a}
			return &metricspb.Metric{Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{DataPoints: []*metricspb.HistogramDataPoint{p}}}}, func() []*commonpb.KeyValue { return p.Attributes }
		},
		"exponential histogram": func(a []*commonpb.KeyValue) (*metricspb.Metric, func() []*commonpb.KeyValue) {
			p := &metricspb.ExponentialHistogramDataPoint{Attributes: a}
			return &metricspb.Metric{Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{DataPoints: []*metricspb.ExponentialHistogramDataPoint{p}}}}, func() []*commonpb.KeyValue { return p.Attributes }
		},
		"summary": func(a []*commonpb.KeyValue) (*metricspb.Metric, func() []*commonpb.KeyValue) {
			p := &metricspb.SummaryDataPoint{Attributes: a}
			return &metricspb.Metric{Data: &metricspb.Metric_Summary{Summary: &metricspb.Summary{DataPoints: []*metricspb.SummaryDataPoint{p}}}}, func() []*commonpb.KeyValue { return p.Attributes }
		},
	}
	senders := []struct{ id, spoof, want string }{
		{otelID1, "dev-cell-2", "dev-cell-1"},
		{cpOtelID, "dev-cell-1", "dev-cp"},
	}
	for name, build := range types {
		for _, s := range senders {
			t.Run(name+" "+s.id, func(t *testing.T) {
				m, attrs := build([]*commonpb.KeyValue{
					str("source_cluster", s.spoof), str("destination_cluster", "unknown"), str("request_protocol", "http"),
				})
				rm := &metricspb.ResourceMetrics{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{m}}}}
				changed := ResetMeshLabels(rm, mustSource(t, s.id))
				wantAttrs(t, attrs(), map[string]string{"source_cluster": s.want, "destination_cluster": "unknown", "request_protocol": "http"})
				if !slices.Equal(changed, []string{"source_cluster"}) {
					t.Fatalf("changed is %v, want [source_cluster]", changed)
				}
			})
		}
	}
}

// otlpUpstream is a fake OTLP receiver behind the gateway.
type otlpUpstream struct {
	mu       sync.Mutex
	logs     []*collogspb.ExportLogsServiceRequest
	traces   []*coltracepb.ExportTraceServiceRequest
	metrics  []*colmetricspb.ExportMetricsServiceRequest
	logsResp *collogspb.ExportLogsServiceResponse
	// block, when not nil, holds each call until it closes or the call ends.
	block chan struct{}
	// fail, when not nil, is the answer to each call.
	fail     error
	calls    atomic.Int64
	inflight atomic.Int64
	// deadlines holds the time that each call had left when it arrived.
	deadlines []time.Duration
}

func (u *otlpUpstream) enter(ctx context.Context) error {
	u.calls.Add(1)
	if dl, ok := ctx.Deadline(); ok {
		u.mu.Lock()
		u.deadlines = append(u.deadlines, time.Until(dl))
		u.mu.Unlock()
	}
	if u.fail != nil {
		return u.fail
	}
	if u.block == nil {
		return nil
	}
	u.inflight.Add(1)
	defer u.inflight.Add(-1)
	select {
	case <-u.block:
		return nil
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	}
}

type upLogs struct {
	collogspb.UnimplementedLogsServiceServer
	u *otlpUpstream
}

func (s upLogs) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	if err := s.u.enter(ctx); err != nil {
		return nil, err
	}
	s.u.mu.Lock()
	defer s.u.mu.Unlock()
	s.u.logs = append(s.u.logs, req)
	if s.u.logsResp != nil {
		return s.u.logsResp, nil
	}
	return &collogspb.ExportLogsServiceResponse{}, nil
}

type upTraces struct {
	coltracepb.UnimplementedTraceServiceServer
	u *otlpUpstream
}

func (s upTraces) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	if err := s.u.enter(ctx); err != nil {
		return nil, err
	}
	s.u.mu.Lock()
	defer s.u.mu.Unlock()
	s.u.traces = append(s.u.traces, req)
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type upMetrics struct {
	colmetricspb.UnimplementedMetricsServiceServer
	u *otlpUpstream
}

func (s upMetrics) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	if err := s.u.enter(ctx); err != nil {
		return nil, err
	}
	s.u.mu.Lock()
	defer s.u.mu.Unlock()
	s.u.metrics = append(s.u.metrics, req)
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

// gwHarness runs the fake upstream and a gateway in front of it, with a manual metric reader.
type gwHarness struct {
	up     *otlpUpstream
	gw     *Gateway
	reader *sdkmetric.ManualReader
	log    *syncBuffer
	// client is the plaintext address of spiffe-client after serve.
	client string
}

func newGWHarness(t *testing.T, up *otlpUpstream) *gwHarness {
	t.Helper()
	s := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(s, upLogs{u: up})
	coltracepb.RegisterTraceServiceServer(s, upTraces{u: up})
	colmetricspb.RegisterMetricsServiceServer(s, upMetrics{u: up})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient("passthrough:///"+ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	out := &syncBuffer{}
	gw, err := NewGateway(conn, mp.Meter("test"), jsonLog(out))
	if err != nil {
		t.Fatal(err)
	}
	return &gwHarness{up: up, gw: gw, reader: reader, log: out}
}

// serve runs the gateway behind spiffe-server with the otlp backend and allow, and spiffe-client
// with the SVID id. It returns a gRPC connection to spiffe-client.
func (h *gwHarness) serve(t *testing.T, allow, id string, opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	telemetryID := "spiffe://mgmt.poc.internal/telemetry"
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewOTLPBackend(h.gw, MaxRecvMsgBytes)
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log := jsonLog(h.log)
	srv := NewServer(ServerConfig{
		TLS: ServerTLS(source(mgmt.svid(t, telemetryID)), env.bundle(), regexp.MustCompile(allow), testRegistry(t), log),
	}, backend, log)
	srvDone := make(chan struct{})
	go func() { _ = srv.Serve(ctx, srvLn); close(srvDone) }()

	cliLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cli := &Client{TLS: ClientTLS(source(env.svid(t, id)), mgmt.bundle(), spiffeIDOf(telemetryID)), Upstream: srvLn.Addr().String(), Log: jsonLog(&syncBuffer{})}
	cliDone := make(chan struct{})
	go func() { _ = cli.Serve(ctx, cliLn); close(cliDone) }()
	h.client = cliLn.Addr().String()

	opts = append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, opts...)
	conn, err := grpc.NewClient("passthrough:///"+cliLn.Addr().String(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		sctx, scancel := context.WithTimeout(context.Background(), time.Second)
		defer scancel()
		backend.(*otlpBackend).Shutdown(sctx)
		cancel()
		<-cliDone
		<-srvDone
	})
	return conn
}

// peerContext is the context of a call from a TLS peer with the SVID id.
func peerContext(t *testing.T, id string) context.Context {
	t.Helper()
	svid := newCA(t, envTD).svid(t, id)
	return peer.NewContext(t.Context(), &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: svid.Certificates}},
	})
}

// counterPoints returns the overwrite counter as attribute set and value.
func (h *gwHarness) counterPoints(t *testing.T) map[attribute.Distinct]int64 {
	return h.points(t, OverwriteCounterName)
}

// points returns the int64 data points of the metric name as attribute set and value.
func (h *gwHarness) points(t *testing.T, name string) map[attribute.Distinct]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := h.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[attribute.Distinct]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range d.DataPoints {
					got[dp.Attributes.Equivalent()] = dp.Value
				}
			case metricdata.Gauge[int64]:
				for _, dp := range d.DataPoints {
					got[dp.Attributes.Equivalent()] = dp.Value
				}
			}
		}
	}
	return got
}

func attrSet(kv ...attribute.KeyValue) attribute.Distinct {
	set := attribute.NewSet(kv...)
	return set.Equivalent()
}

func overwriteKey(attr, level, cluster string) attribute.Distinct {
	set := attribute.NewSet(attribute.String("attribute", attr), attribute.String("level", level), attribute.String("sender.cluster", cluster))
	return set.Equivalent()
}

func spoofedResource() *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		str("service.name", "app"), str("k8s.cluster.name", "dev-cell-2"), str("platform.plane", "cell"),
		str("deployment.environment.name", "dev"), str("platform.cell", "dev-cell-1"),
	}}
}

func TestGatewayForwardsAllSignals(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	conn := h.serve(t, otelPattern, otelID1)
	ctx := t.Context()

	logs := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: spoofedResource(),
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "hello"}}, Attributes: []*commonpb.KeyValue{str("platform_cell", "dev-cell-2")},
		}}}},
	}}}
	if _, err := collogspb.NewLogsServiceClient(conn).Export(ctx, logs); err != nil {
		t.Fatal(err)
	}
	traces := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   spoofedResource(),
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "span"}}}},
	}}}
	if _, err := coltracepb.NewTraceServiceClient(conn).Export(ctx, traces); err != nil {
		t.Fatal(err)
	}
	point := &metricspb.NumberDataPoint{Attributes: []*commonpb.KeyValue{str("source_cluster", "dev-cell-2")}}
	metrics := &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: spoofedResource(),
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "istio_requests_total", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: []*metricspb.NumberDataPoint{point}}},
		}}}},
	}}}
	if _, err := colmetricspb.NewMetricsServiceClient(conn).Export(ctx, metrics); err != nil {
		t.Fatal(err)
	}

	want := cellAttrs("dev-cell-1")
	want["service.name"] = "app"
	h.up.mu.Lock()
	if len(h.up.logs) != 1 || len(h.up.traces) != 1 || len(h.up.metrics) != 1 {
		h.up.mu.Unlock()
		t.Fatalf("upstream got %d logs, %d traces and %d metrics requests, want one each", len(h.up.logs), len(h.up.traces), len(h.up.metrics))
	}
	gotLogs, gotTraces, gotMetrics := h.up.logs[0], h.up.traces[0], h.up.metrics[0]
	h.up.mu.Unlock()
	wantAttrs(t, gotLogs.ResourceLogs[0].Resource.Attributes, want)
	wantAttrs(t, gotTraces.ResourceSpans[0].Resource.Attributes, want)
	wantAttrs(t, gotMetrics.ResourceMetrics[0].Resource.Attributes, want)
	rec := gotLogs.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if rec.Body.GetStringValue() != "hello" || len(rec.Attributes) != 0 {
		t.Fatalf("upstream log record is %v", rec)
	}
	if got := gotTraces.ResourceSpans[0].ScopeSpans[0].Spans[0].Name; got != "span" {
		t.Fatalf("upstream span name is %q", got)
	}
	wantAttrs(t, gotMetrics.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].GetSum().DataPoints[0].Attributes, map[string]string{"source_cluster": "dev-cell-1"})

	wantCounts := map[attribute.Distinct]int64{
		overwriteKey("k8s.cluster.name", LevelResource, "dev-cell-1"): 3,
		overwriteKey("platform.cell", LevelRecord, "dev-cell-1"):      1,
		overwriteKey("source_cluster", LevelDatapoint, "dev-cell-1"):  1,
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := h.counterPoints(t)
		if maps.Equal(got, wantCounts) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counter is %v, want %v", got, wantCounts)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestGatewayPassesPartialSuccess(t *testing.T) {
	partial := &collogspb.ExportLogsPartialSuccess{RejectedLogRecords: 2, ErrorMessage: "two records are too old"}
	h := newGWHarness(t, &otlpUpstream{logsResp: &collogspb.ExportLogsServiceResponse{PartialSuccess: partial}})
	conn := h.serve(t, otelPattern, otelID1)
	resp, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{}, {}, {}}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(resp.GetPartialSuccess(), partial) {
		t.Fatalf("partial_success is %v, want %v", resp.GetPartialSuccess(), partial)
	}
}

// logsOfSize is a logs request with one record whose wire size is size bytes.
func logsOfSize(t *testing.T, size int) *collogspb.ExportLogsServiceRequest {
	t.Helper()
	build := func(n int) *collogspb.ExportLogsServiceRequest {
		body := &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: strings.Repeat("a", n)}}
		return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{Body: body}}}},
		}}}
	}
	n := size - (proto.Size(build(size)) - size)
	req := build(n)
	if got := proto.Size(req); got != size {
		t.Fatalf("request has %d bytes, want %d", got, size)
	}
	return req
}

func TestGatewayReceiveLimit(t *testing.T) {
	sizes := []struct {
		name string
		size int
		code codes.Code
	}{
		{"64 KiB below the limit", MaxRecvMsgBytes - 64<<10, codes.OK},
		{"1 KiB above the limit", MaxRecvMsgBytes + 1<<10, codes.ResourceExhausted},
		{"9 MiB", 9 << 20, codes.ResourceExhausted},
	}
	compressions := map[string][]grpc.CallOption{"plain": nil, "gzip": {grpc.UseCompressor(gzip.Name)}}
	for _, sz := range sizes {
		for cname, opts := range compressions {
			t.Run(sz.name+" "+cname, func(t *testing.T) {
				h := newGWHarness(t, &otlpUpstream{})
				conn := h.serve(t, otelPattern, otelID1)
				_, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), logsOfSize(t, sz.size), opts...)
				if status.Code(err) != sz.code {
					t.Fatalf("got %v, want %v", err, sz.code)
				}
				want := int64(0)
				if sz.code == codes.OK {
					want = 1
				}
				if n := h.up.calls.Load(); n != want {
					t.Fatalf("upstream got %d calls, want %d", n, want)
				}
			})
		}
	}
}

func TestGatewayRefusesGrowthPastUpstreamLimit(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	longCell := "spiffe://dev.env.poc.internal/cell/" + strings.Repeat("a", 59) + "/otel"
	points := make([]*metricspb.NumberDataPoint, 40000)
	for i := range points {
		points[i] = &metricspb.NumberDataPoint{Attributes: []*commonpb.KeyValue{str("source_cluster", "x"), str("destination_cluster", "y")}}
	}
	req := &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "istio_requests_total", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: points}},
		}}}},
	}}}
	if size := proto.Size(req); size > MaxRecvMsgBytes {
		t.Fatalf("the request has %d bytes, more than the receive limit", size)
	}
	_, err := h.gw.ExportMetrics(peerContext(t, longCell), req)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("got %v, want ResourceExhausted", err)
	}
	waitForLog(t, h.log, "request denied", RequestTooLarge, "")
	if n := h.up.calls.Load(); n != 0 {
		t.Fatalf("upstream got %d calls, want none", n)
	}
}

func TestSlotPoolSharesSlots(t *testing.T) {
	p := newSlotPool(maxGatewayCalls, maxSenderCalls)
	senders := []string{"dev-cell-1", "dev-cell-2", "dev-cell-3", "dev-cp"}
	for _, s := range senders {
		for i := range maxSenderCalls {
			if !p.take(s) {
				t.Fatalf("%s could not take slot %d", s, i+1)
			}
		}
		if p.take(s) {
			t.Fatalf("%s took more than its share of %d", s, maxSenderCalls)
		}
	}
	if p.take("dev-cell-4") {
		t.Fatal("a fifth sender took a slot when all 16 are taken")
	}
	p.give("dev-cell-1")
	if !p.take("dev-cell-4") {
		t.Fatal("a fifth sender could not take a freed slot")
	}
	if p.take("dev-cell-1") {
		t.Fatal("dev-cell-1 took a slot when all 16 are taken")
	}
}

func TestGatewayOverload(t *testing.T) {
	block := make(chan struct{})
	h := newGWHarness(t, &otlpUpstream{block: block})
	timeout := 500 * time.Millisecond
	h.gw.timeout = timeout
	client := collogspb.NewLogsServiceClient(h.serve(t, otelPattern, otelID1))
	export := func() error {
		_, err := client.Export(t.Context(), &collogspb.ExportLogsServiceRequest{})
		return err
	}
	slotsUsed := func() int64 {
		return h.points(t, "cellproxy.gateway.slots.used")[attrSet(attribute.String("sender.cluster", "dev-cell-1"))]
	}

	start := time.Now()
	errs := make(chan error, maxSenderCalls)
	for range maxSenderCalls {
		go func() { errs <- export() }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.up.inflight.Load() != maxSenderCalls {
		if time.Now().After(deadline) {
			t.Fatalf("%d calls reached the upstream, want %d", h.up.inflight.Load(), maxSenderCalls)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := slotsUsed(); n != maxSenderCalls {
		t.Fatalf("slots used is %d, want %d", n, maxSenderCalls)
	}

	extra := time.Now()
	err := export()
	if st, _ := status.FromError(err); st.Code() != codes.Unavailable || st.Message() != "denied" {
		t.Fatalf("call %d of one sender gave %v, want Unavailable with only \"denied\"", maxSenderCalls+1, err)
	}
	if d := time.Since(extra); d > 200*time.Millisecond {
		t.Fatalf("call %d took %v, want it to fail at once", maxSenderCalls+1, d)
	}
	if n := h.gw.codec.decoded.Load(); n != maxSenderCalls {
		t.Fatalf("the codec decoded %d messages, want %d: the refused call must not be read", n, maxSenderCalls)
	}
	waitForLog(t, h.log, "request denied", Overloaded, "")

	for range maxSenderCalls {
		select {
		case err := <-errs:
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("a blocked call gave %v, want Unavailable", err)
			}
		case <-time.After(10 * timeout):
			close(block)
			t.Fatalf("a blocked call still runs %v after its %v deadline", 10*timeout, timeout)
		}
	}
	if d := time.Since(start); d < timeout {
		t.Fatalf("the blocked calls ended after %v, before the %v deadline", d, timeout)
	}
	waitForLog(t, h.log, "upstream failed", UpstreamUnavailable, "")
	deadline = time.Now().Add(5 * time.Second)
	for slotsUsed() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("slots used is %d after the calls ended, want 0", slotsUsed())
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(block)
	if err := export(); err != nil {
		t.Fatalf("a call after the blocked calls ended gave %v", err)
	}
}

// rawMessage is wire bytes that rawCodec sends as they are.
type rawMessage struct{ b []byte }

type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	return mem.BufferSlice{mem.SliceBuffer(v.(*rawMessage).b)}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	return proto.Unmarshal(data.Materialize(), v.(proto.Message))
}

// nest wraps b in field num, once for each number, innermost first.
func nest(b []byte, nums ...protowire.Number) []byte {
	for _, n := range nums {
		b = protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), b)
	}
	return b
}

// bombs are logs requests just below the receive limit, made of empty messages of 2 wire bytes
// each: empty resources, and empty attributes of one log record.
func bombs() map[string][]byte {
	n := (MaxRecvMsgBytes - 64) / 2
	return map[string][]byte{
		"empty resources":  bytes.Repeat([]byte{0x0a, 0x00}, n),
		"empty attributes": nest(bytes.Repeat([]byte{0x32, 0x00}, n), 2, 2, 1),
	}
}

func TestGatewayRefusesDecodeBomb(t *testing.T) {
	for name, bomb := range bombs() {
		t.Run(name, func(t *testing.T) {
			h := newGWHarness(t, &otlpUpstream{})
			conn := h.serve(t, otelPattern, otelID1)
			var zipped bytes.Buffer
			zw := stdgzip.NewWriter(&zipped)
			_, _ = zw.Write(bomb)
			_ = zw.Close()

			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			err := conn.Invoke(t.Context(), "/opentelemetry.proto.collector.logs.v1.LogsService/Export", &rawMessage{b: bomb},
				&collogspb.ExportLogsServiceResponse{}, grpc.ForceCodecV2(rawCodec{}), grpc.UseCompressor(gzip.Name))
			took := time.Since(start)
			runtime.ReadMemStats(&after)
			alloc := after.TotalAlloc - before.TotalAlloc
			t.Logf("wire=%d bytes gzip=%d bytes took=%v total_alloc=%d KiB", len(bomb), zipped.Len(), took, alloc>>10)

			if status.Code(err) != codes.ResourceExhausted {
				t.Fatalf("got %v, want ResourceExhausted", err)
			}
			if took > 2*time.Second {
				t.Fatalf("the refusal took %v, want less than 2s", took)
			}
			if alloc > 64<<20 {
				t.Fatalf("the call allocated %d MiB, want less than 64 MiB", alloc>>20)
			}
			if n := h.gw.codec.decoded.Load(); n != 0 {
				t.Fatalf("the codec decoded %d messages, want none", n)
			}
			waitForLog(t, h.log, "request denied", RequestTooLarge, "")
			if n := h.up.calls.Load(); n != 0 {
				t.Fatalf("upstream got %d calls, want none", n)
			}
		})
	}
}

func TestOTLPCodecScanAllocations(t *testing.T) {
	c := newOTLPCodec()
	for name, bomb := range bombs() {
		t.Run(name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(5, func() {
				req := &collogspb.ExportLogsServiceRequest{}
				if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(bomb)}, req); err != nil {
					t.Fatal(err)
				}
				if c.refusal(req) == nil {
					t.Fatal("the codec accepted the bomb")
				}
			})
			t.Logf("allocations per refused bomb: %v", allocs)
			if allocs > 20 {
				t.Fatalf("%v allocations per refused bomb, want at most 20", allocs)
			}
		})
	}
	t.Run("largest allowed shape", func(t *testing.T) {
		kvs := bytes.Repeat([]byte{0x32, 0x00}, defaultScanLimits.Attributes)
		rec := protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), kvs)
		records := (defaultScanLimits.Messages - 16) / (defaultScanLimits.Attributes + 1)
		wire := nest(bytes.Repeat(rec, records), 2, 1)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		req := &collogspb.ExportLogsServiceRequest{}
		if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire)}, req); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		if err := c.refusal(req); err != nil {
			t.Fatalf("the codec refused the largest allowed shape: %v", err)
		}
		t.Logf("wire=%d bytes messages=%d total_alloc=%d MiB", len(wire), records*(defaultScanLimits.Attributes+1)+2, (after.TotalAlloc-before.TotalAlloc)>>20)
	})
}

func TestGatewayForwardDeadline(t *testing.T) {
	cases := []struct {
		name     string
		deadline time.Duration
		min, max time.Duration
		code     codes.Code
	}{
		{"no deadline of the sender", 0, 2500 * time.Millisecond, 3 * time.Second, codes.OK},
		{"sender deadline 2.5s", 2500 * time.Millisecond, time.Second, 1500 * time.Millisecond, codes.OK},
		{"sender deadline below the margin", 500 * time.Millisecond, 0, 0, codes.DeadlineExceeded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newGWHarness(t, &otlpUpstream{})
			h.gw.timeout = 3 * time.Second
			ctx := peerContext(t, otelID1)
			if c.deadline > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, c.deadline)
				defer cancel()
			}
			_, err := h.gw.ExportLogs(ctx, &collogspb.ExportLogsServiceRequest{})
			if status.Code(err) != c.code {
				t.Fatalf("got %v, want %v", err, c.code)
			}
			h.up.mu.Lock()
			defer h.up.mu.Unlock()
			if c.code != codes.OK {
				if len(h.up.deadlines) != 0 {
					t.Fatalf("upstream got %d calls, want none", len(h.up.deadlines))
				}
				return
			}
			if len(h.up.deadlines) != 1 || h.up.deadlines[0] < c.min || h.up.deadlines[0] > c.max {
				t.Fatalf("upstream deadlines are %v, want one between %v and %v", h.up.deadlines, c.min, c.max)
			}
		})
	}
}

func TestGatewayMetrics(t *testing.T) {
	logs := attribute.String("signal", "logs")
	cell1 := attribute.String("sender.cluster", "dev-cell-1")
	t.Run("accepted and last export", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		before := time.Now().Unix()
		if _, err := h.gw.ExportLogs(peerContext(t, otelID1), &collogspb.ExportLogsServiceRequest{}); err != nil {
			t.Fatal(err)
		}
		if got := h.points(t, "cellproxy.gateway.exports.accepted"); !maps.Equal(got, map[attribute.Distinct]int64{attrSet(logs, cell1): 1}) {
			t.Fatalf("accepted is %v", got)
		}
		last := h.points(t, "cellproxy.gateway.last_export.time")[attrSet(logs, cell1)]
		if last < before || last > time.Now().Unix() {
			t.Fatalf("last export time is %d, want between %d and now", last, before)
		}
	})
	t.Run("upstream failure", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{fail: status.Error(codes.Unavailable, "store down")})
		if _, err := h.gw.ExportLogs(peerContext(t, otelID1), &collogspb.ExportLogsServiceRequest{}); status.Code(err) != codes.Unavailable {
			t.Fatalf("got %v, want Unavailable", err)
		}
		want := map[attribute.Distinct]int64{attrSet(logs, attribute.String("code", "Unavailable")): 1}
		if got := h.points(t, "cellproxy.gateway.upstream.failures"); !maps.Equal(got, want) {
			t.Fatalf("failures are %v", got)
		}
	})
	t.Run("denied", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		if _, err := h.gw.ExportLogs(t.Context(), &collogspb.ExportLogsServiceRequest{}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("got %v, want PermissionDenied", err)
		}
		want := map[attribute.Distinct]int64{attrSet(logs, attribute.String("reason", string(PeerNotAllowed))): 1}
		if got := h.points(t, "cellproxy.gateway.exports.denied"); !maps.Equal(got, want) {
			t.Fatalf("denied is %v", got)
		}
	})
}

func TestGatewayHidesUpstreamError(t *testing.T) {
	const retryInfo = "type.googleapis.com/google.rpc.RetryInfo"
	throttle := status.New(codes.Unavailable, "memory limiter of tenant x").Proto()
	throttle.Details = []*anypb.Any{
		{TypeUrl: retryInfo, Value: []byte{0x0a, 0x02, 0x08, 0x05}},
		{TypeUrl: "type.googleapis.com/google.rpc.DebugInfo"},
	}
	cases := []struct {
		name    string
		fail    error
		code    codes.Code
		details []string
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "tenant x path /loki/api"), codes.InvalidArgument, nil},
		{"unavailable with RetryInfo", status.ErrorProto(throttle), codes.Unavailable, []string{retryInfo}},
		{"deadline", status.Error(codes.DeadlineExceeded, "slow store"), codes.Unavailable, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newGWHarness(t, &otlpUpstream{fail: c.fail})
			conn := h.serve(t, otelPattern, otelID1)
			_, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), &collogspb.ExportLogsServiceRequest{})
			st := status.Convert(err)
			if st.Code() != c.code || st.Message() != "denied" {
				t.Fatalf("got %v, want %v with only \"denied\"", err, c.code)
			}
			var urls []string
			for _, d := range st.Proto().GetDetails() {
				urls = append(urls, d.GetTypeUrl())
			}
			if !slices.Equal(urls, c.details) {
				t.Fatalf("details are %v, want %v", urls, c.details)
			}
		})
	}
}

func TestGatewaySenderCancel(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	h := newGWHarness(t, &otlpUpstream{block: block})
	ctx, cancel := context.WithCancel(peerContext(t, otelID1))
	go func() {
		for h.up.inflight.Load() == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	_, err := h.gw.ExportLogs(ctx, &collogspb.ExportLogsServiceRequest{})
	if status.Code(err) != codes.Canceled {
		t.Fatalf("got %v, want Canceled", err)
	}
	if strings.Contains(h.log.String(), "upstream failed") {
		t.Fatalf("a cancel of the sender was logged as an upstream failure:\n%s", h.log.String())
	}
}

func TestGatewayOverwriteLogIsRateLimited(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	now := time.Now()
	h.gw.limiter.now = func() time.Time { return now }
	spoofed := func() *collogspb.ExportLogsServiceRequest {
		return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{Resource: spoofedResource()}}}
	}
	lines := func() []map[string]any {
		var out []map[string]any
		for _, l := range logLines(t, h.log) {
			if l["msg"] == "source attributes overwritten" {
				out = append(out, l)
			}
		}
		return out
	}
	for range 3 {
		if _, err := h.gw.ExportLogs(peerContext(t, otelID1), spoofed()); err != nil {
			t.Fatal(err)
		}
	}
	if got := lines(); len(got) != 1 || got[0]["count"] != float64(1) {
		t.Fatalf("lines after 3 calls in one interval are %v, want one with count 1", got)
	}
	now = now.Add(logEvery)
	if _, err := h.gw.ExportLogs(peerContext(t, otelID1), spoofed()); err != nil {
		t.Fatal(err)
	}
	got := lines()
	if len(got) != 2 || got[1]["count"] != float64(3) || got[1]["suppressed"] != float64(2) {
		t.Fatalf("lines after the interval are %v, want a second one with count 3 and suppressed 2", got)
	}
	if pairs, _ := got[1]["overwrites"].([]any); len(pairs) != 1 || pairs[0] != "resource/k8s.cluster.name=3" {
		t.Fatalf("overwrites are %v, want [resource/k8s.cluster.name=3]", got[1]["overwrites"])
	}
}

// TestGatewayAllowsClientKeepalive runs for 40 seconds: grpc-go sends a GOAWAY after the third
// early ping, and a client pings at most every 10 seconds.
func TestGatewayAllowsClientKeepalive(t *testing.T) {
	if testing.Short() {
		t.Skip("runs for 40 seconds")
	}
	h := newGWHarness(t, &otlpUpstream{})
	conn := h.serve(t, otelPattern, otelID1,
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: minClientPing, Timeout: 5 * time.Second, PermitWithoutStream: true}))
	if _, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), &collogspb.ExportLogsServiceRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	if conn.WaitForStateChange(ctx, connectivity.Ready) {
		t.Fatalf("the idle connection left READY for %v: the server refused the client pings", conn.GetState())
	}
}

func TestGatewayRefusesNonOtelRole(t *testing.T) {
	t.Run("allow pattern", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		conn := h.serve(t, otelPattern, agentID1)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if _, err := collogspb.NewLogsServiceClient(conn).Export(ctx, &collogspb.ExportLogsServiceRequest{}); err == nil {
			t.Fatal("the export from an argocd-agent ID succeeded")
		}
		waitForLog(t, h.log, "peer refused", PeerNotAllowed, agentID1)
		if n := h.up.calls.Load(); n != 0 {
			t.Fatalf("upstream got %d calls, want none", n)
		}
	})
	t.Run("gateway with a loose pattern", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		conn := h.serve(t, `^spiffe://dev\.env\.poc\.internal/.*$`, "spiffe://dev.env.poc.internal/cell/dev-cell-1/celld")
		_, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), &collogspb.ExportLogsServiceRequest{})
		if st, _ := status.FromError(err); st.Code() != codes.PermissionDenied || st.Message() != "denied" {
			t.Fatalf("got %v, want PermissionDenied with only \"denied\"", err)
		}
		waitForLog(t, h.log, "request denied", PeerNotAllowed, "")
		if n := h.up.calls.Load(); n != 0 {
			t.Fatalf("upstream got %d calls, want none", n)
		}
	})
}

func TestGatewayRefusesCallWithoutTLSPeer(t *testing.T) {
	for name, ctx := range map[string]func(t *testing.T) context.Context{
		"no peer": func(t *testing.T) context.Context { return t.Context() },
		"peer without TLS": func(t *testing.T) context.Context {
			return peer.NewContext(t.Context(), &peer.Peer{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newGWHarness(t, &otlpUpstream{})
			_, err := h.gw.ExportLogs(ctx(t), &collogspb.ExportLogsServiceRequest{})
			if st, _ := status.FromError(err); st.Code() != codes.PermissionDenied || st.Message() != "denied" {
				t.Fatalf("got %v, want PermissionDenied with only \"denied\"", err)
			}
			waitForLog(t, h.log, "request denied", PeerNotAllowed, "")
			if n := h.up.calls.Load(); n != 0 {
				t.Fatalf("upstream got %d calls, want none", n)
			}
		})
	}
}

func TestOTLPCodecDropsUnknownFields(t *testing.T) {
	kv := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "keep")
	kv = protowire.AppendString(protowire.AppendTag(kv, 99, protowire.BytesType), "platform.cell=dev-cell-2")
	wire := nest(kv, 1, 1, 1)
	req := &collogspb.ExportLogsServiceRequest{}
	if err := newOTLPCodec().Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire)}, req); err != nil {
		t.Fatal(err)
	}
	attr := req.GetResourceLogs()[0].GetResource().GetAttributes()[0]
	if attr.GetKey() != "keep" || len(attr.ProtoReflect().GetUnknown()) != 0 {
		t.Fatalf("attribute is %v with unknown bytes %q, want key keep and no unknown bytes", attr, attr.ProtoReflect().GetUnknown())
	}
}

// TestGatewayFreesSlotOfExpiredStream sends streams whose grpc-timeout has passed when the tap
// runs. grpc-go then aborts the stream after the tap and before the stats handler sees it, so only
// the end of the stream context frees the slot (http2_server.go lines 596 to 602 in v1.84.0). That
// release runs in its own goroutine, so the test sends one stream at a time and waits for the slot
// after each. A Go client fails such a call locally, so the test writes HTTP/2 frames itself.
func TestGatewayFreesSlotOfExpiredStream(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	conn := h.serve(t, otelPattern, otelID1)
	c := dialTCP(t, h.client)
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(c, c)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	dec := hpack.NewDecoder(4096, nil)
	slotsUsed := func() int64 {
		return h.points(t, "cellproxy.gateway.slots.used")[attrSet(attribute.String("sender.cluster", "dev-cell-1"))]
	}
	for i := range maxSenderCalls + 1 {
		id := uint32(2*i + 1)
		block.Reset()
		for _, f := range [][2]string{
			{":method", "POST"}, {":scheme", "http"}, {":path", "/opentelemetry.proto.collector.logs.v1.LogsService/Export"},
			{":authority", "gateway"}, {"content-type", "application/grpc"}, {"te", "trailers"}, {"grpc-timeout", "1n"},
		} {
			_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
			t.Fatal(err)
		}
		end := ""
		for end == "" {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatalf("read on stream %d: %v", id, err)
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = fr.WriteSettingsAck()
				}
			case *http2.HeadersFrame:
				fields, err := dec.DecodeFull(f.HeaderBlockFragment())
				if err != nil {
					t.Fatal(err)
				}
				for _, hf := range fields {
					if hf.Name == "grpc-status" && f.StreamID == id && f.StreamEnded() {
						end = hf.Value
					}
				}
			case *http2.RSTStreamFrame:
				if f.StreamID == id {
					end = "rst " + f.ErrCode.String()
				}
			case *http2.GoAwayFrame:
				t.Fatalf("server sent GOAWAY %v", f.ErrCode)
			}
		}
		if end == strconv.Itoa(int(codes.Unavailable)) {
			t.Fatalf("stream %d was refused as overloaded: an earlier expired stream holds its slot", id)
		}
		deadline := time.Now().Add(2 * time.Second)
		for slotsUsed() != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("slots used is %d after expired stream %d ended (%s), want 0", slotsUsed(), id, end)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if _, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), &collogspb.ExportLogsServiceRequest{}); err != nil {
		t.Fatalf("an export after the expired streams gave %v", err)
	}
}

func TestOTLPCodecCapsRepeatedScalars(t *testing.T) {
	cases := map[string]proto.Message{
		"entity id_keys": &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{EntityRefs: []*commonpb.EntityRef{{IdKeys: make([]string, 1_800_000)}}},
		}}},
		"exponential histogram buckets": &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{Data: &metricspb.Metric_ExponentialHistogram{
				ExponentialHistogram: &metricspb.ExponentialHistogram{DataPoints: []*metricspb.ExponentialHistogramDataPoint{{
					Positive: &metricspb.ExponentialHistogramDataPoint_Buckets{BucketCounts: make([]uint64, 3_600_000)},
				}}},
			}}}}},
		}}},
	}
	c := newOTLPCodec()
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			wire, err := proto.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if len(wire) > MaxRecvMsgBytes {
				t.Fatalf("the request has %d bytes, more than the receive limit", len(wire))
			}
			allocs := testing.AllocsPerRun(3, func() {
				req := m.ProtoReflect().New().Interface()
				if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire)}, req); err != nil {
					t.Fatal(err)
				}
				if c.refusal(req) == nil {
					t.Fatal("the codec accepted the request")
				}
			})
			t.Logf("wire=%d bytes allocations per refusal: %v", len(wire), allocs)
			if allocs > 20 {
				t.Fatalf("%v allocations per refusal, want at most 20", allocs)
			}
		})
	}
}

// TestOTLPCodecWorstAllowedShape decodes one request at the message, number and string caps
// together, the worst decode cost of one call that the scan lets through.
func TestOTLPCodecWorstAllowedShape(t *testing.T) {
	lim := defaultScanLimits
	empty := make([]*commonpb.KeyValue, lim.Attributes)
	for i := range empty {
		empty[i] = &commonpb.KeyValue{}
	}
	points := make([]*metricspb.NumberDataPoint, (lim.Messages-16)/(lim.Attributes+1))
	for i := range points {
		points[i] = &metricspb.NumberDataPoint{Attributes: empty}
	}
	req := &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{EntityRefs: []*commonpb.EntityRef{{IdKeys: make([]string, lim.Strings)}}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{
			{Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: points}}},
			{Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{
				DataPoints: []*metricspb.ExponentialHistogramDataPoint{{
					Positive: &metricspb.ExponentialHistogramDataPoint_Buckets{BucketCounts: make([]uint64, lim.NumberBytes/8)},
				}},
			}}},
		}}},
	}}}
	wire, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > MaxRecvMsgBytes {
		t.Fatalf("the request has %d bytes, more than the receive limit", len(wire))
	}
	c := newOTLPCodec()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := &colmetricspb.ExportMetricsServiceRequest{}
	if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire)}, got); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if err := c.refusal(got); err != nil {
		t.Fatalf("the codec refused the worst allowed shape: %v", err)
	}
	total, live := (after.TotalAlloc-before.TotalAlloc)>>20, (int64(after.HeapAlloc)-int64(before.HeapAlloc))>>20
	runtime.KeepAlive(got)
	t.Logf("wire=%d bytes total_alloc=%d MiB live_heap=%d MiB", len(wire), total, live)
	if total > 256 {
		t.Fatalf("the decode allocated %d MiB, want at most 256 MiB", total)
	}
}

func TestOTLPBackendShutdownClosesUpstream(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	b := NewOTLPBackend(h.gw, MaxRecvMsgBytes).(*otlpBackend)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	b.Shutdown(ctx)
	if st := h.gw.upstream.GetState(); st != connectivity.Shutdown {
		t.Fatalf("the upstream connection is %v after Shutdown, want SHUTDOWN", st)
	}
}

// TestSlotPoolConcurrent runs many senders at once. Run it with -race.
func TestSlotPoolConcurrent(t *testing.T) {
	p := newSlotPool(maxGatewayCalls, maxSenderCalls)
	senders := []string{"dev-cell-1", "dev-cell-2", "dev-cell-3", "dev-cell-4", "dev-cp"}
	var total atomic.Int64
	per := map[string]*atomic.Int64{}
	for _, s := range senders {
		per[s] = &atomic.Int64{}
	}
	var over atomic.Int64
	var wg sync.WaitGroup
	for g := range 64 {
		s := senders[g%len(senders)]
		wg.Go(func() {
			for range 2000 {
				if !p.take(s) {
					continue
				}
				if total.Add(1) > maxGatewayCalls || per[s].Add(1) > maxSenderCalls {
					over.Add(1)
				}
				per[s].Add(-1)
				total.Add(-1)
				p.give(s)
			}
		})
	}
	wg.Wait()
	if n := over.Load(); n != 0 {
		t.Fatalf("%d takes passed a limit", n)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used != 0 || len(p.bySender) != 0 {
		t.Fatalf("pool holds used=%d and %v at the end, want none", p.used, p.bySender)
	}
}

func TestGatewayClearsRefusalOfDeniedPeer(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	req := &collogspb.ExportLogsServiceRequest{}
	h.gw.codec.refused.Store(req, errors.New("more than 1024 resources"))
	if _, err := h.gw.ExportLogs(t.Context(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, want PermissionDenied", err)
	}
	if _, ok := h.gw.codec.refused.Load(req); ok {
		t.Fatal("the refusal of a denied peer stays in the codec")
	}
}

// hostileResource returns one ResourceLogs that passes a shape cap of the gateway on its own: too many
// attributes in one set, too many scopes, or messages that nest too deep.
func hostileResource(shape string) *logspb.ResourceLogs {
	rl := &logspb.ResourceLogs{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("service.name", "hostile")}}}
	switch shape {
	case "attributes":
		attrs := make([]*commonpb.KeyValue, defaultScanLimits.Attributes+1)
		for i := range attrs {
			attrs[i] = str(fmt.Sprintf("k%d", i), "v")
		}
		rl.ScopeLogs = []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{Attributes: attrs}}}}
	case "scopes":
		rl.ScopeLogs = make([]*logspb.ScopeLogs, defaultScanLimits.Scopes+1)
		for i := range rl.ScopeLogs {
			rl.ScopeLogs[i] = &logspb.ScopeLogs{}
		}
	case "depth":
		v := &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "x"}}
		for range defaultScanLimits.Depth + 4 {
			v = &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: []*commonpb.KeyValue{{Key: "k", Value: v}}}}}
		}
		rl.ScopeLogs = []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{Attributes: []*commonpb.KeyValue{{Key: "deep", Value: v}}}}}}
	}
	return rl
}

func normalResource(marker string) *logspb.ResourceLogs {
	return &logspb.ResourceLogs{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("service.name", marker)}},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: marker}}}}}}}
}

// TestGatewayDropsOnlyTheHostileResource checks that one resource that passes an element cap does not
// make the gateway refuse the other resources of the request. The collector merges the telemetry of
// every workload of its cluster into one request, so a refusal of the whole request, which the sender
// treats as permanent, would let one workload drop the data of the others. The gateway forwards the
// other resources and answers with a partial success. A request with no other resource is still refused.
func TestGatewayDropsOnlyTheHostileResource(t *testing.T) {
	for shape, wantRejected := range map[string]int64{"attributes": 1, "scopes": 0, "depth": 1} {
		t.Run(shape, func(t *testing.T) {
			h := newGWHarness(t, &otlpUpstream{})
			conn := h.serve(t, otelPattern, otelID1)
			client := collogspb.NewLogsServiceClient(conn)
			resp, err := client.Export(t.Context(), &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{
				normalResource("first"), hostileResource(shape), normalResource("second")}})
			if err != nil {
				t.Fatalf("the gateway refused the request: %v, want the normal resources forwarded", err)
			}
			if ps := resp.GetPartialSuccess(); ps.GetRejectedLogRecords() != wantRejected || ps.GetErrorMessage() == "" {
				t.Errorf("partial success %v, want %d rejected log records and a message", ps, wantRejected)
			}
			h.up.mu.Lock()
			defer h.up.mu.Unlock()
			if len(h.up.logs) != 1 || len(h.up.logs[0].ResourceLogs) != 2 {
				t.Fatalf("upstream got %v, want one request with the two normal resources", h.up.logs)
			}
			var got []string
			for _, rl := range h.up.logs[0].ResourceLogs {
				got = append(got, rl.ScopeLogs[0].LogRecords[0].Body.GetStringValue())
			}
			if !slices.Equal(got, []string{"first", "second"}) {
				t.Errorf("upstream got the bodies %v, want [first second]", got)
			}

			_, err = client.Export(t.Context(), &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{hostileResource(shape)}})
			if status.Code(err) != codes.ResourceExhausted {
				t.Errorf("a request with only the hostile resource got %v, want ResourceExhausted", err)
			}
		})
	}
}

// TestGatewayDropsOnlyTheHostileResourceOfEverySignal checks traces and metrics like logs: the response
// carries the partial success of its own signal.
func TestGatewayDropsOnlyTheHostileResourceOfEverySignal(t *testing.T) {
	attrs := make([]*commonpb.KeyValue, defaultScanLimits.Attributes+1)
	for i := range attrs {
		attrs[i] = str(fmt.Sprintf("k%d", i), "v")
	}
	res := func(name string) *resourcepb.Resource {
		return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("service.name", name)}}
	}
	t.Run("traces", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		conn := h.serve(t, otelPattern, otelID1)
		resp, err := coltracepb.NewTraceServiceClient(conn).Export(t.Context(), &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{
			{Resource: res("ok"), ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "ok"}}}}},
			{Resource: res("bad"), ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "bad", Attributes: attrs}}}}}}})
		if err != nil || resp.GetPartialSuccess().GetRejectedSpans() != 1 {
			t.Fatalf("err %v, partial success %v, want one rejected span", err, resp.GetPartialSuccess())
		}
		if len(h.up.traces) != 1 || len(h.up.traces[0].ResourceSpans) != 1 {
			t.Fatalf("upstream got %v, want one resource", h.up.traces)
		}
	})
	t.Run("metrics", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		conn := h.serve(t, otelPattern, otelID1)
		point := func(a []*commonpb.KeyValue) *metricspb.Metric {
			return &metricspb.Metric{Name: "m", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{Attributes: a}}}}}
		}
		resp, err := colmetricspb.NewMetricsServiceClient(conn).Export(t.Context(), &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{
			{Resource: res("ok"), ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{point(nil)}}}},
			{Resource: res("bad"), ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{point(attrs)}}}}}})
		if err != nil || resp.GetPartialSuccess().GetRejectedDataPoints() != 1 {
			t.Fatalf("err %v, partial success %v, want one rejected point", err, resp.GetPartialSuccess())
		}
		if len(h.up.metrics) != 1 || len(h.up.metrics[0].ResourceMetrics) != 1 {
			t.Fatalf("upstream got %v, want one resource", h.up.metrics)
		}
	})
}
