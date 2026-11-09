package cellproxy

import (
	"context"
	"crypto/tls"
	"maps"
	"net"
	"regexp"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

// spoofSets builds nested attribute sets that each hold two spoofed source keys and one other
// key, and remembers each set so the test can check it after the strip.
type spoofSets struct {
	sets []*[]*commonpb.KeyValue
	want []Overwrite
}

func (s *spoofSets) attrs(level string) []*commonpb.KeyValue {
	s.want = append(s.want, Overwrite{Level: level, Attribute: "platform.cell"}, Overwrite{Level: level, Attribute: "k8s.cluster.name"})
	return []*commonpb.KeyValue{str("platform_cell", "dev-cell-2"), str("keep", "yes"), str("k8s.cluster.name", "dev-cell-2")}
}

func (s *spoofSets) track(p *[]*commonpb.KeyValue) { s.sets = append(s.sets, p) }

func (s *spoofSets) check(t *testing.T, deleted []Overwrite) {
	t.Helper()
	for _, p := range s.sets {
		wantAttrs(t, *p, map[string]string{"keep": "yes"})
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
		t.Run(name, func(t *testing.T) {
			s := &spoofSets{}
			req := build(s)
			s.check(t, StripNestedSource(req))
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
	block    chan struct{}
	calls    atomic.Int64
	inflight atomic.Int64
}

func (u *otlpUpstream) enter(ctx context.Context) error {
	u.calls.Add(1)
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
	counter, err := NewOverwriteCounter(mp.Meter("test"))
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	return &gwHarness{up: up, gw: NewGateway(conn, counter, jsonLog(out)), reader: reader, log: out}
}

// serve runs the gateway behind spiffe-server with the otlp backend and allow, and spiffe-client
// with the SVID id. It returns a gRPC connection to spiffe-client.
func (h *gwHarness) serve(t *testing.T, allow, id string) *grpc.ClientConn {
	t.Helper()
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	telemetryID := "spiffe://mgmt.poc.internal/telemetry"
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewOTLPBackend(h.gw, 8<<20)
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

	conn, err := grpc.NewClient("passthrough:///"+cliLn.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		cancel()
		<-cliDone
		<-srvDone
		backend.(*otlpBackend).srv.Stop()
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
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := h.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[attribute.Distinct]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "cellproxy.gateway.attribute.overwrites" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				got[dp.Attributes.Equivalent()] = dp.Value
			}
		}
	}
	return got
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

func TestGatewayRefusesOversize(t *testing.T) {
	cases := map[string][]grpc.CallOption{
		"plain": nil,
		"gzip":  {grpc.UseCompressor(gzip.Name)},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			h := newGWHarness(t, &otlpUpstream{})
			conn := h.serve(t, otelPattern, otelID1)
			body := &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: strings.Repeat("a", 9<<20)}}
			_, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
				ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{Body: body}}}},
			}}}, opts...)
			if status.Code(err) != codes.ResourceExhausted {
				t.Fatalf("got %v, want ResourceExhausted", err)
			}
			if n := h.up.calls.Load(); n != 0 {
				t.Fatalf("upstream got %d calls, want none", n)
			}
		})
	}
}

func TestGatewayOverload(t *testing.T) {
	block := make(chan struct{})
	h := newGWHarness(t, &otlpUpstream{block: block})
	timeout := 500 * time.Millisecond
	h.gw.timeout = timeout
	ctx := peerContext(t, otelID1)
	export := func() error {
		_, err := h.gw.ExportLogs(ctx, &collogspb.ExportLogsServiceRequest{})
		return err
	}

	start := time.Now()
	errs := make(chan error, maxGatewayCalls)
	for range maxGatewayCalls {
		go func() { errs <- export() }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.up.inflight.Load() != maxGatewayCalls {
		if time.Now().After(deadline) {
			t.Fatalf("%d calls reached the upstream, want %d", h.up.inflight.Load(), maxGatewayCalls)
		}
		time.Sleep(5 * time.Millisecond)
	}

	extra := time.Now()
	err := export()
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("call %d gave %v, want Unavailable", maxGatewayCalls+1, err)
	}
	if d := time.Since(extra); d > 100*time.Millisecond {
		t.Fatalf("call %d took %v, want it to fail at once", maxGatewayCalls+1, d)
	}
	waitForLog(t, h.log, "request denied", Overloaded, "")

	for range maxGatewayCalls {
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

	close(block)
	if err := export(); err != nil {
		t.Fatalf("a call after the blocked calls ended gave %v", err)
	}
}

func TestGatewayRefusesNonOtelRole(t *testing.T) {
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
}

func TestGatewayRefusesCallWithoutTLSPeer(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	plain := peer.NewContext(t.Context(), &peer.Peer{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}})
	for name, ctx := range map[string]context.Context{"no peer": t.Context(), "peer without TLS": plain} {
		t.Run(name, func(t *testing.T) {
			_, err := h.gw.ExportLogs(ctx, &collogspb.ExportLogsServiceRequest{})
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
