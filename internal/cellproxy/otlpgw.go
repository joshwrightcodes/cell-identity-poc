package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	// Collectors compress OTLP with gzip by default, so the server must accept it.
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// The source attribute keys. Every collector sets them, and the gateway sets them again from the
// verified SPIFFE ID.
const (
	AttrClusterName = "k8s.cluster.name"
	AttrPlane       = "platform.plane"
	AttrEnvironment = "deployment.environment.name"
	AttrCell        = "platform.cell"
)

// The levels of the overwrite counter.
const (
	LevelResource  = "resource"
	LevelScope     = "scope"
	LevelRecord    = "record"
	LevelDatapoint = "datapoint"
)

const (
	// OverwriteCounterName is the counter of source attributes that the gateway changed or
	// deleted. Prometheus shows it as cellproxy_gateway_attribute_overwrites_total.
	OverwriteCounterName = "cellproxy.gateway.attribute.overwrites"

	meshSourceCluster      = "source_cluster"
	meshDestinationCluster = "destination_cluster"
	meshUnknown            = "unknown"

	// forwardTimeout bounds each call to the upstream.
	forwardTimeout = 10 * time.Second
	// maxGatewayCalls is the number of calls that run at once over all connections.
	maxGatewayCalls = 16
)

// sourceKeys holds the source attribute keys in the order that the gateway writes them.
var sourceKeys = []string{AttrClusterName, AttrPlane, AttrEnvironment, AttrCell}

// sourceLabels maps the label form of each source key to the key.
var sourceLabels = func() map[string]string {
	m := map[string]string{}
	for _, k := range sourceKeys {
		m[labelForm(k)] = k
	}
	return m
}()

// labelForm is the name that a store derives from an attribute key: each character that is not
// an ASCII letter or digit becomes "_", and a run of "_" becomes one. Keys with the same label form
// end up as one label, so k8s_cluster_name and k8s.cluster.name are the same key to the gateway.
func labelForm(k string) string {
	var b strings.Builder
	under := false
	for i := 0; i < len(k); i++ {
		c := k[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
			under = false
			continue
		}
		if !under {
			b.WriteByte('_')
		}
		under = true
	}
	return b.String()
}

// sourceKey returns the source key that k is a form of.
func sourceKey(k string) (string, bool) {
	key, ok := sourceLabels[labelForm(k)]
	return key, ok
}

// SourceAttributes returns the source attributes of a sender, as the source attribute table
// gives them. An environment sender has no platform.cell.
func SourceAttributes(s Source) map[string]string {
	m := map[string]string{AttrClusterName: s.Cluster, AttrPlane: s.Plane, AttrEnvironment: s.Env}
	if s.Plane == PlaneCell {
		m[AttrCell] = s.Cell
	}
	return m
}

func stringValue(v string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}
}

// isString reports whether v is the string want.
func isString(v *commonpb.AnyValue, want string) bool {
	s, ok := v.GetValue().(*commonpb.AnyValue_StringValue)
	return ok && s.StringValue == want
}

func appendOnce(list []string, k string) []string {
	for _, x := range list {
		if x == k {
			return list
		}
	}
	return append(list, k)
}

// ResetResource sets the source attributes of r to those of s. It deletes every other form of a
// source key, and platform.cell for an environment sender. Duplicate keys collapse to one. The
// result names each source key, once, whose value changed or that the sender may not set. A key
// that was absent is set and not named. A nil r stays nil: the holder of r gives it a resource.
func ResetResource(r *resourcepb.Resource, s Source) (changed []string) {
	if r == nil {
		return nil
	}
	want := SourceAttributes(s)
	kept := make([]*commonpb.KeyValue, 0, len(r.Attributes)+len(want))
	for _, kv := range r.Attributes {
		key, ok := sourceKey(kv.GetKey())
		if !ok {
			kept = append(kept, kv)
			continue
		}
		v, allowed := want[key]
		if kv.GetKey() != key || !allowed || !isString(kv.GetValue(), v) {
			changed = appendOnce(changed, key)
		}
	}
	for _, k := range sourceKeys {
		if v, ok := want[k]; ok {
			kept = append(kept, &commonpb.KeyValue{Key: k, Value: stringValue(v)})
		}
	}
	r.Attributes = kept
	return changed
}

// Overwrite is one source attribute that the gateway changed or deleted, at one level.
type Overwrite struct {
	Level, Attribute string
}

// stripSource deletes every form of a source key from attrs. It returns one overwrite for each
// source key that attrs held.
func stripSource(level string, attrs *[]*commonpb.KeyValue) (deleted []Overwrite) {
	if attrs == nil || len(*attrs) == 0 {
		return nil
	}
	var keys []string
	kept := (*attrs)[:0]
	for _, kv := range *attrs {
		if key, ok := sourceKey(kv.GetKey()); ok {
			keys = appendOnce(keys, key)
			continue
		}
		kept = append(kept, kv)
	}
	clear((*attrs)[len(kept):])
	*attrs = kept
	for _, k := range keys {
		deleted = append(deleted, Overwrite{Level: level, Attribute: k})
	}
	return deleted
}

// pointAttrs returns the attribute sets of the data points of m, and of their exemplars.
func pointAttrs(m *metricspb.Metric) (points, exemplars []*[]*commonpb.KeyValue) {
	addExemplars := func(es []*metricspb.Exemplar) {
		for _, e := range es {
			if e != nil {
				exemplars = append(exemplars, &e.FilteredAttributes)
			}
		}
	}
	switch d := m.GetData().(type) {
	case *metricspb.Metric_Gauge:
		for _, p := range d.Gauge.GetDataPoints() {
			if p != nil {
				points = append(points, &p.Attributes)
				addExemplars(p.Exemplars)
			}
		}
	case *metricspb.Metric_Sum:
		for _, p := range d.Sum.GetDataPoints() {
			if p != nil {
				points = append(points, &p.Attributes)
				addExemplars(p.Exemplars)
			}
		}
	case *metricspb.Metric_Histogram:
		for _, p := range d.Histogram.GetDataPoints() {
			if p != nil {
				points = append(points, &p.Attributes)
				addExemplars(p.Exemplars)
			}
		}
	case *metricspb.Metric_ExponentialHistogram:
		for _, p := range d.ExponentialHistogram.GetDataPoints() {
			if p != nil {
				points = append(points, &p.Attributes)
				addExemplars(p.Exemplars)
			}
		}
	case *metricspb.Metric_Summary:
		for _, p := range d.Summary.GetDataPoints() {
			if p != nil {
				points = append(points, &p.Attributes)
			}
		}
	}
	return points, exemplars
}

// scopeAttrs returns the attribute set of a scope, or nil for no scope.
func scopeAttrs(s *commonpb.InstrumentationScope) *[]*commonpb.KeyValue {
	if s == nil {
		return nil
	}
	return &s.Attributes
}

// StripNestedSource deletes every form of the four source keys from each attribute set below
// the resource of req: scopes, log records, spans, span events, span links, metric metadata, data
// points and exemplars. It does this for every sender. req is an OTLP logs, trace or metrics
// export request. The result holds one overwrite for each source key in each attribute set.
func StripNestedSource(req any) (deleted []Overwrite) {
	strip := func(level string, attrs *[]*commonpb.KeyValue) {
		deleted = append(deleted, stripSource(level, attrs)...)
	}
	switch r := req.(type) {
	case *collogspb.ExportLogsServiceRequest:
		for _, rl := range r.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				strip(LevelScope, scopeAttrs(sl.GetScope()))
				for _, lr := range sl.GetLogRecords() {
					if lr != nil {
						strip(LevelRecord, &lr.Attributes)
					}
				}
			}
		}
	case *coltracepb.ExportTraceServiceRequest:
		for _, rs := range r.GetResourceSpans() {
			for _, ss := range rs.GetScopeSpans() {
				strip(LevelScope, scopeAttrs(ss.GetScope()))
				for _, sp := range ss.GetSpans() {
					if sp == nil {
						continue
					}
					strip(LevelRecord, &sp.Attributes)
					for _, e := range sp.Events {
						if e != nil {
							strip(LevelRecord, &e.Attributes)
						}
					}
					for _, l := range sp.Links {
						if l != nil {
							strip(LevelRecord, &l.Attributes)
						}
					}
				}
			}
		}
	case *colmetricspb.ExportMetricsServiceRequest:
		for _, rm := range r.GetResourceMetrics() {
			for _, sm := range rm.GetScopeMetrics() {
				strip(LevelScope, scopeAttrs(sm.GetScope()))
				for _, m := range sm.GetMetrics() {
					if m == nil {
						continue
					}
					strip(LevelRecord, &m.Metadata)
					points, exemplars := pointAttrs(m)
					for _, p := range append(points, exemplars...) {
						strip(LevelDatapoint, p)
					}
				}
			}
		}
	}
	return deleted
}

// ResetMeshLabels sets the Istio labels source_cluster and destination_cluster of every data
// point in rm to the cluster of s, for every sender. A string value "unknown" stays. It deletes
// every other form of the two keys, for example source.cluster, and collapses duplicates. The
// result names a key once for each data point where a value changed or went away.
func ResetMeshLabels(rm *metricspb.ResourceMetrics, s Source) (changed []string) {
	for _, sm := range rm.GetScopeMetrics() {
		for _, m := range sm.GetMetrics() {
			points, _ := pointAttrs(m)
			for _, p := range points {
				changed = append(changed, resetMesh(p, s.Cluster)...)
			}
		}
	}
	return changed
}

func resetMesh(attrs *[]*commonpb.KeyValue, cluster string) (changed []string) {
	kept := (*attrs)[:0]
	first := map[string]*commonpb.KeyValue{}
	for _, kv := range *attrs {
		key := labelForm(kv.GetKey())
		if key != meshSourceCluster && key != meshDestinationCluster {
			kept = append(kept, kv)
			continue
		}
		if kv.GetKey() != key {
			changed = appendOnce(changed, key)
			continue
		}
		if prev, ok := first[key]; ok {
			if !isString(kv.GetValue(), prev.GetValue().GetStringValue()) {
				changed = appendOnce(changed, key)
			}
			continue
		}
		if !isString(kv.GetValue(), meshUnknown) && !isString(kv.GetValue(), cluster) {
			kv.Value = stringValue(cluster)
			changed = appendOnce(changed, key)
		}
		first[key] = kv
		kept = append(kept, kv)
	}
	clear((*attrs)[len(kept):])
	*attrs = kept
	return changed
}

// NewOverwriteCounter creates the counter that NewGateway takes.
func NewOverwriteCounter(m metric.Meter) (metric.Int64Counter, error) {
	return m.Int64Counter(OverwriteCounterName,
		metric.WithUnit("{attribute}"),
		metric.WithDescription("Source attributes that the telemetry gateway changed or deleted, by attribute, level and sender cluster"))
}

// Gateway receives OTLP logs, traces and metrics from the senders that the accept loop verified,
// sets the source attributes again from the SPIFFE ID of each sender, and forwards each request
// to the upstream. Register serves its three OTLP services on a gRPC server.
type Gateway struct {
	logs       collogspb.LogsServiceClient
	traces     coltracepb.TraceServiceClient
	metrics    colmetricspb.MetricsServiceClient
	overwrites metric.Int64Counter
	log        *slog.Logger
	timeout    time.Duration
	slots      chan struct{}
}

// NewGateway returns a gateway that forwards to upstream and counts each overwrite.
func NewGateway(upstream *grpc.ClientConn, overwrites metric.Int64Counter, log *slog.Logger) *Gateway {
	return &Gateway{
		logs:       collogspb.NewLogsServiceClient(upstream),
		traces:     coltracepb.NewTraceServiceClient(upstream),
		metrics:    colmetricspb.NewMetricsServiceClient(upstream),
		overwrites: overwrites,
		log:        log,
		timeout:    forwardTimeout,
		slots:      make(chan struct{}, maxGatewayCalls),
	}
}

// Register serves the OTLP LogsService, TraceService and MetricsService of g on s.
func (g *Gateway) Register(s grpc.ServiceRegistrar) {
	collogspb.RegisterLogsServiceServer(s, logsServer{g: g})
	coltracepb.RegisterTraceServiceServer(s, traceServer{g: g})
	colmetricspb.RegisterMetricsServiceServer(s, metricsServer{g: g})
}

type logsServer struct {
	collogspb.UnimplementedLogsServiceServer
	g *Gateway
}

func (s logsServer) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	return s.g.ExportLogs(ctx, req)
}

type traceServer struct {
	coltracepb.UnimplementedTraceServiceServer
	g *Gateway
}

func (s traceServer) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	return s.g.ExportTraces(ctx, req)
}

type metricsServer struct {
	colmetricspb.UnimplementedMetricsServiceServer
	g *Gateway
}

func (s metricsServer) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	return s.g.ExportMetrics(ctx, req)
}

// ExportLogs resets and forwards one logs request.
func (g *Gateway) ExportLogs(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	return forward(ctx, g, "logs", req, resetLogs, g.logs.Export)
}

// ExportTraces resets and forwards one trace request.
func (g *Gateway) ExportTraces(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	return forward(ctx, g, "traces", req, resetTraces, g.traces.Export)
}

// ExportMetrics resets and forwards one metrics request.
func (g *Gateway) ExportMetrics(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	return forward(ctx, g, "metrics", req, resetMetrics, g.metrics.Export)
}

// resource gives the holder of *r a resource when it has none, and resets it.
func resource(r **resourcepb.Resource, s Source) []Overwrite {
	if *r == nil {
		*r = &resourcepb.Resource{}
	}
	var out []Overwrite
	for _, k := range ResetResource(*r, s) {
		out = append(out, Overwrite{Level: LevelResource, Attribute: k})
	}
	return out
}

func resetLogs(req *collogspb.ExportLogsServiceRequest, s Source) []Overwrite {
	var out []Overwrite
	for _, rl := range req.GetResourceLogs() {
		if rl != nil {
			out = append(out, resource(&rl.Resource, s)...)
		}
	}
	return append(out, StripNestedSource(req)...)
}

func resetTraces(req *coltracepb.ExportTraceServiceRequest, s Source) []Overwrite {
	var out []Overwrite
	for _, rs := range req.GetResourceSpans() {
		if rs != nil {
			out = append(out, resource(&rs.Resource, s)...)
		}
	}
	return append(out, StripNestedSource(req)...)
}

func resetMetrics(req *colmetricspb.ExportMetricsServiceRequest, s Source) []Overwrite {
	var out []Overwrite
	for _, rm := range req.GetResourceMetrics() {
		if rm == nil {
			continue
		}
		out = append(out, resource(&rm.Resource, s)...)
		for _, k := range ResetMeshLabels(rm, s) {
			out = append(out, Overwrite{Level: LevelDatapoint, Attribute: k})
		}
	}
	return append(out, StripNestedSource(req)...)
}

// forward checks the peer, takes a call slot, resets req, counts each overwrite and forwards req
// under the forward timeout. It returns the upstream response unchanged, partial_success included.
func forward[Req, Resp any](ctx context.Context, g *Gateway, signal string, req Req,
	reset func(Req, Source) []Overwrite, call func(context.Context, Req, ...grpc.CallOption) (Resp, error)) (Resp, error) {
	var zero Resp
	log := g.log.With("signal", signal)
	src, err := peerSource(ctx)
	if err != nil {
		return zero, deny(ctx, log, PeerNotAllowed, err.Error())
	}
	log = log.With("sender_cluster", src.Cluster)
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		return zero, deny(ctx, log, Overloaded, "the gateway runs its maximum number of calls")
	}
	if ows := reset(req, src); len(ows) > 0 {
		g.count(ctx, src, ows)
		log.Warn("source attributes overwritten", "count", len(ows))
	}
	fctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	resp, err := call(fctx, req)
	if err == nil {
		return resp, nil
	}
	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable, codes.Canceled:
		return zero, upstreamFailed(ctx, log, err)
	}
	log.Warn("upstream refused", "error", err.Error())
	return zero, err
}

func (g *Gateway) count(ctx context.Context, src Source, ows []Overwrite) {
	n := map[Overwrite]int64{}
	for _, o := range ows {
		n[o]++
	}
	for o, c := range n {
		g.overwrites.Add(ctx, c, metric.WithAttributes(
			attribute.String("attribute", o.Attribute),
			attribute.String("level", o.Level),
			attribute.String("sender.cluster", src.Cluster),
		))
	}
}

// peerSource returns the source of the verified TLS peer of the call.
func peerSource(ctx context.Context) (Source, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return Source{}, errors.New("call has no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return Source{}, errors.New("call has no TLS peer")
	}
	id, err := x509svid.IDFromCert(info.State.PeerCertificates[0])
	if err != nil {
		return Source{}, err
	}
	return ParseSource(id)
}

// deny logs the reason and returns only "denied", with the request ID in the trailer.
func deny(ctx context.Context, log *slog.Logger, reason Reason, detail string) error {
	id := requestID()
	log.Warn("request denied", "reason", string(reason), "request_id", id, "error", detail)
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-request-id", id))
	return status.Error(reason.GRPCCode(), "denied")
}

func upstreamFailed(ctx context.Context, log *slog.Logger, err error) error {
	id := requestID()
	log.Warn("upstream failed", "reason", string(UpstreamUnavailable), "request_id", id, "error", err.Error())
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-request-id", id))
	return status.Error(UpstreamUnavailable.GRPCCode(), "denied")
}

// otlpBackend serves every handed-over connection with one gRPC server.
type otlpBackend struct {
	srv *grpc.Server
	ln  *handoverListener
}

// NewOTLPBackend returns the otlp backend. One gRPC server serves the OTLP services of gw on each
// handed-over connection, and refuses a message larger than maxRecvBytes after decompression.
func NewOTLPBackend(gw *Gateway, maxRecvBytes int) Backend {
	srv := grpc.NewServer(
		grpc.Creds(handoverCreds{}),
		grpc.MaxRecvMsgSize(maxRecvBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: defaultIdleTimeout}),
	)
	gw.Register(srv)
	ln := &handoverListener{conns: make(chan *handoverConn), done: make(chan struct{})}
	go func() { _ = srv.Serve(ln) }()
	return &otlpBackend{srv: srv, ln: ln}
}

func (b *otlpBackend) Name() string { return "otlp" }

// Serve hands conn to the gRPC server and waits until the server closes it or ctx ends.
func (b *otlpBackend) Serve(ctx context.Context, conn *tls.Conn, _ Source) error {
	hc := &handoverConn{Conn: conn, tls: conn, closed: make(chan struct{})}
	select {
	case b.ln.conns <- hc:
	case <-b.ln.done:
		return errors.New("the gRPC server has stopped")
	case <-ctx.Done():
		return nil
	}
	select {
	case <-hc.closed:
	case <-ctx.Done():
		_ = hc.Close()
	}
	return nil
}

// handoverListener gives the gRPC server the connections of the accept loop.
type handoverListener struct {
	conns chan *handoverConn
	once  sync.Once
	done  chan struct{}
}

func (l *handoverListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handoverListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *handoverListener) Addr() net.Addr { return handoverAddr{} }

type handoverAddr struct{}

func (handoverAddr) Network() string { return "handover" }
func (handoverAddr) String() string  { return "accept-loop" }

// handoverConn is a verified TLS connection that reports its close.
type handoverConn struct {
	net.Conn
	tls    *tls.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *handoverConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// handoverCreds are server credentials for a connection whose TLS handshake the accept loop has
// done. They return the TLS state of that connection, so a handler can read the peer SVID.
type handoverCreds struct{}

func (handoverCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("handover credentials serve only the server side")
}

func (handoverCreds) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	hc, ok := c.(*handoverConn)
	if !ok {
		return nil, nil, errors.New("connection did not come from the accept loop")
	}
	return hc, credentials.TLSInfo{
		State:          hc.tls.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}, nil
}

func (handoverCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (c handoverCreds) Clone() credentials.TransportCredentials { return c }

func (handoverCreds) OverrideServerName(string) error { return nil }
