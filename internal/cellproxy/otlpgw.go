package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
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
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
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
	// UpstreamMaxMsgBytes is the receive limit of the upstream. The OTLP receiver of otel-lgtm
	// v0.38.0 sets no max_recv_msg_size_mib, so it keeps the grpc-go default of 4 MiB.
	UpstreamMaxMsgBytes = 4 << 20
	// resetHeadroomBytes bounds the bytes that the resource reset adds to a request. Four source
	// attributes take at most 400 wire bytes, and a request holds at most 1,024 resources.
	resetHeadroomBytes = 512 << 10
	// MaxRecvMsgBytes is the receive limit of the gateway, after decompression. A request at
	// this limit still fits the upstream after the reset.
	MaxRecvMsgBytes = UpstreamMaxMsgBytes - resetHeadroomBytes

	// OverwriteCounterName is the counter of source attributes that the gateway changed or
	// deleted. Prometheus shows it as cellproxy_gateway_attribute_overwrites_total.
	OverwriteCounterName = "cellproxy.gateway.attribute.overwrites"

	// RequestTooLarge: the request passes a shape cap, or passes the upstream limit after the
	// reset. The status is ResourceExhausted.
	RequestTooLarge Reason = "request_too_large"
	// ResourceRefused: one resource of a request passes a shape cap of one resource, or holds a string
	// that is not valid UTF-8. The gateway drops it, forwards the other resources, and reports a partial success.
	ResourceRefused Reason = "resource_refused"
	// RequestMalformed: the request does not decode, for example truncated wire bytes, or a string that
	// is not valid UTF-8 in every resource.
	RequestMalformed Reason = "request_malformed"

	meshSourceCluster      = "source_cluster"
	meshDestinationCluster = "destination_cluster"
	meshUnknown            = "unknown"

	// forwardTimeout caps the deadline of each call to the upstream.
	forwardTimeout = 10 * time.Second
	// forwardMargin is the part of the deadline of the sender that the gateway keeps for its
	// own answer.
	forwardMargin = time.Second
	// maxGatewayCalls is the number of calls that run at once over all senders.
	maxGatewayCalls = 16
	// maxSenderCalls is the share of one sender. With two cells and dev-cp, a backlog of every
	// sender holds 12 of the 16 slots.
	maxSenderCalls = 4
	// maxConnStreams is the HTTP/2 stream limit of each connection.
	maxConnStreams = maxGatewayCalls
	// maxHeaderListBytes bounds the header block of each stream.
	maxHeaderListBytes = 64 << 10
	// logEvery is the shortest time between two repeated Warn lines of one sender.
	logEvery = time.Minute
	// maxLogKeys bounds the keys of the log limiter, as for the refusal lines of the server.
	maxLogKeys = 256
	// minClientPing is the shortest ping interval that a client may use.
	minClientPing = 10 * time.Second
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

// labelForm is the name that a store derives from an attribute key, in lower case: each
// character that is not an ASCII letter or digit becomes "_", a run of "_" becomes one, and a "_"
// at either end goes. Keys with the same label form end up as one label, so k8s_cluster_name,
// k8s.cluster.name and _k8s.cluster.name_ are the same key to the gateway. A map value flattens
// to <key>_<inner key>, so the same rule matches a nested map entry too. Dropping the edges
// matches more keys than a store merges, which costs only a deleted spoof.
func labelForm(k string) string {
	var b strings.Builder
	under := false
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		default:
			if !under {
				b.WriteByte('_')
			}
			under = true
			continue
		}
		b.WriteByte(c)
		under = false
	}
	return strings.Trim(b.String(), "_")
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
	if slices.Contains(list, k) {
		return list
	}
	return append(list, k)
}

// stripMap deletes each entry of the maps in v whose name, joined to prefix, is a source key. It
// walks maps in maps and in arrays. It adds each source key that it deletes to keys, and reports
// whether v is a map that it emptied.
func stripMap(prefix string, v *commonpb.AnyValue, keys *[]string) bool {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_KvlistValue:
		list := x.KvlistValue
		if list == nil {
			return false
		}
		removed := false
		kept := list.Values[:0]
		for _, kv := range list.Values {
			name := prefix + "_" + kv.GetKey()
			if key, ok := sourceKey(name); ok {
				*keys = appendOnce(*keys, key)
				removed = true
				continue
			}
			if stripMap(name, kv.GetValue(), keys) {
				removed = true
				continue
			}
			kept = append(kept, kv)
		}
		clear(list.Values[len(kept):])
		list.Values = kept
		return removed && len(kept) == 0
	case *commonpb.AnyValue_ArrayValue:
		for _, e := range x.ArrayValue.GetValues() {
			stripMap(prefix, e, keys)
		}
	}
	return false
}

// ResetResource sets the source attributes of r to those of s. It deletes every other form of a
// source key, a source key nested in a map value, and platform.cell for an environment sender.
// Duplicate keys collapse to one. The result names each source key, once, whose value changed,
// that the sender may not set, or that appeared in another form. A key that was absent is set and
// not named. A nil r stays nil: the holder of r gives it a resource.
func ResetResource(r *resourcepb.Resource, s Source) (changed []string) {
	if r == nil {
		return nil
	}
	want := SourceAttributes(s)
	kept := make([]*commonpb.KeyValue, 0, len(r.Attributes)+len(want))
	for _, kv := range r.Attributes {
		key, ok := sourceKey(kv.GetKey())
		if !ok {
			if !stripMap(kv.GetKey(), kv.GetValue(), &changed) {
				kept = append(kept, kv)
			}
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

// stripSource deletes every form of a source key from attrs, also inside map values. It returns
// one overwrite for each source key that attrs held.
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
		if stripMap(kv.GetKey(), kv.GetValue(), &keys) {
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
// points and exemplars. It also deletes a source key nested in a map value of such a set. It does
// this for every sender. req is an OTLP logs, trace or metrics export request. The result holds
// one overwrite for each source key in each attribute set.
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

// instruments are the metrics of the gateway. Each attribute set is bounded: signal, reason and
// level are closed sets, attribute is a canonical key, and sender.cluster comes from a verified ID.
type instruments struct {
	overwrites, accepted, denied, failures metric.Int64Counter
	slots                                  metric.Int64UpDownCounter
	lastExport                             metric.Int64Gauge
}

func newInstruments(m metric.Meter) (instruments, error) {
	var in instruments
	var errs [6]error
	in.overwrites, errs[0] = m.Int64Counter(OverwriteCounterName, metric.WithUnit("{attribute}"),
		metric.WithDescription("Source attributes that the telemetry gateway changed or deleted, by attribute, level and sender cluster"))
	in.accepted, errs[1] = m.Int64Counter("cellproxy.gateway.exports.accepted", metric.WithUnit("{request}"),
		metric.WithDescription("Export requests that the upstream accepted, by signal and sender cluster"))
	in.denied, errs[2] = m.Int64Counter("cellproxy.gateway.exports.denied", metric.WithUnit("{request}"),
		metric.WithDescription("Export requests that the gateway refused, by reason, signal and sender cluster"))
	in.failures, errs[3] = m.Int64Counter("cellproxy.gateway.upstream.failures", metric.WithUnit("{request}"),
		metric.WithDescription("Export requests that the upstream failed, by signal and gRPC code"))
	in.slots, errs[4] = m.Int64UpDownCounter("cellproxy.gateway.slots.used", metric.WithUnit("{call}"),
		metric.WithDescription("Calls that hold a gateway slot, by sender cluster"))
	in.lastExport, errs[5] = m.Int64Gauge("cellproxy.gateway.last_export.time", metric.WithUnit("s"),
		metric.WithDescription("Unix time of the last export that the upstream accepted, by signal and sender cluster"))
	return in, errors.Join(errs[:]...)
}

func senderAttr(s Source) attribute.KeyValue { return attribute.String("sender.cluster", s.Cluster) }

// slotPool holds the call slots. A sender takes at most perSender of them.
type slotPool struct {
	mu               sync.Mutex
	total, perSender int
	used             int
	bySender         map[string]int
}

func newSlotPool(total, perSender int) *slotPool {
	return &slotPool{total: total, perSender: perSender, bySender: map[string]int{}}
}

func (p *slotPool) take(sender string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used >= p.total || p.bySender[sender] >= p.perSender {
		return false
	}
	p.used++
	p.bySender[sender]++
	return true
}

func (p *slotPool) give(sender string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.used--
	if p.bySender[sender]--; p.bySender[sender] <= 0 {
		delete(p.bySender, sender)
	}
}

type slotKey struct{}

// slot is one taken call slot. done frees it once.
type slot struct {
	once sync.Once
	free func()
}

func (s *slot) done() { s.once.Do(s.free) }

// logLimiter lets the first line of each key through, then at most one line per logEvery, through
// internal/lograte. It also collects the overwrites of each key between two lines.
type logLimiter struct {
	now     func() time.Time
	limit   *lograte.Limiter
	mu      sync.Mutex
	pending map[string]map[Overwrite]int64
}

func newLogLimiter() *logLimiter {
	l := &logLimiter{now: time.Now, pending: map[string]map[Overwrite]int64{}}
	l.limit = lograte.New(logEvery, maxLogKeys, func() time.Time { return l.now() })
	return l
}

// allow reports whether a line for key may go out, the lines held back before it, and the
// overwrites that add gave key since its last line. It logs the keys that the limiter forgot.
func (l *logLimiter) allow(log *slog.Logger, key string, add []Overwrite) (bool, int, map[Overwrite]int64) {
	counted, ok, suppressed, held := l.limit.Allow(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, h := range held {
		log.Warn("log lines suppressed", "key", h.Key, "suppressed", h.Suppressed)
		delete(l.pending, h.Key)
	}
	p := l.pending[counted]
	if p == nil {
		p = map[Overwrite]int64{}
		l.pending[counted] = p
	}
	for _, o := range add {
		p[o]++
	}
	if !ok {
		return false, 0, nil
	}
	delete(l.pending, counted)
	return true, suppressed, p
}

// Gateway receives OTLP logs, traces and metrics from the senders that the accept loop verified,
// sets the source attributes again from the SPIFFE ID of each sender, and forwards each request
// to the upstream. Register serves its three OTLP services on a gRPC server.
type Gateway struct {
	logs     collogspb.LogsServiceClient
	traces   coltracepb.TraceServiceClient
	metrics  colmetricspb.MetricsServiceClient
	inst     instruments
	log      *slog.Logger
	timeout  time.Duration
	slots    *slotPool
	limiter  *logLimiter
	codec    *otlpCodec
	upstream *grpc.ClientConn
}

// NewGateway returns a gateway that forwards to upstream. Its metrics come from meter.
func NewGateway(upstream *grpc.ClientConn, meter metric.Meter, log *slog.Logger) (*Gateway, error) {
	inst, err := newInstruments(meter)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		logs:     collogspb.NewLogsServiceClient(upstream),
		traces:   coltracepb.NewTraceServiceClient(upstream),
		metrics:  colmetricspb.NewMetricsServiceClient(upstream),
		inst:     inst,
		log:      log,
		timeout:  forwardTimeout,
		slots:    newSlotPool(maxGatewayCalls, maxSenderCalls),
		limiter:  newLogLimiter(),
		codec:    newOTLPCodec(),
		upstream: upstream,
	}, nil
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

// signals maps the method of each OTLP service to its signal.
var signals = map[string]string{
	"/" + collogspb.LogsService_ServiceDesc.ServiceName + "/Export":       "logs",
	"/" + coltracepb.TraceService_ServiceDesc.ServiceName + "/Export":     "traces",
	"/" + colmetricspb.MetricsService_ServiceDesc.ServiceName + "/Export": "metrics",
}

// ExportLogs resets and forwards one logs request.
func (g *Gateway) ExportLogs(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	return forward(ctx, g, "logs", req, resetLogs, g.logs.Export, func(r *collogspb.ExportLogsServiceResponse, n int64, msg string) *collogspb.ExportLogsServiceResponse {
		if r == nil {
			r = &collogspb.ExportLogsServiceResponse{}
		}
		if r.PartialSuccess == nil {
			r.PartialSuccess = &collogspb.ExportLogsPartialSuccess{}
		}
		r.PartialSuccess.RejectedLogRecords += n
		if r.PartialSuccess.ErrorMessage == "" {
			r.PartialSuccess.ErrorMessage = msg
		}
		return r
	})
}

// ExportTraces resets and forwards one trace request.
func (g *Gateway) ExportTraces(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	return forward(ctx, g, "traces", req, resetTraces, g.traces.Export, func(r *coltracepb.ExportTraceServiceResponse, n int64, msg string) *coltracepb.ExportTraceServiceResponse {
		if r == nil {
			r = &coltracepb.ExportTraceServiceResponse{}
		}
		if r.PartialSuccess == nil {
			r.PartialSuccess = &coltracepb.ExportTracePartialSuccess{}
		}
		r.PartialSuccess.RejectedSpans += n
		if r.PartialSuccess.ErrorMessage == "" {
			r.PartialSuccess.ErrorMessage = msg
		}
		return r
	})
}

// ExportMetrics resets and forwards one metrics request.
func (g *Gateway) ExportMetrics(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	return forward(ctx, g, "metrics", req, resetMetrics, g.metrics.Export, func(r *colmetricspb.ExportMetricsServiceResponse, n int64, msg string) *colmetricspb.ExportMetricsServiceResponse {
		if r == nil {
			r = &colmetricspb.ExportMetricsServiceResponse{}
		}
		if r.PartialSuccess == nil {
			r.PartialSuccess = &colmetricspb.ExportMetricsPartialSuccess{}
		}
		r.PartialSuccess.RejectedDataPoints += n
		if r.PartialSuccess.ErrorMessage == "" {
			r.PartialSuccess.ErrorMessage = msg
		}
		return r
	})
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

// tap runs when the headers of a call arrive, before grpc-go reads the message. It refuses a
// peer that is not a telemetry sender, and takes a call slot of the sender. The stats handler
// frees the slot when the call ends, and the end of the stream context frees it on every other
// path.
func (g *Gateway) tap(ctx context.Context, info *tap.Info) (context.Context, error) {
	signal, ok := signals[info.FullMethodName]
	if !ok {
		return ctx, nil
	}
	log := g.log.With("signal", signal)
	src, id, err := peerSource(ctx)
	if err != nil {
		return ctx, g.deny(ctx, log, signal, Source{}, PeerNotAllowed, codes.PermissionDenied, err.Error())
	}
	if !g.slots.take(src.Cluster) {
		return ctx, g.deny(ctx, log.With("sender_cluster", src.Cluster, "spiffe_id", id), signal, src, Overloaded, codes.Unavailable,
			"the sender holds its share of the gateway slots, or every slot is taken")
	}
	attrs := metric.WithAttributes(senderAttr(src))
	g.inst.slots.Add(context.Background(), 1, attrs)
	s := &slot{free: func() {
		g.slots.give(src.Cluster)
		g.inst.slots.Add(context.Background(), -1, attrs)
	}}
	context.AfterFunc(ctx, s.done)
	return context.WithValue(ctx, slotKey{}, s), nil
}

// slotRelease is the stats handler that frees the slot of a call when the call ends.
type slotRelease struct{}

func (slotRelease) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context { return ctx }

func (slotRelease) HandleRPC(ctx context.Context, s stats.RPCStats) {
	if _, ok := s.(*stats.End); !ok {
		return
	}
	if sl, ok := ctx.Value(slotKey{}).(*slot); ok {
		sl.done()
	}
}

func (slotRelease) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }

func (slotRelease) HandleConn(context.Context, stats.ConnStats) {}

// forward checks the peer and the request shape, resets req, counts each overwrite and forwards
// req under a deadline: the deadline of the sender less forwardMargin, at most g.timeout. It
// returns the upstream response unchanged, partial_success included.
func forward[Req proto.Message, Resp any](ctx context.Context, g *Gateway, signal string, req Req,
	reset func(Req, Source) []Overwrite, call func(context.Context, Req, ...grpc.CallOption) (Resp, error),
	partial func(Resp, int64, string) Resp) (Resp, error) {
	var zero Resp
	log := g.log.With("signal", signal)
	refused := g.codec.refusal(req)
	dropped := g.codec.droppedOf(req)
	src, id, err := peerSource(ctx)
	if err != nil {
		return zero, g.deny(ctx, log, signal, Source{}, PeerNotAllowed, codes.PermissionDenied, err.Error())
	}
	log = log.With("sender_cluster", src.Cluster, "spiffe_id", id)
	if refused != nil {
		var de *decodeError
		if errors.As(refused, &de) {
			return zero, g.deny(ctx, log, signal, src, RequestMalformed, codes.InvalidArgument, refused.Error())
		}
		return zero, g.deny(ctx, log, signal, src, RequestTooLarge, codes.ResourceExhausted, refused.Error())
	}
	if ows := reset(req, src); len(ows) > 0 {
		g.count(ctx, src, ows)
		g.logOverwrites(log, src, ows)
	}
	if size := proto.Size(req); size > UpstreamMaxMsgBytes {
		return zero, g.deny(ctx, log, signal, src, RequestTooLarge, codes.ResourceExhausted,
			fmt.Sprintf("the request has %d bytes after the reset, more than the upstream limit of %d", size, UpstreamMaxMsgBytes))
	}
	d := g.timeout
	if dl, ok := ctx.Deadline(); ok {
		d = min(d, time.Until(dl)-forwardMargin)
	}
	if d <= 0 {
		return zero, g.deny(ctx, log, signal, src, UpstreamUnavailable, codes.DeadlineExceeded,
			"the deadline of the sender leaves no time for the upstream")
	}
	fctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	resp, err := call(fctx, req)
	if err == nil {
		attrs := metric.WithAttributes(attribute.String("signal", signal), senderAttr(src))
		g.inst.accepted.Add(ctx, 1, attrs)
		g.inst.lastExport.Record(ctx, time.Now().Unix(), attrs)
		if dropped.resources > 0 {
			g.inst.denied.Add(ctx, int64(dropped.resources), metric.WithAttributes(attribute.String("reason", string(ResourceRefused)),
				attribute.String("signal", signal), senderAttr(src)))
			if ok, suppressed, _ := g.limiter.allow(log, "denied "+string(ResourceRefused)+" "+src.Cluster, nil); ok {
				log.Warn("resources dropped", "reason", string(ResourceRefused), "resources", dropped.resources, "error", dropped.first.Error(), "suppressed", suppressed)
			}
			resp = partial(resp, int64(dropped.records), "the gateway dropped "+strconv.Itoa(dropped.resources)+" resource(s) that pass a shape cap")
		}
		return resp, nil
	}
	if ctx.Err() != nil {
		log.Info("sender canceled the call", "error", ctx.Err().Error())
		return zero, status.FromContextError(ctx.Err()).Err()
	}
	return zero, g.upstreamFailed(ctx, log, signal, src, err)
}

func (g *Gateway) count(ctx context.Context, src Source, ows []Overwrite) {
	n := map[Overwrite]int64{}
	for _, o := range ows {
		n[o]++
	}
	for o, c := range n {
		g.overwrites(ctx, c, o, src)
	}
}

func (g *Gateway) overwrites(ctx context.Context, n int64, o Overwrite, src Source) {
	g.inst.overwrites.Add(ctx, n, metric.WithAttributes(
		attribute.String("attribute", o.Attribute),
		attribute.String("level", o.Level),
		senderAttr(src),
	))
}

// logOverwrites writes one Warn line for each sender at most once per logEvery. The line holds
// every overwrite since the line before, as level/attribute=count.
func (g *Gateway) logOverwrites(log *slog.Logger, src Source, ows []Overwrite) {
	ok, suppressed, counts := g.limiter.allow(log, "overwrite "+src.Cluster, ows)
	if !ok {
		return
	}
	var pairs []string
	var total int64
	for o, c := range counts {
		pairs = append(pairs, fmt.Sprintf("%s/%s=%d", o.Level, o.Attribute, c))
		total += c
	}
	slices.Sort(pairs)
	log.Warn("source attributes overwritten", "count", total, "overwrites", pairs, "suppressed", suppressed)
}

// peerSource returns the source and the ID of the verified TLS peer of the call. Only an otel
// workload is a telemetry sender.
func peerSource(ctx context.Context) (Source, string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return Source{}, "", errors.New("call has no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return Source{}, "", errors.New("call has no TLS peer")
	}
	id, err := x509svid.IDFromCert(info.State.PeerCertificates[0])
	if err != nil {
		return Source{}, "", err
	}
	src, err := ParseSource(id)
	if err != nil {
		return Source{}, id.String(), err
	}
	if src.Role != "otel" {
		return Source{}, id.String(), fmt.Errorf("role %q of %s is not otel", src.Role, id)
	}
	return src, id.String(), nil
}

// deny counts and logs the refusal, and returns code with only "denied". The request ID goes in
// the log and, when the call has a stream, in the trailer. The log line of each sender and reason
// goes out at most once per logEvery.
func (g *Gateway) deny(ctx context.Context, log *slog.Logger, signal string, src Source, reason Reason, code codes.Code, detail string) error {
	attrs := []attribute.KeyValue{attribute.String("reason", string(reason)), attribute.String("signal", signal)}
	if src.Cluster != "" {
		attrs = append(attrs, senderAttr(src))
	}
	g.inst.denied.Add(ctx, 1, metric.WithAttributes(attrs...))
	id := requestID()
	if ok, suppressed, _ := g.limiter.allow(log, "denied "+string(reason)+" "+src.Cluster, nil); ok {
		log.Warn("request denied", "reason", string(reason), "request_id", id, "error", detail, "suppressed", suppressed)
	}
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-request-id", id))
	return status.Error(code, "denied")
}

// upstreamFailed counts and logs an upstream failure. A deadline, a cancel or an Unavailable
// becomes Unavailable, so the sender retries. Any other code stays. The message becomes
// "denied", and only a RetryInfo detail stays, so the sender keeps the throttle delay of the
// upstream.
func (g *Gateway) upstreamFailed(ctx context.Context, log *slog.Logger, signal string, src Source, err error) error {
	st := status.Convert(err)
	g.inst.failures.Add(ctx, 1, metric.WithAttributes(attribute.String("signal", signal), attribute.String("code", st.Code().String())))
	id := requestID()
	if ok, suppressed, _ := g.limiter.allow(log, "upstream "+st.Code().String()+" "+src.Cluster, nil); ok {
		log.Warn("upstream failed", "reason", string(UpstreamUnavailable), "code", st.Code().String(), "request_id", id,
			"error", err.Error(), "suppressed", suppressed)
	}
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-request-id", id))
	p := st.Proto()
	switch st.Code() {
	case codes.DeadlineExceeded, codes.Canceled, codes.Unavailable:
		p.Code = int32(codes.Unavailable)
	}
	p.Message = "denied"
	p.Details = slices.DeleteFunc(p.Details, func(d *anypb.Any) bool {
		return d.GetTypeUrl() != "type.googleapis.com/google.rpc.RetryInfo"
	})
	return status.ErrorProto(p)
}

// otlpBackend serves every handed-over connection with one gRPC server.
type otlpBackend struct {
	srv *grpc.Server
	ln  *handoverListener
	gw  *Gateway
}

// NewOTLPBackend returns the otlp backend. One gRPC server serves the OTLP services of gw on each
// handed-over connection. It refuses a message larger than maxRecvBytes after decompression,
// takes the call slot before it reads a message, and checks the shape of each message before it
// decodes it.
func NewOTLPBackend(gw *Gateway, maxRecvBytes int) Backend {
	srv := grpc.NewServer(
		grpc.Creds(handoverCreds{}),
		grpc.MaxRecvMsgSize(maxRecvBytes),
		grpc.MaxConcurrentStreams(maxConnStreams),
		grpc.MaxHeaderListSize(maxHeaderListBytes),
		grpc.InTapHandle(gw.tap),
		grpc.StatsHandler(slotRelease{}),
		grpc.ForceServerCodecV2(gw.codec),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: minClientPing, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     defaultIdleTimeout,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 30 * time.Second,
			Time:                  time.Minute,
			Timeout:               20 * time.Second,
		}),
	)
	gw.Register(srv)
	ln := &handoverListener{conns: make(chan *handoverConn), done: make(chan struct{})}
	go func() { _ = srv.Serve(ln) }()
	return &otlpBackend{srv: srv, ln: ln, gw: gw}
}

func (b *otlpBackend) Name() string { return "otlp" }

// shutdownWait bounds the wait of Serve for a connection after its context ends.
const shutdownWait = 10 * time.Second

// Serve hands conn to the gRPC server and waits until the server closes it. After ctx ends, it
// waits up to shutdownWait for Shutdown to drain the connection, then closes it.
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
		return nil
	case <-ctx.Done():
	}
	t := time.NewTimer(shutdownWait)
	defer t.Stop()
	select {
	case <-hc.closed:
	case <-t.C:
		_ = hc.Close()
	}
	return nil
}

// Shutdown sends GOAWAY on every connection and waits for the running calls until ctx ends.
// Then it closes every connection and the upstream connection.
func (b *otlpBackend) Shutdown(ctx context.Context) {
	done := make(chan struct{})
	go func() { b.srv.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		b.srv.Stop()
		<-done
	}
	if b.gw.upstream != nil {
		_ = b.gw.upstream.Close()
	}
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
