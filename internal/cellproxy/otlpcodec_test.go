package cellproxy

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"testing"

	"go.opentelemetry.io/otel/attribute"
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
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const logsExport = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"

// badUTF8 is the byte string that replaces the marker "ZZZZ" in marshaled wire bytes. It is not valid UTF-8.
var badUTF8 = []byte{0xff, 0xfe, 0xfd, 0xfc}

// wireOf marshals m and replaces each marker "ZZZZ" with invalid UTF-8. proto.Marshal refuses invalid
// UTF-8 itself, so a hostile sender is simulated on the wire bytes.
func wireOf(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(b, []byte("ZZZZ"), badUTF8)
}

// logsRequest is the wire bytes of a logs request that holds the given resources in order.
func logsRequest(t testing.TB, rls ...*logspb.ResourceLogs) []byte {
	t.Helper()
	var out []byte
	for _, rl := range rls {
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, wireOf(t, rl))
	}
	return out
}

func mapLen(m interface{ Range(func(any, any) bool) }) int {
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// decode runs the codec like grpc-go and the handler do: Unmarshal, then the refusal and the drop.
func decode(t testing.TB, c *otlpCodec, wire []byte) (*collogspb.ExportLogsServiceRequest, droppedResources, error) {
	t.Helper()
	m := &collogspb.ExportLogsServiceRequest{}
	if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire)}, m); err != nil {
		return m, droppedResources{}, err
	}
	refused := c.refusal(m)
	return m, c.droppedOf(m), refused
}

// TestOTLPCodecKeepsNoStateAfterFailedDecode checks that a request that fails to decode after the scan
// dropped a resource leaves nothing in the codec. grpc-go never calls the handler for such a request, so
// an entry would stay for good, and it would keep the decoded request alive.
func TestOTLPCodecKeepsNoStateAfterFailedDecode(t *testing.T) {
	hostile := logsRequest(t, hostileResource("attributes"))
	truncated := protowire.AppendTag(nil, 1, protowire.BytesType)
	truncated = append(truncated, 0x05, 0x01)
	wires := map[string][]byte{
		"truncated tail": append(append([]byte{}, hostile...), truncated...),
		"hostile then good then truncated": append(append(append([]byte{}, hostile...), logsRequest(t, normalResource("ok"))...),
			truncated...),
	}
	for name, wire := range wires {
		t.Run(name, func(t *testing.T) {
			c := newOTLPCodec()
			for range 1000 {
				m := &collogspb.ExportLogsServiceRequest{}
				if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire)}, m); err == nil {
					if c.refusal(m) == nil {
						t.Fatal("the codec accepted a truncated request")
					}
				}
			}
			if n, r := mapLen(&c.dropped), mapLen(&c.refused); n != 0 || r != 0 {
				t.Fatalf("after 1000 failed decodes the codec holds %d drops and %d refusals, want none", n, r)
			}
		})
	}
}

// TestOTLPCodecDropsResourceWithInvalidUTF8 checks that a string that is not valid UTF-8 makes the scan drop
// its own resource, and no other. protobuf-go refuses the whole message for such a string, and the sender
// treats that refusal as permanent, so one workload would drop the data of every other workload in a batch.
func TestOTLPCodecDropsResourceWithInvalidUTF8(t *testing.T) {
	bad := map[string]*logspb.ResourceLogs{
		"attribute value": {Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("k", "ZZZZ")}}},
		"attribute key":   {Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("ZZZZ", "v")}}},
		"schema url":      {SchemaUrl: "ZZZZ"},
		"scope name":      {ScopeLogs: []*logspb.ScopeLogs{{Scope: &commonpb.InstrumentationScope{Name: "ZZZZ"}}}},
		"log body": {ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{
			{Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "ZZZZ"}}}}}}},
		"repeated string": {Resource: &resourcepb.Resource{EntityRefs: []*commonpb.EntityRef{{IdKeys: []string{"ZZZZ"}}}}},
	}
	for name, rl := range bad {
		t.Run(name, func(t *testing.T) {
			c := newOTLPCodec()
			m, drop, err := decode(t, c, logsRequest(t, normalResource("first"), rl, normalResource("second")))
			if err != nil {
				t.Fatalf("the codec failed the whole request: %v", err)
			}
			if drop.resources != 1 || drop.first == nil {
				t.Errorf("dropped %+v, want one resource and a reason", drop)
			}
			if len(m.ResourceLogs) != 2 {
				t.Fatalf("decoded %d resources, want the 2 normal ones", len(m.ResourceLogs))
			}
			if n, r := mapLen(&c.dropped), mapLen(&c.refused); n != 0 || r != 0 {
				t.Errorf("the codec holds %d drops and %d refusals after the handler read them", n, r)
			}
			_, _, err = decode(t, c, logsRequest(t, rl))
			if err == nil {
				t.Error("a request with only the invalid resource was accepted")
			}
		})
	}
}

// TestGatewayAnswersInvalidUTF8WithPartialSuccess goes through the real gRPC server and codec.
func TestGatewayAnswersInvalidUTF8WithPartialSuccess(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	conn := h.serve(t, otelPattern, otelID1)
	bad := &logspb.ResourceLogs{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("k", "ZZZZ")}},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{}, {}}}}}
	resp := &collogspb.ExportLogsServiceResponse{}
	err := conn.Invoke(t.Context(), logsExport, &rawMessage{b: logsRequest(t, normalResource("first"), bad, normalResource("second"))},
		resp, grpc.ForceCodecV2(rawCodec{}))
	if err != nil {
		t.Fatalf("the gateway refused the request: %v", err)
	}
	if got := resp.GetPartialSuccess().GetRejectedLogRecords(); got != 2 {
		t.Errorf("rejected %d log records, want exactly 2", got)
	}
	h.up.mu.Lock()
	if len(h.up.logs) != 1 || len(h.up.logs[0].ResourceLogs) != 2 {
		t.Errorf("upstream got %v, want one request with the two normal resources", h.up.logs)
	}
	h.up.mu.Unlock()
	waitForLog(t, h.log, "resources dropped", ResourceRefused, "")
	want := map[attribute.Distinct]int64{attrSet(attribute.String("reason", string(ResourceRefused)), attribute.String("signal", "logs"),
		attribute.String("sender.cluster", "dev-cell-1")): 1}
	if got := h.points(t, "cellproxy.gateway.exports.denied"); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("denied is %v, want %v", got, want)
	}
	if n, r := mapLen(&h.gw.codec.dropped), mapLen(&h.gw.codec.refused); n != 0 || r != 0 {
		t.Errorf("the codec holds %d drops and %d refusals", n, r)
	}
}

// TestGatewayAnswersUndecodableRequestWithInvalidArgument checks the status of a request that still fails
// to decode, and that the gateway logs and counts the refusal.
func TestGatewayAnswersUndecodableRequestWithInvalidArgument(t *testing.T) {
	h := newGWHarness(t, &otlpUpstream{})
	conn := h.serve(t, otelPattern, otelID1)
	truncated := append(logsRequest(t, hostileResource("attributes")), 0x0a, 0x05, 0x01)
	for name, wire := range map[string][]byte{
		"truncated resource":  truncated,
		"only invalid string": logsRequest(t, &logspb.ResourceLogs{SchemaUrl: "ZZZZ"}),
	} {
		t.Run(name, func(t *testing.T) {
			err := conn.Invoke(t.Context(), logsExport, &rawMessage{b: wire}, &collogspb.ExportLogsServiceResponse{}, grpc.ForceCodecV2(rawCodec{}))
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("got %v, want InvalidArgument", err)
			}
		})
	}
	waitForLog(t, h.log, "request denied", "request_malformed", "")
	if got := h.points(t, "cellproxy.gateway.exports.denied")[attrSet(attribute.String("reason", "request_malformed"),
		attribute.String("signal", "logs"), attribute.String("sender.cluster", "dev-cell-1"))]; got < 1 {
		t.Errorf("the denied counter has %d for request_malformed, want at least 1", got)
	}
	if n, r := mapLen(&h.gw.codec.dropped), mapLen(&h.gw.codec.refused); n != 0 || r != 0 {
		t.Errorf("the codec holds %d drops and %d refusals", n, r)
	}
}

// --- whole-request totals ---

// emptyValues is the wire bytes of an array value with n empty AnyValues. No kind cap counts an AnyValue,
// so only the message cap sees them.
func emptyValues(n int) []byte { return bytes.Repeat([]byte{0x0a, 0x00}, n) }

// logRecordWith wraps the field v of a log record, as a resource of a logs request.
func resourceWithAttrValue(arrayValue []byte) []byte {
	// ArrayValue -> AnyValue.array_value (5) -> KeyValue.value (2) -> LogRecord.attributes (6)
	// -> ScopeLogs.log_records (2) -> ResourceLogs.scope_logs (2) -> request.resource_logs (1)
	return nest(arrayValue, 5, 2, 6, 2, 2, 1)
}

// decodeInto runs the codec on wire into m, and returns the refusal.
func decodeInto(t testing.TB, c *otlpCodec, wire []byte, m proto.Message) error {
	t.Helper()
	if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire)}, m); err != nil {
		return err
	}
	return c.refusal(m)
}

// TestOTLPCodecTotalsOfTheWholeRequest checks each total with the excess in the last resource: each resource
// passes every cap of one resource on its own, and only the totals of the request refuse the sum.
func TestOTLPCodecTotalsOfTheWholeRequest(t *testing.T) {
	lim := defaultScanLimits
	scopes := func(n int) []byte { return nest(bytes.Repeat([]byte{0x12, 0x00}, n), 1) }
	records := func(n int) []byte { return nest(bytes.Repeat([]byte{0x12, 0x00}, n), 2, 1) }
	packedDoubles := func(n int) []byte {
		// HistogramDataPoint.explicit_bounds (7), Histogram.data_points (1), Metric.histogram (9),
		// ScopeMetrics.metrics (2), ResourceMetrics.scope_metrics (2), request.resource_metrics (1).
		b := protowire.AppendBytes(protowire.AppendTag(nil, 7, protowire.BytesType), make([]byte, 8*n))
		return nest(b, 1, 9, 2, 2, 1)
	}
	idKeys := func(n int) []byte {
		var b []byte
		for range n {
			b = protowire.AppendBytes(protowire.AppendTag(b, 3, protowire.BytesType), nil)
		}
		return nest(b, 3, 1, 1)
	}
	twice := func(one []byte) []byte { return append(append([]byte{}, one...), one...) }
	cases := []struct {
		name string
		one  []byte
		req  func() proto.Message
		want string
	}{
		{"messages", resourceWithAttrValue(emptyValues(300000)), func() proto.Message { return &collogspb.ExportLogsServiceRequest{} }, "messages"},
		{"scopes", scopes(lim.Scopes * 3 / 4), func() proto.Message { return &collogspb.ExportLogsServiceRequest{} }, "scopes"},
		{"records", records(lim.Records * 3 / 4), func() proto.Message { return &collogspb.ExportLogsServiceRequest{} }, "records"},
		{"number bytes", packedDoubles(lim.NumberBytes * 3 / 4 / 8), func() proto.Message { return &colmetricspb.ExportMetricsServiceRequest{} }, "bytes of repeated numbers"},
		{"strings", idKeys(lim.Strings * 3 / 4), func() proto.Message { return &collogspb.ExportLogsServiceRequest{} }, "elements of repeated strings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newOTLPCodec()
			if err := decodeInto(t, c, tc.one, tc.req()); err != nil {
				t.Fatalf("one resource alone was refused: %v", err)
			}
			err := decodeInto(t, c, twice(tc.one), tc.req())
			if err == nil {
				t.Fatalf("the codec accepted two resources that pass the total of %s together", tc.name)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.want)) {
				t.Errorf("refusal %q does not name %q", err, tc.want)
			}
		})
	}
	t.Run("1025 small resources", func(t *testing.T) {
		c := newOTLPCodec()
		wire := bytes.Repeat([]byte{0x0a, 0x00}, lim.Resources+1)
		err := decodeInto(t, c, wire, &collogspb.ExportLogsServiceRequest{})
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte("resources")) {
			t.Fatalf("got %v, want a refusal of more than %d resources", err, lim.Resources)
		}
		if err := decodeInto(t, c, wire[:2*lim.Resources], &collogspb.ExportLogsServiceRequest{}); err != nil {
			t.Fatalf("%d resources were refused: %v", lim.Resources, err)
		}
	})
}

// TestOTLPCodecCountsAttributesAcrossMergedFields checks the cap on attributes in one set when a singular
// message field repeats: protobuf merges the occurrences into one message.
func TestOTLPCodecCountsAttributesAcrossMergedFields(t *testing.T) {
	var rl []byte
	for i := range 3 {
		r := wireOf(t, &resourcepb.Resource{Attributes: attrsN(1000, fmt.Sprintf("p%d_", i))})
		rl = protowire.AppendTag(rl, 1, protowire.BytesType)
		rl = protowire.AppendBytes(rl, r)
	}
	c := newOTLPCodec()
	m, drop, err := decode(t, c, nest(rl, 1))
	if err == nil && drop.resources == 0 {
		t.Fatalf("one merged attribute set of %d passed the cap of %d", len(m.ResourceLogs[0].GetResource().GetAttributes()), c.limits.Attributes)
	}
}

func attrsN(n int, prefix string) []*commonpb.KeyValue {
	out := make([]*commonpb.KeyValue, n)
	for i := range out {
		out[i] = str(fmt.Sprintf("%s%d", prefix, i), "v")
	}
	return out
}

// depthRequest is a logs request with one resource whose deepest message is at level d. The ResourceLogs is
// level 1, then ScopeLogs, LogRecord and KeyValue are levels 2 to 4. After that the levels repeat
// AnyValue, KeyValueList and KeyValue.
func depthRequest(d int) []byte {
	var b []byte
	for level := d; level >= 2; level-- {
		var num protowire.Number
		switch {
		case level <= 3:
			num = 2
		case level == 4:
			num = 6
		default:
			num = [3]protowire.Number{2, 6, 1}[(level-5)%3]
		}
		b = nest(b, num)
	}
	return nest(b, 1)
}

// TestOTLPCodecDepthBoundary checks that a resource nests at most Depth levels, the resource being the
// first, and that the next level is dropped.
func TestOTLPCodecDepthBoundary(t *testing.T) {
	for _, d := range []int{defaultScanLimits.Depth, defaultScanLimits.Depth + 1} {
		c := newOTLPCodec()
		m, drop, err := decode(t, c, append(depthRequest(d), logsRequest(t, normalResource("ok"))...))
		if err != nil {
			t.Fatalf("level %d: %v", d, err)
		}
		want := 0
		if d > defaultScanLimits.Depth {
			want = 1
		}
		if drop.resources != want {
			t.Errorf("level %d: dropped %d resources, want %d (decoded %d)", d, drop.resources, want, len(m.ResourceLogs))
		}
	}
}

// TestGatewayCountsRejectedItemsExactly checks that a partial success counts only the top-level items of
// the signal, not span events, links or exemplars, and keeps the message of the upstream.
func TestGatewayCountsRejectedItemsExactly(t *testing.T) {
	long := attrsN(defaultScanLimits.Attributes+1, "k")
	res := func(n string) *resourcepb.Resource {
		return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("service.name", n)}}
	}
	t.Run("traces", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		conn := h.serve(t, otelPattern, otelID1)
		span := &tracepb.Span{Name: "s", Events: []*tracepb.Span_Event{{}, {}, {}}, Links: []*tracepb.Span_Link{{}, {}}}
		bad := &tracepb.Span{Name: "b", Attributes: long}
		resp, err := coltracepb.NewTraceServiceClient(conn).Export(t.Context(), &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{
			{Resource: res("ok"), ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "ok"}}}}},
			{Resource: res("bad"), ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{span, span, bad}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.GetPartialSuccess().GetRejectedSpans(); got != 3 {
			t.Errorf("rejected %d spans, want exactly 3", got)
		}
	})
	t.Run("metrics", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		conn := h.serve(t, otelPattern, otelID1)
		ex := []*metricspb.Exemplar{{}, {}, {}}
		gauge := func(a []*commonpb.KeyValue) *metricspb.Metric {
			return &metricspb.Metric{Name: "m", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{
				{Exemplars: ex, Attributes: a}, {Exemplars: ex}}}}}
		}
		resp, err := colmetricspb.NewMetricsServiceClient(conn).Export(t.Context(), &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{
			{Resource: res("ok"), ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{gauge(nil)}}}},
			{Resource: res("bad"), ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{gauge(long)}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.GetPartialSuccess().GetRejectedDataPoints(); got != 2 {
			t.Errorf("rejected %d data points, want exactly 2", got)
		}
	})
	t.Run("keeps the upstream message", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{logsResp: &collogspb.ExportLogsServiceResponse{
			PartialSuccess: &collogspb.ExportLogsPartialSuccess{RejectedLogRecords: 4, ErrorMessage: "upstream says no"}}})
		conn := h.serve(t, otelPattern, otelID1)
		resp, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{
			normalResource("ok"), hostileResource("attributes")}})
		if err != nil {
			t.Fatal(err)
		}
		ps := resp.GetPartialSuccess()
		if ps.GetRejectedLogRecords() != 5 || ps.GetErrorMessage() != "upstream says no" {
			t.Errorf("partial success %v, want 5 rejected records and the upstream message", ps)
		}
	})
}

// TestOTLPCodecDoesNotDecodeADroppedBombBeforeATruncatedTail checks that a request whose first resource the scan
// drops, and whose tail is truncated, is refused without a decode. protobuf-go would decode the dropped resource in
// full before it reached the tail: about 196 MiB for a request under the receive limit.
func TestOTLPCodecDoesNotDecodeADroppedBombBeforeATruncatedTail(t *testing.T) {
	bomb := resourceWithAttrValue(emptyValues(1_834_000))
	if len(bomb) > MaxRecvMsgBytes {
		t.Fatalf("the bomb has %d bytes, more than the receive limit", len(bomb))
	}
	wire := append(bomb, 0x0a, 0x05, 0x01)
	c := newOTLPCodec()
	m := &collogspb.ExportLogsServiceRequest{}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire)}, m)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	refused := c.refusal(m)
	var de *decodeError
	if !errors.As(refused, &de) {
		t.Fatalf("refusal %v, want a decodeError", refused)
	}
	if alloc := (after.TotalAlloc - before.TotalAlloc) >> 20; alloc > 16 {
		t.Errorf("the codec allocated %d MiB for a refused request, want at most 16 MiB", alloc)
	}
	if n := c.decoded.Load(); n != 0 {
		t.Errorf("the codec decoded %d requests, want none", n)
	}
	if n, r := mapLen(&c.dropped), mapLen(&c.refused); n != 0 || r != 0 {
		t.Errorf("the codec holds %d drops and %d refusals", n, r)
	}
}
