package cellproxy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/encoding"
	encproto "google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// scanLimits bound the shape of one OTLP request before it is decoded. A request at the receive
// limit holds at most about 220,000 messages when every attribute is a short string (about 17
// wire bytes per message). The caps sit well above that and well above one collector batch:
//   - Resources: 1,024. One batch holds the resources of the pods that sent in one batch period.
//     The cap also bounds the bytes that the resource reset adds (see resetHeadroomBytes).
//   - Scopes: 8,192, eight for each resource.
//   - Records: 65,536 log records, spans, span events, span links, data points and exemplars.
//     That is eight times the default collector batch of 8,192 items.
//   - Attributes: 1,024 in one attribute set or map, eight times the SDK default limit of 128.
//   - Messages: 500,000 in total, more than twice the densest request at the receive limit.
//   - Depth: 32 nested messages. An exemplar attribute with a map three levels deep is at depth 17.
type scanLimits struct {
	Resources, Scopes, Records, Attributes, Messages, Depth int
}

var defaultScanLimits = scanLimits{Resources: 1024, Scopes: 8192, Records: 65536, Attributes: 1024, Messages: 500000, Depth: 32}

type scanKind int

const (
	kindOther scanKind = iota
	kindResource
	kindScope
	kindRecord
	kindAttribute
)

var scanKinds = map[protoreflect.FullName]scanKind{
	"opentelemetry.proto.logs.v1.ResourceLogs":                     kindResource,
	"opentelemetry.proto.trace.v1.ResourceSpans":                   kindResource,
	"opentelemetry.proto.metrics.v1.ResourceMetrics":               kindResource,
	"opentelemetry.proto.logs.v1.ScopeLogs":                        kindScope,
	"opentelemetry.proto.trace.v1.ScopeSpans":                      kindScope,
	"opentelemetry.proto.metrics.v1.ScopeMetrics":                  kindScope,
	"opentelemetry.proto.logs.v1.LogRecord":                        kindRecord,
	"opentelemetry.proto.trace.v1.Span":                            kindRecord,
	"opentelemetry.proto.trace.v1.Span.Event":                      kindRecord,
	"opentelemetry.proto.trace.v1.Span.Link":                       kindRecord,
	"opentelemetry.proto.metrics.v1.NumberDataPoint":               kindRecord,
	"opentelemetry.proto.metrics.v1.HistogramDataPoint":            kindRecord,
	"opentelemetry.proto.metrics.v1.ExponentialHistogramDataPoint": kindRecord,
	"opentelemetry.proto.metrics.v1.SummaryDataPoint":              kindRecord,
	"opentelemetry.proto.metrics.v1.Exemplar":                      kindRecord,
	"opentelemetry.proto.common.v1.KeyValue":                       kindAttribute,
}

// errMalformed marks wire bytes that the scan cannot parse. proto.Unmarshal then reports them.
var errMalformed = errors.New("malformed wire bytes")

type scanner struct {
	lim                                  scanLimits
	resources, scopes, records, messages int
}

// scanMessage walks the wire bytes b of a message of type md with protowire, and counts each
// nested message. It allocates nothing, and it stops at the first count above its cap.
func (s *scanner) scanMessage(b []byte, md protoreflect.MessageDescriptor, depth int) error {
	if depth > s.lim.Depth {
		return fmt.Errorf("messages nest deeper than %d", s.lim.Depth)
	}
	fields := md.Fields()
	attrs := 0
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errMalformed
		}
		b = b[n:]
		if typ != protowire.BytesType {
			if n = protowire.ConsumeFieldValue(num, typ, b); n < 0 {
				return errMalformed
			}
			b = b[n:]
			continue
		}
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return errMalformed
		}
		b = b[n:]
		fd := fields.ByNumber(num)
		if fd == nil || fd.Kind() != protoreflect.MessageKind {
			continue
		}
		child := fd.Message()
		if s.messages++; s.messages > s.lim.Messages {
			return fmt.Errorf("more than %d messages", s.lim.Messages)
		}
		switch scanKinds[child.FullName()] {
		case kindResource:
			if s.resources++; s.resources > s.lim.Resources {
				return fmt.Errorf("more than %d resources", s.lim.Resources)
			}
		case kindScope:
			if s.scopes++; s.scopes > s.lim.Scopes {
				return fmt.Errorf("more than %d scopes", s.lim.Scopes)
			}
		case kindRecord:
			if s.records++; s.records > s.lim.Records {
				return fmt.Errorf("more than %d records or points", s.lim.Records)
			}
		case kindAttribute:
			if attrs++; attrs > s.lim.Attributes {
				return fmt.Errorf("more than %d attributes in one set", s.lim.Attributes)
			}
		}
		if err := s.scanMessage(v, child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// otlpCodec is the server codec of the otlp backend. Before it decodes a request, it scans the
// wire bytes and refuses a request whose shape passes scanLimits. grpc-go turns every codec error
// into Internal, so a refused request decodes to an empty message, and the handler reads the
// refusal with refusal. Unknown fields are dropped, so no attribute reaches the upstream in a
// field that the gateway does not know.
type otlpCodec struct {
	limits  scanLimits
	refused sync.Map
	// decoded counts the requests that passed the scan.
	decoded atomic.Int64
}

func newOTLPCodec() *otlpCodec { return &otlpCodec{limits: defaultScanLimits} }

func (c *otlpCodec) Name() string { return encproto.Name }

func (c *otlpCodec) Marshal(v any) (mem.BufferSlice, error) {
	return encoding.GetCodecV2(encproto.Name).Marshal(v)
}

func (c *otlpCodec) Unmarshal(data mem.BufferSlice, v any) error {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("message is %T, want a proto.Message", v)
	}
	buf := data.MaterializeToBuffer(mem.DefaultBufferPool())
	defer buf.Free()
	b := buf.ReadOnlyData()
	s := scanner{lim: c.limits}
	if err := s.scanMessage(b, m.ProtoReflect().Descriptor(), 0); err != nil && !errors.Is(err, errMalformed) {
		c.refused.Store(m, err)
		return nil
	}
	c.decoded.Add(1)
	return proto.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, m)
}

// refusal returns the scan error of req, once.
func (c *otlpCodec) refusal(req any) error {
	if c == nil {
		return nil
	}
	if err, ok := c.refused.LoadAndDelete(req); ok {
		return err.(error)
	}
	return nil
}
