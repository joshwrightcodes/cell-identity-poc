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
//   - NumberBytes: 8 MiB of decoded repeated numbers, for example histogram buckets. A fixed-width
//     field decodes to its wire size, so only varints (up to 8 bytes from 1 wire byte) reach the
//     cap. 8 MiB holds one million 64-bit buckets, and a classic histogram batch at the receive
//     limit holds about 230,000.
//   - Strings: 65,536 elements of repeated strings in total. In OTLP only the id_keys and
//     description_keys of an entity reference are such fields, with a few keys each.
type scanLimits struct {
	Resources, Scopes, Records, Attributes, Messages, Depth, NumberBytes, Strings int
}

var defaultScanLimits = scanLimits{
	Resources: 1024, Scopes: 8192, Records: 65536, Attributes: 1024, Messages: 500000, Depth: 32,
	NumberBytes: 8 << 20, Strings: 65536,
}

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
	lim                                                        scanLimits
	resources, scopes, records, messages, numberBytes, strings int
}

// goSize is the size of one element of a repeated number field of kind k in a Go slice.
func goSize(k protoreflect.Kind) int {
	switch k {
	case protoreflect.BoolKind:
		return 1
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind,
		protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return 8
	}
	return 4
}

// packedCount is the number of elements in the packed bytes v of a field of kind k.
func packedCount(v []byte, k protoreflect.Kind) int {
	switch k {
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return len(v) / 8
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return len(v) / 4
	}
	n := 0
	for _, c := range v {
		if c < 0x80 {
			n++
		}
	}
	return n
}

// numbers counts n decoded elements of a repeated number field of kind k.
func (s *scanner) numbers(n int, k protoreflect.Kind) error {
	if s.numberBytes += n * goSize(k); s.numberBytes > s.lim.NumberBytes {
		return fmt.Errorf("more than %d bytes of repeated numbers", s.lim.NumberBytes)
	}
	return nil
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
		fd := fields.ByNumber(num)
		if typ != protowire.BytesType {
			if n = protowire.ConsumeFieldValue(num, typ, b); n < 0 {
				return errMalformed
			}
			b = b[n:]
			if fd != nil && fd.IsList() {
				if err := s.numbers(1, fd.Kind()); err != nil {
					return err
				}
			}
			continue
		}
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return errMalformed
		}
		b = b[n:]
		if fd == nil {
			continue
		}
		switch k := fd.Kind(); {
		case k == protoreflect.MessageKind:
		case !fd.IsList():
			continue
		case k == protoreflect.StringKind || k == protoreflect.BytesKind:
			if s.strings++; s.strings > s.lim.Strings {
				return fmt.Errorf("more than %d elements of repeated strings", s.lim.Strings)
			}
			continue
		default:
			if err := s.numbers(packedCount(v, k), k); err != nil {
				return err
			}
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
//
// The collector of a cluster merges the telemetry of every workload into one request, so one
// resource that passes a shape cap must not make the gateway refuse the others. The scan therefore
// reads each resource of the request on its own. A resource that passes the caps of one resource
// (attributes in one set, scopes, nesting depth, records, messages, repeated numbers and strings) is
// dropped, and the handler reports it as a partial success. The totals of the whole request keep
// their caps, and a request in which no resource passes is refused as a whole.
type otlpCodec struct {
	limits  scanLimits
	refused sync.Map
	dropped sync.Map
	// decoded counts the requests that passed the scan.
	decoded atomic.Int64
}

// droppedResources says how many resources of a request the scan dropped, how many records and points
// they held (at least one for each), and why the first one failed.
type droppedResources struct {
	resources, records int
	first              error
}

func newOTLPCodec() *otlpCodec { return &otlpCodec{limits: defaultScanLimits} }

func (c *otlpCodec) Name() string { return encproto.Name }

func (c *otlpCodec) Marshal(v any) (mem.BufferSlice, error) {
	return encoding.GetCodecV2(encproto.Name).Marshal(v)
}

// scanRequest reads the resources of a request of type md. It returns the wire bytes without the
// resources that pass a cap of one resource, and what it dropped. It returns an error when a total
// passes its cap or no resource passes. A request of other fields only has nothing to drop.
func (c *otlpCodec) scanRequest(b []byte, md protoreflect.MessageDescriptor) ([]byte, droppedResources, error) {
	var drop droppedResources
	total := scanner{lim: c.limits}
	fields := md.Fields()
	var kept []byte
	keptStart := 0
	survivors := 0
	rest := b
	for len(rest) > 0 {
		start := len(b) - len(rest)
		num, typ, n := protowire.ConsumeTag(rest)
		if n < 0 {
			return b, drop, errMalformed
		}
		rest = rest[n:]
		if typ != protowire.BytesType {
			if n = protowire.ConsumeFieldValue(num, typ, rest); n < 0 {
				return b, drop, errMalformed
			}
			rest = rest[n:]
			continue
		}
		v, n := protowire.ConsumeBytes(rest)
		if n < 0 {
			return b, drop, errMalformed
		}
		rest = rest[n:]
		end := len(b) - len(rest)
		fd := fields.ByNumber(num)
		if fd == nil || fd.Kind() != protoreflect.MessageKind || !fd.IsList() || scanKinds[fd.Message().FullName()] != kindResource {
			continue
		}
		if total.messages++; total.messages > total.lim.Messages {
			return b, drop, fmt.Errorf("more than %d messages", total.lim.Messages)
		}
		if total.resources++; total.resources > total.lim.Resources {
			return b, drop, fmt.Errorf("more than %d resources", total.lim.Resources)
		}
		one := scanner{lim: c.limits}
		if err := one.scanMessage(v, fd.Message(), 1); err != nil {
			if errors.Is(err, errMalformed) {
				return b, drop, errMalformed
			}
			if drop.resources++; drop.first == nil {
				drop.first = err
			}
			drop.records += max(one.records, 1)
			kept = append(kept, b[keptStart:start]...)
			keptStart = end
			continue
		}
		survivors++
		total.messages += one.messages
		total.records += one.records
		total.scopes += one.scopes
		total.numberBytes += one.numberBytes
		total.strings += one.strings
		switch {
		case total.messages > total.lim.Messages:
			return b, drop, fmt.Errorf("more than %d messages", total.lim.Messages)
		case total.records > total.lim.Records:
			return b, drop, fmt.Errorf("more than %d records or points", total.lim.Records)
		case total.numberBytes > total.lim.NumberBytes:
			return b, drop, fmt.Errorf("more than %d bytes of repeated numbers", total.lim.NumberBytes)
		case total.strings > total.lim.Strings:
			return b, drop, fmt.Errorf("more than %d elements of repeated strings", total.lim.Strings)
		}
	}
	if drop.resources == 0 {
		return b, drop, nil
	}
	if survivors == 0 {
		return b, drop, drop.first
	}
	return append(kept, b[keptStart:]...), drop, nil
}

func (c *otlpCodec) Unmarshal(data mem.BufferSlice, v any) error {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("message is %T, want a proto.Message", v)
	}
	buf := data.MaterializeToBuffer(mem.DefaultBufferPool())
	defer buf.Free()
	b, drop, err := c.scanRequest(buf.ReadOnlyData(), m.ProtoReflect().Descriptor())
	if err != nil && !errors.Is(err, errMalformed) {
		c.refused.Store(m, err)
		return nil
	}
	if drop.resources > 0 {
		c.dropped.Store(m, drop)
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

// droppedOf returns what the scan dropped from req, once.
func (c *otlpCodec) droppedOf(req any) droppedResources {
	if c == nil {
		return droppedResources{}
	}
	if d, ok := c.dropped.LoadAndDelete(req); ok {
		return d.(droppedResources)
	}
	return droppedResources{}
}
