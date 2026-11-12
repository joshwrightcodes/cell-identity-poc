package cellproxy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unicode/utf8"

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
	// kindItem is a top-level item of a signal: a log record, a span or a data point. It also counts as a
	// record.
	kindItem
)

var scanKinds = map[protoreflect.FullName]scanKind{
	"opentelemetry.proto.logs.v1.ResourceLogs":                     kindResource,
	"opentelemetry.proto.trace.v1.ResourceSpans":                   kindResource,
	"opentelemetry.proto.metrics.v1.ResourceMetrics":               kindResource,
	"opentelemetry.proto.logs.v1.ScopeLogs":                        kindScope,
	"opentelemetry.proto.trace.v1.ScopeSpans":                      kindScope,
	"opentelemetry.proto.metrics.v1.ScopeMetrics":                  kindScope,
	"opentelemetry.proto.logs.v1.LogRecord":                        kindItem,
	"opentelemetry.proto.trace.v1.Span":                            kindItem,
	"opentelemetry.proto.trace.v1.Span.Event":                      kindRecord,
	"opentelemetry.proto.trace.v1.Span.Link":                       kindRecord,
	"opentelemetry.proto.metrics.v1.NumberDataPoint":               kindItem,
	"opentelemetry.proto.metrics.v1.HistogramDataPoint":            kindItem,
	"opentelemetry.proto.metrics.v1.ExponentialHistogramDataPoint": kindItem,
	"opentelemetry.proto.metrics.v1.SummaryDataPoint":              kindItem,
	"opentelemetry.proto.metrics.v1.Exemplar":                      kindRecord,
	"opentelemetry.proto.common.v1.KeyValue":                       kindAttribute,
}

// errMalformed marks wire bytes that the scan cannot parse. proto.Unmarshal then reports them.
var errMalformed = errors.New("malformed wire bytes")

// decodeError is a request that the gateway cannot decode, as opposed to one that passes a shape cap.
// The handler answers it with InvalidArgument.
type decodeError struct{ err error }

func (e *decodeError) Error() string { return e.err.Error() }

func (e *decodeError) Unwrap() error { return e.err }

// errInvalidUTF8 marks a proto3 string that is not valid UTF-8. protobuf-go refuses the whole message for
// it, so the scan drops the resource that holds it.
var errInvalidUTF8 error = &decodeError{errors.New("string field contains invalid UTF-8")}

type scanner struct {
	lim                                                        scanLimits
	resources, scopes, records, messages, numberBytes, strings int
	// items counts the top-level items of the signal. count turns the scanner into a counter that
	// accepts any string.
	items int
	count bool
}

// overTotal returns the error for the first total of a whole request that passes its cap.
func (s *scanner) overTotal() error {
	switch {
	case s.resources > s.lim.Resources:
		return fmt.Errorf("more than %d resources", s.lim.Resources)
	case s.scopes > s.lim.Scopes:
		return fmt.Errorf("more than %d scopes", s.lim.Scopes)
	case s.messages > s.lim.Messages:
		return fmt.Errorf("more than %d messages", s.lim.Messages)
	case s.records > s.lim.Records:
		return fmt.Errorf("more than %d records or points", s.lim.Records)
	case s.numberBytes > s.lim.NumberBytes:
		return fmt.Errorf("more than %d bytes of repeated numbers", s.lim.NumberBytes)
	case s.strings > s.lim.Strings:
		return fmt.Errorf("more than %d elements of repeated strings", s.lim.Strings)
	}
	return nil
}

// countItems returns the top-level items in the resource bytes b, with no cap but the nesting depth of
// the Go stack. A resource that fails a cap stops the scan early, and the partial success must still
// count every item it drops.
func countItems(b []byte, md protoreflect.MessageDescriptor) int {
	const huge = int(^uint(0) >> 1)
	s := scanner{count: true, lim: scanLimits{Resources: huge, Scopes: huge, Records: huge, Attributes: huge, Messages: huge,
		Depth: 1024, NumberBytes: huge, Strings: huge}}
	_, _ = s.scanMessage(b, md, 1, 0)
	return s.items
}

// singularCounter is the count of attributes in one set, shared by the occurrences of a singular
// message field. protobuf merges them into one message.
type singularCounter struct {
	num protowire.Number
	n   int
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
// nested message. It allocates nothing, and it stops at the first count above its cap. attrs counts the
// attributes of the message, and the occurrences of a singular message field of one parent share it.
func (s *scanner) scanMessage(b []byte, md protoreflect.MessageDescriptor, depth int, attrs int) (int, error) {
	if depth > s.lim.Depth {
		return attrs, fmt.Errorf("messages nest deeper than %d", s.lim.Depth)
	}
	fields := md.Fields()
	var singular [8]singularCounter
	nsingular := 0
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return attrs, errMalformed
		}
		b = b[n:]
		fd := fields.ByNumber(num)
		if typ != protowire.BytesType {
			if n = protowire.ConsumeFieldValue(num, typ, b); n < 0 {
				return attrs, errMalformed
			}
			b = b[n:]
			if fd != nil && fd.IsList() {
				if err := s.numbers(1, fd.Kind()); err != nil {
					return attrs, err
				}
			}
			continue
		}
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return attrs, errMalformed
		}
		b = b[n:]
		if fd == nil {
			continue
		}
		if fd.Kind() == protoreflect.StringKind && !s.count && !utf8.Valid(v) {
			return attrs, errInvalidUTF8
		}
		switch k := fd.Kind(); {
		case k == protoreflect.MessageKind:
		case !fd.IsList():
			continue
		case k == protoreflect.StringKind || k == protoreflect.BytesKind:
			if s.strings++; s.strings > s.lim.Strings {
				return attrs, fmt.Errorf("more than %d elements of repeated strings", s.lim.Strings)
			}
			continue
		default:
			if err := s.numbers(packedCount(v, k), k); err != nil {
				return attrs, err
			}
			continue
		}
		child := fd.Message()
		if s.messages++; s.messages > s.lim.Messages {
			return attrs, fmt.Errorf("more than %d messages", s.lim.Messages)
		}
		kind := scanKinds[child.FullName()]
		switch kind {
		case kindResource:
			if s.resources++; s.resources > s.lim.Resources {
				return attrs, fmt.Errorf("more than %d resources", s.lim.Resources)
			}
		case kindScope:
			if s.scopes++; s.scopes > s.lim.Scopes {
				return attrs, fmt.Errorf("more than %d scopes", s.lim.Scopes)
			}
		case kindRecord, kindItem:
			if s.records++; s.records > s.lim.Records {
				return attrs, fmt.Errorf("more than %d records or points", s.lim.Records)
			}
			if kind == kindItem {
				s.items++
			}
		case kindAttribute:
			if attrs++; attrs > s.lim.Attributes {
				return attrs, fmt.Errorf("more than %d attributes in one set", s.lim.Attributes)
			}
		}
		slot := -1
		if !fd.IsList() {
			slot = 0
			for slot < nsingular && singular[slot].num != num {
				slot++
			}
			if slot == nsingular && nsingular < len(singular) {
				singular[slot].num = num
				nsingular++
			}
			if slot == nsingular {
				slot = -1
			}
		}
		childAttrs := 0
		if slot >= 0 {
			childAttrs = singular[slot].n
		}
		n, err := s.scanMessage(v, child, depth+1, childAttrs)
		if slot >= 0 {
			singular[slot].n = n
		}
		if err != nil {
			return attrs, err
		}
	}
	return attrs, nil
}

// otlpCodec is the server codec of the otlp backend. Before it decodes a request, it scans the
// wire bytes and refuses a request whose shape passes scanLimits. grpc-go turns every codec error
// into Internal, so a refused request decodes to an empty message, and the handler reads the
// refusal with refusal. A request that does not decode is refused the same way, with a decodeError. Unknown fields are dropped, so no attribute reaches the upstream in a
// field that the gateway does not know.
//
// The collector of a cluster merges the telemetry of every workload into one request, so one
// resource that passes a shape cap must not make the gateway refuse the others. The scan therefore
// reads each resource of the request on its own. A resource that passes the caps of one resource
// (attributes in one set, scopes, nesting depth, records, messages, repeated numbers and strings) or
// holds a string that is not valid UTF-8 is dropped, and the handler reports it as a partial success. The totals of the whole request keep
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
	resources int
	// records counts the top-level items (log records, spans, data points) of the dropped resources.
	records int
	first   error
}

func newOTLPCodec() *otlpCodec { return &otlpCodec{limits: defaultScanLimits} }

func (c *otlpCodec) Name() string { return encproto.Name }

func (c *otlpCodec) Marshal(v any) (mem.BufferSlice, error) {
	return encoding.GetCodecV2(encproto.Name).Marshal(v)
}

// scanRequest reads the resources of a request of type md. It returns the wire bytes without the
// resources that pass a cap of one resource, and what it dropped. It returns an error when a total
// passes its cap or no resource passes. It checks every total after each resource and at the end. A request of other fields only has nothing to drop.
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
		total.messages++
		total.resources++
		if err := total.overTotal(); err != nil {
			return b, drop, err
		}
		one := scanner{lim: c.limits}
		if _, err := one.scanMessage(v, fd.Message(), 1, 0); err != nil {
			if errors.Is(err, errMalformed) {
				return b, drop, errMalformed
			}
			if drop.resources++; drop.first == nil {
				drop.first = err
			}
			drop.records += countItems(v, fd.Message())
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
		if err := total.overTotal(); err != nil {
			return b, drop, err
		}
	}
	if err := total.overTotal(); err != nil {
		return b, drop, err
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
	c.decoded.Add(1)
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, m); err != nil {
		// grpc-go turns a codec error into Internal and never calls the handler, so the request
		// leaves no state here: the handler reads the refusal and answers InvalidArgument.
		proto.Reset(m)
		c.refused.Store(m, &decodeError{err})
		return nil
	}
	if drop.resources > 0 {
		c.dropped.Store(m, drop)
	}
	return nil
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
