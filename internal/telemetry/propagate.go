package telemetry

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// propagator is the W3C trace context, the standard OpenTelemetry default.
var propagator propagation.TextMapPropagator = propagation.TraceContext{}

// HandlerOption changes how Handler treats an incoming traceparent header.
type HandlerOption func(*handlerConfig)

type handlerConfig struct{ public bool }

// WithPublicEndpoint marks a listener that does not authenticate its callers. Handler then starts a new root span
// for each request and links the remote span context to it, so a caller cannot choose the trace ID of the log lines.
func WithPublicEndpoint() HandlerOption { return func(c *handlerConfig) { c.public = true } }

// Handler starts a server span named name for each request. It continues the trace of the traceparent header when
// the request has one, unless WithPublicEndpoint is set. It hands the span context to next, so the log lines of the
// handler carry trace_id.
func Handler(tracer trace.Tracer, name string, next http.Handler, opts ...HandlerOption) http.Handler {
	var cfg handlerConfig
	for _, o := range opts {
		o(&cfg)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		startOpts := []trace.SpanStartOption{trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", r.Method), attribute.String("url.path", r.URL.Path))}
		if cfg.public {
			if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
				startOpts = append(startOpts, trace.WithLinks(trace.Link{SpanContext: sc}))
			}
			ctx = trace.ContextWithSpanContext(r.Context(), trace.SpanContext{})
			startOpts = append(startOpts, trace.WithNewRoot())
		}
		ctx, span := tracer.Start(ctx, name, startOpts...)
		defer span.End()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))
		span.SetAttributes(attribute.Int("http.response.status_code", sw.status))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush flushes the wrapped writer when it can.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the writer below.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Transport returns a round tripper that adds the traceparent header of the span in the request context. It passes
// CloseIdleConnections to next.
func Transport(next http.RoundTripper) http.RoundTripper { return transport{next} }

type transport struct{ next http.RoundTripper }

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	propagator.Inject(r.Context(), propagation.HeaderCarrier(r.Header))
	return t.next.RoundTrip(r)
}

func (t transport) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
