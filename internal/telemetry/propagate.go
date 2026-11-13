package telemetry

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// propagator is the W3C trace context, the standard OpenTelemetry default.
var propagator propagation.TextMapPropagator = propagation.TraceContext{}

// Handler starts a server span named name for each request. It continues the trace of the traceparent header when
// the request has one, and it hands the span context to next, so the log lines of the handler carry trace_id.
func Handler(tracer trace.Tracer, name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", r.Method), attribute.String("url.path", r.URL.Path)))
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
