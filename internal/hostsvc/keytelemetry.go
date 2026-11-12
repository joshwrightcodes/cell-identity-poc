package hostsvc

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// instruments holds the spans and metrics of the key handler. Metric names:
// hostsvc.key.requests (by outcome), hostsvc.key.cache.hits, hostsvc.key.lookups (by result) and
// hostsvc.key.lookup.duration.
type instruments struct {
	tracer   trace.Tracer
	requests metric.Int64Counter
	hits     metric.Int64Counter
	lookups  metric.Int64Counter
	duration metric.Float64Histogram
}

func newInstruments(tracer trace.Tracer, meter metric.Meter) (*instruments, error) {
	i := &instruments{tracer: tracer}
	var err error
	if i.requests, err = meter.Int64Counter("hostsvc.key.requests", metric.WithDescription("Key requests by outcome.")); err != nil {
		return nil, err
	}
	if i.hits, err = meter.Int64Counter("hostsvc.key.cache.hits", metric.WithDescription("Key requests answered from the cache.")); err != nil {
		return nil, err
	}
	if i.lookups, err = meter.Int64Counter("hostsvc.key.lookups", metric.WithDescription("Cluster lookups by result.")); err != nil {
		return nil, err
	}
	if i.duration, err = meter.Float64Histogram("hostsvc.key.lookup.duration", metric.WithUnit("s"), metric.WithDescription("Duration of cluster lookups.")); err != nil {
		return nil, err
	}
	return i, nil
}

// Hit implements CacheObserver.
func (i *instruments) Hit() { i.hits.Add(context.Background(), 1) }

// Lookup implements CacheObserver.
func (i *instruments) Lookup(took time.Duration, err error) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	i.lookups.Add(context.Background(), 1, metric.WithAttributes(attribute.String("result", result)))
	i.duration.Record(context.Background(), took.Seconds())
}

// NewInstrumentedKeyHandler is NewKeyHandler with a span for each request and the metrics of
// instruments. It sets the observer of cache.
func NewInstrumentedKeyHandler(cache *KeyCache, known func(string) bool, log *slog.Logger, tracer trace.Tracer, meter metric.Meter) (http.Handler, error) {
	ins, err := newInstruments(tracer, meter)
	if err != nil {
		return nil, err
	}
	cache.SetObserver(ins)
	h := newKeyHandler(cache, known, log)
	h.ins = ins
	return h.routes(), nil
}

func noopInstruments() *instruments {
	i, err := newInstruments(tracenoop.NewTracerProvider().Tracer("hostsvc"), metricnoop.NewMeterProvider().Meter("hostsvc"))
	if err != nil {
		panic(err)
	}
	return i
}

// statusWriter records the status code of a response.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// observe wraps a request: a span, and the request counter with the outcome.
func (h *keyHandler) observe(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request, *string)) {
	ctx, span := h.ins.tracer.Start(r.Context(), "hostsvc.keys", trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	outcome := "served"
	next(sw, r.WithContext(ctx), &outcome)
	span.SetAttributes(attribute.String("outcome", outcome), attribute.Int("http.response.status_code", sw.status))
	if sw.status >= 500 {
		span.SetStatus(codes.Error, outcome)
	}
	h.ins.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}
