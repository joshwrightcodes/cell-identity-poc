// Package telemetry sets up the logs, traces and metrics of a bespoke binary.
//
// Every log line is compact JSON on stdout, including errors from the telemetry SDK. Logs,
// traces and metrics also go out as OTLP over gRPC.
//
// The OTLP gRPC exporters read the standard OTEL_EXPORTER_OTLP_* variables, for example the
// endpoint, headers, timeout and certificates. The SDK reads OTEL_SERVICE_NAME,
// OTEL_RESOURCE_ATTRIBUTES, the sampler, batch and limit variables. Start always uses the three
// gRPC exporters, so OTEL_EXPORTER_OTLP_PROTOCOL, OTEL_TRACES_EXPORTER, OTEL_METRICS_EXPORTER,
// OTEL_LOGS_EXPORTER and OTEL_SDK_DISABLED have no effect.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// providerTimeout bounds the shutdown of each provider.
const providerTimeout = 5 * time.Second

// T holds the logger, tracer and meter of the process. Shutdown flushes and stops them.
type T struct {
	Log      *slog.Logger
	Tracer   trace.Tracer
	Meter    metric.Meter
	Shutdown func(context.Context) error
}

// Start sets up OTLP export of logs, traces and metrics over gRPC for the named service. The
// exporters connect only when they first export. SDK errors and SDK log lines go to stdout as
// JSON, and not through the OTLP bridge, so a failed export cannot feed itself.
func Start(ctx context.Context, service string, stdout io.Writer) (*T, error) {
	installHooks(stdout)
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", service)),
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(),
	)
	if err != nil {
		return nil, fmt.Errorf("resource: %w", err)
	}
	traceExp, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("trace exporter: %w", err)
	}
	metricExp, err := otlpmetricgrpc.New(ctx)
	if err != nil {
		_ = withTimeout(context.Background(), providerTimeout, traceExp.Shutdown)
		return nil, fmt.Errorf("metric exporter: %w", err)
	}
	logExp, err := otlploggrpc.New(ctx)
	if err != nil {
		_ = errors.Join(withTimeout(context.Background(), providerTimeout, traceExp.Shutdown),
			withTimeout(context.Background(), providerTimeout, metricExp.Shutdown))
		return nil, fmt.Errorf("log exporter: %w", err)
	}
	return build(service, stdout, res, exporters{trace: traceExp, metric: metricExp, log: logExp}, providerTimeout), nil
}

// installHooks sends the errors and the internal log lines of the SDK to stdout as JSON.
func installHooks(stdout io.Writer) {
	sdkHandler := slog.NewJSONHandler(stdout, nil)
	otel.SetErrorHandler(newErrorHandler(stdout, time.Now))
	otel.SetLogger(logr.FromSlogHandler(sdkHandler))
}

type exporters struct {
	trace  sdktrace.SpanExporter
	metric sdkmetric.Exporter
	log    sdklog.Exporter
}

func build(service string, stdout io.Writer, res *resource.Resource, exp exporters, timeout time.Duration) *T {
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exp.trace))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp.metric)))
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(exp.log)))
	return &T{
		Log:    NewLogger(stdout, otelslog.NewHandler(service, otelslog.WithLoggerProvider(lp))),
		Tracer: tp.Tracer(service),
		Meter:  mp.Meter(service),
		Shutdown: func(ctx context.Context) error {
			return shutdown(ctx, timeout, tp.Shutdown, mp.Shutdown, lp.Shutdown)
		},
	}
}

// shutdown stops traces and metrics at the same time, then logs, so the records that the other
// shutdowns cause still reach the log exporter. Each provider gets its own timeout under the
// deadline of ctx. The error names each provider that failed.
func shutdown(ctx context.Context, timeout time.Duration, traces, metrics, logs func(context.Context) error) error {
	var traceErr, metricErr error
	var wg sync.WaitGroup
	wg.Go(func() { traceErr = withTimeout(ctx, timeout, traces) })
	wg.Go(func() { metricErr = withTimeout(ctx, timeout, metrics) })
	wg.Wait()
	logErr := withTimeout(ctx, timeout, logs)
	return errors.Join(named("trace provider", traceErr), named("metric provider", metricErr), named("log provider", logErr))
}

func named(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", name, err)
}

func withTimeout(ctx context.Context, timeout time.Duration, f func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return f(ctx)
}

// NewLogger writes each record as JSON to stdout, with the trace and span IDs of its context, and
// also passes it to otlp.
func NewLogger(stdout io.Writer, otlp slog.Handler) *slog.Logger {
	return slog.New(slog.NewMultiHandler(traceHandler{slog.NewJSONHandler(stdout, nil)}, otlp))
}

// traceHandler adds trace_id and span_id to a record whose context holds a valid span.
type traceHandler struct{ slog.Handler }

func (h traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r = r.Clone()
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.Handler.Handle(ctx, r)
}

func (h traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceHandler{h.Handler.WithAttrs(attrs)}
}

func (h traceHandler) WithGroup(name string) slog.Handler {
	return traceHandler{h.Handler.WithGroup(name)}
}
