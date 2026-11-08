// Command celld is the cell daemon. This version is a stub: it watches the SPIFFE Workload API
// and logs the SPIFFE ID of its X.509 SVID once for each new SVID.
//
// Every log line is compact JSON on stdout. Logs, traces and metrics also go out as OTLP. The
// standard OTEL_* variables configure the exporters, for example OTEL_EXPORTER_OTLP_ENDPOINT.
// SPIFFE_ENDPOINT_SOCKET names the Workload API socket.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/contrib/bridges/otelslog"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	serviceName     = "celld"
	shutdownTimeout = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.Stdout, startTelemetry)
	stop()
	os.Exit(code)
}

// telemetry holds the logger, tracer and meter of the process, and a function that flushes them.
type telemetry struct {
	log      *slog.Logger
	tracer   trace.Tracer
	meter    metric.Meter
	shutdown func(context.Context) error
}

type telemetryStarter func(ctx context.Context, stdout io.Writer) (*telemetry, error)

// execute runs celld until ctx ends and returns the exit code. A failure is one JSON error line
// on stdout.
func execute(ctx context.Context, args []string, stdout io.Writer, start telemetryStarter) int {
	boot := slog.New(slog.NewJSONHandler(stdout, nil))
	if len(args) > 0 {
		boot.Error("celld failed", "error", "celld takes no arguments")
		return 1
	}
	tel, err := start(ctx, stdout)
	if err != nil {
		boot.Error("celld failed", "error", fmt.Sprintf("start telemetry: %v", err))
		return 1
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := tel.shutdown(sctx); err != nil {
			boot.Warn("telemetry shutdown", "error", err.Error())
		}
	}()

	w, err := newSVIDWatcher(tel)
	if err != nil {
		tel.log.Error("celld failed", "error", err.Error())
		return 1
	}
	tel.log.Info("watching the workload api", "socket", os.Getenv("SPIFFE_ENDPOINT_SOCKET"))
	if err := workloadapi.WatchX509Context(ctx, w); err != nil && ctx.Err() == nil {
		tel.log.Error("celld failed", "error", fmt.Sprintf("watch the workload api: %v", err))
		return 1
	}
	tel.log.Info("stopped")
	return 0
}

// svidWatcher logs each new default X.509 SVID once. The Workload API also sends an update when
// only the bundle changes, so the watcher compares the SPIFFE ID and the serial number.
type svidWatcher struct {
	tel     *telemetry
	updates metric.Int64Counter
	mu      sync.Mutex
	last    string
}

func newSVIDWatcher(tel *telemetry) (*svidWatcher, error) {
	updates, err := tel.meter.Int64Counter("celld.svid.updates",
		metric.WithDescription("New X.509 SVIDs that celld received from the Workload API"))
	if err != nil {
		return nil, fmt.Errorf("create counter: %w", err)
	}
	return &svidWatcher{tel: tel, updates: updates}, nil
}

func (w *svidWatcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	svid := c.DefaultSVID()
	if svid == nil || len(svid.Certificates) == 0 {
		w.tel.log.Warn("workload api update without an svid")
		return
	}
	leaf := svid.Certificates[0]
	id := svid.ID.String()
	key := id + "/" + leaf.SerialNumber.String()

	w.mu.Lock()
	defer w.mu.Unlock()
	if key == w.last {
		return
	}
	w.last = key

	ctx, span := w.tel.tracer.Start(context.Background(), "x509 svid update",
		trace.WithAttributes(attribute.String("spiffe.id", id)))
	defer span.End()
	w.updates.Add(ctx, 1, metric.WithAttributes(attribute.String("spiffe.id", id)))
	w.tel.log.InfoContext(ctx, "x509 svid updated", "spiffe_id", id,
		"serial", leaf.SerialNumber.Text(16), "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
}

func (w *svidWatcher) OnX509ContextWatchError(err error) {
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return
	}
	w.tel.log.Warn("workload api watch failed", "error", err.Error())
}

// startTelemetry sets up OTLP export of logs, traces and metrics over gRPC. The exporters read
// the standard OTEL_EXPORTER_OTLP_* variables and connect only when they first export.
func startTelemetry(ctx context.Context, stdout io.Writer) (*telemetry, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", serviceName)),
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
		return nil, fmt.Errorf("metric exporter: %w", err)
	}
	logExp, err := otlploggrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("log exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(traceExp))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)))
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)))
	return &telemetry{
		log:    newLogger(stdout, otelslog.NewHandler(serviceName, otelslog.WithLoggerProvider(lp))),
		tracer: tp.Tracer(serviceName),
		meter:  mp.Meter(serviceName),
		shutdown: func(ctx context.Context) error {
			return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx), lp.Shutdown(ctx))
		},
	}, nil
}

// newLogger writes each record as JSON to stdout, with the trace and span IDs of its context, and
// also passes it to otlp.
func newLogger(stdout io.Writer, otlp slog.Handler) *slog.Logger {
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
