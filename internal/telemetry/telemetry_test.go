package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/sys/unix"
)

// syncBuffer is a bytes.Buffer that the test can read while the SDK writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		var m map[string]any
		if err := json.Unmarshal(s.Bytes(), &m); err != nil {
			t.Fatalf("output line is not JSON: %q", s.Text())
		}
		lines = append(lines, m)
	}
	return lines
}

func TestTraceHandlerAddsSpanIDs(t *testing.T) {
	var out bytes.Buffer
	log := NewLogger(&out, slog.DiscardHandler)
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	log.InfoContext(ctx, "with span")
	span.End()
	log.Info("without span")

	lines := jsonLines(t, out.String())
	if len(lines) != 2 {
		t.Fatalf("got %d lines", len(lines))
	}
	if lines[0]["trace_id"] != span.SpanContext().TraceID().String() || lines[0]["span_id"] != span.SpanContext().SpanID().String() {
		t.Fatalf("line with span is %v", lines[0])
	}
	if _, ok := lines[1]["trace_id"]; ok {
		t.Fatalf("line without span has a trace ID: %v", lines[1])
	}
}

// captureStderr runs f with file descriptor 2 on a pipe and returns what f wrote there. Loggers
// that kept the original os.Stderr at package init write to that descriptor too.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved, err := unix.Dup(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(int(w.Fd()), 2); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	restore := func() {
		_ = unix.Dup2(saved, 2)
		_ = unix.Close(saved)
		_ = w.Close()
	}
	defer func() {
		if w != nil {
			restore()
		}
	}()
	f()
	restore()
	w = nil
	return <-done
}

func TestTelemetryErrorsStayJSONOnStdout(t *testing.T) {
	// Port 1 on the loopback address refuses connections, so every export fails.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "300")
	out := &syncBuffer{}
	stderr := captureStderr(t, func() {
		tel, err := Start(t.Context(), "test", out)
		if err != nil {
			t.Fatal(err)
		}
		ctx, span := tel.Tracer.Start(context.Background(), "op")
		tel.Log.InfoContext(ctx, "before shutdown")
		span.End()
		sctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		if err := tel.Shutdown(sctx); err != nil {
			slog.New(slog.NewJSONHandler(out, nil)).Warn("telemetry shutdown", "error", err.Error())
		}
	})
	if stderr != "" {
		t.Fatalf("telemetry wrote to stderr: %q", stderr)
	}
	lines := jsonLines(t, out.String())
	var sdkErrors int
	for _, l := range lines {
		if l["msg"] == "telemetry error" || l["msg"] == "telemetry shutdown" {
			sdkErrors++
		}
	}
	if sdkErrors == 0 {
		t.Fatalf("no JSON line reports the failed export:\n%s", out.String())
	}
}

// spanExporter fails or blocks as the test needs. onShutdown runs inside Shutdown.
type spanExporter struct {
	fail       bool
	block      bool
	onShutdown func()
}

func (e *spanExporter) ExportSpans(ctx context.Context, _ []sdktrace.ReadOnlySpan) error {
	switch {
	case e.block:
		<-ctx.Done()
		return ctx.Err()
	case e.fail:
		return errors.New("span export refused")
	}
	return nil
}

func (e *spanExporter) Shutdown(ctx context.Context) error {
	if e.onShutdown != nil {
		e.onShutdown()
	}
	if e.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

// memLogExporter keeps the body of each exported record and the time of each export.
type memLogExporter struct {
	mu      sync.Mutex
	bodies  []string
	exports []time.Time
}

func (e *memLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range records {
		e.bodies = append(e.bodies, r.Body().AsString())
	}
	e.exports = append(e.exports, time.Now())
	return nil
}

func (e *memLogExporter) Shutdown(context.Context) error   { return nil }
func (e *memLogExporter) ForceFlush(context.Context) error { return nil }

func (e *memLogExporter) has(body string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.bodies {
		if b == body {
			return true
		}
	}
	return false
}

// memMetricExporter keeps the time of each export that holds data.
type memMetricExporter struct {
	mu      sync.Mutex
	exports []time.Time
}

func (e *memMetricExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return sdkmetric.DefaultTemporalitySelector(k)
}

func (e *memMetricExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}

func (e *memMetricExporter) Export(_ context.Context, rm *metricdata.ResourceMetrics) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(rm.ScopeMetrics) > 0 {
		e.exports = append(e.exports, time.Now())
	}
	return nil
}

func (e *memMetricExporter) ForceFlush(context.Context) error { return nil }
func (e *memMetricExporter) Shutdown(context.Context) error   { return nil }

func TestErrorHandlerWritesJSONOnlyToStdout(t *testing.T) {
	out := &syncBuffer{}
	installHooks(out)
	logs := &memLogExporter{}
	tel := build("test", out, resource.Empty(), exporters{trace: &spanExporter{fail: true}, metric: &memMetricExporter{}, log: logs}, time.Second)
	ctx, span := tel.Tracer.Start(context.Background(), "op")
	tel.Log.InfoContext(ctx, "app line")
	span.End()
	_ = tel.Shutdown(context.Background())

	var sdkErrors int
	for _, l := range jsonLines(t, out.String()) {
		if _, ok := l["msg"]; !ok {
			t.Fatalf("stdout line has no msg: %v", l)
		}
		if l["msg"] == "telemetry error" {
			sdkErrors++
		}
	}
	if sdkErrors == 0 {
		t.Fatalf("no stdout line reports the failed export:\n%s", out.String())
	}
	if !logs.has("app line") {
		t.Fatalf("the bridge did not export the application line: %v", logs.bodies)
	}
	if logs.has("telemetry error") {
		t.Fatalf("the bridge exported an SDK error: %v", logs.bodies)
	}
}

func TestErrorHandlerRateLimited(t *testing.T) {
	out := &syncBuffer{}
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	h := newErrorHandler(out, func() time.Time { return now })
	for range 100 {
		h.Handle(errors.New("export refused"))
		now = now.Add(10 * time.Millisecond)
	}
	if lines := jsonLines(t, out.String()); len(lines) != 1 {
		t.Fatalf("100 identical errors in one second gave %d lines, want 1:\n%s", len(lines), out.String())
	}
	h.Handle(errors.New("another error"))
	now = now.Add(10 * time.Second)
	h.Handle(errors.New("export refused"))

	lines := jsonLines(t, out.String())
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), out.String())
	}
	if lines[1]["error"] != "another error" || lines[1]["suppressed"] != float64(0) {
		t.Fatalf("a distinct message is limited on its own, got %v", lines[1])
	}
	last := lines[2]
	if last["msg"] != "telemetry error" || last["error"] != "export refused" || last["suppressed"] != float64(99) {
		t.Fatalf("line after 10 seconds is %v, want suppressed 99", last)
	}
}

func TestShutdownFlushesAllWhenOneStalls(t *testing.T) {
	const timeout = 400 * time.Millisecond
	out := &syncBuffer{}
	installHooks(out)
	logs := &memLogExporter{}
	metrics := &memMetricExporter{}
	tel := build("test", out, resource.Empty(), exporters{trace: &spanExporter{block: true}, metric: metrics, log: logs}, timeout)
	counter, err := tel.Meter.Int64Counter("test.count")
	if err != nil {
		t.Fatal(err)
	}
	ctx, span := tel.Tracer.Start(context.Background(), "op")
	counter.Add(ctx, 1)
	tel.Log.InfoContext(ctx, "app line")
	span.End()

	start := time.Now()
	err = tel.Shutdown(context.Background())
	took := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "trace provider") {
		t.Fatalf("Shutdown error is %v, want one that names the trace provider", err)
	}
	if took > 2*timeout+timeout/2 {
		t.Fatalf("Shutdown took %v, want at most two provider timeouts", took)
	}

	metrics.mu.Lock()
	if len(metrics.exports) == 0 || metrics.exports[0].Sub(start) >= timeout {
		t.Fatalf("metric exports %v, want one within %v of the start", metrics.exports, timeout)
	}
	metrics.mu.Unlock()

	logs.mu.Lock()
	defer logs.mu.Unlock()
	if len(logs.exports) == 0 {
		t.Fatal("the log exporter got nothing")
	}
	if at := logs.exports[len(logs.exports)-1].Sub(start); at < timeout || at >= 2*timeout {
		t.Fatalf("logs flushed %v after the start, want after the trace timeout %v and within their own", at, timeout)
	}
}

func TestShutdownFlushesLogsLast(t *testing.T) {
	out := &syncBuffer{}
	installHooks(out)
	logs := &memLogExporter{}
	traces := &spanExporter{}
	tel := build("test", out, resource.Empty(), exporters{trace: traces, metric: &memMetricExporter{}, log: logs}, time.Second)
	traces.onShutdown = func() { tel.Log.Info("trace exporter closed") }

	if err := tel.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !logs.has("trace exporter closed") {
		t.Fatalf("a record from the trace shutdown did not reach the log exporter: %v", logs.bodies)
	}
}
