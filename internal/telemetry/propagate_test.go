package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// A handler log line carries trace_id, and a request with a traceparent header continues that trace. The transport
// sends the traceparent of the span of the request context.
func TestHandlerAndTransportPropagateTheTrace(t *testing.T) {
	tracer := sdktrace.NewTracerProvider().Tracer("test")
	var out bytes.Buffer
	log := NewLogger(&out, slog.DiscardHandler)
	srv := httptest.NewServer(Handler(tracer, "mgmtd.api", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.InfoContext(r.Context(), "handled")
		w.WriteHeader(http.StatusNoContent)
	})))
	defer srv.Close()

	ctx, span := tracer.Start(context.Background(), "client")
	defer span.End()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := (&http.Client{Transport: Transport(http.DefaultTransport)}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var line map[string]any
	if err := json.Unmarshal(out.Bytes(), &line); err != nil {
		t.Fatalf("log output %q: %v", out.String(), err)
	}
	want := trace.SpanContextFromContext(ctx).TraceID().String()
	if line["trace_id"] != want {
		t.Fatalf("trace_id %v, want %s from the client span", line["trace_id"], want)
	}

	// With no traceparent, the handler still starts a span of its own.
	out.Reset()
	resp, err = http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	line = nil
	if err := json.Unmarshal(out.Bytes(), &line); err != nil || line["trace_id"] == nil || line["trace_id"] == want {
		t.Fatalf("log line %q (%v), want a new trace_id", out.String(), err)
	}
}
