package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// The wrapped writer keeps its Flush, so a streaming handler can flush under Handler.
func TestHandlerWriterFlushes(t *testing.T) {
	tracer := sdktrace.NewTracerProvider().Tracer("test")
	flushed := make(chan bool, 1)
	h := Handler(tracer, "x", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		flushed <- ok
		if ok {
			_, _ = w.Write([]byte("a"))
			f.Flush()
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !<-flushed || !rec.Flushed {
		t.Fatalf("the writer under Handler does not flush: Flusher %v, recorder flushed %v", rec.Flushed, rec.Flushed)
	}
}

// A flush error of the HTTP/2 stream reaches a ResponseController under Handler.
func TestHandlerFlushErrorPassesThrough(t *testing.T) {
	tracer := sdktrace.NewTracerProvider().Tracer("test")
	got := make(chan error, 1)
	srv := httptest.NewUnstartedServer(Handler(tracer, "x", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		w.WriteHeader(http.StatusOK)
		_ = rc.Flush()
		<-r.Context().Done()
		_, _ = w.Write([]byte("late"))
		got <- rc.Flush()
	})))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	resp.Body.Close()
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("Flush after a stream reset returned nil under Handler")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not run")
	}
}
