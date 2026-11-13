package mgmt

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

// A log line of a bind handler carries trace_id when the handler runs under a server span.
func TestBindHandlerLogLineCarriesATraceID(t *testing.T) {
	var out bytes.Buffer
	log := telemetry.NewLogger(&out, slog.DiscardHandler)
	h := telemetry.Handler(sdktrace.NewTracerProvider().Tracer("test"), "mgmtd.bind", NewBindHandler(&fakeBinder{}, log))
	req := httptest.NewRequest(http.MethodPost, mgmtapi.NoncePath("dev-cell-1"), strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 for a body that is no JSON", rec.Code)
	}
	var line map[string]any
	if err := json.Unmarshal(out.Bytes(), &line); err != nil || line["msg"] != "bind_denied" {
		t.Fatalf("log output %q (%v), want one bind_denied line", out.String(), err)
	}
	if id, _ := line["trace_id"].(string); len(id) != 32 {
		t.Fatalf("bind_denied line %v has no trace_id", line)
	}
}

// The bind listener takes no client certificate, so a caller must not choose the trace ID of its log lines.
func TestBindHandlerIgnoresAnIncomingTraceparent(t *testing.T) {
	const callerTrace = "0af7651916cd43dd8448eb211c80319c"
	var out bytes.Buffer
	log := telemetry.NewLogger(&out, slog.DiscardHandler)
	h := telemetry.Handler(sdktrace.NewTracerProvider().Tracer("test"), "mgmtd.bind", NewBindHandler(&fakeBinder{}, log), telemetry.WithPublicEndpoint())
	req := httptest.NewRequest(http.MethodPost, mgmtapi.NoncePath("dev-cell-1"), strings.NewReader("not json"))
	req.Header.Set("traceparent", "00-"+callerTrace+"-b7ad6b7169203331-01")
	h.ServeHTTP(httptest.NewRecorder(), req)
	var line map[string]any
	if err := json.Unmarshal(out.Bytes(), &line); err != nil {
		t.Fatalf("log output %q: %v", out.String(), err)
	}
	id, _ := line["trace_id"].(string)
	if len(id) != 32 || id == callerTrace {
		t.Fatalf("trace_id %q, want a new ID that differs from the caller trace %s", id, callerTrace)
	}
}
