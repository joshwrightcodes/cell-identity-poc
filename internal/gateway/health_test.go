package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthNeedsStoreAndSVID(t *testing.T) {
	e := newGwEnv(t)
	ready := false
	h := NewHealthHandler(e.st, func() bool { return ready })
	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	if got := get("/healthz"); got != http.StatusServiceUnavailable {
		t.Fatalf("no SVID: %d, want 503", got)
	}
	if got := get("/livez"); got != http.StatusOK {
		t.Fatalf("liveness before the SVID: %d, want 200", got)
	}
	ready = true
	if got := get("/healthz"); got != http.StatusOK {
		t.Fatalf("store and SVID ready: %d, want 200", got)
	}
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	if got := get("/healthz"); got != http.StatusServiceUnavailable {
		t.Fatalf("closed store: %d, want 503", got)
	}
	if got := get("/livez"); got != http.StatusOK {
		t.Fatalf("liveness with a closed store: %d, want 200", got)
	}
	if NewHealthHandler(e.st, nil) == nil {
		t.Fatal("nil svidReady")
	}
}
