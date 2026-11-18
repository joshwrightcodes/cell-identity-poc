package hostsvc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

// stepTestServer starts a TLS server with the handler and returns a client config that pins it.
func stepTestServer(t *testing.T, h http.Handler) KeyClientConfig {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	ca := newURICA(t, StepClientTrustDomain)
	return KeyClientConfig{
		Addr: strings.TrimPrefix(srv.URL, "https://"), ServerName: KeyServerHost, Pin: sum[:],
		SVIDs: ca.source(t, cellControllerID, time.Hour), Timeout: 3 * time.Second,
	}
}

func okStatus(id string) []byte {
	b, _ := json.Marshal(mgmtapi.StepStatus{ID: id, Cell: "dev-cell-1", State: mgmtapi.StepQueued})
	return b
}

func asHostError(t *testing.T, err error) *mgmtapi.HostError {
	t.Helper()
	var he *mgmtapi.HostError
	if !errors.As(err, &he) {
		t.Fatalf("error %v is not a *mgmtapi.HostError", err)
	}
	return he
}

func TestStepClientPinned(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	cfg := stepTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write(okStatus(strings.Repeat("ab", 16)))
	}))
	sc, err := NewStepClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ae := newStepEnv(t)
	s, env := ae.newStep("dev-cell-1", func(s *step.Step) { s.ID = strings.Repeat("ab", 16) })
	st, err := sc.Put(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != "PUT" || gotPath != mgmtapi.StepPath(s.ID) || string(gotBody) != string(env) || st.ID != s.ID {
		t.Errorf("PUT: %s %s body %d bytes, status %+v", gotMethod, gotPath, len(gotBody), st)
	}
	if _, err := sc.Get(context.Background(), s.ID); err != nil || gotMethod != "GET" || gotPath != mgmtapi.StepPath(s.ID) {
		t.Errorf("GET: %v %s %s", err, gotMethod, gotPath)
	}
	if _, err := sc.Put(context.Background(), []byte("junk")); err == nil {
		t.Error("Put accepted an envelope that is not a step")
	}
	// Another server certificate is untrusted.
	other := cfg
	other.Pin = make([]byte, sha256.Size)
	sc2, _ := NewStepClient(other)
	_, err = sc2.Get(context.Background(), s.ID)
	if he := asHostError(t, err); he.Reason != mgmtapi.ReasonHostsvcUntrusted || he.Retry() {
		t.Errorf("wrong pin = %+v, want hostsvc_untrusted without retry", he)
	}
	if _, err := NewStepClient(KeyClientConfig{}); err == nil {
		t.Error("NewStepClient accepted an empty config")
	}
}

func TestStepClientErrors(t *testing.T) {
	id := strings.Repeat("cd", 16)
	denied := `{"error":"denied","request_id":"0123456789abcdef"}`
	rows := []struct {
		name       string
		status     int
		retryAfter string
		body       string
		reason     string
		retry      time.Duration
		reqID      string
	}{
		{"denied", 403, "", denied, mgmtapi.ReasonHostsvcDenied, 0, "0123456789abcdef"},
		{"unknown_step", 404, "", denied, mgmtapi.ReasonHostsvcDenied, 0, "0123456789abcdef"},
		{"denied_bad_request_id", 403, "", `{"error":"denied","request_id":"<script>"}`, mgmtapi.ReasonHostsvcDenied, 0, ""},
		{"busy", 503, "60", denied, mgmtapi.ReasonHostsvcBusy, 60 * time.Second, ""},
		{"spec_behind_busy", 503, "30", denied, mgmtapi.ReasonHostsvcBusy, 30 * time.Second, ""},
		{"journal_corrupt_unavailable", 503, "", denied, mgmtapi.ReasonHostsvcUnavailable, 0, ""},
		{"server_error", 500, "", "boom", mgmtapi.ReasonHostsvcUnavailable, 0, ""},
		{"bad_gateway", 502, "5", "", mgmtapi.ReasonHostsvcUnavailable, 0, ""},
		{"ok_but_not_a_status", 200, "", `{"id":"nope"}`, mgmtapi.ReasonHostsvcUnavailable, 0, ""},
		{"ok_but_garbage", 200, "", `garbage`, mgmtapi.ReasonHostsvcUnavailable, 0, ""},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stepTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			sc, _ := NewStepClient(cfg)
			_, err := sc.Get(context.Background(), id)
			he := asHostError(t, err)
			if he.Reason != tc.reason || he.RetryAfter != tc.retry || he.RequestID != tc.reqID || (tc.status != 200 && he.Status != tc.status) {
				t.Errorf("HostError = %+v, want reason %s, RetryAfter %v, request ID %q", he, tc.reason, tc.retry, tc.reqID)
			}
		})
	}
	t.Run("dial_error", func(t *testing.T) {
		cfg := stepTestServer(t, http.NotFoundHandler())
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		cfg.Addr = ln.Addr().String()
		ln.Close()
		sc, _ := NewStepClient(cfg)
		he := asHostError(t, func() error { _, err := sc.Get(context.Background(), id); return err }())
		if he.Reason != mgmtapi.ReasonHostsvcUnavailable || !he.Retry() {
			t.Errorf("dial error = %+v, want hostsvc_unavailable with retry", he)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		cfg := stepTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) }))
		cfg.Timeout = 100 * time.Millisecond
		sc, _ := NewStepClient(cfg)
		if he := asHostError(t, func() error { _, err := sc.Get(context.Background(), id); return err }()); he.Reason != mgmtapi.ReasonHostsvcUnavailable {
			t.Errorf("timeout = %+v", he)
		}
	})
}

func TestKeyClientPutSpec(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	status := 200
	cfg := stepTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
	}))
	kc, err := NewKeyClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{200, 201, 202, 204} {
		status = code
		if err := kc.PutSpec(context.Background(), []byte("envelope")); err != nil {
			t.Errorf("status %d: %v", code, err)
		}
	}
	if gotMethod != "PUT" || gotPath != mgmtapi.HostSpecPath || string(gotBody) != "envelope" {
		t.Errorf("request = %s %s %q", gotMethod, gotPath, gotBody)
	}
	status = 403
	if he := asHostError(t, kc.PutSpec(context.Background(), []byte("x"))); he.Reason != mgmtapi.ReasonHostsvcDenied || he.Status != 403 {
		t.Errorf("403 = %+v", he)
	}
	status = 503
	if he := asHostError(t, kc.PutSpec(context.Background(), []byte("x"))); he.Reason != mgmtapi.ReasonHostsvcUnavailable {
		t.Errorf("503 without Retry-After = %+v", he)
	}
	status = 301
	if he := asHostError(t, kc.PutSpec(context.Background(), []byte("x"))); he.Reason != mgmtapi.ReasonHostsvcUnavailable {
		t.Errorf("301 = %+v: a redirect is not followed and is not success", he)
	}
}
