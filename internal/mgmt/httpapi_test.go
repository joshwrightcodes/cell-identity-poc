package mgmt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

const (
	envdSPIFFE = "spiffe://dev.env.poc.internal/envd"
	mgmtSPIFFE = "spiffe://mgmt.poc.internal/api"
	devTD      = "dev.env.poc.internal"
	mgmtTD     = "mgmt.poc.internal"
)

func mustID(t testing.TB, s string) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromString(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func jsonLog(w io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(w, nil)) }

// fakeSpec is a SpecServer.
type fakeSpec struct {
	mu      sync.Mutex
	bundle  mgmtapi.SpecBundle
	reports []mgmtapi.StatusReport
}

func (f *fakeSpec) Spec() mgmtapi.SpecBundle { return f.bundle }
func (f *fakeSpec) Report(r mgmtapi.StatusReport) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, r)
}
func (f *fakeSpec) got() []mgmtapi.StatusReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mgmtapi.StatusReport(nil), f.reports...)
}

func testBundle() mgmtapi.SpecBundle {
	return mgmtapi.SpecBundle{
		Spec:    json.RawMessage(`{"payloadType":"t","payload":"cA==","signatures":[]}`),
		Records: map[string]json.RawMessage{"dev-cell-1": json.RawMessage(`{"payloadType":"r","payload":"cQ==","signatures":[]}`)},
	}
}

// fakeBinder is a Binder that counts its calls.
type fakeBinder struct {
	mu                  sync.Mutex
	nonceCalls, binds   int
	nonceErr, bindErr   error
	gate                chan struct{}
	entered             chan struct{}
	lastCell, lastNonce string
}

func (f *fakeBinder) Nonce(cell string) (mgmtapi.NonceResponse, error) {
	f.mu.Lock()
	f.nonceCalls++
	err := f.nonceErr
	f.lastCell = cell
	f.mu.Unlock()
	if err != nil {
		return mgmtapi.NonceResponse{}, err
	}
	return mgmtapi.NonceResponse{Nonce: "n1", Audience: mgmtapi.BindAudience(cell, "n1"), ExpiresAt: time.Unix(1700000000, 0).UTC(), Bound: false}, nil
}

func (f *fakeBinder) Bind(ctx context.Context, cell string, req mgmtapi.BindRequest) (mgmtapi.BindResponse, error) {
	f.mu.Lock()
	f.binds++
	err := f.bindErr
	gate, entered := f.gate, f.entered
	f.lastCell, f.lastNonce = cell, req.Nonce
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return mgmtapi.BindResponse{}, ctx.Err()
		}
	}
	if err != nil {
		return mgmtapi.BindResponse{}, err
	}
	return mgmtapi.BindResponse{Status: mgmtapi.StatusBound, Record: spec.Revision{Epoch: 1, Counter: 2}}, nil
}

func (f *fakeBinder) calls() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nonceCalls, f.binds
}

func do(h http.Handler, method, target string, body ...io.Reader) *httptest.ResponseRecorder {
	var b io.Reader
	if len(body) > 0 {
		b = body[0]
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, b))
	return rec
}

var reqIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// apiRig is a running API listener with the limits of the shared table.
type apiRig struct {
	addr    string
	devCA   *spiffetest.CA
	mgmtCA  *spiffetest.CA
	peer    x509bundle.Source
	logs    *lockedBuf
	srv     *http.Server
	handler http.Handler
}

func startAPI(t *testing.T, h http.Handler, peer func(devCA *spiffetest.CA) x509bundle.Source, tweak func(*tls.Config)) *apiRig {
	t.Helper()
	r := &apiRig{devCA: spiffetest.NewCA(t, devTD), mgmtCA: spiffetest.NewCA(t, mgmtTD), logs: &lockedBuf{}, handler: h}
	if peer == nil {
		peer = func(ca *spiffetest.CA) x509bundle.Source { return ca.Bundle() }
	}
	r.peer = peer(r.devCA)
	svids := r.mgmtCA.Source(t, mgmtSPIFFE)
	apiTLS := APIServerTLS(svids, r.peer, mustID(t, envdSPIFFE))
	if tweak != nil {
		tweak(apiTLS)
	}
	api, _ := NewServers(h, http.NotFoundHandler(), apiTLS, BindServerTLS(svids))
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := ListenAPI(raw, api.TLSConfig, jsonLog(r.logs))
	r.srv, r.addr = api, raw.Addr().String()
	go func() { _ = api.Serve(ln) }()
	t.Cleanup(func() { _ = api.Close() })
	return r
}

// client returns an HTTP/2 client that presents svid (nil for no client certificate) and trusts only
// the management root and ID.
func (r *apiRig) client(t *testing.T, svid x509svid.Source) *http.Client {
	t.Helper()
	return h2Client(t, r.mgmtCA, svid)
}

func h2Client(t *testing.T, mgmtCA *spiffetest.CA, svid x509svid.Source) *http.Client {
	t.Helper()
	auth := tlsconfig.AuthorizeID(mustID(t, mgmtSPIFFE))
	var cfg *tls.Config
	if svid == nil {
		cfg = tlsconfig.TLSClientConfig(mgmtCA.Bundle(), auth)
	} else {
		cfg = tlsconfig.MTLSClientConfig(svid, mgmtCA.Bundle(), auth)
	}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (r *apiRig) specURL(env string) string { return "https://" + r.addr + mgmtapi.SpecPath(env) }

func TestAPIServesSpecToEnvdOnly(t *testing.T) {
	fs := &fakeSpec{bundle: testBundle()}
	rig := startAPI(t, NewAPIHandler(fs, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)), nil, nil)
	other := spiffetest.NewCA(t, devTD)

	t.Run("envd", func(t *testing.T) {
		resp, err := rig.client(t, rig.devCA.Source(t, envdSPIFFE)).Get(rig.specURL("dev"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || resp.ProtoMajor != 2 {
			t.Fatalf("status %d proto %d: %s", resp.StatusCode, resp.ProtoMajor, body)
		}
		var got mgmtapi.SpecBundle
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if marshal(t, got) != marshal(t, fs.Spec()) {
			t.Fatalf("body %s is not Spec()", body)
		}
	})
	for _, tc := range []struct {
		name string
		svid x509svid.Source
		mod  func(*http.Client)
	}{
		{"cp_otel", rig.devCA.Source(t, "spiffe://dev.env.poc.internal/cp/otel"), nil},
		{"no_client_cert", nil, nil},
		{"other_ca_envd", other.Source(t, envdSPIFFE), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := rig.client(t, tc.svid).Get(rig.specURL("dev"))
			if err == nil {
				resp.Body.Close()
				t.Fatalf("request succeeded with status %d", resp.StatusCode)
			}
		})
	}
	t.Run("http1", func(t *testing.T) {
		cfg := tlsconfig.MTLSClientConfig(rig.devCA.Source(t, envdSPIFFE), rig.mgmtCA.Bundle(), tlsconfig.AuthorizeID(mustID(t, mgmtSPIFFE)))
		cfg.NextProtos = []string{"http/1.1"}
		tr := &http.Transport{TLSClientConfig: cfg}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(rig.specURL("dev"))
		if err == nil {
			resp.Body.Close()
			t.Fatalf("HTTP/1 request succeeded with status %d", resp.StatusCode)
		}
	})
}

func TestAPIStatusReport(t *testing.T) {
	fs := &fakeSpec{bundle: testBundle()}
	rig := startAPI(t, NewAPIHandler(fs, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)), nil, nil)
	c := rig.client(t, rig.devCA.Source(t, envdSPIFFE))
	url := "https://" + rig.addr + mgmtapi.StatusPath("dev")
	post := func(body string) int {
		t.Helper()
		resp, err := c.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	good := marshal(t, mgmtapi.StatusReport{
		Applied:     spec.Revision{Epoch: 1, Counter: 3},
		LastRefusal: &mgmtapi.Refusal{Reason: mgmtapi.ReasonRevisionOld, Revision: spec.Revision{Epoch: 1, Counter: 2}, At: time.Unix(1700000000, 0).UTC()},
		StoreError:  "x",
	})
	if code := post(good); code != 204 {
		t.Fatalf("status %d, want 204", code)
	}
	got := fs.got()
	if len(got) != 1 || got[0].Applied != (spec.Revision{Epoch: 1, Counter: 3}) || got[0].LastRefusal == nil || got[0].LastRefusal.Reason != mgmtapi.ReasonRevisionOld || got[0].StoreError != "x" {
		t.Fatalf("reports %+v", got)
	}
	for name, body := range map[string]string{
		"unknown_field": `{"applied":{"epoch":1,"counter":1},"extra":1}`,
		"not_json":      `nope`,
		"trailing":      good + `{}`,
		"too_large":     `{"storeError":"` + strings.Repeat("a", 17<<10) + `"}`,
	} {
		if code := post(body); code == 204 || code < 400 {
			t.Errorf("%s: status %d", name, code)
		}
	}
	if n := len(fs.got()); n != 1 {
		t.Fatalf("%d reports after the bad bodies, want 1", n)
	}
}

func TestAPIOtherEnv(t *testing.T) {
	fs := &fakeSpec{bundle: testBundle()}
	rig := startAPI(t, NewAPIHandler(fs, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)), nil, nil)
	c := rig.client(t, rig.devCA.Source(t, envdSPIFFE))
	for _, tc := range []struct{ method, path string }{
		{"GET", mgmtapi.SpecPath("prod")},
		{"POST", mgmtapi.StatusPath("prod")},
		{"GET", "/"},
		{"GET", "/healthz"},
		{"POST", mgmtapi.SpecPath("dev")},
		{"GET", mgmtapi.StatusPath("dev")},
		{"DELETE", mgmtapi.SpecPath("dev")},
		{"POST", mgmtapi.NoncePath("dev-cell-1")},
	} {
		req, _ := http.NewRequest(tc.method, "https://"+rig.addr+tc.path, strings.NewReader("{}"))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s %s: status %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}
	if len(fs.got()) != 0 {
		t.Fatal("a report reached the plane")
	}
}

func TestAPIHandlerChecksPeerID(t *testing.T) {
	ca := spiffetest.NewCA(t, devTD)
	h := NewAPIHandler(&fakeSpec{bundle: testBundle()}, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard))
	req := func(id string) *http.Request {
		r := httptest.NewRequest("GET", mgmtapi.SpecPath("dev"), nil)
		if id != "" {
			r.TLS = &tls.ConnectionState{PeerCertificates: ca.SVID(t, id).Certificates}
		}
		return r
	}
	for name, id := range map[string]string{"cp_otel": "spiffe://dev.env.poc.internal/cp/otel", "no_cert": "", "other_td": "spiffe://other.example/envd"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req(id))
		if rec.Code != 403 {
			t.Errorf("%s: status %d, want 403", name, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req(envdSPIFFE))
	if rec.Code != 200 {
		t.Fatalf("envd: status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", mgmtapi.SpecPath("dev"), nil))
	if rec.Code != 403 {
		t.Fatalf("a request with no TLS state: status %d, want 403", rec.Code)
	}
}

func TestBindHandlerFlow(t *testing.T) {
	logs := &lockedBuf{}
	fb := &fakeBinder{}
	h := NewBindHandler(fb, jsonLog(logs))

	rec := do(h, "POST", mgmtapi.NoncePath("dev-cell-1"), nil)
	if rec.Code != 200 {
		t.Fatalf("nonce: %d %s", rec.Code, rec.Body)
	}
	var n mgmtapi.NonceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &n); err != nil || n.Nonce != "n1" || n.Audience != "mgmt-bind/dev-cell-1/n1" {
		t.Fatalf("nonce body %s: %v", rec.Body, err)
	}
	if rec = do(h, "POST", mgmtapi.NoncePath("dev-cell-1"), strings.NewReader("{}")); rec.Code != 200 {
		t.Fatalf("nonce with an empty object: %d", rec.Code)
	}

	const token = "eyJTRUNSRVQtVE9LRU4tVkFMVUU.payload.sig"
	body := marshal(t, mgmtapi.BindRequest{Nonce: "n1", Token: token})
	rec = do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(body))
	var br mgmtapi.BindResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &br) != nil || br.Status != mgmtapi.StatusBound || br.Record != (spec.Revision{Epoch: 1, Counter: 2}) {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body)
	}
	if fb.lastCell != "dev-cell-1" || fb.lastNonce != "n1" {
		t.Fatalf("binder got cell %q nonce %q", fb.lastCell, fb.lastNonce)
	}

	fb.bindErr = &Error{Reason: mgmtapi.ReasonTokenInvalid, Detail: "bad_signature"}
	rec = do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(body))
	if rec.Code != 403 {
		t.Fatalf("denied bind: %d", rec.Code)
	}
	var d mgmtapi.Denied
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || d.Error != mgmtapi.DeniedError || !reqIDRE.MatchString(d.RequestID) {
		t.Fatalf("denied body %s: %v", rec.Body, err)
	}
	if strings.Contains(rec.Body.String(), "bad_signature") || strings.Contains(rec.Body.String(), "token_invalid") {
		t.Fatalf("the body leaks the reason: %s", rec.Body)
	}
	line := lastLogLine(t, logs, "bind_denied")
	if line["reason"] != mgmtapi.ReasonTokenInvalid || line["detail"] != "bad_signature" || line["cell"] != "dev-cell-1" || line["request_id"] != d.RequestID {
		t.Fatalf("log line %v", line)
	}
	logs.mu.Lock()
	logged := logs.buf.String()
	logs.mu.Unlock()
	if strings.Contains(logged, token) || strings.Contains(logged, "SECRET-TOKEN") {
		t.Fatalf("the log holds the token: %s", logged)
	}

	fb.nonceErr = &Error{Reason: mgmtapi.ReasonCellUnknown}
	if rec = do(h, "POST", mgmtapi.NoncePath("nope")); rec.Code != 403 {
		t.Fatalf("unknown cell nonce: %d", rec.Code)
	}
	fb.bindErr = errors.New("disk full")
	rec = do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(body))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "disk") {
		t.Fatalf("internal error: %d %s", rec.Code, rec.Body)
	}
}

func do2(h http.Handler, method, target string) *httptest.ResponseRecorder {
	return do(h, method, target)
}

func lastLogLine(t *testing.T, logs *lockedBuf, msg string) map[string]any {
	t.Helper()
	logs.mu.Lock()
	defer logs.mu.Unlock()
	var found map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs.buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == msg {
			found = m
		}
	}
	if found == nil {
		t.Fatalf("no %q line in %s", msg, logs.buf.String())
	}
	return found
}

func TestBindMethodAndPath(t *testing.T) {
	fb := &fakeBinder{}
	h := NewBindHandler(fb, jsonLog(io.Discard))
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", mgmtapi.NoncePath("dev-cell-1"), 405},
		{"PUT", mgmtapi.BindPath("dev-cell-1"), 405},
		{"GET", mgmtapi.BindPath("dev-cell-1"), 405},
		{"POST", "/", 404},
		{"POST", "/v1/cells/dev-cell-1", 404},
		{"POST", "/v1/cells/dev-cell-1/other", 404},
		{"POST", "/v1/cells//bind", 404},
		{"POST", mgmtapi.SpecPath("dev"), 404},
		{"POST", mgmtapi.KeysPath("dev-cell-1"), 404},
		{"GET", "/healthz", 404},
	} {
		if rec := do2(h, tc.method, tc.path); rec.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
	if n, b := fb.calls(); n != 0 || b != 0 {
		t.Fatalf("binder called %d, %d times", n, b)
	}
}

func TestBindBodyLimit(t *testing.T) {
	fb := &fakeBinder{}
	logs := &lockedBuf{}
	h := NewBindHandler(fb, jsonLog(logs))
	big := marshal(t, mgmtapi.BindRequest{Nonce: "n", Token: strings.Repeat("a", 17<<10)})
	if rec := do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(big)); rec.Code != 403 {
		t.Fatalf("a body of %d bytes: status %d, want 403", len(big), rec.Code)
	}
	// A body without Content-Length is limited as well.
	req := httptest.NewRequest("POST", mgmtapi.BindPath("dev-cell-1"), io.MultiReader(strings.NewReader(big)))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("a streamed body: status %d, want 403", rec.Code)
	}
	for name, body := range map[string]string{
		"unknown_field": `{"nonce":"n","token":"t","x":1}`,
		"not_json":      `token`,
		"trailing":      `{"nonce":"n","token":"t"}{}`,
		"duplicate":     `{"nonce":"n","nonce":"m","token":"t"}`,
		"array":         `[]`,
	} {
		if rec := do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(body)); rec.Code != 403 {
			t.Errorf("%s: status %d, want 403", name, rec.Code)
		}
	}
	if rec := do(h, "POST", mgmtapi.NoncePath("dev-cell-1"), strings.NewReader(`{"x":1}`)); rec.Code != 403 {
		t.Errorf("nonce with a field: status %d, want 403", rec.Code)
	}
	if n, b := fb.calls(); n != 0 || b != 0 {
		t.Fatalf("binder called %d nonce and %d bind times, want none", n, b)
	}
	logs.mu.Lock()
	echoed := strings.Contains(logs.buf.String(), "aaaaaaaa")
	logs.mu.Unlock()
	if echoed {
		t.Fatal("the log echoes the body")
	}
}

func startBind(t *testing.T, h http.Handler) (addr string, mgmtCA *spiffetest.CA, srv *http.Server) {
	t.Helper()
	mgmtCA = spiffetest.NewCA(t, mgmtTD)
	svids := mgmtCA.Source(t, mgmtSPIFFE)
	dummy := spiffetest.NewCA(t, devTD)
	_, bind := NewServers(http.NotFoundHandler(), h, APIServerTLS(svids, dummy.Bundle(), mustID(t, envdSPIFFE)), BindServerTLS(svids))
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := ListenBind(raw, bind.TLSConfig)
	go func() { _ = bind.Serve(ln) }()
	t.Cleanup(func() { _ = bind.Close() })
	return raw.Addr().String(), mgmtCA, bind
}

func rawTLS(t testing.TB, addr string, mgmtCA *spiffetest.CA, timeout time.Duration) (*tls.Conn, error) {
	t.Helper()
	cfg := tlsconfig.TLSClientConfig(mgmtCA.Bundle(), tlsconfig.AuthorizeID(mustID(t, mgmtSPIFFE)))
	cfg.NextProtos = []string{"h2"}
	d := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(d, "tcp", addr, cfg)
}

func TestListenerConnCap(t *testing.T) {
	addr, mgmtCA, _ := startBind(t, NewBindHandler(&fakeBinder{}, jsonLog(io.Discard)))
	conns := make([]*tls.Conn, 0, 64)
	for i := 0; i < 64; i++ {
		c, err := rawTLS(t, addr, mgmtCA, 5*time.Second)
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		defer c.Close()
		conns = append(conns, c)
	}
	done := make(chan error, 1)
	go func() {
		c, err := rawTLS(t, addr, mgmtCA, 10*time.Second)
		if err == nil {
			defer c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the 65th handshake finished within 1 s: %v", err)
	case <-time.After(1 * time.Second):
	}
	conns[0].Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the 65th handshake after a close: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("the 65th handshake did not finish within 1 s after a close")
	}
}

func TestBindStreamCap(t *testing.T) {
	fb := &fakeBinder{gate: make(chan struct{}), entered: make(chan struct{}, 8)}
	addr, mgmtCA, _ := startBind(t, NewBindHandler(fb, jsonLog(io.Discard)))
	c, err := rawTLS(t, addr, mgmtCA, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cc, err := (&http2.Transport{}).NewClientConn(c)
	if err != nil {
		t.Fatal(err)
	}
	// Until the server settings arrive, the client assumes a larger limit.
	for deadline := time.Now().Add(3 * time.Second); cc.State().MaxConcurrentStreams != 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("MAX_CONCURRENT_STREAMS %d, want 2", cc.State().MaxConcurrentStreams)
		}
	}
	body := marshal(t, mgmtapi.BindRequest{Nonce: "n", Token: "t"})
	send := func() <-chan error {
		ch := make(chan error, 1)
		go func() {
			req, _ := http.NewRequest("POST", "https://"+addr+mgmtapi.BindPath("dev-cell-1"), strings.NewReader(body))
			resp, err := cc.RoundTrip(req)
			if err == nil {
				resp.Body.Close()
			}
			ch <- err
		}()
		return ch
	}
	var results []<-chan error
	for i := 0; i < 3; i++ {
		results = append(results, send())
	}
	for i := 0; i < 2; i++ {
		select {
		case <-fb.entered:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d streams reached the handler", i)
		}
	}
	select {
	case <-fb.entered:
		t.Fatal("a third concurrent stream reached the handler")
	case <-time.After(700 * time.Millisecond):
	}
	if got := cc.State().MaxConcurrentStreams; got != 2 {
		t.Fatalf("MAX_CONCURRENT_STREAMS %d, want 2", got)
	}
	close(fb.gate)
	for i, ch := range results {
		select {
		case err := <-ch:
			if err != nil {
				t.Errorf("request %d: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d did not finish", i)
		}
	}
}

// slowClient holds one bind connection with a trickle of bytes. It ignores GOAWAY, as a hostile
// client does. Mode 0 opens a new stream every 5 s and sends each body at one byte per second.
// Mode 1 sends one header block at one byte per second.
type slowClient struct {
	err    error
	conn   *tls.Conn
	away   chan struct{}
	closed chan struct{}
}

func startSlowClient(t *testing.T, addr string, mgmtCA *spiffetest.CA, mode int) *slowClient {
	t.Helper()
	conn, err := rawTLS(t, addr, mgmtCA, 10*time.Second)
	if err != nil {
		t.Fatalf("slow client: %v", err)
	}
	sc := &slowClient{conn: conn, away: make(chan struct{}), closed: make(chan struct{})}
	var wmu sync.Mutex
	fr := http2.NewFramer(conn, conn)
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(sc.closed)
		var once sync.Once
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				sc.err = err
				return
			}
			switch f.(type) {
			case *http2.GoAwayFrame:
				once.Do(func() { close(sc.away) })
			}
		}
	}()
	headers := func(pad int) []byte {
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		for _, h := range [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", addr}, {":path", mgmtapi.BindPath("dev-cell-1")}, {"content-type", "application/json"}, {"x-pad", strings.Repeat("p", pad)}} {
			_ = enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
		}
		return buf.Bytes()
	}
	locked := func(f func() error) error {
		wmu.Lock()
		defer wmu.Unlock()
		return f()
	}
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		var streams []uint32
		next := uint32(1)
		var block []byte
		if mode == 1 {
			block = headers(400)
			if err := locked(func() error {
				return fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:1], EndHeaders: false})
			}); err != nil {
				return
			}
			block = block[1:]
		}
		for n := 0; ; n++ {
			select {
			case <-tick.C:
			case <-sc.closed:
				return
			}
			if mode == 1 {
				if len(block) == 0 {
					return
				}
				if err := locked(func() error { return fr.WriteContinuation(1, false, block[:1]) }); err != nil {
					return
				}
				block = block[1:]
				continue
			}
			if n%5 == 0 {
				id := next
				next += 2
				if err := locked(func() error {
					return fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: headers(1), EndHeaders: true})
				}); err != nil {
					return
				}
				streams = append(streams, id)
				if len(streams) > 2 {
					streams = streams[1:]
				}
			}
			for _, id := range streams {
				if err := locked(func() error { return fr.WriteData(id, false, []byte{'{'}) }); err != nil {
					return
				}
			}
		}
	}()
	return sc
}

func (s *slowClient) released() bool {
	select {
	case <-s.away:
		return true
	case <-s.closed:
		return true
	default:
		return false
	}
}

func TestBindSlowBodyReleased(t *testing.T) {
	if testing.Short() {
		t.Skip("runs for about 22 s")
	}
	t.Parallel()
	fb := &fakeBinder{}
	addr, mgmtCA, _ := startBind(t, NewBindHandler(fb, jsonLog(io.Discard)))
	start := time.Now()
	var slow []*slowClient
	for i := 0; i < 64; i++ {
		sc := startSlowClient(t, addr, mgmtCA, i%2)
		defer sc.conn.Close()
		slow = append(slow, sc)
	}
	time.Sleep(500 * time.Millisecond)
	nonceCalls := func() int { n, _ := fb.calls(); return n }
	good := h2Client(t, mgmtCA, nil)
	good.Timeout = 30 * time.Second
	var resp *http.Response
	var err error
	for resp == nil {
		resp, err = good.Post("https://"+addr+mgmtapi.NoncePath("dev-cell-1"), "application/json", nil)
		if err != nil {
			t.Fatalf("good bind after %s: %v", time.Since(start), err)
		}
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)
	if resp.StatusCode != 200 || nonceCalls() != 1 {
		t.Fatalf("good request: status %d", resp.StatusCode)
	}
	const limit = 15*time.Second + 5*time.Second + 2*time.Second
	if elapsed > limit {
		t.Fatalf("the good request took %s, more than %s", elapsed, limit)
	}
	if elapsed < 10*time.Second {
		t.Fatalf("the good request took only %s, so the slow clients did not fill the listener", elapsed)
	}
	for time.Since(start) < limit {
		all := true
		for _, sc := range slow {
			all = all && sc.released()
		}
		if all {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for i, sc := range slow {
		if !sc.released() {
			t.Errorf("slow connection %d got neither GOAWAY nor a close after %s", i, elapsed)
		}
	}
}

func TestMaxAgeSendsGoAway(t *testing.T) {
	if testing.Short() {
		t.Skip("runs for about 17 s")
	}
	t.Parallel()
	addr, mgmtCA, _ := startBind(t, NewBindHandler(&fakeBinder{}, jsonLog(io.Discard)))
	c := h2Client(t, mgmtCA, nil)
	start := time.Now()
	var first net.Conn
	var switched time.Duration
	for time.Since(start) < 17*time.Second && switched == 0 {
		var got net.Conn
		trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { got = i.Conn }}
		req, _ := http.NewRequest("POST", "https://"+addr+mgmtapi.NoncePath("dev-cell-1"), nil)
		resp, err := c.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
		if err != nil {
			t.Fatalf("request at %s: %v", time.Since(start), err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d at %s", resp.StatusCode, time.Since(start))
		}
		age := time.Since(start)
		switch {
		case first == nil:
			first = got
		case got != first && switched == 0:
			switched = age
		}
		time.Sleep(time.Second)
	}
	if switched == 0 {
		t.Fatal("the client never moved to a new connection")
	}
	if switched < 14*time.Second || switched > 17*time.Second {
		t.Fatalf("the client moved to a new connection after %s, want about 15 s", switched)
	}
}

func TestRotateKeyPublishes(t *testing.T) {
	r := newRig(t)
	var mu sync.Mutex
	var published []ed25519.PublicKey
	var failWith error
	h := NewAdminHandler(r.plane, func(_ context.Context, pub ed25519.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()
		published = append(published, append(ed25519.PublicKey(nil), pub...))
		return failWith
	})
	old := r.plane.PublicKey()
	rec := do2(h, "POST", "/rotate-key")
	if rec.Code != 200 {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body)
	}
	mu.Lock()
	n := len(published)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("publish called %d times, want 1", n)
	}
	if !published[0].Equal(r.plane.PublicKey()) || published[0].Equal(old) {
		t.Fatal("publish did not get the new key")
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["spec.pub"] != base64.StdEncoding.EncodeToString(published[0]) {
		t.Fatalf("rotate body %s: %v", rec.Body, err)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE") {
		t.Fatal("the answer carries a private key")
	}

	mu.Lock()
	failWith = errors.New("api server down")
	mu.Unlock()
	rec = do2(h, "POST", "/rotate-key")
	if rec.Code != 500 {
		t.Fatalf("failed publish: status %d, want 500", rec.Code)
	}
	var e map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(rec.Body.Bytes()), &e); err != nil || e["error"] == nil || bytes.Count(rec.Body.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("error body %q: %v", rec.Body, err)
	}
}

func TestAdminHandlerCommands(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	h := NewAdminHandler(r.plane, nil)

	rec := do2(h, "GET", "/status")
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != 200 || st.Seq != r.status().Seq || st.Seq == 0 {
		t.Fatalf("status %d %s: %v", rec.Code, rec.Body, err)
	}
	rec = do2(h, "GET", "/pubkey")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString(r.plane.PublicKey())) {
		t.Fatalf("pubkey %d %s", rec.Code, rec.Body)
	}
	rec = do2(h, "GET", "/records")
	var recs map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &recs); err != nil || rec.Code != 200 || len(recs) != 1 || recs[cell1] == nil {
		t.Fatalf("records %d %s: %v", rec.Code, rec.Body, err)
	}
	rec = do2(h, "GET", "/keys/"+cell1)
	var ck mgmtapi.ClusterKeys
	if err := json.Unmarshal(rec.Body.Bytes(), &ck); err != nil || rec.Code != 200 || ck.Issuer != r.keys.issuer(cell1) {
		t.Fatalf("keys %d %s: %v", rec.Code, rec.Body, err)
	}
	if rec = do2(h, "GET", "/keys/nope"); rec.Code != 404 {
		t.Fatalf("keys of an unknown cell: %d", rec.Code)
	}
	r.clk.Advance(61 * time.Second)
	rec = do2(h, "POST", "/keycheck/"+cell1)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), string(CheckUnchanged)) {
		t.Fatalf("keycheck %d %s", rec.Code, rec.Body)
	}
	if rec = do2(h, "GET", "/keycheck/"+cell1); rec.Code != 405 {
		t.Fatalf("GET keycheck: %d", rec.Code)
	}
	if rec = do2(h, "POST", "/status"); rec.Code != 405 {
		t.Fatalf("POST status: %d", rec.Code)
	}
	if rec = do2(h, "GET", "/nope"); rec.Code != 404 {
		t.Fatalf("unknown path: %d", rec.Code)
	}

	// restore
	if rec = do2(h, "POST", "/restore/1"); rec.Code != 200 || !r.status().RestoreActive {
		t.Fatalf("restore 1: %d %s", rec.Code, rec.Body)
	}
	if rec = do2(h, "POST", "/restore/latest"); rec.Code != 200 || r.status().RestoreActive {
		t.Fatalf("restore latest: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"/restore/abc", "/restore/-1", "/restore/"} {
		if rec = do2(h, "POST", bad); rec.Code < 400 || rec.Code >= 500 && rec.Code != 404 {
			t.Errorf("%s: status %d", bad, rec.Code)
		}
	}
}

func TestAdminExpectSeq(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	var published int
	h := NewAdminHandler(r.plane, func(context.Context, ed25519.PublicKey) error { published++; return nil })
	seq := r.status().Seq
	stale := "?expect-seq=" + itoa(seq-1)
	pub := r.plane.PublicKey()
	for _, tc := range []struct{ method, path string }{
		{"POST", "/restore/1"}, {"POST", "/restore/latest"}, {"POST", "/rotate-key"}, {"POST", "/keycheck/" + cell1},
	} {
		rec := do2(h, tc.method, tc.path+stale)
		if rec.Code != 409 || !strings.Contains(rec.Body.String(), mgmtapi.ReasonConflict) {
			t.Errorf("%s with a stale seq: %d %s", tc.path, rec.Code, rec.Body)
		}
	}
	if r.status().Seq != seq || !r.plane.PublicKey().Equal(pub) || published != 0 || r.status().RestoreActive {
		t.Fatal("a stale command changed state")
	}
	if rec := do2(h, "POST", "/restore/1?expect-seq="+itoa(seq)); rec.Code != 200 {
		t.Fatalf("restore at the current seq: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"?expect-seq=x", "?expect-seq=1&expect-seq=2", "?expect-seq="} {
		if rec := do2(h, "POST", "/restore/latest"+bad); rec.Code != 400 {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
}

func itoa(n uint64) string { return strings.TrimSpace(string(mustJSON(n))) }

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func writeBundleFile(t *testing.T, path string, ca *spiffetest.CA) {
	t.Helper()
	pem, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAPIPeerRootLoadsLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer-root.pem")
	fs := &fakeSpec{bundle: testBundle()}
	var rig *apiRig
	rig = startAPI(t, NewAPIHandler(fs, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)), func(*spiffetest.CA) x509bundle.Source {
		return FileBundleSource(path, mustID(t, envdSPIFFE).TrustDomain())
	}, nil)
	get := func() error {
		resp, err := rig.client(t, rig.devCA.Source(t, envdSPIFFE)).Get(rig.specURL("dev"))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return errors.New(resp.Status)
			}
		}
		return err
	}
	if err := get(); err == nil {
		t.Fatal("a handshake succeeded with no bundle file")
	}
	waitLog(t, rig.logs, "peer_root_missing")
	writeBundleFile(t, path, rig.devCA)
	if err := get(); err != nil {
		t.Fatalf("after the file appeared: %v", err)
	}
	// A file that holds another root replaces the first, and the old root stops working.
	other := spiffetest.NewCA(t, devTD)
	writeBundleFile(t, path, other)
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if err := get(); err == nil {
		t.Fatal("the removed root still works")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := get(); err == nil {
		t.Fatal("a handshake succeeded after the file went away")
	}
	_ = rig
}

func waitLog(t *testing.T, logs *lockedBuf, needle string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		logs.mu.Lock()
		ok := strings.Contains(logs.buf.String(), needle)
		logs.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	t.Fatalf("no %q in the log: %s", needle, logs.buf.String())
}

func TestFileBundleSourceReloadsOnChange(t *testing.T) {
	td := mustID(t, envdSPIFFE).TrustDomain()
	path := filepath.Join(t.TempDir(), "b.pem")
	src := FileBundleSource(path, td)
	if _, err := src.GetX509BundleForTrustDomain(td); err == nil || !strings.Contains(err.Error(), "peer_root_missing") {
		t.Fatalf("absent file: %v", err)
	}
	a := spiffetest.NewCA(t, devTD)
	writeBundleFile(t, path, a)
	b, err := src.GetX509BundleForTrustDomain(td)
	if err != nil || len(b.X509Authorities()) != 1 || !b.X509Authorities()[0].Equal(a.Bundle().X509Authorities()[0]) {
		t.Fatalf("first load: %v", err)
	}
	c := spiffetest.NewCA(t, devTD)
	writeBundleFile(t, path, c)
	later := time.Now().Add(time.Minute)
	_ = os.Chtimes(path, later, later)
	b, err = src.GetX509BundleForTrustDomain(td)
	if err != nil || !b.X509Authorities()[0].Equal(c.Bundle().X509Authorities()[0]) {
		t.Fatalf("after the change: %v", err)
	}
	if _, err := src.GetX509BundleForTrustDomain(mustID(t, mgmtSPIFFE).TrustDomain()); err == nil {
		t.Fatal("a bundle for another trust domain")
	}
	if err := os.WriteFile(path, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(path, later.Add(time.Minute), later.Add(time.Minute))
	if _, err := src.GetX509BundleForTrustDomain(td); err == nil {
		t.Fatal("an unreadable file was accepted")
	}
}
