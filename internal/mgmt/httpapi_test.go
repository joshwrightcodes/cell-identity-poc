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

// fakeAPI is an APIServer. reportFn replaces the default answer of Reports, which is one accepted
// outcome for each item.
type fakeAPI struct {
	mu       sync.Mutex
	bundle   mgmtapi.SpecBundle
	reports  []mgmtapi.StatusReport
	ops      mgmtapi.OpsBundle
	opsCalls int
	batches  []mgmtapi.ReportBatch
	reportFn func(context.Context, mgmtapi.ReportBatch) mgmtapi.ReportResult
	ctxs     []context.Context
}

func (f *fakeAPI) Spec() mgmtapi.SpecBundle { return f.bundle }
func (f *fakeAPI) Report(r mgmtapi.StatusReport) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, r)
}
func (f *fakeAPI) got() []mgmtapi.StatusReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mgmtapi.StatusReport(nil), f.reports...)
}

func (f *fakeAPI) OpenOps() mgmtapi.OpsBundle {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opsCalls++
	return f.ops
}

func (f *fakeAPI) Reports(ctx context.Context, b mgmtapi.ReportBatch) mgmtapi.ReportResult {
	f.mu.Lock()
	f.batches = append(f.batches, b)
	f.ctxs = append(f.ctxs, ctx)
	fn := f.reportFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, b)
	}
	res := mgmtapi.ReportResult{Outcomes: []mgmtapi.ItemOutcome{}}
	for _, it := range b.Items {
		res.Outcomes = append(res.Outcomes, mgmtapi.ItemOutcome{ID: it.ID, Outcome: mgmtapi.OutcomeAccepted})
	}
	return res
}

func testBundle() mgmtapi.SpecBundle {
	return mgmtapi.SpecBundle{
		Spec:    json.RawMessage(`{"payloadType":"t","payload":"cA==","signatures":[]}`),
		Records: map[string]json.RawMessage{"dev-cell-1": json.RawMessage(`{"payloadType":"r","payload":"cQ==","signatures":[]}`)},
	}
}

// calls returns the number of Reports and OpenOps calls.
func (f *fakeAPI) calls() (reports, ops int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.batches), f.opsCalls
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
	api := NewServers(h, apiTLS)
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
	fs := &fakeAPI{bundle: testBundle()}
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
	fs := &fakeAPI{bundle: testBundle()}
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
	fs := &fakeAPI{bundle: testBundle()}
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
		{"POST", "/v1/cells/dev-cell-1/nonce"},
		{"POST", "/v1/cells/dev-cell-1/bind"},
		{"GET", mgmtapi.OpsPath("prod")},
		{"POST", mgmtapi.ReportsPath("prod")},
		{"POST", mgmtapi.OpsPath("dev")},
		{"DELETE", mgmtapi.OpsPath("dev")},
		{"GET", mgmtapi.ReportsPath("dev")},
		{"PUT", mgmtapi.ReportsPath("dev")},
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
	if nr, no := fs.calls(); nr != 0 || no != 0 {
		t.Fatalf("%d report and %d ops calls reached the plane", nr, no)
	}
}

func TestAPIHandlerChecksPeerID(t *testing.T) {
	ca := spiffetest.NewCA(t, devTD)
	h := NewAPIHandler(&fakeAPI{bundle: testBundle()}, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard))
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
	fs := &fakeAPI{bundle: testBundle()}
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
