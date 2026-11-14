package mgmt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
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
		"too_large":     `{"storeError":"` + strings.Repeat("a", 65<<10) + `"}`,
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

// peerRequest returns a POST request to target that carries the verified envd certificate.
func peerRequest(t *testing.T, ca *spiffetest.CA, target string, body io.Reader) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", target, body)
	req.TLS = &tls.ConnectionState{PeerCertificates: ca.SVID(t, envdSPIFFE).Certificates}
	return req
}

func TestReportSizeWithStepsAndGateway(t *testing.T) {
	ca := spiffetest.NewCA(t, devTD)
	fs := &fakeAPI{bundle: testBundle()}
	h := NewAPIHandler(fs, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard))
	at := time.Unix(1700000000, 0).UTC()
	cell := strings.Repeat("c", 63)
	var steps []mgmtapi.StepStatus
	for i := range 32 {
		steps = append(steps, mgmtapi.StepStatus{
			ID: fmt.Sprintf("%032x", i), Cell: cell, State: mgmtapi.StepFailedFinal, Stage: mgmtapi.StageBootstrapping,
			Reason: mgmtapi.ReasonHostsvcUnavailable, Detail: step.DetailBootstrapMismatch, RequestID: strings.Repeat("a", 16),
			NodeIP: "255.255.255.255", Attempts: 3, UpdatedAt: at, RetryAt: at,
			LastHostError: &mgmtapi.HostErrorInfo{Reason: mgmtapi.ReasonHostsvcUnavailable, At: at},
		})
	}
	gw := &mgmtapi.GatewayStatus{
		Epoch: 1, SyncedAt: at, OutboxItems: 9, Queued: map[string]int{}, Streams: map[string]int{},
		MostClaimed: map[string]mgmtapi.ClaimInfo{}, Records: map[string]spec.Revision{}, LastBindRefusal: map[string]mgmtapi.BindRefusal{},
	}
	for i := range 8 {
		c := fmt.Sprintf("%s%d", strings.Repeat("g", 62), i)
		gw.Queued[c], gw.Streams[c] = 9, 9
		gw.MostClaimed[c] = mgmtapi.ClaimInfo{OpID: strings.Repeat("b", 32), Count: 99}
		gw.Records[c] = spec.Revision{Epoch: 9, Counter: 99}
		gw.LastBindRefusal[c] = mgmtapi.BindRefusal{Reason: mgmtapi.ReasonTokenInvalid, RequestID: strings.Repeat("a", 16), At: at}
		gw.KeyHints = append(gw.KeyHints, mgmtapi.KeyHint{Cell: c, At: at})
	}
	rep := mgmtapi.StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 3}, Gateway: gw, Steps: steps, StepsAt: at}
	post := func(rep mgmtapi.StatusReport, unknownLength bool) *httptest.ResponseRecorder {
		body := marshal(t, rep)
		var rd io.Reader = strings.NewReader(body)
		if unknownLength {
			rd = io.MultiReader(rd)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, peerRequest(t, ca, mgmtapi.StatusPath("dev"), rd))
		return rec
	}
	for _, unknown := range []bool{false, true} {
		body := marshal(t, rep)
		if len(body) <= maxRequestBody || len(body) >= maxStatusBody {
			t.Fatalf("the report has %d bytes, which must pass 16 KiB and stay under 64 KiB", len(body))
		}
		if rec := post(rep, unknown); rec.Code != http.StatusNoContent {
			t.Fatalf("unknownLength=%v: status %d %s", unknown, rec.Code, rec.Body)
		}
	}
	if got := fs.got(); len(got) != 2 || len(got[1].Steps) != 32 {
		t.Fatalf("the plane got %d reports", len(got))
	}
	// A body of 64 KiB passes and one byte more does not.
	pad := func(n int) mgmtapi.StatusReport {
		r := rep
		r.StoreError = "x"
		r.StoreError = strings.Repeat("x", n-len(marshal(t, r))+1)
		return r
	}
	at64 := pad(maxStatusBody)
	if n := len(marshal(t, at64)); n != maxStatusBody {
		t.Fatalf("padded body has %d bytes", n)
	}
	if rec := post(at64, true); rec.Code != http.StatusNoContent {
		t.Fatalf("64 KiB: status %d %s", rec.Code, rec.Body)
	}
	over := pad(maxStatusBody + 1)
	for _, unknown := range []bool{false, true} {
		rec := post(over, unknown)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "body_too_large") {
			t.Fatalf("64 KiB plus one, unknownLength=%v: status %d %s", unknown, rec.Code, rec.Body)
		}
	}
	if len(fs.got()) != 3 {
		t.Fatalf("a refused report reached the plane: %d", len(fs.got()))
	}
}

// adminPost sends body to path of the admin handler with no Content-Length, as a chunked client does.
func adminPost(h http.Handler, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", path, io.MultiReader(strings.NewReader(body)))
	req.ContentLength = -1
	h.ServeHTTP(rec, req)
	return rec
}

func reasonOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	s, _ := m["reason"].(string)
	return s
}

func TestAdminPortalBodyStrict(t *testing.T) {
	r := newBareRig(t)
	h := NewAdminHandler(r.plane, nil)
	digest := strings.Repeat("a", 64)
	good := `{"cells":["` + cell1 + `"],"bootstrapSHA256":"` + digest + `"}`
	routes := []string{"/portal/request", "/portal/withdraw", "/portal/recreate", "/portal/retry", "/portal/cancel", "/steps/sign"}
	before := r.status().Seq
	for _, route := range routes {
		body := good
		if route == "/steps/sign" {
			body = `{"env":"dev"}`
		}
		for name, bad := range map[string]struct{ body, want string }{
			"unknown_field": {strings.TrimSuffix(body, "}") + `,"extra":1}`, "body_invalid"},
			"force_field":   {strings.TrimSuffix(body, "}") + `,"force":true}`, "body_invalid"},
			"trailing_data": {body + `{}`, "body_invalid"},
			"not_json":      {`nope`, "body_invalid"},
			"empty":         {``, "body_invalid"},
			"too_large":     {body + strings.Repeat(" ", maxRequestBody+1-len(body)), "body_too_large"},
			"wrong_type":    {`{"cells":"` + cell1 + `"}`, "body_invalid"},
		} {
			for _, chunked := range []bool{false, true} {
				var rec *httptest.ResponseRecorder
				if chunked {
					rec = adminPost(h, route, bad.body)
				} else {
					rec = do(h, "POST", route, strings.NewReader(bad.body))
				}
				var m map[string]any
				_ = json.Unmarshal(rec.Body.Bytes(), &m)
				if rec.Code != http.StatusBadRequest || m["error"] != bad.want || m["reason"] != bad.want {
					t.Errorf("%s %s chunked=%v: status %d body %q, want 400 %s", route, name, chunked, rec.Code, rec.Body, bad.want)
				}
			}
		}
		if rec := do(h, "GET", route); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: status %d, want 405", route, rec.Code)
		}
	}
	if r.status().Seq != before || len(r.plane.snap.Load().st.Requests) != 0 {
		t.Fatal("a body that was refused changed the state")
	}

	// A body of exactly 16 KiB reaches the plane.
	padded := good + strings.Repeat(" ", maxRequestBody-len(good))
	if rec := adminPost(h, "/portal/request", padded); rec.Code != http.StatusOK {
		t.Fatalf("a body of 16 KiB: status %d %s", rec.Code, rec.Body)
	}

	// Refusals map to statuses by reason.
	for _, tc := range []struct {
		route, body string
		status      int
		reason      string
	}{
		{"/portal/request", `{"cells":["nope"],"bootstrapSHA256":"` + digest + `"}`, 404, mgmtapi.ReasonCellUnknown},
		{"/portal/request", `{"cells":["` + cell2 + `"],"bootstrapSHA256":"short"}`, 422, mgmtapi.ReasonBootstrapInvalid},
		{"/portal/request", `{"cells":[],"bootstrapSHA256":"` + digest + `"}`, 422, mgmtapi.ReasonPayloadInvalid},
		{"/portal/withdraw", `{"cells":["nope"]}`, 404, mgmtapi.ReasonCellUnknown},
		{"/portal/cancel", `{"cells":["nope"]}`, 404, mgmtapi.ReasonCellUnknown},
		{"/portal/cancel", `{"cells":["` + cell2 + `"]}`, 422, mgmtapi.ReasonNoStep},
		{"/portal/retry", `{"cells":["` + cell2 + `"],"bootstrapSHA256":"` + digest + `"}`, 422, mgmtapi.ReasonNoStep},
		{"/portal/recreate", `{"cells":["` + cell2 + `"],"bootstrapSHA256":"` + digest + `"}`, 422, mgmtapi.ReasonNotRequested},
		{"/portal/recreate", `{"cells":["` + cell1 + `","` + cell2 + `"],"bootstrapSHA256":"` + digest + `"}`, 400, "body_invalid"},
		{"/portal/retry", `{"cells":[],"bootstrapSHA256":"` + digest + `"}`, 400, "body_invalid"},
		{"/portal/cancel", `{"cells":["` + cell1 + `"],"bootstrapSHA256":"` + digest + `"}`, 400, "body_invalid"},
		{"/portal/withdraw", `{"cells":["` + cell1 + `"],"bootstrapSHA256":"` + digest + `"}`, 400, "body_invalid"},
		{"/steps/sign", `{"id":"","env":"dev","cell":"` + cell1 + `","kind":"cell.create","version":1,"keyEpoch":0,"issuedAt":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T01:00:00Z","cluster":{"podSubnet":"10.20.0.0/16","serviceSubnet":"10.21.0.0/16","issuer":"https://x.test"},"bootstrapSHA256":"` + digest + `"}`, 422, mgmtapi.ReasonTestDigestOnly},
	} {
		rec := do(h, "POST", tc.route, strings.NewReader(tc.body))
		if rec.Code != tc.status || reasonOf(t, rec) != tc.reason {
			t.Errorf("%s %s: status %d reason %q body %s, want %d %q", tc.route, tc.body, rec.Code, reasonOf(t, rec), rec.Body, tc.status, tc.reason)
		}
	}
	if rec := do(h, "POST", "/portal/withdraw", strings.NewReader(`{"cells":["`+cell1+`"]}`)); rec.Code != 200 {
		t.Fatalf("withdraw: %d %s", rec.Code, rec.Body)
	}
	if len(r.plane.snap.Load().st.Requests) != 0 {
		t.Fatal("withdraw left a request")
	}
}

func TestAdminPortalRoutesCallThePlane(t *testing.T) {
	r := newBareRig(t)
	h := NewAdminHandler(r.plane, nil)
	digest := strings.Repeat("a", 64)
	rec := do(h, "POST", "/portal/request", strings.NewReader(`{"cells":["`+cell1+`","`+cell2+`"],"bootstrapSHA256":"`+digest+`"}`))
	var res mgmtapi.PortalResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || rec.Code != 200 || len(res.Steps) != 2 || bytes.Count(rec.Body.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("request: %d %s: %v", rec.Code, rec.Body, err)
	}
	first := r.stepOf(cell1).ID
	rec = do(h, "POST", "/portal/retry", strings.NewReader(`{"cells":["`+cell1+`"],"bootstrapSHA256":"`+digest+`"}`))
	if rec.Code != 200 || r.stepOf(cell1) == nil || r.stepOf(cell1).ID == first {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	if rec = do(h, "POST", "/portal/cancel", strings.NewReader(`{"cells":["`+cell2+`"]}`)); rec.Code != 200 || r.stepOf(cell2) != nil {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body)
	}
	if rec = do(h, "POST", "/portal/withdraw", strings.NewReader(`{"cells":["`+cell1+`","`+cell2+`"]}`)); rec.Code != 200 || len(r.plane.snap.Load().st.Requests) != 0 {
		t.Fatalf("withdraw: %d %s", rec.Code, rec.Body)
	}
	if rec = do(h, "POST", "/portal/recreate", strings.NewReader(`{"cells":["`+cell1+`"],"bootstrapSHA256":"`+digest+`"}`)); rec.Code != 422 || reasonOf(t, rec) != mgmtapi.ReasonNotRequested {
		t.Fatalf("recreate of an unrequested cell: %d %s", rec.Code, rec.Body)
	}
}

func TestAdminStepsSign(t *testing.T) {
	r := newBareRig(t)
	h := NewAdminHandler(r.plane, nil)
	body := step.Step{
		Env: "dev", Cell: cell1, Kind: step.KindCellCreate, Version: 1, IssuedAt: r.clk.Now(),
		ExpiresAt: r.clk.Now().Add(time.Hour), Cluster: testCluster(cell1), BootstrapSHA256: step.TestDigest,
	}
	before := r.status().Seq
	rec := do(h, "POST", "/steps/sign", strings.NewReader(marshal(t, body)))
	if rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	got, _, err := step.Verify(bytes.TrimSpace(rec.Body.Bytes()), []ed25519.PublicKey{r.plane.PublicKey()})
	if err != nil || got.Cell != cell1 || got.ID == "" || r.status().Seq != before {
		t.Fatalf("step %+v err %v seq %d to %d", got, err, before, r.status().Seq)
	}
	// A body that the step rules refuse is a bad request, not a server error.
	body.Cell = "Not A Cell"
	if rec = do(h, "POST", "/steps/sign", strings.NewReader(marshal(t, body))); rec.Code != 400 || reasonOf(t, rec) != "body_invalid" {
		t.Fatalf("invalid step: %d %s", rec.Code, rec.Body)
	}
}
