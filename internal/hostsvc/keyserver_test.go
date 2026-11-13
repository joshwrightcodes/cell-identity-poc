package hostsvc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

const (
	mgmtdID     = "spiffe://mgmt.poc.internal/api"
	otherMgmtID = "spiffe://mgmt.poc.internal/telemetry"
)

// lookups is a Facts function that counts calls and answers at once.
type lookups struct {
	n   atomic.Int32
	err error
}

func (l *lookups) facts(_ context.Context, cluster string) (Facts, error) {
	l.n.Add(1)
	if l.err != nil {
		return Facts{}, l.err
	}
	return Facts{Name: cluster, Issuer: "https://" + cluster + ".issuer.poc.internal", JWKS: testJWKS()}, nil
}

func testJWKS() json.RawMessage {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
	b, err := json.Marshal(set)
	if err != nil {
		panic(err)
	}
	return b
}

func privateJWKS() json.RawMessage {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		panic(err)
	}
	return b
}

func useJWKS(use string) json.RawMessage {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: use}}})
	if err != nil {
		panic(err)
	}
	return b
}

func knownCells(n string) bool { return n == "dev-cell-1" || n == "dev-cell-2" }

func newHandler(l *lookups, clock *fakeClock) http.Handler {
	cache := NewKeyCache(l.facts, KeyTTL, KeyMaxInFlight, clock.Now)
	return NewKeyHandler(cache, knownCells, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

func get(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestKeyHandlerServesFacts(t *testing.T) {
	l := &lookups{}
	rec := get(newHandler(l, newFakeClock()), http.MethodGet, mgmtapi.KeysPath("dev-cell-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var keys mgmtapi.ClusterKeys
	if err := json.Unmarshal(rec.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.Name != "dev-cell-1" || keys.Issuer != "https://dev-cell-1.issuer.poc.internal" || !strings.Contains(string(keys.JWKS), "k1") {
		t.Errorf("keys = %+v", keys)
	}
}

func TestKeyHandlerMethods(t *testing.T) {
	l := &lookups{}
	h := newHandler(l, newFakeClock())
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodPatch} {
		rec := get(h, m, mgmtapi.KeysPath("dev-cell-1"))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", m, rec.Code)
		}
		if rec.Header().Get("Allow") != http.MethodGet {
			t.Errorf("%s: Allow = %q", m, rec.Header().Get("Allow"))
		}
	}
	if rec := get(h, http.MethodGet, "/v1/other"); rec.Code != http.StatusNotFound {
		t.Errorf("other path: status = %d, want 404", rec.Code)
	}
	if n := l.n.Load(); n != 0 {
		t.Errorf("lookups = %d, want 0", n)
	}
}

func TestKeyHandlerFactsError(t *testing.T) {
	l := &lookups{err: io.ErrUnexpectedEOF}
	rec := get(newHandler(l, newFakeClock()), http.MethodGet, mgmtapi.KeysPath("dev-cell-1"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" || len(body) != 1 {
		t.Errorf("body = %q, want one JSON error", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "EOF") {
		t.Errorf("body leaks the lookup error: %q", rec.Body)
	}
}

func TestKeyHandlerUnknownCluster(t *testing.T) {
	l := &lookups{}
	h := newHandler(l, newFakeClock())
	for _, name := range []string{"rogue", "management", "dev-cp", "dev-cell-1%2F..", "DEV-CELL-1"} {
		if rec := get(h, http.MethodGet, "/v1/clusters/"+name+"/keys"); rec.Code != http.StatusNotFound {
			t.Errorf("%q: status = %d, want 404", name, rec.Code)
		}
	}
	if n := l.n.Load(); n != 0 {
		t.Errorf("lookups = %d, want 0", n)
	}
}

func TestKeyHandlerCachesFacts(t *testing.T) {
	g := newGatedFacts()
	clock := newFakeClock()
	cache := NewKeyCache(g.facts, KeyTTL, KeyMaxInFlight, clock.Now)
	h := NewKeyHandler(cache, knownCells, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if rec := get(h, http.MethodGet, mgmtapi.KeysPath("dev-cell-1")); rec.Code != http.StatusOK {
				t.Errorf("status = %d", rec.Code)
			}
		})
	}
	waitFor(t, "the lookup to start", func() bool { return g.calls.Load() >= 1 })
	time.Sleep(150 * time.Millisecond)
	close(g.gate)
	wg.Wait()
	if got := g.calls.Load(); got != 1 {
		t.Fatalf("lookups for 100 concurrent requests = %d, want 1", got)
	}
	clock.Advance(59 * time.Second)
	get(h, http.MethodGet, mgmtapi.KeysPath("dev-cell-1"))
	if got := g.calls.Load(); got != 1 {
		t.Errorf("lookups at 59 s = %d, want 1", got)
	}
	clock.Advance(2 * time.Second)
	if rec := get(h, http.MethodGet, mgmtapi.KeysPath("dev-cell-1")); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := g.calls.Load(); got != 2 {
		t.Errorf("lookups at 61 s = %d, want 2", got)
	}
}

func TestKeyHandlerLimitsDenialLogs(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	w := writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return buf.Write(p) })
	clock := newFakeClock()
	cache := NewKeyCache((&lookups{}).facts, KeyTTL, 1, clock.Now)
	h := NewKeyHandler(cache, knownCells, slog.New(slog.NewJSONHandler(w, nil)))
	for range 50 {
		get(h, http.MethodGet, "/v1/clusters/rogue/keys")
	}
	mu.Lock()
	lines := strings.Count(buf.String(), "\n")
	mu.Unlock()
	if lines != 1 {
		t.Fatalf("log lines for 50 denials = %d, want 1", lines)
	}
	clock.Advance(11 * time.Second)
	get(h, http.MethodGet, "/v1/clusters/rogue/keys")
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if strings.Count(out, "\n") != 2 || !strings.Contains(out, `"suppressed":49`) {
		t.Errorf("second window log = %q, want a second line with suppressed 49", out)
	}
}

// keyServer starts the key server on loopback with fake lookups.
func keyServer(t *testing.T, roots x509bundle.Source, l *lookups) (addr string, cert tls.Certificate) {
	t.Helper()
	return keyServerMeter(t, roots, l, nil)
}

func keyServerMeter(t *testing.T, roots x509bundle.Source, l *lookups, meter metric.Meter) (addr string, cert tls.Certificate) {
	t.Helper()
	cert, err := SelfSignedCert(KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := spiffeid.RequireFromString(mgmtdID)
	cache := NewKeyCache(l.facts, KeyTTL, KeyMaxInFlight, nil)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv := NewKeyServer(NewKeyHandler(cache, knownCells, log), ServerTLS(cert, roots, id), log)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeKeys(ctx, srv, ln, log, meter) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ServeKeys: %v", err)
		}
	})
	return ln.Addr().String(), cert
}

func TestKeyHandlerRequiresMgmtdSVID(t *testing.T) {
	mgmtCA := spiffetest.NewCA(t, "mgmt.poc.internal")
	otherCA := spiffetest.NewCA(t, "mgmt.poc.internal")
	call := func(t *testing.T, cert *tls.Certificate) (*http.Response, error) {
		t.Helper()
		l := &lookups{}
		addr, _ := keyServer(t, mgmtCA.Bundle(), l)
		cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
		resp, err := client.Get("https://" + addr + mgmtapi.KeysPath("dev-cell-1"))
		if err == nil {
			t.Cleanup(func() { resp.Body.Close() })
		}
		if err != nil || resp.StatusCode != http.StatusOK {
			if n := l.n.Load(); n != 0 {
				t.Errorf("lookups = %d, want 0", n)
			}
		}
		return resp, err
	}
	tlsCert := func(ca *spiffetest.CA, id string) *tls.Certificate {
		svid := ca.SVID(t, id)
		return &tls.Certificate{Certificate: [][]byte{svid.Certificates[0].Raw}, PrivateKey: svid.PrivateKey, Leaf: svid.Certificates[0]}
	}
	for name, cert := range map[string]*tls.Certificate{
		"no_cert":  nil,
		"other_ca": tlsCert(otherCA, mgmtdID),
		"other_id": tlsCert(mgmtCA, otherMgmtID),
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := call(t, cert)
			if err == nil {
				t.Fatalf("request succeeded with status %d, want a failed handshake", resp.StatusCode)
			}
		})
	}
	t.Run("mgmtd", func(t *testing.T) {
		resp, err := call(t, tlsCert(mgmtCA, mgmtdID))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})
}

func TestServerTLSVersionAndTickets(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	cert, err := SelfSignedCert(KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerTLS(cert, ca.Bundle(), spiffeid.RequireFromString(mgmtdID))
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAnyClientCert || !cfg.SessionTicketsDisabled {
		t.Errorf("config = min %x, auth %v, tickets disabled %v", cfg.MinVersion, cfg.ClientAuth, cfg.SessionTicketsDisabled)
	}
}

func TestSelfSignedCert(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	cert, err := SelfSignedCert("host.docker.internal", now)
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("key algorithm = %v", leaf.PublicKeyAlgorithm)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "host.docker.internal" {
		t.Errorf("DNS names = %v", leaf.DNSNames)
	}
	if !leaf.NotBefore.Equal(now.Add(-time.Minute)) || !leaf.NotAfter.Equal(now.Add(90*24*time.Hour)) {
		t.Errorf("validity = %v to %v", leaf.NotBefore, leaf.NotAfter)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.IsCA {
		t.Errorf("usage = %v, CA %v", leaf.ExtKeyUsage, leaf.IsCA)
	}
}

func TestCheckLoopbackAddr(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:17443", "127.1.2.3:1", "[::1]:1"} {
		if err := CheckLoopbackAddr(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:1", "[::]:1", ":1", "localhost:1", "192.168.5.2:1", "10.0.0.1:1", "127.0.0.1", ""} {
		if err := CheckLoopbackAddr(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func newDiscardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }
