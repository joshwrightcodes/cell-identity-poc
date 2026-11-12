package cellproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const anyCellRole = `^spiffe://dev\.env\.poc\.internal/cell/[a-z0-9-]+/[a-z0-9-]+$`

// findLog waits up to d for a line with msg whose fields hold every value in want, and returns it.
func findLog(t *testing.T, out *syncBuffer, msg string, want map[string]any, d time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
	lines:
		for _, l := range logLines(t, out) {
			if l["msg"] != msg {
				continue
			}
			for k, v := range want {
				if fmt.Sprint(l[k]) != fmt.Sprint(v) {
					continue lines
				}
			}
			return l
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q line with %v in:\n%s", msg, want, out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func countLog(t *testing.T, out *syncBuffer, msg string) int {
	t.Helper()
	n := 0
	for _, l := range logLines(t, out) {
		if l["msg"] == msg {
			n++
		}
	}
	return n
}

// svidUntil issues a leaf for id that expires at notAfter.
func (ca *testCA) svidUntil(t *testing.T, id string, notAfter time.Time) *x509svid.SVID {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: spiffeid.RequireFromString(id), Certificates: []*x509.Certificate{cert}, PrivateKey: key}
}

// rotatingSource gives the next SVID at each call and keeps the last one, as a Workload API
// source does after a rotation.
type rotatingSource struct {
	mu    sync.Mutex
	svids []*x509svid.SVID
	n     int
}

func (s *rotatingSource) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	svid := s.svids[min(s.n, len(s.svids)-1)]
	s.n++
	return svid, nil
}

func (s *rotatingSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return nil, fmt.Errorf("no bundles")
}

// serveFixed opens one tunnel by hand that answers every request with body.
func (h *tunnelHarness) serveFixed(t *testing.T, dial func(context.Context) (net.Conn, error), handler http.Handler) chan struct{} {
	t.Helper()
	conn, err := dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { serveTunnel(t.Context(), newTunnelServer(), conn, handler); close(done) }()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return done
}

func textHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
}

func getURL(t *testing.T, u string, header http.Header) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestHubRefusesSource(t *testing.T) {
	cases := map[string]Source{
		"unknown cell": {Env: "dev", Cluster: "dev-cell-9", Plane: PlaneCell, Cell: "dev-cell-9", Role: "mesh-view"},
		"other plane":  {Env: "dev", Cluster: "dev-cp", Plane: PlaneEnvironment, Cell: "dev-cell-1", Role: "mesh-view"},
		"wrong role":   {Env: "dev", Cluster: "dev-cell-1", Plane: PlaneCell, Cell: "dev-cell-1", Role: "argocd-agent"},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			out := &syncBuffer{}
			reader := sdkmetric.NewManualReader()
			tm, err := NewTunnelMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
			if err != nil {
				t.Fatal(err)
			}
			hub := NewTunnelHub(map[string]string{"dev-cell-1": ":18001"}, time.Second, jsonLog(out), WithMetrics(tm))
			a, b := net.Pipe()
			defer func() { _ = b.Close() }()
			done := make(chan struct{})
			go func() { hub.Accept(tlsServerConn(a), src); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Accept did not return")
			}
			if _, err := b.Read(make([]byte, 1)); err == nil {
				t.Fatal("the connection is still open")
			}
			findLog(t, out, "tunnel_refused", map[string]any{"reason": PeerNotAllowed, "cell": src.Cell, "role": src.Role}, 5*time.Second)
			if n := countLog(t, out, "tunnel_up"); n != 0 {
				t.Fatalf("%d tunnel_up lines", n)
			}
			waitMetric(t, reader, "cell_proxy.tunnel.connects", map[string]string{
				"side": "hub", "cell": src.Cell, "role": src.Role, "result": "refused", "reason": string(PeerNotAllowed)}, 1)
		})
	}
}

// TestHubRefusesNonMeshViewRole checks that the hub binds the role itself, with an --allow-id
// pattern that admits every role of a cell.
func TestHubRefusesNonMeshViewRole(t *testing.T) {
	h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 5 * time.Second, allow: anyCellRole})
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	h.serveFixed(t, h.dialerFor(t, "spiffe://dev.env.poc.internal/cell/dev-cell-1/argocd-agent"), textHandler("forged"))
	findLog(t, h.hubLog, "tunnel_refused", map[string]any{"cell": "dev-cell-1", "role": "argocd-agent", "reason": PeerNotAllowed}, 5*time.Second)
	code, body := h.get(t, "/api/v1/pods")
	if code != http.StatusOK || strings.Contains(string(body), "forged") {
		t.Fatalf("status %d, body %s", code, body)
	}
	if n := countLog(t, h.hubLog, "tunnel_up"); n != 1 {
		t.Fatalf("%d tunnel_up lines, want 1", n)
	}
}

func TestHubBindsTunnelToItsCell(t *testing.T) {
	pub, priv := signerKey(t)
	reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub}, priv, cell("dev-cell-1", false), cell("dev-cell-2", false)))
	if err != nil {
		t.Fatal(err)
	}
	h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 500 * time.Millisecond, cells: []string{"dev-cell-1", "dev-cell-2"}, registry: reg})
	h.serveFixed(t, h.dialerFor(t, "spiffe://dev.env.poc.internal/cell/dev-cell-2/mesh-view"), textHandler("dev-cell-2"))
	h.waitTunnelsFor(t, "dev-cell-2", 1, 5*time.Second)
	if code, body := getURL(t, h.hubURLs["dev-cell-2"]+"/api/v1/pods", nil); code != http.StatusOK || string(body) != "dev-cell-2" {
		t.Fatalf("dev-cell-2 listener: status %d, body %s", code, body)
	}
	code, body := getURL(t, h.hubURLs["dev-cell-1"]+"/api/v1/pods", nil)
	assertRefusal(t, code, body, http.StatusServiceUnavailable, string(UpstreamUnavailable))
}

func TestHubStripsIdentityHeaders(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	var mu sync.Mutex
	var seen http.Header
	h.serveFixed(t, h.dialer(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
	}))
	h.waitTunnels(t, 1, 5*time.Second)
	code, body := getURL(t, h.hubURL+"/api/v1/pods", http.Header{
		"Authorization":    {"Bearer kiali"},
		"Impersonate-User": {"admin"},
		"X-Real-Ip":        {"1.2.3.4"},
		"X-Forwarded-For":  {"1.2.3.4"},
		"Forwarded":        {"for=1.2.3.4"},
		"Cookie":           {"kiali-token=x"},
		"Audit-Id":         {"forged-audit"},
		"X-Remote-User":    {"system:admin"},
		"Accept":           {"application/json"},
	})
	if code != http.StatusOK {
		t.Fatalf("status %d, body %s", code, body)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, k := range []string{"Authorization", "Impersonate-User", "X-Real-Ip", "X-Forwarded-For", "Forwarded", "Cookie", "Audit-Id", "X-Remote-User"} {
		if v := seen.Values(k); len(v) != 0 {
			t.Errorf("the tunnel got %s: %v", k, v)
		}
	}
	if seen.Get("Accept") != "application/json" {
		t.Errorf("the tunnel got Accept %q", seen.Get("Accept"))
	}
}

func TestHubRefusesUpgrade(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	code, body := getURL(t, h.hubURL+"/api/v1/pods", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}})
	assertDenied(t, code, body)
	if n := h.api.hits.Load(); n != 0 {
		t.Fatalf("the API got %d requests", n)
	}
}

func TestHubWaitEndsOnCancel(t *testing.T) {
	hub := NewTunnelHub(map[string]string{"dev-cell-1": ":18001"}, 10*time.Second, jsonLog(&syncBuffer{}))
	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() { hub.Handler("dev-cell-1").ServeHTTP(httptest.NewRecorder(), req); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the handler still waits for a tunnel 1 second after the client canceled")
	}
}

func TestHubLogsReplacement(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	first := h.serveFixed(t, h.dialer(t), textHandler("first"))
	h.waitTunnels(t, 1, 5*time.Second)
	time.Sleep(1100 * time.Millisecond)
	h.serveFixed(t, h.dialer(t), textHandler("second"))
	h.waitTunnels(t, 2, 5*time.Second)
	line := findLog(t, h.hubLog, "tunnel_replaced", map[string]any{"cell": "dev-cell-1", "old_conn_id": 1, "new_conn_id": 2}, 5*time.Second)
	if age, _ := line["old_age_seconds"].(float64); age < 1 {
		t.Fatalf("old_age_seconds %v, want at least 1", line["old_age_seconds"])
	}
	if _, ok := line["new_age_seconds"].(float64); !ok {
		t.Fatalf("no new_age_seconds in %v", line)
	}
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the hub did not close the older connection")
	}
	findLog(t, h.hubLog, "tunnel_down", map[string]any{"cell": "dev-cell-1", "conn_id": 1, "replaced": true}, 5*time.Second)
}

func TestTunnelClosesAtSVIDExpiry(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	src := &rotatingSource{svids: []*x509svid.SVID{
		h.env.svidUntil(t, meshViewID1, time.Now().Add(2*time.Second)),
		h.env.svidUntil(t, meshViewID1, time.Now().Add(time.Hour)),
	}}
	startCell(t, h.dialerWith(src), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	findLog(t, h.hubLog, "tunnel_expired", map[string]any{"cell": "dev-cell-1", "conn_id": 1}, 5*time.Second)
	h.waitTunnels(t, 2, 5*time.Second)
	if code, body := h.get(t, "/api/v1/pods"); code != http.StatusOK {
		t.Fatalf("after the new SVID: status %d, body %s", code, body)
	}
}

func TestTunnelLogsHubAcceptance(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		h := newTunnelHarness(t, 5*time.Second)
		startCell(t, h.dialer(t), h.cellHandler(t))
		findLog(t, h.cellLog, "tunnel_connected", map[string]any{"upstream": h.server}, 5*time.Second)
	})
	t.Run("role refused by the hub", func(t *testing.T) {
		h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 5 * time.Second, allow: anyCellRole})
		startCell(t, h.dialerFor(t, "spiffe://dev.env.poc.internal/cell/dev-cell-1/argocd-agent"), h.cellHandler(t))
		findLog(t, h.cellLog, "tunnel_refused", map[string]any{"reason": PeerNotAllowed, "upstream": h.server}, 5*time.Second)
		if n := countLog(t, h.cellLog, "tunnel_connected"); n != 0 {
			t.Fatalf("%d tunnel_connected lines for a refused tunnel:\n%s", n, h.cellLog.String())
		}
	})
	t.Run("revoked cell refused in the handshake", func(t *testing.T) {
		h := newTunnelHarness(t, 5*time.Second)
		startCell(t, h.dialerFor(t, "spiffe://dev.env.poc.internal/cell/dev-cell-2/mesh-view"), h.cellHandler(t))
		line := findLog(t, h.cellLog, "tunnel_refused", map[string]any{"reason": PeerNotAllowed}, 5*time.Second)
		if e, _ := line["error"].(string); !strings.Contains(e, "tls") {
			t.Fatalf("error %q does not name the TLS refusal", e)
		}
		if n := countLog(t, h.cellLog, "tunnel_connected"); n != 0 {
			t.Fatalf("%d tunnel_connected lines for a refused tunnel", n)
		}
	})
}

// A flood of watches ends at the stream cap: the next request gets 503 with overloaded, the
// refusal counts as a hub refusal, and a request that follows the end of a watch passes again.
func TestHubCapsStreams(t *testing.T) {
	h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 5 * time.Second, maxStreams: 2})
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	var bodies []io.ReadCloser
	for range 2 {
		resp, err := http.Get(h.hubURL + "/api/v1/pods?watch=true")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a watch under the cap got status %d", resp.StatusCode)
		}
		bodies = append(bodies, resp.Body)
	}
	code, body := h.get(t, "/api/v1/pods")
	assertRefusal(t, code, body, http.StatusServiceUnavailable, "overloaded")
	findLog(t, h.hubLog, "request denied", map[string]any{"reason": "overloaded", "cell": "dev-cell-1"}, 5*time.Second)
	h.api.releaseWatches()
	for _, b := range bodies {
		_, _ = io.Copy(io.Discard, b)
		_ = b.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body := h.get(t, "/api/v1/pods")
		if code == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the cap still refuses after the watches ended: %d %s", code, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The listener bounds the header time, the idle time and the header size. It sets no read or write
// timeout, because a watch is one long response.
func TestHubListenerLimits(t *testing.T) {
	h := NewTunnelHub(map[string]string{"dev-cell-1": "127.0.0.1:0"}, time.Second, jsonLog(&syncBuffer{}))
	srv := h.newServer("dev-cell-1")
	if srv.ReadHeaderTimeout != readHeaderTimeout || srv.IdleTimeout != hubIdleTimeout || srv.MaxHeaderBytes != hubMaxHeaderBytes {
		t.Errorf("header timeout %s, idle timeout %s, header bytes %d", srv.ReadHeaderTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Errorf("read timeout %s and write timeout %s end a watch", srv.ReadTimeout, srv.WriteTimeout)
	}
	ts := httptest.NewUnstartedServer(srv.Handler)
	ts.Config = srv
	ts.Start()
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/pods", nil)
	req.Header.Set("X-Big", strings.Repeat("a", hubMaxHeaderBytes+8192))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("a header over %d bytes got status %d, want 431", hubMaxHeaderBytes, resp.StatusCode)
	}
}
