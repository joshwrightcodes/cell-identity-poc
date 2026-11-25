package cellproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"golang.org/x/net/http2"
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
	go func() {
		serveTunnel(t.Context(), newTunnelServer(upstreamReadIdle, upstreamPingTimeout), conn, handler, &http.Server{})
		close(done)
	}()
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

// The cell opens the next tunnel before the SVID of the current one ends, so the hub replaces the old
// tunnel and no request waits for a new dial. The hub timer at the expiry never has to fire.
func TestTunnelRenewsBeforeSVIDExpiry(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	src := &rotatingSource{svids: []*x509svid.SVID{
		h.env.svidUntil(t, meshViewID1, time.Now().Add(5*time.Second)),
		h.env.svidUntil(t, meshViewID1, time.Now().Add(time.Hour)),
	}}
	startCell(t, h.dialerWith(src), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	findLog(t, h.hubLog, "tunnel_replaced", map[string]any{"cell": "dev-cell-1"}, 5*time.Second)
	if n := countLog(t, h.hubLog, "tunnel_expired"); n != 0 {
		t.Fatalf("%d tunnel_expired lines: the old tunnel ran into its expiry, so the cell did not renew early:\n%s", n, h.hubLog.String())
	}
	if code, body := h.get(t, "/api/v1/pods"); code != http.StatusOK {
		t.Fatalf("after the new SVID: status %d, body %s", code, body)
	}
}

// A hub that never closes cannot keep the access past its own SVID: the cell ends the tunnel at the
// earlier expiry of the two leaves.
func TestCellEndsTunnelAtHubSVIDExpiry(t *testing.T) {
	h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 5 * time.Second, hubLeafLife: 3 * time.Second})
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	findLog(t, h.cellLog, "tunnel_expired", map[string]any{"side": "cell"}, 6*time.Second)
	findLog(t, h.hubLog, "tunnel_down", map[string]any{"cell": "dev-cell-1", "conn_id": 1}, 3*time.Second)
}

// The cell ends the tunnel at the expiry of its own leaf, also when the hub keeps the tunnel open. The hub closes a tunnel at
// the expiry of the cell leaf too, at the same instant, so the test runs the cell against keepOpenHub, which never closes one.
func TestCellEndsTunnelAtOwnSVIDExpiry(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	svid := h.env.svidUntil(t, meshViewID1, time.Now().Add(4*time.Second))
	notAfter := svid.Certificates[0].NotAfter
	hub := newKeepOpenHub(t, h)
	src := &rotatingSource{svids: []*x509svid.SVID{svid}}
	startCell(t, TunnelDialer(hub.addr, ClientTLS(src, h.mgmt.bundle(), spiffeIDOf(kialiID)), jsonLog(h.cellLog)), h.cellHandler(t))
	findLog(t, h.cellLog, "tunnel_connected", nil, 5*time.Second)
	findLog(t, h.cellLog, "tunnel_expired", map[string]any{"side": "cell"}, time.Until(notAfter)+3*time.Second)
	// Each tunnel, the renewals too, has the same leaf, so the cell ends each one at notAfter: not before it, and within 1 s after it.
	deadline := time.Now().Add(3 * time.Second)
	for {
		accepted, ends := hub.result()
		if accepted > 0 && len(ends) == accepted {
			for _, end := range ends {
				if end.Before(notAfter) || !end.Before(notAfter.Add(time.Second)) {
					t.Errorf("the cell ended a tunnel at %s, and its leaf expires at %s", end.Format(time.RFC3339Nano), notAfter.Format(time.RFC3339Nano))
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the cell ended %d of the %d tunnels that the hub accepted:\n%s", len(ends), accepted, h.cellLog.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// keepOpenHub stands in for a hub that never closes a tunnel. It accepts a tunnel with the TLS of the hub and starts HTTP/2 on
// it, as the hub does, and it records when the cell ends each tunnel.
type keepOpenHub struct {
	addr     string
	mu       sync.Mutex
	accepted int
	ends     []time.Time
	conns    []net.Conn
}

func newKeepOpenHub(t *testing.T, h *tunnelHarness) *keepOpenHub {
	t.Helper()
	cfg := ServerTLS(source(h.mgmt.svid(t, kialiID)), h.env.bundle(), regexp.MustCompile(meshPattern), testRegistry(t), jsonLog(h.hubLog))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	k := &keepOpenHub{addr: ln.Addr().String()}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); k.serve(c.(*tls.Conn)) }()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		k.mu.Lock()
		for _, c := range k.conns {
			_ = c.Close()
		}
		k.mu.Unlock()
		wg.Wait()
	})
	return k
}

func (k *keepOpenHub) serve(c *tls.Conn) {
	k.mu.Lock()
	k.conns = append(k.conns, c)
	k.mu.Unlock()
	if err := c.Handshake(); err != nil {
		_ = c.Close()
		return
	}
	ended := make(chan struct{})
	cc, err := (&http2.Transport{}).NewClientConn(&endConn{Conn: c, ended: ended})
	if err != nil {
		_ = c.Close()
		return
	}
	k.mu.Lock()
	k.accepted++
	k.mu.Unlock()
	<-ended
	k.mu.Lock()
	k.ends = append(k.ends, time.Now())
	k.mu.Unlock()
	_ = cc.Close()
}

func (k *keepOpenHub) result() (int, []time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.accepted, slices.Clone(k.ends)
}

// endConn closes ended at the first read error, which is the end of the tunnel by the cell.
type endConn struct {
	net.Conn
	ended chan struct{}
	once  sync.Once
}

func (c *endConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.once.Do(func() { close(c.ended) })
	}
	return n, err
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

// The errors that every ended tunnel makes in the reverse proxy go to Debug. Any other error of the proxy
// goes to Warn, so a real failure still shows at the level that an operator reads.
func TestProxyErrorLogLevels(t *testing.T) {
	out := &syncBuffer{}
	log := proxyErrorLog(slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.Print("httputil: ReverseProxy read error during body copy: http2: client connection force closed via ClientConn.Close")
	log.Print("http: proxy error: use of closed network connection")
	log.Print("http: proxy error: tls: bad record MAC")
	levels := map[string]string{}
	for _, l := range logLines(t, out) {
		levels[fmt.Sprint(l["msg"])] = fmt.Sprint(l["level"])
	}
	if len(levels) != 3 {
		t.Fatalf("lines %v", levels)
	}
	for msg, level := range levels {
		want := "DEBUG"
		if strings.Contains(msg, "bad record MAC") {
			want = "WARN"
		}
		if level != want {
			t.Errorf("%q logged at %s, want %s", msg, level, want)
		}
	}
}

func waitStatus(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s", within, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The hub serves the state of each tunnel from its own connections. A cell with a newer tunnel reads as
// up when the hub closes the older one for it, and the end of the older tunnel reads as replaced.
func TestHubStatusFollowsTheTunnels(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	if st := h.hub.Status(); st.Up || st.Cells["dev-cell-1"].Up {
		t.Fatalf("status %+v before any tunnel, want down", st)
	}
	src := &rotatingSource{svids: []*x509svid.SVID{
		h.env.svidUntil(t, meshViewID1, time.Now().Add(5*time.Second)),
		h.env.svidUntil(t, meshViewID1, time.Now().Add(time.Hour)),
	}}
	stop := startCell(t, h.dialerWith(src), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	waitStatus(t, "the status of the first tunnel", 5*time.Second, func() bool { return h.hub.Status().Up })
	findLog(t, h.hubLog, "tunnel_replaced", map[string]any{"cell": "dev-cell-1"}, 5*time.Second)
	// While the older tunnel ends for the newer one, the cell never reads as down.
	for range 50 {
		if st := h.hub.Status(); !st.Up || !st.Cells["dev-cell-1"].Up {
			t.Fatalf("status %+v during the replacement, want up", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitStatus(t, "the end of the older tunnel", 5*time.Second, func() bool {
		e := h.hub.Status().Cells["dev-cell-1"].LastEnd
		return e != nil && e.Cause == "replaced"
	})
	stop()
	waitStatus(t, "the status down after the cell stops", 5*time.Second, func() bool {
		c := h.hub.Status().Cells["dev-cell-1"]
		return !c.Up && c.LastEnd != nil && c.LastEnd.Cause == "peer_closed"
	})
}

// A tunnel that a hub never closes ends at the SVID expiry of the hub, and each side names that cause.
func TestTunnelStatusNamesTheCause(t *testing.T) {
	h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 5 * time.Second, hubLeafLife: 4 * time.Second})
	st := NewTunnelState()
	dial := TunnelDialer(h.server, ClientTLS(source(h.env.svid(t, meshViewID1)), h.mgmt.bundle(), spiffeIDOf(kialiID)), jsonLog(h.cellLog), WithState(st))
	startCell(t, dial, h.cellHandler(t))
	waitStatus(t, "the cell state up", 5*time.Second, func() bool { return st.Status().Up })
	waitStatus(t, "the cell state down at the hub expiry", 6*time.Second, func() bool {
		c := st.Status().Cells["self"]
		return c.LastEnd != nil && c.LastEnd.Cause == "expiry"
	})
	findLog(t, h.hubLog, "tunnel_down", map[string]any{"cell": "dev-cell-1", "cause": "peer_closed"}, 3*time.Second)
}

// The cell finds a dead path with its own pings. With the path blackholed after the tunnel is up, the cell closes the
// tunnel after the idle time and the ping timeout, and its state names the cause local_close. A cell with no pings
// (ReadIdleTimeout 0 in newTunnelServer) never closes it, so this test fails for that mutation.
func TestCellPingsFindABlackholedTunnel(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	state := NewTunnelState()
	inner := TunnelDialer(h.server, ClientTLS(source(h.env.svid(t, meshViewID1)), h.mgmt.bundle(), spiffeIDOf(kialiID)), jsonLog(h.cellLog), WithState(state))
	var hole atomic.Pointer[bhConn]
	dial := func(ctx context.Context) (net.Conn, error) {
		c, err := inner(ctx)
		if err != nil {
			return nil, err
		}
		b := newBHConn(c)
		hole.Store(b)
		return b, nil
	}
	startCell(t, dial, h.cellHandler(t), WithKeepalive(300*time.Millisecond, 300*time.Millisecond))
	waitStatus(t, "the cell state up", 5*time.Second, func() bool { return state.Status().Up })
	hole.Load().on.Store(true)
	waitStatus(t, "the cell to close the blackholed tunnel by its pings", 3*time.Second, func() bool {
		e := state.Status().Cells["self"].LastEnd
		return e != nil && e.Cause == "local_close"
	})
	findLog(t, h.cellLog, "tunnel_closed", map[string]any{"closed_by": "cell"}, time.Second)
}

// The hub finds a dead path with its own pings. With the connection of the hub blackholed after the tunnel is up, the hub
// closes the tunnel after the idle time and the ping timeout, and logs the cause local_close. A hub with no pings
// (ReadIdleTimeout 0 on its transport) never closes it, so this test fails for that mutation.
func TestHubPingsFindABlackholedTunnel(t *testing.T) {
	hs := &holes{}
	h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 5 * time.Second, readIdle: 300 * time.Millisecond, pingTimeout: 300 * time.Millisecond, holes: hs})
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	hs.blackhole()
	findLog(t, h.hubLog, "tunnel_down", map[string]any{"cell": "dev-cell-1", "cause": "local_close"}, 3*time.Second)
}

// A renewal drains the older tunnel: a watch in flight on it goes on, and ends only when the API ends it. The cell never
// reads as down while it happens.
func TestRenewalKeepsAWatchInFlight(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	src := &rotatingSource{svids: []*x509svid.SVID{
		h.env.svidUntil(t, meshViewID1, time.Now().Add(8*time.Second)),
		h.env.svidUntil(t, meshViewID1, time.Now().Add(time.Hour)),
	}}
	startCell(t, h.dialerWith(src), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	resp, err := http.Get(h.hubURL + "/api/v1/pods?watch=true")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	findLog(t, h.hubLog, "tunnel_replaced", map[string]any{"cell": "dev-cell-1"}, 6*time.Second)
	// The older tunnel has its leaf for a few more seconds. The watch ends by itself, before that.
	time.Sleep(500 * time.Millisecond)
	h.api.releaseWatches()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("the watch was cut by the renewal: %v (read %q)", err, body)
	}
	if n := strings.Count(string(body), `"ADDED"`); n != 3 {
		t.Fatalf("the watch delivered %d events, want 3: %q", n, body)
	}
}

// The end of a tunnel that the cell replaced is planned: it logs at info with closed_by renewal.
func TestRenewalLogsAtInfo(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	src := &rotatingSource{svids: []*x509svid.SVID{
		h.env.svidUntil(t, meshViewID1, time.Now().Add(5*time.Second)),
		h.env.svidUntil(t, meshViewID1, time.Now().Add(time.Hour)),
	}}
	startCell(t, h.dialerWith(src), h.cellHandler(t))
	line := findLog(t, h.cellLog, "tunnel_closed", map[string]any{"closed_by": "renewal"}, 8*time.Second)
	if line["level"] != "INFO" {
		t.Fatalf("a renewal logged at %v, want INFO", line["level"])
	}
}
