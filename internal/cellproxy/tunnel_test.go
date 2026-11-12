package cellproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"k8s.io/client-go/rest"
)

const (
	kialiID     = "spiffe://mgmt.poc.internal/kiali"
	meshViewID1 = "spiffe://dev.env.poc.internal/cell/dev-cell-1/mesh-view"
	meshPattern = `^spiffe://dev\.env\.poc\.internal/cell/[a-z0-9-]+/mesh-view$`
	podToken    = "pod-token"
)

var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// fakeAPI is a Kubernetes API server stand-in. It counts every request, records the last one, and
// answers a watch with three events, one chunk each, then holds the stream open until release.
type fakeAPI struct {
	srv      *httptest.Server
	hits     atomic.Int64
	mu       sync.Mutex
	header   http.Header
	reqURL   *url.URL
	body     []byte
	release  chan struct{}
	once     sync.Once
	canceled chan struct{}
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	a := &fakeAPI{release: make(chan struct{}), canceled: make(chan struct{}, 16)}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(a.serve))
	t.Cleanup(func() {
		a.releaseWatches()
		a.srv.Close()
	})
	return a
}

func (a *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	a.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.header, a.reqURL, a.body = r.Header.Clone(), r.URL, body
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("watch") == "true" {
		flusher := w.(http.Flusher)
		for i := 1; i <= 3; i++ {
			_, _ = fmt.Fprintf(w, `{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"p%d"}}}`+"\n", i)
			flusher.Flush()
		}
		select {
		case <-a.release:
		case <-r.Context().Done():
			a.canceled <- struct{}{}
		case <-time.After(10 * time.Second):
		}
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"kind": "PodList", "path": r.URL.Path})
}

func (a *fakeAPI) releaseWatches() { a.once.Do(func() { close(a.release) }) }

func (a *fakeAPI) last() (http.Header, *url.URL, []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.header, a.reqURL, a.body
}

func (a *fakeAPI) url() *url.URL {
	u, _ := url.Parse(a.srv.URL)
	return u
}

// transport is what rest.InClusterConfig and rest.TransportFor give in a pod: the pod token on
// every request that has no Authorization header.
func (a *fakeAPI) transport(t *testing.T) http.RoundTripper {
	t.Helper()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.srv.Certificate().Raw})
	rt, err := rest.TransportFor(&rest.Config{Host: a.srv.URL, BearerToken: podToken, TLSClientConfig: rest.TLSClientConfig{CAData: ca}})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// serveCell sends one request straight to a cell handler.
func serveCell(t *testing.T, h http.Handler, method, target string, body []byte, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// assertRefusal checks the status and the body {"error":<word>,"request_id":<16 hex digits>}.
func assertRefusal(t *testing.T, code int, body []byte, wantCode int, word string) {
	t.Helper()
	if code != wantCode {
		t.Fatalf("status %d, want %d; body %s", code, wantCode, body)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body %q is not JSON: %v", body, err)
	}
	id, _ := m["request_id"].(string)
	if len(m) != 2 || m["error"] != word || !requestIDPattern.MatchString(id) {
		t.Fatalf("body is %s, want only error %q and a request ID", body, word)
	}
}

func assertDenied(t *testing.T, code int, body []byte) {
	t.Helper()
	assertRefusal(t, code, body, http.StatusForbidden, "denied")
}

// trackListener records each accepted connection, so a test can drop them.
type trackListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *trackListener) dropAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = nil
}

// tunnelHarness runs the fake API, spiffe-server with the tunnel backend, and a local listener for
// the hub handler of each cell (dev-cell-1 by default).
type tunnelHarness struct {
	api      *fakeAPI
	hub      *TunnelHub
	hubURL   string
	hubURLs  map[string]string
	server   string
	hubLog   *syncBuffer
	cellLog  *syncBuffer
	mgmt     *testCA
	env      *testCA
	accepted *trackListener
	metrics  *TunnelMetrics
	// stopServer cancels the accept loop, and serverDone closes when it returns.
	stopServer context.CancelFunc
	serverDone chan struct{}
}

// tunnelHarnessConfig changes the defaults of the harness: the cells dev-cell-1, the allow
// pattern meshPattern, and testRegistry (dev-cell-2 revoked).
type tunnelHarnessConfig struct {
	wait     time.Duration
	cells    []string
	allow    string
	registry *Registry
	metrics  *TunnelMetrics
	// maxStreams is the stream cap of the hub. Zero means the default.
	maxStreams int
	// hubLeafLife is the lifetime of the SVID of the hub. Zero means a long one.
	hubLeafLife time.Duration
}

func newTunnelHarness(t *testing.T, wait time.Duration) *tunnelHarness {
	t.Helper()
	return newTunnelHarnessWith(t, tunnelHarnessConfig{wait: wait})
}

func newTunnelHarnessWith(t *testing.T, cfg tunnelHarnessConfig) *tunnelHarness {
	t.Helper()
	if cfg.cells == nil {
		cfg.cells = []string{"dev-cell-1"}
	}
	if cfg.allow == "" {
		cfg.allow = meshPattern
	}
	if cfg.registry == nil {
		cfg.registry = testRegistry(t)
	}
	h := &tunnelHarness{api: newFakeAPI(t), hubLog: &syncBuffer{}, cellLog: &syncBuffer{}, mgmt: newCA(t, mgmtTD), env: newCA(t, envTD), hubURLs: map[string]string{}, metrics: cfg.metrics}
	log := jsonLog(h.hubLog)
	cells := map[string]string{}
	for _, c := range cfg.cells {
		cells[c] = "127.0.0.1:0"
	}
	h.hub = NewTunnelHub(cells, cfg.wait, log, WithMetrics(cfg.metrics), WithMaxStreams(cfg.maxStreams))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.accepted = &trackListener{Listener: ln}
	h.server = ln.Addr().String()
	hubSVID := h.mgmt.svid(t, kialiID)
	if cfg.hubLeafLife > 0 {
		hubSVID = h.mgmt.svidUntil(t, kialiID, time.Now().Add(cfg.hubLeafLife))
	}
	srv := NewServer(ServerConfig{
		TLS: ServerTLS(source(hubSVID), h.env.bundle(), regexp.MustCompile(cfg.allow), cfg.registry, log),
	}, NewTunnelBackend(h.hub), log)
	ctx, cancel := context.WithCancel(context.Background())
	h.stopServer, h.serverDone = cancel, make(chan struct{})
	go func() { _ = srv.Serve(ctx, h.accepted); close(h.serverDone) }()
	var hubSrvs []*httptest.Server
	for _, c := range cfg.cells {
		srv := httptest.NewServer(h.hub.Handler(c))
		hubSrvs = append(hubSrvs, srv)
		h.hubURLs[c] = srv.URL
	}
	h.hubURL = h.hubURLs["dev-cell-1"]
	t.Cleanup(func() {
		h.api.releaseWatches()
		cancel()
		<-h.serverDone
		for _, srv := range hubSrvs {
			srv.Close()
		}
	})
	return h
}

func (h *tunnelHarness) dialer(t *testing.T) func(context.Context) (net.Conn, error) {
	t.Helper()
	return h.dialerFor(t, meshViewID1)
}

// dialerFor dials the hub with an SVID for id from the environment CA.
func (h *tunnelHarness) dialerFor(t *testing.T, id string) func(context.Context) (net.Conn, error) {
	t.Helper()
	return h.dialerWith(source(h.env.svid(t, id)))
}

func (h *tunnelHarness) dialerWith(svids x509svid.Source) func(context.Context) (net.Conn, error) {
	return TunnelDialer(h.server, ClientTLS(svids, h.mgmt.bundle(), spiffeIDOf(kialiID)), jsonLog(h.cellLog), WithMetrics(h.metrics))
}

func (h *tunnelHarness) cellHandler(t *testing.T) http.Handler {
	t.Helper()
	return NewCellHandler(h.api.url(), h.api.transport(t), jsonLog(h.cellLog), WithMetrics(h.metrics))
}

// startCell runs the cell side with dial and handler until the test ends or stop is called.
func startCell(t *testing.T, dial func(context.Context) (net.Conn, error), handler http.Handler) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = RunTunnel(ctx, dial, handler); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("RunTunnel did not stop within 10 seconds of the cancel")
		}
	})
	return func() { cancel(); <-done }
}

// waitTunnels waits until the hub has logged n tunnel_up lines for dev-cell-1, within d.
func (h *tunnelHarness) waitTunnels(t *testing.T, n int, d time.Duration) {
	t.Helper()
	h.waitTunnelsFor(t, "dev-cell-1", n, d)
}

func (h *tunnelHarness) waitTunnelsFor(t *testing.T, cell string, n int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		count := 0
		for _, l := range logLines(t, h.hubLog) {
			if l["msg"] == "tunnel_up" && l["cell"] == cell {
				count++
			}
		}
		if count >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d tunnel_up lines after %s, want %d:\nhub:\n%s\ncell:\n%s", count, d, n, h.hubLog.String(), h.cellLog.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (h *tunnelHarness) get(t *testing.T, target string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(h.hubURL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func TestCellHandlerStripsHeaders(t *testing.T) {
	api := newFakeAPI(t)
	h := NewCellHandler(api.url(), api.transport(t), jsonLog(&syncBuffer{}))
	header := http.Header{
		"Authorization":         {"Bearer x"},
		"Impersonate-User":      {"admin"},
		"Impersonate-Group":     {"system:masters"},
		"Impersonate-Uid":       {"0"},
		"Impersonate-Extra-Foo": {"bar"},
		// With Connection: Upgrade, the reverse proxy keeps Upgrade unless the handler deletes it.
		"Connection":        {"Upgrade"},
		"Upgrade":           {"SPDY/3.1"},
		"X-Forwarded-For":   {"1.2.3.4"},
		"X-Forwarded-Port":  {"443"},
		"X-Forwarded-Proto": {"https"},
		"X-Real-Ip":         {"1.2.3.4"},
		"Forwarded":         {"for=1.2.3.4"},
		// The API server takes a client Audit-ID as the ID of its audit event.
		"Audit-Id":               {"forged-audit"},
		"X-Http-Method-Override": {"DELETE"},
		"X-Remote-User":          {"system:admin"},
		"X-Remote-Group":         {"system:masters"},
		"Cookie":                 {"session=x"},
		"Accept":                 {"application/json;as=Table;v=v1;g=meta.k8s.io"},
		"User-Agent":             {"kiali/v2.34.0"},
	}
	rec := serveCell(t, h, http.MethodGet, "/api/v1/namespaces/apps-demo/pods?labelSelector=app%3Dweb", nil, header)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	got, u, _ := api.last()
	if v := got.Values("Authorization"); len(v) != 1 || v[0] != "Bearer "+podToken {
		t.Fatalf("the API got Authorization %v, want only the pod token", v)
	}
	// Accept-Encoding comes from the transport of the pod.
	allowed := map[string]bool{"Authorization": true, "Accept": true, "Accept-Encoding": true, "User-Agent": true}
	for k := range got {
		if !allowed[k] {
			t.Errorf("the API got %s: %v", k, got[k])
		}
	}
	if got.Get("Accept") != header.Get("Accept") || got.Get("User-Agent") != header.Get("User-Agent") {
		t.Errorf("the API got Accept %q and User-Agent %q", got.Get("Accept"), got.Get("User-Agent"))
	}
	if u.Path != "/api/v1/namespaces/apps-demo/pods" || u.RawQuery != "labelSelector=app%3Dweb" {
		t.Fatalf("the API got %s?%s", u.Path, u.RawQuery)
	}
}

func TestCellHandlerDropsGetBody(t *testing.T) {
	api := newFakeAPI(t)
	h := NewCellHandler(api.url(), api.transport(t), jsonLog(&syncBuffer{}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/apps-demo/pods", strings.NewReader(`{"kind":"DeleteOptions"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	if _, _, body := api.last(); len(body) != 0 {
		t.Fatalf("the API got a GET body %q", body)
	}
}

// TestCellHandlerNormalisesQuery checks that the API gets the query that the allow-list parsed,
// encoded again, and not the bytes that the client sent.
func TestCellHandlerNormalisesQuery(t *testing.T) {
	api := newFakeAPI(t)
	h := NewCellHandler(api.url(), api.transport(t), jsonLog(&syncBuffer{}))
	cases := map[string]string{
		"limit=1&":                       "limit=1",
		"%6Cimit=1":                      "limit=1",
		"&&limit=1":                      "limit=1",
		"labelSelector=a%26b":            "labelSelector=a%26b",
		"limit=5&labelSelector=app%3Dx&": "labelSelector=app%3Dx&limit=5",
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			rec := serveCell(t, h, http.MethodGet, "/api/v1/pods?"+raw, nil, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			if _, u, _ := api.last(); u.RawQuery != want {
				t.Fatalf("the API got query %q, want %q", u.RawQuery, want)
			}
		})
	}
}

// The informer of Kiali lists and watches the ConfigMaps of every namespace. The API must get the
// request for istio-system only, with the query kept.
func TestCellHandlerLimitsConfigMapsToIstioSystem(t *testing.T) {
	api := newFakeAPI(t)
	h := NewCellHandler(api.url(), api.transport(t), jsonLog(&syncBuffer{}))
	for raw, want := range map[string]string{
		"/api/v1/configmaps?limit=500":                    "limit=500",
		"/api/v1/configmaps?watch=true&resourceVersion=7": "resourceVersion=7&watch=true",
	} {
		t.Run(raw, func(t *testing.T) {
			rec := serveCell(t, h, http.MethodGet, raw, nil, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			_, u, _ := api.last()
			if u.Path != "/api/v1/namespaces/istio-system/configmaps" || u.RawQuery != want {
				t.Fatalf("the API got %s?%s, want /api/v1/namespaces/istio-system/configmaps?%s", u.Path, u.RawQuery, want)
			}
		})
	}
	// A path for another namespace is still refused, and a request for it never reaches the API.
	hits := api.hits.Load()
	rec := serveCell(t, h, http.MethodGet, "/api/v1/namespaces/argocd/configmaps", nil, nil)
	if rec.Code != http.StatusForbidden || api.hits.Load() != hits {
		t.Fatalf("a read of ConfigMaps in argocd got %d and %d new API hits", rec.Code, api.hits.Load()-hits)
	}
}

func TestCellHandlerForwardsReview(t *testing.T) {
	api := newFakeAPI(t)
	h := NewCellHandler(api.url(), api.transport(t), jsonLog(&syncBuffer{}))
	review := []byte(`{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"list","resource":"pods"}}}`)
	full := append(review, bytes.Repeat([]byte(" "), 64<<10-len(review))...)
	for name, body := range map[string][]byte{"small": review, "64 KiB": full} {
		t.Run(name, func(t *testing.T) {
			rec := serveCell(t, h, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", body, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			if _, _, got := api.last(); !bytes.Equal(got, body) {
				t.Fatalf("the API got a body of %d bytes, want %d", len(got), len(body))
			}
		})
	}
}

func TestCellHandlerLogsRefusal(t *testing.T) {
	api := newFakeAPI(t)
	out := &syncBuffer{}
	h := NewCellHandler(api.url(), api.transport(t), jsonLog(out))
	rec := serveCell(t, h, http.MethodGet, "/api/v1/nodes", nil, nil)
	assertDenied(t, rec.Code, rec.Body.Bytes())
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	line := waitForLog(t, out, "request denied", RequestNotAllowed, "")
	if line["request_id"] != body["request_id"] || line["path"] != "/api/v1/nodes" {
		t.Fatalf("log line %v does not match body %v", line, body)
	}
}

func TestTunnelRoundTripAndWatch(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)

	t.Run("list", func(t *testing.T) {
		code, body := h.get(t, "/api/v1/namespaces/apps-demo/pods")
		if code != http.StatusOK || !strings.Contains(string(body), `"path":"/api/v1/namespaces/apps-demo/pods"`) {
			t.Fatalf("status %d, body %s", code, body)
		}
		if got, _, _ := h.api.last(); got.Get("Authorization") != "Bearer "+podToken {
			t.Fatalf("the API got Authorization %q", got.Get("Authorization"))
		}
	})
	t.Run("watch", func(t *testing.T) {
		resp, err := http.Get(h.hubURL + "/api/v1/pods?watch=true")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		lines := make(chan string)
		go func() {
			s := bufio.NewScanner(resp.Body)
			for s.Scan() {
				lines <- s.Text()
			}
			close(lines)
		}()
		for i := 1; i <= 3; i++ {
			select {
			case l, ok := <-lines:
				if !ok || !strings.Contains(l, fmt.Sprintf(`"name":"p%d"`, i)) {
					t.Fatalf("event %d is %q (open %v)", i, l, ok)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("event %d did not arrive while the stream was open", i)
			}
		}
		h.api.releaseWatches()
		select {
		case l, ok := <-lines:
			if ok {
				t.Fatalf("extra line %q", l)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the stream did not end after the API ended it")
		}
	})
}

func TestTunnelDenialBody(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	code, body := h.get(t, "/api/v1/namespaces/argocd/configmaps")
	assertDenied(t, code, body)
	if strings.Contains(string(body), "Status") {
		t.Fatalf("body %s looks like a Kubernetes Status", body)
	}
	if n := h.api.hits.Load(); n != 0 {
		t.Fatalf("the API got %d requests", n)
	}
}

func TestTunnelReconnects(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	if code, body := h.get(t, "/api/v1/pods"); code != http.StatusOK {
		t.Fatalf("status %d, body %s", code, body)
	}
	h.accepted.dropAll()
	h.waitTunnels(t, 2, 3*time.Second)
	if code, body := h.get(t, "/api/v1/pods"); code != http.StatusOK {
		t.Fatalf("after the reconnect: status %d, body %s", code, body)
	}
}

// fakeClock moves only when the tunnel sleeps or a connection lives.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	c.sleeps = append(c.sleeps, d)
	return nil
}

// lifeConn is a tunnel connection that lives for life on the fake clock, then ends.
type lifeConn struct {
	net.Conn
	clock *fakeClock
	life  time.Duration
	// expiry is the SVID expiry that the connection reports. Zero means it reports none.
	expiry time.Time
	once   sync.Once
}

func (c *lifeConn) Expiry() time.Time { return c.expiry }

func (c *lifeConn) Read([]byte) (int, error) {
	c.once.Do(func() { c.clock.advance(c.life) })
	return 0, io.EOF
}

func (c *lifeConn) Write(p []byte) (int, error) { return len(p), nil }

func TestTunnelBackoffResets(t *testing.T) {
	run := func(t *testing.T, life time.Duration, svidLife ...time.Duration) []time.Duration {
		t.Helper()
		clock := &fakeClock{t: time.Unix(0, 0)}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		// Five failed dials, then one connection, then the test stops the loop.
		step := 0
		dial := func(context.Context) (net.Conn, error) {
			step++
			switch {
			case step <= 5:
				return nil, errors.New("refused")
			case step == 6:
				a, b := net.Pipe()
				t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
				lc := &lifeConn{Conn: a, clock: clock, life: life}
				if len(svidLife) > 0 {
					lc.expiry = clock.now().Add(svidLife[0])
				}
				return lc, nil
			}
			cancel()
			return nil, errors.New("stopped")
		}
		done := make(chan error, 1)
		go func() {
			done <- runTunnel(ctx, dial, http.NotFoundHandler(), tunnelClock{now: clock.now, sleep: clock.sleep})
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the tunnel loop did not stop")
		}
		clock.mu.Lock()
		defer clock.mu.Unlock()
		if len(clock.sleeps) != 6 {
			t.Fatalf("sleeps %v, want 6", clock.sleeps)
		}
		for i, base := range []time.Duration{1, 2, 4, 8, 16} {
			base *= time.Second
			if d := clock.sleeps[i]; d < base || d > base+base/2 {
				t.Fatalf("sleep %d is %s, want %s plus at most half of it", i+1, d, base)
			}
		}
		return clock.sleeps
	}
	// A tunnel that ends with the SVID of the cell lives a little less than the SVID lifetime of 1 minute,
	// and the cell must dial again within seconds, not after the 30-second cap.
	t.Run("after 30 seconds", func(t *testing.T) {
		sleeps := run(t, 30*time.Second)
		if d := sleeps[5]; d < time.Second || d > 1500*time.Millisecond {
			t.Fatalf("sleep after a 30-second connection is %s, want 1 second plus jitter", d)
		}
	})
	// With an SVID of 20 seconds, a tunnel that lived 10 seconds, half of that life, is stable.
	t.Run("half of a short SVID life", func(t *testing.T) {
		sleeps := run(t, 10*time.Second, 20*time.Second)
		if d := sleeps[5]; d < time.Second || d > 1500*time.Millisecond {
			t.Fatalf("sleep after a tunnel that lived half of its SVID life is %s, want 1 second plus jitter", d)
		}
	})
	t.Run("after 29 seconds", func(t *testing.T) {
		sleeps := run(t, 29*time.Second)
		if d := sleeps[5]; d != 30*time.Second {
			t.Fatalf("sleep after a 29-second connection is %s, want the 30-second cap", d)
		}
	})
}

func TestTunnelCancelPropagates(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	startCell(t, h.dialer(t), h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	client := &http.Client{Transport: &http.Transport{}}
	defer client.CloseIdleConnections()
	if code, body := h.get(t, "/api/v1/pods"); code != http.StatusOK {
		t.Fatalf("status %d, body %s", code, body)
	}
	http.DefaultClient.CloseIdleConnections()
	start := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(t.Context())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.hubURL+"/api/v1/pods?watch=true", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = resp.Body.Close()
	select {
	case <-h.api.canceled:
	case <-time.After(time.Second):
		t.Fatal("the API request did not end within 1 second of the cancel")
	}
	client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > start {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines, want at most %d", runtime.NumGoroutine(), start)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHubWaitsThenUnavailable(t *testing.T) {
	const wait = time.Second
	h := newTunnelHarness(t, wait)
	t.Run("no tunnel", func(t *testing.T) {
		start := time.Now()
		code, body := h.get(t, "/api/v1/pods")
		if elapsed := time.Since(start); elapsed < wait {
			t.Fatalf("answer after %s, want at least %s", elapsed, wait)
		}
		assertRefusal(t, code, body, http.StatusServiceUnavailable, string(UpstreamUnavailable))
		waitForLog(t, h.hubLog, "request denied", UpstreamUnavailable, "")
	})
	t.Run("tunnel during the wait", func(t *testing.T) {
		dial, handler := h.dialer(t), h.cellHandler(t)
		go func() {
			time.Sleep(100 * time.Millisecond)
			startCell(t, dial, handler)
		}()
		if code, body := h.get(t, "/api/v1/pods"); code != http.StatusOK {
			t.Fatalf("status %d, body %s", code, body)
		}
	})
}

func TestHubNewestConnWins(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	ctx := t.Context()
	open := func(name string) chan struct{} {
		conn, err := h.dialer(t)(ctx)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, name) })
		go func() { serveTunnel(ctx, newTunnelServer(), conn, handler); close(done) }()
		t.Cleanup(func() { _ = conn.Close(); <-done })
		return done
	}
	first := open("first")
	h.waitTunnels(t, 1, 5*time.Second)
	if _, body := h.get(t, "/"); string(body) != "first" {
		t.Fatalf("body %q, want first", body)
	}
	open("second")
	h.waitTunnels(t, 2, 5*time.Second)
	if _, body := h.get(t, "/"); string(body) != "second" {
		t.Fatalf("body %q, want second", body)
	}
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the hub did not close the older connection")
	}
}

func TestTunnelRefusesWrongServer(t *testing.T) {
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	const telemetryID = "spiffe://mgmt.poc.internal/telemetry"
	addr := serveTLS(t, mgmt.svid(t, telemetryID))
	out := &syncBuffer{}
	dial := TunnelDialer(addr, ClientTLS(source(env.svid(t, meshViewID1)), mgmt.bundle(), spiffeIDOf(kialiID)), jsonLog(out))
	conn, err := dial(t.Context())
	if err == nil {
		_ = conn.Close()
		t.Fatal("the dial to a server with the telemetry ID succeeded")
	}
	if r := ReasonOf(err); r != PeerNotAllowed {
		t.Fatalf("reason %q, want %q (error %v)", r, PeerNotAllowed, err)
	}
	waitForLog(t, out, "peer refused", PeerNotAllowed, telemetryID)
}

func tlsServerConn(c net.Conn) *tls.Conn { return tls.Server(c, &tls.Config{}) }

// tunnelThroughSpiffeClient runs the cell side over a plaintext dial to spiffe-client, which
// pipes it to spiffe-server with the tunnel backend.
func tunnelThroughSpiffeClient(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cli := &Client{TLS: ClientTLS(source(h.env.svid(t, meshViewID1)), h.mgmt.bundle(), spiffeIDOf(kialiID)), Upstream: h.server, Log: jsonLog(h.cellLog)}
	done := make(chan struct{})
	go func() { _ = cli.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
	startCell(t, dial, h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	if code, body := h.get(t, "/api/v1/pods"); code != http.StatusOK {
		t.Fatalf("status %d, body %s", code, body)
	}
	if n := h.api.hits.Load(); n != 1 {
		t.Fatalf("API hits %d, want 1", n)
	}
}
