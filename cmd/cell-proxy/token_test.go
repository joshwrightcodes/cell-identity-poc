package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
)

const (
	tokenReader = "system:serviceaccount:argocd:argocd-repo-server"
	tokenWriter = "system:serviceaccount:cell-identity-system:celld"
)

type tableReviewer map[string]cellproxy.TokenReview

func (r tableReviewer) Review(_ context.Context, token, audience string) (cellproxy.TokenReview, error) {
	if v, ok := r[token]; ok {
		return v, nil
	}
	return cellproxy.TokenReview{}, nil
}

func useReviewer(t *testing.T, r cellproxy.TokenReviewer) {
	t.Helper()
	prev := newTokenReviewer
	newTokenReviewer = func() (cellproxy.TokenReviewer, error) { return r, nil }
	t.Cleanup(func() { newTokenReviewer = prev })
}

func tokenArgs() []string {
	return []string{"token", "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:5001", "--audience", "bundle-store",
		"--reader", tokenReader, "--writer", tokenWriter, "--health", "127.0.0.1:0"}
}

func TestTokenFlags(t *testing.T) {
	cfg, err := parseToken(tokenArgs()[1:])
	if err != nil || !slices.Equal(cfg.readers, []string{tokenReader}) || !slices.Equal(cfg.writers, []string{tokenWriter}) {
		t.Fatalf("got %+v, %v", cfg, err)
	}
	// --writer may repeat, and may be absent.
	two := append(tokenArgs(), "--writer", "system:serviceaccount:envd-system:envd")
	if cfg, err = parseToken(two[1:]); err != nil || len(cfg.writers) != 2 {
		t.Fatalf("got %+v, %v, want two writers", cfg, err)
	}
	if cfg, err = parseToken(without(tokenArgs(), "--writer")[1:]); err != nil || len(cfg.writers) != 0 {
		t.Fatalf("got %+v, %v, want no writer", cfg, err)
	}
	cases := map[string][]string{
		"no --listen":         without(tokenArgs(), "--listen"),
		"no --upstream":       without(tokenArgs(), "--upstream"),
		"no --audience":       without(tokenArgs(), "--audience"),
		"no --reader":         without(tokenArgs(), "--reader"),
		"upstream with URL":   with(tokenArgs(), "--upstream", "http://127.0.0.1:5001"),
		"empty writer":        with(tokenArgs(), "--writer", ""),
		"argument not a flag": append(slicesClone(tokenArgs()), "extra"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) { assertConfigError(t, a) })
	}
}

func TestTokenClientLoopbackOnly(t *testing.T) {
	args := []string{"token-client", "--listen", "127.0.0.1:0", "--upstream", "bundle-store.cell-system.svc.cluster.local:5000", "--token-file", "/x/token"}
	for _, listen := range []string{"127.0.0.1:5000", "[::1]:5000", "localhost:5000"} {
		if _, err := parseTokenClient(with(args, "--listen", listen)[1:]); err != nil {
			t.Errorf("--listen %s: %v", listen, err)
		}
	}
	for _, listen := range []string{"0.0.0.0:5000", ":5000", "[::]:5000", "10.0.0.5:5000", "example.com:5000", "127.0.0.1"} {
		t.Run(listen, func(t *testing.T) { assertConfigError(t, with(args, "--listen", listen)) })
	}
	cases := map[string][]string{
		"no --upstream":   without(args, "--upstream"),
		"no --token-file": without(args, "--token-file"),
		"upstream URL":    with(args, "--upstream", "http://store:5000"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) { assertConfigError(t, a) })
	}
}

func TestTokenModeServes(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "300")
	var mu sync.Mutex
	var hits []string
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Method+" "+r.URL.Path)
		mu.Unlock()
		_, _ = io.WriteString(w, "{}")
	}))
	defer reg.Close()
	useReviewer(t, tableReviewer{
		"r": {Authenticated: true, Username: tokenReader, Audiences: []string{"bundle-store"}},
		"w": {Authenticated: true, Username: tokenWriter, Audiences: []string{"bundle-store"}},
	})
	args := with(tokenArgs(), "--upstream", strings.TrimPrefix(reg.URL, "http://"))
	out := &syncBuffer{}
	stop := runUntilCanceled(t, args, out)
	health := waitLine(t, out, "health_listening")["addr"].(string)
	base := "http://" + waitLine(t, out, "listening")["addr"].(string)

	get := func(url, method, token string) int {
		req, _ := http.NewRequest(method, url, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if c := get("http://"+health+"/healthz", http.MethodGet, ""); c != http.StatusOK {
		t.Fatalf("health status %d", c)
	}
	path := base + "/v2/bundles/root/manifests/current"
	for _, c := range []struct {
		method, token string
		want          int
	}{
		{http.MethodGet, "r", 200}, {http.MethodGet, "w", 403}, {http.MethodPut, "r", 403},
		{http.MethodPut, "w", 200}, {http.MethodGet, "", 403}, {http.MethodGet, "bad", 403},
	} {
		if got := get(path, c.method, c.token); got != c.want {
			t.Errorf("%s with %q: status %d, want %d", c.method, c.token, got, c.want)
		}
	}
	stop()
	mu.Lock()
	defer mu.Unlock()
	// The first request is the registry check of /healthz.
	if !slices.Equal(hits, []string{"GET /v2/", "GET /v2/bundles/root/manifests/current", "PUT /v2/bundles/root/manifests/current"}) {
		t.Fatalf("upstream got %v", hits)
	}
	if strings.Contains(out.String(), "Bearer") {
		t.Fatalf("a log line holds an Authorization value:\n%s", out.String())
	}
}

func TestTokenClientServes(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "300")
	var mu sync.Mutex
	var auth []string
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer reg.Close()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("projected\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	stop := runUntilCanceled(t, []string{"token-client", "--listen", "127.0.0.1:0", "--upstream", strings.TrimPrefix(reg.URL, "http://"),
		"--token-file", file, "--health", "127.0.0.1:0"}, out)
	health := waitLine(t, out, "health_listening")["addr"].(string)
	base := "http://" + waitLine(t, out, "listening")["addr"].(string)
	for _, u := range []string{base + "/v2/", "http://" + health + "/healthz"} {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d", u, resp.StatusCode)
		}
	}
	stop()
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(auth, []string{"Bearer projected"}) {
		t.Fatalf("upstream got %v", auth)
	}
	if strings.Contains(out.String(), "projected") {
		t.Fatalf("a log line holds the token:\n%s", out.String())
	}
}

// serveStoreForTest serves h through serveStore with the given limits and returns the address.
func serveStoreForTest(t *testing.T, limits storeServerLimits, h http.Handler) string {
	t.Helper()
	prev := storeLimits
	storeLimits = limits
	t.Cleanup(func() { storeLimits = prev })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = serveStore(ctx, ln, h, slog.New(slog.DiscardHandler)) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String()
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
}

func TestStoreServerLimits(t *testing.T) {
	srv := newStoreServer(okHandler(), slog.New(slog.DiscardHandler))
	if srv.IdleTimeout <= 0 || srv.WriteTimeout <= 0 || srv.ReadHeaderTimeout <= 0 || srv.MaxHeaderBytes != 16<<10 {
		t.Fatalf("server limits %v %v %v %d", srv.IdleTimeout, srv.WriteTimeout, srv.ReadHeaderTimeout, srv.MaxHeaderBytes)
	}
}

// readAll reads from conn until the peer closes it, or fails the test after d.
func readAll(t *testing.T, conn net.Conn, d time.Duration) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	b, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("connection stayed open for %v: %v (read %q)", d, err, b)
	}
	return string(b)
}

func TestStoreServerIdleConnectionCloses(t *testing.T) {
	limits := storeLimits
	limits.idle = 200 * time.Millisecond
	addr := serveStoreForTest(t, limits, okHandler())
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := readAll(t, conn, 3*time.Second); !strings.Contains(got, "200 OK") {
		t.Fatalf("response %q", got)
	}
}

func TestStoreServerHeaderLimit(t *testing.T) {
	addr := serveStoreForTest(t, storeLimits, okHandler())
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nX-Big: "+strings.Repeat("a", 20<<10)+"\r\n\r\n")
	if got := readAll(t, conn, 3*time.Second); !strings.Contains(got, "431") {
		t.Fatalf("response %q, want 431", got)
	}
}

func TestStoreServerSlowClient(t *testing.T) {
	limits := storeLimits
	limits.readHeader = 200 * time.Millisecond
	addr := serveStoreForTest(t, limits, okHandler())
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n") // the header never ends
	if got := readAll(t, conn, 3*time.Second); strings.Contains(got, "200 OK") {
		t.Fatalf("response %q", got)
	}
}

func TestStoreServerWriteTimeout(t *testing.T) {
	limits := storeLimits
	limits.write = 200 * time.Millisecond
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	})
	addr := serveStoreForTest(t, limits, slow)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := readAll(t, conn, 3*time.Second); strings.Contains(got, "late") {
		t.Fatalf("response %q after the write timeout", got)
	}
}

// healthStatus starts the token mode against upstream and returns the status of GET /healthz.
func healthStatus(t *testing.T, upstream string) int {
	t.Helper()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "300")
	useReviewer(t, tableReviewer{})
	out := &syncBuffer{}
	stop := runUntilCanceled(t, with(tokenArgs(), "--upstream", upstream), out)
	defer stop()
	health := waitLine(t, out, "health_listening")["addr"].(string)
	resp, err := http.Get("http://" + health + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestTokenHealthFollowsUpstream: /healthz is 200 only when GET /v2/ on the upstream answers 200 or 401, so the
// readiness of the pod follows the loopback registry. Any other answer, a refused connection and a hung upstream give 503.
func TestTokenHealthFollowsUpstream(t *testing.T) {
	if healthUpstreamTimeout != 2*time.Second {
		t.Fatalf("healthUpstreamTimeout = %v, want 2s", healthUpstreamTimeout)
	}
	prev := healthUpstreamTimeout
	healthUpstreamTimeout = 300 * time.Millisecond
	t.Cleanup(func() { healthUpstreamTimeout = prev })
	answer := func(code int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v2/" {
				t.Errorf("health asked the upstream %s %s, want GET /v2/", r.Method, r.URL.Path)
			}
			w.WriteHeader(code)
		}))
	}
	for _, tc := range []struct{ code, want int }{
		{200, 200}, {401, 200}, {404, 503}, {403, 503}, {500, 503}, {302, 503},
	} {
		t.Run(fmt.Sprint("upstream ", tc.code), func(t *testing.T) {
			s := answer(tc.code)
			defer s.Close()
			if got := healthStatus(t, strings.TrimPrefix(s.URL, "http://")); got != tc.want {
				t.Fatalf("/healthz = %d, want %d", got, tc.want)
			}
		})
	}
	t.Run("upstream redirects to an answer of 200", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v2/" {
				http.Redirect(w, r, "/elsewhere", http.StatusFound)
			}
		}))
		defer s.Close()
		if got := healthStatus(t, strings.TrimPrefix(s.URL, "http://")); got != http.StatusServiceUnavailable {
			t.Fatalf("/healthz = %d, want 503", got)
		}
	})
	t.Run("upstream down", func(t *testing.T) {
		s := answer(200)
		addr := strings.TrimPrefix(s.URL, "http://")
		s.Close()
		if got := healthStatus(t, addr); got != http.StatusServiceUnavailable {
			t.Fatalf("/healthz = %d, want 503", got)
		}
	})
	t.Run("upstream hung", func(t *testing.T) {
		release := make(chan struct{})
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
		defer s.Close()
		defer close(release)
		start := time.Now()
		if got := healthStatus(t, strings.TrimPrefix(s.URL, "http://")); got != http.StatusServiceUnavailable {
			t.Fatalf("/healthz = %d, want 503", got)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("the health answer took %v, want it near the timeout", d)
		}
	})
}
