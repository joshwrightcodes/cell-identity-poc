package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

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
	if !slices.Equal(hits, []string{"GET /v2/bundles/root/manifests/current", "PUT /v2/bundles/root/manifests/current"}) {
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
