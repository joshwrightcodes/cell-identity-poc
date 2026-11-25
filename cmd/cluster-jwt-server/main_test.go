package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"

	"github.com/joshwrightcodes/cell-identity-poc/internal/agentban"
	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

type recordAPI struct {
	mu   sync.Mutex
	bans []string
}

func (a *recordAPI) List(context.Context) ([]agentban.Agent, error) {
	return []agentban.Agent{
		{ID: "spiffe://dev-cp.test/spire/agent/cluster_jwt/dev-cell-2/u1/h1"},
		{ID: "spiffe://dev-cp.test/spire/agent/cluster_jwt/dev-cell-1/u2/h1"},
	}, nil
}

func (a *recordAPI) Ban(_ context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bans = append(a.bans, id)
	return nil
}

func (a *recordAPI) banned() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.bans...)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func testDeps(api agentban.API, read func(string) (clusterjwt.RevokedSet, error), out *bytes.Buffer) banDeps {
	return banDeps{
		trustDomain: func(string) (string, error) { return "dev-cp.test", nil },
		telemetry: func(_ context.Context, _ io.Writer) (*telemetry.T, error) {
			return &telemetry.T{
				Log:      slog.New(slog.NewJSONHandler(out, nil)),
				Meter:    noop.NewMeterProvider().Meter("test"),
				Shutdown: func(context.Context) error { return nil },
			}, nil
		},
		api:  func(string) (agentban.API, func() error, error) { return api, func() error { return nil }, nil },
		read: read,
	}
}

func TestBanAgentsMode(t *testing.T) {
	t.Run("flags", func(t *testing.T) {
		for _, args := range [][]string{
			{"--every", "0s"},
			{"extra"},
			{"--nope"},
			{"--trust-domain", "dev-cp.test"},
		} {
			var out bytes.Buffer
			d := testDeps(&recordAPI{}, nil, &out)
			if code := banAgents(context.Background(), args, &out, d); code != exitConfig {
				t.Errorf("args %v: code %d, want %d; output %s", args, code, exitConfig, out.String())
			}
		}
		c, err := parseBan(nil)
		if err != nil || c.health != "127.0.0.1:8086" || c.every != 10*time.Second ||
			c.socket != "/run/spire/sockets/api.sock" || c.config != "/run/spire/config/server.conf" {
			t.Fatalf("defaults %+v, %v", c, err)
		}
		// The arguments of the Ban row of the plan, verbatim.
		if _, err := parseBan([]string{"--server-config", "/run/spire/config/server.conf", "--socket", "/run/spire/sockets/api.sock",
			"--every", "10s", "--health", "127.0.0.1:8086"}); err != nil {
			t.Fatalf("the Ban row arguments: %v", err)
		}
	})

	t.Run("bans and serves health", func(t *testing.T) {
		api := &recordAPI{}
		var out bytes.Buffer
		read := func(path string) (clusterjwt.RevokedSet, error) {
			if path != "/etc/server.conf" {
				return clusterjwt.RevokedSet{}, errors.New("wrong path " + path)
			}
			return clusterjwt.RevokedSet{Cells: map[string]string{"dev-cell-2": clusterjwt.SourceRecord}}, nil
		}
		addr := freeAddr(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan int, 1)
		var safeOut syncBuffer
		d := testDeps(api, read, &out)
		go func() {
			done <- banAgents(ctx, []string{"--server-config", "/etc/server.conf",
				"--every", "20ms", "--health", addr}, &safeOut, d)
		}()
		deadline := time.Now().Add(5 * time.Second)
		for len(api.banned()) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got := api.banned(); len(got) != 1 || !strings.HasSuffix(got[0], "/dev-cell-2/u1/h1") {
			t.Fatalf("banned %v, want only the agent of dev-cell-2", got)
		}
		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("health %d, want 200", resp.StatusCode)
		}
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Fatalf("exit %d, output %s", code, safeOut.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the loop did not stop")
		}
	})
}

type wrongDomainAPI struct{ recordAPI }

func (a *wrongDomainAPI) List(context.Context) ([]agentban.Agent, error) {
	return []agentban.Agent{
		{ID: "spiffe://dev-cp.test/spire/agent/cluster_jwt/dev-cell-2/u1/h1"},
		{ID: "spiffe://other.test/spire/agent/cluster_jwt/dev-cell-2/u2/h1"},
	}, nil
}

// The trust domain comes from the server configuration, and an agent of another trust domain is
// never banned.
func TestBanUsesTheTrustDomainOfServerConf(t *testing.T) {
	api := &wrongDomainAPI{}
	var out bytes.Buffer
	d := testDeps(api, func(string) (clusterjwt.RevokedSet, error) {
		return clusterjwt.RevokedSet{Cells: map[string]string{"dev-cell-2": clusterjwt.SourceRecord}}, nil
	}, &out)
	var asked string
	d.trustDomain = func(path string) (string, error) { asked = path; return "dev-cp.test", nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- banAgents(ctx, []string{"--server-config", "/etc/s.conf", "--every", "20ms", "--health", freeAddr(t)}, io.Discard, d)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(api.banned()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if asked != "/etc/s.conf" {
		t.Fatalf("trust domain read from %q, want the --server-config path", asked)
	}
	if got := api.banned(); len(got) == 0 || slices.ContainsFunc(got, func(id string) bool { return !strings.HasPrefix(id, "spiffe://dev-cp.test/") }) {
		t.Fatalf("banned %v, want only the agent of dev-cp.test", got)
	}
}

func TestReadTrustDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.conf")
	conf := "server {\n  bind_port = 8081\n  trust_domain = \"dev-cp.test\"\n}\nplugins {\n  NodeAttestor \"cluster_jwt\" {\n    plugin_data {\n      trust_domain = \"dev-cp.test\"\n    }\n  }\n}\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if td, err := readTrustDomain(path); err != nil || td != "dev-cp.test" {
		t.Fatalf("readTrustDomain = %q, %v", td, err)
	}
	if err := os.WriteFile(path, []byte("server {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustDomain(path); err == nil {
		t.Fatal("a configuration without trust_domain must fail")
	}
	if _, err := readTrustDomain(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("a missing file must fail")
	}
}

type flakyAPI struct {
	recordAPI
	fail atomic.Bool
}

func (a *flakyAPI) List(ctx context.Context) ([]agentban.Agent, error) {
	if a.fail.Load() {
		return nil, errors.New("socket closed")
	}
	return a.recordAPI.List(ctx)
}

func health(t *testing.T, addr string) int {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func waitHealth(t *testing.T, addr string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if health(t, addr) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("health did not reach %d", want)
}

// Health turns 503 after a read or a list failure lasts for the whole window, and turns 200 again
// after the next good pass.
func TestBanHealthReportsFailures(t *testing.T) {
	api := &flakyAPI{}
	var readFails atomic.Bool
	var out bytes.Buffer
	d := testDeps(api, func(string) (clusterjwt.RevokedSet, error) {
		if readFails.Load() {
			return clusterjwt.RevokedSet{}, errors.New("no verified spec loaded")
		}
		return clusterjwt.RevokedSet{}, nil
	}, &out)
	d.window = 150 * time.Millisecond
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- banAgents(ctx, []string{"--server-config", "/etc/s.conf", "--every", "20ms", "--health", addr}, io.Discard, d)
	}()
	defer func() { cancel(); <-done }()

	waitHealth(t, addr, http.StatusOK)
	readFails.Store(true)
	waitHealth(t, addr, http.StatusServiceUnavailable)
	readFails.Store(false)
	waitHealth(t, addr, http.StatusOK)
	api.fail.Store(true)
	waitHealth(t, addr, http.StatusServiceUnavailable)
	api.fail.Store(false)
	waitHealth(t, addr, http.StatusOK)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
