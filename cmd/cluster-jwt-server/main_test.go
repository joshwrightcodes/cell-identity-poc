package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
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
			{},
			{"--trust-domain", "dev-cp.test", "--every", "0s"},
			{"--trust-domain", "dev-cp.test", "extra"},
			{"--trust-domain", "dev-cp.test", "--nope"},
		} {
			var out bytes.Buffer
			d := testDeps(&recordAPI{}, nil, &out)
			if code := banAgents(context.Background(), args, &out, d); code != exitConfig {
				t.Errorf("args %v: code %d, want %d; output %s", args, code, exitConfig, out.String())
			}
		}
		c, err := parseBan([]string{"--trust-domain", "dev-cp.test"})
		if err != nil || c.health != "127.0.0.1:8086" || c.every != 5*time.Second || c.socket == "" || c.config == "" {
			t.Fatalf("defaults %+v, %v", c, err)
		}
	})

	t.Run("bans and serves health", func(t *testing.T) {
		api := &recordAPI{}
		var out bytes.Buffer
		var mu sync.Mutex
		fail := false
		read := func(path string) (clusterjwt.RevokedSet, error) {
			mu.Lock()
			defer mu.Unlock()
			if path != "/etc/server.conf" {
				return clusterjwt.RevokedSet{}, errors.New("wrong path " + path)
			}
			if fail {
				return clusterjwt.RevokedSet{}, errors.New("no verified spec loaded")
			}
			return clusterjwt.RevokedSet{Cells: map[string]string{"dev-cell-2": clusterjwt.SourceRecord}}, nil
		}
		addr := freeAddr(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan int, 1)
		var safeOut syncBuffer
		d := testDeps(api, read, &out)
		go func() {
			done <- banAgents(ctx, []string{"--trust-domain", "dev-cp.test", "--config", "/etc/server.conf",
				"--every", "20ms", "--health-listen", addr}, &safeOut, d)
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
