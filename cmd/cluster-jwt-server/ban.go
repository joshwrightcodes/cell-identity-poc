package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/hashicorp/hcl"

	"github.com/joshwrightcodes/cell-identity-poc/internal/agentban"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	banMode       = "ban-agents"
	banName       = "cluster-jwt-ban"
	exitConfig    = 2
	flushTimeout  = 15 * time.Second
	minHealthyFor = 30 * time.Second
)

// banDeps holds what a test replaces.
type banDeps struct {
	telemetry func(ctx context.Context, stdout io.Writer) (*telemetry.T, error)
	api       func(socket string) (agentban.API, func() error, error)
	read      func(configPath string) (clusterjwt.RevokedSet, error)
	// trustDomain returns the trust domain of the server configuration.
	trustDomain func(configPath string) (string, error)
	// window is how long a failure may last before health turns 503. Zero means the default.
	window time.Duration
}

func realBanDeps() banDeps {
	return banDeps{
		telemetry: func(ctx context.Context, stdout io.Writer) (*telemetry.T, error) {
			return telemetry.Start(ctx, banName, stdout)
		},
		api:  agentban.NewAgentAPI,
		read: clusterjwt.ReadRevoked,

		trustDomain: readTrustDomain,
	}
}

// readTrustDomain returns server.trust_domain of the SPIRE server configuration, the value that the
// cluster_jwt plugin reads too.
func readTrustDomain(path string) (string, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read server config: %w", err)
	}
	var doc map[string]any
	if err := hcl.Decode(&doc, string(text)); err != nil {
		return "", fmt.Errorf("parse server config: %w", err)
	}
	servers, _ := doc["server"].([]map[string]any)
	if len(servers) != 1 {
		return "", errors.New("server config needs exactly one server block")
	}
	td, _ := servers[0]["trust_domain"].(string)
	if td == "" {
		return "", errors.New("server config has no server.trust_domain")
	}
	return td, nil
}

type banConfig struct {
	config, socket, health string
	every                  time.Duration
}

func parseBan(args []string) (banConfig, error) {
	fs := flag.NewFlagSet(banMode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var c banConfig
	fs.StringVar(&c.config, "server-config", "/run/spire/config/server.conf", "SPIRE server configuration with the trust domain and the cluster_jwt settings")
	fs.StringVar(&c.socket, "socket", "/run/spire/sockets/api.sock", "SPIRE server API socket")
	fs.StringVar(&c.health, "health", "127.0.0.1:8086", "address of the health endpoint")
	fs.DurationVar(&c.every, "every", 10*time.Second, "time between passes")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case c.every <= 0:
		return c, errors.New("--every must be positive")
	}
	return c, nil
}

// banAgents runs the ban container until ctx ends and returns the exit status.
func banAgents(ctx context.Context, args []string, stdout io.Writer, d banDeps) int {
	cfg, err := parseBan(args)
	if err != nil {
		cli.Fail(stdout, banName, err)
		return exitConfig
	}
	tel, err := d.telemetry(ctx, stdout)
	if err != nil {
		cli.Fail(stdout, banName, err)
		return 1
	}
	defer func() {
		fctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
		defer cancel()
		_ = tel.Shutdown(fctx)
	}()
	trustDomain, err := d.trustDomain(cfg.config)
	if err != nil {
		cli.Fail(stdout, banName, err)
		return 1
	}
	api, closeAPI, err := d.api(cfg.socket)
	if err != nil {
		cli.Fail(stdout, banName, err)
		return 1
	}
	defer func() { _ = closeAPI() }()

	// The endpoint is healthy while reads of the revoked set and lists of the agents keep succeeding.
	var lastRead, lastList atomic.Int64
	lastRead.Store(time.Now().UnixNano())
	lastList.Store(time.Now().UnixNano())
	api = healthAPI{API: api, ok: &lastList}
	window := d.window
	if window == 0 {
		window = max(3*cfg.every, minHealthyFor)
	}
	ln, err := net.Listen("tcp", cfg.health)
	if err != nil {
		cli.Fail(stdout, banName, fmt.Errorf("health listener: %w", err))
		return 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if time.Since(time.Unix(0, lastRead.Load())) > window || time.Since(time.Unix(0, lastList.Load())) > window {
			http.Error(w, "the revoked set or the agent list is unreadable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	tel.Log.Info("ban-agents started", "trust_domain", trustDomain, "health", ln.Addr().String())
	err = agentban.Run(ctx, agentban.Config{
		TrustDomain: trustDomain,
		Read: func() (clusterjwt.RevokedSet, error) {
			set, err := d.read(cfg.config)
			if err == nil {
				lastRead.Store(time.Now().UnixNano())
			}
			return set, err
		},
		API:   api,
		Every: cfg.every,
		Log:   tel.Log,
		Meter: tel.Meter,
	})
	if err != nil {
		cli.Fail(stdout, banName, err)
		return 1
	}
	return 0
}

// healthAPI records the time of the last good list.
type healthAPI struct {
	agentban.API
	ok *atomic.Int64
}

func (h healthAPI) List(ctx context.Context) ([]agentban.Agent, error) {
	agents, err := h.API.List(ctx)
	if err == nil {
		h.ok.Store(time.Now().UnixNano())
	}
	return agents, err
}
