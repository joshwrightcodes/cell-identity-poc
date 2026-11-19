package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

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
}

func realBanDeps() banDeps {
	return banDeps{
		telemetry: func(ctx context.Context, stdout io.Writer) (*telemetry.T, error) {
			return telemetry.Start(ctx, banName, stdout)
		},
		api:  agentban.NewAgentAPI,
		read: clusterjwt.ReadRevoked,
	}
}

type banConfig struct {
	config, socket, trustDomain, health string
	every                               time.Duration
}

func parseBan(args []string) (banConfig, error) {
	fs := flag.NewFlagSet(banMode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var c banConfig
	fs.StringVar(&c.config, "config", "/run/spire/config/server.conf", "SPIRE server configuration that holds the cluster_jwt settings")
	fs.StringVar(&c.socket, "socket", "/run/spire/sockets/api.sock", "SPIRE server API socket")
	fs.StringVar(&c.trustDomain, "trust-domain", "", "trust domain of the SPIRE server")
	fs.StringVar(&c.health, "health-listen", "127.0.0.1:8086", "address of the health endpoint")
	fs.DurationVar(&c.every, "every", 5*time.Second, "time between passes")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case c.trustDomain == "":
		return c, errors.New("--trust-domain is required")
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
	api, closeAPI, err := d.api(cfg.socket)
	if err != nil {
		cli.Fail(stdout, banName, err)
		return 1
	}
	defer func() { _ = closeAPI() }()

	// The endpoint is healthy while reads of the revoked set keep succeeding.
	var lastOK atomic.Int64
	lastOK.Store(time.Now().UnixNano())
	window := max(3*cfg.every, minHealthyFor)
	ln, err := net.Listen("tcp", cfg.health)
	if err != nil {
		cli.Fail(stdout, banName, fmt.Errorf("health listener: %w", err))
		return 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if time.Since(time.Unix(0, lastOK.Load())) > window {
			http.Error(w, "the revoked set is unreadable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	tel.Log.Info("ban-agents started", "trust_domain", cfg.trustDomain, "health", ln.Addr().String())
	err = agentban.Run(ctx, agentban.Config{
		TrustDomain: cfg.trustDomain,
		Read: func() (clusterjwt.RevokedSet, error) {
			set, err := d.read(cfg.config)
			if err == nil {
				lastOK.Store(time.Now().UnixNano())
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
