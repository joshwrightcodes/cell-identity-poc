package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

// newTokenReviewer makes the reviewer of the token mode. It uses the in-cluster configuration.
// Tests replace it.
var newTokenReviewer = func() (cellproxy.TokenReviewer, error) {
	kc, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	c, err := authenticationv1client.NewForConfig(kc)
	if err != nil {
		return nil, fmt.Errorf("token review client: %w", err)
	}
	return &cellproxy.KubeReviewer{Reviews: c.TokenReviews()}, nil
}

type tokenModeConfig struct {
	listen, upstream, audience, health string
	readers, writers                   []string
}

// subjectsFlag collects a repeatable flag of non-empty values.
func subjectsFlag(fs *flag.FlagSet, flagName, usage string) *[]string {
	var vals []string
	fs.Func(flagName, usage, func(v string) error {
		if strings.TrimSpace(v) == "" {
			return errors.New("must not be empty")
		}
		vals = append(vals, v)
		return nil
	})
	return &vals
}

// checkHostPort checks that v is host:port with a host and a port and no scheme.
func checkHostPort(flagName, v string) error {
	if host, port, err := net.SplitHostPort(v); err != nil || host == "" || port == "" {
		return fmt.Errorf("--%s %q is not host:port", flagName, v)
	}
	return nil
}

func parseToken(args []string) (tokenModeConfig, error) {
	fs := newFlags("token")
	listen := fs.String("listen", "", "address to listen on")
	upstream := fs.String("upstream", "", "registry as host:port")
	audience := fs.String("audience", "", "audience that every token must name")
	health := fs.String("health", "", "address of the health listener")
	readers := subjectsFlag(fs, "reader", "service account user name that may read; repeat for each")
	writers := subjectsFlag(fs, "writer", "service account user name that may write; repeat for each, or give none")
	if err := parseFlags(fs, args); err != nil {
		return tokenModeConfig{}, err
	}
	if err := required(map[string]string{"listen": *listen, "upstream": *upstream, "audience": *audience}); err != nil {
		return tokenModeConfig{}, err
	}
	if len(*readers) == 0 {
		return tokenModeConfig{}, errors.New("--reader required")
	}
	if err := checkHostPort("upstream", *upstream); err != nil {
		return tokenModeConfig{}, err
	}
	return tokenModeConfig{listen: *listen, upstream: *upstream, audience: *audience, health: *health, readers: *readers, writers: *writers}, nil
}

// runToken serves the store proxy: it passes a request to the registry only for a reader or a
// writer that the TokenReview API names.
func runToken(ctx context.Context, args []string, stdout io.Writer) int {
	cfg, err := parseToken(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return serveTelemetry(ctx, stdout, func(ctx context.Context, tel *telemetry.T) error {
		reviewer, err := newTokenReviewer()
		if err != nil {
			return err
		}
		h, err := cellproxy.NewTokenHandler(cellproxy.TokenConfig{
			Upstream: cfg.upstream, Audience: cfg.audience, Readers: cfg.readers, Writers: cfg.writers,
			Reviewer: reviewer, Log: tel.Log, Meter: tel.Meter,
		})
		if err != nil {
			return err
		}
		tel.Log.Info("token_starting", "upstream", cfg.upstream, "audience", cfg.audience, "readers", cfg.readers, "writers", cfg.writers)
		return listenAndServe(ctx, cfg.listen, cfg.health, h, upstreamHealth(cfg.upstream), tel)
	})
}

type tokenClientModeConfig struct {
	listen, upstream, tokenFile, health string
}

func parseTokenClient(args []string) (tokenClientModeConfig, error) {
	fs := newFlags("token-client")
	listen := fs.String("listen", "", "loopback address to listen on")
	upstream := fs.String("upstream", "", "store proxy as host:port")
	file := fs.String("token-file", "", "file with the bearer token")
	health := fs.String("health", "", "address of the health listener")
	if err := parseFlags(fs, args); err != nil {
		return tokenClientModeConfig{}, err
	}
	if err := required(map[string]string{"listen": *listen, "upstream": *upstream, "token-file": *file}); err != nil {
		return tokenClientModeConfig{}, err
	}
	if err := checkHostPort("upstream", *upstream); err != nil {
		return tokenClientModeConfig{}, err
	}
	if err := loopbackOnly("listen", *listen); err != nil {
		return tokenClientModeConfig{}, err
	}
	return tokenClientModeConfig{listen: *listen, upstream: *upstream, tokenFile: *file, health: *health}, nil
}

// loopbackOnly refuses an address that is not a loopback IP or localhost. The token client sends
// a token for each request, so no other host may reach it.
func loopbackOnly(flagName, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("--%s %q is not host:port", flagName, addr)
	}
	if host == "localhost" {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return fmt.Errorf("--%s %q is not a loopback address", flagName, addr)
	}
	return nil
}

// runTokenClient serves the token client. It has no SVID and no API access.
func runTokenClient(ctx context.Context, args []string, stdout io.Writer) int {
	cfg, err := parseTokenClient(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return serveTelemetry(ctx, stdout, func(ctx context.Context, tel *telemetry.T) error {
		h, err := cellproxy.NewTokenClient(cellproxy.TokenClientConfig{Upstream: cfg.upstream, TokenFile: cfg.tokenFile, Log: tel.Log})
		if err != nil {
			return err
		}
		tel.Log.Info("token_client_starting", "upstream", cfg.upstream)
		return listenAndServe(ctx, cfg.listen, cfg.health, h, nil, tel)
	})
}

// healthUpstreamTimeout bounds the registry check of the store proxy health route. Tests change it.
var healthUpstreamTimeout = cellproxy.StoreHealthTimeout

// upstreamHealth answers GET /healthz of the store proxy from the registry behind it: 200 when GET /v2/ on
// the upstream answers 200 or 401, and 503 for any other answer, a failed connection or no answer within
// healthUpstreamTimeout. The readiness of the pod follows the registry, which has no probe of its own.
func upstreamHealth(upstream string) http.Handler {
	client := &http.Client{
		Timeout:       healthUpstreamTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), healthUpstreamTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+upstream+"/v2/", nil)
		if err == nil {
			var resp *http.Response
			if resp, err = client.Do(req); err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
					_, _ = io.WriteString(w, "ok\n")
					return
				}
			}
		}
		http.Error(w, "upstream not ready", http.StatusServiceUnavailable)
	})
}

// listenAndServe serves h on listen, and on health the route /healthz when health is set. A nil ready answers
// 200, and the store proxy gives the handler of its registry check.
func listenAndServe(ctx context.Context, listen, health string, h http.Handler, ready http.Handler, tel *telemetry.T) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	if health != "" {
		hl, err := net.Listen("tcp", health)
		if err != nil {
			_ = ln.Close()
			return err
		}
		tel.Log.Info("health_listening", "addr", hl.Addr().String())
		mux := http.NewServeMux()
		if ready == nil {
			ready = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
		}
		mux.Handle("GET /healthz", ready)
		go func() { errc <- serveStore(ctx, hl, mux, tel.Log) }()
	}
	tel.Log.Info("listening", "addr", ln.Addr().String())
	go func() { errc <- serveStore(ctx, ln, h, tel.Log) }()
	err = <-errc
	cancel()
	if health != "" {
		<-errc
	}
	return err
}

// storeServerLimits bound how long a client may hold a connection of the token modes.
type storeServerLimits struct {
	readHeader, idle, write time.Duration
	maxHeader               int
}

// storeLimits are the limits of the token modes. There is no read timeout, because a blob upload
// is large. The write timeout covers the time from the end of the request header to the end of the
// response, so it must allow the largest upload. Tests change it.
var storeLimits = storeServerLimits{readHeader: 10 * time.Second, idle: 60 * time.Second, write: 5 * time.Minute, maxHeader: 16 << 10}

// newStoreServer returns an HTTP server with the limits of storeLimits.
func newStoreServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: storeLimits.readHeader,
		IdleTimeout:       storeLimits.idle,
		WriteTimeout:      storeLimits.write,
		MaxHeaderBytes:    storeLimits.maxHeader,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// serveStore serves h on ln until ctx ends, then shuts the server down.
func serveStore(ctx context.Context, ln net.Listener, h http.Handler, log *slog.Logger) error {
	srv := newStoreServer(h, log)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), httpShutdown)
	defer cancel()
	_ = srv.Shutdown(sctx)
	<-errc
	return nil
}
