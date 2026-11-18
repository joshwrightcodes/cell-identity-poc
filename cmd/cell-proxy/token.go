package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

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
		return listenAndServe(ctx, cfg.listen, cfg.health, h, tel)
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
		return listenAndServe(ctx, cfg.listen, cfg.health, h, tel)
	})
}

// listenAndServe serves h on listen, and a health answer on health when it is set.
func listenAndServe(ctx context.Context, listen, health string, h http.Handler, tel *telemetry.T) error {
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
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
		go func() { errc <- serveHTTP(ctx, hl, mux, tel.Log) }()
	}
	tel.Log.Info("listening", "addr", ln.Addr().String())
	go func() { errc <- serveHTTP(ctx, ln, h, tel.Log) }()
	err = <-errc
	cancel()
	if health != "" {
		<-errc
	}
	return err
}
