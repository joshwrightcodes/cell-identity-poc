package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	readHeaderTimeout = 10 * time.Second
	httpShutdown      = 5 * time.Second
)

var cellLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,57}[a-z0-9])?$`)

// tunnelConfig is the tunnel backend of spiffe-server: the listen address of each cell, and the
// wait of a request for its tunnel.
type tunnelConfig struct {
	cells map[string]string
	wait  time.Duration
}

// tunnelCellFlag parses one --tunnel-cell <cell>=<listen addr> into cells.
func tunnelCellFlag(cells map[string]string) func(string) error {
	return func(v string) error {
		cell, addr, ok := strings.Cut(v, "=")
		if !ok || !cellLabel.MatchString(cell) {
			return fmt.Errorf("%q is not <cell>=<listen addr> with a cell name of at most 59 lower-case letters, digits and dashes", v)
		}
		if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
			return fmt.Errorf("%q: the listen address is not host:port", v)
		}
		if _, dup := cells[cell]; dup {
			return fmt.Errorf("cell %s is given twice", cell)
		}
		cells[cell] = addr
		return nil
	}
}

func newTunnelConfig(cells map[string]string, wait time.Duration) (*tunnelConfig, error) {
	if len(cells) == 0 {
		return nil, errors.New("--tunnel-cell required for --backend tunnel")
	}
	if wait <= 0 {
		return nil, fmt.Errorf("--tunnel-wait %s must be positive", wait)
	}
	seen := map[string]string{}
	for cell, addr := range cells {
		if _, port, _ := net.SplitHostPort(addr); port == "0" {
			continue
		}
		if other, dup := seen[addr]; dup {
			return nil, fmt.Errorf("cells %s and %s share the listen address %s", other, cell, addr)
		}
		seen[addr] = cell
	}
	return &tunnelConfig{cells: cells, wait: wait}, nil
}

// serveTunnelHub runs the accept loop with the tunnel backend and the local listener of each
// cell, until ctx ends or one of them fails.
func serveTunnelHub(ctx context.Context, ln net.Listener, tlsCfg *tls.Config, cfg *tunnelConfig, log *slog.Logger) error {
	hub := cellproxy.NewTunnelHub(cfg.cells, cfg.wait, log)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hubErr := make(chan error, 1)
	go func() {
		hubErr <- hub.Serve(ctx)
		cancel()
	}()
	err := cellproxy.NewServer(cellproxy.ServerConfig{TLS: tlsCfg}, cellproxy.NewTunnelBackend(hub), log).Serve(ctx, ln)
	cancel()
	if herr := <-hubErr; err == nil {
		err = herr
	}
	return err
}

type tunnelModeConfig struct {
	upstream string
	expect   spiffeid.ID
	peer     *x509bundle.Bundle
}

func parseTunnel(args []string) (tunnelModeConfig, error) {
	fs := newFlags("tunnel")
	upstream := fs.String("upstream", "", "management plane address as host:port")
	expect := fs.String("expect-id", "", "the exact SPIFFE ID of the tunnel hub")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the management plane trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the management plane")
	if err := fs.Parse(args); err != nil {
		return tunnelModeConfig{}, err
	}
	if err := required(map[string]string{"upstream": *upstream, "expect-id": *expect, "peer-bundle": *bundle, "peer-trust-domain": *td}); err != nil {
		return tunnelModeConfig{}, err
	}
	peer, trustDomain, err := loadPeer(*bundle, *td)
	if err != nil {
		return tunnelModeConfig{}, err
	}
	id, err := expectedID(*expect, trustDomain)
	if err != nil {
		return tunnelModeConfig{}, err
	}
	return tunnelModeConfig{upstream: *upstream, expect: id, peer: peer}, nil
}

// runTunnel is the cell side of the mesh-view tunnel. It reads the Kubernetes API with the
// in-cluster config of its pod.
func runTunnel(ctx context.Context, args []string, stdout io.Writer) int {
	cfg, err := parseTunnel(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return serve(ctx, stdout, func(ctx context.Context, tel *telemetry.T, svids *workloadapi.X509Source) error {
		kc, err := rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("in-cluster config: %w", err)
		}
		rt, err := rest.TransportFor(kc)
		if err != nil {
			return fmt.Errorf("kubernetes transport: %w", err)
		}
		api, err := url.Parse(kc.Host)
		if err != nil {
			return fmt.Errorf("kubernetes host: %w", err)
		}
		tel.Log.Info("tunnel starting", "upstream", cfg.upstream, "expect_id", cfg.expect.String(), "api", api.Host)
		dial := cellproxy.TunnelDialer(cfg.upstream, cellproxy.ClientTLS(svids, cfg.peer, cfg.expect), tel.Log)
		return cellproxy.RunTunnel(ctx, dial, cellproxy.NewCellHandler(api, rt, tel.Log))
	})
}

func parsePromProxy(args []string) (string, *url.URL, error) {
	fs := newFlags("promql-proxy")
	listen := fs.String("listen", "", "address to listen on")
	upstream := fs.String("upstream", "", "Prometheus base URL, for example http://lgtm:9090")
	if err := fs.Parse(args); err != nil {
		return "", nil, err
	}
	if err := required(map[string]string{"listen": *listen, "upstream": *upstream}); err != nil {
		return "", nil, err
	}
	u, err := url.Parse(*upstream)
	if err != nil {
		return "", nil, fmt.Errorf("--upstream: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, fmt.Errorf("--upstream %q must be an http or https URL with a host and no user, query or fragment", *upstream)
	}
	return *listen, u, nil
}

// runPromProxy serves the read-only Prometheus proxy. It has no SVID.
func runPromProxy(ctx context.Context, args []string, stdout io.Writer) int {
	listen, upstream, err := parsePromProxy(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return serveTelemetry(ctx, stdout, func(ctx context.Context, tel *telemetry.T) error {
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			return err
		}
		tel.Log.Info("listening", "addr", ln.Addr().String(), "upstream", upstream.String())
		return serveHTTP(ctx, ln, cellproxy.NewPromProxy(upstream, tel.Log), tel.Log)
	})
}

// serveHTTP serves h on ln until ctx ends, then shuts the server down.
func serveHTTP(ctx context.Context, ln net.Listener, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: readHeaderTimeout, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
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
