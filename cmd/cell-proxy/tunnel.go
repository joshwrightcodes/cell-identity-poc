package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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

// registerTunnelFlags adds --tunnel-cell and --tunnel-wait to fs. The returned function checks
// them against --listen and gives the backend factory of --backend tunnel.
func registerTunnelFlags(fs *flag.FlagSet) func(listen string) (func(*telemetry.T) (cellproxy.Backend, error), error) {
	cells := map[string]string{}
	fs.Func("tunnel-cell", "<cell>=<listen addr> of a tunnel listener; repeat for each cell", tunnelCellFlag(cells))
	wait := fs.Duration("tunnel-wait", 10*time.Second, "how long a tunnel request waits for the tunnel of its cell")
	readIdle := fs.Duration("tunnel-read-idle", 30*time.Second, "how long a tunnel connection may be idle before the hub pings it")
	pingTimeout := fs.Duration("tunnel-ping-timeout", 15*time.Second, "how long the hub waits for the answer to a ping before it closes the tunnel")
	statusAddr := fs.String("tunnel-status", cellproxy.DefaultStatusAddr, "loopback address where the hub serves its tunnel state, read by cell-proxy tunnel-status")
	return func(listen string) (func(*telemetry.T) (cellproxy.Backend, error), error) {
		if err := checkTunnelCells(cells, *wait, listen); err != nil {
			return nil, err
		}
		return func(tel *telemetry.T) (cellproxy.Backend, error) {
			m, err := cellproxy.NewTunnelMetrics(tel.Meter)
			if err != nil {
				return nil, fmt.Errorf("tunnel metrics: %w", err)
			}
			return cellproxy.NewTunnelBackend(cellproxy.NewTunnelHub(cells, *wait, tel.Log, cellproxy.WithMetrics(m), cellproxy.WithStatusAddr(*statusAddr), cellproxy.WithKeepalive(*readIdle, *pingTimeout))), nil
		}, nil
	}
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

func checkTunnelCells(cells map[string]string, wait time.Duration, listen string) error {
	if len(cells) == 0 {
		return errors.New("--tunnel-cell required for --backend tunnel")
	}
	if wait <= 0 {
		return fmt.Errorf("--tunnel-wait %s must be positive", wait)
	}
	seen := map[string]string{listen: "--listen"}
	for cell, addr := range cells {
		if _, port, _ := net.SplitHostPort(addr); port == "0" {
			continue
		}
		if other, dup := seen[addr]; dup {
			return fmt.Errorf("%s and cell %s share the listen address %s", other, cell, addr)
		}
		seen[addr] = "cell " + cell
	}
	return nil
}

// serveBackend runs srv on ln. A backend with listeners of its own (Run) runs them too, and the
// first of the two to fail stops the other.
func serveBackend(ctx context.Context, srv *cellproxy.Server, ln net.Listener, b cellproxy.Backend) error {
	r, ok := b.(interface{ Run(context.Context) error })
	if !ok {
		return srv.Serve(ctx, ln)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- r.Run(ctx)
		cancel()
	}()
	err := srv.Serve(ctx, ln)
	cancel()
	if rerr := <-runErr; err == nil {
		err = rerr
	}
	return err
}

type tunnelModeConfig struct {
	readIdle, pingTimeout time.Duration
	statusAddr            string
	upstream              string
	expect                spiffeid.ID
	peer                  *x509bundle.Bundle
	proof                 bool
}

func parseTunnel(args []string) (tunnelModeConfig, error) {
	fs := newFlags("tunnel")
	upstream := fs.String("upstream", "", "management plane address as host:port")
	expect := fs.String("expect-id", "", "the exact SPIFFE ID of the tunnel hub")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the management plane trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the management plane")
	readIdle := fs.Duration("read-idle", 30*time.Second, "how long the tunnel connection may be idle before the cell pings it")
	pingTimeout := fs.Duration("ping-timeout", 15*time.Second, "how long the cell waits for the answer to a ping before it closes the tunnel")
	status := fs.String("status-listen", cellproxy.DefaultStatusAddr, "loopback address where the tunnel serves its state, read by cell-proxy tunnel-status")
	withProof := fs.Bool("proof", false, "send a pod-bound service account token as a second proof on each tunnel connection")
	if err := parseFlags(fs, args); err != nil {
		return tunnelModeConfig{}, err
	}
	if err := required(map[string]string{"upstream": *upstream, "expect-id": *expect, "peer-bundle": *bundle, "peer-trust-domain": *td}); err != nil {
		return tunnelModeConfig{}, err
	}
	if host, port, err := net.SplitHostPort(*upstream); err != nil || host == "" || port == "" {
		return tunnelModeConfig{}, fmt.Errorf("--upstream %q is not host:port", *upstream)
	}
	peer, trustDomain, err := loadPeer(*bundle, *td)
	if err != nil {
		return tunnelModeConfig{}, err
	}
	id, err := expectedID(*expect, trustDomain)
	if err != nil {
		return tunnelModeConfig{}, err
	}
	return tunnelModeConfig{upstream: *upstream, expect: id, peer: peer, statusAddr: *status, readIdle: *readIdle, pingTimeout: *pingTimeout, proof: *withProof}, nil
}

// runOptions are the options of cellproxy.RunTunnel: the keepalive, and the logger for the lines of the HTTP/2 server.
func (c tunnelModeConfig) runOptions(log *slog.Logger) []cellproxy.TunnelOption {
	return []cellproxy.TunnelOption{cellproxy.WithKeepalive(c.readIdle, c.pingTimeout), cellproxy.WithLogger(log)}
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
		m, err := cellproxy.NewTunnelMetrics(tel.Meter)
		if err != nil {
			return fmt.Errorf("tunnel metrics: %w", err)
		}
		tel.Log.Info("tunnel_starting", "upstream", cfg.upstream, "expect_id", cfg.expect.String(), "api", api.Host)
		state := cellproxy.NewTunnelState()
		go func() {
			if err := cellproxy.ServeStatus(ctx, cfg.statusAddr, state.Status, tel.Log); err != nil {
				tel.Log.Warn("tunnel status listener ended", "error", err.Error())
			}
		}()
		dialOpts := []cellproxy.TunnelOption{cellproxy.WithMetrics(m), cellproxy.WithState(state)}
		if cfg.proof {
			p, err := newProofFunc(svids, kc)
			if err != nil {
				return err
			}
			dialOpts = append(dialOpts, cellproxy.WithProof(p))
		}
		dial := cellproxy.TunnelDialer(cfg.upstream, cellproxy.ClientTLS(svids, cfg.peer, cfg.expect), tel.Log, dialOpts...)
		return cellproxy.RunTunnel(ctx, dial, cellproxy.NewCellHandler(api, rt, tel.Log, cellproxy.WithMetrics(m)), cfg.runOptions(tel.Log)...)
	})
}

func parsePromProxy(args []string) (string, *url.URL, error) {
	fs := newFlags("promql-proxy")
	listen := fs.String("listen", "", "address to listen on")
	upstream := fs.String("upstream", "", "Prometheus base URL, for example http://lgtm:9090")
	if err := parseFlags(fs, args); err != nil {
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

// runTunnelStatus prints the tunnel state that the process of this container serves.
func runTunnelStatus(ctx context.Context, args []string, stdout io.Writer) int {
	fs := newFlags("tunnel-status")
	addr := fs.String("addr", cellproxy.DefaultStatusAddr, "address of the status listener")
	if err := parseFlags(fs, args); err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return cli.Run(stdout, name, func(out io.Writer) error {
		st, err := cellproxy.FetchStatus(ctx, *addr)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(st)
	})
}
