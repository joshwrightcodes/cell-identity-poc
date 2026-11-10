// Command relay passes TCP streams through the environment control plane, by listen port.
//
//	relay --route <listen port>=<host:port> [--route ...] [--health <addr>]
//
// Each route listens on its port on every address, and pipes each connection to its upstream. The
// relay ends no TLS and reads no byte of a stream, so the SPIFFE mTLS of cell-proxy runs end to
// end. It dials the upstream only after the first byte of the client, so a silent client or a
// port check opens no upstream connection. The limits:
//
//   - the first byte of a client must come within 10 seconds;
//   - the upstream dial must finish within 5 seconds;
//   - both sockets send TCP keepalives every 30 seconds;
//   - a client half-close reaches the upstream as a half-close, and an upstream close or error
//     closes both sides.
//
// --health serves HTTP 200 on /healthz for the kubelet probes, on its own port, so a probe never
// reaches a route. The relay logs compact JSON to stdout and exports OTLP, as package
// internal/telemetry describes. A configuration error is one JSON error line and exit status 2.
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
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	name             = "relay"
	dialTimeout      = 5 * time.Second
	firstByteTimeout = 10 * time.Second
	keepAlive        = 30 * time.Second
	// shutdownTimeout bounds the telemetry flush.
	shutdownTimeout = 15 * time.Second
	exitConfig      = 2
	// firstReadSize is the most that the relay reads before it dials the upstream.
	firstReadSize = 32 << 10
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)
	code := execute(ctx, os.Args[1:], os.Stdout)
	stop()
	os.Exit(code)
}

type route struct {
	listen   int
	upstream string
}

type routeFlags []string

func (r *routeFlags) String() string     { return strings.Join(*r, ",") }
func (r *routeFlags) Set(v string) error { *r = append(*r, v); return nil }

// parseRoutes reads each <listen port>=<host:port>. A listen port may appear once.
func parseRoutes(vals []string) ([]route, error) {
	if len(vals) == 0 {
		return nil, errors.New("give at least one --route <listen port>=<host:port>")
	}
	var routes []route
	for _, v := range vals {
		port, upstream, ok := strings.Cut(v, "=")
		if !ok {
			return nil, fmt.Errorf("--route %q is not <listen port>=<host:port>", v)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--route %q: the listen port is not a number from 1 to 65535", v)
		}
		host, uport, err := net.SplitHostPort(upstream)
		if err != nil {
			return nil, fmt.Errorf("--route %q: the upstream is not host:port: %w", v, err)
		}
		if p, err := strconv.Atoi(uport); host == "" || err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("--route %q: the upstream needs a host and a port from 1 to 65535", v)
		}
		if slices.ContainsFunc(routes, func(r route) bool { return r.listen == n }) {
			return nil, fmt.Errorf("--route names the listen port %d twice", n)
		}
		routes = append(routes, route{listen: n, upstream: upstream})
	}
	return routes, nil
}

type config struct {
	routes []route
	health string
}

func parse(args []string) (config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var routes routeFlags
	fs.Var(&routes, "route", "<listen port>=<host:port>, repeatable")
	health := fs.String("health", "", "address of the HTTP health listener, for example :8080")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	parsed, err := parseRoutes(routes)
	if err != nil {
		return config{}, err
	}
	if *health != "" {
		if _, port, err := net.SplitHostPort(*health); err != nil || port == "" {
			return config{}, fmt.Errorf("--health %q is not [host]:port", *health)
		}
	}
	return config{routes: parsed, health: *health}, nil
}

// execute parses the flags, starts telemetry and serves every route until ctx ends.
func execute(ctx context.Context, args []string, stdout io.Writer) int {
	cfg, err := parse(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	tel, err := telemetry.Start(ctx, name, stdout)
	if err != nil {
		cli.Fail(stdout, name, fmt.Errorf("start telemetry: %w", err))
		return 1
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := tel.Shutdown(sctx); err != nil {
			slog.New(slog.NewJSONHandler(stdout, nil)).Warn("telemetry shutdown", "error", err.Error())
		}
	}()
	if err := run(ctx, cfg, tel); err != nil {
		tel.Log.Error(name+" failed", "error", err.Error())
		return 1
	}
	tel.Log.Info("stopped")
	return 0
}

func run(ctx context.Context, cfg config, tel *telemetry.T) error {
	conns, err := tel.Meter.Int64Counter("relay.connections",
		metric.WithDescription("Client connections that the relay closed, by listen port and result"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var listeners []net.Listener
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	for _, r := range cfg.routes {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(r.listen))
		if err != nil {
			return err
		}
		listeners = append(listeners, ln)
	}
	errs := make(chan error, len(cfg.routes)+1)
	var wg sync.WaitGroup
	for i, r := range cfg.routes {
		rl := &relay{upstream: r.upstream, dialTimeout: dialTimeout, firstByteTimeout: firstByteTimeout, keepAlive: keepAlive,
			log: tel.Log.With("listen_port", r.listen, "upstream", r.upstream), conns: conns,
			attrs: []attribute.KeyValue{attribute.Int("listen.port", r.listen)}}
		ln := listeners[i]
		wg.Go(func() { errs <- rl.serve(ctx, ln) })
	}
	if cfg.health != "" {
		srv := &http.Server{Addr: cfg.health, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		})}
		stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
		defer stop()
		wg.Go(func() {
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("health listener: %w", err)
			}
		})
	}
	var first error
	select {
	case <-ctx.Done():
	case first = <-errs:
	}
	cancel()
	wg.Wait()
	return first
}

// relay serves one route.
type relay struct {
	upstream                                 string
	dialTimeout, firstByteTimeout, keepAlive time.Duration
	log                                      *slog.Logger
	// conns counts the ended connections, with attrs. It may be nil.
	conns metric.Int64Counter
	attrs []attribute.KeyValue
}

// serve accepts on ln until ctx ends, then closes every open connection and waits for them.
func (r *relay) serve(ctx context.Context, ln net.Listener) error {
	r.log.Info("listening", "addr", ln.Addr().String())
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	var pause time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			pause = min(max(2*pause, 5*time.Millisecond), time.Second)
			r.log.Warn("accept failed", "error", err.Error(), "retry_in", pause.String())
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(pause):
			}
			continue
		}
		pause = 0
		wg.Go(func() { r.handle(ctx, c) })
	}
}

// handle waits for the first bytes of the client, dials the upstream and pipes both ways.
func (r *relay) handle(ctx context.Context, down net.Conn) {
	start := time.Now()
	client := down.RemoteAddr().String()
	defer func() { _ = down.Close() }()
	setKeepAlive(down, r.keepAlive)
	done := func(result string, err error, sent, received int64) {
		attrs := []any{"client", client, "result", result, "duration", time.Since(start).String(),
			"bytes_up", sent, "bytes_down", received}
		if err != nil {
			attrs = append(attrs, "error", err.Error())
		}
		level := slog.LevelInfo
		if result != "closed" && result != "stopped" {
			level = slog.LevelWarn
		}
		r.log.Log(ctx, level, "connection ended", attrs...)
		if r.conns != nil {
			kv := append(slices.Clone(r.attrs), attribute.String("result", result))
			r.conns.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(kv...))
		}
	}
	buf := make([]byte, firstReadSize)
	_ = down.SetReadDeadline(time.Now().Add(r.firstByteTimeout))
	n, err := down.Read(buf)
	_ = down.SetReadDeadline(time.Time{})
	if n == 0 {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			done("first_byte_timeout", nil, 0, 0)
		} else {
			done("client_closed_early", err, 0, 0)
		}
		return
	}
	d := net.Dialer{Timeout: r.dialTimeout, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: r.keepAlive, Interval: r.keepAlive}}
	up, err := d.DialContext(ctx, "tcp", r.upstream)
	if err != nil {
		done("upstream_unavailable", err, 0, 0)
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := up.Write(buf[:n]); err != nil {
		done("upstream_write_failed", err, 0, 0)
		return
	}
	sent, received, result, err := pipe(ctx, down, up)
	done(result, err, sent+int64(n), received)
}

// pipe copies both ways. A client EOF half-closes the upstream, and the copy from the upstream
// goes on. An upstream EOF, an error on either side or the end of ctx closes both sides.
func pipe(ctx context.Context, down, up net.Conn) (sent, received int64, result string, err error) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = down.Close()
			_ = up.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	upDone := make(chan error, 1)
	go func() {
		n, err := io.Copy(up, down)
		sent = n
		if err == nil {
			// The client half-closed. The upstream sees EOF and may still answer.
			if cw, ok := up.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
				upDone <- nil
				return
			}
		}
		closeBoth()
		upDone <- err
	}()
	received, downErr := io.Copy(down, up)
	closeBoth()
	upErr := <-upDone
	switch {
	case ctx.Err() != nil:
		return sent, received, "stopped", nil
	case downErr != nil && !errors.Is(downErr, net.ErrClosed):
		return sent, received, "upstream_error", downErr
	case upErr != nil && !errors.Is(upErr, net.ErrClosed):
		return sent, received, "client_error", upErr
	}
	return sent, received, "closed", nil
}

func setKeepAlive(c net.Conn, period time.Duration) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: period, Interval: period})
	}
}
