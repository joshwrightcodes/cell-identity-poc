// Command cellgw is the cell gateway. It takes celld streams and bind requests from the cells,
// syncs with envd, and keeps the operation queue and the outbox in SQLite.
//
//	cellgw serve --env <env> --envd-id <spiffe id> --spec-key-file <file> [--cell-node <cell>=<ip> ...] [--data-dir /var/lib/cellgw] [--stream-listen :8450] [--bind-listen :8451] [--envd-listen :8452] [--health-listen :8080] [--admin-socket /run/cellgw/admin.sock] [--replica-cap 2]
//	cellgw ctl [--socket <path>] status | queue --cell <c> | enqueue --cell <c> [--replay] | inject | outbox
//
// serve takes its SVID from the Workload API at SPIFFE_ENDPOINT_SOCKET. Every log line is compact
// JSON on stdout. Logs, traces and metrics also go out as OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is
// set. ctl prints one JSON line. enqueue reads one signed operation envelope and inject reads one
// outbox item, both on standard input.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gateway"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	name              = "cellgw"
	sourceTimeout     = 30 * time.Second
	serverStopTimeout = 8 * time.Second
	flushTimeout      = 10 * time.Second
	pruneEvery        = time.Minute
	exitConfig        = 2
	usage             = "usage: cellgw serve|ctl [flags]"
)

// celldSubject is the service account that signs the proofs of the cells.
var celldSubject = record.Subject{Namespace: "cell-identity-system", ServiceAccount: "celld"}

// svidSource is what serve needs from the Workload API: the SVID, and the bundles that check the
// client certificates.
type svidSource interface {
	x509svid.Source
	x509bundle.Source
}

// deps holds what a test replaces.
type deps struct {
	telemetry func(ctx context.Context, stdout io.Writer) (*telemetry.T, error)
	svids     func(ctx context.Context) (svidSource, func(), error)
}

func realDeps() deps {
	return deps{
		telemetry: func(ctx context.Context, stdout io.Writer) (*telemetry.T, error) {
			return telemetry.Start(ctx, name, stdout)
		},
		svids: func(ctx context.Context) (svidSource, func(), error) {
			sctx, cancel := context.WithTimeout(ctx, sourceTimeout)
			defer cancel()
			src, err := workloadapi.NewX509Source(sctx)
			if err != nil {
				return nil, nil, fmt.Errorf("x509 source from the workload api: %w", err)
			}
			return src, func() { _ = src.Close() }, nil
		},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second signal ends the process at once.
	context.AfterFunc(ctx, stop)
	code := execute(ctx, os.Args[1:], os.Stdin, os.Stdout, realDeps())
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, d deps) int {
	if len(args) == 0 {
		cli.Fail(stdout, name, errors.New(usage))
		return exitConfig
	}
	switch args[0] {
	case "serve":
		cfg, err := parseServe(args[1:])
		if err != nil {
			cli.Fail(stdout, name, err)
			return exitConfig
		}
		if err := serve(ctx, cfg, stdout, d); err != nil {
			cli.Fail(stdout, name, err)
			var ce *configError
			if errors.As(err, &ce) {
				return exitConfig
			}
			return 1
		}
		return 0
	case "ctl":
		return ctlCommand(ctx, args[1:], stdin, stdout)
	}
	cli.Fail(stdout, name, fmt.Errorf("unknown command %q; %s", args[0], usage))
	return exitConfig
}

// configError is an error of the settings, which ends the process with status 2.
type configError struct{ err error }

func (e *configError) Error() string { return e.err.Error() }
func (e *configError) Unwrap() error { return e.err }

func newFlags(mode string) *flag.FlagSet {
	fs := flag.NewFlagSet(name+" "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

// cellNodes is a repeatable flag: <cell>=<ip>.
type cellNodes map[string]netip.Addr

func (c cellNodes) String() string { return fmt.Sprint(map[string]netip.Addr(c)) }

func (c cellNodes) Set(v string) error {
	cell, ip, ok := strings.Cut(v, "=")
	if !ok || !spec.ValidName(cell) {
		return fmt.Errorf("%q is not <cell>=<ip>", v)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("%q: %w", v, err)
	}
	if _, dup := c[cell]; dup {
		return fmt.Errorf("cell %q appears twice", cell)
	}
	c[cell] = addr.Unmap()
	return nil
}

type serveConfig struct {
	dataDir                                                         string
	streamListen, bindListen, envdListen, healthListen, adminSocket string
	env                                                             string
	envd                                                            spiffeid.ID
	key                                                             ed25519.PublicKey
	operatorKeys                                                    []ed25519.PublicKey
	nodes                                                           map[string]netip.Addr
	replicaCap                                                      int
}

// readSpecKey reads the pinned public key: the standard base64 of its 32 raw bytes, as in the
// ConfigMap key spec.pub.
func readSpecKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--spec-key-file: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("--spec-key-file: not standard base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("--spec-key-file: key has %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

func parseServe(args []string) (serveConfig, error) {
	fs := newFlags("serve")
	dataDir := fs.String("data-dir", "/var/lib/cellgw", "directory of the queue database")
	stream := fs.String("stream-listen", ":8450", "address of the celld stream listener")
	bind := fs.String("bind-listen", ":8451", "address of the bind listener")
	envdAddr := fs.String("envd-listen", ":8452", "address of the envd API listener")
	health := fs.String("health-listen", ":8080", "address of the health endpoint")
	sock := fs.String("admin-socket", defaultSocket, "path of the admin socket")
	env := fs.String("env", "", "environment name")
	envdID := fs.String("envd-id", "", "the exact SPIFFE ID of envd")
	keyFile := fs.String("spec-key-file", "", "file with the base64 public key that signs specs")
	opKeyFile := fs.String("operator-key-file", "", "file with the operator public keys that sign local revocations, one or two base64 lines")
	replicas := fs.Int("replica-cap", gateway.DefaultReplicaCap, "streams of distinct pods that one cell may hold")
	nodes := cellNodes{}
	fs.Var(nodes, "cell-node", "node address of a cell, as <cell>=<ip>; repeat for each cell")
	if err := parseFlags(fs, args); err != nil {
		return serveConfig{}, err
	}
	var missing []string
	for k, v := range map[string]string{"env": *env, "envd-id": *envdID, "spec-key-file": *keyFile} {
		if v == "" {
			missing = append(missing, "--"+k)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return serveConfig{}, fmt.Errorf("%s required", strings.Join(missing, ", "))
	}
	if *replicas < 1 {
		return serveConfig{}, errors.New("--replica-cap must be at least 1")
	}
	id, err := spiffeid.FromString(*envdID)
	if err != nil {
		return serveConfig{}, fmt.Errorf("--envd-id: %w", err)
	}
	key, err := readSpecKey(*keyFile)
	if err != nil {
		return serveConfig{}, err
	}
	var opKeys []ed25519.PublicKey
	if *opKeyFile != "" {
		raw, err := os.ReadFile(*opKeyFile)
		if err != nil {
			return serveConfig{}, fmt.Errorf("--operator-key-file: %w", err)
		}
		if opKeys, err = revoke.ParseKeys(raw); err != nil {
			return serveConfig{}, fmt.Errorf("--operator-key-file: %w", err)
		}
	}
	return serveConfig{operatorKeys: opKeys, dataDir: *dataDir, streamListen: *stream, bindListen: *bind, envdListen: *envdAddr,
		healthListen: *health, adminSocket: *sock, env: *env, envd: id, key: key, nodes: nodes, replicaCap: *replicas}, nil
}

// limitedErrorLog sends the errors of an HTTP server to log, at most one line in each window.
func limitedErrorLog(l *slog.Logger) *log.Logger {
	limit := lograte.New(10*time.Second, 16, time.Now)
	return log.New(writerFunc(func(p []byte) (int, error) {
		if _, ok, suppressed, _ := limit.Allow("server_error"); ok {
			l.Warn("server_error", "error", strings.TrimSpace(string(p)), "suppressed", suppressed)
		}
		return len(p), nil
	}), "", 0)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func serve(ctx context.Context, cfg serveConfig, stdout io.Writer, d deps) error {
	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	meter := metric.Meter(metricnoop.NewMeterProvider().Meter(name))
	tracer := tracenoop.NewTracerProvider().Tracer(name)
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		tel, err := d.telemetry(ctx, stdout)
		if err != nil {
			return fmt.Errorf("start telemetry: %w", err)
		}
		logger, meter, tracer = tel.Log, tel.Meter, tel.Tracer
		defer func() {
			// ctx may have ended, so the flush gets a context of its own.
			sctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
			defer cancel()
			if err := tel.Shutdown(sctx); err != nil {
				slog.New(slog.NewJSONHandler(stdout, nil)).Warn("telemetry shutdown", "error", err.Error())
			}
		}()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	defer wg.Wait()
	errc := make(chan error, 8)
	spawn := func(what string, f func() error) {
		wg.Go(func() {
			if err := f(); err != nil {
				errc <- fmt.Errorf("%s: %w", what, err)
			}
		})
	}

	if err := os.MkdirAll(cfg.dataDir, 0o700); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	notifier := gwapi.NewNotifier()
	st, err := gateway.Open(ctx, filepath.Join(cfg.dataDir, "queue.db"), notifier, nil, logger)
	if err != nil {
		return err
	}
	defer st.Close()
	if len(cfg.operatorKeys) > 0 {
		// The stored envelopes verify again under the pinned keys, so the overlay survives a restart.
		if err := st.SetRevocations(ctx, nil, cfg.operatorKeys, cfg.env); err != nil {
			return err
		}
	} else {
		logger.Info("revocation_overlay_off", "reason", "no --operator-key-file")
	}

	// Liveness answers as soon as the store is open. Readiness waits for the SVID.
	var ready atomic.Bool
	healthLn, err := net.Listen("tcp", cfg.healthListen)
	if err != nil {
		return fmt.Errorf("health listener: %w", err)
	}
	health := &http.Server{Handler: gateway.NewHealthHandler(st, ready.Load), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	spawn("health", func() error { return ignoreClosed(health.Serve(healthLn)) })
	defer health.Close()

	svids, closeSVIDs, err := d.svids(ctx)
	if err != nil {
		return err
	}
	defer closeSVIDs()
	ready.Store(true)

	td, err := spiffeid.TrustDomainFromString(cfg.env + ".env.poc.internal")
	if err != nil {
		return &configError{fmt.Errorf("--env: %w", err)}
	}
	streamH := gateway.NewStreamHandler(st, gateway.StreamConfig{
		ReplicaCap: cfg.replicaCap, Subject: celldSubject, Notifier: notifier, Log: logger, Meter: meter,
	})
	bindH := gateway.NewBindHandler(st, gateway.BindConfig{CellNodes: cfg.nodes, Subject: celldSubject, Log: logger, Meter: meter})
	envdH := gateway.NewEnvdHandler(st, []ed25519.PublicKey{cfg.key}, cfg.envd, streamH.Streams, bindH.LastRefusals, logger,
		gateway.WithKeyHints(streamH.TakeHints), gateway.WithEnv(cfg.env), gateway.WithOperatorKeys(cfg.operatorKeys))
	if err := gateway.RegisterGauges(meter, st, streamH.Streams); err != nil {
		return fmt.Errorf("register metrics: %w", err)
	}

	streamTLS := gateway.StreamServerTLS(svids, svids, td)
	streamSrv := gateway.NewStreamServer(streamH, streamTLS, tracer)
	bindTLS := gateway.BindServerTLS(svids)
	bindSrv := gateway.NewBindServer(bindH, bindTLS, tracer)
	envdTLS := gateway.EnvdServerTLS(svids, svids, cfg.envd)
	envdSrv := gateway.NewEnvdServer(envdH, envdTLS, tracer)
	for _, s := range []*http.Server{streamSrv, bindSrv, envdSrv} {
		s.ErrorLog = limitedErrorLog(logger)
	}

	var raws []net.Listener
	closeRaws := func() {
		for _, l := range raws {
			_ = l.Close()
		}
	}
	for _, a := range []struct{ what, addr string }{{"stream", cfg.streamListen}, {"bind", cfg.bindListen}, {"envd", cfg.envdListen}} {
		l, err := net.Listen("tcp", a.addr)
		if err != nil {
			closeRaws()
			return fmt.Errorf("%s listener: %w", a.what, err)
		}
		raws = append(raws, l)
	}
	adminLn, err := listenAdmin(cfg.adminSocket)
	if err != nil {
		closeRaws()
		return err
	}

	status := func() any {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		s, err := st.Stats(sctx)
		if err != nil {
			return map[string]string{"error": err.Error()}
		}
		for cell, n := range streamH.Streams() {
			s.Streams[cell] = n
		}
		for cell, r := range bindH.LastRefusals() {
			s.LastBindRefusal[cell] = r
		}
		return s
	}
	spawn("stream", func() error { return ignoreClosed(streamSrv.Serve(gateway.ListenStream(raws[0], streamTLS))) })
	spawn("bind", func() error { return ignoreClosed(bindSrv.Serve(gateway.ListenBind(raws[1], bindTLS))) })
	spawn("envd", func() error { return ignoreClosed(envdSrv.Serve(gateway.ListenEnvd(raws[2], envdTLS))) })
	spawn("admin", func() error { return serveAdmin(ctx, adminLn, gateway.NewAdminHandler(st, status)) })
	wg.Go(func() { pruneLoop(ctx, st, logger, pruneEvery) })

	logger.Info("listening", "env", cfg.env, "stream", raws[0].Addr().String(), "bind", raws[1].Addr().String(),
		"envd", raws[2].Addr().String(), "health", healthLn.Addr().String(), "admin", cfg.adminSocket, "epoch", st.Epoch())

	var failure error
	select {
	case <-ctx.Done():
	case failure = <-errc:
	}
	cancel()
	sctx, stop := context.WithTimeout(context.Background(), serverStopTimeout)
	defer stop()
	for _, s := range []*http.Server{streamSrv, bindSrv, envdSrv, health} {
		if s.Shutdown(sctx) != nil {
			_ = s.Close()
		}
	}
	logger.Info("stopped")
	return failure
}

// pruneLoop removes the done items and the old outcomes every `every`. An outcome lives for the
// retention of the store plus at most one period.
func pruneLoop(ctx context.Context, st *gateway.Store, log *slog.Logger, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := st.Prune(ctx); err != nil && ctx.Err() == nil {
				log.Warn("prune_failed", "error", err.Error())
			}
		}
	}
}
