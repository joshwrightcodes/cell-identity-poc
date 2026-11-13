// Command mgmtd is the management plane process. It signs the spec and the records of one
// environment, serves the spec to envd over mTLS, binds cells through a server-only TLS listener,
// and answers local commands on an admin socket.
//
//	mgmtd serve --intent <file> --peer-bundle <file> --peer-trust-domain <td> --allow-id <id> --hostsvc-addr <host:port> --hostsvc-server-name <name> --hostsvc-pin <file> --public-configmap <ns>/<name> [--data-dir /var/lib/mgmtd] [--api-listen :8446] [--bind-listen :8447] [--health-listen :8080] [--admin-socket /run/mgmtd/ctl/admin.sock] [--hostsvc-timeout 10s] [--check-every 15m]
//	mgmtd reset-state [--data-dir /var/lib/mgmtd]
//	mgmtd ctl [--socket <path>] [--expect-seq <n>] status | records | pubkey | keys --cell <c> | keycheck --cell <c> | restore --revision <n|latest> | rotate-key
//
// serve takes its SVID from the Workload API at SPIFFE_ENDPOINT_SOCKET. Every log line is compact
// JSON on stdout. Logs, traces and metrics also go out as OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is
// set. reset-state renames the state file and the key file in the data directory, so the next serve starts fresh
// under a new key. The signing key stays in the data directory and never reaches logs, arguments or the
// environment.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel/metric"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	name = "mgmtd"
	// sourceTimeout bounds the wait for the first SVID from the Workload API.
	sourceTimeout = 30 * time.Second
	// serverStopTimeout is the one budget for the stop of the three servers, and flushTimeout bounds
	// the telemetry flush. Together they stay below the 30 s termination grace of a pod.
	serverStopTimeout = 8 * time.Second
	flushTimeout      = 10 * time.Second
	exitConfig        = 2
)

// deps holds what a test replaces.
type deps struct {
	telemetry func(ctx context.Context, stdout io.Writer) (*telemetry.T, error)
	kube      func() (kubernetes.Interface, error)
	svids     func(ctx context.Context) (x509svid.Source, func(), error)
	nofile    func() (uint64, error)
	// beforePlane runs before the plane loads. Tests use it to hold the load.
	beforePlane func()
}

func realDeps() deps {
	return deps{
		telemetry: func(ctx context.Context, stdout io.Writer) (*telemetry.T, error) {
			return telemetry.Start(ctx, name, stdout)
		},
		kube: func() (kubernetes.Interface, error) {
			cfg, err := rest.InClusterConfig()
			if err != nil {
				return nil, fmt.Errorf("in-cluster config: %w", err)
			}
			return kubernetes.NewForConfig(cfg)
		},
		svids: func(ctx context.Context) (x509svid.Source, func(), error) {
			sctx, cancel := context.WithTimeout(ctx, sourceTimeout)
			defer cancel()
			src, err := workloadapi.NewX509Source(sctx)
			if err != nil {
				return nil, nil, fmt.Errorf("x509 source from the workload api: %w", err)
			}
			return src, func() { _ = src.Close() }, nil
		},
		nofile: func() (uint64, error) {
			var r syscall.Rlimit
			if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
				return 0, err
			}
			return uint64(r.Cur), nil
		},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second signal ends the process at once.
	context.AfterFunc(ctx, stop)
	code := execute(ctx, os.Args[1:], os.Stdout, realDeps())
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, stdout io.Writer, d deps) int {
	if len(args) == 0 {
		cli.Fail(stdout, name, errors.New("usage: mgmtd serve|ctl|reset-state [flags]"))
		return exitConfig
	}
	switch args[0] {
	case "serve":
		cfg, err := parseServe(args[1:])
		if err != nil {
			cli.Fail(stdout, name, err)
			return exitConfig
		}
		err = serve(ctx, cfg, stdout, d)
		var ce *configError
		switch {
		case err == nil:
			return 0
		case errors.As(err, &ce):
			cli.Fail(stdout, name, err)
			return exitConfig
		default:
			cli.Fail(stdout, name, err)
			return 1
		}
	case "ctl":
		return ctlCommand(ctx, args[1:], stdout)
	case "reset-state":
		return resetCommand(args[1:], stdout, time.Now)
	}
	cli.Fail(stdout, name, fmt.Errorf("unknown command %q; usage: mgmtd serve|ctl|reset-state [flags]", args[0]))
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

type serveConfig struct {
	intent, dataDir                      string
	apiListen, bindListen, healthListen  string
	adminSocket, peerBundle              string
	peerTD                               spiffeid.TrustDomain
	allow                                spiffeid.ID
	hostsvcAddr, hostsvcName, hostsvcPin string
	hostsvcTimeout                       time.Duration
	cmNamespace, cmName                  string
	checkEvery                           time.Duration
}

func parseServe(args []string) (serveConfig, error) {
	fs := newFlags("serve")
	intent := fs.String("intent", "", "intent file")
	dataDir := fs.String("data-dir", "/var/lib/mgmtd", "directory of the signing key and the state")
	apiListen := fs.String("api-listen", ":8446", "address of the mTLS API listener")
	bindListen := fs.String("bind-listen", ":8447", "address of the bind listener")
	health := fs.String("health-listen", ":8080", "address of the health endpoint")
	sock := fs.String("admin-socket", defaultSocket, "path of the admin socket")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the peer trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the API peer")
	allow := fs.String("allow-id", "", "the exact SPIFFE ID of the API peer")
	hAddr := fs.String("hostsvc-addr", "", "address of the host service as host:port")
	hName := fs.String("hostsvc-server-name", "", "server name for the host service certificate")
	hPin := fs.String("hostsvc-pin", "", "PEM file with the pinned host service certificate")
	hTimeout := fs.Duration("hostsvc-timeout", 10*time.Second, "timeout of a host service call")
	cm := fs.String("public-configmap", "", "ConfigMap for the public key, as <namespace>/<name>")
	every := fs.Duration("check-every", 15*time.Minute, "time between key checks of a bound cell")
	if err := parseFlags(fs, args); err != nil {
		return serveConfig{}, err
	}
	var missing []string
	for k, v := range map[string]string{"intent": *intent, "peer-bundle": *bundle, "peer-trust-domain": *td, "allow-id": *allow,
		"hostsvc-addr": *hAddr, "hostsvc-server-name": *hName, "hostsvc-pin": *hPin, "public-configmap": *cm} {
		if v == "" {
			missing = append(missing, "--"+k)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return serveConfig{}, fmt.Errorf("%s required", strings.Join(missing, ", "))
	}
	if *hTimeout <= 0 || *every <= 0 {
		return serveConfig{}, errors.New("--hostsvc-timeout and --check-every must be positive")
	}
	trust, err := spiffeid.TrustDomainFromString(*td)
	if err != nil {
		return serveConfig{}, fmt.Errorf("--peer-trust-domain: %w", err)
	}
	id, err := spiffeid.FromString(*allow)
	if err != nil {
		return serveConfig{}, fmt.Errorf("--allow-id: %w", err)
	}
	if id.TrustDomain() != trust {
		return serveConfig{}, fmt.Errorf("--allow-id %s is not in --peer-trust-domain %s", id, trust)
	}
	ns, cmName, ok := strings.Cut(*cm, "/")
	if !ok || ns == "" || cmName == "" || strings.Contains(cmName, "/") {
		return serveConfig{}, errors.New("--public-configmap must be <namespace>/<name>")
	}
	return serveConfig{intent: *intent, dataDir: *dataDir, apiListen: *apiListen, bindListen: *bindListen, healthListen: *health,
		adminSocket: *sock, peerBundle: *bundle, peerTD: trust, allow: id, hostsvcAddr: *hAddr, hostsvcName: *hName,
		hostsvcPin: *hPin, hostsvcTimeout: *hTimeout, cmNamespace: ns, cmName: cmName, checkEvery: *every}, nil
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

func serve(ctx context.Context, cfg serveConfig, stdout io.Writer, d deps) error {
	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	var meter metric.Meter
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

	// Liveness answers as soon as the process runs, also during the wait for the first SVID.
	// Readiness follows the plane: 503 until it has loaded.
	var ready atomic.Bool
	healthLn, err := net.Listen("tcp", cfg.healthListen)
	if err != nil {
		return fmt.Errorf("health listener: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "loading", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	health := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	logger.Info("health_listening", "addr", healthLn.Addr().String())
	spawn("health", func() error { return ignoreClosed(health.Serve(healthLn)) })
	defer health.Close()

	soft, err := d.nofile()
	if err != nil {
		return fmt.Errorf("read the limit on open files: %w", err)
	}
	if need := mgmt.FilesNeeded(); soft < need {
		return &configError{fmt.Errorf("soft limit on open files is %d, below the %d that the listeners need", soft, need)}
	}
	pinPEM, err := os.ReadFile(cfg.hostsvcPin)
	if err != nil {
		return &configError{fmt.Errorf("--hostsvc-pin: %w", err)}
	}
	pin, err := hostsvc.PinFromPEM(pinPEM)
	if err != nil {
		return &configError{fmt.Errorf("--hostsvc-pin: %w", err)}
	}
	intent, err := mgmt.LoadIntent(cfg.intent)
	if err != nil {
		return &configError{err}
	}

	svids, closeSVIDs, err := d.svids(ctx)
	if err != nil {
		return err
	}
	defer closeSVIDs()
	kube, err := d.kube()
	if err != nil {
		return err
	}
	keyClient, err := hostsvc.NewKeyClient(hostsvc.KeyClientConfig{
		Addr: cfg.hostsvcAddr, ServerName: cfg.hostsvcName, Pin: pin, SVIDs: svids, Timeout: cfg.hostsvcTimeout,
	})
	if err != nil {
		return &configError{err}
	}

	if d.beforePlane != nil {
		d.beforePlane()
	}
	plane, err := mgmt.NewPlane(mgmt.Config{
		Intent:     intent,
		KeyPath:    filepath.Join(cfg.dataDir, keyFileName),
		Store:      &mgmt.FileStore{Path: filepath.Join(cfg.dataDir, stateFileName), Log: logger},
		Keys:       keyClient,
		Log:        logger,
		Meter:      meter,
		CheckEvery: cfg.checkEvery,
	})
	if err != nil {
		return fmt.Errorf("start the plane: %w", err)
	}
	ready.Store(true)

	apiTLS := mgmt.APIServerTLS(svids, mgmt.FileBundleSource(cfg.peerBundle, cfg.peerTD), cfg.allow)
	apiSrv, bindSrv := mgmt.NewServers(
		telemetry.Handler(tracer, "mgmtd.api", mgmt.NewAPIHandler(plane, intent.Env, cfg.allow, logger)),
		telemetry.Handler(tracer, "mgmtd.bind", mgmt.NewBindHandler(plane, logger)),
		apiTLS, mgmt.BindServerTLS(svids))
	apiSrv.ErrorLog, bindSrv.ErrorLog = limitedErrorLog(logger), limitedErrorLog(logger)

	apiRaw, err := net.Listen("tcp", cfg.apiListen)
	if err != nil {
		return fmt.Errorf("api listener: %w", err)
	}
	bindRaw, err := net.Listen("tcp", cfg.bindListen)
	if err != nil {
		_ = apiRaw.Close()
		return fmt.Errorf("bind listener: %w", err)
	}

	publisher := newKeyPublisher(plane.PublicKey, func(ctx context.Context, pub ed25519.PublicKey) error {
		return PublishPublicKey(ctx, kube, cfg.cmNamespace, cfg.cmName, pub)
	})
	adminLn, err := listenAdmin(cfg.adminSocket)
	if err != nil {
		_ = apiRaw.Close()
		_ = bindRaw.Close()
		return err
	}

	spawn("api", func() error { return ignoreClosed(apiSrv.Serve(mgmt.ListenAPI(apiRaw, apiSrv.TLSConfig, logger))) })
	spawn("bind", func() error { return ignoreClosed(bindSrv.Serve(mgmt.ListenBind(bindRaw, bindSrv.TLSConfig, logger))) })
	spawn("admin", func() error { return serveAdmin(ctx, adminLn, mgmt.NewAdminHandler(plane, publisher.adminPublish)) })
	wg.Go(func() { _ = plane.RunChecks(ctx) })
	wg.Go(func() { publisher.run(ctx, logger, time.Second, 5*time.Minute) })

	logger.Info("listening", "env", intent.Env, "api", apiRaw.Addr().String(), "bind", bindRaw.Addr().String(),
		"health", healthLn.Addr().String(), "admin", cfg.adminSocket, "cells", cellNames(intent))

	var failure error
	select {
	case <-ctx.Done():
	case failure = <-errc:
	}
	cancel()
	sctx, stop := context.WithTimeout(context.Background(), serverStopTimeout)
	defer stop()
	for _, s := range []*http.Server{apiSrv, bindSrv, health} {
		if s.Shutdown(sctx) != nil {
			_ = s.Close()
		}
	}
	logger.Info("stopped")
	return failure
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func cellNames(in mgmt.Intent) []string {
	var out []string
	for _, c := range in.Cells {
		out = append(out, c.Name)
	}
	return out
}
