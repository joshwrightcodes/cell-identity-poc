// Command cell-controller reads the signed provisioning steps that envd keeps in a ConfigMap,
// verifies them under its own pinned spec keys, sends them to the host service over mutual TLS, and
// reports their progress in a second ConfigMap.
//
//	cell-controller run --env <env> --steps-configmap <ns>/<name> --status-configmap <ns>/<name>
//	  --spec-key-dir <dir> --hostsvc-addr <host:port> --hostsvc-server-name <name>
//	  --hostsvc-pin <file> [--health-listen :8080] [--interval 10s]
//
// run takes its SVID from the Workload API at SPIFFE_ENDPOINT_SOCKET. It trusts the host service
// only through the certificate in --hostsvc-pin. Every file in --spec-key-dir that ends in .pub is
// a trusted spec key, so a rotation can stage a second key. Every log line is compact JSON on
// stdout, and logs, traces and metrics also go out as OTLP through package internal/telemetry.
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
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellctl"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spireclient"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	name = "cell-controller"
	// sourceTimeout bounds the wait for the first SVID from the Workload API.
	sourceTimeout = 30 * time.Second
	// shutdownTimeout bounds the whole telemetry flush.
	shutdownTimeout = 15 * time.Second
	// kubeTimeout bounds each request to the Kubernetes API.
	kubeTimeout = 15 * time.Second
	// exitConfig is the status of a configuration error.
	exitConfig = 2
)

// deps holds what a test replaces.
type deps struct {
	telemetry func(ctx context.Context, stdout io.Writer) (*telemetry.T, error)
	kube      func() (kubernetes.Interface, error)
	svids     func(ctx context.Context) (x509svid.Source, func(), error)
	// host replaces the client of the host service.
	host func(cfg runConfig, svids x509svid.Source) (cellctl.HostClient, error)
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
			cfg.Timeout = kubeTimeout
			return kubernetes.NewForConfig(cfg)
		},
		svids: func(ctx context.Context) (x509svid.Source, func(), error) {
			sctx, cancel := context.WithTimeout(ctx, sourceTimeout)
			defer cancel()
			src, err := workloadapi.NewX509Source(sctx, spireclient.SourceOptions())
			if err != nil {
				return nil, nil, fmt.Errorf("x509 source from the workload api: %w", err)
			}
			return src, func() { _ = src.Close() }, nil
		},
		host: func(cfg runConfig, svids x509svid.Source) (cellctl.HostClient, error) {
			c, err := hostsvc.NewStepClient(hostsvc.KeyClientConfig{
				Addr: cfg.hostAddr, ServerName: cfg.hostServerName, Pin: cfg.pin, SVIDs: svids,
			})
			if err != nil {
				return nil, err
			}
			return hostClient{c}, nil
		},
	}
}

// hostClient adapts the step client, whose Put reads the step ID from the envelope.
type hostClient struct{ c *hostsvc.StepClient }

func (h hostClient) Put(ctx context.Context, _ string, envelope []byte) (mgmtapi.StepStatus, error) {
	return h.c.Put(ctx, envelope)
}

func (h hostClient) Get(ctx context.Context, id string) (mgmtapi.StepStatus, error) {
	return h.c.Get(ctx, id)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second signal ends the process at once, also during the flush.
	context.AfterFunc(ctx, stop)
	code := execute(ctx, os.Args[1:], os.Stdout, realDeps())
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, stdout io.Writer, d deps) int {
	if len(args) == 0 {
		cli.Fail(stdout, name, errors.New("usage: cell-controller run [flags]"))
		return exitConfig
	}
	if args[0] != "run" {
		cli.Fail(stdout, name, fmt.Errorf("unknown mode %q", args[0]))
		return exitConfig
	}
	cfg, err := parseRun(args[1:])
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return runCommand(ctx, cfg, stdout, d)
}

type runConfig struct {
	env            string
	namespace      string
	stepsName      string
	statusName     string
	keyDir         string
	hostAddr       string
	hostServerName string
	pin            []byte
	healthListen   string
	interval       time.Duration
}

func parseRun(args []string) (runConfig, error) {
	fs := flag.NewFlagSet(name+" run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("env", "", "environment name")
	steps := fs.String("steps-configmap", "", "ConfigMap that holds the signed steps, as <namespace>/<name>")
	status := fs.String("status-configmap", "", "ConfigMap that receives the step status, as <namespace>/<name>")
	keyDir := fs.String("spec-key-dir", "", "directory with the base64 public keys (*.pub) that sign specs and steps")
	addr := fs.String("hostsvc-addr", "", "address of the host service as <ip>:<port>")
	serverName := fs.String("hostsvc-server-name", "", "server name for the TLS handshake with the host service")
	pinFile := fs.String("hostsvc-pin", "", "PEM file with the certificate of the host service")
	health := fs.String("health-listen", ":8080", "address of the health endpoint")
	interval := fs.Duration("interval", cellctl.DefaultInterval, "time between reads of the steps ConfigMap")
	if err := fs.Parse(args); err != nil {
		return runConfig{}, err
	}
	if fs.NArg() > 0 {
		return runConfig{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := required(map[string]string{
		"env": *env, "steps-configmap": *steps, "status-configmap": *status, "spec-key-dir": *keyDir,
		"hostsvc-addr": *addr, "hostsvc-server-name": *serverName, "hostsvc-pin": *pinFile,
	}); err != nil {
		return runConfig{}, err
	}
	if *interval <= 0 {
		return runConfig{}, errors.New("--interval must be positive")
	}
	if !spec.ValidName(*env) {
		return runConfig{}, errors.New("--env must be a DNS label")
	}
	stepsNS, stepsName, err := configMapRef("steps-configmap", *steps)
	if err != nil {
		return runConfig{}, err
	}
	statusNS, statusName, err := configMapRef("status-configmap", *status)
	if err != nil {
		return runConfig{}, err
	}
	if stepsNS != statusNS {
		return runConfig{}, errors.New("--steps-configmap and --status-configmap must be in one namespace")
	}
	if fi, err := os.Stat(*keyDir); err != nil || !fi.IsDir() {
		return runConfig{}, errors.New("--spec-key-dir must be a directory")
	}
	if _, port, err := net.SplitHostPort(*addr); err != nil {
		return runConfig{}, fmt.Errorf("--hostsvc-addr: %w", err)
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return runConfig{}, errors.New("--hostsvc-addr: the port is not a number from 1 to 65535")
	}
	pem, err := os.ReadFile(*pinFile)
	if err != nil {
		return runConfig{}, fmt.Errorf("--hostsvc-pin: %w", err)
	}
	pin, err := hostsvc.PinFromPEM(pem)
	if err != nil {
		return runConfig{}, fmt.Errorf("--hostsvc-pin: %w", err)
	}
	return runConfig{env: *env, namespace: stepsNS, stepsName: stepsName, statusName: statusName, keyDir: *keyDir,
		hostAddr: *addr, hostServerName: *serverName, pin: pin, healthListen: *health, interval: *interval}, nil
}

func required(values map[string]string) error {
	var missing []string
	for k, v := range values {
		if v == "" {
			missing = append(missing, "--"+k)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("%s required", strings.Join(missing, ", "))
	}
	return nil
}

// configMapRef splits "namespace/name".
func configMapRef(flagName, v string) (namespace, cmName string, err error) {
	ns, n, ok := strings.Cut(v, "/")
	if !ok || ns == "" || n == "" || strings.Contains(n, "/") {
		return "", "", fmt.Errorf("--%s must be <namespace>/<name>", flagName)
	}
	return ns, n, nil
}

func runCommand(ctx context.Context, cfg runConfig, stdout io.Writer, d deps) int {
	tel, err := d.telemetry(ctx, stdout)
	if err != nil {
		cli.Fail(stdout, name, fmt.Errorf("start telemetry: %w", err))
		return 1
	}
	defer func() {
		// ctx may have ended, so the flush gets a context of its own.
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := tel.Shutdown(sctx); err != nil {
			tel.Log.Warn("telemetry shutdown", "error", err.Error())
		}
	}()
	if err := serve(ctx, cfg, tel, d); err != nil {
		tel.Log.Error(name+" failed", "error", err.Error())
		return 1
	}
	tel.Log.Info("stopped")
	return 0
}

func serve(ctx context.Context, cfg runConfig, tel *telemetry.T, d deps) error {
	kube, err := d.kube()
	if err != nil {
		return err
	}
	svids, closeSVIDs, err := d.svids(ctx)
	if err != nil {
		return err
	}
	defer closeSVIDs()
	host, err := d.host(cfg, svids)
	if err != nil {
		return fmt.Errorf("host service client: %w", err)
	}
	ctl, err := cellctl.New(cellctl.Config{
		Env: cfg.env, Namespace: cfg.namespace, StepsName: cfg.stepsName, StatusName: cfg.statusName,
		Client: kube, Keys: hostsvc.KeysFromDir(cfg.keyDir), Host: host, Interval: cfg.interval,
		Log: tel.Log, Meter: tel.Meter,
	})
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.healthListen)
	if err != nil {
		return fmt.Errorf("health listener: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/healthz", healthHandler(ctl))
	health := newHealthServer(mux)
	go func() { _ = health.Serve(ln) }()
	defer func() { _ = health.Close() }()

	tel.Log.Info("cell-controller started", "env", cfg.env, "steps", cfg.namespace+"/"+cfg.stepsName,
		"status", cfg.namespace+"/"+cfg.statusName, "hostsvc", cfg.hostAddr, "health", ln.Addr().String())
	if err := ctl.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// healthHandler answers 200 once the controller has read its steps ConfigMap, and 503 before.
func healthHandler(c *cellctl.Controller) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !c.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
}

// newHealthServer returns the server of the health endpoint, with limits on every phase of a request.
func newHealthServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}
