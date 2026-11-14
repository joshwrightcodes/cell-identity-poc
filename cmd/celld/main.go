// Command celld is the cell daemon. It binds the cluster issuer of its cell to the management
// plane through the cell gateway, claims signed operations on a stream to the gateway, applies them
// and reports the results. It also watches the SPIFFE Workload API and logs the SPIFFE ID of its
// X.509 SVID once for each new SVID.
//
//	celld --cell <name> --env <env> --gateway <host:port> --gateway-bind <host:port> \
//	  --gateway-id <spiffe id> --trust-bundle <file> --op-key-dir <dir> --ops-namespace <namespace>
//
// The bind loop and the stream run in their own goroutines and never stop the SVID watch. The
// environment names the pod: POD_NAME, POD_UID, POD_NAMESPACE and SERVICE_ACCOUNT. Each *.pub file
// in --op-key-dir holds the standard base64 of one operation public key.
//
// Every log line is compact JSON on stdout, and logs, traces and metrics also go out as OTLP, as
// package internal/telemetry describes. SPIFFE_ENDPOINT_SOCKET names the Workload API socket.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bind"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/executor"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	serviceName = "celld"
	// effectGrace is how long an effect may keep running after SIGTERM. It lies inside the 30 s
	// termination grace period of the pod, and leaves time for the telemetry flush.
	effectGrace = 5 * time.Second
	// shutdownTimeout bounds the whole flush. Each provider has its own shorter timeout inside it.
	shutdownTimeout = 15 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second signal ends the process at once, also during the flush.
	context.AfterFunc(ctx, stop)
	code := execute(ctx, os.Args[1:], os.Stdout, deps{
		start: startTelemetry, lookupEnv: os.LookupEnv, kubeClient: inClusterClient, bindRun: bind.Run,
		streamRun: executor.RunStream,
	})
	stop()
	os.Exit(code)
}

type telemetryStarter func(ctx context.Context, stdout io.Writer) (*telemetry.T, error)

// deps holds what execute takes from its environment, so that tests can replace it.
type deps struct {
	start      telemetryStarter
	lookupEnv  func(string) (string, bool)
	kubeClient func() (kubernetes.Interface, error)
	bindRun    func(ctx context.Context, cfg bind.Config) error
	streamRun  func(ctx context.Context, cfg executor.StreamConfig) error
	// effectGrace is how long an effect may run after the first signal. Zero takes effectGrace.
	effectGrace time.Duration
}

// options are the settings that the flags and the environment give.
type options struct {
	cell, env, gateway, gatewayBind, trustBundle, opKeyDir, opsNamespace string
	gatewayID                                                            spiffeid.ID
	pod                                                                  struct{ name, uid, namespace, serviceAccount string }
}

func parseOptions(args []string, lookupEnv func(string) (string, bool)) (options, error) {
	var o options
	var gatewayID string
	fs := flag.NewFlagSet("celld", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.cell, "cell", "", "name of this cell")
	fs.StringVar(&o.env, "env", "", "environment of this cell")
	fs.StringVar(&o.gateway, "gateway", "", "address of the gateway stream listener as <host>:<port>")
	fs.StringVar(&o.gatewayBind, "gateway-bind", "", "address of the gateway bind listener as <host>:<port>")
	fs.StringVar(&gatewayID, "gateway-id", "", "SPIFFE ID of the cell gateway")
	fs.StringVar(&o.trustBundle, "trust-bundle", "", "PEM trust bundle of the environment")
	fs.StringVar(&o.opKeyDir, "op-key-dir", "", "directory with one *.pub file for each operation public key")
	fs.StringVar(&o.opsNamespace, "ops-namespace", "", "namespace of the operation records")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	for _, f := range []struct{ name, value string }{
		{"cell", o.cell}, {"env", o.env}, {"gateway", o.gateway}, {"gateway-bind", o.gatewayBind},
		{"gateway-id", gatewayID}, {"trust-bundle", o.trustBundle}, {"op-key-dir", o.opKeyDir},
		{"ops-namespace", o.opsNamespace},
	} {
		if f.value == "" {
			return o, fmt.Errorf("--%s is required", f.name)
		}
	}
	id, err := spiffeid.FromString(gatewayID)
	if err != nil {
		return o, fmt.Errorf("--gateway-id: %w", err)
	}
	o.gatewayID = id
	for _, e := range []struct {
		name string
		dst  *string
	}{
		{satoken.EnvPodName, &o.pod.name}, {satoken.EnvPodUID, &o.pod.uid}, {satoken.EnvPodNamespace, &o.pod.namespace}, {satoken.EnvServiceAccount, &o.pod.serviceAccount},
	} {
		v, ok := lookupEnv(e.name)
		if !ok || v == "" {
			return o, fmt.Errorf("environment variable %s is required", e.name)
		}
		*e.dst = v
	}
	return o, nil
}

// loadOpKeys reads every *.pub file in dir: the standard base64 of one ed25519 public key.
func loadOpKeys(dir string) ([]ed25519.PublicKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("--op-key-dir: %w", err)
	}
	var keys []ed25519.PublicKey
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("--op-key-dir: %w", err)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("--op-key-dir: %s is not the base64 of a %d byte key", e.Name(), ed25519.PublicKeySize)
		}
		keys = append(keys, ed25519.PublicKey(key))
	}
	if len(keys) == 0 {
		return nil, errors.New("--op-key-dir: no *.pub file")
	}
	return keys, nil
}

func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func inClusterClient() (kubernetes.Interface, error) {
	rc, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster configuration: %w", err)
	}
	return kubernetes.NewForConfig(rc)
}

// execute runs celld until ctx ends and returns the exit code. A failure is one JSON error line
// on stdout.
func execute(ctx context.Context, args []string, stdout io.Writer, d deps) int {
	opts, err := parseOptions(args, d.lookupEnv)
	if err != nil {
		cli.Fail(stdout, "celld", err)
		return 1
	}
	keys, err := loadOpKeys(opts.opKeyDir)
	if err != nil {
		cli.Fail(stdout, "celld", err)
		return 1
	}
	kube, err := d.kubeClient()
	if err != nil {
		cli.Fail(stdout, "celld", err)
		return 1
	}
	tel, err := d.start(ctx, stdout)
	if err != nil {
		cli.Fail(stdout, "celld", fmt.Errorf("start telemetry: %w", err))
		return 1
	}
	defer func() {
		// ctx may have ended, so the flush gets a context of its own.
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := tel.Shutdown(ctx); err != nil {
			slog.New(slog.NewJSONHandler(stdout, nil)).Warn("telemetry shutdown", "error", err.Error())
		}
	}()

	attempts, err := tel.Meter.Int64Counter("celld.bind.attempts",
		metric.WithDescription("Bind attempts of celld, by result"))
	if err != nil {
		tel.Log.Error("celld failed", "error", fmt.Sprintf("create counter: %v", err))
		return 1
	}
	w, err := newSVIDWatcher(tel)
	if err != nil {
		tel.Log.Error("celld failed", "error", err.Error())
		return 1
	}
	tokens := satoken.PodTokenFunc(kube.CoreV1(), opts.pod.namespace, opts.pod.serviceAccount, opts.pod.name, opts.pod.uid)
	exec := executor.New(executor.Config{
		Cell: opts.cell, Env: opts.env, Pod: opts.pod.name, PodUID: opts.pod.uid, Namespace: opts.opsNamespace,
		Keys: keys, Client: kube, Log: tel.Log, Meter: tel.Meter,
	})
	bundle := bind.FileBundle(opts.trustBundle, opts.gatewayID.TrustDomain())

	bgCtx, stopBackground := context.WithCancel(ctx)
	grace := d.effectGrace
	if grace <= 0 {
		grace = effectGrace
	}
	// An effect that runs at SIGTERM gets a few more seconds to finish and write its record.
	effectCtx, stopEffect := context.WithCancel(context.WithoutCancel(ctx))
	stopGrace := context.AfterFunc(bgCtx, func() { time.AfterFunc(grace, stopEffect) })
	var background sync.WaitGroup
	defer func() {
		stopBackground()
		background.Wait()
		stopGrace()
		stopEffect()
	}()
	background.Add(2)
	go func() {
		defer background.Done()
		cfg := bind.Config{
			Cell: opts.cell, Upstream: opts.gatewayBind, Log: tel.Log,
			TLS:    bind.ClientTLS(bundle, opts.gatewayID),
			Tokens: tokens,
			Tracer: tel.Tracer,
			Observe: func(ctx context.Context, result string) {
				attempts.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
			},
		}
		if err := d.bindRun(bgCtx, cfg); err != nil && bgCtx.Err() == nil {
			tel.Log.Error("bind stopped", "error", err.Error())
		}
	}()
	go func() {
		defer background.Done()
		cfg := executor.StreamConfig{
			Cell: opts.cell, Upstream: opts.gateway, Log: tel.Log, Tracer: tel.Tracer,
			TLS:         executor.StreamTLS(w, bundle, opts.gatewayID),
			SVIDUpdates: w.signal, Tokens: tokens, Exec: exec, EffectCtx: effectCtx,
			Status: executor.NewStatus(opts.cell, opts.pod.name, opts.pod.uid, buildVersion(), w.expiry, exec),
		}
		if err := d.streamRun(bgCtx, cfg); err != nil && bgCtx.Err() == nil {
			tel.Log.Error("stream stopped", "error", err.Error())
		}
	}()

	tel.Log.Info("watching the workload api", "socket", os.Getenv("SPIFFE_ENDPOINT_SOCKET"))
	if err := workloadapi.WatchX509Context(ctx, w); err != nil && ctx.Err() == nil {
		tel.Log.Error("celld failed", "error", fmt.Sprintf("watch the workload api: %v", err))
		return 1
	}
	tel.Log.Info("stopped")
	return 0
}

// svidWatcher logs each new default X.509 SVID once, as "x509 svid updated", and counts it. The
// Workload API also sends an update when only the bundle changes, so the watcher compares the
// SPIFFE ID and the serial number. After a gap, a watch error or an update without an SVID, the
// watcher logs the next SVID again. A known SVID then logs as "x509 svid held", with no count and
// no span, so the log always shows whether celld holds an SVID now.
type svidWatcher struct {
	tel     *telemetry.T
	counter metric.Int64Counter
	mu      sync.Mutex
	last    string
	gap     bool
	current *x509svid.SVID
	// signal gets one value for each new SVID. A value that nobody has read yet is not repeated.
	signal chan struct{}
}

func newSVIDWatcher(tel *telemetry.T) (*svidWatcher, error) {
	counter, err := tel.Meter.Int64Counter("celld.svid.updates",
		metric.WithDescription("New X.509 SVIDs that celld received from the Workload API"))
	if err != nil {
		return nil, fmt.Errorf("create counter: %w", err)
	}
	return &svidWatcher{tel: tel, counter: counter, signal: make(chan struct{}, 1)}, nil
}

func (w *svidWatcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	// DefaultSVID panics on an empty list.
	var svid *x509svid.SVID
	if c != nil && len(c.SVIDs) > 0 {
		svid = c.DefaultSVID()
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if svid == nil || len(svid.Certificates) == 0 {
		w.gap = true
		w.tel.Log.Warn("workload api update without an svid")
		return
	}
	w.current = svid
	leaf := svid.Certificates[0]
	id := svid.ID.String()
	key := id + "/" + leaf.SerialNumber.String()
	attrs := []any{"spiffe_id", id, "serial", leaf.SerialNumber.Text(16), "not_after", leaf.NotAfter.UTC().Format(time.RFC3339)}
	switch {
	case key == w.last && !w.gap:
		return
	case key == w.last:
		w.gap = false
		w.tel.Log.Info("x509 svid held", attrs...)
		return
	}
	w.last, w.gap = key, false
	select {
	case w.signal <- struct{}{}:
	default:
	}

	ctx, span := w.tel.Tracer.Start(context.Background(), "x509 svid update",
		trace.WithAttributes(attribute.String("spiffe.id", id)))
	defer span.End()
	w.counter.Add(ctx, 1, metric.WithAttributes(attribute.String("spiffe.id", id)))
	w.tel.Log.InfoContext(ctx, "x509 svid updated", attrs...)
}

// GetX509SVID returns the current SVID, and an error while the Workload API has sent none.
func (w *svidWatcher) GetX509SVID() (*x509svid.SVID, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current == nil {
		return nil, errors.New("the Workload API has sent no SVID")
	}
	return w.current, nil
}

// expiry returns the NotAfter time of the current SVID, or the zero time when there is none.
func (w *svidWatcher) expiry() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current == nil {
		return time.Time{}
	}
	return w.current.Certificates[0].NotAfter
}

// OnX509ContextWatchError logs the error and marks a gap, so the next SVID logs again.
func (w *svidWatcher) OnX509ContextWatchError(err error) {
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return
	}
	w.mu.Lock()
	w.gap = true
	w.mu.Unlock()
	w.tel.Log.Warn("workload api watch failed", "error", err.Error())
}

func startTelemetry(ctx context.Context, stdout io.Writer) (*telemetry.T, error) {
	return telemetry.Start(ctx, serviceName, stdout)
}
