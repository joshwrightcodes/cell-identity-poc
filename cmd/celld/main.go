// Command celld is the cell daemon. It binds the cluster issuer of its cell to the management
// plane, and it watches the SPIFFE Workload API and logs the SPIFFE ID of its X.509 SVID once for
// each new SVID.
//
//	celld --cell <name> --bind-upstream <host:port> --bind-expect-id <spiffe id> --bind-peer-bundle <file>
//
// The bind loop runs in its own goroutine and never stops the SVID watch. The environment names the
// pod: POD_NAME, POD_UID, POD_NAMESPACE and SERVICE_ACCOUNT.
//
// Every log line is compact JSON on stdout, and logs, traces and metrics also go out as OTLP, as
// package internal/telemetry describes. SPIFFE_ENDPOINT_SOCKET names the Workload API socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
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
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bind"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	serviceName = "celld"
	// shutdownTimeout bounds the whole flush. Each provider has its own shorter timeout inside it.
	shutdownTimeout = 15 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second signal ends the process at once, also during the flush.
	context.AfterFunc(ctx, stop)
	code := execute(ctx, os.Args[1:], os.Stdout, deps{
		start: startTelemetry, lookupEnv: os.LookupEnv, tokenClient: inClusterClient, bindRun: bind.Run,
	})
	stop()
	os.Exit(code)
}

type telemetryStarter func(ctx context.Context, stdout io.Writer) (*telemetry.T, error)

// deps holds what execute takes from its environment, so that tests can replace it.
type deps struct {
	start       telemetryStarter
	lookupEnv   func(string) (string, bool)
	tokenClient func() (corev1client.ServiceAccountsGetter, error)
	bindRun     func(ctx context.Context, cfg bind.Config) error
}

// options are the settings that the flags and the environment give.
type options struct {
	cell, upstream, peerBundle string
	expectID                   spiffeid.ID
	pod                        struct{ name, uid, namespace, serviceAccount string }
}

func parseOptions(args []string, lookupEnv func(string) (string, bool)) (options, error) {
	var o options
	var expect string
	fs := flag.NewFlagSet("celld", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.cell, "cell", "", "name of this cell")
	fs.StringVar(&o.upstream, "bind-upstream", "", "address of the bind listener as <host>:<port>")
	fs.StringVar(&expect, "bind-expect-id", "", "SPIFFE ID of the management plane API")
	fs.StringVar(&o.peerBundle, "bind-peer-bundle", "", "PEM trust bundle of the management plane")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	for _, f := range []struct{ name, value string }{
		{"cell", o.cell}, {"bind-upstream", o.upstream}, {"bind-expect-id", expect}, {"bind-peer-bundle", o.peerBundle},
	} {
		if f.value == "" {
			return o, fmt.Errorf("--%s is required", f.name)
		}
	}
	id, err := spiffeid.FromString(expect)
	if err != nil {
		return o, fmt.Errorf("--bind-expect-id: %w", err)
	}
	o.expectID = id
	for _, e := range []struct {
		name string
		dst  *string
	}{
		{"POD_NAME", &o.pod.name}, {"POD_UID", &o.pod.uid}, {"POD_NAMESPACE", &o.pod.namespace}, {"SERVICE_ACCOUNT", &o.pod.serviceAccount},
	} {
		v, ok := lookupEnv(e.name)
		if !ok || v == "" {
			return o, fmt.Errorf("environment variable %s is required", e.name)
		}
		*e.dst = v
	}
	return o, nil
}

func inClusterClient() (corev1client.ServiceAccountsGetter, error) {
	rc, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster configuration: %w", err)
	}
	return corev1client.NewForConfig(rc)
}

// execute runs celld until ctx ends and returns the exit code. A failure is one JSON error line
// on stdout.
func execute(ctx context.Context, args []string, stdout io.Writer, d deps) int {
	opts, err := parseOptions(args, d.lookupEnv)
	if err != nil {
		cli.Fail(stdout, "celld", err)
		return 1
	}
	tokens, err := d.tokenClient()
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
	bindCtx, stopBind := context.WithCancel(ctx)
	bindDone := make(chan struct{})
	defer func() {
		stopBind()
		<-bindDone
	}()
	go func() {
		defer close(bindDone)
		cfg := bind.Config{
			Cell: opts.cell, Upstream: opts.upstream, Log: tel.Log,
			TLS:    bind.ClientTLS(bind.FileBundle(opts.peerBundle, opts.expectID.TrustDomain()), opts.expectID),
			Tokens: bind.PodTokenFunc(tokens, opts.pod.namespace, opts.pod.serviceAccount, opts.pod.name, opts.pod.uid),
			Observe: func(ctx context.Context, result string) {
				attempts.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
			},
		}
		if err := d.bindRun(bindCtx, cfg); err != nil && bindCtx.Err() == nil {
			tel.Log.Error("bind stopped", "error", err.Error())
		}
	}()

	w, err := newSVIDWatcher(tel)
	if err != nil {
		tel.Log.Error("celld failed", "error", err.Error())
		return 1
	}
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
	updates metric.Int64Counter
	mu      sync.Mutex
	last    string
	gap     bool
}

func newSVIDWatcher(tel *telemetry.T) (*svidWatcher, error) {
	updates, err := tel.Meter.Int64Counter("celld.svid.updates",
		metric.WithDescription("New X.509 SVIDs that celld received from the Workload API"))
	if err != nil {
		return nil, fmt.Errorf("create counter: %w", err)
	}
	return &svidWatcher{tel: tel, updates: updates}, nil
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

	ctx, span := w.tel.Tracer.Start(context.Background(), "x509 svid update",
		trace.WithAttributes(attribute.String("spiffe.id", id)))
	defer span.End()
	w.updates.Add(ctx, 1, metric.WithAttributes(attribute.String("spiffe.id", id)))
	w.tel.Log.InfoContext(ctx, "x509 svid updated", attrs...)
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
