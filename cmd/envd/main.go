// Command envd pulls the signed spec and cell records of one environment from the management plane,
// verifies them, keeps them in a ConfigMap and reports its status.
//
//	envd run --upstream <host:port> --expect-id <id> --peer-bundle <file> --peer-trust-domain <td> --spec-key-file <file> --env <env> --output-configmap <ns>/<name> [--interval 10s] [--health-listen :8080]
//	envd check --spec-key-file <file> --env <env> --current-configmap <ns>/<name>
//
// run takes its SVID from the Workload API at SPIFFE_ENDPOINT_SOCKET and trusts the management plane
// only through --peer-bundle. Every log line is compact JSON on stdout, and logs, traces and metrics
// also go out as OTLP through package internal/telemetry.
//
// check reads one SpecBundle from standard input, loads the current state without writing it, and
// prints one JSON line. It starts no telemetry. The exit status is 0 for accepted and unchanged, and
// 1 for refused.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/envd"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	name = "envd"
	// sourceTimeout bounds the wait for the first SVID from the Workload API.
	sourceTimeout = 30 * time.Second
	// shutdownTimeout bounds the whole telemetry flush.
	shutdownTimeout = 15 * time.Second
	// loadTimeout bounds the read of the stored state by check.
	loadTimeout = 15 * time.Second
	// exitConfig is the status of a configuration error.
	exitConfig = 2
)

// deps holds what a test replaces.
type deps struct {
	telemetry func(ctx context.Context, stdout io.Writer) (*telemetry.T, error)
	kube      func() (kubernetes.Interface, error)
	svids     func(ctx context.Context) (x509svid.Source, func(), error)
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
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second signal ends the process at once, also during the flush.
	context.AfterFunc(ctx, stop)
	code := execute(ctx, os.Args[1:], os.Stdin, os.Stdout, realDeps())
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, d deps) int {
	if len(args) == 0 {
		cli.Fail(stdout, name, errors.New("usage: envd run|check [flags]"))
		return exitConfig
	}
	switch args[0] {
	case "run":
		cfg, err := parseRun(args[1:])
		if err != nil {
			cli.Fail(stdout, name, err)
			return exitConfig
		}
		return runCommand(ctx, cfg, stdout, d)
	case "check":
		cfg, err := parseCheck(args[1:])
		if err != nil {
			cli.Fail(stdout, name, err)
			return exitConfig
		}
		return checkCommand(ctx, cfg, stdin, stdout, d)
	}
	cli.Fail(stdout, name, fmt.Errorf("unknown mode %q", args[0]))
	return exitConfig
}

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

// readSpecKey reads the pinned public key: the standard base64 of its 32 raw bytes, as in ConfigMap
// key spec.pub.
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

func checkEnv(env string) error {
	if !spec.ValidName(env) {
		return errors.New("--env must be a DNS label")
	}
	return nil
}

type runConfig struct {
	upstream     string
	expect       spiffeid.ID
	peer         *x509bundle.Bundle
	key          ed25519.PublicKey
	env          string
	namespace    string
	configMap    string
	interval     time.Duration
	healthListen string
}

func parseRun(args []string) (runConfig, error) {
	fs := newFlags("run")
	upstream := fs.String("upstream", "", "management plane address as host:port")
	expect := fs.String("expect-id", "", "the exact SPIFFE ID of the management plane")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the management trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the management plane")
	keyFile := fs.String("spec-key-file", "", "file with the base64 public key that signs specs")
	env := fs.String("env", "", "environment name")
	out := fs.String("output-configmap", "", "ConfigMap that holds the records, as <namespace>/<name>")
	interval := fs.Duration("interval", 10*time.Second, "time between pulls")
	health := fs.String("health-listen", ":8080", "address of the health endpoint")
	if err := parseFlags(fs, args); err != nil {
		return runConfig{}, err
	}
	if err := required(map[string]string{
		"upstream": *upstream, "expect-id": *expect, "peer-bundle": *bundle, "peer-trust-domain": *td,
		"spec-key-file": *keyFile, "env": *env, "output-configmap": *out,
	}); err != nil {
		return runConfig{}, err
	}
	if *interval <= 0 {
		return runConfig{}, errors.New("--interval must be positive")
	}
	if err := checkEnv(*env); err != nil {
		return runConfig{}, err
	}
	trustDomain, err := spiffeid.TrustDomainFromString(*td)
	if err != nil {
		return runConfig{}, fmt.Errorf("--peer-trust-domain: %w", err)
	}
	id, err := spiffeid.FromString(*expect)
	if err != nil {
		return runConfig{}, fmt.Errorf("--expect-id: %w", err)
	}
	if id.TrustDomain() != trustDomain {
		return runConfig{}, fmt.Errorf("--expect-id %s is not in --peer-trust-domain %s", id, trustDomain)
	}
	peer, err := x509bundle.Load(trustDomain, *bundle)
	if err != nil {
		return runConfig{}, fmt.Errorf("--peer-bundle: %w", err)
	}
	if peer.Empty() {
		return runConfig{}, errors.New("--peer-bundle holds no certificate")
	}
	key, err := readSpecKey(*keyFile)
	if err != nil {
		return runConfig{}, err
	}
	ns, cm, err := configMapRef("output-configmap", *out)
	if err != nil {
		return runConfig{}, err
	}
	return runConfig{upstream: *upstream, expect: id, peer: peer, key: key, env: *env, namespace: ns,
		configMap: cm, interval: *interval, healthListen: *health}, nil
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
			slog.New(slog.NewJSONHandler(stdout, nil)).Warn("telemetry shutdown", "error", err.Error())
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

	keys := []ed25519.PublicKey{cfg.key}
	// The transport adds the traceparent header, so a trace of a round continues in the logs of mgmtd.
	client := envd.NewClient(cellproxy.ClientTLS(svids, cfg.peer, cfg.expect))
	client.Transport = telemetry.Transport(client.Transport)
	puller := envd.NewPuller(envd.PullerConfig{
		Client:   client,
		BaseURL:  "https://" + cfg.upstream,
		Env:      cfg.env,
		Keys:     keys,
		Store:    envd.NewConfigMapStore(kube, cfg.namespace, cfg.configMap, cfg.env, keys, tel.Log),
		Interval: cfg.interval,
		Log:      tel.Log,
		Meter:    tel.Meter,
		Tracer:   tel.Tracer,
	})

	ln, err := net.Listen("tcp", cfg.healthListen)
	if err != nil {
		return fmt.Errorf("health listener: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/healthz", envd.HealthHandler(puller))
	health := newHealthServer(mux)
	go func() { _ = health.Serve(ln) }()
	defer func() { _ = health.Close() }()

	tel.Log.Info("envd started", "env", cfg.env, "upstream", cfg.upstream, "configmap", cfg.namespace+"/"+cfg.configMap,
		"health", ln.Addr().String())
	if err := puller.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
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

type checkConfig struct {
	key       ed25519.PublicKey
	env       string
	namespace string
	configMap string
}

func parseCheck(args []string) (checkConfig, error) {
	fs := newFlags("check")
	keyFile := fs.String("spec-key-file", "", "file with the base64 public key that signs specs")
	env := fs.String("env", "", "environment name")
	cur := fs.String("current-configmap", "", "ConfigMap that holds the current records, as <namespace>/<name>")
	if err := parseFlags(fs, args); err != nil {
		return checkConfig{}, err
	}
	if err := required(map[string]string{"spec-key-file": *keyFile, "env": *env, "current-configmap": *cur}); err != nil {
		return checkConfig{}, err
	}
	if err := checkEnv(*env); err != nil {
		return checkConfig{}, err
	}
	key, err := readSpecKey(*keyFile)
	if err != nil {
		return checkConfig{}, err
	}
	ns, cm, err := configMapRef("current-configmap", *cur)
	if err != nil {
		return checkConfig{}, err
	}
	return checkConfig{key: key, env: *env, namespace: ns, configMap: cm}, nil
}

type checkResult struct {
	Result   string         `json:"result"`
	Revision *spec.Revision `json:"revision,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

func checkCommand(ctx context.Context, cfg checkConfig, stdin io.Reader, stdout io.Writer, d deps) int {
	var refusal *envd.Refused
	code := cli.Run(stdout, name, func(out io.Writer) error {
		body, err := io.ReadAll(io.LimitReader(stdin, envd.MaxBodyBytes+1))
		if err != nil {
			return fmt.Errorf("read bundle: %w", err)
		}
		if len(body) > envd.MaxBodyBytes {
			return fmt.Errorf("bundle is larger than %d bytes", envd.MaxBodyBytes)
		}
		var b mgmtapi.SpecBundle
		if err := json.Unmarshal(body, &b); err != nil {
			return fmt.Errorf("decode bundle: %w", err)
		}
		kube, err := d.kube()
		if err != nil {
			return err
		}
		keys := []ed25519.PublicKey{cfg.key}
		store := envd.NewConfigMapStore(kube, cfg.namespace, cfg.configMap, cfg.env, keys, slog.New(slog.DiscardHandler))
		lctx, cancel := context.WithTimeout(ctx, loadTimeout)
		defer cancel()
		cur, err := store.Load(lctx)
		if err != nil {
			return err
		}
		next, changed, err := envd.Accept(cur, b, cfg.env, keys)
		if errors.As(err, &refusal) {
			return nil
		}
		if err != nil {
			return err
		}
		res := checkResult{Result: "unchanged", Revision: &next.Revision}
		if changed {
			res.Result = "accepted"
		}
		return json.NewEncoder(out).Encode(res)
	})
	if code != 0 {
		return code
	}
	if refusal != nil {
		_ = json.NewEncoder(stdout).Encode(checkResult{Result: "refused", Reason: refusal.Reason})
		return 1
	}
	return 0
}
