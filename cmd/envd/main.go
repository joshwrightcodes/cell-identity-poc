// Command envd pulls the signed spec and cell records of one environment from the management plane,
// verifies them, keeps them in a ConfigMap and reports its status.
//
//	envd run --upstream <host:port> --expect-id <id> --peer-bundle <file> --peer-trust-domain <td>
//	  --spec-key-file <file> --env <env> --output-configmap <ns>/<name>
//	  --gateway <https-url> --gateway-id <id> --hints-configmap <ns>/<name>
//	  --steps-configmap <ns>/<name> --step-status-configmap <ns>/<name>
//	  [--interval 10s] [--report-rate 5] [--health-listen :8080] [--cluster <name>]
//	  [--bundle-mirror <host:port> --bundle-store <host:port> --bundle-store-token <file>
//	   --bundle-state-configmap <ns>/<name> --bundle-health-timeout 5m]
//	  [--operator-key-file <file> --revocations-configmap <ns>/<name>]
//	envd check --spec-key-file <file> --env <env> --current-configmap <ns>/<name>
//
// run takes its SVID from the Workload API at SPIFFE_ENDPOINT_SOCKET and trusts the management plane
// only through --peer-bundle. It reaches the cell gateway with the same SVID, trusts the bundle of
// its own trust domain from the Workload API, and accepts only the exact --gateway-id. Every log line is compact JSON on stdout, and logs, traces and metrics
// also go out as OTLP through package internal/telemetry.
//
// With --bundle-mirror, run also applies the signed bundle set of --cluster (operation kind
// bundle.apply) that the ops pull carries in planeBundle, and reports the result in its status. run
// never forwards an operation for --cluster to the gateway. The plane path runs only after run accepts
// a spec and only when a gateway is set, because the ops pull belongs to the relay legs.
//
// With --operator-key-file, run takes in the signed local revocation entries of
// --revocations-configmap, holds the ones that verify under the pinned operator keys in its
// ConfigMap, and passes them to the gateway and in each status report.
//
// check reads one SpecBundle from standard input, loads the current state without writing it, and
// prints one JSON line. It starts no telemetry. The exit status is 0 for accepted and unchanged, and
// 1 for refused.
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/envd"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spireclient"
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
	// kubeTimeout bounds each request to the Kubernetes API.
	kubeTimeout = 15 * time.Second
	// defaultBundleRefillEvery is the time between probes of the bundle store.
	defaultBundleRefillEvery = time.Minute
	// defaultBundleHealthTimeout is the time that a new bundle set has to become healthy.
	defaultBundleHealthTimeout = 5 * time.Minute
	// exitConfig is the status of a configuration error.
	exitConfig = 2
)

// deps holds what a test replaces.
type deps struct {
	telemetry func(ctx context.Context, stdout io.Writer) (*telemetry.T, error)
	kube      func() (kubernetes.Interface, error)
	svids     func(ctx context.Context) (x509svid.Source, func(), error)
	// dynamic serves the bundle applier, and runs only with --bundle-mirror.
	dynamic func() (dynamic.Interface, error)
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
		dynamic: func() (dynamic.Interface, error) {
			cfg, err := rest.InClusterConfig()
			if err != nil {
				return nil, fmt.Errorf("in-cluster config: %w", err)
			}
			cfg.Timeout = kubeTimeout
			return dynamic.NewForConfig(cfg)
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
	reportRate   float64
	healthListen string
	gateway      string
	gatewayID    spiffeid.ID
	hintsNS      string
	hintsName    string
	stepsNS      string
	stepsName    string
	statusNS     string
	statusName   string
	// cluster is the name of the cluster of envd. The bundle fields go together, and only with
	// bundleMirror does envd apply signed bundle sets for cluster.
	cluster             string
	keyFile             string
	bundleMirror        string
	bundleStore         string
	bundleStoreToken    string
	bundleNS            string
	bundleName          string
	bundleHealthTimeout time.Duration
	// operatorKeyFile is the pin of the operator keys, and operatorKeys the keys that it held at
	// startup. They go with revocationsNS and revocationsName, the input of the local revocations.
	operatorKeyFile   string
	operatorKeys      []ed25519.PublicKey
	revocationsNS     string
	revocationsName   string
	bundleRefillEvery time.Duration
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
	reportRate := fs.Float64("report-rate", envd.DefaultReportRate, "report items per second that envd posts to the management plane")
	health := fs.String("health-listen", ":8080", "address of the health endpoint")
	gateway := fs.String("gateway", "", "base URL of the cell gateway, https://<host>:<port>")
	gatewayID := fs.String("gateway-id", "", "the exact SPIFFE ID of the cell gateway")
	hints := fs.String("hints-configmap", "", "ConfigMap that holds the key hints, as <namespace>/<name>")
	steps := fs.String("steps-configmap", "", "ConfigMap that holds the signed steps for the cell controller, as <namespace>/<name>")
	stepStatus := fs.String("step-status-configmap", "", "ConfigMap that holds the step status of the cell controller, as <namespace>/<name>")
	cluster := fs.String("cluster", "", "name of the cluster of envd; the gateway never receives an operation for it")
	mirror := fs.String("bundle-mirror", "", "address of the bundle mirror as <host>:<port>; turns on bundle.apply for --cluster")
	store := fs.String("bundle-store", "", "address of the in-cluster bundle store as <host>:<port>")
	storeToken := fs.String("bundle-store-token", "", "file with the projected token for the bundle store")
	state := fs.String("bundle-state-configmap", "", "ConfigMap that holds the bundle state, as <namespace>/<name>")
	healthTimeout := fs.Duration("bundle-health-timeout", defaultBundleHealthTimeout, "time that a new bundle set has to become healthy")
	operatorKeyFile := fs.String("operator-key-file", "", "file with the pinned operator public keys, one standard base64 key on each line")
	revocations := fs.String("revocations-configmap", "", "ConfigMap that holds the signed local revocation entries, as <namespace>/<name>")
	refillEvery := fs.Duration("bundle-refill-every", defaultBundleRefillEvery, "time between probes of the bundle store, which refills it after a loss; 0 turns the probe off")
	if err := parseFlags(fs, args); err != nil {
		return runConfig{}, err
	}
	if err := required(map[string]string{
		"upstream": *upstream, "expect-id": *expect, "peer-bundle": *bundle, "peer-trust-domain": *td,
		"spec-key-file": *keyFile, "env": *env, "output-configmap": *out,
		"gateway": *gateway, "gateway-id": *gatewayID, "hints-configmap": *hints,
		"steps-configmap": *steps, "step-status-configmap": *stepStatus,
	}); err != nil {
		return runConfig{}, err
	}
	if *interval <= 0 {
		return runConfig{}, errors.New("--interval must be positive")
	}
	if !(*reportRate > 0) || math.IsInf(*reportRate, 0) {
		return runConfig{}, errors.New("--report-rate must be positive")
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
	gwURL, err := url.Parse(*gateway)
	if err != nil || gwURL.Scheme != "https" || gwURL.Host == "" || gwURL.Path != "" && gwURL.Path != "/" ||
		gwURL.RawQuery != "" || gwURL.ForceQuery || gwURL.Fragment != "" || gwURL.User != nil {
		return runConfig{}, errors.New("--gateway must be an https URL with a host and no path, query, fragment or user")
	}
	gwID, err := spiffeid.FromString(*gatewayID)
	if err != nil {
		return runConfig{}, fmt.Errorf("--gateway-id: %w", err)
	}
	hns, hname, err := configMapRef("hints-configmap", *hints)
	if err != nil {
		return runConfig{}, err
	}
	sns, sname, err := configMapRef("steps-configmap", *steps)
	if err != nil {
		return runConfig{}, err
	}
	stns, stname, err := configMapRef("step-status-configmap", *stepStatus)
	if err != nil {
		return runConfig{}, err
	}
	rc := runConfig{upstream: *upstream, expect: id, peer: peer, key: key, keyFile: *keyFile, env: *env, namespace: ns,
		configMap: cm, interval: *interval, reportRate: *reportRate, healthListen: *health,
		gateway: strings.TrimSuffix(*gateway, "/"), gatewayID: gwID, hintsNS: hns, hintsName: hname,
		stepsNS: sns, stepsName: sname, statusNS: stns, statusName: stname, cluster: *cluster,
		bundleMirror: *mirror, bundleStore: *store, bundleStoreToken: *storeToken, bundleHealthTimeout: *healthTimeout, bundleRefillEvery: *refillEvery}
	if err := checkPlaneFlags(&rc, fs, *state); err != nil {
		return runConfig{}, err
	}
	if err := checkRevocationFlags(&rc, *operatorKeyFile, *revocations); err != nil {
		return runConfig{}, err
	}
	return rc, nil
}

// checkRevocationFlags checks --operator-key-file and --revocations-configmap, which go together.
func checkRevocationFlags(rc *runConfig, keyFile, revocations string) error {
	if keyFile == "" && revocations == "" {
		return nil
	}
	if err := required(map[string]string{"operator-key-file": keyFile, "revocations-configmap": revocations}); err != nil {
		return err
	}
	keys, err := readOperatorKeys(keyFile)
	if err != nil {
		return err
	}
	ns, cm, err := configMapRef("revocations-configmap", revocations)
	if err != nil {
		return err
	}
	rc.operatorKeyFile, rc.operatorKeys, rc.revocationsNS, rc.revocationsName = keyFile, keys, ns, cm
	return nil
}

// readOperatorKeys reads the pin of the operator keys, as in key keys.pub of ConfigMap operator-key.
func readOperatorKeys(path string) ([]ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--operator-key-file: %w", err)
	}
	keys, err := revoke.ParseKeys(raw)
	if err != nil {
		return nil, fmt.Errorf("--operator-key-file: %w", err)
	}
	return keys, nil
}

// operatorKeys returns a function that reads the pin in path again on each call, so that a key
// rotation takes effect without a restart. A failed read gives the last keys that loaded, or seed
// before any read works, and logs one line until a read works again.
func operatorKeys(path string, seed []ed25519.PublicKey, log *slog.Logger) func() []ed25519.PublicKey {
	var mu sync.Mutex
	last, failing := seed, false
	return func() []ed25519.PublicKey {
		mu.Lock()
		defer mu.Unlock()
		keys, err := readOperatorKeys(path)
		if err != nil {
			if !failing {
				log.Warn("operator keys not reloaded", "error", err.Error())
			}
			failing = true
			return last
		}
		last, failing = keys, false
		return last
	}
}

// checkPlaneFlags checks the cluster and bundle flags. The bundle flags go together: with --bundle-mirror
// they are all required, and without it none may be set.
func checkPlaneFlags(rc *runConfig, fs *flag.FlagSet, state string) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if rc.cluster != "" && !spec.ValidName(rc.cluster) {
		return errors.New("--cluster must be a DNS label")
	}
	if rc.bundleMirror == "" {
		for _, n := range []string{"bundle-store", "bundle-store-token", "bundle-state-configmap", "bundle-health-timeout", "bundle-refill-every"} {
			if set[n] {
				return fmt.Errorf("--%s needs --bundle-mirror", n)
			}
		}
		return nil
	}
	if err := required(map[string]string{"cluster": rc.cluster, "bundle-store": rc.bundleStore,
		"bundle-store-token": rc.bundleStoreToken, "bundle-state-configmap": state}); err != nil {
		return err
	}
	if rc.bundleHealthTimeout <= 0 {
		return errors.New("--bundle-health-timeout must be positive")
	}
	if rc.bundleRefillEvery < 0 {
		return errors.New("--bundle-refill-every must not be negative")
	}
	var err error
	rc.bundleNS, rc.bundleName, err = configMapRef("bundle-state-configmap", state)
	return err
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

	mgmtClient, gateway, err := newClients(svids, cfg)
	if err != nil {
		return err
	}
	pc := pullerConfig(cfg, kube, mgmtClient, gateway, tel)
	if cfg.bundleMirror != "" {
		dyn, err := d.dynamic()
		if err != nil {
			return err
		}
		if pc.Plane, err = newPlane(cfg, kube, dyn, tel, func(c bundleapply.Config) envd.BundleApplier { return bundleapply.New(c) }); err != nil {
			return err
		}
	}
	puller := envd.NewPuller(pc)
	if pc.Plane != nil {
		var refill sync.WaitGroup
		rctx, stopRefill := context.WithCancel(ctx)
		defer func() { stopRefill(); refill.Wait() }()
		refill.Go(func() { pc.Plane.RunRefill(rctx) })
	}

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

// pullerConfig wires the puller to the ConfigMaps that cfg names.
func pullerConfig(cfg runConfig, kube kubernetes.Interface, mgmt *http.Client, gateway envd.GatewayClient, tel *telemetry.T) envd.PullerConfig {
	keys := []ed25519.PublicKey{cfg.key}
	var opKeys func() []ed25519.PublicKey
	var revocations envd.RevocationSource
	var storeOpts []envd.StoreOption
	if cfg.operatorKeyFile != "" {
		opKeys = operatorKeys(cfg.operatorKeyFile, cfg.operatorKeys, tel.Log)
		revocations = envd.ConfigMapRevocations{Client: kube, Namespace: cfg.revocationsNS, Name: cfg.revocationsName}
		storeOpts = append(storeOpts, envd.WithOperatorKeys(opKeys))
	}
	return envd.PullerConfig{
		Cluster:      cfg.cluster,
		Client:       mgmt,
		BaseURL:      "https://" + cfg.upstream,
		Env:          cfg.env,
		Keys:         keys,
		OperatorKeys: opKeys,
		Revocations:  revocations,
		Store:        envd.NewConfigMapStore(kube, cfg.namespace, cfg.configMap, cfg.env, keys, tel.Log, storeOpts...),
		Gateway:      gateway,
		Hints:        envd.NewConfigMapHints(kube, cfg.hintsNS, cfg.hintsName, tel.Log),
		Steps:        envd.NewStepStore(kube, cfg.stepsNS, cfg.stepsName, envd.KeyFingerprint(keys), tel.Log),
		StepStatus:   envd.NewConfigMapStepStatus(kube, cfg.statusNS, cfg.statusName, tel.Log),
		Interval:     cfg.interval,
		ReportRate:   cfg.reportRate,
		Log:          tel.Log,
		Meter:        tel.Meter,
		Tracer:       tel.Tracer,
	}
}

// newPlane builds the plane path: the engine of role cp, which reads sets from the mirror, writes
// them to the in-cluster store with the projected token and keeps its state in the ConfigMap of
// --bundle-state-configmap.
func newPlane(cfg runConfig, kube kubernetes.Interface, dyn dynamic.Interface, tel *telemetry.T, build func(bundleapply.Config) envd.BundleApplier) (*envd.Plane, error) {
	mirror, err := ocistore.New(ocistore.Client{Base: cfg.bundleMirror})
	if err != nil {
		return nil, fmt.Errorf("--bundle-mirror: %w", err)
	}
	store, err := ocistore.New(ocistore.Client{Base: cfg.bundleStore, Token: tokenFromFile(cfg.bundleStoreToken), WriteOnly: true})
	if err != nil {
		return nil, fmt.Errorf("--bundle-store: %w", err)
	}
	holder, err := os.Hostname()
	if err != nil || holder == "" {
		holder = name
	}
	keys := planeKeys(cfg.keyFile, cfg.key, tel.Log)
	engine := build(bundleapply.Config{
		Role: "cp", Env: cfg.env, Target: cfg.cluster, Holder: holder,
		Mirror: mirror, Store: store, Dynamic: dyn, Client: kube,
		Policy: bundle.DefaultPolicy(), Keys: engineKeys(cfg.keyFile),
		State:         &bundleapply.ConfigMapStore{Client: kube, Namespace: cfg.bundleNS, Name: cfg.bundleName, MadeBy: name},
		HealthTimeout: cfg.bundleHealthTimeout,
		Log:           tel.Log, Tracer: tel.Tracer, Meter: tel.Meter,
	})
	return envd.NewPlane(envd.PlaneConfig{Env: cfg.env, Cluster: cfg.cluster, Keys: keys, Applier: engine, RefillEvery: cfg.bundleRefillEvery, Log: tel.Log})
}

// planeKeys returns a function that reads the pinned key in path again on each call. A failed read
// gives the last key that loaded, or seed (the key that envd read at startup) before any read works, so a rotation in progress does not stop an apply.
func planeKeys(path string, seed ed25519.PublicKey, log *slog.Logger) func() []crypto.PublicKey {
	var mu sync.Mutex
	last := []crypto.PublicKey{seed}
	return func() []crypto.PublicKey {
		mu.Lock()
		defer mu.Unlock()
		key, err := readSpecKey(path)
		if err != nil {
			log.Warn("bundle key not reloaded", "error", err.Error())
			return last
		}
		last = []crypto.PublicKey{key}
		return last
	}
}

// engineKeys returns a function that reads the pinned key in path again on each call, for the
// engine. A failed read is an error, so the engine leaves the operation open and tries it again later.
func engineKeys(path string) func() ([]crypto.PublicKey, error) {
	return func() ([]crypto.PublicKey, error) {
		key, err := readSpecKey(path)
		if err != nil {
			return nil, err
		}
		return []crypto.PublicKey{key}, nil
	}
}

// tokenFromFile returns a function that reads the token in path each time it runs, so that a token
// that the kubelet rotates takes effect at once.
func tokenFromFile(path string) func() (string, error) {
	return func() (string, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read the bundle store token: %w", err)
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return "", errors.New("the bundle store token file is empty")
		}
		return tok, nil
	}
}

// newClients builds the client of the management plane and the client of the gateway. The gateway
// runs in the trust domain of envd, so its roots come from the Workload API, and it must carry
// --gateway-id exactly. A --gateway-id outside the trust domain of the SVID is a configuration error.
func newClients(svids x509svid.Source, cfg runConfig) (*http.Client, envd.GatewayClient, error) {
	bundles, ok := svids.(x509bundle.Source)
	if !ok {
		return nil, nil, errors.New("the workload api source holds no trust bundles")
	}
	own, err := svids.GetX509SVID()
	if err != nil {
		return nil, nil, fmt.Errorf("envd svid: %w", err)
	}
	if own.ID.TrustDomain() != cfg.gatewayID.TrustDomain() {
		return nil, nil, fmt.Errorf("--gateway-id %s is outside the trust domain %s of the envd svid", cfg.gatewayID, own.ID.TrustDomain())
	}
	mgmt := tracedClient(cellproxy.ClientTLS(svids, cfg.peer, cfg.expect))
	gateway := envd.NewGatewayClient(tracedClient(cellproxy.ClientTLS(svids, bundles, cfg.gatewayID)), cfg.gateway)
	return mgmt, gateway, nil
}

// tracedClient returns the envd HTTP client for tlsCfg. Its transport adds the traceparent header, so
// a trace of a round continues in the logs of the server.
func tracedClient(tlsCfg *tls.Config) *http.Client {
	c := envd.NewClient(tlsCfg)
	c.Transport = telemetry.Transport(c.Transport)
	return c
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
