// Command hostsvc creates, describes and deletes the harness clusters, and serves their keys.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

const (
	defaultServeAddr = "127.0.0.1:17443"
	defaultClientID  = "spiffe://" + hostsvc.MgmtTrustDomain + "/api"
	keyedComponent   = hostsvc.CellComponent

	defaultStepClientID = "spiffe://" + hostsvc.StepClientTrustDomain + "/cp/cell-controller"
	defaultJournalDir   = "build/hostsvc/steps"
	defaultAdminSocket  = "build/hostsvc/admin.sock"

	// maxStepInFlight is the number of requests that one peer may have in flight.
	maxStepInFlight = 4
)

// serveFlags holds the flags of serve and the flags that other commands share with it.
type serveFlags struct {
	listen, bundle, clientID                        string
	stepBundle, stepID, keysDir, env, cpCluster     string
	journalDir, repoRoot, adminSocket, bootstrapCmd string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.Stdout)
	stop()
	os.Exit(code)
}

// execute runs one command and returns the exit code. Every log line is compact JSON on stdout.
// A failure is one JSON error line on stdout, so the facts command prints only data on success.
func execute(ctx context.Context, args []string, stdout io.Writer) int {
	slog.SetDefault(slog.New(slog.NewJSONHandler(stdout, nil)))
	var exit *exitError
	code := cli.Run(stdout, "hostsvc", func(out io.Writer) error {
		err := run(ctx, args, out, stdout)
		errors.As(err, &exit)
		return err
	})
	if code != 0 && exit != nil {
		return exit.code
	}
	return code
}

// exitError is an error with its own exit code.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// Hooks that tests replace.
var (
	startTelemetry  = telemetry.Start
	selfExecutable  = os.Executable
	nofileSoftLimit = func() (uint64, error) {
		var r syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
			return 0, err
		}
		return uint64(r.Cur), nil
	}
)

// run runs one command. It writes data to out, and the logs of serve go to logOut.
func run(ctx context.Context, args []string, out, logOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hostsvc up|down [--only <name>] | create --cluster <cell> | facts --cluster <name> | bootstrap-digest [--root <dir>] | ctl steps|log|cancel|reset-journal | serve --listen <addr> --client-bundle <file> [--client-id <id>] [--journal-dir <dir>] | pin --addr <addr> [--expect-sha256 <hex>]  [--topology <file>]")
	}
	cmd := args[0]
	var sub string
	if cmd == "ctl" {
		if len(args) < 2 {
			return errors.New("usage: hostsvc ctl steps | log --step <id> [--follow] | cancel --cell <c>|--step <id> | reset-journal")
		}
		sub, args = args[1], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	topoPath := fs.String("topology", "harness/topology.yaml", "topology file")
	only := fs.String("only", "", "act on this cluster only (up, down)")
	name := fs.String("cluster", "", "cluster name (facts)")
	listen := fs.String("listen", defaultServeAddr, "loopback address to listen on (serve)")
	bundlePath := fs.String("client-bundle", "", "PEM file with the roots of the management plane (serve)")
	clientID := fs.String("client-id", defaultClientID, "SPIFFE ID that a client must carry (serve)")
	addr := fs.String("addr", defaultServeAddr, "address of the server (pin)")
	expect := fs.String("expect-sha256", "", "hex SHA-256 of the DER certificate that the server must present (pin)")
	var sf serveFlags
	fs.StringVar(&sf.stepBundle, "step-client-bundle", "", "PEM file with the roots of the step client trust domain; it may be absent at start (serve)")
	fs.StringVar(&sf.stepID, "step-client-id", defaultStepClientID, "SPIFFE ID of the step client (serve)")
	fs.StringVar(&sf.keysDir, "step-keys-dir", "", "directory of the management public keys, *.pub (serve)")
	fs.StringVar(&sf.env, "env", "dev", "environment name of steps and specs (serve)")
	fs.StringVar(&sf.cpCluster, "cp-cluster", "dev-cp", "control plane cluster that the admitting stage targets (serve)")
	fs.StringVar(&sf.journalDir, "journal-dir", "", "directory of the step journal and logs (serve, create); serve runs the step route only with it")
	fs.StringVar(&sf.repoRoot, "repo-root", ".", "repository root of the bootstrap digest (serve)")
	fs.StringVar(&sf.adminSocket, "admin-socket", "", "path of the admin socket (serve, ctl); default <journal-dir>/../admin.sock for serve, build/hostsvc/admin.sock for ctl")
	fs.StringVar(&sf.bootstrapCmd, "bootstrap-cmd", "mise run cell:up", "command of the admitting and bootstrapping stages (serve)")
	retry := fs.Bool("retry-of-create", false, "delete a half-built cluster that has no marker first (create)")
	root := fs.String("root", ".", "repository root (bootstrap-digest)")
	stepID := fs.String("step", "", "step ID (ctl log, cancel)")
	follow := fs.Bool("follow", false, "follow the log (ctl log)")
	cellName := fs.String("cell", "", "cell name (ctl cancel)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch cmd {
	case "pin":
		return pin(ctx, *addr, *expect, out)
	case "bootstrap-digest":
		sum, n, err := hostsvc.BootstrapDigest(*root)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Sum   string `json:"bootstrapSHA256"`
			Files int    `json:"files"`
		}{sum, n})
	case "ctl":
		return ctl(ctx, sub, sf.adminSocket, *stepID, *cellName, *follow, out)
	}
	if sf.journalDir == "" && cmd == "create" {
		if sf.journalDir = os.Getenv("POC_JOURNAL_DIR"); sf.journalDir == "" {
			sf.journalDir = defaultJournalDir
		}
	}
	topo, err := topology.Load(*topoPath)
	if err != nil {
		return err
	}
	svc := hostsvc.New(hostsvc.NewKindRuntime(), topo)

	names := func() []string {
		if *only != "" {
			return []string{*only}
		}
		var out []string
		for _, c := range topo.Clusters {
			out = append(out, c.Name)
		}
		return out
	}

	switch cmd {
	case "up":
		if *only == "" {
			return svc.UpAll(ctx)
		}
		_, err := svc.Up(ctx, *only)
		return err
	case "create":
		if *name == "" {
			return fmt.Errorf("create needs --cluster")
		}
		if err := hostsvc.CheckCreateStep(sf.journalDir, os.Getenv("POC_STEP_ID"), *name); err != nil {
			return err
		}
		svc.Records, svc.StepID = hostsvc.FileCreateRecords{Dir: sf.journalDir}, os.Getenv("POC_STEP_ID")
		_, err := svc.Create(ctx, *name, *retry)
		return err
	case "down":
		for _, n := range names() {
			if err := svc.Down(ctx, n); err != nil {
				return err
			}
		}
	case "facts":
		if *name == "" {
			return fmt.Errorf("facts needs --cluster")
		}
		f, err := svc.Facts(ctx, *name)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(f)
	case "serve":
		sf.listen, sf.bundle, sf.clientID = *listen, *bundlePath, *clientID
		return serve(ctx, svc, topo, sf, logOut)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

// stepStack is the step machinery that serve runs when --journal-dir is set.
type stepStack struct {
	spec    *hostsvc.SpecStore
	journal *hostsvc.Journal
	actor   *hostsvc.Actor
	handler struct{ steps, spec http.Handler }
	admin   http.Handler
}

func newStepStack(topo *topology.Topology, sf serveFlags, log *slog.Logger, meter metric.Meter) (*stepStack, error) {
	if sf.keysDir == "" {
		return nil, errors.New("serve needs --step-keys-dir with --journal-dir")
	}
	if !spec.ValidName(sf.env) || !spec.ValidName(sf.cpCluster) {
		return nil, errors.New("--env and --cp-cluster must be DNS labels")
	}
	cmdline := strings.Fields(sf.bootstrapCmd)
	if len(cmdline) == 0 {
		return nil, errors.New("--bootstrap-cmd is empty")
	}
	exe, err := selfExecutable()
	if err != nil {
		return nil, fmt.Errorf("find own executable: %w", err)
	}
	keys := hostsvc.KeysFromDir(sf.keysDir)
	store, err := hostsvc.OpenSpecStore(sf.journalDir, keys, sf.env)
	if err != nil {
		return nil, err
	}
	store.SetLogger(log)
	j, err := hostsvc.OpenJournal(sf.journalDir, time.Now)
	switch {
	case errors.Is(err, hostsvc.ErrJournalCorrupt):
		log.Error("journal_corrupt", "dir", sf.journalDir, "error", err.Error())
	case err != nil:
		return nil, err
	}
	j.SetLogger(log)
	j.Reap(hostsvc.KillOrphanGroup)
	root := sf.repoRoot
	v := &hostsvc.StepVerifier{
		Keys: keys, Env: sf.env, Topo: topo, Spec: store,
		Digest: func() (string, error) { sum, _, err := hostsvc.BootstrapDigest(root); return sum, err },
	}
	actor, err := hostsvc.NewActor(hostsvc.ActorConfig{
		Journal: j, Verifier: v, Spec: store, Stages: hostsvc.DefaultStages(exe, cmdline, sf.cpCluster),
		Start: hostsvc.StartGroup, Log: log, Meter: meter,
	})
	if err != nil {
		return nil, err
	}
	st := &stepStack{spec: store, journal: j, actor: actor, admin: hostsvc.NewAdminHandler(actor, j)}
	st.handler.steps = hostsvc.NewStepHandler(v, actor, log, time.Now)
	st.handler.spec = hostsvc.NewSpecHandler(store, log)
	return st, nil
}

func binarySHA256() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// serve answers key requests from the management plane until ctx ends. With --journal-dir it also
// takes specs from the management plane and signed steps from the cell controller, and runs them.
func serve(ctx context.Context, svc *hostsvc.Service, topo *topology.Topology, sf serveFlags, logOut io.Writer) error {
	listen, bundlePath, clientID := sf.listen, sf.bundle, sf.clientID
	if err := hostsvc.CheckLoopbackAddr(listen); err != nil {
		return err
	}
	soft, err := nofileSoftLimit()
	if err != nil {
		return fmt.Errorf("read the limit on open files: %w", err)
	}
	if err := hostsvc.CheckFileLimit(soft); err != nil {
		return &exitError{code: 2, err: err}
	}
	id, err := spiffeid.FromString(clientID)
	if err != nil {
		return fmt.Errorf("client id: %w", err)
	}
	if id.TrustDomain().Name() != hostsvc.MgmtTrustDomain || id.Path() == "" {
		return fmt.Errorf("client id %q must be a workload in trust domain %s", clientID, hostsvc.MgmtTrustDomain)
	}
	stepID, err := spiffeid.FromString(sf.stepID)
	if err != nil {
		return fmt.Errorf("step client id: %w", err)
	}
	if stepID.TrustDomain().Name() != hostsvc.StepClientTrustDomain || stepID.Path() == "" {
		return fmt.Errorf("step client id %q must be a workload in trust domain %s", sf.stepID, hostsvc.StepClientTrustDomain)
	}
	if bundlePath == "" {
		return errors.New("serve needs --client-bundle")
	}
	mgmtRoots, err := hostsvc.LoadClientRoots(bundlePath, id.TrustDomain(), time.Now())
	if err != nil {
		return err
	}
	devPaths := map[spiffeid.TrustDomain]string{stepID.TrustDomain(): sf.stepBundle}
	devRoots := hostsvc.FileBundleSet(devPaths)
	roots := hostsvc.MultiSource(map[spiffeid.TrustDomain]x509bundle.Source{id.TrustDomain(): mgmtRoots, stepID.TrustDomain(): devRoots})
	cert, err := hostsvc.SelfSignedCert(hostsvc.KeyServerHost, time.Now())
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	log := slog.Default()
	var tel *telemetry.T
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		t, err := startTelemetry(ctx, "hostsvc", logOut)
		if err != nil {
			return fmt.Errorf("start telemetry: %w", err)
		}
		tel, log = t, t.Log
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := t.Shutdown(sctx); err != nil {
				slog.Warn("telemetry shutdown", "error", err)
			}
		}()
	}
	var meter metric.Meter
	if tel != nil {
		meter = tel.Meter
	}

	cells := topo.WithComponent(keyedComponent)
	cache := hostsvc.NewKeyCache(svc.Facts, hostsvc.KeyTTL, hostsvc.KeyMaxInFlight, nil)
	isKnown := func(n string) bool { return slices.Contains(cells, n) }
	keys := hostsvc.NewKeyHandler(cache, isKnown, log)
	if tel != nil {
		if keys, err = hostsvc.NewInstrumentedKeyHandler(cache, isKnown, log, tel.Tracer, tel.Meter); err != nil {
			return fmt.Errorf("instrument key handler: %w", err)
		}
	}
	if (sf.journalDir == "") != (sf.keysDir == "") {
		return errors.New("serve needs both --journal-dir and --step-keys-dir, or neither")
	}
	var stack *stepStack
	var stepsH, specH http.Handler
	tlsIDs := []spiffeid.ID{id}
	if sf.journalDir != "" {
		if stack, err = newStepStack(topo, sf, log, meter); err != nil {
			return err
		}
		stepsH, specH = stack.handler.steps, stack.handler.spec
		tlsIDs = append(tlsIDs, stepID)
	}
	rctx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	actorDone := make(chan struct{})
	var adminSrv *http.Server
	if stack != nil {
		sock := sf.adminSocket
		if sock == "" {
			sock = filepath.Join(filepath.Dir(sf.journalDir), "admin.sock")
		}
		aln, err := hostsvc.ListenAdmin(sock)
		if err != nil {
			return err
		}
		adminSrv = hostsvc.NewAdminServer(stack.admin)
		go func() { _ = adminSrv.Serve(aln) }()
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = adminSrv.Shutdown(sctx)
		}()
		go func() {
			defer close(actorDone)
			_ = stack.actor.Run(rctx)
		}()
	} else {
		close(actorDone)
	}

	srv := hostsvc.NewKeyServer(hostsvc.NewRouter(keys, specH, stepsH, id, stepID, maxStepInFlight), hostsvc.ServerTLS(cert, roots, tlsIDs...), log)
	certSum := sha256.Sum256(cert.Leaf.Raw)
	log.Info("serving", "addr", ln.Addr().String(), "cert_sha256", hex.EncodeToString(certSum[:]),
		"root_sha256", mgmtRoots.SHA256(), "dev_root_sha256", devRoots.SHA256(stepID.TrustDomain()),
		"binary_sha256", binarySHA256(), "pid", os.Getpid(), "client_id", id.String(), "clusters", cells)
	err = hostsvc.ServeKeys(ctx, srv, ln, log, meter)
	stopRun()
	select {
	case <-actorDone:
	case <-time.After(30 * time.Second):
		log.Error("actor did not stop in time")
	}
	return err
}

// ctl sends one command to the admin socket. A command prints one JSON line, except log, which
// prints the step log.
func ctl(ctx context.Context, sub, sock, stepID, cell string, follow bool, out io.Writer) error {
	if sock == "" {
		sock = defaultAdminSocket
	}
	c := hostsvc.NewAdminClient(sock)
	var method, path string
	switch sub {
	case "steps":
		method, path = http.MethodGet, "/steps"
	case "log":
		if stepID == "" {
			return errors.New("log needs --step")
		}
		method, path = http.MethodGet, "/log?step="+url.QueryEscape(stepID)
		if follow {
			path += "&follow=1"
		}
	case "cancel":
		if (cell == "") == (stepID == "") {
			return errors.New("cancel needs exactly one of --cell and --step")
		}
		method, path = http.MethodPost, "/cancel?cell="+url.QueryEscape(cell)
		if cell == "" {
			path = "/cancel?step=" + url.QueryEscape(stepID)
		}
	case "reset-journal":
		method, path = http.MethodPost, "/reset-journal"
	default:
		return fmt.Errorf("unknown ctl command %q", sub)
	}
	body, err := c.Do(ctx, method, path)
	if err != nil {
		return err
	}
	defer body.Close()
	if sub == "log" {
		_, err = io.Copy(out, body)
		return err
	}
	var v json.RawMessage
	if err := json.NewDecoder(body).Decode(&v); err != nil {
		return fmt.Errorf("read answer: %w", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, v); err != nil {
		return err
	}
	compact.WriteByte('\n')
	_, err = out.Write(compact.Bytes())
	return err
}

// pin makes one handshake that accepts any certificate, and prints the leaf as one PEM block.
// With expect set, a leaf with another SHA-256 is an error and nothing is printed.
func pin(ctx context.Context, addr, expect string, out io.Writer) error {
	var want []byte
	if expect != "" {
		var err error
		if want, err = hex.DecodeString(strings.TrimSpace(expect)); err != nil || len(want) != sha256.Size {
			return errors.New("--expect-sha256 must be 64 hexadecimal digits")
		}
	}
	var leaf []byte
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: hostsvc.KeyServerHost,
		// The command exists to read the certificate that the server presents.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			leaf = cs.PeerCertificates[0].Raw
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("pin %s: %w", addr, err)
	}
	_ = conn.Close()
	if want != nil {
		if sum := sha256.Sum256(leaf); !bytes.Equal(sum[:], want) {
			return fmt.Errorf("server certificate has SHA-256 %x, want %x", sum, want)
		}
	}
	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: leaf})
}
