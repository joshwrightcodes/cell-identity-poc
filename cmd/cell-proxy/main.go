// Command cell-proxy carries streams between the planes over SPIFFE mTLS.
//
//	cell-proxy spiffe-client --listen <addr> --upstream <host:port> --expect-id <id> --peer-bundle <file> --peer-trust-domain <td> [--proof]
//	cell-proxy spiffe-server --listen <addr> --peer-bundle <file> --peer-trust-domain <td> --allow-id <regex> --registry-dir <dir> --registry-signer <file> --backend grpc-header --upstream <host:port> --identity-header x-cell-agent
//	cell-proxy spiffe-server --listen <addr> --peer-bundle <file> --peer-trust-domain <td> --allow-id <regex> --registry-dir <dir> --registry-signer <file> --backend otlp --upstream <host:port> [--upstream-wait <duration>]
//	cell-proxy spiffe-server ... --backend tunnel --tunnel-cell <cell>=<listen addr> [--tunnel-cell ...] [--tunnel-wait 10s]
//	cell-proxy spiffe-server ... --proof-subject <role>=<namespace>/<service account> [--proof-subject ...] [--registry-reload 10s]
//	cell-proxy tunnel --upstream <host:port> --expect-id <id> --peer-bundle <file> --peer-trust-domain <td> [--proof]
//	cell-proxy promql-proxy --listen <addr> --upstream <url>
//	cell-proxy token --listen <addr> --upstream <host:port> --audience <aud> --reader <user> [--reader ...] [--writer <user> ...] [--health <addr>]
//	cell-proxy token-client --listen <loopback addr> --upstream <host:port> --token-file <file> [--health <addr>]
//	cell-proxy probe --upstream <host:port> --expect-id <id> --peer-bundle <file> --peer-trust-domain <td>
//	cell-proxy whoami
//
// spiffe-client takes plaintext TCP and pipes each connection over mTLS to one exact server ID.
// spiffe-server ends mTLS, checks the client ID against --allow-id and the signed cell records
// in --registry-dir, and hands the connection to its backend. The otlp backend is the telemetry
// gateway: it sets the source attributes again and forwards OTLP in plaintext gRPC to --upstream,
// a peer in the same namespace. With --upstream-wait it opens its listener only after the first
// upstream connection is ready, and fails when that takes longer. Both get their own SVID from the Workload API at
// SPIFFE_ENDPOINT_SOCKET, and trust a peer only through the --peer-bundle file.
// They log compact JSON to stdout and export OTLP, as package internal/telemetry describes. A
// configuration error is one JSON error line and exit status 2. promql-proxy passes only the
// Prometheus reads of Kiali to --upstream, and has no SVID.
//
// With --proof, spiffe-client and tunnel send a second proof before the first payload byte: a
// service account token of their pod, bound to the TLS session of the connection. They need the
// in-cluster configuration and the pod environment. spiffe-server checks the proof of each cell
// source against the live registry and the service account that --proof-subject names for the role
// of the source. An --allow-id that can admit a cell source needs at least one --proof-subject.
// spiffe-server needs --registry-signer. It reloads the registry every --registry-reload, refuses a
// registry whose signers.pub differs from that file, and keeps the last good registry on an error.
//
// probe makes one handshake with no client certificate, and prints the verified server ID.
// whoami prints the sorted IDs of the X.509 SVIDs of this process and expiresAt, the RFC 3339 NotAfter of
// the first SVID in the order of the Workload API, which is not always the first ID printed. Neither starts telemetry. A configuration error is one JSON error line and exit status 2, as in the other modes. Any other
// failure is one JSON error line and exit status 1. The probe error line carries a reason:
// upstream_unavailable when the dial fails, peer_untrusted, peer_not_allowed or protocol_not_h2
// for a refused server, and handshake_failed for any other handshake error.
//
// The tunnel backend of spiffe-server holds one tunnel for each --tunnel-cell, and serves a
// plaintext HTTP listener for each cell that sends its requests through the tunnel of that cell.
// tunnel is the cell side: it dials one exact server ID with its SVID, and serves the allowed
// Kubernetes reads on the dialed connection with the token of its pod. promql-proxy passes only
// the Prometheus reads of Kiali to --upstream, and has no SVID.
//
// token fronts the in-cluster bundle store. It asks the TokenReview API who owns the bearer token of
// each request, and passes a read (GET, HEAD) only for a --reader and a write (POST, PUT, PATCH)
// only for a --writer. It refuses every other request with 403 and counts it in store_proxy.denials.
// Its --health route answers 200 only while GET /v2/ on --upstream answers 200 or 401 within 2 s, and 503 otherwise.
// With no --writer, it refuses every write. token-client listens on a loopback address only, and
// sends each request to --upstream with the token that --token-file holds, which it reads again for
// every request. Neither mode has an SVID.
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
	"os"
	"os/signal"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const (
	name = "cell-proxy"
	// sourceTimeout bounds the wait for the first SVID from the Workload API.
	sourceTimeout = 30 * time.Second
	// shutdownTimeout bounds the whole telemetry flush.
	shutdownTimeout = 15 * time.Second
	// exitConfig is the status of a configuration error.
	exitConfig = 2
	// drainTimeout bounds the wait for running calls when the server stops.
	drainTimeout = 5 * time.Second
	// upstreamMaxBackoff bounds the wait between two connection attempts to the OTLP upstream, so
	// the gateway follows a store that comes back.
	upstreamMaxBackoff = 5 * time.Second
	// registryReload is the default of --registry-reload.
	registryReload = 10 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second signal ends the process at once, also during the flush.
	context.AfterFunc(ctx, stop)
	code := execute(ctx, os.Args[1:], os.Stdout)
	stop()
	os.Exit(code)
}

// execute runs one mode and returns the exit status.
func execute(ctx context.Context, args []string, stdout io.Writer) int {
	if len(args) == 0 {
		cli.Fail(stdout, name, errors.New("give a mode: spiffe-client, spiffe-server, tunnel, tunnel-status, promql-proxy, token, token-client, probe or whoami"))
		return exitConfig
	}
	switch args[0] {
	case "spiffe-client":
		return runClient(ctx, args[1:], stdout)
	case "spiffe-server":
		return runServer(ctx, args[1:], stdout)
	case "tunnel":
		return runTunnel(ctx, args[1:], stdout)
	case "tunnel-status":
		return runTunnelStatus(ctx, args[1:], stdout)
	case "promql-proxy":
		return runPromProxy(ctx, args[1:], stdout)
	case "token":
		return runToken(ctx, args[1:], stdout)
	case "token-client":
		return runTokenClient(ctx, args[1:], stdout)
	case "probe":
		cfg, err := parseProbe(args[1:])
		if err != nil {
			cli.Fail(stdout, name, err)
			return exitConfig
		}
		return cli.Run(stdout, name, func(out io.Writer) error { return probe(ctx, cfg, out) })
	case "whoami":
		if len(args) > 1 {
			cli.Fail(stdout, name, errors.New("whoami takes no arguments"))
			return exitConfig
		}
		return cli.Run(stdout, name, func(out io.Writer) error { return whoami(ctx, out) })
	}
	cli.Fail(stdout, name, fmt.Errorf("unknown mode %q", args[0]))
	return exitConfig
}

func newFlags(mode string) *flag.FlagSet {
	fs := flag.NewFlagSet(name+" "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags parses args and refuses an argument that is not a flag.
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

// loadPeer reads the peer bundle file for the trust domain td. It is the only source of peer
// trust.
func loadPeer(path, td string) (*x509bundle.Bundle, spiffeid.TrustDomain, error) {
	trustDomain, err := spiffeid.TrustDomainFromString(td)
	if err != nil {
		return nil, spiffeid.TrustDomain{}, fmt.Errorf("--peer-trust-domain: %w", err)
	}
	b, err := x509bundle.Load(trustDomain, path)
	if err != nil {
		return nil, spiffeid.TrustDomain{}, fmt.Errorf("--peer-bundle: %w", err)
	}
	if b.Empty() {
		return nil, spiffeid.TrustDomain{}, errors.New("--peer-bundle holds no certificate")
	}
	return b, trustDomain, nil
}

// expectedID parses --expect-id, which must be in the peer trust domain.
func expectedID(s string, td spiffeid.TrustDomain) (spiffeid.ID, error) {
	id, err := spiffeid.FromString(s)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("--expect-id: %w", err)
	}
	if id.TrustDomain() != td {
		return spiffeid.ID{}, fmt.Errorf("--expect-id %s is not in --peer-trust-domain %s", id, td)
	}
	return id, nil
}

type clientConfig struct {
	listen, upstream string
	expect           spiffeid.ID
	peer             *x509bundle.Bundle
	proof            bool
}

func parseClient(args []string) (clientConfig, error) {
	fs := newFlags("spiffe-client")
	listen := fs.String("listen", "", "plaintext address to listen on")
	upstream := fs.String("upstream", "", "server address as host:port")
	expect := fs.String("expect-id", "", "the exact SPIFFE ID of the server")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the server trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the server")
	withProof := fs.Bool("proof", false, "send a pod-bound service account token as a second proof before the first payload byte")
	if err := parseFlags(fs, args); err != nil {
		return clientConfig{}, err
	}
	if err := required(map[string]string{"listen": *listen, "upstream": *upstream, "expect-id": *expect, "peer-bundle": *bundle, "peer-trust-domain": *td}); err != nil {
		return clientConfig{}, err
	}
	peer, trustDomain, err := loadPeer(*bundle, *td)
	if err != nil {
		return clientConfig{}, err
	}
	id, err := expectedID(*expect, trustDomain)
	if err != nil {
		return clientConfig{}, err
	}
	return clientConfig{listen: *listen, upstream: *upstream, expect: id, peer: peer, proof: *withProof}, nil
}

func runClient(ctx context.Context, args []string, stdout io.Writer) int {
	cfg, err := parseClient(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return serve(ctx, stdout, func(ctx context.Context, tel *telemetry.T, svids *workloadapi.X509Source) error {
		c := &cellproxy.Client{TLS: cellproxy.ClientTLS(svids, cfg.peer, cfg.expect), Upstream: cfg.upstream, Log: tel.Log}
		if cfg.proof {
			kc, err := rest.InClusterConfig()
			if err != nil {
				return fmt.Errorf("in-cluster config: %w", err)
			}
			if c.Proof, err = newProofFunc(svids, kc); err != nil {
				return err
			}
		}
		ln, err := net.Listen("tcp", cfg.listen)
		if err != nil {
			return err
		}
		return c.Serve(ctx, ln)
	})
}

type serverConfig struct {
	listen   string
	peer     *x509bundle.Bundle
	allow    *regexp.Regexp
	registry *cellproxy.Registry
	// registryDir, signer and reload set the watcher.
	registryDir, signer string
	reload              time.Duration
	// signerSHA256 is the fingerprint of the pinned keys that LoadPinnedRegistry returned.
	signerSHA256 string
	// subjects maps a role to the service account that sends its proof.
	subjects map[string]record.Subject
	backend  func(tel *telemetry.T) (cellproxy.Backend, error)
	// waitUpstream, when set, blocks until the first upstream connection is ready. The server
	// opens its listener after that, so a readiness probe of the listener covers the upstream.
	waitUpstream func(ctx context.Context) error
}

func parseServer(args []string) (serverConfig, error) {
	fs := newFlags("spiffe-server")
	listen := fs.String("listen", ":8444", "address to listen on")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the client trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the clients")
	allow := fs.String("allow-id", "", "anchored regular expression for the client SPIFFE IDs")
	registryDir := fs.String("registry-dir", "", "directory with signers.pub and the *.dsse.json cell records")
	signer := fs.String("registry-signer", "", "file with the pinned signer keys: the registry is reloaded, and a registry whose signers.pub differs from this file is refused")
	reload := fs.Duration("registry-reload", registryReload, "how often to reload the registry. Needs --registry-signer")
	subjects := map[string]record.Subject{}
	fs.Func("proof-subject", "<role>=<namespace>/<service account> that sends the proof of that role; repeat for each role", proofSubjectFlag(subjects))
	backend := fs.String("backend", "", "backend for each connection: grpc-header, otlp or tunnel")
	upstream := fs.String("upstream", "", "backend upstream as host:port")
	upstreamWait := fs.Duration("upstream-wait", 0, "otlp backend: wait this long for the first upstream connection before the listener opens, and fail after that. 0 does not wait")
	header := fs.String("identity-header", "x-cell-agent", "header that carries <env>-<cell> to the upstream")
	tunnelBackend := registerTunnelFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return serverConfig{}, err
	}
	if err := required(map[string]string{"peer-bundle": *bundle, "peer-trust-domain": *td, "allow-id": *allow, "registry-dir": *registryDir, "registry-signer": *signer, "backend": *backend}); err != nil {
		return serverConfig{}, err
	}
	peer, _, err := loadPeer(*bundle, *td)
	if err != nil {
		return serverConfig{}, err
	}
	if err := fullyAnchored(*allow); err != nil {
		return serverConfig{}, fmt.Errorf("--allow-id %q: %w", *allow, err)
	}
	pattern, err := regexp.Compile(*allow)
	if err != nil {
		return serverConfig{}, fmt.Errorf("--allow-id: %w", err)
	}
	if len(subjects) == 0 && mayAdmitCell(*allow) {
		return serverConfig{}, errors.New("--allow-id can admit a cell source, so at least one --proof-subject <role>=<namespace>/<service account> is required")
	}
	if *reload <= 0 {
		return serverConfig{}, errors.New("--registry-reload must be positive")
	}
	reg, fingerprint, err := cellproxy.LoadPinnedRegistry(*registryDir, *signer)
	if err != nil {
		return serverConfig{}, fmt.Errorf("--registry-dir with --registry-signer: %w", err)
	}
	cfg := serverConfig{listen: *listen, peer: peer, allow: pattern, registry: reg, registryDir: *registryDir, signer: *signer, reload: *reload, signerSHA256: fingerprint}
	if len(subjects) > 0 {
		cfg.subjects = subjects
	}
	if *upstreamWait != 0 && *backend != "otlp" {
		return serverConfig{}, errors.New("--upstream-wait applies to --backend otlp only")
	}
	switch *backend {
	case "tunnel":
		if cfg.backend, err = tunnelBackend(*listen); err != nil {
			return serverConfig{}, err
		}
	case "grpc-header":
		if err := required(map[string]string{"upstream": *upstream, "identity-header": *header}); err != nil {
			return serverConfig{}, err
		}
		cfg.backend = func(tel *telemetry.T) (cellproxy.Backend, error) {
			return cellproxy.NewHeaderBackend(*upstream, *header, tel.Log), nil
		}
	case "otlp":
		if err := hostPort(*upstream); err != nil {
			return serverConfig{}, err
		}
		bo := backoff.DefaultConfig
		bo.MaxDelay = upstreamMaxBackoff
		up, err := grpc.NewClient(*upstream,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithConnectParams(grpc.ConnectParams{Backoff: bo}),
			grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(cellproxy.UpstreamMaxMsgBytes)))
		if err != nil {
			return serverConfig{}, fmt.Errorf("--upstream: %w", err)
		}
		if *upstreamWait < 0 {
			_ = up.Close()
			return serverConfig{}, errors.New("--upstream-wait must not be negative")
		}
		if *upstreamWait > 0 {
			cfg.waitUpstream = func(ctx context.Context) error { return waitUpstreamReady(ctx, up, *upstream, *upstreamWait) }
		}
		cfg.backend = func(tel *telemetry.T) (cellproxy.Backend, error) {
			gw, err := cellproxy.NewGateway(up, tel.Meter, tel.Log)
			if err != nil {
				_ = up.Close()
				return nil, err
			}
			up.Connect()
			tel.Log.Info("otlp upstream", "upstream", *upstream, "max_recv_bytes", cellproxy.MaxRecvMsgBytes)
			return cellproxy.NewOTLPBackend(gw, cellproxy.MaxRecvMsgBytes), nil
		}
	default:
		return serverConfig{}, fmt.Errorf("unknown --backend %q", *backend)
	}
	return cfg, nil
}

// waitUpstreamReady blocks until conn is READY, for at most wait. It starts the first connect. It
// returns ctx.Err() when ctx ends first, so a stop of the pod is no failure of the wait.
func waitUpstreamReady(ctx context.Context, conn *grpc.ClientConn, target string, wait time.Duration) error {
	start := time.Now()
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	conn.Connect()
	for state := conn.GetState(); state != connectivity.Ready; state = conn.GetState() {
		if !conn.WaitForStateChange(wctx, state) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("the upstream %s was not ready after %s (limit %s), last state %s", target, time.Since(start).Round(time.Millisecond), wait, state)
		}
	}
	return nil
}

// hostPort checks that --upstream is host:port with a host and a port number.
func hostPort(s string) error {
	if s == "" {
		return errors.New("--upstream required")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("--upstream %q is not host:port: %w", s, err)
	}
	if n, err := strconv.Atoi(port); host == "" || err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("--upstream %q needs a host and a port from 1 to 65535", s)
	}
	return nil
}

func runServer(ctx context.Context, args []string, stdout io.Writer) int {
	cfg, err := parseServer(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return serve(ctx, stdout, func(ctx context.Context, tel *telemetry.T, svids *workloadapi.X509Source) error {
		st := cfg.registry.Stats()
		tel.Log.Info("registry loaded", "content_sha256", cfg.registry.ContentSHA256(),
			"records", st.Records, "revoked", st.Revoked, "signers", st.Signers)
		backend, err := cfg.backend(tel)
		if err != nil {
			return err
		}
		if d, ok := backend.(interface{ Shutdown(context.Context) }); ok {
			stop := context.AfterFunc(ctx, func() {
				dctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
				defer cancel()
				d.Shutdown(dctx)
			})
			defer stop()
		}
		if cfg.waitUpstream != nil {
			if err := cfg.waitUpstream(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			tel.Log.Info("otlp upstream ready")
		}
		ln, err := net.Listen("tcp", cfg.listen)
		if err != nil {
			return err
		}
		reg := cellproxy.WatchLoaded(ctx, cfg.registry, cfg.signerSHA256, cfg.registryDir, cfg.signer, cfg.reload, tel.Log)
		scfg := serverProofConfig(cellproxy.ServerConfig{TLS: cellproxy.ServerTLS(svids, cfg.peer, cfg.allow, reg, tel.Log), Meter: tel.Meter}, cfg, reg)
		srv := cellproxy.NewServer(scfg, backend, tel.Log)
		reg.OnAdopt(func(r *cellproxy.Registry) { srv.CloseRevoked(r) })
		return serveBackend(ctx, srv, ln, backend)
	})
}

// serve starts telemetry and the X.509 source, then runs fn until ctx ends. A failure is one
// JSON error line and status 1.
func serve(ctx context.Context, stdout io.Writer, fn func(context.Context, *telemetry.T, *workloadapi.X509Source) error) int {
	return serveTelemetry(ctx, stdout, func(ctx context.Context, tel *telemetry.T) error {
		sctx, cancel := context.WithTimeout(ctx, sourceTimeout)
		svids, err := workloadapi.NewX509Source(sctx)
		cancel()
		if err != nil {
			return fmt.Errorf("x509 source from the workload api: %w", err)
		}
		defer func() { _ = svids.Close() }()
		return fn(ctx, tel, svids)
	})
}

// serveTelemetry starts telemetry, then runs fn until ctx ends. A failure is one JSON error line
// and status 1.
func serveTelemetry(ctx context.Context, stdout io.Writer, fn func(context.Context, *telemetry.T) error) int {
	tel, err := telemetry.Start(ctx, name, stdout)
	if err != nil {
		cli.Fail(stdout, name, fmt.Errorf("start telemetry: %w", err))
		return 1
	}
	cellproxy.BridgeStdLog(tel.Log)
	defer func() {
		// ctx may have ended, so the flush gets a context of its own.
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := tel.Shutdown(sctx); err != nil {
			slog.New(slog.NewJSONHandler(stdout, nil)).Warn("telemetry shutdown", "error", err.Error())
		}
	}()
	if err := fn(ctx, tel); err != nil {
		tel.Log.Error(name+" failed", "error", err.Error())
		return 1
	}
	tel.Log.Info("stopped")
	return 0
}

// fullyAnchored requires that the whole pattern sits between ^ and $. A top-level alternation
// such as ^a|b$ anchors each branch at one end only, so it fails. Group it as ^(?:a|b)$.
func fullyAnchored(p string) error {
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return err
	}
	re = re.Simplify()
	if re.Op == syntax.OpConcat && len(re.Sub) >= 2 &&
		re.Sub[0].Op == syntax.OpBeginText && re.Sub[len(re.Sub)-1].Op == syntax.OpEndText {
		return nil
	}
	return errors.New("must be one expression between ^ and $, for example ^(?:a|b)$")
}

// reasonError adds the reason of a refused probe to the error line.
type reasonError struct {
	reason cellproxy.Reason
	err    error
}

func (e reasonError) Error() string   { return e.err.Error() }
func (e reasonError) Unwrap() error   { return e.err }
func (e reasonError) LogAttrs() []any { return []any{"reason", string(e.reason)} }

type probeConfig struct {
	upstream string
	expect   spiffeid.ID
	peer     *x509bundle.Bundle
}

func parseProbe(args []string) (probeConfig, error) {
	fs := newFlags("probe")
	upstream := fs.String("upstream", "", "server address as host:port")
	expect := fs.String("expect-id", "", "the exact SPIFFE ID of the server")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the server trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the server")
	if err := parseFlags(fs, args); err != nil {
		return probeConfig{}, err
	}
	if err := required(map[string]string{"upstream": *upstream, "expect-id": *expect, "peer-bundle": *bundle, "peer-trust-domain": *td}); err != nil {
		return probeConfig{}, err
	}
	peer, trustDomain, err := loadPeer(*bundle, *td)
	if err != nil {
		return probeConfig{}, err
	}
	want, err := expectedID(*expect, trustDomain)
	if err != nil {
		return probeConfig{}, err
	}
	return probeConfig{upstream: *upstream, expect: want, peer: peer}, nil
}

func probe(ctx context.Context, cfg probeConfig, out io.Writer) error {
	got, err := cellproxy.Probe(ctx, cfg.upstream, cfg.peer, cfg.expect)
	if err != nil {
		reason := cellproxy.ReasonOf(err)
		var op *net.OpError
		switch {
		case reason != "":
		case errors.As(err, &op) && op.Op == "dial":
			reason = cellproxy.UpstreamUnavailable
		default:
			reason = cellproxy.HandshakeFailed
		}
		return reasonError{reason: reason, err: err}
	}
	return json.NewEncoder(out).Encode(struct {
		ServerID string `json:"server_id"`
		Verified bool   `json:"verified"`
	}{got.String(), true})
}

func whoami(ctx context.Context, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, sourceTimeout)
	defer cancel()
	svids, err := workloadapi.FetchX509SVIDs(ctx)
	if err != nil {
		return fmt.Errorf("fetch x509 svids from the workload api: %w", err)
	}
	ids := make([]string, 0, len(svids))
	for _, s := range svids {
		ids = append(ids, s.ID.String())
	}
	slices.Sort(ids)
	var expires string
	if len(svids) > 0 && len(svids[0].Certificates) > 0 {
		expires = svids[0].Certificates[0].NotAfter.UTC().Format(time.RFC3339)
	}
	return json.NewEncoder(out).Encode(struct {
		IDs       []string `json:"ids"`
		ExpiresAt string   `json:"expiresAt"`
	}{slices.Compact(ids), expires})
}

// serverProofConfig sets the proof check on every server, whatever the --allow-id pattern allows.
// A cell source whose role has no --proof-subject is refused, so the check fails closed.
func serverProofConfig(scfg cellproxy.ServerConfig, cfg serverConfig, reg cellproxy.RegistrySource) cellproxy.ServerConfig {
	scfg.Proof = &cellproxy.ProofCheck{Registry: reg, Subjects: cfg.subjects}
	return scfg
}

var subjectName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// proofSubjectFlag parses one --proof-subject <role>=<namespace>/<service account> into subjects.
func proofSubjectFlag(subjects map[string]record.Subject) func(string) error {
	return func(v string) error {
		role, rest, ok := strings.Cut(v, "=")
		ns, sa, ok2 := strings.Cut(rest, "/")
		if !ok || !ok2 || !subjectName.MatchString(role) || !subjectName.MatchString(ns) || !subjectName.MatchString(sa) {
			return fmt.Errorf("%q is not <role>=<namespace>/<service account>", v)
		}
		if _, dup := subjects[role]; dup {
			return fmt.Errorf("role %s is given twice", role)
		}
		subjects[role] = record.Subject{Namespace: ns, ServiceAccount: sa}
		return nil
	}
}

// mayAdmitCell reports whether the anchored pattern p can admit an ID with a cell/ path. It says
// no only when the pattern names the /cp/ path as a literal, the literals of the pattern, joined and
// folded to lower case, do not spell cell, and no element can match a slash by itself. It only
// gives an early configuration error: the proof check of the server does not depend on it.
func mayAdmitCell(p string) bool {
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return true
	}
	var cp, wild bool
	var all strings.Builder
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpLiteral:
			lit := string(r.Rune)
			cp = cp || strings.Contains(lit, "/cp/")
			all.WriteString(strings.ToLower(lit))
		case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			wild = true
		case syntax.OpCharClass:
			for i := 0; i+1 < len(r.Rune); i += 2 {
				if r.Rune[i] <= '/' && '/' <= r.Rune[i+1] {
					wild = true
				}
			}
		}
		for _, s := range r.Sub {
			walk(s)
			if r.Op == syntax.OpRepeat || r.Op == syntax.OpStar || r.Op == syntax.OpPlus {
				walk(s)
			}
		}
	}
	walk(re)
	return !cp || strings.Contains(all.String(), "cell") || wild
}

// newProofFunc makes the ProofFunc of this process: a token of the pod for the cell and role in
// its SVID. It reads the pod identity from the environment and asks the cell API server for tokens.
func newProofFunc(svids x509svid.Source, kc *rest.Config) (cellproxy.ProofFunc, error) {
	svid, err := svids.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("--proof: svid: %w", err)
	}
	src, err := cellproxy.ParseSource(svid.ID)
	if err != nil || src.Plane != cellproxy.PlaneCell {
		return nil, fmt.Errorf("--proof needs the SVID of a cell workload, not %s", svid.ID)
	}
	api, err := corev1client.NewForConfig(kc)
	if err != nil {
		return nil, fmt.Errorf("--proof: kubernetes client: %w", err)
	}
	tokens, err := satoken.PodTokenFuncFromEnv(api)
	if err != nil {
		return nil, fmt.Errorf("--proof: %w", err)
	}
	return cellproxy.NewProofWriter(tokens, src.Cell, src.Role), nil
}
