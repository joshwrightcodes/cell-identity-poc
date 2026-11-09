// Command cell-proxy carries streams between the planes over SPIFFE mTLS.
//
//	cell-proxy spiffe-client --listen <addr> --upstream <host:port> --expect-id <id> --peer-bundle <file> --peer-trust-domain <td>
//	cell-proxy spiffe-server --listen <addr> --peer-bundle <file> --peer-trust-domain <td> --allow-id <regex> --registry-dir <dir> --backend grpc-header --upstream <host:port> --identity-header x-cell-agent
//	cell-proxy spiffe-server --listen <addr> --peer-bundle <file> --peer-trust-domain <td> --allow-id <regex> --registry-dir <dir> --backend otlp --upstream <host:port>
//	cell-proxy probe --upstream <host:port> --expect-id <id> --peer-bundle <file> --peer-trust-domain <td>
//	cell-proxy whoami
//
// spiffe-client takes plaintext TCP and pipes each connection over mTLS to one exact server ID.
// spiffe-server ends mTLS, checks the client ID against --allow-id and the signed cell records
// in --registry-dir, and hands the connection to its backend. The otlp backend is the telemetry
// gateway: it sets the source attributes again and forwards OTLP in plaintext gRPC to --upstream,
// a peer in the same namespace. Both get their own SVID from the Workload API at
// SPIFFE_ENDPOINT_SOCKET, and trust a peer only through the --peer-bundle file.
// They log compact JSON to stdout and export OTLP, as package internal/telemetry describes. A
// configuration error is one JSON error line and exit status 2.
//
// probe makes one handshake with no client certificate, and prints the verified server ID.
// whoami prints the sorted IDs of the X.509 SVIDs of this process. Neither starts telemetry. A
// configuration error is one JSON error line and exit status 2, as in the other modes. Any other
// failure is one JSON error line and exit status 1. The probe error line carries a reason:
// upstream_unavailable when the dial fails, peer_untrusted, peer_not_allowed or protocol_not_h2
// for a refused server, and handshake_failed for any other handshake error.
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
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
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
	// otlpMaxRecvBytes is the largest OTLP message after decompression. Collectors set
	// send_batch_max_size so that a batch stays below it.
	otlpMaxRecvBytes = 8 << 20
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
		cli.Fail(stdout, name, errors.New("give a mode: spiffe-client, spiffe-server, probe or whoami"))
		return exitConfig
	}
	switch args[0] {
	case "spiffe-client":
		return runClient(ctx, args[1:], stdout)
	case "spiffe-server":
		return runServer(ctx, args[1:], stdout)
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
}

func parseClient(args []string) (clientConfig, error) {
	fs := newFlags("spiffe-client")
	listen := fs.String("listen", "", "plaintext address to listen on")
	upstream := fs.String("upstream", "", "server address as host:port")
	expect := fs.String("expect-id", "", "the exact SPIFFE ID of the server")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the server trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the server")
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
	return clientConfig{listen: *listen, upstream: *upstream, expect: id, peer: peer}, nil
}

func runClient(ctx context.Context, args []string, stdout io.Writer) int {
	cfg, err := parseClient(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return exitConfig
	}
	return serve(ctx, stdout, func(ctx context.Context, tel *telemetry.T, svids *workloadapi.X509Source) error {
		ln, err := net.Listen("tcp", cfg.listen)
		if err != nil {
			return err
		}
		c := &cellproxy.Client{TLS: cellproxy.ClientTLS(svids, cfg.peer, cfg.expect), Upstream: cfg.upstream, Log: tel.Log}
		return c.Serve(ctx, ln)
	})
}

type serverConfig struct {
	listen   string
	peer     *x509bundle.Bundle
	allow    *regexp.Regexp
	registry *cellproxy.Registry
	backend  func(tel *telemetry.T) (cellproxy.Backend, error)
}

func parseServer(args []string) (serverConfig, error) {
	fs := newFlags("spiffe-server")
	listen := fs.String("listen", ":8444", "address to listen on")
	bundle := fs.String("peer-bundle", "", "PEM file with the roots of the client trust domain")
	td := fs.String("peer-trust-domain", "", "trust domain of the clients")
	allow := fs.String("allow-id", "", "anchored regular expression for the client SPIFFE IDs")
	registryDir := fs.String("registry-dir", "", "directory with signers.pub and the *.dsse.json cell records")
	backend := fs.String("backend", "", "backend for each connection: grpc-header or otlp")
	upstream := fs.String("upstream", "", "backend upstream as host:port")
	header := fs.String("identity-header", "x-cell-agent", "header that carries <env>-<cell> to the upstream")
	if err := parseFlags(fs, args); err != nil {
		return serverConfig{}, err
	}
	if err := required(map[string]string{"peer-bundle": *bundle, "peer-trust-domain": *td, "allow-id": *allow, "registry-dir": *registryDir, "backend": *backend}); err != nil {
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
	reg, err := cellproxy.LoadRegistry(*registryDir)
	if err != nil {
		return serverConfig{}, fmt.Errorf("--registry-dir: %w", err)
	}
	cfg := serverConfig{listen: *listen, peer: peer, allow: pattern, registry: reg}
	switch *backend {
	case "grpc-header":
		if err := required(map[string]string{"upstream": *upstream, "identity-header": *header}); err != nil {
			return serverConfig{}, err
		}
		cfg.backend = func(tel *telemetry.T) (cellproxy.Backend, error) {
			return cellproxy.NewHeaderBackend(*upstream, *header, tel.Log), nil
		}
	case "otlp":
		if err := required(map[string]string{"upstream": *upstream}); err != nil {
			return serverConfig{}, err
		}
		cfg.backend = func(tel *telemetry.T) (cellproxy.Backend, error) {
			up, err := grpc.NewClient(*upstream, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return nil, fmt.Errorf("--upstream: %w", err)
			}
			counter, err := cellproxy.NewOverwriteCounter(tel.Meter)
			if err != nil {
				return nil, err
			}
			return cellproxy.NewOTLPBackend(cellproxy.NewGateway(up, counter, tel.Log), otlpMaxRecvBytes), nil
		}
	default:
		return serverConfig{}, fmt.Errorf("unknown --backend %q", *backend)
	}
	return cfg, nil
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
		ln, err := net.Listen("tcp", cfg.listen)
		if err != nil {
			return err
		}
		tlsCfg := cellproxy.ServerTLS(svids, cfg.peer, cfg.allow, cfg.registry, tel.Log)
		return cellproxy.NewServer(cellproxy.ServerConfig{TLS: tlsCfg}, backend, tel.Log).Serve(ctx, ln)
	})
}

// serve starts telemetry and the X.509 source, then runs fn until ctx ends. A failure is one
// JSON error line and status 1.
func serve(ctx context.Context, stdout io.Writer, fn func(context.Context, *telemetry.T, *workloadapi.X509Source) error) int {
	tel, err := telemetry.Start(ctx, name, stdout)
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
	sctx, cancel := context.WithTimeout(ctx, sourceTimeout)
	svids, err := workloadapi.NewX509Source(sctx)
	cancel()
	if err != nil {
		tel.Log.Error(name+" failed", "error", fmt.Sprintf("x509 source from the workload api: %v", err))
		return 1
	}
	defer func() { _ = svids.Close() }()
	if err := fn(ctx, tel, svids); err != nil {
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
	return json.NewEncoder(out).Encode(struct {
		IDs []string `json:"ids"`
	}{slices.Compact(ids)})
}
