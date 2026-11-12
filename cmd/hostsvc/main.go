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
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

const (
	defaultServeAddr = "127.0.0.1:17443"
	defaultClientID  = "spiffe://" + hostsvc.MgmtTrustDomain + "/api"
	keyedComponent   = "cell-identity"
)

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
	return cli.Run(stdout, "hostsvc", func(out io.Writer) error { return run(ctx, args, out, stdout) })
}

// run runs one command. It writes data to out, and the logs of serve go to logOut.
func run(ctx context.Context, args []string, out, logOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hostsvc up|down [--only <name>] | facts --cluster <name> | serve --listen <addr> --client-bundle <file> [--client-id <id>] | pin --addr <addr> [--expect-sha256 <hex>]  [--topology <file>]")
	}
	cmd := args[0]
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
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if cmd == "pin" {
		return pin(ctx, *addr, *expect, out)
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
		for _, n := range names() {
			if _, err := svc.Up(ctx, n); err != nil {
				return err
			}
		}
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
		return serve(ctx, svc, topo, *listen, *bundlePath, *clientID, logOut)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

// serve answers key requests from the management plane until ctx ends.
func serve(ctx context.Context, svc *hostsvc.Service, topo *topology.Topology, listen, bundlePath, clientID string, logOut io.Writer) error {
	if err := hostsvc.CheckLoopbackAddr(listen); err != nil {
		return err
	}
	id, err := spiffeid.FromString(clientID)
	if err != nil {
		return fmt.Errorf("client id: %w", err)
	}
	if id.TrustDomain().Name() != hostsvc.MgmtTrustDomain || id.Path() == "" {
		return fmt.Errorf("client id %q must be a workload in trust domain %s", clientID, hostsvc.MgmtTrustDomain)
	}
	if bundlePath == "" {
		return errors.New("serve needs --client-bundle")
	}
	roots, err := hostsvc.NewBundleFile(bundlePath, id.TrustDomain())
	if err != nil {
		return err
	}
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
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		t, err := telemetry.Start(ctx, "hostsvc", logOut)
		if err != nil {
			return fmt.Errorf("start telemetry: %w", err)
		}
		log = t.Log
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := t.Shutdown(sctx); err != nil {
				slog.Warn("telemetry shutdown", "error", err)
			}
		}()
	}

	cells := topo.WithComponent(keyedComponent)
	cache := hostsvc.NewKeyCache(svc.Facts, hostsvc.KeyTTL, hostsvc.KeyMaxInFlight, nil)
	handler := hostsvc.NewKeyHandler(cache, func(n string) bool { return slices.Contains(cells, n) }, log)
	srv := hostsvc.NewKeyServer(handler, hostsvc.ServerTLS(cert, roots, id), log)
	certSum := sha256.Sum256(cert.Leaf.Raw)
	log.Info("serving", "addr", ln.Addr().String(), "cert_sha256", hex.EncodeToString(certSum[:]),
		"root_sha256", roots.RootSHA256(), "pid", os.Getpid(), "client_id", id.String(), "clusters", cells)
	return hostsvc.ServeKeys(ctx, srv, ln)
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
