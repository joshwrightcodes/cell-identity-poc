package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const (
	mgmtTD      = "mgmt.poc.internal"
	principalID = "spiffe://mgmt.poc.internal/argocd/principal"
	viewPattern = `^spiffe://dev\.env\.poc\.internal/cell/[a-z0-9-]+/argocd-agent$`
)

// syncBuffer is a bytes.Buffer that the test can read while the command writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		var m map[string]any
		if err := json.Unmarshal(s.Bytes(), &m); err != nil {
			t.Fatalf("stdout line is not one JSON object: %q", s.Text())
		}
		lines = append(lines, m)
	}
	return lines
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, td string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://" + td)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert, key}
}

func (ca testCA) bundleFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// leaf returns the DER certificate and PKCS#8 key of an SVID for id.
func (ca testCA) leaf(t *testing.T, id string) ([]byte, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der, pkcs8, key
}

// serveTLS runs a TLS 1.3 server that presents an SVID for id and completes each handshake.
func (ca testCA) serveTLS(t *testing.T, id string) string {
	t.Helper()
	der, _, key := ca.leaf(t, id)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// fakeWorkloadAPI sends one response with its SVIDs to each FetchX509SVID caller.
type fakeWorkloadAPI struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer
	resp *workloadpb.X509SVIDResponse
}

func (f *fakeWorkloadAPI) FetchX509SVID(_ *workloadpb.X509SVIDRequest, stream grpc.ServerStreamingServer[workloadpb.X509SVIDResponse]) error {
	if err := stream.Send(f.resp); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

// serveWorkloadAPI serves SVIDs for ids from ca and sets SPIFFE_ENDPOINT_SOCKET.
func serveWorkloadAPI(t *testing.T, ca testCA, ids ...string) {
	t.Helper()
	resp := &workloadpb.X509SVIDResponse{}
	for _, id := range ids {
		der, key, _ := ca.leaf(t, id)
		resp.Svids = append(resp.Svids, &workloadpb.X509SVID{SpiffeId: id, X509Svid: der, X509SvidKey: key, Bundle: ca.cert.Raw})
	}
	// A unix socket path must be short, so the socket does not live in t.TempDir.
	dir, err := os.MkdirTemp("", "cell-proxy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "api.sock")
	lis, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(srv, &fakeWorkloadAPI{resp: resp})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix://"+path)
}

// registryDir writes a signers.pub and one record for dev-cell-1.
func registryDir(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "kid": "ec-1",
		"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	env, err := record.Sign(record.Cell{Name: "dev-cell-1", Env: "dev", Issuer: "https://dev-cell-1:6443", JWKS: jwk, Epoch: 1, Counter: 1}, priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "signers.pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dev-cell-1.dsse.json"), env, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func serverArgs(t *testing.T, envCA testCA) []string {
	t.Helper()
	return []string{
		"spiffe-server", "--listen", "127.0.0.1:0",
		"--peer-bundle", envCA.bundleFile(t), "--peer-trust-domain", "dev.env.poc.internal",
		"--allow-id", viewPattern, "--registry-dir", registryDir(t),
		"--backend", "grpc-header", "--upstream", "127.0.0.1:1", "--identity-header", "x-cell-agent",
	}
}

// without drops a flag and its value from args.
func without(args []string, flag string) []string {
	i := slices.Index(args, flag)
	return slices.Delete(slices.Clone(args), i, i+2)
}

// with sets the value of a flag in args.
func with(args []string, flag, value string) []string {
	out := slices.Clone(args)
	out[slices.Index(out, flag)+1] = value
	return out
}

func TestServerRequiresTrustFlags(t *testing.T) {
	envCA := newCA(t, "dev.env.poc.internal")
	args := serverArgs(t, envCA)
	garbage := filepath.Join(t.TempDir(), "garbage.crt")
	if err := os.WriteFile(garbage, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no --peer-bundle":       without(args, "--peer-bundle"),
		"no --peer-trust-domain": without(args, "--peer-trust-domain"),
		"no --allow-id":          without(args, "--allow-id"),
		"no --registry-dir":      without(args, "--registry-dir"),
		"unparsable bundle":      with(args, "--peer-bundle", garbage),
		"missing bundle file":    with(args, "--peer-bundle", filepath.Join(t.TempDir(), "absent.crt")),
		"unanchored --allow-id":  with(args, "--allow-id", "dev"),
		"top-level alternation":  with(args, "--allow-id", "^a|b$"),
		"gateway alternation":    with(args, "--allow-id", `^spiffe://dev\.env\.poc\.internal/cp/otel|/cell/[a-z0-9-]+/celld$`),
		"multi-line anchors":     with(args, "--allow-id", "(?m)^a$"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := execute(t.Context(), a, &out); code != 2 {
				t.Fatalf("exit code %d, want 2\n%s", code, out.String())
			}
			lines := jsonLines(t, out.String())
			if len(lines) != 1 || lines[0]["level"] != "ERROR" || lines[0]["error"] == nil {
				t.Fatalf("output is %v, want one JSON error line", lines)
			}
		})
	}
}

func TestAllowIDMustBeFullyAnchored(t *testing.T) {
	good := []string{viewPattern, `^(?:a|b)$`, `^spiffe://dev\.env\.poc\.internal/(?:cp/otel|cell/[a-z0-9-]+/otel)$`}
	for _, p := range good {
		if err := fullyAnchored(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	bad := []string{"dev", "^a|b$", "^a", "a$", `^a\$`, "(?m)^a$", "^(a$)", "^a$|^b$"}
	for _, p := range bad {
		if err := fullyAnchored(p); err == nil {
			t.Errorf("%s is accepted", p)
		}
	}
}

func TestProbeReportsServerID(t *testing.T) {
	mgmt := newCA(t, mgmtTD)
	addr := mgmt.serveTLS(t, principalID)
	bundle := mgmt.bundleFile(t)
	probe := func(expect string) (int, []map[string]any) {
		var out bytes.Buffer
		code := execute(t.Context(), []string{"probe", "--upstream", addr, "--expect-id", expect,
			"--peer-bundle", bundle, "--peer-trust-domain", mgmtTD}, &out)
		lines := jsonLines(t, out.String())
		if len(lines) != 1 {
			t.Fatalf("stdout has %d lines, want 1:\n%s", len(lines), out.String())
		}
		return code, lines
	}
	t.Run("verified", func(t *testing.T) {
		code, lines := probe(principalID)
		if code != 0 || len(lines[0]) != 2 || lines[0]["server_id"] != principalID || lines[0]["verified"] != true {
			t.Fatalf("exit %d, output %v", code, lines)
		}
	})
	t.Run("peer_not_allowed", func(t *testing.T) {
		code, lines := probe("spiffe://mgmt.poc.internal/telemetry")
		if code != 1 || lines[0]["reason"] != "peer_not_allowed" || lines[0]["level"] != "ERROR" {
			t.Fatalf("exit %d, output %v", code, lines)
		}
	})
}

func TestConfigErrorsExitTwo(t *testing.T) {
	mgmt := newCA(t, mgmtTD)
	envCA := newCA(t, "dev.env.poc.internal")
	bundle := mgmt.bundleFile(t)
	probeArgs := []string{"probe", "--upstream", "127.0.0.1:1", "--expect-id", principalID, "--peer-bundle", bundle, "--peer-trust-domain", mgmtTD}
	clientArgs := []string{"spiffe-client", "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--expect-id", principalID, "--peer-bundle", bundle, "--peer-trust-domain", mgmtTD}
	cases := map[string][]string{
		"probe with no --upstream":      without(probeArgs, "--upstream"),
		"probe with an unknown flag":    append(slices.Clone(probeArgs), "--nope"),
		"probe with an extra argument":  append(slices.Clone(probeArgs), "extra"),
		"whoami with an argument":       {"whoami", "extra"},
		"server with an extra argument": append(serverArgs(t, envCA), "extra"),
		"client with an extra argument": append(clientArgs, "extra"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := execute(t.Context(), a, &out); code != 2 {
				t.Fatalf("exit code %d, want 2\n%s", code, out.String())
			}
			if lines := jsonLines(t, out.String()); len(lines) != 1 || lines[0]["level"] != "ERROR" {
				t.Fatalf("output is %v, want one JSON error line", lines)
			}
		})
	}
}

func TestProbeReasons(t *testing.T) {
	mgmt := newCA(t, mgmtTD)
	bundle := mgmt.bundleFile(t)
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	der, _, key := mgmt.leaf(t, principalID)
	noALPN, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = noALPN.Close() })
	go func() {
		for {
			c, err := noALPN.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	cases := map[string]struct{ addr, want string }{
		"closed port": {"127.0.0.1:1", "upstream_unavailable"},
		"not TLS":     {plain.Addr().String(), "handshake_failed"},
		"no ALPN":     {noALPN.Addr().String(), "protocol_not_h2"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			code := execute(t.Context(), []string{"probe", "--upstream", c.addr, "--expect-id", principalID, "--peer-bundle", bundle, "--peer-trust-domain", mgmtTD}, &out)
			lines := jsonLines(t, out.String())
			if code != 1 || len(lines) != 1 || lines[0]["reason"] != c.want {
				t.Fatalf("exit %d, output %v, want reason %s", code, lines, c.want)
			}
		})
	}
}

func TestWhoamiPrintsOnlyIDs(t *testing.T) {
	ca := newCA(t, "dev.env.poc.internal")
	serveWorkloadAPI(t, ca, "spiffe://dev.env.poc.internal/cell/dev-cell-1/otel", "spiffe://dev.env.poc.internal/cell/dev-cell-1/argocd-agent")
	var out bytes.Buffer
	if code := execute(t.Context(), []string{"whoami"}, &out); code != 0 {
		t.Fatalf("exit code %d\n%s", code, out.String())
	}
	want := `{"ids":["spiffe://dev.env.poc.internal/cell/dev-cell-1/argocd-agent","spiffe://dev.env.poc.internal/cell/dev-cell-1/otel"]}` + "\n"
	if out.String() != want {
		t.Fatalf("stdout is %q, want %q", out.String(), want)
	}
}

func TestLogsAreJSON(t *testing.T) {
	// Port 1 on the loopback address refuses connections, so every OTLP export fails fast.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "300")
	mgmt, envCA := newCA(t, mgmtTD), newCA(t, "dev.env.poc.internal")
	serveWorkloadAPI(t, mgmt, principalID)

	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- execute(ctx, serverArgs(t, envCA), out) }()

	var addr string
	deadline := time.Now().Add(30 * time.Second)
	for addr == "" {
		for _, l := range jsonLines(t, out.String()) {
			if l["msg"] == "listening" {
				addr, _ = l["addr"].(string)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("spiffe-server did not listen:\n%s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A plain TCP connection fails the handshake, so the server logs a refusal.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("not tls\n"))
	_ = c.Close()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d after cancel\n%s", code, out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("spiffe-server did not stop")
	}
	lines := jsonLines(t, out.String())
	msgs := map[string]bool{}
	for _, l := range lines {
		msgs[l["msg"].(string)] = true
	}
	for _, want := range []string{"registry loaded", "listening", "handshake failed"} {
		if !msgs[want] {
			t.Fatalf("no %q line in:\n%s", want, out.String())
		}
	}
	for _, l := range lines {
		if l["msg"] == "registry loaded" && (l["records"] != float64(1) || l["revoked"] != float64(0) || l["signers"] != float64(1) || l["content_sha256"] == nil) {
			t.Fatalf("registry line is %v", l)
		}
		if l["msg"] == "handshake failed" && (l["reason"] != "handshake_failed" || l["remote"] == nil) {
			t.Fatalf("refusal line is %v, want reason and remote", l)
		}
	}
}
