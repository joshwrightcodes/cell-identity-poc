package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const topologyFile = "../../harness/topology.yaml"

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testCA is a root CA of trust domain mgmt.poc.internal with the URI SAN that SPIRE roots carry.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newMgmtCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://mgmt.poc.internal")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "root"}, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// svid issues a client certificate with the SPIFFE ID id.
func (ca *testCA) svid(t *testing.T, id string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writeBundle(t *testing.T, ca *testCA) string {
	t.Helper()
	return writeFile(t, "bundle.pem", ca.pem())
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// caForDomain returns a PEM CA certificate with the SPIFFE trust domain URI, as SPIRE issues.
func caForDomain(t *testing.T, domain string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uris []*url.URL
	if domain != "" {
		u, _ := url.Parse("spiffe://" + domain)
		uris = append(uris, u)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, URIs: uris,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type running struct {
	addr string
	out  *syncBuffer
	done chan int
	stop context.CancelFunc
	once sync.Once
}

func (r *running) finish(t *testing.T) {
	t.Helper()
	r.once.Do(func() {
		r.stop()
		select {
		case <-r.done:
		case <-time.After(10 * time.Second):
			t.Error("serve did not stop")
		}
	})
}

// startServe runs hostsvc serve on a loopback port and waits for its serving line.
func startServe(t *testing.T, bundle string, extra ...string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{out: &syncBuffer{}, done: make(chan int, 1), stop: cancel}
	args := append([]string{"serve", "--listen", "127.0.0.1:0", "--client-bundle", bundle, "--topology", topologyFile}, extra...)
	go func() { r.done <- execute(ctx, args, r.out) }()
	t.Cleanup(func() { r.finish(t) })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(r.out.String(), "\n") {
			if strings.Contains(l, `"msg":"serving"`) {
				m := jsonLines(t, l)[0]
				r.addr, _ = m["addr"].(string)
				return r
			}
		}
		select {
		case code := <-r.done:
			t.Fatalf("serve exited with %d: %s", code, r.out.String())
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Fatalf("no serving line: %s", r.out.String())
	return nil
}

func mgmtClientCert(t *testing.T, ca *testCA) tls.Certificate {
	t.Helper()
	return ca.svid(t, "spiffe://mgmt.poc.internal/api")
}

func TestServeRefusesNonLoopback(t *testing.T) {
	bundle := writeBundle(t, newMgmtCA(t))
	for _, addr := range []string{"0.0.0.0:0", "[::]:0", ":0", "192.168.5.2:17443", "localhost:17443", "10.0.0.1:1"} {
		var out syncBuffer
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		code := execute(ctx, []string{"serve", "--listen", addr, "--client-bundle", bundle, "--topology", topologyFile}, &out)
		cancel()
		if code == 0 {
			t.Errorf("%s: exit 0", addr)
			continue
		}
		lines := jsonLines(t, out.String())
		if len(lines) != 1 || !strings.Contains(lines[0]["error"].(string), "loopback") {
			t.Errorf("%s: output = %q, want one loopback error", addr, out.String())
		}
	}
}

func TestServeRequiresClientBundle(t *testing.T) {
	good := writeBundle(t, newMgmtCA(t))
	cases := map[string][]string{
		"no flag":        {"serve", "--listen", "127.0.0.1:0"},
		"missing file":   {"serve", "--listen", "127.0.0.1:0", "--client-bundle", filepath.Join(t.TempDir(), "none.pem")},
		"not PEM":        {"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeFile(t, "x.pem", []byte("hello"))},
		"empty file":     {"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeFile(t, "x.pem", nil)},
		"other domain":   {"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeFile(t, "x.pem", caForDomain(t, "dev.env.poc.internal"))},
		"no URI SAN":     {"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeFile(t, "x.pem", caForDomain(t, ""))},
		"other id":       {"serve", "--listen", "127.0.0.1:0", "--client-bundle", good, "--client-id", "spiffe://dev.env.poc.internal/api"},
		"domain as id":   {"serve", "--listen", "127.0.0.1:0", "--client-bundle", good, "--client-id", "spiffe://mgmt.poc.internal"},
		"bad id":         {"serve", "--listen", "127.0.0.1:0", "--client-bundle", good, "--client-id", "nope"},
		"leaf as bundle": {"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeFile(t, "x.pem", leafPEM(t))},
	}
	for name, args := range cases {
		var out syncBuffer
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		code := execute(ctx, append(args, "--topology", topologyFile), &out)
		cancel()
		if code == 0 {
			t.Errorf("%s: exit 0", name)
			continue
		}
		if lines := jsonLines(t, out.String()); len(lines) != 1 || lines[0]["error"] == nil {
			t.Errorf("%s: output = %q, want one error line", name, out.String())
		}
	}
}

func leafPEM(t *testing.T) []byte {
	t.Helper()
	cert, err := hostsvc.SelfSignedCert("x", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Leaf.Raw})
}

func TestServeTLS13Only(t *testing.T) {
	ca := newMgmtCA(t)
	r := startServe(t, writeBundle(t, ca))
	cert := mgmtClientCert(t, ca)
	conn, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	if err == nil {
		conn.Close()
		t.Fatal("a TLS 1.2 client completed the handshake")
	}
	conn, err = tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("TLS 1.3 client: %v", err)
	}
	conn.Close()
}

// The cap counts connections that passed the handshake and the client check. The 17th verified
// client finishes its handshake, but its request gets no answer until a slot frees.
func TestServeConnCap(t *testing.T) {
	ca := newMgmtCA(t)
	r := startServe(t, writeBundle(t, ca))
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{mgmtClientCert(t, ca)}}
	var held []*tls.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 1; i <= 16; i++ {
		c, err := tls.Dial("tcp", r.addr, cfg)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		if _, err := c.Write([]byte("GET /none HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(make([]byte, 64)); err != nil || n == 0 {
			t.Fatalf("client %d got no answer: %v", i, err)
		}
		held = append(held, c)
	}
	seventeen, err := tls.Dial("tcp", r.addr, cfg)
	if err != nil {
		t.Fatalf("17th client: %v", err)
	}
	defer seventeen.Close()
	if _, err := seventeen.Write([]byte("GET /none HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = seventeen.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := seventeen.Read(make([]byte, 64)); err == nil {
		t.Fatalf("the 17th client got %d bytes while 16 connections were open", n)
	}
	held[0].Close()
	held = held[1:]
	_ = seventeen.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := seventeen.Read(make([]byte, 64)); err != nil || n == 0 {
		t.Fatalf("the 17th client got no answer after a slot freed: %v", err)
	}
}

// A client with no credential does not take a slot: 16 verified clients fit beside any number of
// silent sockets.
func TestServeSilentSocketsTakeNoSlot(t *testing.T) {
	ca := newMgmtCA(t)
	r := startServe(t, writeBundle(t, ca))
	var silent []net.Conn
	defer func() {
		for _, c := range silent {
			c.Close()
		}
	}()
	for range 40 {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		silent = append(silent, c)
	}
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{mgmtClientCert(t, ca)}}
	for i := 1; i <= 16; i++ {
		c, err := tls.Dial("tcp", r.addr, cfg)
		if err != nil {
			t.Fatalf("verified client %d: %v", i, err)
		}
		defer c.Close()
		_, _ = c.Write([]byte("GET /none HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := c.Read(make([]byte, 64)); err != nil || n == 0 {
			t.Fatalf("verified client %d got no answer beside silent sockets: %v", i, err)
		}
	}
}

// The server trusts the roots that it read at start. A new root in the file changes nothing.
func TestServeIgnoresBundleChangesAfterStart(t *testing.T) {
	ca, other := newMgmtCA(t), newMgmtCA(t)
	bundle := writeBundle(t, ca)
	r := startServe(t, bundle)
	if err := os.WriteFile(bundle, other.pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	status := func(cert tls.Certificate) (int, error) {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}},
		}}
		resp, err := client.Get("https://" + r.addr + "/none")
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := status(mgmtClientCert(t, ca)); err != nil || code != http.StatusNotFound {
		t.Errorf("client of the first root: %d, %v", code, err)
	}
	if code, err := status(mgmtClientCert(t, other)); err == nil {
		t.Errorf("client of the new root got %d after the file changed", code)
	}
}

func TestServeRootSHA256IsTheBundle(t *testing.T) {
	ca := newMgmtCA(t)
	r := startServe(t, writeBundle(t, ca))
	sum := sha256.Sum256(ca.cert.Raw)
	m := jsonLines(t, lineWith(t, r.out, `"msg":"serving"`))[0]
	if m["root_sha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("root_sha256 = %v, want %x", m["root_sha256"], sum)
	}
}

func lineWith(t *testing.T, out *syncBuffer, sub string) string {
	t.Helper()
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	t.Fatalf("no line with %s: %s", sub, out.String())
	return ""
}

var hexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestServeLogsAreJSON(t *testing.T) {
	ca := newMgmtCA(t)
	stderr := captureStderr(t)
	r := startServe(t, writeBundle(t, ca))
	conn, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(make([]byte, 1))
		conn.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(r.out.String(), `"msg":"handshake refused"`) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	r.finish(t)
	if got := stderr(); got != "" {
		t.Errorf("serve wrote to stderr: %q", got)
	}
	var serving map[string]any
	var sawServerError bool
	for _, m := range jsonLines(t, r.out.String()) {
		switch m["msg"] {
		case "serving":
			serving = m
		case "handshake refused":
			sawServerError = true
		}
	}
	if !sawServerError {
		t.Error("no JSON line for the failed handshake")
	}
	if serving == nil {
		t.Fatal("no serving line")
	}
	for _, k := range []string{"cert_sha256", "root_sha256"} {
		if s, _ := serving[k].(string); !hexRE.MatchString(s) {
			t.Errorf("%s = %v, want 64 hex digits", k, serving[k])
		}
	}
	if pid, _ := serving["pid"].(float64); int(pid) != os.Getpid() {
		t.Errorf("pid = %v, want %d", serving["pid"], os.Getpid())
	}
}

func TestServeCertSHA256IsTheLeaf(t *testing.T) {
	ca := newMgmtCA(t)
	r := startServe(t, writeBundle(t, ca))
	var out bytes.Buffer
	if err := pin(t.Context(), r.addr, "", &out); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(out.Bytes())
	sum := sha256.Sum256(block.Bytes)
	if !strings.Contains(r.out.String(), hex.EncodeToString(sum[:])) {
		t.Errorf("serving line does not carry the leaf SHA-256 %x: %s", sum, r.out.String())
	}
}

// countingListener accepts connections and counts them, and closes each at once.
func countingListener(t *testing.T, addr string) (net.Listener, *int32Counter) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c := &int32Counter{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.add()
			conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln, c
}

type int32Counter struct {
	mu sync.Mutex
	n  int
}

func (c *int32Counter) add() { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *int32Counter) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// Without OTEL_EXPORTER_OTLP_ENDPOINT the server starts no exporter. The per-signal endpoints point
// at a counting listener, so a started exporter would connect there at shutdown at the latest.
func TestServeNoExporterWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	ln, c := countingListener(t, "127.0.0.1:0")
	for _, sig := range []string{"TRACES", "METRICS", "LOGS"} {
		t.Setenv("OTEL_EXPORTER_OTLP_"+sig+"_ENDPOINT", "http://"+ln.Addr().String())
	}
	ca := newMgmtCA(t)
	r := startServe(t, writeBundle(t, ca))
	r.finish(t)
	if n := c.get(); n != 0 {
		t.Errorf("%d connections to the signal endpoints without OTEL_EXPORTER_OTLP_ENDPOINT, want 0", n)
	}
}

func TestServeExportsWhenEndpointSet(t *testing.T) {
	ln, c := countingListener(t, "127.0.0.1:0")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+ln.Addr().String())
	ca := newMgmtCA(t)
	r := startServe(t, writeBundle(t, ca))
	r.finish(t)
	if c.get() == 0 {
		t.Error("no connection to the endpoint in OTEL_EXPORTER_OTLP_ENDPOINT")
	}
}

func TestPinPrintsLeafPEM(t *testing.T) {
	cert, addr := tlsServer(t)
	var out strings.Builder
	if code := execute(t.Context(), []string{"pin", "--addr", addr}, &out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	block, rest := pem.Decode([]byte(out.String()))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("output is not one PEM certificate: %q", out.String())
	}
	if !bytes.Equal(block.Bytes, cert.Leaf.Raw) {
		t.Error("PEM block is not the leaf of the server")
	}
	if strings.Count(out.String(), "-----BEGIN") != 1 {
		t.Errorf("want one PEM block: %q", out.String())
	}
	sum := sha256.Sum256(cert.Leaf.Raw)
	var ok strings.Builder
	if code := execute(t.Context(), []string{"pin", "--addr", addr, "--expect-sha256", hex.EncodeToString(sum[:])}, &ok); code != 0 || ok.String() != out.String() {
		t.Errorf("with the right hash: exit %d, output %q", code, ok.String())
	}
}

func TestPinExpectMismatch(t *testing.T) {
	_, addr := tlsServer(t)
	for _, want := range []string{strings.Repeat("00", 32), "zz", "00"} {
		var out strings.Builder
		code := execute(t.Context(), []string{"pin", "--addr", addr, "--expect-sha256", want}, &out)
		if code != 1 {
			t.Errorf("%s: exit %d, want 1", want, code)
		}
		lines := jsonLines(t, out.String())
		if len(lines) != 1 || lines[0]["error"] == nil || strings.Contains(out.String(), "BEGIN") {
			t.Errorf("%s: output = %q, want one JSON error line and no PEM", want, out.String())
		}
	}
}

// tlsServer serves a self-signed certificate, and asks for a client certificate like the key server.
func tlsServer(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	cert, err := hostsvc.SelfSignedCert(hostsvc.KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return cert, ln.Addr().String()
}

func TestServeRefusesLowFileLimit(t *testing.T) {
	old := nofileSoftLimit
	nofileSoftLimit = func() (uint64, error) { return 256, nil }
	t.Cleanup(func() { nofileSoftLimit = old })
	ca := newMgmtCA(t)
	var out syncBuffer
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	code := execute(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeBundle(t, ca), "--topology", topologyFile}, &out)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	lines := jsonLines(t, out.String())
	msg, _ := lines[0]["error"].(string)
	if len(lines) != 1 || !strings.Contains(msg, "RLIMIT_NOFILE") || !strings.Contains(msg, "256") {
		t.Errorf("output = %q, want one error line that names the limit", out.String())
	}
}

func TestServeAcceptsEnoughFiles(t *testing.T) {
	old := nofileSoftLimit
	nofileSoftLimit = func() (uint64, error) { return hostsvc.FilesNeeded(), nil }
	t.Cleanup(func() { nofileSoftLimit = old })
	startServe(t, writeBundle(t, newMgmtCA(t)))
}

// With an OTLP endpoint, serve installs the instrumented handler and counts refused handshakes.
func TestServeInstallsInstrumentedHandler(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	old := startTelemetry
	startTelemetry = func(context.Context, string, io.Writer) (*telemetry.T, error) {
		return &telemetry.T{Log: slog.Default(), Tracer: tp.Tracer("t"), Meter: mp.Meter("m"), Shutdown: func(context.Context) error { return nil }}, nil
	}
	t.Cleanup(func() { startTelemetry = old })
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")

	ca := newMgmtCA(t)
	r := startServe(t, writeBundle(t, ca))
	cert := mgmtClientCert(t, ca)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
	}}
	resp, err := client.Get("https://" + r.addr + "/v1/clusters/rogue/keys")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	bad := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
	}}
	if resp, err := bad.Get("https://" + r.addr + "/x"); err == nil {
		resp.Body.Close()
	}

	var outcome bool
	for _, s := range rec.Ended() {
		for _, a := range s.Attributes() {
			if a.Key == "outcome" && a.Value.AsString() == "unknown_cluster" {
				outcome = true
			}
		}
	}
	if !outcome {
		t.Errorf("no span with outcome unknown_cluster among %d spans", len(rec.Ended()))
	}
	deadline := time.Now().Add(3 * time.Second)
	var failed, requests int64
	for time.Now().Before(deadline) {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		failed, requests = 0, 0
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					v, _ := dp.Attributes.Value("reason")
					o, _ := dp.Attributes.Value("outcome")
					if m.Name == "hostsvc.key.handshake.refusals" && v.AsString() == "handshake_failed" {
						failed += dp.Value
					}
					if m.Name == "hostsvc.key.requests" && o.AsString() == "unknown_cluster" {
						requests += dp.Value
					}
				}
			}
		}
		if failed >= 1 && requests >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if failed < 1 || requests < 1 {
		t.Errorf("handshake_failed refusals = %d, unknown_cluster requests = %d, want at least 1 each", failed, requests)
	}
}
