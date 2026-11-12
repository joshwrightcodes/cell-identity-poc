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
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
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

func writeBundle(t *testing.T, ca *spiffetest.CA) string {
	t.Helper()
	data, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "bundle.pem", data)
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
	u, _ := url.Parse("spiffe://" + domain)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, URIs: []*url.URL{u},
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

func mgmtClientCert(t *testing.T, ca *spiffetest.CA) tls.Certificate {
	t.Helper()
	svid := ca.SVID(t, "spiffe://mgmt.poc.internal/api")
	return tls.Certificate{Certificate: [][]byte{svid.Certificates[0].Raw}, PrivateKey: svid.PrivateKey}
}

func TestServeRefusesNonLoopback(t *testing.T) {
	bundle := writeBundle(t, spiffetest.NewCA(t, "mgmt.poc.internal"))
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
	good := writeBundle(t, spiffetest.NewCA(t, "mgmt.poc.internal"))
	cases := map[string][]string{
		"no flag":        {"serve", "--listen", "127.0.0.1:0"},
		"missing file":   {"serve", "--listen", "127.0.0.1:0", "--client-bundle", filepath.Join(t.TempDir(), "none.pem")},
		"not PEM":        {"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeFile(t, "x.pem", []byte("hello"))},
		"empty file":     {"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeFile(t, "x.pem", nil)},
		"other domain":   {"serve", "--listen", "127.0.0.1:0", "--client-bundle", writeFile(t, "x.pem", caForDomain(t, "dev.env.poc.internal"))},
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
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
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

func TestServeConnCap(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	r := startServe(t, writeBundle(t, ca))
	cert := mgmtClientCert(t, ca)
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
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
		held = append(held, c)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	c, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", r.addr)
	if err == nil {
		c.Close()
		t.Fatal("the 17th client completed its handshake while 16 connections were open")
	}
	held[0].Close()
	held = held[1:]
	c, err = tls.Dial("tcp", r.addr, cfg)
	if err != nil {
		t.Fatalf("client after a slot freed: %v", err)
	}
	c.Close()
}

var hexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestServeLogsAreJSON(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	stderr := captureStderr(t)
	r := startServe(t, writeBundle(t, ca))
	conn, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(make([]byte, 1))
		conn.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(r.out.String(), `"msg":"server error"`) && time.Now().Before(deadline) {
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
		case "server error":
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
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
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
		return nil, nil
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

func TestServeNoExporterWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	_, c := countingListener(t, "localhost:4317")
	if c == nil {
		t.Skip("localhost:4317 is in use, so connections cannot be counted")
	}
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	r := startServe(t, writeBundle(t, ca))
	time.Sleep(2500 * time.Millisecond)
	r.finish(t)
	if n := c.get(); n != 0 {
		t.Errorf("%d connections to localhost:4317 without OTEL_EXPORTER_OTLP_ENDPOINT, want 0", n)
	}
}

func TestServeExportsWhenEndpointSet(t *testing.T) {
	ln, c := countingListener(t, "127.0.0.1:0")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+ln.Addr().String())
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
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
