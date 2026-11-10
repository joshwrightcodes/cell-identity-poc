package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestScanFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	got, err := scan(context.Background(), "127.0.0.1", port-2, port+2, 300*time.Millisecond, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int{port}) {
		t.Errorf("open = %v, want [%d]", got, port)
	}
}

func TestParsePorts(t *testing.T) {
	lo, hi, err := parsePorts("20-30")
	if err != nil || lo != 20 || hi != 30 {
		t.Errorf("range: %d %d %v", lo, hi, err)
	}
	lo, hi, err = parsePorts("443")
	if err != nil || lo != 443 || hi != 443 {
		t.Errorf("single: %d %d %v", lo, hi, err)
	}
	for _, bad := range []string{"", "0-5", "9-3", "1-70000", "a"} {
		if _, _, err := parsePorts(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestServeReportsRemote(t *testing.T) {
	srv := httptest.NewServer(handler())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	var local string
	ctx := context.Background()
	dialer := &net.Dialer{}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, n, a)
			if err == nil {
				local = c.LocalAddr().String()
			}
			return c, err
		},
	}}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Remote string `json:"remote"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Remote != local {
		t.Errorf("remote = %q, want %q", out.Remote, local)
	}
	if strings.Contains(out.Remote, "203.0.113.9") {
		t.Error("forwarded header must be ignored")
	}
}

func TestGetPrintsBodyAndFailsOnStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	var sb strings.Builder
	if err := get(context.Background(), srv.URL, &sb, time.Second); err != nil || sb.String() != "hello" {
		t.Errorf("body = %q err = %v", sb.String(), err)
	}
	if err := get(context.Background(), srv.URL+"/bad", &sb, time.Second); err == nil {
		t.Error("want error on 403")
	}
}

func TestScanPrintsOnlyJSON(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	var out strings.Builder
	args := []string{"scan", "--host", "127.0.0.1", "--ports", strconv.Itoa(port)}
	if err := run(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	var got []int
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("stdout is not pure JSON: %q: %v", out.String(), err)
	}
	if !slices.Equal(got, []int{port}) {
		t.Errorf("open = %v, want [%d]", got, port)
	}
}

func TestFailureIsOneJSONErrorLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer srv.Close()
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"scan"},
		{"scan", "--host", "not-an-ip"},
		{"get"},
		{"get", "--url", srv.URL},
		{"get", "--bogus"},
		{"get", "-h"},
		{"scan", "-h"},
		{"scan", "--bogus"},
		{"serve", "--bogus"},
	} {
		var out strings.Builder
		stderr := captureStderr(t)
		code := execute(context.Background(), args, &out)
		if got := stderr(); got != "" {
			t.Errorf("%v: wrote to stderr: %q", args, got)
		}
		if code == 0 {
			t.Errorf("%v: exit code 0, want non-zero", args)
		}
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("%v: %d lines, want 1: %q", args, len(lines), out.String())
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
			t.Fatalf("%v: not JSON: %q: %v", args, lines[0], err)
		}
		if msg, _ := m["error"].(string); msg == "" {
			t.Errorf("%v: no error field: %v", args, m)
		}
	}
}

func TestSuccessPrintsOnlyData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	var out strings.Builder
	stderr := captureStderr(t)
	defer func() {
		if got := stderr(); got != "" {
			t.Errorf("wrote to stderr: %q", got)
		}
	}()
	if code := execute(context.Background(), []string{"get", "--url", srv.URL}, &out); code != 0 || out.String() != "hello" {
		t.Errorf("get: code %d, stdout %q", code, out.String())
	}
	out.Reset()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	if code := execute(context.Background(), []string{"scan", "--host", "127.0.0.1", "--ports", closed}, &out); code != 0 || out.String() != "[]\n" {
		t.Errorf("scan: code %d, stdout %q", code, out.String())
	}
}

func TestServeLogsAreJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan int)
	go func() { done <- execute(ctx, []string{"serve", "--addr", "127.0.0.1:0"}, &out) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "\n") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("serve exit code %d, output %q", code, out.String())
	}
	for _, l := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Errorf("serve log is not JSON: %q: %v", l, err)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// captureStderr redirects os.Stderr to a pipe and returns a function that restores it and
// returns what was written.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	return func() string {
		os.Stderr = orig
		_ = w.Close()
		b, _ := io.ReadAll(r)
		_ = r.Close()
		return string(b)
	}
}

func dialResult(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if code := execute(t.Context(), append([]string{"dial"}, args...), &out); code != 0 {
		t.Fatalf("dial %v: exit %d: %s", args, code, out.String())
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("dial output is not one JSON line: %q", out.String())
	}
	return m
}

func TestDialReportsConnectedAndRefused(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	if r := dialResult(t, "--addr", lis.Addr().String()); r["result"] != "connected" {
		t.Fatalf("open port: %v", r)
	}
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := closed.Addr().String()
	_ = closed.Close()
	if r := dialResult(t, "--addr", addr, "--timeout", "1s"); r["result"] != "refused" || r["addr"] != addr {
		t.Fatalf("closed port: %v", r)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "dial tcp 10.0.0.1:1: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestDialClassifiesErrors(t *testing.T) {
	cases := map[string]error{
		"connected": nil,
		"refused":   &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		"timeout":   &net.OpError{Op: "dial", Err: timeoutError{}},
		"error":     &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)},
	}
	for want, err := range cases {
		if got := dialClass(err); got != want {
			t.Errorf("dialClass(%v) = %q, want %q", err, got, want)
		}
	}
	if got := dialClass(context.DeadlineExceeded); got != "timeout" {
		t.Errorf("dialClass(context.DeadlineExceeded) = %q, want timeout", got)
	}
}

func TestDialRejectsHostName(t *testing.T) {
	var out bytes.Buffer
	if code := execute(t.Context(), []string{"dial", "--addr", "example.com:80"}, &out); code != 1 || !strings.Contains(out.String(), "IP address") {
		t.Fatalf("exit %d, output %q", code, out.String())
	}
}

// A body that breaks off after part of the data gives only the error line, not the partial data.
func TestGetPrintsNoPartialBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"partial":`))
		w.(http.Flusher).Flush()
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
			}
		}
	}))
	defer srv.Close()
	var out bytes.Buffer
	if code := execute(context.Background(), []string{"get", "--url", srv.URL}, &out); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	var rec map[string]any
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &rec) != nil || rec["msg"] != "netprobe failed" {
		t.Fatalf("want one JSON error line and no partial body, got %q", out.String())
	}
}

// testChain makes a CA and a leaf with the URI SAN id, and returns the leaf and CA PEM blocks, the
// leaf key PEM, and the leaf certificate.
func testChain(t *testing.T, id string) (chainPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return chainPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), leaf
}

// TestTLSServeUsesStdinCert starts tlsserve with a chain and key on standard input. A client sees
// that chain, TLS 1.3 and ALPN h2. The output never holds the key.
func TestTLSServeUsesStdinCert(t *testing.T) {
	chain, key, leaf := testChain(t, "spiffe://dev.env.poc.internal/cell/dev-cell-2/argocd-agent")
	old := stdin
	stdin = bytes.NewReader(append(append([]byte{}, chain...), key...))
	t.Cleanup(func() { stdin = old })
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- execute(ctx, []string{"tlsserve", "--addr", "127.0.0.1:0"}, out) }()
	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for addr == "" {
		for l := range strings.SplitSeq(out.String(), "\n") {
			var rec struct{ Msg, Addr string }
			if json.Unmarshal([]byte(l), &rec) == nil && rec.Msg == "serving tls" {
				addr = rec.Addr
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("tlsserve logged no address: %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatalf("handshake with tlsserve: %v", err)
	}
	st := conn.ConnectionState()
	_ = conn.Close()
	if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" {
		t.Errorf("version %x, ALPN %q; want TLS 1.3 and h2", st.Version, st.NegotiatedProtocol)
	}
	if len(st.PeerCertificates) != 2 || !st.PeerCertificates[0].Equal(leaf) {
		t.Fatalf("the client saw %d certificates, want the leaf and the CA from stdin", len(st.PeerCertificates))
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("exit status %d after the stop, want 0: %s", code, out.String())
	}
	if strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), "BEGIN") {
		t.Errorf("the output holds PEM: %q", out.String())
	}
}

// TestTLSServeRefusesBadInput gives tlsserve no key, or no certificate. Each fails with one JSON
// error line.
func TestTLSServeRefusesBadInput(t *testing.T) {
	chain, key, _ := testChain(t, "spiffe://x/y")
	for name, in := range map[string][]byte{"no key": chain, "no certificate": key, "empty": nil} {
		t.Run(name, func(t *testing.T) {
			old := stdin
			stdin = bytes.NewReader(in)
			t.Cleanup(func() { stdin = old })
			var out strings.Builder
			if code := execute(context.Background(), []string{"tlsserve", "--addr", "127.0.0.1:0"}, &out); code == 0 {
				t.Fatal("exit status 0, want a failure")
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if len(lines) != 1 || !strings.Contains(lines[0], `"level":"ERROR"`) {
				t.Fatalf("output %q, want one JSON error line", out.String())
			}
		})
	}
}

// TestHTTPModePrintsOneLine sends a GET and a POST with a body from stdin. Each prints one JSON line
// with the status and the first 4 KiB of the body, also for a 403.
func TestHTTPModePrintsOneLine(t *testing.T) {
	var gotBody, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotMethod = string(b), r.Method
		if r.URL.Path == "/denied" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("no"))
			return
		}
		_, _ = w.Write(bytes.Repeat([]byte("a"), 5000))
	}))
	defer srv.Close()
	run := func(args ...string) (int, map[string]any) {
		var out strings.Builder
		code := execute(context.Background(), append([]string{"http"}, args...), &out)
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("%v: %d lines, want one: %q", args, len(lines), out.String())
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
			t.Fatalf("%v: not JSON: %q", args, lines[0])
		}
		return code, m
	}
	code, m := run("--method", "GET", "--url", srv.URL+"/ok")
	if code != 0 || m["status"] != float64(200) || len(m["body"].(string)) != 4096 || gotMethod != "GET" {
		t.Fatalf("GET: exit %d, status %v, body %d bytes, method %s; want 0, 200, 4096 bytes, GET", code, m["status"], len(m["body"].(string)), gotMethod)
	}
	old := stdin
	stdin = strings.NewReader(`{"kind":"x"}`)
	t.Cleanup(func() { stdin = old })
	code, m = run("--method", "POST", "--url", srv.URL+"/denied", "--body-stdin")
	if code != 0 || m["status"] != float64(403) || m["body"] != "no" || gotBody != `{"kind":"x"}` || gotMethod != "POST" {
		t.Fatalf("POST: exit %d, line %v, server got %s %q; want 0, 403, the stdin body", code, m, gotMethod, gotBody)
	}
	if code, m = run("--method", "GET", "--url", "http://127.0.0.1:1/"); code == 0 || m["error"] == nil {
		t.Fatalf("a refused request: exit %d, line %v; want a JSON error line", code, m)
	}
	if code, _ = run("--url", srv.URL); code == 0 {
		t.Fatal("no --method: exit 0, want a failure")
	}
}
