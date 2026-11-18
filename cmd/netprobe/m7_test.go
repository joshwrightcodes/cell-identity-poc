package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// caPEM returns the CA certificate of a chain from testChain.
func caPEM(t *testing.T, chain []byte) []byte {
	t.Helper()
	_, rest := pem.Decode(chain)
	ca, _ := pem.Decode(rest)
	if ca == nil {
		t.Fatal("the chain holds no CA certificate")
	}
	return pem.EncodeToMemory(ca)
}

// tlsServer serves TLS 1.3 h2 with the chain and key until the test ends. Each accepted connection
// stays open until the client closes it.
func tlsServer(t *testing.T, chain, key []byte, cfg *tls.Config) string {
	t.Helper()
	cert, err := tls.X509KeyPair(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg.MinVersion, cfg.NextProtos, cfg.Certificates = tls.VersionTLS13, []string{"h2"}, []tls.Certificate{cert}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
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
			go func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func writeFile(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bundle.crt")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTLSDialReasons dials a server with the expected ID, a wrong ID, and roots of another CA.
func TestTLSDialReasons(t *testing.T) {
	const id = "spiffe://mgmt.poc.internal/telemetry"
	chain, key, _ := testChain(t, id)
	otherChain, _, _ := testChain(t, id)
	addr := tlsServer(t, chain, key, nil)
	cases := []struct {
		name, expect string
		roots        []byte
		handshake    string
		reason       string
	}{
		{"exact ID", id, caPEM(t, chain), "ok", ""},
		{"wrong ID", "spiffe://mgmt.poc.internal/api", caPEM(t, chain), "failed", "peer_not_allowed"},
		{"other CA", id, caPEM(t, otherChain), "failed", "peer_untrusted"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			code := execute(context.Background(), []string{"tlsdial", "--addr", addr, "--expect-id", c.expect, "--bundle", writeFile(t, c.roots)}, &out)
			if code != 0 {
				t.Fatalf("exit status %d: %s", code, out.String())
			}
			var r tlsDialResult
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatalf("output is not one JSON line: %q", out.String())
			}
			if r.Handshake != c.handshake || r.Reason != c.reason {
				t.Errorf("handshake %q reason %q, want %q and %q: %+v", r.Handshake, r.Reason, c.handshake, c.reason, r)
			}
			if c.handshake == "ok" && (!r.Verified || r.PeerID != id || r.After != "open") {
				t.Errorf("a good dial reports %+v, want verified, peer %s and an open connection", r, id)
			}
		})
	}
}

// TestTLSDialSeesServerAlert presents a client certificate that the server refuses. In TLS 1.3 the
// client handshake ends first, so the refusal shows in the first read.
func TestTLSDialSeesServerAlert(t *testing.T) {
	chain, key, _ := testChain(t, "spiffe://mgmt.poc.internal/api")
	clientChain, clientKey, _ := testChain(t, "spiffe://mgmt.poc.internal/api")
	addr := tlsServer(t, chain, key, &tls.Config{
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return errors.New("refused") },
	})
	old := stdin
	stdin = bytes.NewReader(append(append([]byte{}, clientChain...), clientKey...))
	t.Cleanup(func() { stdin = old })
	var out bytes.Buffer
	if code := execute(context.Background(), []string{"tlsdial", "--addr", addr, "--no-verify", "--client-cert-stdin"}, &out); code != 0 {
		t.Fatalf("exit status %d: %s", code, out.String())
	}
	var r tlsDialResult
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("output is not one JSON line: %q", out.String())
	}
	if r.Handshake != "ok" || r.Verified || !strings.HasPrefix(r.After, "alert:") {
		t.Errorf("got %+v, want an unverified handshake and an alert on the first read", r)
	}
	if strings.Contains(out.String(), "PRIVATE KEY") {
		t.Errorf("the output holds the key: %q", out.String())
	}
}

// TestTLSDialNeedsFlags refuses a dial with no server check.
func TestTLSDialNeedsFlags(t *testing.T) {
	var out bytes.Buffer
	if code := execute(context.Background(), []string{"tlsdial", "--addr", "127.0.0.1:1"}, &out); code == 0 {
		t.Fatalf("tlsdial with no --expect-id and no --no-verify succeeded: %s", out.String())
	}
}

// echoUpstream records what it receives and echoes it back.
func echoUpstream(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 6)
				if _, err := io.ReadFull(c, b); err == nil {
					got <- b
					_, _ = c.Write(b)
				}
			}()
		}
	}()
	return ln.Addr().String(), got
}

// startFlipForward runs flipforward and returns its address and its log.
func startFlipForward(t *testing.T, args ...string) (string, *syncBuffer) {
	t.Helper()
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, append([]string{"flipforward", "--listen", "127.0.0.1:0"}, args...), out)
	}()
	t.Cleanup(func() {
		cancel()
		if code := <-done; code != 0 {
			t.Errorf("flipforward exit status %d: %s", code, out.String())
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		for l := range strings.SplitSeq(out.String(), "\n") {
			var rec struct{ Msg, Addr string }
			if json.Unmarshal([]byte(l), &rec) == nil && rec.Msg == "forwarding" {
				return rec.Addr, out
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("flipforward logged no address: %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// roundTrip sends "abcdef" through addr and returns what the upstream got and what came back.
func roundTrip(t *testing.T, addr string, got <-chan []byte) (up, down []byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	down = make([]byte, 6)
	if _, err := io.ReadFull(c, down); err != nil {
		t.Fatal(err)
	}
	return <-got, down
}

// TestFlipForwardPassesBytes forwards both ways unchanged when no flip is set.
func TestFlipForwardPassesBytes(t *testing.T) {
	upstream, got := echoUpstream(t)
	addr, _ := startFlipForward(t, "--upstream", upstream)
	up, down := roundTrip(t, addr, got)
	if string(up) != "abcdef" || string(down) != "abcdef" {
		t.Errorf("upstream got %q and the client got %q, want both unchanged", up, down)
	}
}

// TestFlipForwardFlipsExactlyOneByte flips byte 3 in one direction and leaves the other unchanged.
func TestFlipForwardFlipsExactlyOneByte(t *testing.T) {
	for _, dir := range []string{"up", "down"} {
		t.Run(dir, func(t *testing.T) {
			upstream, got := echoUpstream(t)
			addr, log := startFlipForward(t, "--upstream", upstream, "--flip-at", "3", "--dir", dir)
			up, down := roundTrip(t, addr, got)
			want := []byte("abcdef")
			want[3] ^= 0xFF
			flipped, clean := up, down
			if dir == "down" {
				flipped, clean = down, up
			}
			if dir == "up" {
				// The echo returns the flipped byte, so the client sees it too.
				clean = nil
			}
			if !bytes.Equal(flipped, want) {
				t.Errorf("%s direction carried %q, want %q", dir, flipped, want)
			}
			if clean != nil && string(clean) != "abcdef" {
				t.Errorf("the other direction carried %q, want it unchanged", clean)
			}
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(log.String(), `"flipped":true`) {
				if time.Now().After(deadline) {
					t.Fatalf("no connection line with flipped true: %s", log.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
			if strings.Contains(log.String(), "abcdef") {
				t.Errorf("the log holds relayed bytes: %s", log.String())
			}
		})
	}
}

// record builds one TLS record of type typ with payload p.
func record(typ byte, p string) []byte {
	return append([]byte{typ, 3, 3, byte(len(p) >> 8), byte(len(p))}, p...)
}

// TestRecordScannerSkipsHandshakeRecords counts printable runs only in application data records.
func TestRecordScannerSkipsHandshakeRecords(t *testing.T) {
	stream := append(record(22, "host.docker.internal-a-long-server-name"), record(23, "\x01hello world!!\x02ab")...)
	for _, split := range []int{1, 3, len(stream)} {
		s := &recordScanner{}
		for i := 0; i < len(stream); i += split {
			s.Write(stream[i:min(i+split, len(stream))])
		}
		if s.maxRun != 13 {
			t.Errorf("chunks of %d: max run %d, want 13 from the application data record only", split, s.maxRun)
		}
	}
}

// TestWatchPrintsOffsets dials a listener and prints one line for each dial, in time order.
func TestWatchPrintsOffsets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var out bytes.Buffer
	if code := execute(context.Background(), []string{"watch", "--addr", ln.Addr().String(), "--interval", "50ms", "--for", "220ms"}, &out); code != 0 {
		t.Fatalf("exit status %d: %s", code, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("got %d lines, want at least 3: %q", len(lines), out.String())
	}
	last := int64(-1)
	for _, l := range lines {
		var r struct {
			MS     int64
			Result string
		}
		if err := json.Unmarshal([]byte(l), &r); err != nil || r.Result != "connected" || r.MS < last {
			t.Errorf("line %q: want a connected dial at an offset not below %d", l, last)
		}
		last = r.MS
	}
}

// TestTLSServeCountsBytesAfterHandshake logs how many bytes a client sent after the handshake.
func TestTLSServeCountsBytesAfterHandshake(t *testing.T) {
	chain, key, _ := testChain(t, "spiffe://mgmt.poc.internal/api")
	old := stdin
	stdin = bytes.NewReader(append(append([]byte{}, chain...), key...))
	t.Cleanup(func() { stdin = old })
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- execute(ctx, []string{"tlsserve", "--addr", "127.0.0.1:0"}, out) }()
	defer func() { cancel(); <-done }()
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
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // test client
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	for {
		for l := range strings.SplitSeq(out.String(), "\n") {
			var rec struct {
				Msg   string
				Bytes int64 `json:"bytes_after_handshake"`
			}
			if json.Unmarshal([]byte(l), &rec) == nil && rec.Msg == "connection closed" {
				if rec.Bytes != 10 {
					t.Fatalf("bytes_after_handshake %d, want 10", rec.Bytes)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection closed line: %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTLSDialHandshakeFlip dials a TLS server through flipforward, which flips a byte of the server
// handshake. The client fails the handshake and names handshake_failed.
func TestTLSDialHandshakeFlip(t *testing.T) {
	const id = "spiffe://mgmt.poc.internal/telemetry"
	chain, key, _ := testChain(t, id)
	upstream := tlsServer(t, chain, key, nil)
	addr, _ := startFlipForward(t, "--upstream", upstream, "--flip-at", "100", "--dir", "down")
	var out bytes.Buffer
	code := execute(context.Background(), []string{"tlsdial", "--addr", addr, "--expect-id", id, "--bundle", writeFile(t, caPEM(t, chain))}, &out)
	if code != 0 {
		t.Fatalf("exit status %d: %s", code, out.String())
	}
	var r tlsDialResult
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("output is not one JSON line: %q", out.String())
	}
	if r.Handshake != "failed" || r.Reason != "handshake_failed" {
		t.Errorf("handshake %q reason %q, want failed and handshake_failed: %+v", r.Handshake, r.Reason, r)
	}
}

// countingServer serves TLS 1.3 h2 and sends the number of bytes that each connection carried after its handshake on the channel,
// when the connection ends.
func countingServer(t *testing.T, chain, key []byte) (string, <-chan int) {
	t.Helper()
	cert, err := tls.X509KeyPair(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	counts := make(chan int, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if err := c.(*tls.Conn).Handshake(); err != nil {
					counts <- 0
					return
				}
				n, _ := io.Copy(io.Discard, c)
				counts <- int(n)
			}()
		}
	}()
	return ln.Addr().String(), counts
}

// TestTLSDialCanary: with --canary, a client that passes the handshake writes 32 bytes, and a client that refuses the server writes none.
// --no-verify accepts any server, so it writes to an impostor, which is the positive control of the disclosure check.
func TestTLSDialCanary(t *testing.T) {
	const id = "spiffe://mgmt.poc.internal/telemetry"
	chain, key, _ := testChain(t, id)
	otherChain, _, _ := testChain(t, id)
	for _, c := range []struct {
		name  string
		args  func(roots []byte) []string
		roots []byte
		sent  bool
		bytes int
	}{
		{"verified server", func(r []byte) []string { return []string{"--expect-id", id, "--bundle", writeFile(t, r)} }, caPEM(t, chain), true, 32},
		{"wrong ID", func(r []byte) []string {
			return []string{"--expect-id", "spiffe://mgmt.poc.internal/api", "--bundle", writeFile(t, r)}
		}, caPEM(t, chain), false, 0},
		{"other CA", func(r []byte) []string { return []string{"--expect-id", id, "--bundle", writeFile(t, r)} }, caPEM(t, otherChain), false, 0},
		{"no verify", func(_ []byte) []string { return []string{"--no-verify"} }, nil, true, 32},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, counts := countingServer(t, chain, key)
			var out bytes.Buffer
			args := append([]string{"tlsdial", "--addr", addr, "--canary"}, c.args(c.roots)...)
			if code := execute(context.Background(), args, &out); code != 0 {
				t.Fatalf("exit status %d: %s", code, out.String())
			}
			var r tlsDialResult
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatalf("output is not one JSON line: %q", out.String())
			}
			if r.CanarySent != c.sent {
				t.Errorf("canary_sent %v, want %v: %+v", r.CanarySent, c.sent, r)
			}
			select {
			case n := <-counts:
				if n != c.bytes {
					t.Errorf("the server counted %d bytes after the handshake, want %d", n, c.bytes)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the server logged no ended connection")
			}
		})
	}
}

// TestRecordScannerFlagsNonTLS: a stream whose first header is not a TLS record is not TLS, and its run count is not below the bytes read.
func TestRecordScannerFlagsNonTLS(t *testing.T) {
	plain := &recordScanner{}
	plain.Write([]byte("GET / HTTP/1.1\r\nHost: example\r\n\r\n"))
	if plain.tls() || plain.maxRun < 5 {
		t.Errorf("plaintext: tls %v, max run %d, want not TLS", plain.tls(), plain.maxRun)
	}
	good := &recordScanner{}
	good.Write(append(record(22, "hello"), record(23, "\x00\x01\x02")...))
	if !good.tls() {
		t.Error("a stream of TLS records is reported as not TLS")
	}
	if (&recordScanner{}).tls() {
		t.Error("an empty stream is reported as TLS")
	}
}
