package cellproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"regexp"
	"testing"
	"time"
)

// holdBackend reports the source of each connection, then holds the connection until the peer
// closes it.
type holdBackend struct{ sources chan Source }

func (b *holdBackend) Name() string { return "hold" }

func (b *holdBackend) Serve(_ context.Context, conn *tls.Conn, src Source) error {
	b.sources <- src
	_, _ = io.Copy(io.Discard, conn)
	return nil
}

// testServer runs a server with backend b, the given allow pattern and config, and returns its
// address, its log and the CA of the environment.
func testServer(t *testing.T, cfg ServerConfig, b Backend, pattern string, level slog.Level) (string, *syncBuffer, *testCA) {
	t.Helper()
	return testServerWith(t, cfg, b, pattern, level, testRegistry(t))
}

// testServerWith is testServer with the registry source reg.
func testServerWith(t *testing.T, cfg ServerConfig, b Backend, pattern string, level slog.Level, reg RegistrySource) (string, *syncBuffer, *testCA) {
	t.Helper()
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	out := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: level}))
	cfg.TLS = ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(pattern), reg, log)
	return serveOn(t, NewServer(cfg, b, log), out, env)
}

func serveOn(t *testing.T, srv *Server, out *syncBuffer, env *testCA) (string, *syncBuffer, *testCA) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), out, env
}

// clientConfig presents an SVID for id from ca, or no certificate when ca is nil and id is "".
func clientConfig(t *testing.T, ca *testCA, id string, protos ...string) *tls.Config {
	t.Helper()
	if protos == nil {
		protos = []string{"h2"}
	}
	// The tests check the server side only, and an SVID has no DNS name to verify.
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: protos}
	if id != "" {
		cfg.Certificates = []tls.Certificate{tlsCert(ca.svid(t, id))}
	}
	return cfg
}

// dialHeld opens a connection that the caller closes.
func dialHeld(t *testing.T, addr string, cfg *tls.Config) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// closedWithin reports whether the server closes c within d.
func closedWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func waitSource(t *testing.T, sources chan Source, out *syncBuffer) Source {
	t.Helper()
	select {
	case src := <-sources:
		return src
	case <-time.After(5 * time.Second):
		t.Fatalf("the backend got no connection:\n%s", out.String())
	}
	return Source{}
}

func noSource(t *testing.T, sources chan Source) {
	t.Helper()
	select {
	case src := <-sources:
		t.Fatalf("the backend got a connection from %+v", src)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestServerDropsSilentConnections(t *testing.T) {
	b := &holdBackend{sources: make(chan Source, 4)}
	addr, out, env := testServer(t, ServerConfig{MaxHandshakes: 2, FirstByteTimeout: 300 * time.Millisecond}, b, viewPattern, slog.LevelInfo)
	silent := []net.Conn{dialTCP(t, addr), dialTCP(t, addr)}
	t.Cleanup(func() {
		for _, c := range silent {
			_ = c.Close()
		}
	})
	time.Sleep(100 * time.Millisecond)
	extra := dialTCP(t, addr)
	defer func() { _ = extra.Close() }()
	if !closedWithin(extra, time.Second) {
		t.Fatal("a connection beyond the handshake budget stayed open")
	}
	waitForLog(t, out, "connection refused", Overloaded, "")
	for i, c := range silent {
		if !closedWithin(c, 2*time.Second) {
			t.Fatalf("silent connection %d stayed open after the first-byte timeout", i)
		}
	}
	dialHeld(t, addr, clientConfig(t, env, agentID1))
	if src := waitSource(t, b.sources, out); src.Cell != "dev-cell-1" {
		t.Fatalf("source is %+v", src)
	}
}

func TestServerLimitsConnectionsPerSource(t *testing.T) {
	b := &holdBackend{sources: make(chan Source, 8)}
	pattern := `^spiffe://dev\.env\.poc\.internal/cell/dev-cell-1/(?:argocd-agent|otel)$`
	addr, out, env := testServer(t, ServerConfig{MaxConnsPerSource: 2, MaxConns: 3}, b, pattern, slog.LevelInfo)
	otelID := "spiffe://dev.env.poc.internal/cell/dev-cell-1/otel"
	for range 2 {
		dialHeld(t, addr, clientConfig(t, env, agentID1))
		waitSource(t, b.sources, out)
	}
	third := dialHeld(t, addr, clientConfig(t, env, agentID1))
	if !closedWithin(third, 2*time.Second) {
		t.Fatal("a third connection of one source stayed open")
	}
	waitForLog(t, out, "connection refused", Overloaded, agentID1)
	noSource(t, b.sources)

	dialHeld(t, addr, clientConfig(t, env, otelID))
	if src := waitSource(t, b.sources, out); src.Role != "otel" {
		t.Fatalf("another source is refused while one source is full: %+v", src)
	}
	fourth := dialHeld(t, addr, clientConfig(t, env, otelID))
	if !closedWithin(fourth, 2*time.Second) {
		t.Fatal("a connection beyond MaxConns stayed open")
	}
	waitForLog(t, out, "connection refused", Overloaded, otelID)
	noSource(t, b.sources)
}

func TestServerLogsProbeAtDebug(t *testing.T) {
	b := &holdBackend{sources: make(chan Source, 1)}
	addr, out, _ := testServer(t, ServerConfig{}, b, viewPattern, slog.LevelDebug)
	for range 3 {
		c, err := tls.Dial("tcp", addr, clientConfig(t, nil, ""))
		if err == nil {
			closedWithin(c, 2*time.Second)
			_ = c.Close()
		}
	}
	line := waitForLog(t, out, "peer refused", NoClientCert, "")
	if line["level"] != "DEBUG" || line["remote"] == nil {
		t.Fatalf("probe line is %v, want DEBUG with remote", line)
	}
	for _, l := range logLines(t, out) {
		if l["level"] == "WARN" || l["level"] == "ERROR" {
			t.Fatalf("a probe caused %v", l)
		}
	}
	if n := len(logLines(t, out)); n != 2 {
		t.Fatalf("three probes gave %d lines, want listening and one rate-limited refusal:\n%s", n, out.String())
	}
	noSource(t, b.sources)
}

func TestServerRequiresALPN(t *testing.T) {
	b := &holdBackend{sources: make(chan Source, 1)}
	addr, out, env := testServer(t, ServerConfig{}, b, viewPattern, slog.LevelInfo)
	c2, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{tlsCert(env.svid(t, agentID1))}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if !closedWithin(c2, 2*time.Second) {
		t.Fatal("a client with no ALPN stayed connected")
	}
	waitForLog(t, out, "peer refused", ProtocolNotH2, "")
	noSource(t, b.sources)
}

func TestServerIssuesNoSessionTickets(t *testing.T) {
	b := &recordBackend{sources: make(chan Source, 2)}
	addr, out, env := testServer(t, ServerConfig{}, b, viewPattern, slog.LevelInfo)
	cfg := clientConfig(t, env, agentID1)
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	for i := range 2 {
		c := dialHeld(t, addr, cfg)
		// Reading to the end lets the client take any session ticket.
		closedWithin(c, 2*time.Second)
		if c.ConnectionState().DidResume {
			t.Fatalf("connection %d resumed a session, so the server skipped its checks", i)
		}
		waitSource(t, b.sources, out)
	}
}

func TestServerTrustsOnlyPeerBundleFile(t *testing.T) {
	mgmt, env, attacker := newCA(t, mgmtTD), newCA(t, envTD), newCA(t, envTD)
	out := &syncBuffer{}
	log := jsonLog(out)
	// The SVID source of the server also holds a bundle for the environment, with the attacker root.
	own := source(mgmt.svid(t, principalID), mgmt.bundle(), attacker.bundle())
	b := &recordBackend{sources: make(chan Source, 1)}
	srv := NewServer(ServerConfig{TLS: ServerTLS(own, env.bundle(), regexp.MustCompile(viewPattern), testRegistry(t), log)}, b, log)
	addr, _, _ := serveOn(t, srv, out, env)
	c, err := tls.Dial("tcp", addr, clientConfig(t, attacker, agentID1))
	if err == nil {
		closedWithin(c, 2*time.Second)
		_ = c.Close()
	}
	waitForLog(t, out, "peer refused", PeerUntrusted, agentID1)
	noSource(t, b.sources)
}

// flakyListener fails its first Accept calls, as a process out of file descriptors does.
type flakyListener struct {
	net.Listener
	fails int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.fails > 0 {
		l.fails--
		return nil, errors.New("accept: too many open files")
	}
	return l.Listener.Accept()
}

func TestServerRetriesAcceptErrors(t *testing.T) {
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	out := &syncBuffer{}
	b := &recordBackend{sources: make(chan Source, 1)}
	srv := NewServer(ServerConfig{TLS: ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(viewPattern), testRegistry(t), jsonLog(out))}, b, jsonLog(out))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, &flakyListener{Listener: ln, fails: 3}) }()
	t.Cleanup(func() { cancel(); <-done })
	d := &net.Dialer{Deadline: time.Now().Add(5 * time.Second)}
	c, err := tls.DialWithDialer(d, "tcp", ln.Addr().String(), clientConfig(t, env, agentID1))
	if err != nil {
		t.Fatalf("no handshake after the accept errors: %v", err)
	}
	defer func() { _ = c.Close() }()
	waitSource(t, b.sources, out)
	for _, l := range logLines(t, out) {
		if l["msg"] == "accept failed" {
			return
		}
	}
	t.Fatalf("no accept failed line:\n%s", out.String())
}

func TestClientRequiresALPN(t *testing.T) {
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	srv, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert(mgmt.svid(t, principalID))}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	out := &syncBuffer{}
	cli := &Client{TLS: ClientTLS(source(env.svid(t, agentID1)), mgmt.bundle(), spiffeIDOf(principalID)), Upstream: srv.Addr().String(), Log: jsonLog(out)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { _ = cli.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	c := dialTCP(t, ln.Addr().String())
	defer func() { _ = c.Close() }()
	if !closedWithin(c, 2*time.Second) {
		t.Fatal("spiffe-client kept a connection to a server with no ALPN")
	}
	waitForLog(t, out, "peer refused", ProtocolNotH2, "")
}

// TestServerTLSRequiresClientCertWithoutVerifyCallback replaces the verify callback, as a later
// caller might. A client with no certificate must still fail the handshake.
func TestServerTLSRequiresClientCertWithoutVerifyCallback(t *testing.T) {
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	cfg := ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(viewPattern), testRegistry(t), jsonLog(&syncBuffer{}))
	cfg.GetConfigForClient = nil
	cfg.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	result := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		defer func() { _ = c.Close() }()
		result <- c.(*tls.Conn).Handshake()
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), clientConfig(t, nil, ""))
	if err == nil {
		defer func() { _ = c.Close() }()
	}
	select {
	case err := <-result:
		if ReasonOf(err) != NoClientCert {
			t.Fatalf("server handshake gave %v, want reason %s", err, NoClientCert)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server handshake did not end")
	}
}
