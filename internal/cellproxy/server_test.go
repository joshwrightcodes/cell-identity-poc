package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// upstream is a fake gRPC server behind the proxy. It echoes each message, and records the hits
// and the metadata of each call.
type upstream struct {
	hits     atomic.Int64
	mu       sync.Mutex
	md       []metadata.MD
	canceled chan struct{}
}

func newUpstream() *upstream { return &upstream{canceled: make(chan struct{}, 16)} }

func (u *upstream) record(ctx context.Context) {
	u.hits.Add(1)
	md, _ := metadata.FromIncomingContext(ctx)
	u.mu.Lock()
	u.md = append(u.md, md)
	u.mu.Unlock()
}

func (u *upstream) lastMD() metadata.MD {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.md) == 0 {
		return nil
	}
	return u.md[len(u.md)-1]
}

func (u *upstream) unary(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	in := &wrapperspb.StringValue{}
	if err := dec(in); err != nil {
		return nil, err
	}
	srv.(*upstream).record(ctx)
	return in, nil
}

// bidi echoes each message. The message "notfound" ends the call with NotFound and trailer
// x-test: 1. A cancel from the client is reported on canceled.
func (u *upstream) bidi(srv any, stream grpc.ServerStream) error {
	up := srv.(*upstream)
	up.record(stream.Context())
	for {
		in := &wrapperspb.StringValue{}
		if err := stream.RecvMsg(in); err != nil {
			if status.Code(err) == codes.Canceled || errors.Is(stream.Context().Err(), context.Canceled) {
				up.canceled <- struct{}{}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if in.Value == "notfound" {
			stream.SetTrailer(metadata.Pairs("x-test", "1"))
			return status.Error(codes.NotFound, "no such item")
		}
		if err := stream.SendMsg(in); err != nil {
			return err
		}
	}
}

// fail ends a unary call with NotFound and trailer x-test: 1 before any reply, so grpc-go sends
// a trailers-only response.
func (u *upstream) fail(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	if err := dec(&wrapperspb.StringValue{}); err != nil {
		return nil, err
	}
	srv.(*upstream).record(ctx)
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-test", "1"))
	return nil, status.Error(codes.NotFound, "no such item")
}

func (u *upstream) register(s *grpc.Server) {
	unary := func(name string) grpc.MethodDesc { return grpc.MethodDesc{MethodName: name, Handler: u.unary} }
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "test.Echo", HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{unary("Unary"), {MethodName: "Fail", Handler: u.fail}},
		Streams: []grpc.StreamDesc{{StreamName: "Bidi", Handler: u.bidi, ServerStreams: true, ClientStreams: true}},
	}, u)
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "authapi.Authentication", HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{unary("Authenticate"), unary("RefreshToken")},
		// A stream on the RefreshToken path lets a test send two frames.
		Streams: []grpc.StreamDesc{{StreamName: "RefreshToken", Handler: u.bidi, ServerStreams: true, ClientStreams: true}},
	}, u)
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "versionapi.Version", HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{unary("Version")},
	}, u)
}

// tracked is an upstream connection that reports its close.
type tracked struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *tracked) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// splitListener accepts upstream connections and hands connection i to target i modulo the
// number of targets, so each gRPC server can send its own GOAWAY.
type splitListener struct {
	net.Listener
	mu      sync.Mutex
	conns   []*tracked
	targets []chan net.Conn
}

func (l *splitListener) run() {
	for i := 0; ; i++ {
		c, err := l.Listener.Accept()
		if err != nil {
			for _, t := range l.targets {
				close(t)
			}
			return
		}
		tc := &tracked{Conn: c, closed: make(chan struct{})}
		l.mu.Lock()
		l.conns = append(l.conns, tc)
		l.mu.Unlock()
		l.targets[i%len(l.targets)] <- tc
	}
}

func (l *splitListener) accepted() []*tracked {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*tracked(nil), l.conns...)
}

// chanListener serves the connections of one target.
type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	once sync.Once
	done chan struct{}
}

func newChanListener(ch chan net.Conn, addr net.Addr) *chanListener {
	return &chanListener{ch: ch, addr: addr, done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if ok {
			return c, nil
		}
	case <-l.done:
	}
	return nil, net.ErrClosed
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

// harness runs the fake upstream, spiffe-server with the grpc-header backend, and spiffe-client.
type harness struct {
	up        *upstream
	upstreams []*grpc.Server
	split     *splitListener
	serverLog *syncBuffer
	clientLog *syncBuffer
	server    string
	client    string
}

type harnessConfig struct {
	agentID   string
	upstreams int
}

func newHarness(t *testing.T, cfg harnessConfig) *harness {
	t.Helper()
	if cfg.agentID == "" {
		cfg.agentID = agentID1
	}
	if cfg.upstreams == 0 {
		cfg.upstreams = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	h := &harness{up: newUpstream(), serverLog: &syncBuffer{}, clientLog: &syncBuffer{}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.split = &splitListener{Listener: ln}
	for range cfg.upstreams {
		ch := make(chan net.Conn)
		h.split.targets = append(h.split.targets, ch)
		s := grpc.NewServer()
		h.up.register(s)
		h.upstreams = append(h.upstreams, s)
		go func() { _ = s.Serve(newChanListener(ch, ln.Addr())) }()
	}
	go h.split.run()

	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log := jsonLog(h.serverLog)
	srv := NewServer(ServerConfig{
		TLS: ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(viewPattern), testRegistry(t), log),
	}, NewHeaderBackend(ln.Addr().String(), "x-cell-agent", log), log)
	srvDone := make(chan struct{})
	go func() { _ = srv.Serve(ctx, srvLn); close(srvDone) }()
	h.server = srvLn.Addr().String()

	cliLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cli := &Client{TLS: ClientTLS(source(env.svid(t, cfg.agentID)), mgmt.bundle(), spiffeIDOf(principalID)), Upstream: h.server, Log: jsonLog(h.clientLog)}
	cliDone := make(chan struct{})
	go func() { _ = cli.Serve(ctx, cliLn); close(cliDone) }()
	h.client = cliLn.Addr().String()

	t.Cleanup(func() {
		cancel()
		<-cliDone
		<-srvDone
		for _, s := range h.upstreams {
			s.Stop()
		}
		_ = ln.Close()
	})
	return h
}

// dial opens a gRPC connection to spiffe-client.
func (h *harness) dial(t *testing.T) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///"+h.client, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func withToken(ctx context.Context, t *testing.T) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", accessToken(t, "dev-dev-cell-1", "autonomous"))
}

func bidiDesc() *grpc.StreamDesc { return &grpc.StreamDesc{ServerStreams: true, ClientStreams: true} }

func send(t *testing.T, s grpc.ClientStream, v string) {
	t.Helper()
	if err := s.SendMsg(wrapperspb.String(v)); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, s grpc.ClientStream, want string) {
	t.Helper()
	got := &wrapperspb.StringValue{}
	if err := s.RecvMsg(got); err != nil {
		t.Fatal(err)
	}
	if got.Value != want {
		t.Fatalf("got %q, want %q", got.Value, want)
	}
}

func unaryCall(ctx context.Context, conn *grpc.ClientConn, method string, opts ...grpc.CallOption) error {
	return conn.Invoke(ctx, method, wrapperspb.String("hello"), &wrapperspb.StringValue{}, opts...)
}

func TestServerProxiesBidiStream(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	conn := h.dial(t)

	t.Run("ping-pong", func(t *testing.T) {
		s, err := conn.NewStream(withToken(t.Context(), t), bidiDesc(), "/test.Echo/Bidi")
		if err != nil {
			t.Fatal(err)
		}
		for i := range 100 {
			start := time.Now()
			msg := string(rune('a' + i%26))
			send(t, s, msg)
			recv(t, s, msg)
			if d := time.Since(start); d > 200*time.Millisecond {
				t.Fatalf("reply %d took %v, want at most 200ms", i, d)
			}
		}
		if err := s.CloseSend(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("status and trailer", func(t *testing.T) {
		s, err := conn.NewStream(withToken(t.Context(), t), bidiDesc(), "/test.Echo/Bidi")
		if err != nil {
			t.Fatal(err)
		}
		send(t, s, "notfound")
		err = s.RecvMsg(&wrapperspb.StringValue{})
		if st, _ := status.FromError(err); st.Code() != codes.NotFound || st.Message() != "no such item" {
			t.Fatalf("got %v, want NotFound with the upstream message", err)
		}
		if got := s.Trailer().Get("x-test"); len(got) != 1 || got[0] != "1" {
			t.Fatalf("trailer x-test is %v, want [1]", got)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(withToken(t.Context(), t))
		s, err := conn.NewStream(ctx, bidiDesc(), "/test.Echo/Bidi")
		if err != nil {
			t.Fatal(err)
		}
		send(t, s, "x")
		recv(t, s, "x")
		cancel()
		select {
		case <-h.up.canceled:
		case <-time.After(time.Second):
			t.Fatal("the cancel did not reach the upstream within 1 second")
		}
	})
}

// TestServerKeepsTrailersOnlyStatus makes 200 calls that end with a trailers-only response. Each
// must reach the client with the upstream code, message and trailer.
func TestServerKeepsTrailersOnlyStatus(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	conn := h.dial(t)
	for i := range 200 {
		var trailer metadata.MD
		err := unaryCall(withToken(t.Context(), t), conn, "/test.Echo/Fail", grpc.Trailer(&trailer))
		if st, _ := status.FromError(err); st.Code() != codes.NotFound || st.Message() != "no such item" {
			t.Fatalf("call %d gave %v, want NotFound with the upstream message", i, err)
		}
		if got := trailer.Get("x-test"); len(got) != 1 || got[0] != "1" {
			t.Fatalf("call %d trailer x-test is %v, want [1]", i, got)
		}
	}
}

func TestServerClosesUpstreamWithDownstream(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	open := func() (*grpc.ClientConn, *tracked) {
		before := len(h.split.accepted())
		conn, err := grpc.NewClient("passthrough:///"+h.client, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		if err := unaryCall(withToken(t.Context(), t), conn, "/test.Echo/Unary"); err != nil {
			t.Fatal(err)
		}
		conns := h.split.accepted()
		if len(conns) != before+1 {
			t.Fatalf("one downstream connection gave %d upstream connections", len(conns)-before)
		}
		return conn, conns[len(conns)-1]
	}

	conn, up := open()
	_ = conn.Close()
	select {
	case <-up.closed:
	case <-time.After(time.Second):
		t.Fatal("the upstream connection stayed open 1 second after the downstream close")
	}

	runtime.GC()
	start := runtime.NumGoroutine()
	for range 20 {
		conn, _ := open()
		_ = conn.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > start {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%d goroutines after 20 connections, %d at the start:\n%s", runtime.NumGoroutine(), start, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerUsesOneUpstreamConnPerDownstream(t *testing.T) {
	h := newHarness(t, harnessConfig{upstreams: 2})
	ctx := withToken(t.Context(), t)
	first, err := h.dial(t).NewStream(ctx, bidiDesc(), "/test.Echo/Bidi")
	if err != nil {
		t.Fatal(err)
	}
	send(t, first, "1")
	recv(t, first, "1")
	second, err := h.dial(t).NewStream(ctx, bidiDesc(), "/test.Echo/Bidi")
	if err != nil {
		t.Fatal(err)
	}
	send(t, second, "2")
	recv(t, second, "2")
	if n := len(h.split.accepted()); n != 2 {
		t.Fatalf("two downstream connections gave %d upstream connections, want 2", n)
	}

	// GracefulStop sends GOAWAY on the first upstream connection only, and waits for its stream.
	stopped := make(chan struct{})
	go func() { h.upstreams[0].GracefulStop(); close(stopped) }()
	time.Sleep(200 * time.Millisecond)
	send(t, second, "after goaway")
	recv(t, second, "after goaway")

	if err := first.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if err := first.RecvMsg(&wrapperspb.StringValue{}); !errors.Is(err, io.EOF) {
		t.Fatalf("first stream ended with %v, want EOF", err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the first upstream did not stop")
	}
	send(t, second, "after stop")
	recv(t, second, "after stop")
}

func TestServerStripsClientIdentityHeader(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	ctx := metadata.AppendToOutgoingContext(withToken(t.Context(), t),
		"x-cell-agent", "dev-dev-cell-2", "x-cell-agent", "dev-dev-cell-2",
		"x-forwarded-for", "1.2.3.4", "x-forwarded-port", "443", "x-real-ip", "1.2.3.4", "forwarded", "for=1.2.3.4")
	if err := unaryCall(ctx, h.dial(t), "/test.Echo/Unary"); err != nil {
		t.Fatal(err)
	}
	md := h.up.lastMD()
	if got := md.Get("x-cell-agent"); len(got) != 1 || got[0] != "dev-dev-cell-1" {
		t.Fatalf("upstream x-cell-agent is %v, want exactly [dev-dev-cell-1]", got)
	}
	if got := md.Get(":authority"); len(got) != 1 || got[0] != h.split.Addr().String() {
		t.Fatalf("upstream :authority is %v, want the upstream address %s", got, h.split.Addr())
	}
	for _, k := range []string{"x-forwarded-for", "x-forwarded-port", "x-real-ip", "forwarded"} {
		if got := md.Get(k); len(got) != 0 {
			t.Fatalf("upstream got %s %v", k, got)
		}
	}
}

func TestEachBackendThroughSpiffeClient(t *testing.T) {
	t.Run("grpc-header", func(t *testing.T) {
		h := newHarness(t, harnessConfig{})
		if err := unaryCall(withToken(t.Context(), t), h.dial(t), "/test.Echo/Unary"); err != nil {
			t.Fatal(err)
		}
		if n := h.up.hits.Load(); n != 1 {
			t.Fatalf("upstream hits %d, want 1", n)
		}
	})
	t.Run("otlp", func(t *testing.T) {
		h := newGWHarness(t, &otlpUpstream{})
		conn := h.serve(t, otelPattern, otelID1)
		if _, err := collogspb.NewLogsServiceClient(conn).Export(t.Context(), &collogspb.ExportLogsServiceRequest{}); err != nil {
			t.Fatal(err)
		}
		if n := h.up.calls.Load(); n != 1 {
			t.Fatalf("upstream calls %d, want 1", n)
		}
	})
	t.Run("tunnel", tunnelThroughSpiffeClient)
}

func TestReasonStatusMapping(t *testing.T) {
	cases := []struct {
		reason Reason
		code   codes.Code
		http   int
	}{
		{PeerUntrusted, codes.PermissionDenied, http.StatusForbidden},
		{PeerNotAllowed, codes.PermissionDenied, http.StatusForbidden},
		{SubjectMismatch, codes.PermissionDenied, http.StatusForbidden},
		{RequestNotAllowed, codes.PermissionDenied, http.StatusForbidden},
		{UpstreamUnavailable, codes.Unavailable, http.StatusServiceUnavailable},
		{Overloaded, codes.Unavailable, http.StatusServiceUnavailable},
		{NoClientCert, codes.PermissionDenied, http.StatusForbidden},
		{ProtocolNotH2, codes.PermissionDenied, http.StatusForbidden},
		{HandshakeFailed, codes.PermissionDenied, http.StatusForbidden},
	}
	for _, c := range cases {
		if got := c.reason.GRPCCode(); got != c.code {
			t.Errorf("%s gives gRPC %v, want %v", c.reason, got, c.code)
		}
		if got := c.reason.HTTPStatus(); got != c.http {
			t.Errorf("%s gives HTTP %d, want %d", c.reason, got, c.http)
		}
	}
	names := map[Reason]string{
		PeerUntrusted: "peer_untrusted", PeerNotAllowed: "peer_not_allowed", SubjectMismatch: "subject_mismatch",
		RequestNotAllowed: "request_not_allowed", UpstreamUnavailable: "upstream_unavailable", Overloaded: "overloaded",
		NoClientCert: "no_client_cert", ProtocolNotH2: "protocol_not_h2", HandshakeFailed: "handshake_failed",
	}
	for r, want := range names {
		if string(r) != want {
			t.Errorf("reason %q, want %q", r, want)
		}
	}
}

// recordBackend records the source of each connection that reaches it.
type recordBackend struct{ sources chan Source }

func (b *recordBackend) Name() string { return "record" }

func (b *recordBackend) Serve(_ context.Context, conn *tls.Conn, src Source) error {
	b.sources <- src
	return conn.Close()
}

func TestServerAllowPattern(t *testing.T) {
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	out := &syncBuffer{}
	backend := &recordBackend{sources: make(chan Source, 1)}
	srv := NewServer(ServerConfig{
		TLS: ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(viewPattern), testRegistry(t), jsonLog(out)),
	}, backend, jsonLog(out))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	connect := func(t *testing.T, ca *testCA, id string) {
		t.Helper()
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			// The test checks the server side only, and an SVID has no DNS name to verify.
			Certificates: []tls.Certificate{tlsCert(ca.svid(t, id))}, InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
		})
		if err == nil {
			// In TLS 1.3 the server checks the client certificate after the client finishes.
			_, _ = c.Read(make([]byte, 1))
			_ = c.Close()
		}
	}

	t.Run("cell/dev-cell-1/argocd-agent", func(t *testing.T) {
		connect(t, env, agentID1)
		select {
		case src := <-backend.sources:
			if src.Cell != "dev-cell-1" || src.Env != "dev" || src.Role != "argocd-agent" {
				t.Fatalf("source is %+v", src)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("the backend got no connection:\n%s", out.String())
		}
	})
	refused := map[string]string{
		"cell/dev-cell-1/celld":                    "spiffe://dev.env.poc.internal/cell/dev-cell-1/celld",
		"cell/dev-cell-1/argocd-agentx":            "spiffe://dev.env.poc.internal/cell/dev-cell-1/argocd-agentx",
		"cell/dev-cell-1/argocd-agent/x":           "spiffe://dev.env.poc.internal/cell/dev-cell-1/argocd-agent/x",
		"cell/dev-cell-3/argocd-agent (no record)": "spiffe://dev.env.poc.internal/cell/dev-cell-3/argocd-agent",
		"cell/rogue/argocd-agent (reserved)":       "spiffe://dev.env.poc.internal/cell/rogue/argocd-agent",
		"revoked dev-cell-2":                       agentID2,
	}
	for name, id := range refused {
		t.Run(name, func(t *testing.T) {
			drain(backend)
			connect(t, env, id)
			waitForLog(t, out, "peer refused", PeerNotAllowed, id)
			assertNoSource(t, backend)
		})
	}
	t.Run("self-signed", func(t *testing.T) {
		drain(backend)
		connect(t, nil, agentID1)
		line := waitForLog(t, out, "peer refused", PeerUntrusted, agentID1)
		if _, ok := line["spiffe_id"]; ok || line["remote"] == nil {
			t.Fatalf("an untrusted ID is logged as spiffe_id, or the line has no remote: %v", line)
		}
		assertNoSource(t, backend)
	})
}

// drain drops a source that an earlier failed subtest left, so each subtest checks only its own
// connection.
func drain(b *recordBackend) {
	select {
	case <-b.sources:
	default:
	}
}

func assertNoSource(t *testing.T, b *recordBackend) {
	t.Helper()
	select {
	case src := <-b.sources:
		t.Fatalf("the backend got a connection from %+v", src)
	default:
	}
}
