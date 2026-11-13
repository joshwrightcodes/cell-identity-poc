package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

const (
	gwTD   = "dev.env.poc.internal"
	gwID   = "spiffe://dev.env.poc.internal/cp/gateway"
	cellID = "spiffe://dev.env.poc.internal/cell/cell-1/celld"
)

// pipeListener hands out the server end of in-memory connections.
type pipeListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

// freezeConn is the server end of a connection that can go silent: it still takes every byte the
// client writes, and it sends nothing, and it does not close.
type freezeConn struct {
	net.Conn
	mu     sync.Mutex
	frozen bool
}

func (c *freezeConn) freeze() {
	c.mu.Lock()
	c.frozen = true
	c.mu.Unlock()
}

func (c *freezeConn) isFrozen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.frozen
}

func (c *freezeConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if !c.isFrozen() || err != nil {
			return n, err
		}
	}
}

func (c *freezeConn) Write(p []byte) (int, error) {
	if c.isFrozen() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// seenFrame is a frame that the gateway read, with the time and the stream it came on.
type seenFrame struct {
	at     time.Time
	stream int
	f      gwapi.Frame
}

// gateway plays the stream handler of the cell gateway. Tests build it and use it inside a
// synctest bubble.
type gateway struct {
	t   *testing.T
	ca  *spiffetest.CA
	srv *http.Server
	pl  *pipeListener

	mu       sync.Mutex
	seen     []seenFrame
	streams  int
	conns    []*freezeConn
	bindings []string
	helloBad int
	dials    int
	queue    []gwapi.Frame
	handler  func(s *gwStream)
	minted   []minted
	cur      *gwStream
}

type minted struct {
	audience string
	at       time.Time
}

func newGateway(t *testing.T, serverID string) *gateway {
	t.Helper()
	return newGatewayWithCA(t, spiffetest.NewCA(t, gwTD), serverID)
}

func newGatewayWithCA(t *testing.T, ca *spiffetest.CA, serverID string) *gateway {
	t.Helper()
	g := &gateway{t: t, ca: ca, pl: &pipeListener{ch: make(chan net.Conn), done: make(chan struct{})}}
	cfg := tlsconfig.MTLSServerConfig(g.ca.Source(t, serverID), g.ca.Bundle(), tlsconfig.AuthorizeAny())
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos = []string{"h2"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+gwapi.StreamPattern, g.serve)
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	g.srv = &http.Server{Handler: mux, Protocols: protos, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = g.srv.Serve(tls.NewListener(g.pl, cfg)) }()
	return g
}

func (g *gateway) close() {
	_ = g.srv.Close()
	_ = g.pl.Close()
}

func (g *gateway) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	c, s := net.Pipe()
	fc := &freezeConn{Conn: s}
	g.mu.Lock()
	g.dials++
	g.conns = append(g.conns, fc)
	g.mu.Unlock()
	select {
	case g.pl.ch <- fc:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (g *gateway) record(stream int, f gwapi.Frame) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, seenFrame{at: time.Now(), stream: stream, f: f})
}

// frames returns the frames of one type that the gateway has read.
func (g *gateway) frames(typ string) []seenFrame {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []seenFrame
	for _, s := range g.seen {
		if s.f.Type == typ {
			out = append(out, s)
		}
	}
	return out
}

func (g *gateway) offer(frames ...gwapi.Frame) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.queue = append(g.queue, frames...)
}

func (g *gateway) nextOffer() (gwapi.Frame, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.queue) == 0 {
		return gwapi.Frame{}, false
	}
	f := g.queue[0]
	g.queue = g.queue[1:]
	return f, true
}

// gwStream is one stream, after a good hello.
type gwStream struct {
	g    *gateway
	n    int
	w    http.ResponseWriter
	dec  *gwapi.Decoder
	conn *freezeConn
	mu   sync.Mutex
}

func (s *gwStream) recv() (gwapi.Frame, error) {
	f, err := s.dec.Decode()
	if err == nil {
		s.g.record(s.n, f)
	}
	return f, err
}

func (s *gwStream) send(f gwapi.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return gwapi.Encode(s.w, f)
}

// current returns the newest stream that passed its hello.
func (g *gateway) current() *gwStream {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cur
}

// loop reads frames until the stream ends. hook sees each frame first and returns true when it
// answered the frame itself. The default answers a claim from the offers, a result and a status
// with ack, and a ping with pong.
func (s *gwStream) loop(hook func(f gwapi.Frame) bool) {
	for {
		f, err := s.recv()
		if err != nil {
			return
		}
		if hook != nil && hook(f) {
			continue
		}
		switch f.Type {
		case gwapi.TypeClaim:
			if l, ok := s.g.nextOffer(); ok {
				_ = s.send(l)
			} else {
				_ = s.send(gwapi.Frame{Type: gwapi.TypeNone})
			}
		case gwapi.TypeResult, gwapi.TypeStatus:
			_ = s.send(gwapi.Frame{Type: gwapi.TypeAck})
		case gwapi.TypePing:
			_ = s.send(gwapi.Frame{Type: gwapi.TypePong})
		}
	}
}

func (g *gateway) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.streams++
	n := g.streams
	h := g.handler
	var conn *freezeConn
	if len(g.conns) > 0 {
		conn = g.conns[len(g.conns)-1]
	}
	g.mu.Unlock()
	s := &gwStream{g: g, n: n, w: w, dec: gwapi.NewDecoder(r.Body), conn: conn}
	hello, err := s.recv()
	if err != nil || hello.Type != gwapi.TypeHello {
		return
	}
	binding, err := proof.Binding(*r.TLS)
	if err != nil {
		return
	}
	parts := strings.Split(hello.Token, "|")
	g.mu.Lock()
	if len(parts) < 2 || parts[1] != proof.HelloAudience(r.PathValue("cell"), binding) {
		g.helloBad++
		g.mu.Unlock()
		_ = s.send(gwapi.Frame{Type: gwapi.TypeRefused, Reason: gwapi.ReasonProofInvalid})
		return
	}
	g.bindings = append(g.bindings, binding)
	g.cur = s
	g.mu.Unlock()
	_ = s.send(gwapi.Frame{Type: gwapi.TypeWelcome, Pod: "uid-1", Cap: 2})
	if h == nil {
		s.loop(nil)
		return
	}
	h(s)
}

// tokens is the TokenFunc of the tests. A token reads "t|<audience>|<unix nano>|<number>".
func (g *gateway) tokens(_ context.Context, audience string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	g.minted = append(g.minted, minted{audience, now})
	return fmt.Sprintf("t|%s|%d|%d", audience, now.UnixNano(), len(g.minted)), nil
}

func tokenAudience(token string) string {
	p := strings.Split(token, "|")
	if len(p) < 2 {
		return ""
	}
	return p[1]
}

func (g *gateway) mintedCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.minted)
}

func (g *gateway) streamCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.streams
}

// streamFixture is a gateway, a rig, an executor and a stream config that uses them.
type streamFixture struct {
	t       *testing.T
	g       *gateway
	rig     *rig
	exec    *Executor
	cfg     StreamConfig
	updates chan struct{}
	cancel  context.CancelFunc
	done    chan error
}

func newFixture(t *testing.T, mod ...func(*StreamConfig)) *streamFixture {
	t.Helper()
	g := newGateway(t, gwID)
	r := newRig(t)
	e := r.executor("uid-1")
	updates := make(chan struct{}, 4)
	cfg := StreamConfig{
		Cell: "cell-1", Upstream: "gw.test:8450",
		TLS:         StreamTLS(g.ca.Source(t, cellID), g.ca.Bundle(), spiffeid.RequireFromString(gwID)),
		SVIDUpdates: updates, Tokens: g.tokens, Exec: e,
		Status: NewStatus("cell-1", "celld-uid-1", "uid-1", "test", func() time.Time { return time.Now().Add(time.Hour) }, e),
		Log:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		dial:   g.dial,
	}
	for _, m := range mod {
		m(&cfg)
	}
	return &streamFixture{t: t, g: g, rig: r, exec: e, cfg: cfg, updates: updates}
}

func (f *streamFixture) start() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.done = make(chan error, 1)
	go func() { f.done <- RunStream(ctx, f.cfg) }()
}

func (f *streamFixture) stop() {
	f.cancel()
	<-f.done
	f.g.close()
}

// waitFor polls cond in fake time until it holds, or fails the test after within.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %s", within, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// lease makes the lease frame of a valid test.count operation.
func (f *streamFixture) lease(id string, fe op.Fence) (gwapi.Frame, string) {
	o := f.rig.operation(testKind, "{}")
	return gwapi.Frame{Type: gwapi.TypeLease, LeaseID: id, Envelope: f.rig.sign(o), Fence: fe}, o.ID
}

type tlsConfig = tls.Config

var errNoSVID = errors.New("no SVID yet")

func sleepFake(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func fmtSscan(token string, iat *int64) (int, error) {
	p := strings.Split(token, "|")
	if len(p) < 3 {
		return 0, errors.New("short token")
	}
	return fmt.Sscan(p[2], iat)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.b.Bytes())
}

type slogDiscard struct{}

func (slogDiscard) Enabled(context.Context, slog.Level) bool  { return false }
func (slogDiscard) Handle(context.Context, slog.Record) error { return nil }
func (h slogDiscard) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h slogDiscard) WithGroup(string) slog.Handler           { return h }
