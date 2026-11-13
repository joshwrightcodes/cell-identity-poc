package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	defaultHandshakeTimeout  = 10 * time.Second
	defaultFirstByteTimeout  = 3 * time.Second
	defaultIdleTimeout       = 5 * time.Minute
	defaultMaxConns          = 256
	defaultMaxHandshakes     = 64
	defaultMaxConnsPerSource = 8
	keepAlivePeriod          = 30 * time.Second
	maxAcceptBackoff         = time.Second
)

// Backend serves one verified downstream connection. Serve must block until the connection ends,
// because the server closes conn when Serve returns.
type Backend interface {
	Name() string
	Serve(ctx context.Context, conn *tls.Conn, src Source) error
}

// ServerConfig configures the accept loop. A zero duration or count takes its default.
//
//   - HandshakeTimeout bounds the whole handshake: 10 seconds.
//   - FirstByteTimeout bounds the wait for the first byte of a new connection: 3 seconds.
//   - IdleTimeout ends an HTTP/2 connection with no open stream: 5 minutes.
//   - MaxHandshakes bounds the connections that have not finished the handshake: 64.
//   - MaxConns bounds the verified connections: 256.
//   - MaxConnsPerSource bounds the verified connections of one source: 8.
type ServerConfig struct {
	TLS                                             *tls.Config
	HandshakeTimeout, FirstByteTimeout, IdleTimeout time.Duration
	MaxHandshakes, MaxConns, MaxConnsPerSource      int
	// Proof, when set, makes the server read and verify a proof frame from each cell source after
	// the connection slots are taken and before the backend runs. Environment sources skip it.
	Proof *ProofCheck
}

// Server ends TLS for each connection and hands the verified peer to its backend.
type Server struct {
	cfg        ServerConfig
	backend    Backend
	log        *slog.Logger
	refusals   *refusalLog
	handshakes chan struct{}

	mu        sync.Mutex
	conns     int
	perSource map[Source]int
}

// NewServer returns a server for cfg and b.
func NewServer(cfg ServerConfig, b Backend, log *slog.Logger) *Server {
	setDefault(&cfg.HandshakeTimeout, defaultHandshakeTimeout)
	setDefault(&cfg.FirstByteTimeout, defaultFirstByteTimeout)
	setDefault(&cfg.IdleTimeout, defaultIdleTimeout)
	setDefault(&cfg.MaxHandshakes, defaultMaxHandshakes)
	setDefault(&cfg.MaxConns, defaultMaxConns)
	setDefault(&cfg.MaxConnsPerSource, defaultMaxConnsPerSource)
	log = log.With("backend", b.Name())
	return &Server{
		cfg: cfg, backend: b, log: log, refusals: newRefusalLog(log),
		handshakes: make(chan struct{}, cfg.MaxHandshakes), perSource: map[Source]int{},
	}
}

func setDefault[T comparable](v *T, def T) {
	var zero T
	if *v == zero {
		*v = def
	}
}

// Serve accepts connections on ln until ctx ends, then waits for the open connections to end.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	return serveListener(ctx, ln, s.log, func(c net.Conn) {
		select {
		case s.handshakes <- struct{}{}:
		default:
			s.refusals.write("connection refused", Overloaded, c.RemoteAddr().String(), "", errors.New("too many handshakes"))
			_ = c.Close()
			return
		}
		s.handle(ctx, c)
	})
}

// serveListener runs handle in a goroutine for each accepted connection until ctx ends. It retries
// an accept error with a growing pause, so a lack of file descriptors does not end the process.
func serveListener(ctx context.Context, ln net.Listener, log *slog.Logger, handle func(net.Conn)) error {
	log.Info("listening", "addr", ln.Addr().String())
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	var pause time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			pause = min(max(2*pause, 5*time.Millisecond), maxAcceptBackoff)
			log.Warn("accept failed", "error", err.Error(), "retry_in", pause.String())
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(pause):
			}
			continue
		}
		pause = 0
		wg.Go(func() { handle(c) })
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	remote := c.RemoteAddr().String()
	conn, src, id, ok := s.handshake(ctx, c, remote)
	if !ok {
		return
	}
	defer func() { _ = conn.Close() }()
	release, ok := s.acquire(src)
	if !ok {
		s.refusals.write("connection refused", Overloaded, remote, id, errors.New("connection limit of the server or the source reached"))
		return
	}
	defer release()
	if s.cfg.Proof != nil && src.Plane == PlaneCell {
		if err := s.cfg.Proof.check(conn, src, id); err != nil {
			s.refusals.write("proof refused", ReasonOf(err), remote, id, err)
			return
		}
	}
	log := s.log.With("spiffe_id", id, "remote", remote)
	log.Info("peer accepted")
	if err := s.backend.Serve(withIdleTimeout(ctx, s.cfg.IdleTimeout), conn, src); err != nil {
		log.Warn("backend failed", "error", err.Error())
	}
	log.Info("connection closed")
}

// handshake holds a handshake slot until the handshake ends, and returns the verified peer. On
// failure it logs the refusal and closes c.
func (s *Server) handshake(ctx context.Context, c net.Conn, remote string) (*tls.Conn, Source, string, bool) {
	defer func() { <-s.handshakes }()
	setKeepAlive(c)
	_ = c.SetReadDeadline(time.Now().Add(s.cfg.FirstByteTimeout))
	conn := tls.Server(&firstByteConn{Conn: c}, s.cfg.TLS)
	fail := func(reason Reason, id string, err error) (*tls.Conn, Source, string, bool) {
		s.refusals.write("peer refused", reason, remote, id, err)
		_ = conn.Close()
		return nil, Source{}, "", false
	}
	hctx, cancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	err := conn.HandshakeContext(hctx)
	cancel()
	if err != nil {
		// ServerTLS has logged each refused peer already.
		if ReasonOf(err) == "" {
			s.refusals.write("handshake failed", HandshakeFailed, remote, "", err)
		}
		_ = conn.Close()
		return nil, Source{}, "", false
	}
	st := conn.ConnectionState()
	if st.NegotiatedProtocol != "h2" {
		return fail(ProtocolNotH2, "", errors.New("the client did not agree on ALPN h2"))
	}
	if len(st.PeerCertificates) == 0 {
		return fail(NoClientCert, "", errors.New("no verified peer certificate"))
	}
	id, err := x509svid.IDFromCert(st.PeerCertificates[0])
	if err != nil {
		return fail(PeerUntrusted, "", err)
	}
	src, err := ParseSource(id)
	if err != nil {
		return fail(PeerNotAllowed, id.String(), err)
	}
	return conn, src, id.String(), true
}

// acquire takes a connection slot of the server and one of src, or reports that either is full.
func (s *Server) acquire(src Source) (func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns >= s.cfg.MaxConns || s.perSource[src] >= s.cfg.MaxConnsPerSource {
		return nil, false
	}
	s.conns++
	s.perSource[src]++
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.conns--
		if s.perSource[src]--; s.perSource[src] == 0 {
			delete(s.perSource, src)
		}
	}, true
}

// firstByteConn clears the read deadline of a new connection once its first byte arrives. The
// handshake timeout bounds the rest of the handshake.
type firstByteConn struct {
	net.Conn
	once sync.Once
}

func (c *firstByteConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() { _ = c.Conn.SetReadDeadline(time.Time{}) })
	}
	return n, err
}

func setKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: keepAlivePeriod, Interval: keepAlivePeriod})
	}
}

type idleTimeoutKey struct{}

// withIdleTimeout passes the idle timeout of the server to its backend.
func withIdleTimeout(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, idleTimeoutKey{}, d)
}

func idleTimeout(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(idleTimeoutKey{}).(time.Duration); ok {
		return d
	}
	return defaultIdleTimeout
}
