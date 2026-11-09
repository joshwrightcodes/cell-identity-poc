package cellproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
	defaultIdleTimeout      = 5 * time.Minute
	defaultMaxConns         = 256
	keepAlivePeriod         = 30 * time.Second
)

// Backend serves one verified downstream connection until it ends.
type Backend interface {
	Name() string
	Serve(ctx context.Context, conn *tls.Conn, src Source) error
}

// ServerConfig configures the accept loop. A zero duration or count takes its default: 10
// seconds, 5 minutes and 256 connections.
type ServerConfig struct {
	TLS                           *tls.Config
	HandshakeTimeout, IdleTimeout time.Duration
	MaxConns                      int
}

// Server ends TLS for each connection and hands the verified peer to its backend.
type Server struct {
	cfg     ServerConfig
	backend Backend
	log     *slog.Logger
}

// NewServer returns a server for cfg and b.
func NewServer(cfg ServerConfig, b Backend, log *slog.Logger) *Server {
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = defaultMaxConns
	}
	return &Server{cfg: cfg, backend: b, log: log.With("backend", b.Name())}
}

// Serve accepts connections on ln until ctx ends, then waits for the open connections to end.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.log.Info("listening", "addr", ln.Addr().String())
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	slots := make(chan struct{}, s.cfg.MaxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		select {
		case slots <- struct{}{}:
		default:
			s.log.Warn("connection refused", "reason", string(Overloaded), "remote", c.RemoteAddr().String())
			_ = c.Close()
			continue
		}
		wg.Go(func() {
			defer func() { <-slots }()
			s.handle(ctx, c)
		})
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	setKeepAlive(c)
	remote := c.RemoteAddr().String()
	conn := tls.Server(c, s.cfg.TLS)
	defer func() { _ = conn.Close() }()
	hctx, cancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	err := conn.HandshakeContext(hctx)
	cancel()
	if err != nil {
		// ServerTLS has logged each refused peer already.
		if ReasonOf(err) == "" {
			s.log.Warn("handshake failed", "remote", remote, "error", err.Error())
		}
		return
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		s.log.Warn("peer refused", "reason", string(PeerUntrusted), "remote", remote, "error", "no verified peer certificate")
		return
	}
	id, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		s.log.Warn("peer refused", "reason", string(PeerUntrusted), "remote", remote, "error", err.Error())
		return
	}
	src, err := ParseSource(id)
	if err != nil {
		s.log.Warn("peer refused", "reason", string(PeerNotAllowed), "spiffe_id", id.String(), "remote", remote, "error", err.Error())
		return
	}
	log := s.log.With("spiffe_id", id.String(), "remote", remote)
	log.Info("peer accepted")
	if err := s.backend.Serve(withIdleTimeout(ctx, s.cfg.IdleTimeout), conn, src); err != nil {
		log.Warn("backend failed", "error", err.Error())
	}
	log.Info("connection closed")
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
