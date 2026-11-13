package mgmt

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/connlimit"
	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
)

// Settings of the API listener. Tests shorten them.
var (
	// maxPendingHandshakes is the size of the pool of API connections that have not finished the TLS
	// handshake.
	maxPendingHandshakes = 1024
	// handshakeDeadline is the time from accept to the end of the handshake, and firstByteDeadline is
	// the time from accept to the first byte of the client.
	handshakeDeadline = 5 * time.Second
	firstByteDeadline = 1 * time.Second

	// maxConns is the number of verified API connections.
	maxConns  = 64
	apiMaxAge = 5 * time.Minute
	apiGrace  = 5 * time.Second
)

const (
	filesMargin  = 64
	refuseWindow = 10 * time.Second
	refuseKeys   = 16
)

// Reasons of a refused API connection, as logged.
const (
	refusedPoolFull    = "pool_full"
	refusedTimeout     = "handshake_timeout"
	refusedFailed      = "handshake_failed"
	refusedNotAccepted = "not_accepted"
	refusedPeerRoot    = "peer_root_missing"
)

// FilesNeeded returns the number of open files that the listener may use at once: the pending
// pool, the verified connections and a margin for the rest of the process.
func FilesNeeded() uint64 {
	return uint64(maxPendingHandshakes + maxConns + filesMargin)
}

// ListenAPI wraps ln for the API server. The TLS handshake and the check of the client certificate
// run first, in one pool of pending connections. Only a verified connection takes one of the
// verified slots, which a peer without a valid certificate can never hold. A full pool refuses the
// new connection at once and evicts none. A pending connection has a first-byte deadline and a hard
// deadline, counted from accept. Each verified connection has the maximum age of the API.
// Refusals go to log, at most one line for each reason in each window. The server must use
// NewServers, which reads the verified peer for each connection.
func ListenAPI(ln net.Listener, cfg *tls.Config, log *slog.Logger) net.Listener {
	limit := lograte.New(refuseWindow, refuseKeys, time.Now)
	report := func(kind string, err error) {
		if kind == refusedFailed && strings.Contains(err.Error(), refusedPeerRoot) {
			kind = refusedPeerRoot
		}
		if _, ok, suppressed, _ := limit.Allow(kind); ok {
			log.Warn("handshake_refused", "reason", kind, "error", err.Error(), "suppressed", suppressed)
		}
	}
	hl := newHandshakeListener(ln, cfg, maxPendingHandshakes, handshakeDeadline, firstByteDeadline, report)
	return connlimit.Listen(hl, maxConns, apiMaxAge, apiGrace, nil)
}

// peerIDs maps a verified API connection, by its two addresses, to the SPIFFE ID of its client,
// from the end of the handshake until the server reads it in ConnContext.
var peerIDs sync.Map

type peerCtxKey struct{}

// peerInfo is the verified client of an API connection and the end of its certificate.
type peerInfo struct {
	ID       spiffeid.ID
	NotAfter time.Time
}

func connKey(c net.Conn) string { return c.LocalAddr().String() + ">" + c.RemoteAddr().String() }

// handshakeListener returns only connections whose TLS handshake succeeded.
type handshakeListener struct {
	net.Listener
	cfg       *tls.Config
	max       int
	timeout   time.Duration
	firstByte time.Duration
	report    func(kind string, err error)

	out       chan net.Conn
	done      chan struct{}
	closeOnce sync.Once

	mu      sync.Mutex
	pending map[*pendingConn]struct{}
}

type pendingConn struct {
	conn net.Conn
	seen atomic.Bool
	hard time.Time
}

// watchConn extends the deadline of a pending connection to its hard deadline at the first byte.
type watchConn struct {
	net.Conn
	p *pendingConn
}

func (w watchConn) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if n > 0 && w.p.seen.CompareAndSwap(false, true) {
		_ = w.Conn.SetDeadline(w.p.hard)
	}
	return n, err
}

func newHandshakeListener(inner net.Listener, cfg *tls.Config, max int, timeout, firstByte time.Duration, report func(string, error)) *handshakeListener {
	l := &handshakeListener{
		Listener: inner, cfg: cfg, max: max, timeout: timeout, firstByte: firstByte, report: report,
		out: make(chan net.Conn), done: make(chan struct{}), pending: map[*pendingConn]struct{}{},
	}
	go l.acceptLoop()
	return l
}

func (l *handshakeListener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				_ = l.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		p := &pendingConn{conn: c, hard: time.Now().Add(l.timeout)}
		l.mu.Lock()
		full := len(l.pending) >= l.max
		if !full {
			l.pending[p] = struct{}{}
		}
		l.mu.Unlock()
		if full {
			_ = c.Close()
			l.report(refusedPoolFull, errors.New("pool of pending handshakes is full"))
			continue
		}
		go l.handshake(p)
	}
}

func (l *handshakeListener) release(p *pendingConn) {
	l.mu.Lock()
	delete(l.pending, p)
	l.mu.Unlock()
}

func (l *handshakeListener) handshake(p *pendingConn) {
	raw := p.conn
	first := time.Now().Add(l.firstByte)
	if first.After(p.hard) {
		first = p.hard
	}
	_ = raw.SetDeadline(first)
	tc := tls.Server(watchConn{Conn: raw, p: p}, l.cfg)
	err := tc.Handshake()
	l.release(p)
	if err != nil {
		_ = raw.Close()
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			l.report(refusedTimeout, err)
		} else {
			l.report(refusedFailed, err)
		}
		return
	}
	_ = tc.SetDeadline(time.Time{})
	key := connKey(tc)
	if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
		if id, err := x509svid.IDFromCert(cs.PeerCertificates[0]); err == nil {
			peerIDs.Store(key, peerInfo{ID: id, NotAfter: cs.PeerCertificates[0].NotAfter})
		}
	}
	var out net.Conn = tc
	if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
		out = newExpiringConn(tc, cs.PeerCertificates[0].NotAfter)
	}
	select {
	case l.out <- out:
	case <-time.After(l.timeout):
		peerIDs.Delete(key)
		_ = out.Close()
		l.report(refusedNotAccepted, errors.New("verified connection was not accepted"))
	case <-l.done:
		peerIDs.Delete(key)
		_ = out.Close()
	}
}

// expiringConn closes the connection when the client certificate expires, so a connection never
// outlives the SVID that opened it.
type expiringConn struct {
	net.Conn
	timer *time.Timer
}

func newExpiringConn(c net.Conn, notAfter time.Time) net.Conn {
	e := &expiringConn{Conn: c}
	e.timer = time.AfterFunc(time.Until(notAfter), func() { _ = c.Close() })
	return e
}

func (e *expiringConn) Close() error {
	e.timer.Stop()
	return e.Conn.Close()
}

func (l *handshakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.out:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handshakeListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.Listener.Close()
		l.mu.Lock()
		for p := range l.pending {
			_ = p.conn.Close()
		}
		l.pending = map[*pendingConn]struct{}{}
		l.mu.Unlock()
	})
	return err
}

func peerFromContext(ctx interface{ Value(any) any }) (peerInfo, bool) {
	p, ok := ctx.Value(peerCtxKey{}).(peerInfo)
	return p, ok
}
