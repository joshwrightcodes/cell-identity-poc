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

// Settings of the two listeners. Tests shorten them.
var (
	// maxPendingHandshakes is the size of the pool of API connections that have not finished the TLS
	// handshake.
	maxPendingHandshakes = 1024
	// handshakeDeadline is the time from accept to the end of the handshake, and firstByteDeadline is
	// the time from accept to the first byte of the client.
	handshakeDeadline = 5 * time.Second
	firstByteDeadline = 1 * time.Second

	maxConns  = 64
	apiMaxAge = 5 * time.Minute
	apiGrace  = 5 * time.Second
	// bindMaxAge plus bindGrace is the hard deadline of a bind connection. It stays below the 30 s
	// attempt timeout of celld, and above the maximum age plus a 10 s key fetch.
	bindMaxAge = 15 * time.Second
	bindGrace  = 10 * time.Second
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

// FilesNeeded returns the number of open files that both listeners may use at once: the pending
// pool, the verified connections of each listener and a margin for the rest of the process.
func FilesNeeded() uint64 { return uint64(maxPendingHandshakes + 2*maxConns + filesMargin) }

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

// ListenBind wraps ln for the bind server. A cell has no certificate to prove at the TLS layer, so
// every connection counts against the cap of 64. A connection beyond the cap is closed at once with
// no TLS, so a real cell fails fast and retries, and no connection waits in the kernel queue. A
// connection ends at its maximum age plus the grace at the latest. The TLS handshake runs inside
// the server, under its timeouts. Refusals go to log, at most one line in each window.
func ListenBind(ln net.Listener, cfg *tls.Config, log *slog.Logger) net.Listener {
	limit := lograte.New(refuseWindow, refuseKeys, time.Now)
	rl := &refusingListener{Listener: ln, max: int32(maxConns), refused: func() {
		if _, ok, suppressed, _ := limit.Allow("bind_full"); ok {
			log.Warn("connection_refused", "reason", "listener_full", "suppressed", suppressed)
		}
	}}
	// connlimit holds one more slot than the cap, so that one Accept always waits on rl and a
	// refusal never depends on the timing of the server's accept loop.
	return tls.NewListener(connlimit.Listen(rl, maxConns+1, bindMaxAge, bindGrace, nil), cfg)
}

// refusingListener closes each connection beyond max open connections as soon as it accepts it.
type refusingListener struct {
	net.Listener
	max     int32
	open    atomic.Int32
	refused func()
}

func (l *refusingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.open.Add(1) > l.max {
			l.open.Add(-1)
			_ = c.Close()
			l.refused()
			continue
		}
		return &countedConn{Conn: c, l: l}, nil
	}
}

type countedConn struct {
	net.Conn
	l    *refusingListener
	once sync.Once
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.open.Add(-1) })
	return err
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
