package hostsvc

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Reasons of a refused connection, as logged and as the label of the refusal metric.
const (
	refusedPoolFull  = "pool_full"
	refusedTimeout   = "handshake_timeout"
	refusedFailed    = "handshake_failed"
	refusedUndeliver = "not_accepted"
)

// peerIDs maps a verified connection (by its two addresses) to the SPIFFE ID of its peer, from the
// end of the handshake until ConnContext reads it.
var peerIDs sync.Map

type peerCtxKey struct{}

func connKey(c net.Conn) string { return c.LocalAddr().String() + ">" + c.RemoteAddr().String() }

// PeerID returns the SPIFFE ID of the verified client of a request. The server runs the TLS
// handshake before the HTTP server sees the connection, so Request.TLS is nil and a handler reads
// the peer from the request context instead.
func PeerID(ctx context.Context) (spiffeid.ID, bool) {
	id, ok := ctx.Value(peerCtxKey{}).(spiffeid.ID)
	return id, ok
}

// handshakeListener runs the TLS handshake of each accepted connection, and returns only
// connections whose handshake succeeded. The TLS config checks the client certificate during the
// handshake, so every connection that Accept returns has a verified peer.
//
// Connections that have not finished the handshake share one pool of at most max. A full pool
// refuses the new connection at once and never evicts a pending one, so a flood costs the real
// client nothing until the pool is full. A pending connection has firstByte to send its first byte
// and timeout in all, counted from accept, to finish the handshake. Accept never blocks on the
// pool, so a flood cannot keep a later connection waiting in the kernel queue.
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

// watchConn extends the deadline of a connection to its hard deadline when the first byte arrives.
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

func newHandshakeListener(inner net.Listener, cfg *tls.Config, max int, timeout, firstByte time.Duration, report func(kind string, err error)) *handshakeListener {
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
				l.Close()
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
			peerIDs.Store(key, id)
		}
	}
	select {
	case l.out <- tc:
	case <-time.After(l.timeout):
		peerIDs.Delete(key)
		_ = tc.Close()
		l.report(refusedUndeliver, errors.New("verified connection was not accepted"))
	case <-l.done:
		peerIDs.Delete(key)
		_ = tc.Close()
	}
}

// connContext is the ConnContext of the key server. It marks the connection for the maximum age
// and adds the verified peer to the context.
func connContext(ctx context.Context, c net.Conn, base func(context.Context, net.Conn) context.Context) context.Context {
	ctx = base(ctx, c)
	if v, ok := peerIDs.LoadAndDelete(connKey(c)); ok {
		ctx = context.WithValue(ctx, peerCtxKey{}, v.(spiffeid.ID))
	}
	return ctx
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
