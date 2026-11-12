package hostsvc

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// errEvicted is the reason for a pending handshake that a newer connection pushed out.
var errEvicted = errors.New("handshake evicted by a newer connection")

// handshakeListener runs the TLS handshake of each accepted connection, and returns only
// connections whose handshake succeeded. The TLS config checks the client certificate during the
// handshake, so every connection that Accept returns has a verified peer.
//
// Connections that have not finished the handshake live in two pools, and each has the timeout to
// finish. A connection starts in the silent pool, which holds at most maxSilent connections, because
// a client that has sent no byte costs the server only a socket. A connection moves to the active
// pool when its first byte arrives. The active pool holds at most maxActive connections, the
// handshakes in progress. A full pool evicts its oldest connection, so a client that sends its hello
// at once always gets a turn, and silent sockets can never push an active handshake out. Accept
// never blocks on the pools, so a flood cannot keep a later connection waiting in the kernel queue.
type handshakeListener struct {
	net.Listener
	cfg       *tls.Config
	maxSilent int
	maxActive int
	timeout   time.Duration
	report    func(kind string, err error)

	out       chan net.Conn
	done      chan struct{}
	closeOnce sync.Once

	mu     sync.Mutex
	silent []*pendingConn
	active []*pendingConn
}

type pendingConn struct {
	conn    net.Conn
	evicted atomic.Bool
	moved   atomic.Bool
}

// watchConn tells the listener that the peer sent a byte.
type watchConn struct {
	net.Conn
	p *pendingConn
	l *handshakeListener
}

func (w watchConn) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if n > 0 && w.p.moved.CompareAndSwap(false, true) {
		w.l.activate(w.p)
	}
	return n, err
}

func newHandshakeListener(inner net.Listener, cfg *tls.Config, maxSilent, maxActive int, timeout time.Duration, report func(kind string, err error)) *handshakeListener {
	l := &handshakeListener{
		Listener: inner, cfg: cfg, maxSilent: maxSilent, maxActive: maxActive, timeout: timeout, report: report,
		out: make(chan net.Conn), done: make(chan struct{}),
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
		p := &pendingConn{conn: c}
		l.admit(p)
		go l.handshake(p)
	}
}

// push adds p to pool, and returns the oldest connection of pool when the pool was full.
func push(pool []*pendingConn, max int, p *pendingConn) ([]*pendingConn, *pendingConn) {
	var victim *pendingConn
	if len(pool) >= max {
		victim, pool = pool[0], pool[1:]
	}
	return append(pool, p), victim
}

func (l *handshakeListener) evict(victim *pendingConn) {
	if victim != nil {
		victim.evicted.Store(true)
		_ = victim.conn.Close()
	}
}

// admit puts a new connection in the silent pool.
func (l *handshakeListener) admit(p *pendingConn) {
	l.mu.Lock()
	var victim *pendingConn
	l.silent, victim = push(l.silent, l.maxSilent, p)
	l.mu.Unlock()
	l.evict(victim)
}

// activate moves p from the silent pool to the active pool.
func (l *handshakeListener) activate(p *pendingConn) {
	l.mu.Lock()
	var victim *pendingConn
	if remove(&l.silent, p) {
		l.active, victim = push(l.active, l.maxActive, p)
	}
	l.mu.Unlock()
	l.evict(victim)
}

func remove(pool *[]*pendingConn, p *pendingConn) bool {
	for i, q := range *pool {
		if q == p {
			*pool = append((*pool)[:i], (*pool)[i+1:]...)
			return true
		}
	}
	return false
}

// release removes p from both pools, and reports whether p was still in one of them.
func (l *handshakeListener) release(p *pendingConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return remove(&l.silent, p) || remove(&l.active, p)
}

func (l *handshakeListener) handshake(p *pendingConn) {
	raw := p.conn
	_ = raw.SetDeadline(time.Now().Add(l.timeout))
	tc := tls.Server(watchConn{Conn: raw, p: p, l: l}, l.cfg)
	err := tc.Handshake()
	if !l.release(p) && err == nil {
		err = errEvicted
	}
	if err != nil {
		_ = raw.Close()
		if p.evicted.Load() {
			l.report("handshake_evicted", errEvicted)
		} else {
			l.report("handshake_failed", err)
		}
		return
	}
	_ = tc.SetDeadline(time.Time{})
	select {
	case l.out <- tc:
	case <-time.After(l.timeout):
		_ = tc.Close()
	case <-l.done:
		_ = tc.Close()
	}
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
		for _, p := range append(l.silent, l.active...) {
			_ = p.conn.Close()
		}
		l.silent, l.active = nil, nil
		l.mu.Unlock()
	})
	return err
}
