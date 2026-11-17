// Package connlimit bounds a listener: a cap on open connections, a hard deadline on each
// connection, and a way for an HTTP server to retire an old connection.
package connlimit

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type ctxKey struct{}

// Listen wraps inner. It allows at most maxConns open connections, and Accept waits for a slot
// while the cap is reached. Close wakes a waiting Accept. Each accepted connection has a hard
// deadline of maxAge + grace on the real clock, which a later SetDeadline call cannot extend. now
// supplies the accept time that Expired compares with maxAge, and nil means time.Now. Listen
// panics when maxConns or maxAge is not positive or grace is negative, because each value is a
// fixed setting of the caller.
func Listen(inner net.Listener, maxConns int, maxAge, grace time.Duration, now func() time.Time) net.Listener {
	if maxConns < 1 || maxAge <= 0 || grace < 0 {
		panic("connlimit: maxConns and maxAge must be positive and grace must not be negative")
	}
	if now == nil {
		now = time.Now
	}
	return &listener{
		Listener: inner, slots: make(chan struct{}, maxConns), done: make(chan struct{}),
		maxAge: maxAge, grace: grace, now: now,
	}
}

// ListenPerSource wraps inner like Listen and also allows at most perSource open connections from
// one source, where the source is the remote IP address after netip.Addr.Unmap, with no port. A
// connection above perSource is closed at once inside Accept, and Accept goes on to the next one.
// Only the connections that Accept returns count toward maxConns. A zero maxAge sets no deadline
// and Expired is always false. ListenPerSource panics when maxConns or perSource is not positive
// or maxAge or grace is negative, because each value is a fixed setting of the caller.
func ListenPerSource(inner net.Listener, maxConns, perSource int, maxAge, grace time.Duration, now func() time.Time) net.Listener {
	if maxConns < 1 || perSource < 1 || maxAge < 0 || grace < 0 {
		panic("connlimit: maxConns and perSource must be positive, and maxAge and grace must not be negative")
	}
	if now == nil {
		now = time.Now
	}
	return &listener{
		Listener: inner, slots: make(chan struct{}, maxConns), done: make(chan struct{}),
		maxAge: maxAge, grace: grace, now: now, perSource: perSource, sources: map[netip.Addr]int{},
	}
}

type listener struct {
	net.Listener
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	maxAge    time.Duration
	grace     time.Duration
	now       func() time.Time

	// perSource is 0 for a listener that Listen made, which has no per-source cap.
	perSource int
	mu        sync.Mutex
	sources   map[netip.Addr]int
}

// sourceOf returns the remote IP of c without its port, zone or 4-in-6 form. An address that does
// not parse gives the zero Addr, so all such connections share one source.
func sourceOf(c net.Conn) netip.Addr {
	var ap netip.AddrPort
	switch a := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		ap = a.AddrPort()
	case nil:
		return netip.Addr{}
	default:
		var err error
		if ap, err = netip.ParseAddrPort(a.String()); err != nil {
			return netip.Addr{}
		}
	}
	return ap.Addr().Unmap().WithZone("")
}

// admit counts c against its source. It reports false when the source already holds perSource.
func (l *listener) admit(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sources[src] >= l.perSource {
		return false
	}
	l.sources[src]++
	return true
}

func (l *listener) release(src netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sources[src]--; l.sources[src] <= 0 {
		delete(l.sources, src)
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.slots
			return nil, err
		}
		var src netip.Addr
		if l.perSource > 0 {
			// Closing a connection above the cap leaves the slot taken for the next one.
			if src = sourceOf(c); !l.admit(src) {
				c.Close()
				continue
			}
		}
		var hard time.Time
		if l.perSource == 0 || l.maxAge > 0 {
			hard = time.Now().Add(l.maxAge + l.grace)
			if err := c.SetDeadline(hard); err != nil {
				// Closing this connection leaves the slot taken for the next one, and keeps Serve running.
				c.Close()
				if l.perSource > 0 {
					l.release(src)
				}
				continue
			}
		}
		return &conn{Conn: c, l: l, hard: hard, acceptedAt: l.now(), src: src}, nil
	}
}

func (l *listener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type conn struct {
	net.Conn
	l          *listener
	hard       time.Time
	acceptedAt time.Time
	src        netip.Addr
	closeOnce  sync.Once
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		if c.l.perSource > 0 {
			c.l.release(c.src)
		}
		<-c.l.slots
	})
	return err
}

// clamp keeps a deadline at or before the hard deadline. A zero time means no deadline, which
// becomes the hard deadline. A connection with no hard deadline keeps the deadline as given.
func (c *conn) clamp(t time.Time) time.Time {
	if c.hard.IsZero() {
		return t
	}
	if t.IsZero() || t.After(c.hard) {
		return c.hard
	}
	return t
}

func (c *conn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(c.clamp(t)) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(c.clamp(t)) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(c.clamp(t)) }

func (c *conn) expired() bool { return c.l.maxAge > 0 && c.l.now().Sub(c.acceptedAt) >= c.l.maxAge }

// ConnContext is an http.Server.ConnContext function. It records the connection in the context
// that Expired reads. It finds the connection of this package under a TLS layer.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	for c != nil {
		if cc, ok := c.(*conn); ok {
			return context.WithValue(ctx, ctxKey{}, cc)
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return ctx
		}
		c = u.NetConn()
	}
	return ctx
}

// Expired reports whether the connection of a request is older than maxAge. It is false for a
// context that ConnContext did not mark.
func Expired(ctx context.Context) bool {
	c, ok := ctx.Value(ctxKey{}).(*conn)
	return ok && c.expired()
}

// MaxAge sets Connection: close on each response of an expired connection. The HTTP/2 server then
// sends GOAWAY, and the HTTP/1 server closes the connection.
func MaxAge(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Expired(r.Context()) {
			w.Header().Set("Connection", "close")
		}
		h.ServeHTTP(w, r)
	})
}
