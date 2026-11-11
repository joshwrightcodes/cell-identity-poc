// Package connlimit bounds a listener: a cap on open connections, a hard deadline on each
// connection, and a way for an HTTP server to retire an old connection.
package connlimit

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

type ctxKey struct{}

// Listen wraps inner. It allows at most maxConns open connections, and Accept waits for a slot
// while the cap is reached. Each accepted connection has a hard deadline of maxAge + grace on the
// real clock, which a later SetDeadline call cannot extend. now supplies the accept time that
// Expired compares with maxAge.
func Listen(inner net.Listener, maxConns int, maxAge, grace time.Duration, now func() time.Time) net.Listener {
	if maxConns < 1 {
		maxConns = 1
	}
	if now == nil {
		now = time.Now
	}
	return &listener{
		Listener: inner, slots: make(chan struct{}, maxConns), done: make(chan struct{}),
		maxAge: maxAge, grace: grace, now: now,
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
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	hard := time.Now().Add(l.maxAge + l.grace)
	if err := c.SetDeadline(hard); err != nil {
		c.Close()
		<-l.slots
		return nil, err
	}
	return &conn{Conn: c, l: l, hard: hard, acceptedAt: l.now()}, nil
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
	closeOnce  sync.Once
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { <-c.l.slots })
	return err
}

// clamp keeps a deadline at or before the hard deadline. A zero time means no deadline, which
// becomes the hard deadline.
func (c *conn) clamp(t time.Time) time.Time {
	if t.IsZero() || t.After(c.hard) {
		return c.hard
	}
	return t
}

func (c *conn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(c.clamp(t)) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(c.clamp(t)) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(c.clamp(t)) }

func (c *conn) expired() bool { return c.l.now().Sub(c.acceptedAt) >= c.l.maxAge }

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
