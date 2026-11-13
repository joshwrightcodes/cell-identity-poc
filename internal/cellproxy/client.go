package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 10 * time.Second
)

// Client takes plaintext TCP connections and pipes the bytes of each one over mTLS to Upstream.
type Client struct {
	TLS      *tls.Config
	Upstream string
	Log      *slog.Logger

	once     sync.Once
	refusals *refusalLog
}

// Serve accepts connections on ln until ctx ends, then waits for the open connections to end.
func (c *Client) Serve(ctx context.Context, ln net.Listener) error {
	c.once.Do(func() { c.refusals = newRefusalLog(c.Log) })
	return serveListener(ctx, ln, c.Log.With("upstream", c.Upstream), func(down net.Conn) { c.handle(ctx, down) })
}

func (c *Client) handle(ctx context.Context, down net.Conn) {
	defer func() { _ = down.Close() }()
	setKeepAlive(down)
	d := net.Dialer{Timeout: dialTimeout, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: keepAlivePeriod, Interval: keepAlivePeriod}}
	raw, err := d.DialContext(ctx, "tcp", c.Upstream)
	if err != nil {
		c.refusals.write("upstream dial failed", UpstreamUnavailable, c.Upstream, "", err)
		return
	}
	up := tls.Client(raw, c.TLS)
	defer func() { _ = up.Close() }()
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err = up.HandshakeContext(hctx)
	cancel()
	if err == nil {
		err = requireH2(up)
	}
	if err != nil {
		var pe *PeerError
		if errors.As(err, &pe) {
			c.refusals.write("peer refused", pe.Reason, c.Upstream, pe.ID, pe.Err)
		} else {
			c.refusals.write("handshake failed", HandshakeFailed, c.Upstream, "", err)
		}
		return
	}
	pipe(ctx, down, up)
}

// requireH2 refuses a server that did not agree on ALPN h2.
func requireH2(conn *tls.Conn) error {
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		return &PeerError{Reason: ProtocolNotH2, Err: fmt.Errorf("server agreed on ALPN %q, not h2", p)}
	}
	return nil
}

// pipe copies bytes both ways. When one side closes or half-closes, or ctx ends, it closes both.
func pipe(ctx context.Context, a, b net.Conn) {
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
	closeBoth()
	<-done
}
