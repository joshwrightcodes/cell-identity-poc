package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
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
}

// Serve accepts connections on ln until ctx ends, then waits for the open connections to end.
func (c *Client) Serve(ctx context.Context, ln net.Listener) error {
	c.Log.Info("listening", "addr", ln.Addr().String(), "upstream", c.Upstream)
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		down, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { c.handle(ctx, down) })
	}
}

func (c *Client) handle(ctx context.Context, down net.Conn) {
	defer func() { _ = down.Close() }()
	setKeepAlive(down)
	d := net.Dialer{Timeout: dialTimeout, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: keepAlivePeriod, Interval: keepAlivePeriod}}
	raw, err := d.DialContext(ctx, "tcp", c.Upstream)
	if err != nil {
		c.Log.Warn("upstream dial failed", "reason", string(UpstreamUnavailable), "error", err.Error())
		return
	}
	up := tls.Client(raw, c.TLS)
	defer func() { _ = up.Close() }()
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err = up.HandshakeContext(hctx)
	cancel()
	if err != nil {
		var pe *PeerError
		if errors.As(err, &pe) {
			c.Log.Warn("peer refused", "reason", string(pe.Reason), "spiffe_id", pe.ID, "error", pe.Err.Error())
		} else {
			c.Log.Warn("handshake failed", "error", err.Error())
		}
		return
	}
	pipe(ctx, down, up)
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
