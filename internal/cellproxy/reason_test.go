package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

// serveTLSLike listens on loopback, runs handle for each connection, and returns the address.
func serveTLSLike(t *testing.T, handle func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// tlsServerConfig returns a server config with a CA-signed SVID, TLS 1.3 and the given ALPN protocols.
func tlsServerConfig(t *testing.T, maxVersion uint16, protos ...string) *tls.Config {
	t.Helper()
	ca := spiffetest.NewCA(t, "poc.internal")
	cfg := tlsconfig.TLSServerConfig(ca.Source(t, "spiffe://poc.internal/gateway"))
	cfg.MinVersion, cfg.MaxVersion, cfg.NextProtos = tls.VersionTLS12, maxVersion, protos
	return cfg
}

// flipDown forwards to upstream and flips every bit of the byte at offset at of the upstream to client direction.
func flipDown(t *testing.T, upstream string, at int) string {
	t.Helper()
	return serveTLSLike(t, func(c net.Conn) {
		u, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		defer u.Close()
		go func() { _, _ = io.Copy(u, c) }()
		buf := make([]byte, 4096)
		off := 0
		for {
			n, err := u.Read(buf)
			if at >= off && at < off+n {
				buf[at-off] ^= 0xFF
			}
			off += n
			if n > 0 {
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
}

// TestTLSReasonRealHandshakes runs real client handshakes over TCP. crypto/tls returns an alert as a
// net.OpError of an unexported type, so only a real handshake shows what TLSReason must classify.
func TestTLSReasonRealHandshakes(t *testing.T) {
	clientCfg := func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, InsecureSkipVerify: true} //nolint:gosec // Only the error class is under test.
	}
	tlsListen := func(cfg *tls.Config) string {
		return serveTLSLike(t, func(c net.Conn) {
			tc := tls.Server(c, cfg)
			if tc.Handshake() == nil {
				_, _ = io.Copy(io.Discard, tc)
			}
		})
	}
	good := tlsListen(tlsServerConfig(t, tls.VersionTLS13, "h2"))
	for name, addr := range map[string]string{
		"alpn mismatch": tlsListen(tlsServerConfig(t, tls.VersionTLS13, "http/1.1")),
		"tls 1.2 only":  tlsListen(tlsServerConfig(t, tls.VersionTLS12, "h2")),
		"plain http": serveTLSLike(t, func(c net.Conn) {
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		}),
		"flipped handshake byte": flipDown(t, good, 100),
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			err = tls.Client(conn, clientCfg()).Handshake()
			if err == nil {
				t.Fatal("the handshake succeeded")
			}
			if got := TLSReason(err); got != HandshakeFailed {
				t.Errorf("TLSReason(%v) = %q, want %q", err, got, HandshakeFailed)
			}
		})
	}
}

// An HTTP client that meets a plain HTTP answer on its TLS port returns http.ErrSchemeMismatch.
func TestTLSReasonThroughHTTPClient(t *testing.T) {
	addr := serveTLSLike(t, func(c net.Conn) {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
	})
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, InsecureSkipVerify: true}} //nolint:gosec // Only the error class is under test.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/", http.NoBody)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the request succeeded")
	}
	if got := TLSReason(err); got != HandshakeFailed {
		t.Errorf("TLSReason(%v) = %q, want %q", err, got, HandshakeFailed)
	}
}

func TestTLSReasonOtherErrors(t *testing.T) {
	dialErr := func() error {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().String()
		_ = ln.Close()
		_, err := net.Dial("tcp", addr)
		return err
	}()
	for name, tc := range map[string]struct {
		err  error
		want Reason
	}{
		"peer error":       {fmt.Errorf("dial: %w", &PeerError{Reason: PeerNotAllowed, Err: errors.New("x")}), PeerNotAllowed},
		"connection error": {dialErr, ""},
		"context end":      {fmt.Errorf("dial: %w", context.DeadlineExceeded), ""},
		"plain error":      {errors.New("connection refused"), ""},
	} {
		if got := TLSReason(tc.err); got != tc.want {
			t.Errorf("%s: TLSReason = %q, want %q", name, got, tc.want)
		}
	}
}

func TestHandshakeReasonEOF(t *testing.T) {
	if got := HandshakeReason(fmt.Errorf("handshake: %w", io.ErrUnexpectedEOF)); got != HandshakeFailed {
		t.Errorf("HandshakeReason(unexpected EOF) = %q, want %q", got, HandshakeFailed)
	}
	if got := TLSReason(io.ErrUnexpectedEOF); got != "" {
		t.Errorf("TLSReason(unexpected EOF) = %q, want none outside a handshake", got)
	}
}
