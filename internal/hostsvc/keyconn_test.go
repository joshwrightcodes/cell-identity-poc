package hostsvc

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

func tlsCertOf(t *testing.T, ca *spiffetest.CA, id string) tls.Certificate {
	t.Helper()
	svid := ca.SVID(t, id)
	return tls.Certificate{Certificate: [][]byte{svid.Certificates[0].Raw}, PrivateKey: svid.PrivateKey, Leaf: svid.Certificates[0]}
}

func dialPending(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// closedWithin reports whether the peer closes c within d.
func closedWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func newTestHandshakeListener(t *testing.T, max int, timeout, firstByte time.Duration) (*handshakeListener, string) {
	t.Helper()
	l, addr, _ := newTestHandshakeListenerCA(t, max, timeout, firstByte)
	return l, addr
}

func newTestHandshakeListenerCA(t *testing.T, max int, timeout, firstByte time.Duration) (*handshakeListener, string, *spiffetest.CA) {
	t.Helper()
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	cert, err := SelfSignedCert(KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerTLS(cert, ca.Bundle(), spiffeid.RequireFromString(mgmtdID))
	l := newHandshakeListener(inner, cfg, max, timeout, firstByte, func(string, error) {})
	t.Cleanup(func() { l.Close() })
	return l, inner.Addr().String(), ca
}

func pendingLen(l *handshakeListener) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending)
}

// A full pool refuses the new connection and keeps every pending one.
func TestHandshakeListenerRefusesWhenFullAndNeverEvicts(t *testing.T) {
	refusals := make(chan string, 16)
	l, addr := newTestHandshakeListener(t, 3, 30*time.Second, 30*time.Second)
	l.report = func(kind string, _ error) { refusals <- kind }
	var held []net.Conn
	for range 3 {
		held = append(held, dialPending(t, addr))
	}
	waitFor(t, "three pending connections", func() bool { return pendingLen(l) == 3 })
	for range 5 {
		extra := dialPending(t, addr)
		if !closedWithin(extra, 2*time.Second) {
			t.Fatal("a connection past the cap was not refused")
		}
	}
	for i, c := range held {
		if closedWithin(c, 100*time.Millisecond) {
			t.Errorf("pending connection %d was evicted", i)
		}
	}
	if got := pendingLen(l); got != 3 {
		t.Errorf("pending = %d, want 3", got)
	}
	if kind := <-refusals; kind != refusedPoolFull {
		t.Errorf("refusal reason = %q, want %q", kind, refusedPoolFull)
	}
}

func TestHandshakeListenerFirstByteDeadline(t *testing.T) {
	l, addr := newTestHandshakeListener(t, 8, 30*time.Second, 150*time.Millisecond)
	silent := dialPending(t, addr)
	if !closedWithin(silent, 3*time.Second) {
		t.Fatal("a silent connection stayed open past the first-byte deadline")
	}
	waitFor(t, "the pool to empty", func() bool { return pendingLen(l) == 0 })
}

func TestHandshakeListenerHardDeadlineAfterFirstByte(t *testing.T) {
	_, addr := newTestHandshakeListener(t, 8, 400*time.Millisecond, 100*time.Millisecond)
	c := dialPending(t, addr)
	if _, err := c.Write([]byte{0x16}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if closedWithin(c, 100*time.Millisecond) {
		t.Fatal("a connection that sent a byte was closed at the first-byte deadline")
	}
	if !closedWithin(c, 3*time.Second) {
		t.Fatal("a connection with a partial hello stayed open past the hard deadline")
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Errorf("closed after %v, want about the hard deadline of 400ms", d)
	}
}

func TestHandshakeListenerCloseClosesPending(t *testing.T) {
	l, addr := newTestHandshakeListener(t, 8, 30*time.Second, 30*time.Second)
	c := dialPending(t, addr)
	waitFor(t, "a pending connection", func() bool { return pendingLen(l) == 1 })
	l.Close()
	if !closedWithin(c, 2*time.Second) {
		t.Error("Close left a pending connection open")
	}
}

// A verified connection that nobody accepts does not wait for ever.
func TestHandshakeListenerDropsUnacceptedConnection(t *testing.T) {
	_, addr, ca := newTestHandshakeListenerCA(t, 8, 300*time.Millisecond, 300*time.Millisecond)
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{tlsCertOf(t, ca, mgmtdID)}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !closedWithin(c, 3*time.Second) {
		t.Error("a verified connection that was never accepted stayed open")
	}
}

func TestHandshakeListenerReturnsOnlyVerifiedPeers(t *testing.T) {
	l, addr := newTestHandshakeListener(t, 8, 2*time.Second, 2*time.Second)
	got := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			got <- c
		}
	}()
	// No client certificate: the handshake fails, and Accept returns nothing.
	bad, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err == nil {
		bad.Close()
	}
	select {
	case <-got:
		t.Fatal("Accept returned a connection without a client certificate")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestKeyServerSettings(t *testing.T) {
	if maxConns != 16 || maxPending != 1024 {
		t.Errorf("connection cap = %d, pending cap = %d, want 16 and 1024", maxConns, maxPending)
	}
	if connMaxAge != 30*time.Second || connGrace != 5*time.Second || handshakeTimeout != 5*time.Second || firstByteTimeout != time.Second {
		t.Errorf("max age %v, grace %v, handshake timeout %v", connMaxAge, connGrace, handshakeTimeout)
	}
	srv := NewKeyServer(http.NotFoundHandler(), &tls.Config{}, newDiscardLogger())
	if srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 10*time.Second || srv.WriteTimeout != 10*time.Second ||
		srv.IdleTimeout != 30*time.Second || srv.MaxHeaderBytes != 8<<10 {
		t.Errorf("limits = %v %v %v %v %d", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
	if srv.ConnContext == nil {
		t.Error("ConnContext is not set, so the maximum age cannot reach the handler")
	}
}

func TestKeyServerMaxAge(t *testing.T) {
	oldAge, oldGrace := connMaxAge, connGrace
	connMaxAge, connGrace = 300*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { connMaxAge, connGrace = oldAge, oldGrace })
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	addr, _ := keyServer(t, ca.Bundle(), &lookups{})
	cert := tlsCertOf(t, ca, mgmtdID)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}}}
	defer client.CloseIdleConnections()
	fetch := func() *http.Response {
		resp, err := client.Get("https://" + addr + "/none")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	if fetch().Close {
		t.Error("a young connection was told to close")
	}
	time.Sleep(350 * time.Millisecond)
	if !fetch().Close {
		t.Error("a connection past the maximum age was not told to close")
	}

	idle, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	if !closedWithin(idle, 3*time.Second) {
		t.Error("an idle connection survived the hard deadline")
	}
}

type swapRoots struct {
	mu  sync.Mutex
	cur x509bundle.Source
}

func (s *swapRoots) set(b x509bundle.Source) { s.mu.Lock(); s.cur = b; s.mu.Unlock() }

func (s *swapRoots) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur.GetX509BundleForTrustDomain(td)
}

// A session ticket from before a root change must not let a client skip the certificate check.
func TestKeyServerChecksClientAgainAfterResumption(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	other := spiffetest.NewCA(t, "mgmt.poc.internal")
	roots := &swapRoots{cur: ca.Bundle()}
	addr, _ := keyServer(t, roots, &lookups{})
	client := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, Certificates: []tls.Certificate{tlsCertOf(t, ca, mgmtdID)},
			ClientSessionCache: tls.NewLRUClientSessionCache(4),
		},
	}}
	for i := range 2 {
		resp, err := client.Get("https://" + addr + "/none")
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		resp.Body.Close()
	}
	roots.set(other.Bundle())
	if resp, err := client.Get("https://" + addr + "/none"); err == nil {
		resp.Body.Close()
		t.Fatal("a client with a ticket from the old root got an answer after the root changed")
	}
}
