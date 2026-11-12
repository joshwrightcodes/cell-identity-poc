package hostsvc

import (
	"context"
	"crypto/sha256"
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

// A flood of sockets that send nothing must not keep mgmtd from reading keys.
func TestKeyServerSurvivesSilentFlood(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	l := &lookups{}
	addr, cert := keyServer(t, ca.Bundle(), l)
	sum := sha256.Sum256(cert.Leaf.Raw)
	c, err := NewKeyClient(KeyClientConfig{Addr: addr, ServerName: KeyServerHost, Pin: sum[:], SVIDs: ca.Source(t, mgmtdID), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for ctx.Err() == nil {
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					continue
				}
				_ = conn.SetReadDeadline(time.Now().Add(7 * time.Second))
				_, _ = io.Copy(io.Discard, conn)
				conn.Close()
			}
		})
	}
	defer func() { stop(); wg.Wait() }()
	time.Sleep(300 * time.Millisecond)
	for i := 1; i <= 20; i++ {
		start := time.Now()
		if _, err := c.Keys(t.Context(), "dev-cell-1"); err != nil {
			t.Fatalf("key read %d failed during the flood after %v: %v", i, time.Since(start), err)
		}
	}
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

func newTestHandshakeListener(t *testing.T, maxSilent, maxActive int, timeout time.Duration) (*handshakeListener, string) {
	t.Helper()
	l, addr, _ := newTestHandshakeListenerCA(t, maxSilent, maxActive, timeout)
	return l, addr
}

func newTestHandshakeListenerCA(t *testing.T, maxSilent, maxActive int, timeout time.Duration) (*handshakeListener, string, *spiffetest.CA) {
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
	l := newHandshakeListener(inner, cfg, maxSilent, maxActive, timeout, func(string, error) {})
	t.Cleanup(func() { l.Close() })
	return l, inner.Addr().String(), ca
}

func poolLens(l *handshakeListener) (silent, active int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.silent), len(l.active)
}

func waitPools(t *testing.T, l *handshakeListener, silent, active int) {
	t.Helper()
	waitFor(t, "the pools to hold the connections", func() bool {
		s, a := poolLens(l)
		return s == silent && a == active
	})
}

// sendByte makes c active and waits until the listener has seen it.
func sendByte(t *testing.T, l *handshakeListener, c net.Conn, wantActive int) {
	t.Helper()
	if _, err := c.Write([]byte{0x16}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a byte to arrive", func() bool { _, a := poolLens(l); return a == wantActive })
}

func TestHandshakeListenerSilentPoolEvictsOldest(t *testing.T) {
	l, addr := newTestHandshakeListener(t, 3, 2, 30*time.Second)
	var conns []net.Conn
	for range 3 {
		conns = append(conns, dialPending(t, addr))
	}
	waitPools(t, l, 3, 0)
	conns = append(conns, dialPending(t, addr))
	if !closedWithin(conns[0], 2*time.Second) {
		t.Fatal("the oldest silent connection was not evicted")
	}
	if closedWithin(conns[1], 200*time.Millisecond) {
		t.Error("the second silent connection was evicted")
	}
	waitPools(t, l, 3, 0)
}

func TestHandshakeListenerSilentFloodSparesActive(t *testing.T) {
	l, addr := newTestHandshakeListener(t, 3, 2, 30*time.Second)
	active := dialPending(t, addr)
	waitPools(t, l, 1, 0)
	sendByte(t, l, active, 1)
	for range 20 {
		dialPending(t, addr)
	}
	waitFor(t, "the silent pool to fill", func() bool { s, _ := poolLens(l); return s == 3 })
	if closedWithin(active, 200*time.Millisecond) {
		t.Error("a connection that had sent a byte was evicted by silent connections")
	}
	if _, a := poolLens(l); a != 1 {
		t.Errorf("active pool = %d, want 1", a)
	}
}

func TestHandshakeListenerActivePoolEvictsOldest(t *testing.T) {
	l, addr := newTestHandshakeListener(t, 8, 2, 30*time.Second)
	first, second, third := dialPending(t, addr), dialPending(t, addr), dialPending(t, addr)
	waitPools(t, l, 3, 0)
	sendByte(t, l, first, 1)
	sendByte(t, l, second, 2)
	sendByte(t, l, third, 2)
	if !closedWithin(first, 2*time.Second) {
		t.Error("the oldest active connection was not evicted")
	}
	if closedWithin(second, 200*time.Millisecond) {
		t.Error("the newer active connection was evicted")
	}
}

func TestHandshakeListenerTimesOut(t *testing.T) {
	_, addr := newTestHandshakeListener(t, 8, 8, 150*time.Millisecond)
	c := dialPending(t, addr)
	if !closedWithin(c, 3*time.Second) {
		t.Error("a silent connection stayed open past the handshake timeout")
	}
}

// A verified connection that nobody accepts does not wait for ever.
func TestHandshakeListenerDropsUnacceptedConnection(t *testing.T) {
	_, addr, ca := newTestHandshakeListenerCA(t, 8, 8, 300*time.Millisecond)
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
	l, addr := newTestHandshakeListener(t, 8, 8, 2*time.Second)
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
	if maxConns != 16 || maxActive != 8 || maxSilent != 128 {
		t.Errorf("connection cap = %d, active cap = %d, silent cap = %d, want 16, 8 and 128", maxConns, maxActive, maxSilent)
	}
	if connMaxAge != 30*time.Second || connGrace != 5*time.Second || handshakeTimeout != 5*time.Second {
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
	defer func() { connMaxAge, connGrace = oldAge, oldGrace }()
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
