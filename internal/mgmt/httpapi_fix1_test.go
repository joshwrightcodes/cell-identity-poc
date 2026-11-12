package mgmt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"golang.org/x/net/http2"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

// The listener limits of the shared table.
func TestListenerLimitsOfTheSharedTable(t *testing.T) {
	if maxConns != 64 || apiMaxAge != 5*time.Minute || bindMaxAge != 15*time.Second || apiGrace != 5*time.Second || bindGrace != 10*time.Second {
		t.Fatalf("connections %d, API age %s grace %s, bind age %s grace %s", maxConns, apiMaxAge, apiGrace, bindMaxAge, bindGrace)
	}
	if maxEstablished != 1024 || maxPendingHandshakes != 1024 || handshakeDeadline != 5*time.Second || firstByteDeadline != time.Second || bindHandlerTimeout != 25*time.Second {
		t.Fatalf("established %d, pending %d, hard %s, first byte %s, handler %s", maxEstablished, maxPendingHandshakes, handshakeDeadline, firstByteDeadline, bindHandlerTimeout)
	}
	if bindMaxAge+bindGrace >= 30*time.Second {
		t.Fatal("the bind hard deadline must stay below the 30 s attempt timeout of celld")
	}
	dummy := spiffetest.NewCA(t, devTD)
	svids := dummy.Source(t, mgmtSPIFFE)
	api, bind := NewServers(http.NotFoundHandler(), http.NotFoundHandler(), APIServerTLS(svids, dummy.Bundle(), mustID(t, envdSPIFFE)), BindServerTLS(svids))
	for _, tc := range []struct {
		name              string
		srv               *http.Server
		streams           int32
		read, write, idle time.Duration
	}{
		{"api", api, 4, 15 * time.Second, 15 * time.Second, 60 * time.Second},
		{"bind", bind, 2, 10 * time.Second, 15 * time.Second, 30 * time.Second},
	} {
		s := tc.srv
		if s.HTTP2 == nil || int32(s.HTTP2.MaxConcurrentStreams) != tc.streams || s.ReadTimeout != tc.read || s.WriteTimeout != tc.write ||
			s.IdleTimeout != tc.idle || s.ReadHeaderTimeout != 10*time.Second || s.ConnContext == nil || s.Handler == nil {
			t.Errorf("%s server limits %+v", tc.name, s)
		}
		if s.Protocols == nil || s.Protocols.HTTP1() || !s.Protocols.HTTP2() {
			t.Errorf("%s server protocols %v", tc.name, s.Protocols)
		}
	}
}

func envdRaw(t *testing.T, r *apiRig, timeout time.Duration) (*tls.Conn, error) {
	t.Helper()
	cfg := tlsconfig.MTLSClientConfig(r.devCA.Source(t, envdSPIFFE), r.mgmtCA.Bundle(), tlsconfig.AuthorizeID(mustID(t, mgmtSPIFFE)))
	cfg.NextProtos = []string{"h2"}
	return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", r.addr, cfg)
}

func newAPI(t *testing.T) *apiRig {
	t.Helper()
	return startAPI(t, NewAPIHandler(&fakeSpec{bundle: testBundle()}, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)), nil, nil)
}

// 64 verified connections fill the verified slots. The 65th request waits until one closes.
func TestAPIVerifiedConnCap(t *testing.T) {
	rig := newAPI(t)
	var conns []*tls.Conn
	for i := 0; i < 64; i++ {
		c, err := envdRaw(t, rig, 5*time.Second)
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		defer c.Close()
		conns = append(conns, c)
	}
	time.Sleep(200 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		resp, err := rig.client(t, rig.devCA.Source(t, envdSPIFFE)).Get(rig.specURL("dev"))
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("a request was served with 64 connections open: %v", err)
	case <-time.After(1 * time.Second):
	}
	conns[0].Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the request after a close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request was not served within 2 s after a close")
	}
}

// A verified connection that no slot takes within the handshake deadline is closed and logged.
func TestAPIVerifiedConnNotAcceptedIsClosed(t *testing.T) {
	setPending(t, 1024, 1500*time.Millisecond, time.Second)
	rig := newAPI(t)
	for i := 0; i < 64; i++ {
		c, err := envdRaw(t, rig, 5*time.Second)
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		defer c.Close()
	}
	extra, err := envdRaw(t, rig, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the connection with no slot stayed open: %v", err)
	}
	waitLog(t, rig.logs, "not_accepted")
}

func TestAPIStreamCap(t *testing.T) {
	rig := newAPI(t)
	c, err := envdRaw(t, rig, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cc, err := (&http2.Transport{}).NewClientConn(c)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for cc.State().MaxConcurrentStreams != 4 {
		if time.Now().After(deadline) {
			t.Fatalf("MAX_CONCURRENT_STREAMS %d, want 4", cc.State().MaxConcurrentStreams)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The API listener ends a busy connection at its maximum age through GOAWAY, and not at the hard
// deadline. The test shortens both times.
func TestAPIMaxAgeSendsGoAway(t *testing.T) {
	oldAge, oldGrace := apiMaxAge, apiGrace
	apiMaxAge, apiGrace = time.Second, 4*time.Second
	t.Cleanup(func() { apiMaxAge, apiGrace = oldAge, oldGrace })
	rig := newAPI(t)
	c := rig.client(t, rig.devCA.Source(t, envdSPIFFE))
	var first net.Conn
	var firstAt time.Time
	for time.Since(firstAt) < 3*time.Second || first == nil {
		var got net.Conn
		trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { got = i.Conn }}
		req, _ := http.NewRequest("GET", rig.specURL("dev"), nil)
		resp, err := c.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
		if err != nil {
			t.Fatalf("request at %s: %v", time.Since(firstAt), err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		switch {
		case first == nil:
			first, firstAt = got, time.Now()
		case got != first:
			if age := time.Since(firstAt); age < 800*time.Millisecond || age > 2500*time.Millisecond {
				t.Fatalf("moved to a new connection after %s, want about 1 s and before the hard deadline at 5 s", age)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the client stayed on one connection past the maximum age")
}

// shortCA makes a CA of its own, so that a test can issue a certificate with a chosen end.
type shortCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	td   spiffeid.TrustDomain
}

func newShortCA(t *testing.T, td string) *shortCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "short"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must0(t, err)
	cert, _ := x509.ParseCertificate(der)
	return &shortCA{cert: cert, key: key, td: mustID(t, "spiffe://"+td+"/x").TrustDomain()}
}

func (c *shortCA) bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(c.td, []*x509.Certificate{c.cert})
}

type staticSVID struct{ s *x509svid.SVID }

func (s staticSVID) GetX509SVID() (*x509svid.SVID, error) { return s.s, nil }

func (c *shortCA) svid(t *testing.T, id string, notAfter time.Time) *x509svid.SVID {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	must0(t, err)
	leaf, _ := x509.ParseCertificate(der)
	return &x509svid.SVID{ID: mustID(t, id), Certificates: []*x509.Certificate{leaf}, PrivateKey: key}
}

func must0(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// A verified connection closes when the client certificate expires, long before the maximum age,
// and a request on an expired certificate gets 403.
func TestAPIConnClosesAtCertificateExpiry(t *testing.T) {
	ca := newShortCA(t, devTD)
	rig := startAPI(t, NewAPIHandler(&fakeSpec{bundle: testBundle()}, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)),
		func(*spiffetest.CA) x509bundle.Source { return ca.bundle() }, nil)
	svid := ca.svid(t, envdSPIFFE, time.Now().Add(1500*time.Millisecond))
	cfg := tlsconfig.MTLSClientConfig(staticSVID{svid}, rig.mgmtCA.Bundle(), tlsconfig.AuthorizeID(mustID(t, mgmtSPIFFE)))
	cfg.NextProtos = []string{"h2"}
	c, err := tls.Dial("tcp", rig.addr, cfg)
	must0(t, err)
	defer c.Close()
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the connection stayed open: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the connection closed after %s, want about 1.5 s", d)
	}
}

func TestAPIHandlerRefusesExpiredCertificate(t *testing.T) {
	ca := newShortCA(t, devTD)
	h := NewAPIHandler(&fakeSpec{bundle: testBundle()}, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard))
	for name, notAfter := range map[string]time.Time{"valid": time.Now().Add(time.Hour), "expired": time.Now().Add(-time.Second)} {
		r := httptest.NewRequest("GET", mgmtapi.SpecPath("dev"), nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: ca.svid(t, envdSPIFFE, notAfter.Add(2*time.Second)).Certificates}
		r.TLS.PeerCertificates[0].NotAfter = notAfter
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if want := map[string]int{"valid": 200, "expired": 403}[name]; rec.Code != want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, want)
		}
	}
}

// The map of verified peers holds an entry only until the server reads it.
func TestPeerEntriesAreConsumed(t *testing.T) {
	rig := newAPI(t)
	c := rig.client(t, rig.devCA.Source(t, envdSPIFFE))
	for i := 0; i < 3; i++ {
		resp, err := c.Get(rig.specURL("dev"))
		must0(t, err)
		resp.Body.Close()
	}
	n := 0
	peerIDs.Range(func(k, _ any) bool {
		if strings.Contains(k.(string), rig.addr) {
			n++
		}
		return true
	})
	if n != 0 {
		t.Fatalf("%d peer entries for the listener after the requests", n)
	}
}

func TestAdminRestoreUnknownRevisionIsNotFound(t *testing.T) {
	r := newRig(t)
	h := NewAdminHandler(r.plane, nil)
	rec := do2(h, "POST", "/restore/99")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"reason":"not_found"`) {
		t.Fatalf("restore of an unknown counter: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"/restore/0", "/restore/00x"} {
		if rec := do2(h, "POST", bad); rec.Code != 400 {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
}

func TestSigningKeyCreatedIsLoggedInEveryPath(t *testing.T) {
	r := newRig(t)
	if n := r.logs.count("signing_key_created"); n != 1 {
		t.Fatalf("%d lines after a fresh start, want 1", n)
	}
	// The key file is lost and the state survives.
	must0(t, os.Remove(filepath.Join(r.dir, "ed25519.key")))
	r.restart(nil)
	if n := r.logs.count("signing_key_created"); n != 2 {
		t.Fatalf("%d lines after a lost key with a surviving state, want 2", n)
	}
	// The key is created and the first commit fails; the next start must not hide the creation.
	r2 := newRig(t)
	r2.mod = func(c *Config) { c.Store = failingStore{r2.store} }
	must0(t, os.Remove(filepath.Join(r2.dir, "ed25519.key")))
	if _, err := NewPlane(r2.config()); err == nil {
		t.Fatal("a plane started with a failing store")
	}
	if n := r2.logs.count("signing_key_created"); n != 2 {
		t.Fatalf("%d lines for a key created before a failed commit, want 2", n)
	}
}

type failingStore struct{ Store }

func (failingStore) Save(*State) error { return io.ErrClosedPipe }
