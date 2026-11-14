package hostsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// uriCA is a certificate authority whose root carries the URI SAN spiffe://<td>, as SPIRE issues it.
type uriCA struct {
	td   string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newURICA(t testing.TB, td string) *uriCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://" + td)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "root " + td}, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &uriCA{td: td, cert: cert, key: key}
}

func (c *uriCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

type svidSource struct{ s *x509svid.SVID }

func (s svidSource) GetX509SVID() (*x509svid.SVID, error) { return s.s, nil }

// source issues a leaf for id with a lifetime of ttl, and one minute before now.
func (c *uriCA) source(t testing.TB, id string, ttl time.Duration) x509svid.Source {
	t.Helper()
	return svidSource{c.issue(t, c.cert, c.key, id, ttl)}
}

func (c *uriCA) issue(t testing.TB, parent *x509.Certificate, pkey *ecdsa.PrivateKey, id string, ttl time.Duration) *x509svid.SVID {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(ttl - time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u},
	}
	if parent == nil {
		parent, pkey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, pkey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &x509svid.SVID{ID: spiffeid.RequireFromString(id), Certificates: []*x509.Certificate{leaf}, PrivateKey: key}
}

// selfSigned returns a source whose leaf signed itself.
func selfSigned(t testing.TB, id string) x509svid.Source {
	t.Helper()
	return svidSource{(&uriCA{}).issue(t, nil, nil, id, time.Hour)}
}

// routeEnv is a TLS host service with the router and recording handlers.
type routeEnv struct {
	t        *testing.T
	mgmt     *uriCA
	dev      *uriCA
	devFile  string
	mgmtFile string
	addr     string
	cert     tls.Certificate

	mu      sync.Mutex
	hits    map[string]int
	gate    chan struct{}
	entered chan struct{}
}

func (r *routeEnv) handler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits[name]++
		gate, entered := r.gate, r.entered
		r.mu.Unlock()
		if name == "steps" && gate != nil {
			entered <- struct{}{}
			<-gate
		}
		_, _ = io.WriteString(w, `{"route":"`+name+`"}`)
	})
}

func (r *routeEnv) hitCount(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[name]
}

func newRouteEnv(t *testing.T) *routeEnv {
	t.Helper()
	dir := t.TempDir()
	r := &routeEnv{t: t, mgmt: newURICA(t, MgmtTrustDomain), dev: newURICA(t, StepClientTrustDomain), hits: map[string]int{}}
	r.mgmtFile, r.devFile = filepath.Join(dir, "mgmt.pem"), filepath.Join(dir, "dev-root.crt")
	for p, ca := range map[string]*uriCA{r.mgmtFile: r.mgmt, r.devFile: r.dev} {
		if err := os.WriteFile(p, ca.pem(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	roots := FileBundleSet(map[spiffeid.TrustDomain]string{
		spiffeid.RequireTrustDomainFromString(MgmtTrustDomain):       r.mgmtFile,
		spiffeid.RequireTrustDomainFromString(StepClientTrustDomain): r.devFile,
	})
	cert, err := SelfSignedCert(KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.cert = cert
	mgmtID, stepsID := spiffeid.RequireFromString(mgmtAPIID), spiffeid.RequireFromString(cellControllerID)
	srv := NewKeyServer(NewRouter(r.handler("keys"), r.handler("spec"), r.handler("steps"), mgmtID, stepsID, 4),
		ServerTLS(cert, roots, mgmtID, stepsID), discardLog())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeKeys(ctx, srv, ln, discardLog(), nil) }()
	t.Cleanup(func() {
		r.mu.Lock()
		if r.gate != nil {
			select {
			case <-r.gate:
			default:
				close(r.gate)
			}
		}
		r.mu.Unlock()
		cancel()
		<-done
	})
	r.addr = ln.Addr().String()
	return r
}

func (r *routeEnv) client(src x509svid.Source) *KeyClient {
	r.t.Helper()
	sum := sha256.Sum256(r.cert.Leaf.Raw)
	kc, err := NewKeyClient(KeyClientConfig{Addr: r.addr, ServerName: KeyServerHost, Pin: sum[:], SVIDs: src, Timeout: 5 * time.Second})
	if err != nil {
		r.t.Fatal(err)
	}
	return kc
}

const (
	keysPath  = "/v1/clusters/dev-cell-1/keys"
	stepsPath = "/v1/steps/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestRouterPeerAuthorization(t *testing.T) {
	r := newRouteEnv(t)
	mgmtSrc := r.mgmt.source(t, mgmtAPIID, time.Hour)
	ccSrc := r.dev.source(t, cellControllerID, time.Hour)
	call := func(src x509svid.Source, method, path string) error {
		_, err := r.client(src).call(context.Background(), method, path, nil)
		return err
	}
	status := func(err error) int {
		var he *mgmtapi.HostError
		if !errors.As(err, &he) {
			t.Fatalf("error %v is not a HostError", err)
		}
		return he.Status
	}
	allowed := map[string]struct {
		src          x509svid.Source
		method, path string
		route        string
	}{
		"mgmt_api_on_keys":         {mgmtSrc, "GET", keysPath, "keys"},
		"mgmt_api_on_spec":         {mgmtSrc, "PUT", mgmtapi.HostSpecPath, "spec"},
		"cell_controller_on_steps": {ccSrc, "GET", stepsPath, "steps"},
	}
	for name, c := range allowed {
		t.Run(name, func(t *testing.T) {
			if err := call(c.src, c.method, c.path); err != nil {
				t.Fatal(err)
			}
			if r.hitCount(c.route) != 1 {
				t.Errorf("handler %s hit %d times, want 1", c.route, r.hitCount(c.route))
			}
		})
	}
	for name, c := range map[string]struct {
		src          x509svid.Source
		method, path string
	}{
		"mgmt_api_on_steps":          {mgmtSrc, "GET", stepsPath},
		"cell_controller_on_keys":    {ccSrc, "GET", keysPath},
		"cell_controller_on_spec":    {ccSrc, "PUT", mgmtapi.HostSpecPath},
		"cell_controller_on_unknown": {ccSrc, "GET", "/v1/other"},
	} {
		t.Run(name, func(t *testing.T) {
			before := r.hitCount("keys") + r.hitCount("spec") + r.hitCount("steps")
			if got := status(call(c.src, c.method, c.path)); got != http.StatusForbidden {
				t.Errorf("status = %d, want 403", got)
			}
			if after := r.hitCount("keys") + r.hitCount("spec") + r.hitCount("steps"); after != before {
				t.Error("a refused request reached a handler")
			}
		})
	}
	t.Run("mgmt_api_on_unknown_goes_to_keys", func(t *testing.T) {
		before := r.hitCount("keys")
		if err := call(mgmtSrc, "GET", "/v1/other"); err != nil {
			t.Fatal(err)
		}
		if r.hitCount("keys") != before+1 {
			t.Error("an unknown path from the management peer did not reach the key handler, which answers 404")
		}
	})
	handshakeFails := map[string]x509svid.Source{
		"cp_gateway":                       r.dev.source(t, "spiffe://dev.env.poc.internal/cp/gateway", time.Hour),
		"dev_ca_signs_mgmt_api_id":         r.dev.source(t, mgmtAPIID, time.Hour),
		"mgmt_ca_signs_cell_controller_id": r.mgmt.source(t, cellControllerID, time.Hour),
		"self_signed_cell_controller":      selfSigned(t, cellControllerID),
		"long_lived_leaf":                  r.dev.source(t, cellControllerID, 2*time.Hour),
		"leaf_of_66_minutes":               r.dev.source(t, cellControllerID, 66*time.Minute),
	}
	for name, src := range handshakeFails {
		t.Run(name, func(t *testing.T) {
			err := call(src, "GET", stepsPath)
			if err == nil {
				t.Fatal("the request succeeded, want a failed handshake")
			}
			if got := status(err); got != 0 {
				t.Errorf("status = %d, want a failure before any HTTP answer", got)
			}
		})
	}
	t.Run("no_cert", func(t *testing.T) {
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}}
		resp, err := hc.Get("https://" + r.addr + keysPath)
		if err == nil {
			resp.Body.Close()
			t.Fatal("a request without a certificate succeeded")
		}
	})
	t.Run("leaf_of_65_minutes_ok", func(t *testing.T) {
		if err := call(r.dev.source(t, cellControllerID, 64*time.Minute), "GET", stepsPath); err != nil {
			t.Errorf("a leaf that lives 63 minutes: %v", err)
		}
	})
	t.Run("long_lived_mgmt_leaf_ok", func(t *testing.T) {
		if err := call(r.mgmt.source(t, mgmtAPIID, 24*time.Hour), "GET", keysPath); err != nil {
			t.Errorf("the lifetime limit applies to the step client trust domain only: %v", err)
		}
	})
}

func TestRouterPerPeerInflight(t *testing.T) {
	r := newRouteEnv(t)
	r.mu.Lock()
	r.gate, r.entered = make(chan struct{}), make(chan struct{}, 8)
	r.mu.Unlock()
	cc := r.dev.source(t, cellControllerID, time.Hour)
	mgmt := r.mgmt.source(t, mgmtAPIID, time.Hour)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			_, err := r.client(cc).call(context.Background(), "GET", stepsPath, nil)
			errs <- err
		})
	}
	for range 4 {
		select {
		case <-r.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("four step requests did not reach the handler")
		}
	}
	_, err := r.client(cc).call(context.Background(), "GET", stepsPath, nil)
	var he *mgmtapi.HostError
	if !errors.As(err, &he) || he.Status != http.StatusServiceUnavailable || he.Reason != mgmtapi.ReasonHostsvcBusy || he.RetryAfter != 60*time.Second {
		t.Errorf("fifth request = %v, want 503 hostsvc_busy with Retry-After 60", err)
	}
	if _, err := r.client(mgmt).call(context.Background(), "GET", keysPath, nil); err != nil {
		t.Errorf("a mgmt_api keys request while the cell controller is at its limit: %v", err)
	}
	close(r.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a blocked request failed: %v", err)
		}
	}
	// A slot is free again.
	if _, err := r.client(cc).call(context.Background(), "GET", stepsPath, nil); err != nil {
		t.Errorf("request after the slots freed: %v", err)
	}
}

func TestServerTLSNoResumption(t *testing.T) {
	r := newRouteEnv(t)
	cs := tls.NewLRUClientSessionCache(4)
	svid := r.dev.issue(t, r.dev.cert, r.dev.key, cellControllerID, time.Hour)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, ClientSessionCache: cs,
		Certificates: []tls.Certificate{{Certificate: [][]byte{svid.Certificates[0].Raw}, PrivateKey: svid.PrivateKey}},
	}
	for i := range 2 {
		c, err := tls.Dial("tcp", r.addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("GET " + stepsPath + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		_, _ = io.ReadAll(c) // reads the session ticket frames, if the server sent any
		if c.ConnectionState().DidResume {
			t.Errorf("connection %d resumed a session", i+1)
		}
		c.Close()
	}
	cert, _ := SelfSignedCert(KeyServerHost, time.Now())
	if cfg := ServerTLS(cert, r.mgmt.bundleSource(t), spiffeid.RequireFromString(mgmtAPIID)); !cfg.SessionTicketsDisabled || cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ServerTLS config: tickets disabled %v, min %x, auth %v", cfg.SessionTicketsDisabled, cfg.MinVersion, cfg.ClientAuth)
	}
}

func (c *uriCA) bundleSource(t testing.TB) x509bundle.Source {
	t.Helper()
	return x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString(c.td), []*x509.Certificate{c.cert})
}
