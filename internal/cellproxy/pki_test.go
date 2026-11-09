package cellproxy

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const (
	mgmtTD      = "mgmt.poc.internal"
	envTD       = "dev.env.poc.internal"
	principalID = "spiffe://mgmt.poc.internal/argocd/principal"
	agentID1    = "spiffe://dev.env.poc.internal/cell/dev-cell-1/argocd-agent"
	agentID2    = "spiffe://dev.env.poc.internal/cell/dev-cell-2/argocd-agent"
	viewPattern = `^spiffe://dev\.env\.poc\.internal/cell/[a-z0-9-]+/argocd-agent$`
)

// testCA is a root CA for one trust domain.
type testCA struct {
	td   spiffeid.TrustDomain
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial = struct {
	sync.Mutex
	n int64
}{n: 1}

func nextSerial() *big.Int {
	serial.Lock()
	defer serial.Unlock()
	serial.n++
	return big.NewInt(serial.n)
}

func newCA(t *testing.T, td string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://" + td)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{td: spiffeid.RequireTrustDomainFromString(td), cert: cert, key: key}
}

func (ca *testCA) bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(ca.td, []*x509.Certificate{ca.cert})
}

// bundleFile writes the root as PEM, as the peer-root ConfigMap holds it.
func (ca *testCA) bundleFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// svid issues a leaf for id. A nil CA gives a self-signed leaf.
func (ca *testCA) svid(t *testing.T, id string) *x509svid.SVID {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	parent, signer := tmpl, any(key)
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: spiffeid.RequireFromString(id), Certificates: []*x509.Certificate{cert}, PrivateKey: key}
}

// svidSource holds one SVID and the bundle set that a Workload API source would also hold.
type svidSource struct {
	svid    *x509svid.SVID
	bundles *x509bundle.Set
}

func (s *svidSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

func (s *svidSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundles.GetX509BundleForTrustDomain(td)
}

func source(svid *x509svid.SVID, bundles ...*x509bundle.Bundle) *svidSource {
	return &svidSource{svid: svid, bundles: x509bundle.NewSet(bundles...)}
}

// tlsCert turns an SVID into a certificate for a plain crypto/tls peer.
func tlsCert(s *x509svid.SVID) tls.Certificate {
	c := tls.Certificate{PrivateKey: s.PrivateKey, Leaf: s.Certificates[0]}
	for _, cert := range s.Certificates {
		c.Certificate = append(c.Certificate, cert.Raw)
	}
	return c
}

// serveTLS runs a TLS 1.3 server that presents svid and completes each handshake.
func serveTLS(t *testing.T, svid *x509svid.SVID) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert(svid)}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	})
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
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// testJWKS is a key set with one P-256 public key, as a cell record needs.
var testJWKS = func() json.RawMessage {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "ec-1"}}})
	if err != nil {
		panic(err)
	}
	return raw
}()

func cell(name string, revoked bool) record.Cell {
	return record.Cell{Name: name, Env: "dev", Issuer: "https://" + name + ":6443", JWKS: testJWKS, Revoked: revoked, Epoch: 1, Counter: 1}
}

func signerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// writeRegistry writes signers.pub with the given keys and one signed file for each record,
// as the cell-registry ConfigMap holds them. A nil pubs list writes no signers.pub.
func writeRegistry(t *testing.T, pubs []ed25519.PublicKey, priv ed25519.PrivateKey, cells ...record.Cell) string {
	t.Helper()
	dir := t.TempDir()
	if pubs != nil {
		var lines []string
		for _, p := range pubs {
			lines = append(lines, base64.StdEncoding.EncodeToString(p))
		}
		if err := os.WriteFile(filepath.Join(dir, "signers.pub"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range cells {
		env, err := record.Sign(c, priv)
		if err != nil {
			t.Fatal(err)
		}
		name := c.Name
		if i > 0 && cells[i-1].Name == c.Name {
			name += "-" + string(rune('a'+i))
		}
		if err := os.WriteFile(filepath.Join(dir, name+".dsse.json"), env, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// testRegistry allows dev-cell-1 and holds a revoked record for dev-cell-2.
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	pub, priv := signerKey(t)
	reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub}, priv, cell("dev-cell-1", false), cell("dev-cell-2", true)))
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// syncBuffer is a bytes.Buffer that the test can read while the proxy writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func jsonLog(out *syncBuffer) *slog.Logger { return slog.New(slog.NewJSONHandler(out, nil)) }

// logLines decodes every line of out, and fails the test on a line that is not one JSON object.
func logLines(t *testing.T, out *syncBuffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	s := bufio.NewScanner(strings.NewReader(out.String()))
	for s.Scan() {
		var m map[string]any
		if err := json.Unmarshal(s.Bytes(), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", s.Text())
		}
		lines = append(lines, m)
	}
	return lines
}

// waitForLog waits up to 5 seconds for a line with msg and reason. A non-empty id must match
// the spiffe_id of the line too.
func waitForLog(t *testing.T, out *syncBuffer, msg string, reason Reason, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, l := range logLines(t, out) {
			if l["msg"] == msg && l["reason"] == string(reason) && (id == "" || l["spiffe_id"] == id) {
				return l
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q line with reason %q and ID %q in:\n%s", msg, reason, id, out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
