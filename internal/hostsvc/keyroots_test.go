package hostsvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type rootOpts struct {
	uris      []string
	notCA     bool
	noCertSig bool
	expired   bool
}

func rootPEM(t *testing.T, o rootOpts) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: !o.notCA, KeyUsage: x509.KeyUsageCertSign,
	}
	if o.noCertSig {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if o.expired {
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-3*time.Hour), time.Now().Add(-2*time.Hour)
	}
	for _, u := range o.uris {
		p, _ := url.Parse(u)
		tmpl.URIs = append(tmpl.URIs, p)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemBytes(p []byte) []byte {
	b, _ := pem.Decode(p)
	return b.Bytes
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var mgmtTD = spiffeid.RequireTrustDomainFromString(MgmtTrustDomain)

const mgmtURI = "spiffe://mgmt.poc.internal"

func TestLoadClientRootsAccepts(t *testing.T) {
	one := rootPEM(t, rootOpts{uris: []string{mgmtURI}})
	two := rootPEM(t, rootOpts{uris: []string{mgmtURI}})
	r, err := LoadClientRoots(writeTemp(t, append(append([]byte{}, one...), two...)), mgmtTD, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	for _, p := range [][]byte{one, two} {
		b, _ := pem.Decode(p)
		h.Write(b.Bytes)
	}
	if got, want := r.SHA256(), hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("SHA256 = %s, want the hash of the DER bytes of both roots, %s", got, want)
	}
	b, err := r.GetX509BundleForTrustDomain(mgmtTD)
	if err != nil || len(b.X509Authorities()) != 2 {
		t.Errorf("bundle = %v, %v", b, err)
	}
	if _, err := r.GetX509BundleForTrustDomain(spiffeid.RequireTrustDomainFromString("dev.env.poc.internal")); err == nil {
		t.Error("want an error for another trust domain")
	}
}

func TestLoadClientRootsRefuses(t *testing.T) {
	good := rootPEM(t, rootOpts{uris: []string{mgmtURI}})
	cases := map[string][]byte{
		"no URI SAN":      rootPEM(t, rootOpts{}),
		"other domain":    rootPEM(t, rootOpts{uris: []string{"spiffe://dev.env.poc.internal"}}),
		"workload URI":    rootPEM(t, rootOpts{uris: []string{"spiffe://mgmt.poc.internal/api"}}),
		"two URIs":        rootPEM(t, rootOpts{uris: []string{mgmtURI, "spiffe://dev.env.poc.internal"}}),
		"not a CA":        rootPEM(t, rootOpts{uris: []string{mgmtURI}, notCA: true}),
		"no cert sign":    rootPEM(t, rootOpts{uris: []string{mgmtURI}, noCertSig: true}),
		"expired":         rootPEM(t, rootOpts{uris: []string{mgmtURI}, expired: true}),
		"good then bad":   append(append([]byte{}, good...), rootPEM(t, rootOpts{})...),
		"trailing text":   append(append([]byte{}, good...), []byte("junk\n")...),
		"leading text":    append([]byte("junk\n"), good...),
		"wrong block":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
		"not a cert":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
		"block headers":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"a": "b"}, Bytes: pemBytes(good)}),
		"empty":           nil,
		"whitespace only": []byte("\n\n"),
	}
	for name, data := range cases {
		if _, err := LoadClientRoots(writeTemp(t, data), mgmtTD, time.Now()); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := LoadClientRoots(filepath.Join(t.TempDir(), "none"), mgmtTD, time.Now()); err == nil {
		t.Error("missing file: want an error")
	}
}

// The roots are read once: a later change of the file changes nothing.
func TestLoadClientRootsReadsOnce(t *testing.T) {
	p := writeTemp(t, rootPEM(t, rootOpts{uris: []string{mgmtURI}}))
	r, err := LoadClientRoots(p, mgmtTD, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	before := r.SHA256()
	if err := os.WriteFile(p, rootPEM(t, rootOpts{uris: []string{mgmtURI}}), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := r.GetX509BundleForTrustDomain(mgmtTD)
	if r.SHA256() != before || len(b.X509Authorities()) != 1 {
		t.Error("the roots changed after the file changed")
	}
	h := sha256.New()
	h.Write(b.X509Authorities()[0].Raw)
	if hex.EncodeToString(h.Sum(nil)) != before {
		t.Error("SHA256 is not the hash of the roots that the server uses")
	}
}
