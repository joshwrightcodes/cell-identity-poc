// Package spiffetest makes an in-memory certificate authority and X509-SVIDs for tests. It is not
// for production code.
package spiffetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// CA signs SVIDs for one trust domain.
type CA struct {
	td   spiffeid.TrustDomain
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA makes a self-signed P-256 authority for trustDomain.
func NewCA(t testing.TB, trustDomain string) *CA {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "test CA " + trustDomain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{td: td, cert: cert, key: key}
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// SVID issues an SVID for the SPIFFE ID id, valid for one hour.
func (ca *CA) SVID(t testing.TB, id string) *x509svid.SVID {
	t.Helper()
	return ca.SVIDWithTTL(t, id, time.Hour)
}

// SVIDWithTTL issues an SVID for the SPIFFE ID id whose leaf expires after ttl.
func (ca *CA) SVIDWithTTL(t testing.TB, id string, ttl time.Duration) *x509svid.SVID {
	t.Helper()
	sid, err := spiffeid.FromString(id)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(sid.String())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: sid, Certificates: []*x509.Certificate{leaf}, PrivateKey: key}
}

// Bundle returns the trust bundle of the authority.
func (ca *CA) Bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(ca.td, []*x509.Certificate{ca.cert})
}

type source struct{ svid *x509svid.SVID }

func (s source) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

// Source returns an x509svid.Source that always serves one SVID for id.
func (ca *CA) Source(t testing.TB, id string) x509svid.Source {
	t.Helper()
	return source{svid: ca.SVID(t, id)}
}
