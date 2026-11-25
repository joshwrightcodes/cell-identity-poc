package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"errors"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/trustmetrics"
)

func trustTestCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func trustTestFile(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	var data []byte
	for _, c := range certs {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func trustTestShape(chains []trustmetrics.Chain) []string {
	var out []string
	for _, c := range chains {
		out = append(out, fmt.Sprintf("%s/%s/%d", c.TrustDomain, c.Source, len(c.Certs)))
	}
	return out
}

type trustTestSource struct {
	svid  *x509svid.SVID
	roots []*x509.Certificate
}

func (s trustTestSource) GetX509SVID() (*x509svid.SVID, error) {
	if s.svid == nil {
		return nil, errors.New("no svid")
	}
	return s.svid, nil
}

func (s trustTestSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return x509bundle.FromX509Authorities(td, s.roots), nil
}

func TestTrustChains(t *testing.T) {
	root, rootKey := trustTestCert(t, "root", nil, nil)
	leaf, _ := trustTestCert(t, "leaf", root, rootKey)
	id := spiffeid.RequireFromString("spiffe://mgmt.poc.internal/mgmtd")
	file := trustTestFile(t, root)
	withSVID := &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{leaf}}
	for _, tc := range []struct {
		name string
		src  trustTestSource
		file string
		want []string
	}{
		{"svid, own bundle and file", trustTestSource{withSVID, []*x509.Certificate{root}}, file, []string{"mgmt.poc.internal/svid/1", "mgmt.poc.internal/bundle/1", "dev.env.poc.internal/bundle/1"}},
		{"no svid", trustTestSource{}, file, []string{"dev.env.poc.internal/bundle/1"}},
		{"missing file", trustTestSource{withSVID, []*x509.Certificate{root}}, "", []string{"mgmt.poc.internal/svid/1", "mgmt.poc.internal/bundle/1"}},
		{"nothing", trustTestSource{}, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := trustTestShape(trustChains(tc.src, serveConfig{peerTD: spiffeid.RequireTrustDomainFromString("dev.env.poc.internal"), peerBundle: tc.file}))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("chains %v, want %v", got, tc.want)
			}
		})
	}
}
