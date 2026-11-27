package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

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

// trustChains gives the SVID chain under the trust domain of the SVID and the roots of the bundle file under the given trust domain.
func TestCelldTrustChains(t *testing.T) {
	root, rootKey := trustTestCert(t, "root", nil, nil)
	leaf, _ := trustTestCert(t, "leaf", root, rootKey)
	id := spiffeid.RequireFromString("spiffe://dev.env.poc.internal/cell/dev-cell-1/celld")
	file := trustTestFile(t, root)
	for _, tc := range []struct {
		name string
		svid bool
		file string
		want []string
	}{
		{"svid and file", true, file, []string{"dev.env.poc.internal/svid/2", "dev.env.poc.internal/bundle/1"}},
		{"no svid", false, file, []string{"dev.env.poc.internal/bundle/1"}},
		{"missing file", true, "", []string{"dev.env.poc.internal/svid/2"}},
		{"nothing", false, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tel, err := testTelemetry(discard())(t.Context(), io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			w, err := newSVIDWatcher(tel)
			if err != nil {
				t.Fatal(err)
			}
			if tc.svid {
				w.OnX509ContextUpdate(&workloadapi.X509Context{SVIDs: []*x509svid.SVID{{ID: id, Certificates: []*x509.Certificate{leaf, root}}}})
			}
			got := trustTestShape(trustChains(w, options{gatewayID: spiffeid.RequireFromString("spiffe://dev.env.poc.internal/cell/gateway"), trustBundle: tc.file}))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("chains %v, want %v", got, tc.want)
			}
		})
	}
}
