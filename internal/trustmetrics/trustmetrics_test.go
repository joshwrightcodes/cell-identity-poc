package trustmetrics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// issue makes a certificate that parent signs. A nil parent makes a self-signed one.
func issue(t *testing.T, cn string, serial int64, life time.Duration, parent *authority) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: epoch, NotAfter: epoch.Add(life), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority{cert, key}
}

type series struct {
	trustDomain, ca, sha, source string
}

func collect(t *testing.T, read func() []Chain) map[series]int64 {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	if err := Register(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), read); err != nil {
		t.Fatal(err)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[series]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "trust.ca.not_after" {
				continue
			}
			if m.Unit != "s" {
				t.Fatalf("unit %q", m.Unit)
			}
			for _, dp := range m.Data.(metricdata.Gauge[int64]).DataPoints {
				v := func(k string) string { x, _ := dp.Attributes.Value(attribute.Key(k)); return x.AsString() }
				got[series{v("trust_domain"), v("ca"), v("sha256"), v("source")}] = dp.Value
			}
		}
	}
	return got
}

func digest(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])[:16]
}

func TestChainClasses(t *testing.T) {
	root := issue(t, "root", 1, 8*time.Hour, nil)
	inter := issue(t, "intermediate", 2, 4*time.Hour, &root)
	spire := issue(t, "spire", 3, 2*time.Hour, &inter)
	leaf := issue(t, "leaf", 4, time.Hour, &spire)
	const td = "dev.env.poc.internal"

	chains := []Chain{
		{td, SourceSVID, []*x509.Certificate{leaf.cert, spire.cert, inter.cert}},
		{"mgmt", SourceSVID, []*x509.Certificate{leaf.cert, spire.cert, inter.cert, root.cert}},
		{td, SourceBundle, []*x509.Certificate{root.cert, inter.cert}},
	}
	got := collect(t, func() []Chain { return chains })
	want := map[series]int64{
		{td, "issuing", digest(spire.cert), "svid"}:          spire.cert.NotAfter.Unix(),
		{td, "intermediate", digest(inter.cert), "svid"}:     inter.cert.NotAfter.Unix(),
		{"mgmt", "issuing", digest(spire.cert), "svid"}:      spire.cert.NotAfter.Unix(),
		{"mgmt", "intermediate", digest(inter.cert), "svid"}: inter.cert.NotAfter.Unix(),
		{"mgmt", "root", digest(root.cert), "svid"}:          root.cert.NotAfter.Unix(),
		{td, "root", digest(root.cert), "bundle"}:            root.cert.NotAfter.Unix(),
		{td, "root", digest(inter.cert), "bundle"}:           inter.cert.NotAfter.Unix(),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series %v, want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("series %+v = %d (present %v), want %d", k, g, ok, v)
		}
	}
	for k := range got {
		if k.sha == digest(leaf.cert) {
			t.Errorf("the leaf has a series: %+v", k)
		}
	}
}

func TestRootDigestSameAcrossSources(t *testing.T) {
	root := issue(t, "root", 1, 8*time.Hour, nil)
	chains := []Chain{
		{"td", SourceSVID, []*x509.Certificate{root.cert, root.cert}},
		{"td", SourceBundle, []*x509.Certificate{root.cert}},
	}
	got := collect(t, func() []Chain { return chains })
	roots := map[string]bool{}
	for k := range got {
		if k.ca == "root" {
			roots[k.source] = true
			if k.sha != digest(root.cert) {
				t.Errorf("source %s digest %s, want %s", k.source, k.sha, digest(root.cert))
			}
		}
	}
	if len(roots) != 2 || len(got) != 2 {
		t.Fatalf("want one root series for each of two sources, got %v", got)
	}
}

func TestNoSeriesWithoutChain(t *testing.T) {
	if got := collect(t, func() []Chain { return nil }); len(got) != 0 {
		t.Fatalf("series with no chain: %v", got)
	}
	root := issue(t, "root", 1, time.Hour, nil)
	leaf := issue(t, "leaf", 2, time.Hour, &root)
	only := []Chain{{"td", SourceSVID, []*x509.Certificate{leaf.cert}}}
	if got := collect(t, func() []Chain { return only }); len(got) != 0 {
		t.Fatalf("series for a lone leaf: %v", got)
	}
	dir := t.TempDir()
	if c := FileChain("td", SourceBundle, filepath.Join(dir, "missing.pem")); c != nil {
		t.Fatalf("chain from a missing file: %v", c)
	}
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := FileChain("td", SourceBundle, bad); c != nil {
		t.Fatalf("chain from a bad file: %v", c)
	}
	good := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw})
	corrupt := append(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})...)
	mixed := filepath.Join(dir, "mixed.pem")
	if err := os.WriteFile(mixed, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if c := FileChain("td", SourceBundle, mixed); c != nil {
		t.Fatalf("chain from a file with a corrupt certificate: %v", c)
	}
	if c := SVIDChain("td", nil); c != nil {
		t.Fatalf("chain from no certificates: %v", c)
	}
}

func TestFileChain(t *testing.T) {
	a := issue(t, "a", 1, time.Hour, nil)
	b := issue(t, "b", 2, 2*time.Hour, nil)
	var data []byte
	for _, c := range []*x509.Certificate{a.cert, b.cert} {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got := collect(t, func() []Chain { return FileChain("td", SourceBundle, path) })
	if len(got) != 2 || got[series{"td", "root", digest(a.cert), "bundle"}] != a.cert.NotAfter.Unix() ||
		got[series{"td", "root", digest(b.cert), "bundle"}] != b.cert.NotAfter.Unix() {
		t.Fatalf("series %v", got)
	}
}

type fakeSource struct {
	svid    *x509svid.SVID
	authors []*x509.Certificate
}

func (f fakeSource) GetX509SVID() (*x509svid.SVID, error) {
	if f.svid == nil {
		return nil, errors.New("no svid")
	}
	return f.svid, nil
}

func (f fakeSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return x509bundle.FromX509Authorities(td, f.authors), nil
}

func TestSourceChains(t *testing.T) {
	root := issue(t, "root", 1, time.Hour, nil)
	leaf := issue(t, "leaf", 2, time.Hour, &root)
	id := spiffeid.RequireFromString("spiffe://mgmt.poc.internal/mgmtd")
	svid := &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{leaf.cert}}
	got := collect(t, func() []Chain { return SourceChains(fakeSource{svid, []*x509.Certificate{root.cert}}) })
	want := map[series]int64{{"mgmt.poc.internal", "root", digest(root.cert), "bundle"}: root.cert.NotAfter.Unix()}
	if len(got) != 1 || got[series{"mgmt.poc.internal", "root", digest(root.cert), "bundle"}] != want[series{"mgmt.poc.internal", "root", digest(root.cert), "bundle"}] {
		t.Fatalf("series %v", got)
	}
	if c := SourceChains(fakeSource{}); c != nil {
		t.Fatalf("chain with no SVID: %v", c)
	}
	if c := SourceChains(nilSource{}); c != nil {
		t.Fatalf("chain from a nil SVID: %v", c)
	}
}

type nilSource struct{}

func (nilSource) GetX509SVID() (*x509svid.SVID, error) { return nil, nil }
