package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func runOK(t *testing.T, args []string, stdin string) string {
	t.Helper()
	var out bytes.Buffer
	if code := execute(args, strings.NewReader(stdin), &out, func() time.Time { return testNow }); code != 0 {
		t.Fatalf("pkigen %v: exit %d: %s", args, code, out.String())
	}
	return out.String()
}

// runFail returns the error message of the one JSON line that a failed run prints.
func runFail(t *testing.T, args []string, stdin string) string {
	t.Helper()
	var out bytes.Buffer
	if code := execute(args, strings.NewReader(stdin), &out, func() time.Time { return testNow }); code == 0 {
		t.Fatalf("pkigen %v: expected a failure, got: %s", args, out.String())
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one output line, got %d: %q", len(lines), out.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("error line is not JSON: %v: %q", err, lines[0])
	}
	if rec["level"] != "ERROR" {
		t.Fatalf("error line has level %v", rec["level"])
	}
	msg, _ := rec["error"].(string)
	return msg
}

// parseBundle checks the block order (key, then certificate) and returns both.
func parseBundle(t *testing.T, s string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	rest := []byte(s)
	var blocks []*pem.Block
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	if strings.TrimSpace(string(rest)) != "" {
		t.Fatalf("trailing data after the PEM blocks: %q", rest)
	}
	if len(blocks) != 2 || blocks[0].Type != "EC PRIVATE KEY" || blocks[1].Type != "CERTIFICATE" {
		t.Fatalf("expected EC PRIVATE KEY then CERTIFICATE, got %d blocks", len(blocks))
	}
	key, err := x509.ParseECPrivateKey(blocks[0].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(blocks[1].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func certOnly(t *testing.T, s string) string {
	t.Helper()
	_, c := parseBundle(t, s)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func checkCA(t *testing.T, c *x509.Certificate, trustDomain string, days int) {
	t.Helper()
	if !c.BasicConstraintsValid || !c.IsCA {
		t.Fatal("certificate is not a CA")
	}
	if c.MaxPathLen != -1 || c.MaxPathLenZero {
		t.Fatalf("certificate has a path length limit: MaxPathLen=%d MaxPathLenZero=%v", c.MaxPathLen, c.MaxPathLenZero)
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("key usage is %v, want certSign|cRLSign", c.KeyUsage)
	}
	if len(c.ExtKeyUsage) != 0 {
		t.Fatalf("CA has extended key usages %v", c.ExtKeyUsage)
	}
	if len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://"+trustDomain {
		t.Fatalf("URI SANs are %v, want spiffe://%s", c.URIs, trustDomain)
	}
	if len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses) != 0 {
		t.Fatal("certificate has SANs other than the SPIFFE URI")
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("public key is %T, want ECDSA P-256", c.PublicKey)
	}
	if c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("signature algorithm is %v", c.SignatureAlgorithm)
	}
	if !c.NotBefore.Equal(testNow) {
		t.Fatalf("NotBefore is %v, want %v", c.NotBefore, testNow)
	}
	if want := testNow.Add(time.Duration(days) * 24 * time.Hour); !c.NotAfter.Equal(want) {
		t.Fatalf("NotAfter is %v, want %v", c.NotAfter, want)
	}
	if len(c.SubjectKeyId) == 0 {
		t.Fatal("certificate has no subject key ID")
	}
}

func TestRootIsSelfSignedCA(t *testing.T) {
	key, cert := parseBundle(t, runOK(t, []string{"root"}, ""))
	checkCA(t, cert, "dev.env.poc.internal", 365)
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("root is not self-signed: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("root key does not match the certificate")
	}
}

func TestIntermediateChainVerifies(t *testing.T) {
	root := runOK(t, []string{"root"}, "")
	_, rootCert := parseBundle(t, root)
	interKey, inter := parseBundle(t, runOK(t, []string{"intermediate", "--days", "30"}, root))
	checkCA(t, inter, "dev.env.poc.internal", 30)
	if !interKey.PublicKey.Equal(inter.PublicKey) {
		t.Fatal("intermediate key does not match the certificate")
	}
	if !bytes.Equal(inter.AuthorityKeyId, rootCert.SubjectKeyId) {
		t.Fatal("intermediate authority key ID does not name the root")
	}
	if bytes.Equal(inter.RawSubject, rootCert.RawSubject) {
		t.Fatal("intermediate and root have the same subject")
	}

	// A CA below the intermediate stands in for SPIRE's own CA, and a leaf sits below that.
	// This only verifies when the intermediate has no path length limit.
	spireKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spireTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "spire ca"},
		NotBefore: testNow, NotAfter: testNow.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	spireDER, err := x509.CreateCertificate(rand.Reader, spireTmpl, inter, &spireKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	spireCA, _ := x509.ParseCertificate(spireDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), NotBefore: testNow, NotAfter: testNow.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: inter.URIs,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, spireCA, &leafKey.PublicKey, spireKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	inters.AddCert(inter)
	inters.AddCert(spireCA)
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: testNow.Add(time.Minute), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("leaf below the intermediate does not verify: %v", err)
	}

	// The same check as SPIRE's disk UpstreamAuthority: the intermediate verifies against the root bundle.
	if _, err := inter.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("intermediate does not verify against the root with default key usages: %v", err)
	}
}

func TestTrustDomainFlag(t *testing.T) {
	root := runOK(t, []string{"root", "--trust-domain", "mgmt.poc.internal"}, "")
	_, rc := parseBundle(t, root)
	checkCA(t, rc, "mgmt.poc.internal", 365)
	_, ic := parseBundle(t, runOK(t, []string{"intermediate", "--trust-domain", "mgmt.poc.internal"}, root))
	checkCA(t, ic, "mgmt.poc.internal", 30)
}

func TestRootDaysFlag(t *testing.T) {
	_, c := parseBundle(t, runOK(t, []string{"root", "--days", "10"}, ""))
	checkCA(t, c, "dev.env.poc.internal", 10)
}

func TestCertPrintsOnlyTheCertificate(t *testing.T) {
	root := runOK(t, []string{"root"}, "")
	got := runOK(t, []string{"cert"}, root)
	if got != certOnly(t, root) {
		t.Fatalf("cert printed %q", got)
	}
	if strings.Contains(got, "PRIVATE KEY") {
		t.Fatal("cert printed a private key")
	}
}

func TestFailures(t *testing.T) {
	root := runOK(t, []string{"root", "--days", "20"}, "")
	otherKey, _ := parseBundle(t, runOK(t, []string{"root"}, ""))
	otherKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshal(t, otherKey)}))
	keyOnly := root[:strings.Index(root, "-----BEGIN CERTIFICATE-----")]
	rootKeyB64 := strings.Split(keyOnly, "\n")[1]

	cases := []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"no command", nil, "", "usage"},
		{"unknown command", []string{"leaf"}, "", "unknown command"},
		{"bad flag", []string{"root", "--nope"}, "", "flag"},
		{"extra argument", []string{"root", "extra"}, "", "unexpected argument"},
		{"zero days", []string{"root", "--days", "0"}, "", "--days"},
		{"bad trust domain", []string{"root", "--trust-domain", "Bad Domain"}, "", "trust domain"},
		{"trust domain with scheme", []string{"root", "--trust-domain", "spiffe://x"}, "", "trust domain"},
		{"empty stdin", []string{"intermediate"}, "", "no PEM"},
		{"garbage stdin", []string{"intermediate"}, "hello", "no PEM"},
		{"key only", []string{"intermediate"}, keyOnly, "CERTIFICATE"},
		{"cert only", []string{"intermediate"}, certOnly(t, root), "EC PRIVATE KEY"},
		{"wrong key", []string{"intermediate"}, otherKeyPEM + certOnly(t, root), "does not match"},
		{"outlives root", []string{"intermediate", "--days", "30"}, root, "outlive"},
		{"trailing data", []string{"intermediate"}, root + "junk", "trailing"},
		{"three blocks", []string{"intermediate"}, root + certOnly(t, root), "two PEM blocks"},
		{"cert from empty stdin", []string{"cert"}, "", "no PEM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := runFail(t, tc.args, tc.stdin)
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("error %q does not contain %q", msg, tc.want)
			}
			if strings.Contains(msg, rootKeyB64) || strings.Contains(msg, "PRIVATE KEY-----") {
				t.Fatal("error message carries key material")
			}
		})
	}
}

func TestIntermediateRejectsNonCARoot(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: testNow, NotAfter: testNow.Add(400 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	in := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshal(t, key)})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if msg := runFail(t, []string{"intermediate"}, in); !strings.Contains(msg, "not a CA") {
		t.Fatalf("error %q", msg)
	}
}

func mustMarshal(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
