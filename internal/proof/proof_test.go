package proof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

func selfSigned(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proof-test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsPair makes one TLS 1.3 connection over a real TCP socket and returns both ends.
func tlsPair(t testing.TB, cert tls.Certificate, version uint16) (client, server *tls.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	type res struct {
		c   *tls.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			ch <- res{nil, err}
			return
		}
		s := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
		ch <- res{s, s.Handshake()}
	}()
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { c.Close(); r.c.Close() })
	return c, r.c
}

func TestBindingDiffersPerConnection(t *testing.T) {
	cert := selfSigned(t)
	c1, s1 := tlsPair(t, cert, tls.VersionTLS13)
	c2, s2 := tlsPair(t, cert, tls.VersionTLS13)
	bc1, err1 := Binding(c1.ConnectionState())
	bs1, err2 := Binding(s1.ConnectionState())
	bc2, err3 := Binding(c2.ConnectionState())
	bs2, err4 := Binding(s2.ConnectionState())
	for _, err := range []error{err1, err2, err3, err4} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if bc1 != bs1 || bc2 != bs2 {
		t.Fatalf("the two ends of a connection disagree: %q %q, %q %q", bc1, bs1, bc2, bs2)
	}
	if bc1 == bc2 {
		t.Fatalf("two connections gave one binding %q", bc1)
	}
	for _, b := range []string{bc1, bc2} {
		if len(b) != 22 || strings.ContainsAny(b, "=+/") {
			t.Fatalf("binding %q is not 22 base64url characters without padding", b)
		}
	}
}

func TestBindingRefusesWhatIsNotTLS13(t *testing.T) {
	c, _ := tlsPair(t, selfSigned(t), tls.VersionTLS12)
	if _, err := Binding(c.ConnectionState()); err == nil {
		t.Fatal("a TLS 1.2 connection gave a binding")
	}
	if _, err := Binding(tls.ConnectionState{}); err == nil {
		t.Fatal("an unfinished handshake gave a binding")
	}
}

func TestAudiences(t *testing.T) {
	body := []byte(`{"a":1}`)
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])
	if got, want := StreamAudience("dev-cell-1", "otel", "BIND"), "mgmt-stream/dev-cell-1/otel/BIND"; got != want {
		t.Errorf("stream %q", got)
	}
	if got, want := HelloAudience("dev-cell-1", "BIND"), "env-stream/dev-cell-1/BIND"; got != want {
		t.Errorf("hello %q", got)
	}
	base := ReportAudience("dev-cell-1", "result", body)
	if want := "mgmt-report/dev-cell-1/result/" + hexSum; base != want {
		t.Errorf("report %q, want %q", base, want)
	}
	if ReportAudience("dev-cell-1", "result", []byte(`{"a":2}`)) == base {
		t.Error("a changed body byte kept the audience")
	}
	if ReportAudience("dev-cell-1", "status", body) == base {
		t.Error("kind status kept the audience of kind result")
	}
	if ReportAudience("dev-cell-2", "result", body) == base {
		t.Error("another cell kept the audience")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, "token-a"); err != nil {
		t.Fatal(err)
	}
	if got := buf.Bytes()[:4]; !bytes.Equal(got, []byte{0, 0, 0, 7}) {
		t.Fatalf("length prefix %v", got)
	}
	got, err := ReadFrame(&buf)
	if err != nil || got != "token-a" {
		t.Fatalf("got %q %v", got, err)
	}
	if err := WriteFrame(&buf, strings.Repeat("x", MaxFrame+1)); err == nil {
		t.Fatal("WriteFrame wrote a frame above the limit")
	}
	if err := WriteFrame(&buf, strings.Repeat("x", MaxFrame)); err != nil {
		t.Fatalf("a frame at the limit: %v", err)
	}
}

func asProofError(t *testing.T, err error) *Error {
	t.Helper()
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("got %T %v, want *proof.Error", err, err)
	}
	return pe
}

func TestFrameLimits(t *testing.T) {
	t.Run("length_0_is_missing", func(t *testing.T) {
		_, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0}))
		if pe := asProofError(t, err); pe.Reason != ReasonMissing {
			t.Fatalf("got %+v", pe)
		}
	})
	t.Run("8193_is_too_large", func(t *testing.T) {
		_, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0x20, 0x01}))
		if pe := asProofError(t, err); pe.Reason != ReasonInvalid || pe.Detail != "too_large" {
			t.Fatalf("got %+v", pe)
		}
	})
	t.Run("8192_is_read", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, strings.Repeat("y", MaxFrame)); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadFrame(&buf); err != nil || len(got) != MaxFrame {
			t.Fatalf("got %d %v", len(got), err)
		}
	})
	t.Run("short_read", func(t *testing.T) {
		_, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 9, 'a', 'b'}))
		if err == nil || errors.As(err, new(*Error)) {
			t.Fatalf("got %v, want a plain read error", err)
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("short_header", func(t *testing.T) {
		if _, err := ReadFrame(bytes.NewReader([]byte{0, 0})); err == nil {
			t.Fatal("a short header read without error")
		}
	})
	t.Run("never_reads_ahead", func(t *testing.T) {
		var buf bytes.Buffer
		_ = WriteFrame(&buf, "abc")
		buf.WriteString("NEXT")
		r := &countReader{r: &buf}
		if got, err := ReadFrame(r); err != nil || got != "abc" {
			t.Fatalf("got %q %v", got, err)
		}
		if r.n != 4+3 {
			t.Fatalf("read %d bytes, want 7", r.n)
		}
		rest, _ := io.ReadAll(&buf)
		if string(rest) != "NEXT" {
			t.Fatalf("next bytes %q", rest)
		}
	})
}

type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestErrorTransient(t *testing.T) {
	for detail, want := range map[string]bool{
		"token_expired": true, "unknown_kid": true, "subject_mismatch": false, "wrong_audience": false, "": false,
	} {
		e := &Error{Reason: ReasonInvalid, Detail: detail}
		if e.Transient() != want {
			t.Errorf("detail %q: Transient %v", detail, !want)
		}
		if e.Error() == "" {
			t.Error("empty Error()")
		}
	}
}

func TestProofVerify(t *testing.T) {
	celld := record.Subject{Namespace: "cell-identity-system", ServiceAccount: "celld"}
	other := record.Subject{Namespace: "observability-system", ServiceAccount: "otel-uplink"}
	signer := kubetoken.NewSigner(t, "k1", jose.ES256)
	foreign := kubetoken.NewSigner(t, "k2", jose.ES256)
	rec := record.Cell{
		Name: "dev-cell-1", Env: "dev", Issuer: "https://cell-1", JWKS: signer.JWKS(),
		Subjects: []record.Subject{celld, other},
	}
	now := time.Now()
	const aud = "mgmt-report/dev-cell-1/result/abc"
	claims := func(s record.Subject, audience string) kubetoken.Claims {
		return kubetoken.Claims{
			Issuer: "https://cell-1", Namespace: s.Namespace, ServiceAccount: s.ServiceAccount,
			PodName: "celld-0", PodUID: "uid-1", NodeName: "n1", Audience: []string{audience},
		}
	}

	good := signer.Token(t, claims(celld, aud))
	got, err := Verify(rec, good, aud, celld, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.PodName != "celld-0" || got.PodUID != "uid-1" || got.Namespace != celld.Namespace {
		t.Fatalf("claims %+v", got)
	}

	sameNS := record.Subject{Namespace: celld.Namespace, ServiceAccount: "other-account"}
	rec.Subjects = append(rec.Subjects, sameNS)
	t.Run("audience_argument_differs", func(t *testing.T) {
		_, err := Verify(rec, good, "mgmt-report/dev-cell-1/result/other", celld, now)
		if pe := asProofError(t, err); pe.Detail != "wrong_audience" {
			t.Fatalf("got %+v", pe)
		}
	})
	for _, tc := range []struct {
		name      string
		token     string
		reason    string
		detail    string
		transient bool
	}{
		{"other_subject", signer.Token(t, claims(other, aud)), ReasonInvalid, "subject_mismatch", false},
		{"same_namespace_other_account", signer.Token(t, claims(sameNS, aud)), ReasonInvalid, "subject_mismatch", false},
		{"wrong_audience", signer.Token(t, claims(celld, "mgmt-report/dev-cell-1/result/zzz")), ReasonInvalid, "wrong_audience", false},
		{"foreign_key", foreign.Token(t, claims(celld, aud)), ReasonInvalid, "unknown_kid", true},
		{"expired", func() string {
			c := claims(celld, aud)
			c.IssuedAt, c.Lifetime = now.Add(-11*time.Minute), 10*time.Minute
			return signer.Token(t, c)
		}(), ReasonInvalid, "token_expired", true},
		{"empty", "", ReasonMissing, "", false},
		{"garbage", "not.a.token", ReasonInvalid, "malformed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(rec, tc.token, aud, celld, now)
			pe := asProofError(t, err)
			if pe.Reason != tc.reason || pe.Detail != tc.detail || pe.Transient() != tc.transient {
				t.Fatalf("got %+v transient %v", pe, pe.Transient())
			}
		})
	}
}
