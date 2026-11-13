package hostsvc

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

func wantKeyError(t *testing.T, err error, reason string) {
	t.Helper()
	var ke *mgmtapi.KeyError
	if !errors.As(err, &ke) {
		t.Fatalf("error = %v (%T), want *mgmtapi.KeyError", err, err)
	}
	if ke.Reason != reason {
		t.Errorf("reason = %q, want %q (%v)", ke.Reason, reason, err)
	}
}

// pinnedServer serves handler over TLS 1.3 with a self-signed certificate, and returns the client
// settings that pin it.
func pinnedServer(t *testing.T, handler http.Handler) (KeyClientConfig, *atomic.Int32) {
	t.Helper()
	cert, err := SelfSignedCert(KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return pinnedServerCert(t, handler, cert)
}

func pinnedServerCert(t *testing.T, handler http.Handler, cert tls.Certificate) (KeyClientConfig, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler.ServeHTTP(w, r)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	sum := sha256.Sum256(cert.Leaf.Raw)
	return KeyClientConfig{
		Addr: srv.Listener.Addr().String(), ServerName: KeyServerHost, Pin: sum[:],
		SVIDs: ca.Source(t, mgmtdID), Timeout: 2 * time.Second,
	}, &hits
}

func answer(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

func keysBody(name, issuer string, jwks json.RawMessage, extra string) string {
	return `{"name":"` + name + `","issuer":"` + issuer + `","jwks":` + string(jwks) + extra + `}`
}

var goodKeys = keysBody("dev-cell-1", "https://dev-cell-1.issuer.poc.internal", testJWKS(), "")

func TestKeyClientPinned(t *testing.T) {
	cfg, hits := pinnedServer(t, answer(goodKeys))
	t.Run("match", func(t *testing.T) {
		c, err := NewKeyClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := c.Keys(t.Context(), "dev-cell-1")
		if err != nil {
			t.Fatal(err)
		}
		if keys.Issuer != "https://dev-cell-1.issuer.poc.internal" {
			t.Errorf("keys = %+v", keys)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		before := hits.Load()
		bad := cfg
		bad.Pin = make([]byte, sha256.Size)
		c, err := NewKeyClient(bad)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Keys(t.Context(), "dev-cell-1")
		wantKeyError(t, err, mgmtapi.ReasonIssuerUntrusted)
		if got := hits.Load(); got != before {
			t.Errorf("the server saw %d requests after a pin mismatch, want 0", got-before)
		}
	})
}

func TestKeyClientUnavailable(t *testing.T) {
	cfg, _ := pinnedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case mgmtapi.KeysPath("slow"):
			time.Sleep(time.Second)
		case mgmtapi.KeysPath("missing"):
			http.Error(w, "no", http.StatusNotFound)
		case mgmtapi.KeysPath("gateway"):
			http.Error(w, "no", http.StatusBadGateway)
		case mgmtapi.KeysPath("redirect"):
			http.Redirect(w, r, mgmtapi.KeysPath("dev-cell-1"), http.StatusFound)
		case mgmtapi.KeysPath("dev-cell-1"):
			_, _ = w.Write([]byte(goodKeys))
		case mgmtapi.KeysPath("html"):
			_, _ = w.Write([]byte("<html>"))
		case mgmtapi.KeysPath("extra"):
			_, _ = w.Write([]byte(keysBody("extra", "i", testJWKS(), `,"admin":true`)))
		case mgmtapi.KeysPath("nokeys"):
			_, _ = w.Write([]byte(`{"name":"nokeys","issuer":"i","jwks":{"other":1}}`))
		case mgmtapi.KeysPath("notset"):
			_, _ = w.Write([]byte(`{"name":"notset","issuer":"i","jwks":{"keys":"x"}}`))
		case mgmtapi.KeysPath("array"):
			_, _ = w.Write([]byte(`{"name":"array","issuer":"i","jwks":[1]}`))
		case mgmtapi.KeysPath("emptykeys"):
			_, _ = w.Write([]byte(keysBody("emptykeys", "i", json.RawMessage(`{"keys":[]}`), "")))
		case mgmtapi.KeysPath("nullkeys"):
			_, _ = w.Write([]byte(keysBody("nullkeys", "i", json.RawMessage(`{"keys":null}`), "")))
		case mgmtapi.KeysPath("noissuer"):
			_, _ = w.Write([]byte(keysBody("noissuer", "", testJWKS(), "")))
		case mgmtapi.KeysPath("octkey"):
			_, _ = w.Write([]byte(keysBody("octkey", "i", json.RawMessage(`{"keys":[{"kty":"oct","kid":"k","k":"c2VjcmV0"}]}`), "")))
		case mgmtapi.KeysPath("privatekey"):
			_, _ = w.Write([]byte(keysBody("privatekey", "i", privateJWKS(), "")))
		case mgmtapi.KeysPath("encuse"):
			_, _ = w.Write([]byte(keysBody("encuse", "i", useJWKS("enc"), "")))
		case mgmtapi.KeysPath("nojwks"):
			_, _ = w.Write([]byte(`{"name":"nojwks","issuer":"i"}`))
		}
	}))
	cfg.Timeout = 300 * time.Millisecond
	c, err := NewKeyClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"slow", "missing", "gateway", "redirect", "html", "extra", "nokeys", "notset", "array", "nojwks", "emptykeys", "nullkeys", "noissuer", "octkey", "privatekey", "encuse"} {
		t.Run(name, func(t *testing.T) {
			_, err := c.Keys(t.Context(), name)
			wantKeyError(t, err, mgmtapi.ReasonIssuerUnavailable)
		})
	}
	t.Run("dial", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		dead := cfg
		dead.Addr = addr
		c, err := NewKeyClient(dead)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Keys(t.Context(), "dev-cell-1")
		wantKeyError(t, err, mgmtapi.ReasonIssuerUnavailable)
	})
}

func TestKeyClientBodyLimit(t *testing.T) {
	big := keysBody("dev-cell-1", "i", testJWKS(), `,"pad":"`+strings.Repeat("a", maxKeysBody)+`"`)
	cfg, _ := pinnedServer(t, answer(big))
	c, err := NewKeyClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Keys(t.Context(), "dev-cell-1")
	wantKeyError(t, err, mgmtapi.ReasonIssuerUnavailable)
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error = %v, want the size limit", err)
	}
}

func TestKeyClientBodyJustUnderLimit(t *testing.T) {
	jwks := testJWKS()
	pad := strings.Repeat("a", maxKeysBody-len(keysBody("dev-cell-1", "", jwks, "")))
	body := keysBody("dev-cell-1", pad, jwks, "")
	if len(body) > maxKeysBody {
		t.Fatalf("test body is %d bytes", len(body))
	}
	cfg, _ := pinnedServer(t, answer(body))
	c, _ := NewKeyClient(cfg)
	if _, err := c.Keys(t.Context(), "dev-cell-1"); err != nil {
		t.Errorf("body of %d bytes: %v", len(body), err)
	}
}

func TestKeyClientNameMismatch(t *testing.T) {
	cfg, _ := pinnedServer(t, answer(keysBody("dev-cell-2", "i", testJWKS(), "")))
	c, err := NewKeyClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Keys(t.Context(), "dev-cell-1")
	wantKeyError(t, err, mgmtapi.ReasonIssuerUntrusted)
}

func TestKeyClientRefusesTLS12Server(t *testing.T) {
	cert, err := SelfSignedCert(KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(answer(goodKeys))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	sum := sha256.Sum256(cert.Leaf.Raw)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	c, _ := NewKeyClient(KeyClientConfig{Addr: srv.Listener.Addr().String(), ServerName: KeyServerHost, Pin: sum[:], SVIDs: ca.Source(t, mgmtdID)})
	_, err = c.Keys(t.Context(), "dev-cell-1")
	wantKeyError(t, err, mgmtapi.ReasonIssuerUnavailable)
}

func TestKeyClientAgainstKeyServer(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	l := &lookups{}
	addr, cert := keyServer(t, ca.Bundle(), l)
	sum := sha256.Sum256(cert.Leaf.Raw)
	cfg := KeyClientConfig{Addr: addr, ServerName: KeyServerHost, Pin: sum[:], SVIDs: ca.Source(t, mgmtdID)}
	c, err := NewKeyClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := c.Keys(t.Context(), "dev-cell-1")
	if err != nil {
		t.Fatal(err)
	}
	if keys.Name != "dev-cell-1" {
		t.Errorf("keys = %+v", keys)
	}
	_, err = c.Keys(t.Context(), "rogue")
	wantKeyError(t, err, mgmtapi.ReasonIssuerUnavailable)
}

func TestNewKeyClientChecksConfig(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	good := KeyClientConfig{Addr: "127.0.0.1:1", ServerName: "x", Pin: make([]byte, 32), SVIDs: ca.Source(t, mgmtdID)}
	if _, err := NewKeyClient(good); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*KeyClientConfig){
		"addr":  func(c *KeyClientConfig) { c.Addr = "" },
		"name":  func(c *KeyClientConfig) { c.ServerName = "" },
		"pin":   func(c *KeyClientConfig) { c.Pin = c.Pin[:31] },
		"svids": func(c *KeyClientConfig) { c.SVIDs = nil },
	} {
		c := good
		mod(&c)
		if _, err := NewKeyClient(c); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestPinFromPEM(t *testing.T) {
	cert, _ := SelfSignedCert("x", time.Now())
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Leaf.Raw})
	got, err := PinFromPEM(p)
	want := sha256.Sum256(cert.Leaf.Raw)
	if err != nil || string(got) != string(want[:]) {
		t.Errorf("pin = %x, %v", got, err)
	}
	for name, bad := range map[string][]byte{
		"text":          []byte("nope"),
		"empty":         nil,
		"wrong type":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cert.Leaf.Raw}),
		"not a cert":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"two blocks":    append(append([]byte{}, p...), p...),
		"trailing text": append(append([]byte{}, p...), []byte("extra")...),
		"block headers": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"a": "b"}, Bytes: cert.Leaf.Raw}),
	} {
		if _, err := PinFromPEM(bad); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestKeyClientRefusesExpiredPinnedLeaf(t *testing.T) {
	cert, err := SelfSignedCert(KeyServerHost, time.Now().Add(-100*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cfg, hits := pinnedServerCert(t, answer(goodKeys), cert)
	c, _ := NewKeyClient(cfg)
	_, err = c.Keys(t.Context(), "dev-cell-1")
	wantKeyError(t, err, mgmtapi.ReasonIssuerUnavailable)
	if hits.Load() != 0 {
		t.Errorf("the server saw %d requests, want 0", hits.Load())
	}
}

func newNoCertTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}
}

func newMgmtClient(t *testing.T, ca *spiffetest.CA) *http.Client {
	t.Helper()
	cert := tlsCertOf(t, ca, mgmtdID)
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
	}}
}
