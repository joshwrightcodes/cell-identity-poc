package hostsvc

import (
	"crypto/sha256"
	"crypto/tls"
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

const goodKeys = `{"name":"dev-cell-1","issuer":"https://dev-cell-1.issuer.poc.internal","jwks":{"keys":[]}}`

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
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case mgmtapi.KeysPath("html"):
			_, _ = w.Write([]byte("<html>"))
		case mgmtapi.KeysPath("extra"):
			_, _ = w.Write([]byte(`{"name":"extra","issuer":"i","jwks":{"keys":[]},"admin":true}`))
		case mgmtapi.KeysPath("nokeys"):
			_, _ = w.Write([]byte(`{"name":"nokeys","issuer":"i","jwks":{"other":1}}`))
		case mgmtapi.KeysPath("notset"):
			_, _ = w.Write([]byte(`{"name":"notset","issuer":"i","jwks":{"keys":"x"}}`))
		case mgmtapi.KeysPath("array"):
			_, _ = w.Write([]byte(`{"name":"array","issuer":"i","jwks":[1]}`))
		case mgmtapi.KeysPath("nojwks"):
			_, _ = w.Write([]byte(`{"name":"nojwks","issuer":"i"}`))
		}
	}))
	cfg.Timeout = 300 * time.Millisecond
	c, err := NewKeyClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"slow", "missing", "gateway", "redirect", "html", "extra", "nokeys", "notset", "array", "nojwks"} {
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
	big := `{"name":"dev-cell-1","issuer":"i","jwks":{"keys":[]},"pad":"` + strings.Repeat("a", maxKeysBody) + `"}`
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
	pad := strings.Repeat("a", maxKeysBody-len(`{"name":"dev-cell-1","issuer":"","jwks":{"keys":[]},"x":""}`))
	body := `{"name":"dev-cell-1","issuer":"` + pad + `","jwks":{"keys":[]}}`
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
	cfg, _ := pinnedServer(t, answer(`{"name":"dev-cell-2","issuer":"i","jwks":{"keys":[]}}`))
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
	if _, err := PinFromPEM([]byte("nope")); err == nil {
		t.Error("want an error for text that is not PEM")
	}
}
