package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

func TestRunPrintsVerifiableConfigMap(t *testing.T) {
	facts := func(string) (hostsvc.Facts, error) {
		return hostsvc.Facts{Name: "dev-cell-1", Issuer: "https://10.0.0.1:6443", JWKS: json.RawMessage(`{"keys":[{"kty":"RSA"}]}`)}, nil
	}
	var out bytes.Buffer
	if err := run([]string{"--cluster", "dev-cell-1", "--subject", "celld/celld"}, &out, facts); err != nil {
		t.Fatal(err)
	}
	var recLine, pubLine string
	for _, l := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(l, "  record.dsse.json: "); ok {
			recLine = v
		}
		if v, ok := strings.CutPrefix(l, "  signer.pub: "); ok {
			pubLine = v
		}
	}
	var env, pubB64 string
	if err := json.Unmarshal([]byte(recLine), &env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(pubLine), &pubB64); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	c, err := record.Verify([]byte(env), []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "dev-cell-1" || c.Env != "dev" || len(c.Subjects) != 1 {
		t.Fatalf("unexpected cell %+v", c)
	}
}

func TestRunRejectsBadSubject(t *testing.T) {
	err := run([]string{"--cluster", "x", "--subject", "nope"}, &bytes.Buffer{}, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
}
