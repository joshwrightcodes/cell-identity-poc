package record

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testCell() Cell {
	return Cell{
		Name:     "dev-cell-1",
		Env:      "dev",
		Issuer:   "https://10.0.0.1:6443",
		JWKS:     json.RawMessage(`{"keys":[{"kty":"RSA"}]}`),
		Subjects: []Subject{{Namespace: "celld", ServiceAccount: "celld"}},
		Epoch:    1,
		Counter:  7,
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	env, err := Sign(testCell(), priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "dev-cell-1" || got.Counter != 7 || got.Epoch != 1 || got.Revoked ||
		len(got.Subjects) != 1 || got.Subjects[0].Namespace != "celld" {
		t.Fatalf("unexpected cell %+v", got)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := testKey(t)
	other, _ := testKey(t)
	env, _ := Sign(testCell(), priv)
	if _, err := Verify(env, []ed25519.PublicKey{other}); err == nil {
		t.Fatal("expected an error for a wrong key")
	}
	if _, err := Verify(env, nil); err == nil {
		t.Fatal("expected an error for no keys")
	}
}

func mutate(t *testing.T, env []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	pub, priv := testKey(t)
	env, _ := Sign(testCell(), priv)
	c := testCell()
	c.Revoked = false
	c.Counter = 8
	body, _ := json.Marshal(c)
	bad := mutate(t, env, func(m map[string]any) {
		m["payload"] = base64.StdEncoding.EncodeToString(body)
	})
	if _, err := Verify(bad, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected an error for a tampered payload")
	}
}

func TestVerifyRejectsWrongPayloadType(t *testing.T) {
	pub, priv := testKey(t)
	env, _ := Sign(testCell(), priv)
	bad := mutate(t, env, func(m map[string]any) { m["payloadType"] = "text/plain" })
	_, err := Verify(bad, []ed25519.PublicKey{pub})
	if err == nil || !strings.Contains(err.Error(), "payload type") {
		t.Fatalf("expected a payload type error, got %v", err)
	}
}

func TestVerifyRejectsNoSignatures(t *testing.T) {
	pub, priv := testKey(t)
	env, _ := Sign(testCell(), priv)
	bad := mutate(t, env, func(m map[string]any) { m["signatures"] = []any{} })
	if _, err := Verify(bad, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected an error for no signatures")
	}
}

func TestVerifyRejectsUnknownFields(t *testing.T) {
	pub, priv := testKey(t)
	body := []byte(`{"name":"dev-cell-1","bogus":true}`)
	env, err := signPayload(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(env, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}

func TestPAEMatchesSpecVector(t *testing.T) {
	got := string(pae("http://example.com/HelloWorld", []byte("hello world")))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestVerifyRejectsIncompleteRecords(t *testing.T) {
	pub, priv := testKey(t)
	cases := map[string]func(c *Cell){
		"empty name":   func(c *Cell) { c.Name = "" },
		"empty env":    func(c *Cell) { c.Env = "" },
		"empty issuer": func(c *Cell) { c.Issuer = "" },
		"empty keys":   func(c *Cell) { c.JWKS = json.RawMessage(`{"keys":[]}`) },
		"not a set":    func(c *Cell) { c.JWKS = json.RawMessage(`[1]`) },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			c := testCell()
			f(&c)
			env, err := Sign(c, priv)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(env, []ed25519.PublicKey{pub}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestVerifyRejectsInvalidJWKSJSON(t *testing.T) {
	pub, priv := testKey(t)
	body := []byte(`{"name":"a","env":"dev","issuer":"i","jwks":"notjson"}`)
	env, _ := signPayload(body, priv)
	if _, err := Verify(env, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestVerifyRejectsTrailingData(t *testing.T) {
	pub, priv := testKey(t)
	good, _ := json.Marshal(testCell())
	env, _ := signPayload(append(good, []byte(` {"x":1}`)...), priv)
	if _, err := Verify(env, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestVerifyMultiSignatureRule(t *testing.T) {
	pub, priv := testKey(t)
	env, _ := Sign(testCell(), priv)
	garbage := map[string]any{"sig": base64.StdEncoding.EncodeToString([]byte("garbage"))}
	withGarbage := func(m map[string]any) {
		m["signatures"] = append([]any{garbage}, m["signatures"].([]any)...)
	}
	if _, err := Verify(mutate(t, env, withGarbage), []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("one valid plus garbage must pass: %v", err)
	}
	onlyGarbage := func(m map[string]any) { m["signatures"] = []any{garbage, garbage} }
	if _, err := Verify(mutate(t, env, onlyGarbage), []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("only invalid signatures must fail")
	}
}
