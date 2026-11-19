package mgmt

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSigstoreBundleShape(t *testing.T) {
	r, _ := boundRig(t)
	res := r.signBundle(cell1, cellComps(), false)
	key := fingerprint(r.plane.PublicKey())
	got, err := sigstoreBundle(res.Envelope, key)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 {
		t.Fatalf("members %v", m)
	}
	var media string
	_ = json.Unmarshal(m["mediaType"], &media)
	if media != "application/vnd.dev.sigstore.bundle.v0.3+json" {
		t.Fatalf("media type %q", media)
	}
	var vm struct {
		PublicKey struct {
			Hint string `json:"hint"`
		} `json:"publicKey"`
		TlogEntries json.RawMessage `json:"tlogEntries"`
	}
	if err := json.Unmarshal(m["verificationMaterial"], &vm); err != nil || vm.PublicKey.Hint != key || vm.TlogEntries != nil {
		t.Fatalf("verification material %s: %v", m["verificationMaterial"], err)
	}
	if bytes.Contains(got, []byte("tlogEntries")) {
		t.Fatal("the bundle has a tlog entry")
	}
	if !bytes.Equal(m["dsseEnvelope"], res.Envelope) {
		t.Fatalf("the envelope changed:\n%s\n%s", m["dsseEnvelope"], res.Envelope)
	}
	if !bytes.Equal(res.SigstoreBundle, got) {
		t.Fatal("the result carries another bundle")
	}
}

// The envelope sits in the bundle byte for byte, even with characters that a JSON encoder escapes.
func TestSigstoreBundleWrapsEnvelopeUnchanged(t *testing.T) {
	key := strings.Repeat("ab", 32)
	for _, env := range []string{
		`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"AAAA"}]}`,
		"{ \"payload\" : \"<&>\",\n \"payloadType\" : \"x\",\n \"signatures\" : [ ] }",
	} {
		got, err := sigstoreBundle([]byte(env), key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(got, []byte(`"dsseEnvelope":`+env+`}`)) {
			t.Fatalf("envelope changed in %s", got)
		}
	}
}

func TestSigstoreBundleRefusals(t *testing.T) {
	ok := `{"payloadType":"x","payload":"e30=","signatures":[]}`
	for name, c := range map[string]struct{ env, key string }{
		"not json":     {`{`, strings.Repeat("a", 64)},
		"array":        {`[]`, strings.Repeat("a", 64)},
		"empty":        {``, strings.Repeat("a", 64)},
		"short key":    {ok, "abc"},
		"upper key":    {ok, strings.Repeat("A", 64)},
		"quote in key": {ok, strings.Repeat("a", 63) + `"`},
	} {
		if _, err := sigstoreBundle([]byte(c.env), c.key); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
