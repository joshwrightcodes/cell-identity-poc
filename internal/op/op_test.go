package op

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

func keypair(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func valid() Operation {
	return Operation{
		ID: strings.Repeat("ab", 16), Env: "dev", Cell: "dev-cell-1", Kind: KindDemoAppend, Version: 1,
		KeyEpoch: 1, IssuedAt: t0, ExpiresAt: t0.Add(10 * time.Minute), Args: json.RawMessage(`{"line":"hello"}`),
	}
}

func TestOpRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	want := valid()
	env, err := Sign(want, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Env != want.Env || got.Cell != want.Cell || got.Kind != want.Kind ||
		got.Version != 1 || got.KeyEpoch != 1 || !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) ||
		string(got.Args) != `{"line":"hello"}` {
		t.Fatalf("got %+v", got)
	}
	signed, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, signed) {
		t.Fatalf("payload %s differs from the signed body %s", payload, signed)
	}
}

func TestOpWireNames(t *testing.T) {
	raw, err := json.Marshal(valid())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "env", "cell", "kind", "version", "keyEpoch", "issuedAt", "expiresAt", "args"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %s", k, raw)
		}
	}
	if len(m) != 9 {
		t.Errorf("got %s", raw)
	}
}

func TestOpVerifyRefusesOtherTypes(t *testing.T) {
	pub, priv := keypair(t)
	keys := []ed25519.PublicKey{pub}
	recEnv, err := record.Sign(record.Cell{Name: "c", Env: "dev", Issuer: "https://i", JWKS: json.RawMessage(`{"keys":[{"kty":"oct"}]}`)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	specEnv, err := record.SignEnvelope(spec.PayloadType, []byte(`{}`), priv)
	if err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string][]byte{"record": recEnv, "spec": specEnv} {
		if _, _, err := Verify(env, keys); !errors.Is(err, record.ErrPayloadType) {
			t.Errorf("%s envelope: %v", name, err)
		}
	}
	opEnv, err := Sign(valid(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Verify(opEnv, keys); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("record.Verify: %v", err)
	}
	if _, _, err := spec.Verify(opEnv, keys); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("spec.Verify: %v", err)
	}
}

func signRaw(t testing.TB, priv ed25519.PrivateKey, body string) []byte {
	t.Helper()
	env, err := record.SignEnvelope(PayloadType, []byte(body), priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestOpVerifyRules(t *testing.T) {
	pub, priv := keypair(t)
	keys := []ed25519.PublicKey{pub}
	mod := func(f func(*Operation)) []byte {
		o := valid()
		f(&o)
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		return signRaw(t, priv, string(b))
	}
	base, _ := json.Marshal(valid())
	for _, tc := range []struct {
		name string
		env  []byte
		bad  bool
	}{
		{"id_31_hex", mod(func(o *Operation) { o.ID = strings.Repeat("a", 31) }), true},
		{"id_upper", mod(func(o *Operation) { o.ID = strings.Repeat("AB", 16) }), true},
		{"version_2", mod(func(o *Operation) { o.Version = 2 }), true},
		{"key_epoch_0", mod(func(o *Operation) { o.KeyEpoch = 0 }), true},
		{"cell_upper", mod(func(o *Operation) { o.Cell = "Dev-Cell" }), true},
		{"cell_60_chars", mod(func(o *Operation) { o.Cell = strings.Repeat("a", 60) }), true},
		{"env_upper", mod(func(o *Operation) { o.Env = "DEV" }), true},
		{"expires_equal_issued", mod(func(o *Operation) { o.ExpiresAt = o.IssuedAt }), true},
		{"ttl_over_1h", mod(func(o *Operation) { o.ExpiresAt = o.IssuedAt.Add(time.Hour + time.Second) }), true},
		{"ttl_under_1s", mod(func(o *Operation) { o.ExpiresAt = o.IssuedAt.Add(500 * time.Millisecond) }), true},
		{"unknown_field", signRaw(t, priv, strings.TrimSuffix(string(base), "}")+`,"extra":1}`), true},
		{"trailing_data", signRaw(t, priv, string(base)+` {}`), true},
		{"ttl_1h", mod(func(o *Operation) { o.ExpiresAt = o.IssuedAt.Add(time.Hour) }), false},
		{"cell_59_chars", mod(func(o *Operation) { o.Cell = strings.Repeat("a", 59) }), false},
		{"ttl_1s", mod(func(o *Operation) { o.ExpiresAt = o.IssuedAt.Add(time.Second) }), false},
		{"kind_not_checked", mod(func(o *Operation) { o.Kind = "something.else" }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Verify(tc.env, keys)
			if tc.bad && !errors.Is(err, record.ErrDecode) {
				t.Fatalf("got %v, want ErrDecode", err)
			}
			if !tc.bad && err != nil {
				t.Fatalf("got %v, want success", err)
			}
		})
	}
}

func TestOpVerifyErrors(t *testing.T) {
	pub, priv := keypair(t)
	otherPub, _ := keypair(t)
	env, err := Sign(valid(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(env, []ed25519.PublicKey{otherPub}); !errors.Is(err, record.ErrSignature) {
		t.Errorf("foreign key: %v", err)
	}
	if _, _, err := Verify(env, nil); !errors.Is(err, record.ErrSignature) {
		t.Errorf("no keys: %v", err)
	}
	noSig := []byte(`{"payloadType":"` + PayloadType + `","payload":"e30=","signatures":[]}`)
	if _, _, err := Verify(noSig, []ed25519.PublicKey{pub}); !errors.Is(err, record.ErrSignature) {
		t.Errorf("no signatures: %v", err)
	}
	var e struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(e.Payload)
	body[len(body)-3] ^= 1
	e.Payload = base64.StdEncoding.EncodeToString(body)
	tampered, _ := json.Marshal(e)
	if _, _, err := Verify(tampered, []ed25519.PublicKey{pub}); !errors.Is(err, record.ErrSignature) {
		t.Errorf("tampered byte: %v", err)
	}
	if _, _, err := Verify([]byte(`not json`), []ed25519.PublicKey{pub}); !errors.Is(err, record.ErrDecode) {
		t.Errorf("garbage: %v", err)
	}
}

func TestOpPeek(t *testing.T) {
	_, priv := keypair(t)
	o := valid()
	o.KeyEpoch = 7
	env, err := Sign(o, priv)
	if err != nil {
		t.Fatal(err)
	}
	var e map[string]any
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	sigs := e["signatures"].([]any)
	sigs[0].(map[string]any)["sig"] = "AAAA"
	tampered, _ := json.Marshal(e)
	id, cell, epoch, err := Peek(tampered)
	if err != nil || id != o.ID || cell != o.Cell || epoch != 7 {
		t.Fatalf("got %q %q %d %v", id, cell, epoch, err)
	}
	if _, _, _, err := Peek([]byte(`{`)); !errors.Is(err, record.ErrDecode) {
		t.Errorf("garbage: %v", err)
	}
	other, _ := record.SignEnvelope(spec.PayloadType, []byte(`{}`), priv)
	if _, _, _, err := Peek(other); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("other type: %v", err)
	}
	bad := valid()
	bad.ID = "not-an-id\n"
	badEnv, _ := Sign(bad, priv)
	if _, _, _, err := Peek(badEnv); !errors.Is(err, record.ErrDecode) {
		t.Errorf("hostile id: %v", err)
	}
}

func TestEnvelopeSHA256AndNewID(t *testing.T) {
	if got := EnvelopeSHA256([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("got %s", got)
	}
	a, b := NewID(), NewID()
	if a == b || len(a) != 32 || !idRE.MatchString(a) {
		t.Fatalf("ids %q %q", a, b)
	}
}

func TestDemoAppendArgs(t *testing.T) {
	line := func(s string) json.RawMessage {
		b, _ := json.Marshal(map[string]string{"line": s})
		return b
	}
	for name, tc := range map[string]struct {
		args json.RawMessage
		ok   bool
	}{
		"200":       {line(strings.Repeat("a", 200)), true},
		"printable": {line(" ~!"), true},
		"201":       {line(strings.Repeat("a", 201)), false},
		"empty":     {line(""), false},
		"newline":   {line("a\nb"), false},
		"non_ascii": {line("café"), false},
		"del":       {line("a\x7f"), false},
		"unknown":   {json.RawMessage(`{"line":"a","x":1}`), false},
		"missing":   {json.RawMessage(`{}`), false},
		"null":      {json.RawMessage(`null`), false},
		"none":      {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseDemoAppend(tc.args)
			if tc.ok != (err == nil) {
				t.Fatalf("got %v", err)
			}
			if tc.ok && got.Line == "" {
				t.Fatal("empty line on success")
			}
		})
	}
}

func TestIsFinal(t *testing.T) {
	for _, o := range []string{OutcomeApplied, OutcomeAlreadyApplied, OutcomeExpired, OutcomeRefused} {
		if !IsFinal(o) {
			t.Errorf("%q should be final", o)
		}
	}
	for _, o := range []string{OutcomeLeaseLost, OutcomeStoreFull, "", "abandoned", "unknown"} {
		if IsFinal(o) {
			t.Errorf("%q should not be final", o)
		}
	}
}

func TestOutcomeAndReasonValues(t *testing.T) {
	for got, want := range map[string]string{
		OutcomeApplied: "applied", OutcomeAlreadyApplied: "already_applied", OutcomeExpired: "expired",
		OutcomeRefused: "refused", OutcomeLeaseLost: "lease_lost", OutcomeStoreFull: "store_full",
		ReasonSignatureInvalid: "signature_invalid", ReasonPayloadInvalid: "payload_invalid",
		ReasonWrongTarget: "wrong_target", ReasonEnvMismatch: "env_mismatch", ReasonKindUnknown: "kind_unknown",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if ReasonStoreFull != OutcomeStoreFull || ReasonLeaseLost != OutcomeLeaseLost {
		t.Error("the local reasons equal the local outcomes")
	}
}

func TestFenceCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b Fence
		want int
	}{
		{Fence{1, 5}, Fence{1, 5}, 0}, {Fence{1, 5}, Fence{1, 6}, -1}, {Fence{1, 6}, Fence{1, 5}, 1},
		{Fence{2, 0}, Fence{1, 99}, 1}, {Fence{1, 99}, Fence{2, 0}, -1},
	} {
		if got := tc.a.Compare(tc.b); got != tc.want {
			t.Errorf("%v vs %v: got %d", tc.a, tc.b, got)
		}
	}
}

func TestResultAndStatusWireNames(t *testing.T) {
	for _, tc := range []struct {
		v    any
		keys []string
	}{
		{Result{OpID: "a", PeekedID: "b", Cell: "c", Pod: "p", Outcome: "o", Reason: "r", Fence: Fence{1, 2}, At: t0, EnvelopeSHA256: "x"},
			[]string{"opId", "peekedId", "cell", "pod", "outcome", "reason", "fence", "at", "envelopeSHA256"}},
		{Status{Cell: "c", Pod: "p", PodUID: "u", Seq: 1, At: t0, SVIDExpiresAt: t0, OldestUnreportedAt: t0, Applied: 1, Refused: 2, ForgedSeen: 3, Unreported: 4, Records: 5, Version: "v"},
			[]string{"cell", "pod", "podUID", "seq", "at", "svidExpiresAt", "oldestUnreportedAt", "applied", "refused", "forgedSeen", "unreported", "records", "version"}},
	} {
		raw, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if len(m) != len(tc.keys) {
			t.Errorf("%T encodes %s", tc.v, raw)
		}
		for _, k := range tc.keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%T lacks %q in %s", tc.v, k, raw)
			}
		}
	}
}

func TestResultDetail(t *testing.T) {
	for _, d := range []string{
		"timeout:apps-sample:Synced/Progressing", "apps-sample:OutOfSync/Degraded", "rollback_unhealthy", "version_conflict",
		"istio-system/default-deny", "mesh_injection", "0", strings.Repeat("a", 96),
	} {
		if !ValidDetail(d) {
			t.Errorf("%q should be valid", d)
		}
		want := Result{Cell: "c", Outcome: OutcomeRolledBack, Reason: ReasonUnhealthy, Detail: d, At: t0}
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		var got Result
		if err := record.DecodeStrict(raw, &got); err != nil {
			t.Fatalf("%q: %v", d, err)
		}
		if got.Detail != d || got.Outcome != OutcomeRolledBack || got.Reason != "unhealthy" {
			t.Errorf("round trip of %q gave %+v", d, got)
		}
	}
	for _, d := range []string{"", "_x", ":x", "-x", ".x", "/x", "a b", "a\n", "a;b", "é", strings.Repeat("a", 97)} {
		if ValidDetail(d) {
			t.Errorf("%q should be invalid", d)
		}
	}
	raw, _ := json.Marshal(Result{Cell: "c", Outcome: OutcomeApplied, At: t0})
	if strings.Contains(string(raw), "detail") {
		t.Errorf("an empty detail is encoded: %s", raw)
	}
}

func TestIsFinalRolledBack(t *testing.T) {
	if !IsFinal(OutcomeRolledBack) || OutcomeRolledBack != "rolled_back" {
		t.Error("rolled_back must be final")
	}
	for got, want := range map[string]string{
		KindBundleApply: "bundle.apply", ReasonVersionOld: "version_old", ReasonComponentNotAllowed: "component_not_allowed",
		ReasonPolicyBlocksPlanes: "policy_blocks_planes", ReasonDigestMismatch: "digest_mismatch", ReasonUnhealthy: "unhealthy",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestMaxBundleArgsBytes(t *testing.T) {
	if MaxBundleArgsBytes != 24*1024 {
		t.Errorf("MaxBundleArgsBytes is %d", MaxBundleArgsBytes)
	}
}

func TestStatusNoBundleKey(t *testing.T) {
	raw, _ := json.Marshal(Status{Cell: "c", Pod: "p", At: t0})
	if strings.Contains(string(raw), "bundle") {
		t.Errorf("a status with no bundle has a bundle key: %s", raw)
	}
	raw, err := json.Marshal(Status{Cell: "c", Bundle: &BundleStatus{
		Version: bundle.Version{Epoch: 2, Counter: 3}, RootDigest: "sha256:ab", State: "healthy", AllowSHA256: "cd",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Bundle map[string]json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Bundle) != 4 || string(m.Bundle["version"]) != `{"epoch":2,"counter":3}` ||
		string(m.Bundle["rootDigest"]) != `"sha256:ab"` || string(m.Bundle["state"]) != `"healthy"` || string(m.Bundle["allowSHA256"]) != `"cd"` {
		t.Errorf("bundle status %s", raw)
	}
}
