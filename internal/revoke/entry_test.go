package revoke

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

func testKey(t *testing.T, b byte) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func testEntry() Entry {
	return Entry{
		ID:       "0123456789abcdef",
		Env:      "dev",
		Cell:     "dev-cell-2",
		Record:   spec.Revision{Epoch: 1, Counter: 7},
		IssuedAt: time.Date(2026, 11, 20, 3, 4, 5, 0, time.UTC),
	}
}

func TestEntryRoundTrip(t *testing.T) {
	key := testKey(t, 1)
	e := testEntry()
	env, err := Sign(e, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(env) > MaxEntryBytes {
		t.Errorf("envelope of %d bytes", len(env))
	}
	var outer struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(env, &outer); err != nil {
		t.Fatal(err)
	}
	if outer.PayloadType != PayloadType || PayloadType != "application/vnd.poc.local-revocation+json" {
		t.Errorf("payload type %q", outer.PayloadType)
	}
	body, _ := base64.StdEncoding.DecodeString(outer.Payload)
	want := `{"id":"0123456789abcdef","env":"dev","cell":"dev-cell-2","record":{"epoch":1,"counter":7},"issuedAt":"2026-11-20T03:04:05Z"}`
	if string(body) != want {
		t.Errorf("payload %s, want %s", body, want)
	}
	other := testKey(t, 2)
	got, err := Verify(env, []ed25519.PublicKey{pub(other), pub(key)})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != e.ID || got.Env != e.Env || got.Cell != e.Cell || got.Record != e.Record || !got.IssuedAt.Equal(e.IssuedAt) {
		t.Errorf("got %+v, want %+v", got, e)
	}
	if _, err := Verify(env, []ed25519.PublicKey{pub(other)}); !errors.Is(err, record.ErrSignature) {
		t.Errorf("other key: %v", err)
	}
	if _, err := Verify(env, nil); !errors.Is(err, record.ErrSignature) {
		t.Errorf("no keys: %v", err)
	}
	if MaxEntryBytes != 4<<10 || MaxHeld != 16 {
		t.Errorf("limits %d %d", MaxEntryBytes, MaxHeld)
	}
}

// signBody signs a raw payload as an entry, so a test can make a payload that Sign refuses.
func signBody(t *testing.T, body string, key ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := record.SignEnvelope(PayloadType, []byte(body), key)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestEntryRules(t *testing.T) {
	key := testKey(t, 1)
	keys := []ed25519.PublicKey{pub(key)}
	good := testEntry()
	for _, tc := range []struct {
		name string
		edit func(*Entry)
		body string
		env  func(*testing.T) []byte
	}{
		{name: "id_15_hex", edit: func(e *Entry) { e.ID = "0123456789abcde" }},
		{name: "id_upper", edit: func(e *Entry) { e.ID = "0123456789ABCDEF" }},
		{name: "cell_upper", edit: func(e *Entry) { e.Cell = "Dev-cell-2" }},
		{name: "cell_empty", edit: func(e *Entry) { e.Cell = "" }},
		{name: "cell_too_long", edit: func(e *Entry) { e.Cell = strings.Repeat("a", 60) }},
		{name: "record_zero", edit: func(e *Entry) { e.Record = spec.Revision{} }},
		{name: "record_counter_zero", edit: func(e *Entry) { e.Record = spec.Revision{Epoch: 1} }},
		{name: "env_empty", edit: func(e *Entry) { e.Env = "" }},
		{name: "env_too_long", edit: func(e *Entry) { e.Env = strings.Repeat("a", 64) }},
		{name: "issued_zero", edit: func(e *Entry) { e.IssuedAt = time.Time{} }},
		{name: "unknown_field", body: `{"id":"0123456789abcdef","env":"dev","cell":"dev-cell-2","record":{"epoch":1,"counter":7},"issuedAt":"2026-11-20T03:04:05Z","revoked":false}`},
		{name: "duplicate_field", body: `{"id":"0123456789abcdef","env":"dev","cell":"dev-cell-2","cell":"dev-cell-1","record":{"epoch":1,"counter":7},"issuedAt":"2026-11-20T03:04:05Z"}`},
		{name: "case_folded_field", body: `{"ID":"0123456789abcdef","env":"dev","cell":"dev-cell-2","record":{"epoch":1,"counter":7},"issuedAt":"2026-11-20T03:04:05Z"}`},
		{name: "trailing_data", body: `{"id":"0123456789abcdef","env":"dev","cell":"dev-cell-2","record":{"epoch":1,"counter":7},"issuedAt":"2026-11-20T03:04:05Z"} {}`},
		{name: "not_json", body: `revoke dev-cell-2`},
		{name: "too_large", env: func(t *testing.T) []byte {
			env, err := Sign(good, key)
			if err != nil {
				t.Fatal(err)
			}
			return append(env, bytes.Repeat([]byte(" "), MaxEntryBytes)...)
		}},
		{name: "keyid", env: func(t *testing.T) []byte {
			return editEnvelope(t, mustSign(t, good, key), func(m map[string]any) {
				m["signatures"].([]any)[0].(map[string]any)["keyid"] = strings.Repeat("k", 2000)
			})
		}},
		{name: "keyid_empty", env: func(t *testing.T) []byte {
			return editEnvelope(t, mustSign(t, good, key), func(m map[string]any) {
				m["signatures"].([]any)[0].(map[string]any)["keyid"] = ""
			})
		}},
		{name: "two_signatures", env: func(t *testing.T) []byte {
			return editEnvelope(t, mustSign(t, good, key), func(m map[string]any) {
				sigs := m["signatures"].([]any)
				m["signatures"] = append(sigs, map[string]any{"sig": base64.StdEncoding.EncodeToString(make([]byte, 64))})
			})
		}},
		{name: "same_signature_twice", env: func(t *testing.T) []byte {
			return editEnvelope(t, mustSign(t, good, key), func(m map[string]any) {
				sigs := m["signatures"].([]any)
				m["signatures"] = append(sigs, sigs[0])
			})
		}},
		{name: "noncanonical_payload", env: func(t *testing.T) []byte {
			return editEnvelope(t, mustSign(t, good, key), func(m map[string]any) {
				p := m["payload"].(string)
				m["payload"] = p[:8] + "\n" + p[8:]
			})
		}},
		{name: "noncanonical_payload_cr", env: func(t *testing.T) []byte {
			return editEnvelope(t, mustSign(t, good, key), func(m map[string]any) {
				p := m["payload"].(string)
				m["payload"] = p + "\r\n"
			})
		}},
		{name: "noncanonical_sig", env: func(t *testing.T) []byte {
			return editEnvelope(t, mustSign(t, good, key), func(m map[string]any) {
				s := m["signatures"].([]any)[0].(map[string]any)
				s["sig"] = s["sig"].(string)[:8] + "\n" + s["sig"].(string)[8:]
			})
		}},
		{name: "extra_member", env: func(t *testing.T) []byte {
			return editEnvelope(t, mustSign(t, good, key), func(m map[string]any) { m["pad"] = strings.Repeat("p", 2000) })
		}},
		{name: "too_large_payload", body: `{"id":"0123456789abcdef","env":"dev","cell":"dev-cell-2","record":{"epoch":1,"counter":7},"issuedAt":"2026-11-20T03:04:05Z"` + strings.Repeat(" ", MaxEntryBytes) + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var env []byte
			switch {
			case tc.edit != nil:
				e := good
				tc.edit(&e)
				if _, err := Sign(e, key); err == nil {
					t.Error("Sign accepts the entry")
				}
				body, err := json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				env = signBody(t, string(body), key)
			case tc.env != nil:
				env = tc.env(t)
			default:
				env = signBody(t, tc.body, key)
			}
			if _, err := Verify(env, keys); !errors.Is(err, record.ErrDecode) {
				t.Errorf("Verify: %v, want ErrDecode", err)
			}
		})
	}
	if _, err := Verify(signBody(t, `{"id":"0123456789abcdef","env":"dev","cell":"dev-cell-2","record":{"epoch":1,"counter":7},"issuedAt":"2026-11-20T03:04:05Z"}`, key), keys); err != nil {
		t.Errorf("the base payload of the rows fails: %v", err)
	}
	long := good
	long.Env, long.Cell = strings.Repeat("e", 63), strings.Repeat("c", 59)
	if env, err := Sign(long, key); err != nil {
		t.Errorf("longest names: %v", err)
	} else if _, err := Verify(env, keys); err != nil {
		t.Errorf("longest names: %v", err)
	}
	if _, err := Sign(good, key[:10]); err == nil {
		t.Error("Sign accepts a short key")
	}
}

// TestEntryOtherPayloadTypes checks the domain separation: the same key signs entries, records,
// specs, operations, steps and bundle attestations, and no envelope verifies as another type.
func TestEntryOtherPayloadTypes(t *testing.T) {
	key := testKey(t, 1)
	keys := []ed25519.PublicKey{pub(key)}
	entry, err := Sign(testEntry(), key)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(entry, &outer); err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(outer.Payload)
	others := []string{record.PayloadType, spec.PayloadType, op.PayloadType, step.PayloadType, bundle.PayloadType}
	for _, pt := range others {
		t.Run("entry_body_as_"+pt, func(t *testing.T) {
			env, err := record.SignEnvelope(pt, body, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(env, keys); !errors.Is(err, record.ErrPayloadType) {
				t.Errorf("Verify: %v, want ErrPayloadType", err)
			}
			relabelled := relabel(t, env, PayloadType)
			if _, err := Verify(relabelled, keys); !errors.Is(err, record.ErrSignature) {
				t.Errorf("Verify after relabel: %v, want ErrSignature", err)
			}
		})
		t.Run("entry_as_"+pt, func(t *testing.T) {
			if _, err := record.VerifyEnvelope(entry, pt, keys); !errors.Is(err, record.ErrPayloadType) {
				t.Errorf("VerifyEnvelope: %v, want ErrPayloadType", err)
			}
			if _, err := record.VerifyEnvelope(relabel(t, entry, pt), pt, keys); !errors.Is(err, record.ErrSignature) {
				t.Errorf("VerifyEnvelope after relabel: %v, want ErrSignature", err)
			}
		})
	}
	if _, err := record.Verify(entry, keys); err == nil {
		t.Error("an entry verifies as a record")
	}
	if _, _, err := spec.Verify(entry, keys); err == nil {
		t.Error("an entry verifies as a spec")
	}
	if _, _, err := op.Verify(entry, keys); err == nil {
		t.Error("an entry verifies as an operation")
	}
	if _, _, err := step.Verify(entry, keys); err == nil {
		t.Error("an entry verifies as a step")
	}
	if _, _, err := bundle.ParseAttestation(entry, []crypto.PublicKey{pub(key)}); err == nil {
		t.Error("an entry parses as an attestation")
	}
	rec, err := record.Sign(record.Cell{Name: "dev-cell-2", Env: "dev", Issuer: "https://i", JWKS: json.RawMessage(`{"keys":[]}`), Epoch: 1, Counter: 7}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(rec, keys); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("a record: %v, want ErrPayloadType", err)
	}
}

// relabel returns env with its payloadType field set to pt and every other field kept.
func relabel(t *testing.T, env []byte, pt string) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	m["payloadType"], _ = json.Marshal(pt)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustSign(t *testing.T, e Entry, key ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := Sign(e, key)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// editEnvelope decodes env into generic JSON, lets edit change it, and encodes it again.
func editEnvelope(t *testing.T, env []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestVerifyCanonicalForm checks the forms that Verify accepts besides the bytes of Sign: other
// whitespace and other member order. It also checks the size limit before any parse, and an
// envelope with no signature.
func TestVerifyCanonicalForm(t *testing.T) {
	key := testKey(t, 1)
	keys := []ed25519.PublicKey{pub(key)}
	signed := mustSign(t, testEntry(), key)
	var indented bytes.Buffer
	if err := json.Indent(&indented, signed, " ", "\t"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(indented.Bytes(), keys); err != nil {
		t.Errorf("indented envelope: %v", err)
	}
	reordered := editEnvelope(t, signed, func(map[string]any) {})
	if _, err := Verify(reordered, keys); err != nil {
		t.Errorf("reordered envelope: %v", err)
	}
	none := editEnvelope(t, signed, func(m map[string]any) { m["signatures"] = []any{} })
	if _, err := Verify(none, keys); !errors.Is(err, record.ErrSignature) {
		t.Errorf("no signature: %v, want ErrSignature", err)
	}
	big := bytes.Repeat([]byte("x"), MaxEntryBytes+1)
	if _, err := Verify(big, keys); !errors.Is(err, ErrTooLarge) || !errors.Is(err, record.ErrDecode) {
		t.Errorf("oversized input: %v, want ErrTooLarge and ErrDecode", err)
	}
	if _, err := Verify(bytes.Repeat([]byte("x"), MaxEntryBytes), keys); errors.Is(err, ErrTooLarge) {
		t.Errorf("an input at the limit is too large: %v", err)
	}
}

// TestEntryLargestEnvelope bounds the largest envelope that Sign can write, so a reader can size a
// body that carries MaxHeld entries.
func TestEntryLargestEnvelope(t *testing.T) {
	e := testEntry()
	e.Env, e.Cell = strings.Repeat("e", 63), strings.Repeat("c", 59)
	e.Record = spec.Revision{Epoch: ^uint64(0), Counter: ^uint64(0)}
	e.IssuedAt = time.Date(2026, 11, 20, 3, 4, 5, 999999999, time.FixedZone("x", -11*3600-59*60))
	env := mustSign(t, e, testKey(t, 1))
	if len(env) > MaxCanonicalBytes {
		t.Errorf("largest envelope is %d bytes, above %d", len(env), MaxCanonicalBytes)
	}
}
