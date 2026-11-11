package spec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

var digest = strings.Repeat("ab", 32)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func goodSpec() Spec {
	return Spec{
		Env:      "dev",
		Revision: Revision{Epoch: 1, Counter: 5},
		Cells: []Entry{
			{Name: "dev-cell-1", Revision: Revision{1, 3}, RecordSHA256: digest},
			{Name: "dev-cell-2", Revision: Revision{1, 5}, RecordSHA256: digest},
		},
		Retired: []Retired{{Name: "dev-cell-9", Revision: Revision{1, 2}}},
	}
}

func TestSpecRoundTrip(t *testing.T) {
	pub, priv := keyPair(t)
	want := goodSpec()
	env, err := Sign(want, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(want)
	if string(payload) != string(body) {
		t.Fatalf("payload %s, want %s", payload, body)
	}
	if got.Env != want.Env || got.Revision != want.Revision || len(got.Cells) != 2 || len(got.Retired) != 1 ||
		got.Cells[1] != want.Cells[1] || got.Retired[0] != want.Retired[0] {
		t.Fatalf("got %+v", got)
	}
}

func TestSpecEmptyListsEncodeAsArrays(t *testing.T) {
	_, priv := keyPair(t)
	env, err := Sign(Spec{Env: "dev", Revision: Revision{1, 1}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	_, payload, err := Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"cells":[]`) || !strings.Contains(string(payload), `"retired":[]`) {
		t.Fatalf("payload %s", payload)
	}
}

func TestSpecVerifyRefusesRecordType(t *testing.T) {
	pub, priv := keyPair(t)
	keys := []ed25519.PublicKey{pub}
	cell := record.Cell{Name: "dev-cell-1", Env: "dev", Issuer: "https://x", Epoch: 1, Counter: 1,
		JWKS: json.RawMessage(`{"keys":[]}`)}
	recEnv, err := record.Sign(cell, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(recEnv, keys); !errors.Is(err, record.ErrPayloadType) {
		t.Fatalf("spec.Verify of a record: %v", err)
	}
	specEnv, err := Sign(goodSpec(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Verify(specEnv, keys); !errors.Is(err, record.ErrPayloadType) {
		t.Fatalf("record.Verify of a spec: %v", err)
	}
}

func TestSpecVerifyErrors(t *testing.T) {
	pub, priv := keyPair(t)
	foreign, _ := keyPair(t)
	keys := []ed25519.PublicKey{pub}
	good, err := Sign(goodSpec(), priv)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(good, &m); err != nil {
		t.Fatal(err)
	}
	m["signatures"] = []any{}
	noSigs, _ := json.Marshal(m)
	tampered := []byte(strings.Replace(string(good), `"payload":"`, `"payload":"A`, 1))
	cases := []struct {
		name string
		env  []byte
		keys []ed25519.PublicKey
		want error
	}{
		{"no_signatures", noSigs, keys, record.ErrSignature},
		{"foreign_key", good, []ed25519.PublicKey{foreign}, record.ErrSignature},
		{"bad_json", []byte("not json"), keys, record.ErrDecode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Verify(tc.env, tc.keys); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("tampered_byte", func(t *testing.T) {
		_, _, err := Verify(tampered, keys)
		if !errors.Is(err, record.ErrSignature) && !errors.Is(err, record.ErrDecode) {
			t.Fatalf("got %v", err)
		}
		if err == nil {
			t.Fatal("tampered envelope verified")
		}
	})
	t.Run("tampered_payload_byte_is_signature_error", func(t *testing.T) {
		body, _ := json.Marshal(goodSpec())
		body[len(body)-3] ^= 0x01
		m["payload"] = encode(body)
		m["signatures"] = signaturesOf(t, good)
		env, _ := json.Marshal(m)
		if _, _, err := Verify(env, keys); !errors.Is(err, record.ErrSignature) {
			t.Fatalf("got %v, want ErrSignature", err)
		}
	})
}

func TestSpecVerifyRefusesBadIndex(t *testing.T) {
	pub, priv := keyPair(t)
	keys := []ed25519.PublicKey{pub}
	e := func(name string, c uint64) Entry {
		return Entry{Name: name, Revision: Revision{1, c}, RecordSHA256: digest}
	}
	mut := func(f func(*Spec)) Spec {
		s := goodSpec()
		f(&s)
		return s
	}
	type rawCase struct {
		name string
		body string
	}
	structural := []struct {
		name string
		spec Spec
		pass bool
	}{
		{"readd_above_mark", mut(func(s *Spec) {
			s.Cells = []Entry{e("dev-cell-9", 5)}
			s.Retired = nil
		}), true},
		{"names_out_of_order", mut(func(s *Spec) { s.Cells = []Entry{e("b", 1), e("a", 1)} }), false},
		{"duplicate_name", mut(func(s *Spec) { s.Cells = []Entry{e("a", 1), e("a", 2)} }), false},
		{"retired_out_of_order", mut(func(s *Spec) {
			s.Retired = []Retired{{"b", Revision{1, 1}}, {"a", Revision{1, 1}}}
		}), false},
		{"name_in_both_lists", mut(func(s *Spec) { s.Retired = []Retired{{"dev-cell-1", Revision{1, 1}}} }), false},
		{"name_of_59_passes", mut(func(s *Spec) { s.Cells = []Entry{e(strings.Repeat("a", 59), 1)} }), true},
		{"name_of_60", mut(func(s *Spec) { s.Cells = []Entry{e(strings.Repeat("a", 60), 1)} }), false},
		{"uppercase_name", mut(func(s *Spec) { s.Cells = []Entry{e("Cell", 1)} }), false},
		{"empty_name", mut(func(s *Spec) { s.Cells = []Entry{e("", 1)} }), false},
		{"retired_name_of_60", mut(func(s *Spec) {
			s.Retired = []Retired{{strings.Repeat("a", 60), Revision{1, 1}}}
		}), false},
		{"digest_of_63", mut(func(s *Spec) { s.Cells[0].RecordSHA256 = digest[:63] }), false},
		{"uppercase_digest", mut(func(s *Spec) { s.Cells[0].RecordSHA256 = strings.ToUpper(digest) }), false},
		{"epoch_0", mut(func(s *Spec) { s.Revision.Epoch = 0 }), false},
		{"counter_0", mut(func(s *Spec) { s.Revision.Counter = 0 }), false},
		{"entry_epoch_0", mut(func(s *Spec) { s.Cells[0].Revision.Epoch = 0 }), false},
		{"entry_counter_0", mut(func(s *Spec) { s.Cells[0].Revision.Counter = 0 }), false},
		{"entry_above_spec_counter", mut(func(s *Spec) { s.Cells[0].Revision.Counter = 6 }), false},
		{"entry_above_spec_epoch", mut(func(s *Spec) { s.Cells[0].Revision = Revision{2, 1} }), false},
		{"retired_above_spec", mut(func(s *Spec) { s.Retired[0].Revision = Revision{1, 6} }), false},
		{"retired_revision_0", mut(func(s *Spec) { s.Retired[0].Revision = Revision{} }), false},
		{"env_Dev", mut(func(s *Spec) { s.Env = "Dev" }), false},
		{"env_empty", mut(func(s *Spec) { s.Env = "" }), false},
	}
	for _, tc := range structural {
		t.Run(tc.name, func(t *testing.T) {
			env, err := Sign(tc.spec, priv)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = Verify(env, keys)
			if tc.pass {
				if err != nil {
					t.Fatalf("control failed: %v", err)
				}
				return
			}
			if !errors.Is(err, record.ErrDecode) {
				t.Fatalf("got %v, want ErrDecode", err)
			}
		})
	}
	good, _ := json.Marshal(goodSpec())
	raws := []rawCase{
		{"unknown_field", strings.Replace(string(good), `"env":"dev"`, `"env":"dev","extra":1`, 1)},
		{"trailing_data", string(good) + `{}`},
		{"null_cells_value_type", strings.Replace(string(good), `"cells":[`, `"cells":{"x":`, 1)},
	}
	for _, tc := range raws {
		t.Run(tc.name, func(t *testing.T) {
			env, err := record.SignEnvelope(PayloadType, []byte(tc.body), priv)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Verify(env, keys); !errors.Is(err, record.ErrDecode) {
				t.Fatalf("got %v, want ErrDecode", err)
			}
		})
	}
}

func TestRevisionCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b Revision
		want int
	}{
		{Revision{1, 1}, Revision{1, 1}, 0},
		{Revision{1, 2}, Revision{1, 1}, 1},
		{Revision{1, 9}, Revision{2, 1}, -1},
		{Revision{2, 1}, Revision{1, 9}, 1},
		{Revision{1, 1}, Revision{1, 2}, -1},
	} {
		if got := tc.a.Compare(tc.b); got != tc.want {
			t.Errorf("%v.Compare(%v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestRecordDigestIsPayloadSHA256(t *testing.T) {
	payload := []byte(`{"name":"a"}`)
	sum := sha256.Sum256(payload)
	if got := RecordDigest(payload); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("got %s", got)
	}
	if RecordRevision(record.Cell{Epoch: 2, Counter: 7}) != (Revision{2, 7}) {
		t.Fatal("RecordRevision must copy epoch and counter")
	}
}

func TestRevisionJSONNames(t *testing.T) {
	raw, _ := json.Marshal(goodSpec())
	for _, name := range []string{`"env"`, `"revision"`, `"cells"`, `"retired"`, `"epoch"`, `"counter"`, `"name"`, `"recordSHA256"`} {
		if !strings.Contains(string(raw), name) {
			t.Errorf("missing %s in %s", name, raw)
		}
	}
}

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func signaturesOf(t *testing.T, env []byte) any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	return m["signatures"]
}
