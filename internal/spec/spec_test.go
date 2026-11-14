package spec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
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
			s.Retired = []Retired{}
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
		{"env_of_63_passes", mut(func(s *Spec) { s.Env = strings.Repeat("a", 63) }), true},
		{"env_of_64", mut(func(s *Spec) { s.Env = strings.Repeat("a", 64) }), false},
		{"env_Dev", mut(func(s *Spec) { s.Env = "Dev" }), false},
		{"env_empty", mut(func(s *Spec) { s.Env = "" }), false},
	}
	for _, tc := range structural {
		t.Run(tc.name, func(t *testing.T) {
			env := signRaw(t, tc.spec, priv)
			_, _, err := Verify(env, keys)
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
		{"duplicate_member", strings.Replace(string(good), `"env":"dev"`, `"env":"dev","env":"prod"`, 1)},
		{"case_folded_member", strings.Replace(string(good), `"env":"dev"`, `"ENV":"dev"`, 1)},
		{"case_folded_nested", strings.Replace(string(good), `"epoch":1`, `"EPOCH":1`, 1)},
		{"absent_cells", `{"env":"dev","revision":{"epoch":1,"counter":5},"retired":[]}`},
		{"absent_retired", `{"env":"dev","revision":{"epoch":1,"counter":5},"cells":[]}`},
		{"null_cells", `{"env":"dev","revision":{"epoch":1,"counter":5},"cells":null,"retired":[]}`},
		{"null_retired", `{"env":"dev","revision":{"epoch":1,"counter":5},"cells":[],"retired":null}`},
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

func signRaw(t *testing.T, s Spec, key ed25519.PrivateKey) []byte {
	t.Helper()
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	env, err := record.SignEnvelope(PayloadType, body, key)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestSignRefusesWhatVerifyRefuses(t *testing.T) {
	_, priv := keyPair(t)
	bad := goodSpec()
	bad.Retired[0].Revision = Revision{Epoch: 1, Counter: 6}
	if _, err := Sign(bad, priv); err == nil {
		t.Fatal("Sign accepted a retired mark above the spec revision")
	}
	bad = goodSpec()
	bad.Env = "Dev"
	if _, err := Sign(bad, priv); err == nil {
		t.Fatal("Sign accepted env Dev")
	}
	if err := goodSpec().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"dev-cell-1": true, strings.Repeat("a", 59): true, strings.Repeat("a", 60): false,
		"": false, "Cell": false, "-a": false, "a-": false, "a_b": false,
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSpecVerifyRejectsRewrittenPayloadType(t *testing.T) {
	pub, priv := keyPair(t)
	keys := []ed25519.PublicKey{pub}
	cell := record.Cell{Name: "dev-cell-1", Env: "dev", Issuer: "https://x", Epoch: 1, Counter: 1,
		JWKS: json.RawMessage(`{"keys":[]}`)}
	recEnv, _ := record.Sign(cell, priv)
	specEnv, _ := Sign(goodSpec(), priv)
	rewrite := func(env []byte, typ string) []byte {
		var m map[string]any
		if err := json.Unmarshal(env, &m); err != nil {
			t.Fatal(err)
		}
		m["payloadType"] = typ
		out, _ := json.Marshal(m)
		return out
	}
	if _, _, err := Verify(rewrite(recEnv, PayloadType), keys); !errors.Is(err, record.ErrSignature) {
		t.Fatalf("record envelope relabelled as a spec: %v, want ErrSignature", err)
	}
	if _, err := record.Verify(rewrite(specEnv, record.PayloadType), keys); !errors.Is(err, record.ErrSignature) {
		t.Fatalf("spec envelope relabelled as a record: %v, want ErrSignature", err)
	}
}

func TestCheckRecord(t *testing.T) {
	cell := record.Cell{Name: "dev-cell-1", Env: "dev", Issuer: "https://x", Epoch: 1, Counter: 3}
	payload := []byte(`{"name":"dev-cell-1"}`)
	s := goodSpec()
	s.Cells[0].RecordSHA256 = RecordDigest(payload)
	if err := s.CheckRecord("dev-cell-1", cell, payload); err != nil {
		t.Fatalf("control failed: %v", err)
	}
	cases := []struct {
		name  string
		cell  string
		edit  func(*record.Cell)
		bytes []byte
		want  error
	}{
		{"unindexed", "dev-cell-7", nil, payload, ErrUnindexed},
		{"retired_is_unindexed", "dev-cell-9", nil, payload, ErrUnindexed},
		{"name", "dev-cell-1", func(c *record.Cell) { c.Name = "dev-cell-2" }, payload, ErrMismatch},
		{"env", "dev-cell-1", func(c *record.Cell) { c.Env = "prod" }, payload, ErrMismatch},
		{"epoch", "dev-cell-1", func(c *record.Cell) { c.Epoch = 2 }, payload, ErrMismatch},
		{"counter", "dev-cell-1", func(c *record.Cell) { c.Counter = 4 }, payload, ErrMismatch},
		{"digest", "dev-cell-1", nil, []byte(`{"name":"other"}`), ErrMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cell
			if tc.edit != nil {
				tc.edit(&c)
			}
			if err := s.CheckRecord(tc.cell, c, tc.bytes); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func specWithSteps() Spec {
	s := goodSpec()
	s.Steps = []StepEntry{
		{Name: "dev-cell-1", StepID: strings.Repeat("ab", 16), StepSHA256: digest},
		{Name: "dev-cell-3", StepID: strings.Repeat("cd", 16), StepSHA256: digest},
	}
	return s
}

func TestSpecWithStepsRoundTrip(t *testing.T) {
	pub, priv := keyPair(t)
	want := specWithSteps()
	env, err := Sign(want, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Steps) != 2 || got.Steps[0] != want.Steps[0] || got.Steps[1] != want.Steps[1] {
		t.Fatalf("got %+v", got.Steps)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	if string(m["steps"]) != `[{"name":"dev-cell-1","stepID":"`+strings.Repeat("ab", 16)+`","stepSHA256":"`+digest+`"},{"name":"dev-cell-3","stepID":"`+strings.Repeat("cd", 16)+`","stepSHA256":"`+digest+`"}]` {
		t.Fatalf("steps %s", m["steps"])
	}
}

func TestSpecStepsRules(t *testing.T) {
	pub, priv := keyPair(t)
	keys := []ed25519.PublicKey{pub}
	id := strings.Repeat("ab", 16)
	mod := func(steps ...StepEntry) []byte {
		s := goodSpec()
		s.Steps = steps
		return signRaw(t, s, priv)
	}
	for _, tc := range []struct {
		name string
		env  []byte
		bad  bool
	}{
		{"names_out_of_order", mod(StepEntry{"dev-cell-2", id, digest}, StepEntry{"dev-cell-1", id, digest}), true},
		{"duplicate_name", mod(StepEntry{"dev-cell-1", id, digest}, StepEntry{"dev-cell-1", id, digest}), true},
		{"step_id_upper", mod(StepEntry{"dev-cell-1", strings.Repeat("AB", 16), digest}), true},
		{"step_id_31_hex", mod(StepEntry{"dev-cell-1", strings.Repeat("a", 31), digest}), true},
		{"digest_63", mod(StepEntry{"dev-cell-1", id, strings.Repeat("a", 63)}), true},
		{"digest_upper", mod(StepEntry{"dev-cell-1", id, strings.Repeat("AB", 32)}), true},
		{"name_invalid", mod(StepEntry{"Dev-Cell", id, digest}), true},
		{"name_also_in_cells", mod(StepEntry{"dev-cell-2", id, digest}), false},
		{"name_also_in_retired", mod(StepEntry{"dev-cell-9", id, digest}), false},
		{"empty_steps", mod(), false},
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
	bad := goodSpec()
	bad.Steps = []StepEntry{{"dev-cell-2", id, digest}, {"dev-cell-1", id, digest}}
	if _, err := Sign(bad, priv); err == nil {
		t.Fatal("Sign accepted steps out of order")
	}
}

func TestSpecWithoutStepsUnchanged(t *testing.T) {
	pub, priv := keyPair(t)
	env, err := Sign(goodSpec(), priv)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/m4-spec.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	if got := hex.EncodeToString(sum[:]); got != strings.TrimSpace(string(want)) {
		t.Fatalf("payload digest %s, M4 digest %s; payload %s", got, want, payload)
	}
	if strings.Contains(string(payload), "steps") {
		t.Fatalf("payload %s", payload)
	}
}
