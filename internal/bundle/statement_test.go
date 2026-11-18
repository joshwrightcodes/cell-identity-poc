package bundle_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

func keypair(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func trust(pubs ...ed25519.PublicKey) []crypto.PublicKey {
	out := make([]crypto.PublicKey, len(pubs))
	for i, p := range pubs {
		out[i] = p
	}
	return out
}

func testSet() bundle.Set {
	return bundle.Set{
		Version: bundle.Version{Epoch: 3, Counter: 7},
		Components: []bundle.Component{
			{Name: "apps-sample", Wave: 5, Namespace: "apps-demo", Digest: hexDigest('1')},
			{Name: "istiod", Wave: 3, Namespace: "istio-system", Digest: hexDigest('2'),
				IgnoreDifferences: json.RawMessage(`[{"group":"admissionregistration.k8s.io","kind":"ValidatingWebhookConfiguration","jqPathExpressions":[".webhooks[]?.failurePolicy"]}]`)},
			{Name: "namespaces", Wave: -2, Namespace: "default", Digest: hexDigest('3')},
		},
	}
}

var rootDigest = hexDigest('f')

func signStatement(t testing.TB, st bundle.Statement, priv ed25519.PrivateKey) []byte {
	t.Helper()
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	env, err := record.SignEnvelope(bundle.PayloadType, body, priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestStatementRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	set := testSet()
	st := bundle.NewStatement("dev", "dev-cell-1", set, rootDigest)
	env, err := bundle.SignAttestation(st, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, gotSet, err := bundle.ParseAttestation(env, trust(pub))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "https://in-toto.io/Statement/v1" || got.PredicateType != "https://cell.poc.internal/bundle-set/v1" {
		t.Errorf("types %q %q", got.Type, got.PredicateType)
	}
	if got.Predicate.Env != "dev" || got.Predicate.Target != "dev-cell-1" || got.Predicate.Version != set.Version {
		t.Errorf("predicate %+v", got.Predicate)
	}
	if got.RootDigest() != rootDigest {
		t.Errorf("root digest %q", got.RootDigest())
	}
	if bundle.ContentSHA256(gotSet) != bundle.ContentSHA256(set) || gotSet.Version != set.Version {
		t.Errorf("set %+v differs from %+v", gotSet, set)
	}

	// The wire form that cosign and in-toto readers see.
	var wire map[string]any
	var envMap struct {
		PayloadType string `json:"payloadType"`
		Payload     []byte `json:"payload"`
	}
	if err := json.Unmarshal(env, &envMap); err != nil {
		t.Fatal(err)
	}
	if envMap.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("payloadType %q", envMap.PayloadType)
	}
	if err := json.Unmarshal(envMap.Payload, &wire); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"_type", "subject", "predicateType", "predicate"} {
		if _, ok := wire[k]; !ok {
			t.Errorf("statement has no %q", k)
		}
	}
	subs := wire["subject"].([]any)
	if len(subs) != 4 {
		t.Fatalf("%d subjects", len(subs))
	}
	first := subs[0].(map[string]any)
	if first["name"] != "bundles/dev-cell-1/root" || first["digest"].(map[string]any)["sha256"] != strings.Repeat("f", 64) {
		t.Errorf("root subject %v", first)
	}
	second := subs[1].(map[string]any)
	if second["name"] != "bundles/dev-cell-1/apps-sample" || second["digest"].(map[string]any)["sha256"] != strings.Repeat("1", 64) {
		t.Errorf("component subject %v", second)
	}
	pred := wire["predicate"].(map[string]any)
	for _, c := range pred["components"].([]any) {
		if _, has := c.(map[string]any)["digest"]; has {
			t.Error("a predicate component carries a digest")
		}
	}
}

func TestAttestationWrongKeyAndSigner(t *testing.T) {
	pub, priv := keypair(t)
	otherPub, _ := keypair(t)
	env, err := bundle.SignAttestation(bundle.NewStatement("dev", "c", testSet(), rootDigest), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bundle.ParseAttestation(env, trust(otherPub)); !errors.Is(err, record.ErrSignature) {
		t.Errorf("wrong key: %v", err)
	}
	if _, _, err := bundle.ParseAttestation(env, nil); !errors.Is(err, record.ErrSignature) {
		t.Errorf("no keys: %v", err)
	}
	if _, _, err := bundle.ParseAttestation(env, []crypto.PublicKey{"not a key", pub}); err != nil {
		t.Errorf("a foreign key type next to a good key: %v", err)
	}
	if _, err := bundle.SignAttestation(bundle.NewStatement("dev", "c", testSet(), rootDigest), nil); err == nil {
		t.Error("nil signer signed")
	}
}

func TestStatementSubjectsMatchSet(t *testing.T) {
	pub, priv := keypair(t)
	base := func() bundle.Statement { return bundle.NewStatement("dev", "dev-cell-1", testSet(), rootDigest) }
	sub := func(name string, c byte) bundle.Subject {
		return bundle.Subject{Name: name, Digest: bundle.SubjectDigest{SHA256: strings.Repeat(string(c), 64)}}
	}
	for _, tc := range []struct {
		name string
		want string
		mod  func(*bundle.Statement)
	}{
		{"missing_root", "no root subject", func(s *bundle.Statement) { s.Subject = s.Subject[1:] }},
		{"missing_component", "has no subject", func(s *bundle.Statement) { s.Subject = append(s.Subject[:2:2], s.Subject[3:]...) }},
		{"extra_subject", "subjects for", func(s *bundle.Statement) { s.Subject = append(s.Subject, sub("bundles/dev-cell-1/other", '9')) }},
		{"duplicate_root", "appears twice", func(s *bundle.Statement) { s.Subject = append(s.Subject, s.Subject[0]) }},
		{"duplicate_component", "appears twice", func(s *bundle.Statement) { s.Subject = append(s.Subject, s.Subject[1]) }},
		{"duplicate_swaps_missing", "appears twice", func(s *bundle.Statement) { s.Subject[3] = s.Subject[2] }},
		{"other_target", "has no subject", func(s *bundle.Statement) { s.Predicate.Target = "dev-cell-2" }},
		{"no_subjects", "has no subject", func(s *bundle.Statement) { s.Subject = nil }},
		{"digest_short", "64 lowercase", func(s *bundle.Statement) { s.Subject[1].Digest.SHA256 = strings.Repeat("a", 63) }},
		{"digest_upper", "64 lowercase", func(s *bundle.Statement) { s.Subject[1].Digest.SHA256 = strings.Repeat("A", 64) }},
		{"wrong_type", "_type is", func(s *bundle.Statement) { s.Type = "https://in-toto.io/Statement/v0.1" }},
		{"wrong_predicate_type", "predicateType is", func(s *bundle.Statement) { s.PredicateType = "https://slsa.dev/provenance/v1" }},
		{"env_bad", "env is not", func(s *bundle.Statement) { s.Predicate.Env = "Dev" }},
		{"target_bad", "target is not", func(s *bundle.Statement) { s.Predicate.Target = "a/b" }},
		{"epoch_zero", "epoch is 0", func(s *bundle.Statement) { s.Predicate.Version.Epoch = 0 }},
		{"no_components", "0 components", func(s *bundle.Statement) { s.Predicate.Components = nil }},
		{"components_unordered", "is not above", func(s *bundle.Statement) {
			c := s.Predicate.Components
			c[0], c[1] = c[1], c[0]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := base()
			tc.mod(&st)
			_, _, err := bundle.ParseAttestation(signStatement(t, st, priv), trust(pub))
			if !errors.Is(err, record.ErrDecode) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want ErrDecode with %q, got %v", tc.want, err)
			}
			// SignAttestation refuses what ParseAttestation refuses.
			if _, err := bundle.SignAttestation(st, priv); !errors.Is(err, record.ErrDecode) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SignAttestation: want ErrDecode with %q, got %v", tc.want, err)
			}
		})
	}
	if _, _, err := bundle.ParseAttestation(signStatement(t, base(), priv), trust(pub)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestStatementStrictDecode(t *testing.T) {
	pub, priv := keypair(t)
	st := bundle.NewStatement("dev", "c", testSet(), rootDigest)
	body, _ := json.Marshal(st)
	for name, mut := range map[string]func(string) string{
		"unknown_member":   func(s string) string { return strings.Replace(s, `{"_type"`, `{"extra":1,"_type"`, 1) },
		"other_algorithm":  func(s string) string { return strings.Replace(s, `"sha256":`, `"sha512":`, 1) },
		"trailing_data":    func(s string) string { return s + " {}" },
		"duplicate_member": func(s string) string { return strings.Replace(s, `{"_type"`, `{"_type":"x","_type"`, 1) },
	} {
		env, err := record.SignEnvelope(bundle.PayloadType, []byte(mut(string(body))), priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := bundle.ParseAttestation(env, trust(pub)); !errors.Is(err, record.ErrDecode) {
			t.Errorf("%s: want ErrDecode, got %v", name, err)
		}
	}
}

// paddedStatement returns a statement whose JSON encoding has exactly n bytes.
func paddedStatement(t testing.TB, n int) bundle.Statement {
	t.Helper()
	mk := func(pad int) bundle.Statement {
		set := testSet()
		set.Components[0].IgnoreDifferences = json.RawMessage(`[{"name":"` + strings.Repeat("x", pad) + `"}]`)
		return bundle.NewStatement("dev", "c", set, rootDigest)
	}
	body, _ := json.Marshal(mk(0))
	st := mk(n - len(body))
	body, _ = json.Marshal(st)
	if len(body) != n {
		t.Fatalf("padding gave %d bytes, want %d", len(body), n)
	}
	return st
}

func TestStatementSize(t *testing.T) {
	pub, priv := keypair(t)
	at := paddedStatement(t, bundle.MaxStatementBytes)
	env, err := bundle.SignAttestation(at, priv)
	if err != nil {
		t.Fatalf("16 KiB: %v", err)
	}
	if _, _, err := bundle.ParseAttestation(env, trust(pub)); err != nil {
		t.Fatalf("16 KiB parse: %v", err)
	}

	over := paddedStatement(t, bundle.MaxStatementBytes+1)
	if _, err := bundle.SignAttestation(over, priv); err == nil {
		t.Error("16 KiB plus one byte signed")
	}
	// An envelope that another signer made, with one byte too many.
	body, _ := json.Marshal(over)
	env, err = record.SignEnvelope(bundle.PayloadType, body, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bundle.ParseAttestation(env, trust(pub)); !errors.Is(err, record.ErrDecode) {
		t.Errorf("16 KiB plus one byte parsed: %v", err)
	}
}

func TestAttestationOtherTypes(t *testing.T) {
	pub, priv := keypair(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	opEnv, err := op.Sign(op.Operation{
		ID: strings.Repeat("ab", 16), Env: "dev", Cell: "c", Kind: op.KindDemoAppend, Version: 1, KeyEpoch: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), Args: json.RawMessage(`{"line":"x"}`),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	other := map[string][]byte{"op": opEnv}
	for name, pt := range map[string]string{"spec": spec.PayloadType, "record": record.PayloadType, "step": step.PayloadType} {
		env, err := record.SignEnvelope(pt, []byte(`{}`), priv)
		if err != nil {
			t.Fatal(err)
		}
		other[name] = env
	}
	for name, env := range other {
		if _, _, err := bundle.ParseAttestation(env, trust(pub)); !errors.Is(err, record.ErrPayloadType) {
			t.Errorf("%s envelope: want ErrPayloadType, got %v", name, err)
		}
	}
	att, err := bundle.SignAttestation(bundle.NewStatement("dev", "c", testSet(), rootDigest), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := op.Verify(att, []ed25519.PublicKey{pub}); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("op.Verify of an attestation: want ErrPayloadType, got %v", err)
	}
}

// cosign attest signs Ed25519ph with an Ed25519 key. The verifier accepts only pure Ed25519, the
// scheme of record.SignEnvelope.
func TestAttestationRefusesEd25519ph(t *testing.T) {
	pub, priv := keypair(t)
	body, _ := json.Marshal(bundle.NewStatement("dev", "c", testSet(), rootDigest))
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(bundle.PayloadType), bundle.PayloadType, len(body), body))
	digest := sha512.Sum512(pae)
	sig, err := priv.Sign(nil, digest[:], &ed25519.Options{Hash: crypto.SHA512})
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(map[string]any{
		"payloadType": bundle.PayloadType,
		"payload":     base64.StdEncoding.EncodeToString(body),
		"signatures":  []map[string]string{{"sig": base64.StdEncoding.EncodeToString(sig)}},
	})
	if _, _, err := bundle.ParseAttestation(env, trust(pub)); !errors.Is(err, record.ErrSignature) {
		t.Fatalf("Ed25519ph: want ErrSignature, got %v", err)
	}
	// Control: the pure signature over the same PAE passes.
	pure, _ := json.Marshal(map[string]any{
		"payloadType": bundle.PayloadType,
		"payload":     base64.StdEncoding.EncodeToString(body),
		"signatures":  []map[string]string{{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, pae))}},
	})
	if _, _, err := bundle.ParseAttestation(pure, trust(pub)); err != nil {
		t.Fatalf("pure Ed25519: %v", err)
	}
}
