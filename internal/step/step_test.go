package step

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
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

func valid() Step {
	return Step{
		ID: strings.Repeat("ab", 16), Env: "dev", Cell: "dev-cell-1", Kind: KindCellCreate, Version: 1,
		KeyEpoch: 1, IssuedAt: t0, ExpiresAt: t0.Add(DefaultTTL),
		Cluster:         ClusterRef{PodSubnet: "10.20.0.0/16", ServiceSubnet: "10.21.0.0/16", Issuer: "https://dev-cell-1.example:6443"},
		BootstrapSHA256: strings.Repeat("cd", 32),
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

func TestConstants(t *testing.T) {
	if PayloadType != "application/vnd.poc.provision-step+json" || KindCellCreate != "cell.create" || Code != "step_invalid" {
		t.Fatal("constant changed")
	}
	if DefaultTTL != 6*time.Hour || MinTTL != 10*time.Minute || MaxTTL != 24*time.Hour || MaxSkew != 60*time.Second {
		t.Fatal("limit changed")
	}
	sum := sha256.Sum256([]byte("other"))
	if TestDigest != hex.EncodeToString(sum[:]) {
		t.Fatalf("TestDigest %s", TestDigest)
	}
}

func TestStepRoundTrip(t *testing.T) {
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
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	body, _ := json.Marshal(want)
	if string(payload) != string(body) {
		t.Fatalf("payload %s, want %s", payload, body)
	}
	if PayloadSHA256(payload) != hex.EncodeToString(func() []byte { s := sha256.Sum256(body); return s[:] }()) {
		t.Fatal("PayloadSHA256 is not the SHA-256 of the payload")
	}
}

func TestStepWireNames(t *testing.T) {
	raw, err := json.Marshal(valid())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	keys := []string{"id", "env", "cell", "kind", "version", "keyEpoch", "issuedAt", "expiresAt", "cluster", "bootstrapSHA256"}
	if len(m) != len(keys) {
		t.Fatalf("encodes %s", raw)
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("lacks key %q in %s", k, raw)
		}
	}
	var c map[string]json.RawMessage
	if err := json.Unmarshal(m["cluster"], &c); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"podSubnet", "serviceSubnet", "issuer"} {
		if _, ok := c[k]; !ok || len(c) != 3 {
			t.Errorf("cluster lacks key %q in %s", k, m["cluster"])
		}
	}
}

func TestStepVerifyRefusesOtherTypes(t *testing.T) {
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
	opEnv, err := op.Sign(op.Operation{
		ID: strings.Repeat("ab", 16), Env: "dev", Cell: "dev-cell-1", Kind: op.KindDemoAppend, Version: 1,
		KeyEpoch: 1, IssuedAt: t0, ExpiresAt: t0.Add(time.Minute), Args: json.RawMessage(`{"line":"x"}`),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string][]byte{"record": recEnv, "spec": specEnv, "op": opEnv} {
		if _, _, err := Verify(env, keys); !errors.Is(err, record.ErrPayloadType) {
			t.Errorf("%s envelope: %v", name, err)
		}
	}
	stepEnv, err := Sign(valid(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Verify(stepEnv, keys); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("record.Verify: %v", err)
	}
	if _, _, err := spec.Verify(stepEnv, keys); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("spec.Verify: %v", err)
	}
	if _, _, err := op.Verify(stepEnv, keys); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("op.Verify: %v", err)
	}
}

func TestStepVerifyRules(t *testing.T) {
	pub, priv := keypair(t)
	keys := []ed25519.PublicKey{pub}
	mod := func(f func(*Step)) []byte {
		s := valid()
		f(&s)
		b, err := json.Marshal(s)
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
		{"id_31_hex", mod(func(s *Step) { s.ID = strings.Repeat("a", 31) }), true},
		{"id_upper", mod(func(s *Step) { s.ID = strings.Repeat("AB", 16) }), true},
		{"version_2", mod(func(s *Step) { s.Version = 2 }), true},
		{"key_epoch_0", mod(func(s *Step) { s.KeyEpoch = 0 }), true},
		{"kind_other", mod(func(s *Step) { s.Kind = "cell.delete" }), true},
		{"env_upper", mod(func(s *Step) { s.Env = "DEV" }), true},
		{"cell_upper", mod(func(s *Step) { s.Cell = "Dev-Cell" }), true},
		{"cell_60_chars", mod(func(s *Step) { s.Cell = strings.Repeat("a", 60) }), true},
		{"subnet_not_canonical", mod(func(s *Step) { s.Cluster.PodSubnet = "10.20.0.1/16" }), true},
		{"subnet_leading_zero", mod(func(s *Step) { s.Cluster.ServiceSubnet = "10.021.0.0/16" }), true},
		{"subnet_ipv6", mod(func(s *Step) { s.Cluster.PodSubnet = "fd00::/64" }), true},
		{"subnet_mapped", mod(func(s *Step) { s.Cluster.PodSubnet = "::ffff:10.20.0.0/112" }), true},
		{"subnet_empty", mod(func(s *Step) { s.Cluster.ServiceSubnet = "" }), true},
		{"issuer_http", mod(func(s *Step) { s.Cluster.Issuer = "http://dev-cell-1.example:6443" }), true},
		{"issuer_path", mod(func(s *Step) { s.Cluster.Issuer = "https://dev-cell-1.example/path" }), true},
		{"issuer_slash", mod(func(s *Step) { s.Cluster.Issuer = "https://dev-cell-1.example/" }), true},
		{"issuer_query", mod(func(s *Step) { s.Cluster.Issuer = "https://dev-cell-1.example?a=b" }), true},
		{"issuer_fragment", mod(func(s *Step) { s.Cluster.Issuer = "https://dev-cell-1.example#f" }), true},
		{"issuer_no_host", mod(func(s *Step) { s.Cluster.Issuer = "https://" }), true},
		{"issuer_userinfo", mod(func(s *Step) { s.Cluster.Issuer = "https://u@dev-cell-1.example" }), true},
		{"digest_63", mod(func(s *Step) { s.BootstrapSHA256 = strings.Repeat("a", 63) }), true},
		{"digest_upper", mod(func(s *Step) { s.BootstrapSHA256 = strings.Repeat("AB", 32) }), true},
		{"expires_equal_issued", mod(func(s *Step) { s.ExpiresAt = s.IssuedAt }), true},
		{"ttl_9m59s", mod(func(s *Step) { s.ExpiresAt = s.IssuedAt.Add(10*time.Minute - time.Second) }), true},
		{"ttl_24h1s", mod(func(s *Step) { s.ExpiresAt = s.IssuedAt.Add(24*time.Hour + time.Second) }), true},
		{"unknown_field", signRaw(t, priv, strings.TrimSuffix(string(base), "}")+`,"extra":1}`), true},
		{"trailing_data", signRaw(t, priv, string(base)+` {}`), true},
		{"ttl_10m", mod(func(s *Step) { s.ExpiresAt = s.IssuedAt.Add(10 * time.Minute) }), false},
		{"ttl_24h", mod(func(s *Step) { s.ExpiresAt = s.IssuedAt.Add(24 * time.Hour) }), false},
		{"cell_59_chars", mod(func(s *Step) { s.Cell = strings.Repeat("a", 59) }), false},
		{"issuer_ip_port", mod(func(s *Step) { s.Cluster.Issuer = "https://172.18.0.5:6443" }), false},
		{"subnet_24", mod(func(s *Step) { s.Cluster.PodSubnet = "10.20.1.0/24" }), false},
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

func TestStepCheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		now  time.Time
		mut  func(*Step)
		want string
	}{
		{"ok", "dev", t0.Add(time.Minute), nil, ""},
		{"other_env", "prod", t0.Add(time.Minute), nil, DetailEnvMismatch},
		{"expired", "dev", t0.Add(DefaultTTL), nil, DetailExpired},
		{"last_instant", "dev", t0.Add(DefaultTTL - time.Nanosecond), nil, ""},
		{"issued_61s_ahead", "dev", t0.Add(-61 * time.Second), nil, DetailNotYetValid},
		{"issued_59s_ahead", "dev", t0.Add(-59 * time.Second), nil, ""},
		{"issued_60s_ahead", "dev", t0.Add(-60 * time.Second), nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := valid()
			err := Check(s, tc.env, tc.now)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var e *Error
			if !errors.As(err, &e) || e.Detail != tc.want {
				t.Fatalf("got %v, want detail %s", err, tc.want)
			}
		})
	}
}

func TestStepVerifyErrors(t *testing.T) {
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
	if _, _, err := Verify(env, []ed25519.PublicKey{otherPub, pub}); err != nil {
		t.Errorf("second key: %v", err)
	}
}

func TestStepPeek(t *testing.T) {
	_, priv := keypair(t)
	s := valid()
	s.KeyEpoch = 7
	env, err := Sign(s, priv)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	m["signatures"].([]any)[0].(map[string]any)["sig"] = "AAAA"
	tampered, _ := json.Marshal(m)
	id, cell, epoch, err := Peek(tampered)
	if err != nil || id != s.ID || cell != s.Cell || epoch != 7 {
		t.Fatalf("got %q %q %d %v", id, cell, epoch, err)
	}
	if _, _, _, err := Peek([]byte(`{`)); !errors.Is(err, record.ErrDecode) {
		t.Errorf("garbage: %v", err)
	}
	other, _ := record.SignEnvelope(spec.PayloadType, []byte(`{}`), priv)
	if _, _, _, err := Peek(other); !errors.Is(err, record.ErrPayloadType) {
		t.Errorf("other type: %v", err)
	}
	for name, mut := range map[string]func(*Step){
		"hostile_id":   func(s *Step) { s.ID = "not-an-id\n" },
		"hostile_cell": func(s *Step) { s.Cell = "Bad Cell\n" },
	} {
		bad := valid()
		mut(&bad)
		raw, _ := json.Marshal(bad)
		badEnv := signRaw(t, priv, string(raw))
		if _, _, _, err := Peek(badEnv); !errors.Is(err, record.ErrDecode) {
			t.Errorf("%s: %v", name, err)
		}
	}
	notBase64 := []byte(`{"payloadType":"` + PayloadType + `","payload":"!!!","signatures":[]}`)
	if _, _, _, err := Peek(notBase64); !errors.Is(err, record.ErrDecode) {
		t.Errorf("payload not base64: %v", err)
	}
}

func TestNewID(t *testing.T) {
	a, b := NewID(), NewID()
	if !idRE.MatchString(a) || a == b {
		t.Fatalf("ids %q %q", a, b)
	}
}

func TestDetailOf(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"signature":    {record.ErrSignature, DetailSignatureInvalid},
		"signature_w":  {errors.Join(errors.New("x"), record.ErrSignature), DetailSignatureInvalid},
		"payload_type": {record.ErrPayloadType, DetailPayloadInvalid},
		"decode":       {record.ErrDecode, DetailPayloadInvalid},
		"error_expiry": {&Error{Detail: DetailExpired}, DetailExpired},
		"error_wrap":   {errors.Join(errors.New("x"), &Error{Detail: DetailEnvMismatch}), DetailEnvMismatch},
		"other":        {errors.New("boom"), DetailPayloadInvalid},
	} {
		if got := DetailOf(tc.err); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
	if (&Error{Detail: DetailExpired}).Error() == "" {
		t.Fatal("Error() is empty")
	}
}

func TestDetailStrings(t *testing.T) {
	want := map[string]string{
		DetailSignatureInvalid: "signature_invalid", DetailPayloadInvalid: "payload_invalid",
		DetailEnvMismatch: "env_mismatch", DetailCellUnknown: "cell_unknown", DetailClusterMismatch: "cluster_mismatch",
		DetailExpired: "expired", DetailNotYetValid: "not_yet_valid", DetailBootstrapMismatch: "bootstrap_mismatch",
		DetailStepConflict: "step_conflict", DetailStepUnindexed: "step_unindexed", DetailStepMissing: "step_missing",
		DetailRevisionOld: "revision_old", DetailPeerNotAllowed: "peer_not_allowed", DetailRateLimited: "rate_limited",
		DetailQueueFull: "queue_full", DetailSpecBehind: "spec_behind", DetailJournalCorrupt: "journal_corrupt",
		DetailCancelled: "cancelled", DetailTimeout: "timeout", DetailInterrupted: "interrupted", DetailStageFailed: "stage_failed",
	}
	if len(want) != 21 {
		t.Fatalf("two detail constants share a string: %v", want)
	}
	for got, w := range want {
		if got != w {
			t.Errorf("detail %q, want %q", got, w)
		}
	}
	if len(Details()) != 21 {
		t.Fatalf("Details() lists %d", len(Details()))
	}
	for _, d := range Details() {
		if _, ok := want[d]; !ok {
			t.Errorf("Details() holds %q", d)
		}
	}
}

func TestSameExceptEpoch(t *testing.T) {
	base := valid()
	other := base
	other.KeyEpoch = 9
	if !SameExceptEpoch(base, other) || !SameExceptEpoch(base, base) {
		t.Fatal("steps that differ only in epoch must match")
	}
	for name, mut := range map[string]func(*Step){
		"id":        func(s *Step) { s.ID = strings.Repeat("ef", 16) },
		"env":       func(s *Step) { s.Env = "prod" },
		"cell":      func(s *Step) { s.Cell = "dev-cell-2" },
		"kind":      func(s *Step) { s.Kind = "other" },
		"version":   func(s *Step) { s.Version = 2 },
		"issued":    func(s *Step) { s.IssuedAt = s.IssuedAt.Add(time.Second) },
		"expires":   func(s *Step) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) },
		"pod":       func(s *Step) { s.Cluster.PodSubnet = "10.30.0.0/16" },
		"service":   func(s *Step) { s.Cluster.ServiceSubnet = "10.31.0.0/16" },
		"issuer":    func(s *Step) { s.Cluster.Issuer = "https://x.example" },
		"bootstrap": func(s *Step) { s.BootstrapSHA256 = TestDigest },
	} {
		c := base
		mut(&c)
		if SameExceptEpoch(base, c) {
			t.Errorf("%s differs but SameExceptEpoch is true", name)
		}
	}
}

func TestStepSignRefusesWhatVerifyRefuses(t *testing.T) {
	_, priv := keypair(t)
	for name, mut := range map[string]func(*Step){
		"id":      func(s *Step) { s.ID = "x" },
		"version": func(s *Step) { s.Version = 2 },
		"epoch":   func(s *Step) { s.KeyEpoch = 0 },
		"kind":    func(s *Step) { s.Kind = "cell.delete" },
		"env":     func(s *Step) { s.Env = "DEV" },
		"cell":    func(s *Step) { s.Cell = strings.Repeat("a", 60) },
		"subnet":  func(s *Step) { s.Cluster.PodSubnet = "10.20.0.1/16" },
		"issuer":  func(s *Step) { s.Cluster.Issuer = "http://x.example" },
		"digest":  func(s *Step) { s.BootstrapSHA256 = "abc" },
		"ttl":     func(s *Step) { s.ExpiresAt = s.IssuedAt.Add(time.Minute) },
	} {
		s := valid()
		mut(&s)
		if _, err := Sign(s, priv); !errors.Is(err, record.ErrDecode) {
			t.Errorf("%s: got %v, want ErrDecode", name, err)
		}
	}
}
