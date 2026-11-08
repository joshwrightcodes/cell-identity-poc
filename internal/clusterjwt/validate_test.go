package clusterjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const (
	testIssuer = "https://10.0.0.1:6443"
	testEnv    = "dev"
	testNonce  = "n0nce"
	rsaKID     = "rsa-1"
	ecKID      = "ec-1"
)

var testNow = time.Unix(1_800_000_000, 0)

type keys struct {
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func newKeys(t *testing.T) keys {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys{rsa: r, ec: e}
}

func (k keys) record(t *testing.T) record.Cell {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &k.rsa.PublicKey, KeyID: rsaKID},
		{Key: &k.ec.PublicKey, KeyID: ecKID},
	}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return record.Cell{
		Name: "dev-cell-1", Env: testEnv, Issuer: testIssuer, JWKS: raw,
		Subjects: []record.Subject{{Namespace: "celld", ServiceAccount: "celld"}},
	}
}

type ref struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type k8s struct {
	Namespace string `json:"namespace,omitempty"`
	Svcacct   ref    `json:"serviceaccount"`
	Pod       *ref   `json:"pod,omitempty"`
	Node      *ref   `json:"node,omitempty"`
}

// spec describes one token. A mutator changes a good token into a bad one.
type spec struct {
	Issuer   string
	Audience any
	IAT, EXP int64
	K8s      k8s
	Alg      jose.SignatureAlgorithm
	KID      string
	Key      any
	Omit     []string
}

func (k keys) good() spec {
	return spec{
		Issuer:   testIssuer,
		Audience: []string{"spire-" + testEnv + "/" + testNonce},
		IAT:      testNow.Add(-time.Minute).Unix(),
		EXP:      testNow.Add(4 * time.Minute).Unix(),
		K8s: k8s{
			Namespace: "celld",
			Svcacct:   ref{Name: "celld", UID: "sa-uid"},
			Pod:       &ref{Name: "celld-0", UID: "pod-uid"},
			Node:      &ref{Name: "node-a", UID: "node-uid"},
		},
		Alg: jose.RS256, KID: rsaKID, Key: k.rsa,
	}
}

func (s spec) token(t *testing.T) string {
	t.Helper()
	claims := map[string]any{
		"iss": s.Issuer, "aud": s.Audience, "iat": s.IAT, "exp": s.EXP,
		"sub":           "system:serviceaccount:" + s.K8s.Namespace + ":" + s.K8s.Svcacct.Name,
		"kubernetes.io": s.K8s,
	}
	for _, name := range s.Omit {
		delete(claims, name)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.KID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.Alg, Key: s.Key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func check(t *testing.T, rec record.Cell, token string, want Reason) {
	t.Helper()
	_, err := Validate(rec, token, testEnv, testNonce, testNow)
	if got := ReasonOf(err); got != want {
		t.Fatalf("reason = %q (err %v), want %q", got, err, want)
	}
}

func TestValidateAcceptsGoodToken(t *testing.T) {
	k := newKeys(t)
	got, err := Validate(k.record(t), k.good().token(t), testEnv, testNonce, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.Namespace != "celld" || got.ServiceAccount != "celld" || got.PodUID != "pod-uid" ||
		got.PodName != "celld-0" || got.NodeName != "node-a" {
		t.Fatalf("unexpected claims %+v", got)
	}
	if !got.IssuedAt.Equal(testNow.Add(-time.Minute)) || !got.Expiry.Equal(testNow.Add(4*time.Minute)) {
		t.Fatalf("unexpected times %v %v", got.IssuedAt, got.Expiry)
	}
}

func TestValidateAcceptsES256(t *testing.T) {
	k := newKeys(t)
	s := k.good()
	s.Alg, s.KID, s.Key = jose.ES256, ecKID, k.ec
	check(t, k.record(t), s.token(t), "")
}

func TestValidateReasons(t *testing.T) {
	k := newKeys(t)
	other := newKeys(t)
	cases := []struct {
		name   string
		want   Reason
		rec    func(record.Cell) record.Cell
		mutate func(*spec)
		token  func() string
	}{
		{name: "revoked", want: Revoked, rec: func(c record.Cell) record.Cell { c.Revoked = true; return c }},
		{name: "malformed", want: Malformed, token: func() string { return "not-a-token" }},
		{name: "alg_not_allowed", want: AlgNotAllowed, mutate: func(s *spec) {
			s.Alg = jose.RS512
		}},
		{name: "unknown_kid", want: UnknownKID, mutate: func(s *spec) { s.KID = "other" }},
		{name: "bad_signature", want: BadSignature, mutate: func(s *spec) { s.Key = other.rsa }},
		{name: "issuer_mismatch", want: IssuerMismatch, mutate: func(s *spec) { s.Issuer = "https://evil.example" }},
		{name: "subject_not_allowed", want: SubjectNotAllowed, mutate: func(s *spec) {
			s.K8s.Svcacct.Name = "other"
		}},
		{name: "not_pod_bound", want: NotPodBound, mutate: func(s *spec) { s.K8s.Pod = nil }},
		{name: "lifetime_too_long", want: LifetimeTooLong, mutate: func(s *spec) {
			s.EXP = s.IAT + 3600
		}},
		{name: "stale_iat", want: StaleIAT, mutate: func(s *spec) {
			s.IAT = testNow.Add(-16 * time.Minute).Unix()
			s.EXP = s.IAT + 600
		}},
		{name: "iat_in_future", want: IATInFuture, mutate: func(s *spec) {
			s.IAT = testNow.Add(10 * time.Minute).Unix()
			s.EXP = s.IAT + 300
		}},
		{name: "expired", want: Expired, mutate: func(s *spec) {
			s.IAT = testNow.Add(-5 * time.Minute).Unix()
			s.EXP = testNow.Add(-2 * time.Minute).Unix()
		}},
		{name: "wrong_audience", want: WrongAudience, mutate: func(s *spec) {
			s.Audience = []string{"spire-dev/other-nonce"}
		}},
	}
	for _, tc := range cases {
		t.Run(string(tc.want), func(t *testing.T) {
			rec := k.record(t)
			if tc.rec != nil {
				rec = tc.rec(rec)
			}
			var token string
			if tc.token != nil {
				token = tc.token()
			} else {
				s := k.good()
				if tc.mutate != nil {
					tc.mutate(&s)
				}
				token = s.token(t)
			}
			check(t, rec, token, tc.want)
		})
	}
}

func TestRevokedBeatsEverything(t *testing.T) {
	k := newKeys(t)
	rec := k.record(t)
	rec.Revoked = true
	check(t, rec, "garbage", Revoked)
}

func TestForeignKeyWithSameIssuer(t *testing.T) {
	k := newKeys(t)
	other := newKeys(t)
	s := k.good()
	s.Key, s.KID = other.rsa, "foreign-kid"
	check(t, k.record(t), s.token(t), UnknownKID)
}

func TestForeignKeyWithKnownKid(t *testing.T) {
	k := newKeys(t)
	other := newKeys(t)
	s := k.good()
	s.Key = other.rsa
	check(t, k.record(t), s.token(t), BadSignature)
}

func TestAlgMustMatchKey(t *testing.T) {
	k := newKeys(t)
	s := k.good()
	s.Alg, s.Key = jose.ES256, k.ec
	check(t, k.record(t), s.token(t), AlgNotAllowed)
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestAlgNoneAndHMAC(t *testing.T) {
	k := newKeys(t)
	rec := k.record(t)
	payload := b64(map[string]any{"iss": testIssuer})

	none := b64(map[string]string{"alg": "none", "kid": rsaKID}) + "." + payload + "."
	check(t, rec, none, AlgNotAllowed)

	head := b64(map[string]string{"alg": "HS256", "kid": rsaKID})
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(head + "." + payload))
	hs := head + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	check(t, rec, hs, AlgNotAllowed)
}

func TestSkew(t *testing.T) {
	k := newKeys(t)
	for _, tc := range []struct {
		ahead time.Duration
		want  Reason
	}{{29 * time.Second, ""}, {31 * time.Second, IATInFuture}} {
		s := k.good()
		s.IAT = testNow.Add(tc.ahead).Unix()
		s.EXP = s.IAT + 300
		check(t, k.record(t), s.token(t), tc.want)
	}
}

func TestLifetimeBoundary(t *testing.T) {
	k := newKeys(t)
	for _, tc := range []struct {
		life int64
		want Reason
	}{{900, ""}, {901, LifetimeTooLong}} {
		s := k.good()
		s.IAT = testNow.Add(-time.Minute).Unix()
		s.EXP = s.IAT + tc.life
		check(t, k.record(t), s.token(t), tc.want)
	}
}

func TestTwoAudiences(t *testing.T) {
	k := newKeys(t)
	s := k.good()
	s.Audience = []string{"spire-dev/" + testNonce, "https://kubernetes.default.svc"}
	check(t, k.record(t), s.token(t), WrongAudience)
}

func TestStringAudienceAccepted(t *testing.T) {
	k := newKeys(t)
	s := k.good()
	s.Audience = "spire-dev/" + testNonce
	check(t, k.record(t), s.token(t), "")
}

func TestErrorCarriesNoTokenContents(t *testing.T) {
	k := newKeys(t)
	s := k.good()
	s.Key = newKeys(t).rsa
	token := s.token(t)
	_, err := Validate(k.record(t), token, testEnv, testNonce, testNow)
	if err == nil || strings.Contains(err.Error(), token[:20]) || !strings.Contains(err.Error(), "bad_signature") {
		t.Fatalf("unexpected error %v", err)
	}
	if ReasonOf(errors.New("x")) != "" || ReasonOf(nil) != "" {
		t.Fatal("ReasonOf must return the empty reason for foreign errors")
	}
}

func TestMissingTimeClaims(t *testing.T) {
	k := newKeys(t)
	for _, name := range []string{"exp", "iat"} {
		t.Run(name, func(t *testing.T) {
			s := k.good()
			s.Omit = []string{name}
			check(t, k.record(t), s.token(t), Malformed)
		})
	}
}

func TestMissingAudience(t *testing.T) {
	k := newKeys(t)
	s := k.good()
	s.Omit = []string{"aud"}
	check(t, k.record(t), s.token(t), WrongAudience)
}
