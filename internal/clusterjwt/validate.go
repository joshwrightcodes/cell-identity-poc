package clusterjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const (
	// MaxTokenLifetime is the longest lifetime that the server accepts for a token.
	MaxTokenLifetime = 15 * time.Minute
	maxIATAge        = 15 * time.Minute
	skew             = 30 * time.Second
	minRSABits       = 2048
)

var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// Claims holds the facts of a validated token.
type Claims struct {
	Namespace, ServiceAccount, PodName, PodUID, NodeName string
	IssuedAt, Expiry                                     time.Time
}

// objectRef is the name and UID pair that the API server writes for each bound object.
type objectRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// kubeClaims is the private claim that the API server adds under "kubernetes.io".
type kubeClaims struct {
	Namespace string     `json:"namespace"`
	Svcacct   objectRef  `json:"serviceaccount"`
	Pod       *objectRef `json:"pod"`
	Node      *objectRef `json:"node"`
}

type tokenClaims struct {
	jwt.Claims
	Kube kubeClaims `json:"kubernetes.io"`
}

// Validate checks a service account token against a cell record. It trusts only the keys in
// rec.JWKS and never reads keys from the token. It returns an *Error that carries a Reason.
func Validate(rec record.Cell, token, env, nonce string, now time.Time) (Claims, error) {
	want := Audience(env, nonce)
	return validate(rec, token, now, func(aud []string) bool {
		return env != "" && nonce != "" && rec.Env == env && singleAudience(aud, want)
	})
}

// ValidateFor runs every check of Validate except the env check, and requires the token to carry
// exactly one audience, equal to audience. An empty audience never matches.
func ValidateFor(rec record.Cell, token, audience string, now time.Time) (Claims, error) {
	return validate(rec, token, now, func(aud []string) bool {
		return audience != "" && singleAudience(aud, audience)
	})
}

// Precheck runs every claim check of Validate without a signature check and without a key lookup,
// so a caller can refuse a bad token before it fetches keys. It returns the same reasons as
// ValidateFor. An empty issuer skips the issuer check, and an empty audience never matches.
func Precheck(token, issuer, audience string, subject record.Subject, now time.Time) error {
	jws, err := jose.ParseSignedCompact(token, allowedAlgs)
	if err != nil {
		return parseFailure(err)
	}
	if len(jws.Signatures) != 1 {
		return fail(Malformed)
	}
	tc, err := decodeClaims(jws.UnsafePayloadWithoutVerification())
	if err != nil {
		return err
	}
	_, err = checkClaims(tc, claimRules{
		issuer: issuer,
		subjectAllowed: func(namespace, serviceAccount string) bool {
			return subject.Namespace == namespace && subject.ServiceAccount == serviceAccount
		},
		audienceOK: func(aud []string) bool { return audience != "" && singleAudience(aud, audience) },
	}, now)
	return err
}

func singleAudience(aud []string, want string) bool {
	return len(aud) == 1 && aud[0] == want
}

func validate(rec record.Cell, token string, now time.Time, audienceOK func([]string) bool) (Claims, error) {
	if rec.Revoked {
		return Claims{}, fail(Revoked)
	}

	jws, err := jose.ParseSignedCompact(token, allowedAlgs)
	if err != nil {
		return Claims{}, parseFailure(err)
	}
	if len(jws.Signatures) != 1 {
		return Claims{}, fail(Malformed)
	}
	head := jws.Signatures[0].Header
	alg := jose.SignatureAlgorithm(head.Algorithm)

	candidates := keysWithID(rec.JWKS, head.KeyID)
	if len(candidates) == 0 {
		return Claims{}, fail(UnknownKID)
	}
	for _, k := range candidates {
		if !keyMatchesAlg(k, alg) {
			return Claims{}, fail(AlgNotAllowed)
		}
	}

	payload, err := verifyAny(jws, candidates)
	if err != nil {
		return Claims{}, fail(BadSignature)
	}
	tc, err := decodeClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	return checkClaims(tc, claimRules{
		issuer:         rec.Issuer,
		subjectAllowed: func(namespace, serviceAccount string) bool { return subjectAllowed(rec, namespace, serviceAccount) },
		audienceOK:     audienceOK,
	}, now)
}

func parseFailure(err error) error {
	var unexpected *jose.ErrUnexpectedSignatureAlgorithm
	if errors.As(err, &unexpected) {
		return fail(AlgNotAllowed)
	}
	return fail(Malformed)
}

func decodeClaims(payload []byte) (tokenClaims, error) {
	var tc tokenClaims
	if err := json.Unmarshal(payload, &tc); err != nil {
		return tc, fail(Malformed)
	}
	if tc.IssuedAt == nil || tc.Expiry == nil {
		return tc, fail(Malformed)
	}
	return tc, nil
}

// claimRules holds what a token is compared with. An empty issuer skips the issuer check.
type claimRules struct {
	issuer         string
	subjectAllowed func(namespace, serviceAccount string) bool
	audienceOK     func([]string) bool
}

func checkClaims(tc tokenClaims, rules claimRules, now time.Time) (Claims, error) {
	if rules.issuer != "" && tc.Issuer != rules.issuer {
		return Claims{}, fail(IssuerMismatch)
	}
	if !rules.subjectAllowed(tc.Kube.Namespace, tc.Kube.Svcacct.Name) ||
		tc.Subject != "system:serviceaccount:"+tc.Kube.Namespace+":"+tc.Kube.Svcacct.Name {
		return Claims{}, fail(SubjectNotAllowed)
	}
	if tc.Kube.Pod == nil || tc.Kube.Pod.UID == "" || tc.Kube.Pod.Name == "" ||
		tc.Kube.Node == nil || tc.Kube.Node.Name == "" {
		return Claims{}, fail(NotPodBound)
	}

	iat, exp := tc.IssuedAt.Time(), tc.Expiry.Time()
	if !exp.After(iat) {
		return Claims{}, fail(Malformed)
	}
	if exp.Sub(iat) > MaxTokenLifetime {
		return Claims{}, fail(LifetimeTooLong)
	}
	if now.Sub(iat) > maxIATAge {
		return Claims{}, fail(StaleIAT)
	}
	if iat.Sub(now) > skew {
		return Claims{}, fail(IATInFuture)
	}
	if tc.NotBefore != nil && tc.NotBefore.Time().Sub(now) > skew {
		return Claims{}, fail(IATInFuture)
	}
	if now.Sub(exp) > skew {
		return Claims{}, fail(Expired)
	}
	if !rules.audienceOK(tc.Audience) {
		return Claims{}, fail(WrongAudience)
	}

	return Claims{
		Namespace:      tc.Kube.Namespace,
		ServiceAccount: tc.Kube.Svcacct.Name,
		PodName:        tc.Kube.Pod.Name,
		PodUID:         tc.Kube.Pod.UID,
		NodeName:       tc.Kube.Node.Name,
		IssuedAt:       iat,
		Expiry:         exp,
	}, nil
}

// keysWithID returns the usable public keys in the key set with the given ID. An empty ID
// matches nothing, and RSA keys under 2048 bits are not usable.
func keysWithID(jwks json.RawMessage, kid string) []jose.JSONWebKey {
	if kid == "" {
		return nil
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil
	}
	var out []jose.JSONWebKey
	for _, raw := range set.Keys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(raw); err != nil || !k.Valid() || !k.IsPublic() || k.KeyID != kid {
			continue
		}
		if pub, ok := k.Key.(*rsa.PublicKey); ok && pub.N.BitLen() < minRSABits {
			continue
		}
		out = append(out, k)
	}
	return out
}

// keyMatchesAlg reports whether the token algorithm equals the algorithm of the key.
func keyMatchesAlg(k jose.JSONWebKey, alg jose.SignatureAlgorithm) bool {
	if k.Algorithm != "" && k.Algorithm != string(alg) {
		return false
	}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		return alg == jose.RS256
	case *ecdsa.PublicKey:
		return alg == jose.ES256 && pub.Curve == elliptic.P256()
	default:
		return false
	}
}

func verifyAny(jws *jose.JSONWebSignature, keys []jose.JSONWebKey) ([]byte, error) {
	for _, k := range keys {
		if payload, err := jws.Verify(k); err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("no key verifies the signature")
}

func subjectAllowed(rec record.Cell, namespace, serviceAccount string) bool {
	for _, s := range rec.Subjects {
		if s.Namespace == namespace && s.ServiceAccount == serviceAccount {
			return true
		}
	}
	return false
}
