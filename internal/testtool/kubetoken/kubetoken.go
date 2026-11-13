// Package kubetoken makes service account tokens that look like the ones the Kubernetes API server
// issues, for tests. It is not for production code.
package kubetoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Signer signs tokens with one key.
type Signer struct {
	kid string
	alg jose.SignatureAlgorithm
	key any
	pub any
}

// NewSigner makes a key for alg, which is RS256 or ES256.
func NewSigner(t testing.TB, kid string, alg jose.SignatureAlgorithm) *Signer {
	t.Helper()
	s := &Signer{kid: kid, alg: alg}
	switch alg {
	case jose.RS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		s.key, s.pub = k, &k.PublicKey
	case jose.ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s.key, s.pub = k, &k.PublicKey
	default:
		t.Fatalf("kubetoken: unsupported algorithm %q", alg)
	}
	return s
}

// JWKS returns the public key as a JSON key set.
func (s *Signer) JWKS() json.RawMessage {
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: s.pub, KeyID: s.kid}}})
	if err != nil {
		panic(err)
	}
	return raw
}

// Claims describes one token. A zero IssuedAt means the current time, and a zero Lifetime means
// ten minutes. Unbound leaves out the pod and node references.
type Claims struct {
	Issuer, Namespace, ServiceAccount, PodName, PodUID, NodeName string
	Audience                                                     []string
	IssuedAt                                                     time.Time
	Lifetime                                                     time.Duration
	Unbound                                                      bool
}

type ref struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type kube struct {
	Namespace string `json:"namespace"`
	Svcacct   ref    `json:"serviceaccount"`
	Pod       *ref   `json:"pod,omitempty"`
	Node      *ref   `json:"node,omitempty"`
}

// Token returns a signed compact token for c.
func (s *Signer) Token(t testing.TB, c Claims) string {
	t.Helper()
	iat := c.IssuedAt
	if iat.IsZero() {
		iat = time.Now()
	}
	life := c.Lifetime
	if life == 0 {
		life = 10 * time.Minute
	}
	k := kube{Namespace: c.Namespace, Svcacct: ref{Name: c.ServiceAccount, UID: "sa-uid"}}
	if !c.Unbound {
		k.Pod = &ref{Name: c.PodName, UID: c.PodUID}
		k.Node = &ref{Name: c.NodeName, UID: "node-uid"}
	}
	body, err := json.Marshal(map[string]any{
		"iss": c.Issuer, "aud": c.Audience, "iat": iat.Unix(), "exp": iat.Add(life).Unix(),
		"sub":           "system:serviceaccount:" + c.Namespace + ":" + c.ServiceAccount,
		"kubernetes.io": k,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: s.key}, opts)
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
