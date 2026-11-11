package kubetoken_test

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

func TestSignerTokensValidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, alg := range []jose.SignatureAlgorithm{jose.ES256, jose.RS256} {
		t.Run(string(alg), func(t *testing.T) {
			s := kubetoken.NewSigner(t, "k1", alg)
			rec := record.Cell{
				Name: "dev-cell-1", Env: "dev", Issuer: "https://issuer", JWKS: s.JWKS(),
				Subjects: []record.Subject{{Namespace: "celld", ServiceAccount: "celld"}},
			}
			tok := s.Token(t, kubetoken.Claims{
				Issuer: "https://issuer", Namespace: "celld", ServiceAccount: "celld", PodName: "p", PodUID: "u",
				NodeName: "n", Audience: []string{"spire-dev/n1"}, IssuedAt: now, Lifetime: 10 * time.Minute,
			})
			claims, err := clusterjwt.Validate(rec, tok, "dev", "n1", now.Add(time.Minute))
			if err != nil || claims.PodUID != "u" || claims.NodeName != "n" {
				t.Fatalf("got %+v %v", claims, err)
			}
			unbound := s.Token(t, kubetoken.Claims{
				Issuer: "https://issuer", Namespace: "celld", ServiceAccount: "celld",
				Audience: []string{"spire-dev/n1"}, IssuedAt: now, Unbound: true,
			})
			_, err = clusterjwt.Validate(rec, unbound, "dev", "n1", now)
			if clusterjwt.ReasonOf(err) != clusterjwt.NotPodBound {
				t.Fatalf("got %v, want not_pod_bound", err)
			}
		})
	}
}
