package cellproxy

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

// TokenReview is the answer of the API server to one review of a bearer token. Audiences holds
// the audiences of the request that the token matches.
type TokenReview struct {
	Authenticated bool
	Username      string
	Audiences     []string
	Error         string
}

// TokenReviewer asks the API server who owns a bearer token for one audience. An error means the
// reviewer could not get an answer. A token that the API server refuses is not an error: it gives
// a TokenReview that is not authenticated.
type TokenReviewer interface {
	Review(ctx context.Context, token, audience string) (TokenReview, error)
}

// KubeReviewer reviews tokens through the TokenReview API of a cluster.
type KubeReviewer struct {
	Reviews authenticationv1client.TokenReviewInterface
}

// Review creates a TokenReview that names audience.
func (k *KubeReviewer) Review(ctx context.Context, token, audience string) (TokenReview, error) {
	res, err := k.Reviews.Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{audience}},
	}, metav1.CreateOptions{})
	if err != nil {
		return TokenReview{}, fmt.Errorf("token review: %w", err)
	}
	return TokenReview{
		Authenticated: res.Status.Authenticated,
		Username:      res.Status.User.Username,
		Audiences:     res.Status.Audiences,
		Error:         res.Status.Error,
	}, nil
}
