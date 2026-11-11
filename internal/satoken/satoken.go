// Package satoken requests a service account token that is bound to one pod.
package satoken

import (
	"context"
	"errors"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	// RequestTimeout is the longest time that one TokenRequest may take. It stays below the
	// challenge timeout of the SPIRE server, so a slow API server ends as a client error.
	RequestTimeout = 8 * time.Second

	boundObjectKind = "Pod"
	boundObjectAPIV = "v1"
)

// Request names the service account, the pod to bind to, and the one audience of the token.
type Request struct {
	Namespace, ServiceAccount, PodName, PodUID, Audience string
	TTL                                                  time.Duration
}

// Create makes one TokenRequest for the service account. The token binds to the pod by name and UID.
func Create(ctx context.Context, c corev1client.ServiceAccountsGetter, r Request) (string, error) {
	if r.TTL < time.Second {
		return "", errors.New("token lifetime must be at least one second")
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	seconds := int64(r.TTL / time.Second)
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{r.Audience},
			ExpirationSeconds: &seconds,
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				APIVersion: boundObjectAPIV, Kind: boundObjectKind, Name: r.PodName, UID: apitypes.UID(r.PodUID),
			},
		},
	}
	out, err := c.ServiceAccounts(r.Namespace).CreateToken(ctx, r.ServiceAccount, req, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	if out == nil || strings.TrimSpace(out.Status.Token) == "" {
		return "", errors.New("the API returned no token")
	}
	return out.Status.Token, nil
}
