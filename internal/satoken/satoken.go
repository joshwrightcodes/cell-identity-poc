// Package satoken requests a service account token that is bound to one pod.
package satoken

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	if r.Namespace == "" || r.ServiceAccount == "" || r.Audience == "" || r.PodName == "" || r.PodUID == "" {
		return "", errors.New("token request needs a namespace, service account, audience, pod name and pod UID")
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

// TokenFunc returns a token whose only audience is audience.
type TokenFunc func(ctx context.Context, audience string) (string, error)

// PodTokenTTL is the lifetime of a token that PodTokenFunc requests.
const PodTokenTTL = 600 * time.Second

// Names of the downward API variables that identify the pod of celld. They equal the names in
// package clusterjwt, which imports this package and so cannot be imported here.
const (
	EnvPodName        = "POD_NAME"
	EnvPodUID         = "POD_UID"
	EnvPodNamespace   = "POD_NAMESPACE"
	EnvServiceAccount = "SERVICE_ACCOUNT"
)

// PodTokenFunc returns a TokenFunc that requests a token of 600 s for the service account, bound
// to the pod. Each call makes a new TokenRequest.
func PodTokenFunc(c corev1client.ServiceAccountsGetter, namespace, serviceAccount, podName, podUID string) TokenFunc {
	return func(ctx context.Context, audience string) (string, error) {
		return Create(ctx, c, Request{
			Namespace: namespace, ServiceAccount: serviceAccount, PodName: podName, PodUID: podUID,
			Audience: audience, TTL: PodTokenTTL,
		})
	}
}

// PodTokenFuncFromEnv is PodTokenFunc with the pod identity from the four environment variables of
// the pod. It fails when any one is empty.
func PodTokenFuncFromEnv(c corev1client.ServiceAccountsGetter) (TokenFunc, error) {
	var v [4]string
	for i, name := range []string{EnvPodNamespace, EnvServiceAccount, EnvPodName, EnvPodUID} {
		if v[i] = os.Getenv(name); v[i] == "" {
			return nil, fmt.Errorf("environment variable %s is empty", name)
		}
	}
	return PodTokenFunc(c, v[0], v[1], v[2], v[3]), nil
}
