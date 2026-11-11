package satoken

import (
	"context"
	"errors"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func fakeWith(t *testing.T, token string, err error, got *[]*authenticationv1.TokenRequest, ns *[]string) *fake.Clientset {
	t.Helper()
	c := fake.NewSimpleClientset()
	c.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(k8stesting.CreateAction)
		if !ok || a.GetSubresource() != "token" {
			return false, nil, nil
		}
		if err != nil {
			return true, nil, err
		}
		tr := ca.GetObject().(*authenticationv1.TokenRequest).DeepCopy()
		*got = append(*got, tr)
		*ns = append(*ns, a.GetNamespace()+"/"+ca.(k8stesting.CreateActionImpl).Name)
		tr.Status.Token = token
		return true, tr, nil
	})
	return c
}

func TestSATokenCreate(t *testing.T) {
	var reqs []*authenticationv1.TokenRequest
	var names []string
	c := fakeWith(t, "tok", nil, &reqs, &names)
	tok, err := Create(context.Background(), c.CoreV1(), Request{
		Namespace: "cell-identity-system", ServiceAccount: "celld", PodName: "celld-0", PodUID: "uid-1",
		Audience: "mgmt-bind/dev-cell-1/n1", TTL: 10 * time.Minute,
	})
	if err != nil || tok != "tok" {
		t.Fatalf("got %q %v", tok, err)
	}
	if len(reqs) != 1 || names[0] != "cell-identity-system/celld" {
		t.Fatalf("requests %v %v", reqs, names)
	}
	spec := reqs[0].Spec
	if len(spec.Audiences) != 1 || spec.Audiences[0] != "mgmt-bind/dev-cell-1/n1" {
		t.Fatalf("audiences %v", spec.Audiences)
	}
	if spec.ExpirationSeconds == nil || *spec.ExpirationSeconds != 600 {
		t.Fatalf("expiration %v", spec.ExpirationSeconds)
	}
	ref := spec.BoundObjectRef
	if ref == nil || ref.Kind != "Pod" || ref.APIVersion != "v1" || ref.Name != "celld-0" || string(ref.UID) != "uid-1" {
		t.Fatalf("boundObjectRef %+v", ref)
	}
}

func TestSATokenCreateEmptyTokenIsError(t *testing.T) {
	var reqs []*authenticationv1.TokenRequest
	var names []string
	c := fakeWith(t, "  ", nil, &reqs, &names)
	if _, err := Create(context.Background(), c.CoreV1(), Request{Namespace: "n", ServiceAccount: "s", PodName: "p", PodUID: "u", Audience: "a", TTL: 10 * time.Minute}); err == nil {
		t.Fatal("expected an error for an empty token")
	}
}

func TestSATokenCreatePassesAPIError(t *testing.T) {
	boom := errors.New("boom")
	var reqs []*authenticationv1.TokenRequest
	var names []string
	c := fakeWith(t, "", boom, &reqs, &names)
	if _, err := Create(context.Background(), c.CoreV1(), Request{Namespace: "n", ServiceAccount: "s", PodName: "p", PodUID: "u", Audience: "a", TTL: 10 * time.Minute}); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}
