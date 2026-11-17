package satoken

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
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

type deadlineGetter struct {
	corev1client.ServiceAccountInterface
	deadline *time.Time
	has      *bool
}

func (d deadlineGetter) ServiceAccounts(string) corev1client.ServiceAccountInterface { return d }

func (d deadlineGetter) CreateToken(ctx context.Context, _ string, _ *authenticationv1.TokenRequest, _ metav1.CreateOptions) (*authenticationv1.TokenRequest, error) {
	*d.deadline, *d.has = ctx.Deadline()
	return &authenticationv1.TokenRequest{Status: authenticationv1.TokenRequestStatus{Token: "tok"}}, nil
}

func TestSATokenCreateHasEightSecondTimeout(t *testing.T) {
	var deadline time.Time
	var has bool
	start := time.Now()
	_, err := Create(context.Background(), deadlineGetter{deadline: &deadline, has: &has}, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("the TokenRequest has no deadline")
	}
	if d := deadline.Sub(start); d > 9*time.Second || d < 7*time.Second {
		t.Fatalf("deadline is %v away, want 8s", d)
	}
	if RequestTimeout != 8*time.Second {
		t.Fatalf("RequestTimeout = %v", RequestTimeout)
	}
}

func validRequest() Request {
	return Request{Namespace: "n", ServiceAccount: "s", PodName: "p", PodUID: "u", Audience: "a", TTL: 10 * time.Minute}
}

func TestSATokenCreateRefusesEmptyFields(t *testing.T) {
	for name, edit := range map[string]func(*Request){
		"namespace": func(r *Request) { r.Namespace = "" }, "service_account": func(r *Request) { r.ServiceAccount = "" },
		"audience": func(r *Request) { r.Audience = "" }, "pod_name": func(r *Request) { r.PodName = "" },
		"pod_uid": func(r *Request) { r.PodUID = "" }, "ttl": func(r *Request) { r.TTL = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			var reqs []*authenticationv1.TokenRequest
			var names []string
			c := fakeWith(t, "tok", nil, &reqs, &names)
			r := validRequest()
			edit(&r)
			if _, err := Create(context.Background(), c.CoreV1(), r); err == nil {
				t.Fatal("expected an error")
			}
			if len(reqs) != 0 {
				t.Fatal("a refused request reached the API")
			}
		})
	}
}

func TestPodTokenFunc(t *testing.T) {
	var reqs []*authenticationv1.TokenRequest
	var names []string
	c := fakeWith(t, "tok", nil, &reqs, &names)
	var tf TokenFunc = PodTokenFunc(c.CoreV1(), "cell-identity-system", "celld", "celld-0", "uid-1")
	tok, err := tf(context.Background(), "mgmt-report/dev-cell-1/result/abc")
	if err != nil || tok != "tok" {
		t.Fatalf("got %q %v", tok, err)
	}
	if len(reqs) != 1 || names[0] != "cell-identity-system/celld" {
		t.Fatalf("requests %v %v", reqs, names)
	}
	s := reqs[0].Spec
	if len(s.Audiences) != 1 || s.Audiences[0] != "mgmt-report/dev-cell-1/result/abc" {
		t.Fatalf("audiences %v", s.Audiences)
	}
	if s.ExpirationSeconds == nil || *s.ExpirationSeconds != 600 {
		t.Fatalf("expiration %v", s.ExpirationSeconds)
	}
	if r := s.BoundObjectRef; r == nil || r.Kind != "Pod" || r.Name != "celld-0" || string(r.UID) != "uid-1" {
		t.Fatalf("boundObjectRef %+v", r)
	}
	if _, err := tf(context.Background(), ""); err == nil {
		t.Fatal("an empty audience made a token")
	}
	for i := 0; i < 2; i++ {
		if _, err := tf(context.Background(), "a"); err != nil {
			t.Fatal(err)
		}
	}
	if len(reqs) != 3 {
		t.Fatalf("each call must make a new request, got %d", len(reqs))
	}
}

func TestPodTokenFuncFromEnvRequiresAll(t *testing.T) {
	var reqs []*authenticationv1.TokenRequest
	var names []string
	c := fakeWith(t, "tok", nil, &reqs, &names)
	all := map[string]string{
		EnvPodName: "celld-0", EnvPodUID: "uid-1", EnvPodNamespace: "cell-identity-system", EnvServiceAccount: "celld",
	}
	set := func(skip string) {
		for k, v := range all {
			if k == skip {
				v = ""
			}
			t.Setenv(k, v)
		}
	}
	for name := range all {
		set(name)
		if _, err := PodTokenFuncFromEnv(c.CoreV1()); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("empty %s: got %v", name, err)
		}
	}
	set("")
	tf, err := PodTokenFuncFromEnv(c.CoreV1())
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := tf(context.Background(), "aud"); err != nil || tok != "tok" {
		t.Fatalf("got %q %v", tok, err)
	}
	if names[0] != "cell-identity-system/celld" || reqs[0].Spec.BoundObjectRef.Name != "celld-0" || string(reqs[0].Spec.BoundObjectRef.UID) != "uid-1" {
		t.Fatalf("request %v %+v", names, reqs[0].Spec.BoundObjectRef)
	}
}
