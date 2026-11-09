package cellproxy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// example is one request of an allow-list table.
type example struct {
	name, method, target string
}

// allowedExamples cover each read that Kiali v2.34.0 makes against a remote cluster, as the M3
// research table lists them (discovery, informers, Istio and Gateway API resources, direct reads,
// the webhook check and the review probe).
var allowedExamples = []example{
	{"GET /api", "GET", "/api"},
	{"GET /api/v1", "GET", "/api/v1"},
	{"GET /apis", "GET", "/apis"},
	{"GET /apis/apps", "GET", "/apis/apps"},
	{"GET /apis/networking.istio.io/v1", "GET", "/apis/networking.istio.io/v1"},
	{"GET /apis/gateway.networking.k8s.io/v1beta1", "GET", "/apis/gateway.networking.k8s.io/v1beta1"},
	{"GET /version", "GET", "/version"},

	{"list pods", "GET", "/api/v1/pods"},
	{"watch pods", "GET", "/api/v1/pods?watch=true&resourceVersion=12&allowWatchBookmarks=true&timeoutSeconds=300"},
	{"list pods with paging", "GET", "/api/v1/pods?limit=500&continue=abc&resourceVersion=0&resourceVersionMatch=NotOlderThan"},
	{"list pods by selector", "GET", "/api/v1/pods?labelSelector=app%3Dx&fieldSelector=spec.nodeName%3Dn"},
	{"watch pods with initial events", "GET", "/api/v1/pods?watch=1&sendInitialEvents=true&resourceVersionMatch=NotOlderThan"},
	{"list pods in a namespace", "GET", "/api/v1/namespaces/apps-demo/pods"},
	{"get one pod", "GET", "/api/v1/namespaces/apps-demo/pods/web-0"},
	{"list services", "GET", "/api/v1/services"},
	{"get one service", "GET", "/api/v1/namespaces/apps-demo/services/web"},
	{"list namespaces", "GET", "/api/v1/namespaces"},
	{"get one namespace", "GET", "/api/v1/namespaces/apps-demo"},
	{"list replicationcontrollers", "GET", "/api/v1/replicationcontrollers"},
	{"list replicationcontrollers in a namespace", "GET", "/api/v1/namespaces/apps-demo/replicationcontrollers"},

	{"list deployments", "GET", "/apis/apps/v1/deployments"},
	{"get one deployment", "GET", "/apis/apps/v1/namespaces/apps-demo/deployments/web"},
	{"list replicasets", "GET", "/apis/apps/v1/replicasets"},
	{"list statefulsets", "GET", "/apis/apps/v1/statefulsets"},
	{"watch daemonsets", "GET", "/apis/apps/v1/daemonsets?watch=true"},
	{"list jobs", "GET", "/apis/batch/v1/jobs"},
	{"list cronjobs in a namespace", "GET", "/apis/batch/v1/namespaces/apps-demo/cronjobs"},

	{"list gateways (istio)", "GET", "/apis/networking.istio.io/v1/gateways"},
	{"list destinationrules", "GET", "/apis/networking.istio.io/v1/destinationrules"},
	{"list sidecars", "GET", "/apis/networking.istio.io/v1/sidecars"},
	{"list serviceentries", "GET", "/apis/networking.istio.io/v1/serviceentries"},
	{"watch virtualservices", "GET", "/apis/networking.istio.io/v1/virtualservices?watch=true"},
	{"list workloadentries", "GET", "/apis/networking.istio.io/v1/workloadentries"},
	{"list workloadgroups", "GET", "/apis/networking.istio.io/v1/workloadgroups"},
	{"list envoyfilters", "GET", "/apis/networking.istio.io/v1alpha3/envoyfilters"},
	{"list wasmplugins", "GET", "/apis/extensions.istio.io/v1alpha1/wasmplugins"},
	{"list trafficextensions", "GET", "/apis/extensions.istio.io/v1alpha1/trafficextensions"},
	{"list authorizationpolicies", "GET", "/apis/security.istio.io/v1/authorizationpolicies"},
	{"list peerauthentications", "GET", "/apis/security.istio.io/v1/peerauthentications"},
	{"get one requestauthentication", "GET", "/apis/security.istio.io/v1/namespaces/apps-demo/requestauthentications/jwt"},
	{"list telemetries", "GET", "/apis/telemetry.istio.io/v1/telemetries"},

	{"list gatewayclasses", "GET", "/apis/gateway.networking.k8s.io/v1/gatewayclasses"},
	{"get one gatewayclass", "GET", "/apis/gateway.networking.k8s.io/v1/gatewayclasses/istio"},
	{"list gateways (gateway api)", "GET", "/apis/gateway.networking.k8s.io/v1/gateways"},
	{"list httproutes", "GET", "/apis/gateway.networking.k8s.io/v1/httproutes"},
	{"list grpcroutes", "GET", "/apis/gateway.networking.k8s.io/v1/grpcroutes"},
	{"list referencegrants", "GET", "/apis/gateway.networking.k8s.io/v1beta1/referencegrants"},
	{"list tlsroutes", "GET", "/apis/gateway.networking.k8s.io/v1/tlsroutes"},
	{"list tcproutes", "GET", "/apis/gateway.networking.k8s.io/v1alpha2/tcproutes"},
	{"list udproutes", "GET", "/apis/gateway.networking.k8s.io/v1alpha2/udproutes"},
	{"list inferencepools", "GET", "/apis/inference.networking.k8s.io/v1/inferencepools"},

	{"list mutatingwebhookconfigurations", "GET", "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"},
	{"get one mutatingwebhookconfiguration", "GET", "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/istio-revision-tag-default"},

	{"list configmaps in istio-system", "GET", "/api/v1/namespaces/istio-system/configmaps"},
	{"get one configmap in istio-system", "GET", "/api/v1/namespaces/istio-system/configmaps/istio"},
	{"watch configmaps in istio-system", "GET", "/api/v1/namespaces/istio-system/configmaps?watch=true"},

	{"POST selfsubjectaccessreviews", "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"},
}

// deniedExamples must never reach the API. Each name that starts with "secrets" asks for a Secret.
var deniedExamples = []example{
	{"secrets list", "GET", "/api/v1/secrets"},
	{"secrets list in a namespace", "GET", "/api/v1/namespaces/argocd/secrets"},
	{"secrets watch", "GET", "/api/v1/namespaces/argocd/secrets?watch=true"},
	{"secrets get", "GET", "/api/v1/namespaces/argocd/secrets/argocd-redis"},

	{"pods log", "GET", "/api/v1/namespaces/apps-demo/pods/web-0/log"},
	{"pods exec GET", "GET", "/api/v1/namespaces/apps-demo/pods/web-0/exec?command=sh"},
	{"pods exec POST", "POST", "/api/v1/namespaces/apps-demo/pods/web-0/exec"},
	{"pods attach", "POST", "/api/v1/namespaces/apps-demo/pods/web-0/attach"},
	{"pods portforward", "POST", "/api/v1/namespaces/istio-system/pods/istiod-0/portforward"},
	{"pods portforward GET", "GET", "/api/v1/namespaces/istio-system/pods/istiod-0/portforward"},
	{"pods proxy", "GET", "/api/v1/namespaces/apps-demo/pods/web-0/proxy"},
	{"pods proxy path", "GET", "/api/v1/namespaces/apps-demo/pods/web-0:8080/proxy/debug"},
	{"pods status", "GET", "/api/v1/namespaces/apps-demo/pods/web-0/status"},
	{"pods ephemeralcontainers", "GET", "/api/v1/namespaces/apps-demo/pods/web-0/ephemeralcontainers"},
	{"services proxy", "GET", "/api/v1/namespaces/apps-demo/services/web/proxy"},
	{"services proxy path", "GET", "/api/v1/namespaces/apps-demo/services/web:80/proxy/admin"},
	{"deployments scale", "GET", "/apis/apps/v1/namespaces/apps-demo/deployments/web/scale"},
	{"namespaces status", "GET", "/api/v1/namespaces/apps-demo/status"},
	{"namespaces finalize", "GET", "/api/v1/namespaces/apps-demo/finalize"},

	{"configmaps in argocd", "GET", "/api/v1/namespaces/argocd/configmaps"},
	{"one configmap in argocd", "GET", "/api/v1/namespaces/argocd/configmaps/argocd-cm"},
	{"configmaps cluster-wide", "GET", "/api/v1/configmaps"},
	{"configmaps watch cluster-wide", "GET", "/api/v1/configmaps?watch=true"},

	{"legacy watch pods", "GET", "/api/v1/watch/pods"},
	{"legacy watch pods in a namespace", "GET", "/api/v1/watch/namespaces/apps-demo/pods"},
	{"legacy watch configmaps in istio-system", "GET", "/api/v1/watch/namespaces/istio-system/configmaps"},
	{"legacy watch deployments", "GET", "/apis/apps/v1/watch/deployments"},
	{"legacy watch virtualservices", "GET", "/apis/networking.istio.io/v1/watch/namespaces/apps-demo/virtualservices"},

	{"serviceaccounts", "GET", "/api/v1/serviceaccounts"},
	{"serviceaccounts token", "POST", "/api/v1/namespaces/argocd/serviceaccounts/argocd-agent/token"},
	{"nodes", "GET", "/api/v1/nodes"},
	{"nodes proxy", "GET", "/api/v1/nodes/n1/proxy/metrics"},
	{"applications", "GET", "/apis/argoproj.io/v1alpha1/applications"},
	{"roles", "GET", "/apis/rbac.authorization.k8s.io/v1/roles"},
	{"validatingwebhookconfigurations", "GET", "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"},
	{"customresourcedefinitions", "GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"},
	{"openapi", "GET", "/openapi/v3"},
	{"healthz", "GET", "/healthz"},
	{"metrics", "GET", "/metrics"},
	{"root", "GET", "/"},
	{"version item", "GET", "/version/x"},
	{"pods cluster-wide item", "GET", "/api/v1/pods/web-0"},
	{"namespaced resource under a cluster path", "GET", "/apis/apps/v1/deployments/web"},
	{"cluster resource under a namespace", "GET", "/apis/gateway.networking.k8s.io/v1/namespaces/apps-demo/gatewayclasses"},
	{"group with no version path", "GET", "/apis/apps/deployments/web"},
	{"core under apis", "GET", "/apis/core/v1/pods"},
	{"unknown version shape", "GET", "/apis/apps/latest/deployments"},

	{"POST pods", "POST", "/api/v1/namespaces/apps-demo/pods"},
	{"PUT pod", "PUT", "/api/v1/namespaces/apps-demo/pods/web-0"},
	{"PATCH pod", "PATCH", "/api/v1/namespaces/apps-demo/pods/web-0"},
	{"DELETE pod", "DELETE", "/api/v1/namespaces/apps-demo/pods/web-0"},
	{"DELETE pods collection", "DELETE", "/api/v1/namespaces/apps-demo/pods"},
	{"DELETE namespace", "DELETE", "/api/v1/namespaces/apps-demo"},
	{"POST namespaces", "POST", "/api/v1/namespaces"},
	{"PATCH deployment", "PATCH", "/apis/apps/v1/namespaces/apps-demo/deployments/web"},
	{"POST virtualservices", "POST", "/apis/networking.istio.io/v1/namespaces/apps-demo/virtualservices"},
	{"PUT configmap in istio-system", "PUT", "/api/v1/namespaces/istio-system/configmaps/istio"},
	{"PATCH mutatingwebhookconfiguration", "PATCH", "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/istio-sidecar-injector"},
	{"DELETE mutatingwebhookconfiguration", "DELETE", "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/istio-sidecar-injector"},
	{"POST discovery", "POST", "/api/v1"},
	{"HEAD pods", "HEAD", "/api/v1/pods"},
	{"OPTIONS pods", "OPTIONS", "/api/v1/pods"},
	{"GET selfsubjectaccessreviews", "GET", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"},
	{"PUT selfsubjectaccessreviews", "PUT", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"},
	{"PATCH selfsubjectaccessreviews", "PATCH", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"},
	{"DELETE selfsubjectaccessreviews", "DELETE", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"},
	{"POST selfsubjectaccessreviews v1beta1", "POST", "/apis/authorization.k8s.io/v1beta1/selfsubjectaccessreviews"},
	{"POST selfsubjectaccessreviews with a name", "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews/x"},
	{"POST selfsubjectaccessreviews with dryRun", "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews?dryRun=All"},
	{"POST subjectaccessreviews", "POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews"},
	{"POST selfsubjectrulesreviews", "POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"},
	{"POST tokenreviews", "POST", "/apis/authentication.k8s.io/v1/tokenreviews"},
	{"POST tokenrequests", "POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews"},
}

// canonicalExamples are paths and queries that are not in canonical form. A nil body sends none.
var canonicalExamples = []struct {
	name, method, target string
	body                 []byte
}{
	{"dot-dot segment", "GET", "/api/v1/namespaces/istio-system/configmaps/../secrets", nil},
	{"escaped slash", "GET", "/api/v1/namespaces/istio-system%2Fconfigmaps", nil},
	{"empty segment", "GET", "/api/v1//pods", nil},
	{"trailing slash", "GET", "/api/v1/pods/", nil},
	{"upper case", "GET", "/API/v1/pods", nil},
	{"repeated watch key", "GET", "/api/v1/pods?watch=true&watch=false", nil},
	{"unknown query key", "GET", "/api/v1/pods?pretty=true", nil},
	{"review body of 65 KiB", "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", []byte(strings.Repeat("a", 65<<10))},
}

func parseTarget(t *testing.T, target string) *url.URL {
	t.Helper()
	u, err := url.ParseRequestURI(target)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAllowListTable(t *testing.T) {
	for _, e := range allowedExamples {
		t.Run("allowed/"+e.name, func(t *testing.T) {
			if !Allowed(e.method, parseTarget(t, e.target)) {
				t.Fatalf("%s %s is denied, want allowed", e.method, e.target)
			}
		})
	}
	for _, e := range deniedExamples {
		t.Run("denied/"+e.name, func(t *testing.T) {
			if Allowed(e.method, parseTarget(t, e.target)) {
				t.Fatalf("%s %s is allowed, want denied", e.method, e.target)
			}
		})
	}
}

func TestAllowListCanonicalPaths(t *testing.T) {
	api := newFakeAPI(t)
	h := NewCellHandler(api.url(), api.transport(t), jsonLog(&syncBuffer{}))
	for _, c := range canonicalExamples {
		t.Run(c.name, func(t *testing.T) {
			if c.body == nil && Allowed(c.method, parseTarget(t, c.target)) {
				t.Errorf("Allowed accepts %s %s", c.method, c.target)
			}
			before := api.hits.Load()
			rec := serveCell(t, h, c.method, c.target, c.body, nil)
			assertDenied(t, rec.Code, rec.Body.Bytes())
			if n := api.hits.Load() - before; n != 0 {
				t.Fatalf("the API got %d requests for %s %s", n, c.method, c.target)
			}
		})
	}
}

func TestCanonicalPath(t *testing.T) {
	good := map[string]string{
		"/api/v1/pods":        "/api/v1/pods",
		"/version":            "/version",
		"/api/v1/pods?x=%2F":  "/api/v1/pods",
		"/apis/apps/v1/a-b.c": "/apis/apps/v1/a-b.c",
	}
	for target, want := range good {
		got, ok := CanonicalPath(parseTarget(t, target))
		if !ok || got != want {
			t.Errorf("CanonicalPath(%s) = %q, %v; want %q, true", target, got, ok, want)
		}
	}
	bad := []*url.URL{
		{Path: "/api/v1/pods/."},
		{Path: "/api/./v1"},
		{Path: "/api/v1/pod%s"},
		{Path: "/api/v1/pöds"},
		{Path: "/api/v1/po ds"},
		{Path: "api/v1/pods"},
		{Path: ""},
		{Path: "/"},
		{Path: "/api/v1/pods", RawPath: "/api/v1/p%6Fds"},
		{Opaque: "/api/v1/pods"},
	}
	for _, u := range bad {
		if got, ok := CanonicalPath(u); ok {
			t.Errorf("CanonicalPath(%#v) = %q, true; want false", u, got)
		}
	}
}

func TestDeniedRequestsNeverReachAPI(t *testing.T) {
	api := newFakeAPI(t)
	h := NewCellHandler(api.url(), api.transport(t), jsonLog(&syncBuffer{}))
	for _, e := range deniedExamples {
		t.Run(e.name, func(t *testing.T) {
			var body []byte
			if e.method == http.MethodPost || e.method == http.MethodPut || e.method == http.MethodPatch {
				body = []byte(`{"kind":"Pod"}`)
			}
			rec := serveCell(t, h, e.method, e.target, body, nil)
			assertDenied(t, rec.Code, rec.Body.Bytes())
		})
	}
	for _, c := range canonicalExamples {
		t.Run("canonical/"+c.name, func(t *testing.T) {
			rec := serveCell(t, h, c.method, c.target, c.body, nil)
			assertDenied(t, rec.Code, rec.Body.Bytes())
		})
	}
	if n := api.hits.Load(); n != 0 {
		t.Fatalf("the API got %d requests, want 0", n)
	}
}
