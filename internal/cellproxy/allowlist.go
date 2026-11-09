package cellproxy

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// scope says where a resource lives: in a namespace, or once for the whole cluster.
type scope int

const (
	namespaced scope = iota
	clusterWide
)

const (
	reviewGroup    = "authorization.k8s.io"
	reviewPath     = "/apis/" + reviewGroup + "/v1/selfsubjectaccessreviews"
	configMapNS    = "istio-system"
	configMapsName = "configmaps"
)

// coreResources are the resources under /api/v1 that Kiali v2.34.0 reads from a remote cluster:
// informers (pods, services) and direct reads (namespaces, replicationcontrollers, ConfigMaps).
// ConfigMaps are allowed only in istio-system, where Kiali reads the mesh config.
var coreResources = map[string]scope{
	"pods":                   namespaced,
	"services":               namespaced,
	"namespaces":             clusterWide,
	"replicationcontrollers": namespaced,
	configMapsName:           namespaced,
}

// groupResources are the resources under /apis/<group>/<version> that Kiali v2.34.0 reads, as
// the M3 research table lists them (kubernetes/types.go and cmd/server.go in the Kiali source).
var groupResources = map[string]map[string]scope{
	"apps":  {"deployments": namespaced, "replicasets": namespaced, "statefulsets": namespaced, "daemonsets": namespaced},
	"batch": {"jobs": namespaced, "cronjobs": namespaced},
	"networking.istio.io": {
		"gateways": namespaced, "destinationrules": namespaced, "sidecars": namespaced, "serviceentries": namespaced,
		"virtualservices": namespaced, "workloadentries": namespaced, "workloadgroups": namespaced, "envoyfilters": namespaced,
	},
	"security.istio.io":   {"authorizationpolicies": namespaced, "peerauthentications": namespaced, "requestauthentications": namespaced},
	"telemetry.istio.io":  {"telemetries": namespaced},
	"extensions.istio.io": {"wasmplugins": namespaced, "trafficextensions": namespaced},
	"gateway.networking.k8s.io": {
		"gatewayclasses": clusterWide, "gateways": namespaced, "httproutes": namespaced, "grpcroutes": namespaced,
		"referencegrants": namespaced, "tlsroutes": namespaced, "tcproutes": namespaced, "udproutes": namespaced,
	},
	"inference.networking.k8s.io":  {"inferencepools": namespaced},
	"admissionregistration.k8s.io": {"mutatingwebhookconfigurations": clusterWide},
}

// queryKeys are the only query keys that a request may carry, each at most once.
var queryKeys = map[string]bool{
	"watch": true, "resourceVersion": true, "resourceVersionMatch": true, "labelSelector": true, "fieldSelector": true,
	"limit": true, "continue": true, "timeoutSeconds": true, "allowWatchBookmarks": true, "sendInitialEvents": true,
}

var (
	groupName  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	apiVersion = regexp.MustCompile(`^v[1-9][0-9]*((alpha|beta)[1-9][0-9]*)?$`)
)

// Allowed reports whether the mesh-view tunnel may send a request to the Kubernetes API. It
// allows GET on discovery paths, /version, and the collection, object and watch paths of the
// resources that Kiali reads, and POST on the self subject access review path. The path must
// be canonical, and the query may hold only the keys in queryKeys, each once. Everything else
// is denied, every subresource and the legacy watch paths included.
func Allowed(method string, u *url.URL) bool {
	p, ok := CanonicalPath(u)
	if !ok || !queryAllowed(u.RawQuery) {
		return false
	}
	switch method {
	case http.MethodPost:
		return p == reviewPath
	case http.MethodGet:
		return readAllowed(strings.Split(p[1:], "/"))
	}
	return false
}

func queryAllowed(raw string) bool {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return false
	}
	for k, vs := range q {
		if !queryKeys[k] || len(vs) != 1 {
			return false
		}
	}
	return true
}

func readAllowed(segs []string) bool {
	switch {
	case len(segs) == 1:
		return segs[0] == "api" || segs[0] == "apis" || segs[0] == "version"
	case segs[0] == "api":
		if segs[1] != "v1" {
			return false
		}
		return resourceAllowed(coreResources, segs[2:])
	case segs[0] == "apis":
		if !groupName.MatchString(segs[1]) {
			return false
		}
		if len(segs) == 2 {
			return true
		}
		if !apiVersion.MatchString(segs[2]) {
			return false
		}
		if len(segs) == 3 {
			return true
		}
		resources, ok := groupResources[segs[1]]
		return ok && resourceAllowed(resources, segs[3:])
	}
	return false
}

// resourceAllowed checks the part of a path after the group version: a collection
// (<resource>), a cluster object (<resource>/<name>), a namespaced collection
// (namespaces/<ns>/<resource>) or a namespaced object (namespaces/<ns>/<resource>/<name>).
func resourceAllowed(resources map[string]scope, rest []string) bool {
	switch len(rest) {
	case 0:
		return true
	case 1:
		_, ok := resources[rest[0]]
		return ok && rest[0] != configMapsName
	case 2:
		s, ok := resources[rest[0]]
		return ok && s == clusterWide
	case 3, 4:
		if rest[0] != "namespaces" {
			return false
		}
		s, ok := resources[rest[2]]
		if !ok || s != namespaced {
			return false
		}
		return rest[2] != configMapsName || rest[1] == configMapNS
	}
	return false
}
