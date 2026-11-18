package bundle

import (
	"fmt"
	"slices"
	"strings"
)

const kubernetesServer = "https://kubernetes.default.svc"

// harnessGroups gives the API group of each kind in the harness cluster objects of allow.json.
var harnessGroups = map[string]string{
	"ValidatingAdmissionPolicy":        "admissionregistration.k8s.io",
	"ValidatingAdmissionPolicyBinding": "admissionregistration.k8s.io",
}

// ExpectedAppProjectSpec returns the spec that the AppProject name must have in a cluster of role,
// as JSON-compatible values. The engine refuses an AppProject of a bundle with any other spec, and
// the render of the argocd bundle uses the same function. A name that the role does not list gives
// an error.
func ExpectedAppProjectSpec(role, name string, p Policy) (map[string]any, error) {
	r, ok := p.Roles[role]
	if !ok || !slices.Contains(r.AppProjects, name) {
		return nil, fmt.Errorf("role %q has no AppProject %q", role, name)
	}
	var class *Class
	for _, cn := range r.Components {
		if c, ok := p.Classes[cn]; ok && c.Project == name {
			class = &c
			break
		}
	}
	if class == nil {
		return nil, fmt.Errorf("role %q has no component in the class of AppProject %q", role, name)
	}
	spec := map[string]any{"sourceRepos": []any{"oci://" + StoreHost + "/bundles/*"}}
	var dests []any
	for _, ns := range class.DestinationNamespaces {
		dests = append(dests, map[string]any{"server": kubernetesServer, "namespace": ns})
	}
	set := func(key string, v []any) {
		if len(v) > 0 {
			spec[key] = v
		}
	}
	set("destinations", dests)
	set("clusterResourceWhitelist", kindEntries(class.ClusterKinds))
	set("namespaceResourceWhitelist", kindEntries(class.NamespacedKinds))
	var black []any
	for _, h := range r.HarnessClusterObjects {
		g, ok := harnessGroups[h.Kind]
		if !ok {
			return nil, fmt.Errorf("harness cluster kind %q has no known API group", h.Kind)
		}
		black = append(black, map[string]any{"group": g, "kind": h.Kind, "name": h.Name})
	}
	set("clusterResourceBlacklist", black)
	return spec, nil
}

// kindEntries turns group/Kind strings into group and kind pairs. A kind without a slash is in the
// core group, and "*" stands for every group and kind.
func kindEntries(kinds []string) []any {
	var out []any
	for _, k := range kinds {
		group, kind := "", k
		if k == "*" {
			group = "*"
		} else if i := strings.LastIndex(k, "/"); i >= 0 {
			group, kind = k[:i], k[i+1:]
		}
		out = append(out, map[string]any{"group": group, "kind": kind})
	}
	return out
}
