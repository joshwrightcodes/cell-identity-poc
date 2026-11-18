package bundleapply

import (
	"cmp"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	kubernetesServer = "https://kubernetes.default.svc"
	detailProject    = "appproject_spec"
)

// harnessGroups gives the API group of each kind in the harness cluster objects of allow.json.
var harnessGroups = map[string]string{
	"ValidatingAdmissionPolicy":        "admissionregistration.k8s.io",
	"ValidatingAdmissionPolicyBinding": "admissionregistration.k8s.io",
}

// ExpectedAppProjectSpec returns the spec that the AppProject name must have in a cluster of role,
// as JSON-compatible values. The engine refuses an AppProject of a bundle with any other spec, and
// the render of the argocd bundle uses the same function. A name that the role does not list gives
// an error.
func ExpectedAppProjectSpec(role, name string, p bundle.Policy) (map[string]any, error) {
	r, ok := p.Roles[role]
	if !ok || !slices.Contains(r.AppProjects, name) {
		return nil, fmt.Errorf("role %q has no AppProject %q", role, name)
	}
	var class *bundle.Class
	for _, cn := range r.Components {
		if c, ok := p.Classes[cn]; ok && c.Project == name {
			class = &c
			break
		}
	}
	if class == nil {
		return nil, fmt.Errorf("role %q has no component in the class of AppProject %q", role, name)
	}
	spec := map[string]any{"sourceRepos": []any{"oci://" + bundle.StoreHost + "/bundles/*"}}
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

// checkAppProjects refuses an AppProject object whose spec differs from ExpectedAppProjectSpec.
func checkAppProjects(role string, p bundle.Policy, objs []Object) *Refusal {
	for _, o := range objs {
		if o.Kind != "AppProject" || !strings.HasPrefix(o.APIVersion, "argoproj.io/") {
			continue
		}
		refuse := &Refusal{Reason: op.ReasonComponentNotAllowed, Detail: detailProject, Object: o.ref()}
		want, err := ExpectedAppProjectSpec(role, o.Name, p)
		if err != nil {
			return refuse
		}
		got, _ := o.Raw["spec"].(map[string]any)
		if !reflect.DeepEqual(normalise(want), normalise(got)) {
			return refuse
		}
	}
	return nil
}

// normalise converts v to plain JSON values, drops empty lists and objects, and sorts every list
// by the JSON form of its entries, so that order and empty fields do not matter.
func normalise(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var plain any
	if err := json.Unmarshal(b, &plain); err != nil {
		return nil
	}
	return prune(plain)
}

func prune(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if e = prune(e); e != nil {
				out[k] = e
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			out = append(out, prune(e))
		}
		slices.SortFunc(out, func(a, b any) int {
			ja, _ := json.Marshal(a)
			jb, _ := json.Marshal(b)
			return cmp.Compare(string(ja), string(jb))
		})
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return v
	}
}
