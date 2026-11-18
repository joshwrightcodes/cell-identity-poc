package bundle_test

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

//go:embed allow.json
var allowFile []byte

var (
	platformNS = []string{"argocd", "cell-system", "istio-system", "istio-egress", "observability-system", "apps-demo"}
	clusterKs  = []string{"Namespace", "apiextensions.k8s.io/CustomResourceDefinition",
		"rbac.authorization.k8s.io/ClusterRole", "rbac.authorization.k8s.io/ClusterRoleBinding",
		"admissionregistration.k8s.io/ValidatingWebhookConfiguration", "admissionregistration.k8s.io/MutatingWebhookConfiguration",
		"admissionregistration.k8s.io/ValidatingAdmissionPolicy", "admissionregistration.k8s.io/ValidatingAdmissionPolicyBinding"}
	cellComps = []string{"namespaces", "argocd", "cell-system", "network-policy", "istio-base", "istio-cni", "istiod",
		"observability-system", "istio-egress", "mesh-policy", "apps-demo"}
	cpExtra = []string{"external-secrets", "spire-server", "relay-system"}
)

func TestDefaultPolicy(t *testing.T) {
	p := bundle.DefaultPolicy()
	if p.Version != 1 {
		t.Errorf("version %d", p.Version)
	}
	catList := func(parts ...[]string) []string { return slices.Concat(parts...) }

	want := map[string]bundle.Class{
		"platform": {
			Project: "cell", ObjectNamespaces: platformNS,
			DestinationNamespaces: catList(platformNS, []string{"default"}),
			ClusterKinds:          clusterKs, NamespacedKinds: []string{"*"},
		},
		"cp-platform": {
			Project:               "cell",
			ObjectNamespaces:      catList(platformNS, []string{"external-secrets", "spire-system", "relay-system"}),
			DestinationNamespaces: catList(platformNS, []string{"default", "external-secrets", "spire-system", "relay-system"}),
			ClusterKinds:          clusterKs, NamespacedKinds: []string{"*"},
		},
		"app": {
			Project: "cell-app", ObjectNamespaces: []string{"apps-demo"}, DestinationNamespaces: []string{"apps-demo"},
			ClusterKinds:         []string{},
			NamespacedKinds:      []string{"ConfigMap", "Secret", "ServiceAccount", "Service", "apps/Deployment"},
			ServiceClusterIPOnly: true, NoSidecarOptOut: true,
		},
	}
	if !reflect.DeepEqual(p.Classes, want) {
		t.Errorf("classes differ\n got %+v\nwant %+v", p.Classes, want)
	}

	comps := func(names []string, class string) map[string]string {
		m := map[string]string{}
		for _, n := range names {
			m[n] = class
		}
		return m
	}
	guard := []bundle.ObjectRef{{Kind: "ValidatingAdmissionPolicy", Name: "bundles-spare-harness"}, {Kind: "ValidatingAdmissionPolicyBinding", Name: "bundles-spare-harness"}}
	wantRoles := map[string]bundle.Role{
		"cell": {
			Components:            func() map[string]string { m := comps(cellComps, "platform"); m["apps-sample"] = "app"; return m }(),
			HarnessNamespaces:     []string{"cell-identity-system", "cell-ops-system", "mesh-view-system"},
			HarnessClusterObjects: append(slices.Clone(guard), bundle.ObjectRef{Kind: "ValidatingAdmissionPolicy", Name: "bundles-app-limits"}, bundle.ObjectRef{Kind: "ValidatingAdmissionPolicyBinding", Name: "bundles-app-limits"}),
			MeshGuarded:           []string{"argocd", "cell-system", "observability-system"},
			AppComponents:         []string{"apps-sample"},
			AppProjects:           []string{"cell", "cell-app"},
			PlanePolicies: []bundle.PolicyRef{{Namespace: "cell-identity-system", Name: "celld"}, {Namespace: "argocd", Name: "argocd-agent"},
				{Namespace: "observability-system", Name: "otel-uplink"}, {Namespace: "mesh-view-system", Name: "mesh-view"},
				{Namespace: "cell-system", Name: "plane-celld-store"}},
		},
		"cp": {
			Components:            comps(catList(cellComps, cpExtra), "cp-platform"),
			HarnessNamespaces:     []string{"envd-system", "gateway-system", "cell-controller-system"},
			HarnessClusterObjects: guard,
			MeshGuarded:           []string{"argocd", "cell-system", "observability-system", "spire-system", "relay-system", "external-secrets"},
			AppComponents:         []string{},
			AppProjects:           []string{"cell"},
			PlanePolicies: []bundle.PolicyRef{{Namespace: "envd-system", Name: "envd"}, {Namespace: "cell-system", Name: "plane-envd-store"},
				{Namespace: "spire-system", Name: "plane-cells"}, {Namespace: "spire-system", Name: "plane-envd"},
				{Namespace: "relay-system", Name: "plane-cells"}, {Namespace: "relay-system", Name: "plane-upstream"}},
		},
		"open": {
			Components: map[string]string{}, HarnessNamespaces: []string{}, HarnessClusterObjects: []bundle.ObjectRef{},
			MeshGuarded: []string{}, AppComponents: []string{},
			AppProjects: []string{}, PlanePolicies: []bundle.PolicyRef{},
		},
	}
	if !reflect.DeepEqual(p.Roles, wantRoles) {
		t.Errorf("roles differ\n got %+v\nwant %+v", p.Roles, wantRoles)
	}
	if len(p.Roles["cell"].Components) != 12 || len(p.Roles["cp"].Components) != 14 {
		t.Errorf("component counts %d %d", len(p.Roles["cell"].Components), len(p.Roles["cp"].Components))
	}

	// ClassOf follows the data. The role open has no class, so management has no signed root.
	if cl, ok := p.ClassOf("cell", "apps-sample"); !ok || cl.Project != "cell-app" {
		t.Errorf("cell/apps-sample: %v %+v", ok, cl)
	}
	for _, c := range []string{"apps-sample", "argocd", "istiod", "namespaces"} {
		for _, role := range []string{"open", "", "Cell", "nope"} {
			if _, ok := p.ClassOf(role, c); ok {
				t.Errorf("role %q has a class for %s", role, c)
			}
		}
	}
	if _, ok := p.ClassOf("cp", "apps-sample"); ok {
		t.Error("apps-sample must exist only in role cell")
	}
	if _, ok := p.ClassOf("cell", "external-secrets"); ok {
		t.Error("external-secrets must exist only in role cp")
	}
	if _, ok := p.ClassOf("cell", "nope"); ok {
		t.Error("unknown component has a class")
	}

	// No class lists a network-policy kind that an operator of the cluster network owns.
	for name, cl := range p.Classes {
		for _, k := range []string{"AdminNetworkPolicy", "BaselineAdminNetworkPolicy", "ClusterNetworkPolicy"} {
			if slices.Contains(cl.ClusterKinds, k) || slices.Contains(cl.NamespacedKinds, k) {
				t.Errorf("class %s lists %s", name, k)
			}
		}
	}
}

func TestAppProjectsNeverDefault(t *testing.T) {
	for role, r := range bundle.DefaultPolicy().Roles {
		if slices.Contains(r.AppProjects, "default") {
			t.Errorf("role %s allows the AppProject default", role)
		}
	}
}

// harnessComponents are the harness components of scripts/lib.sh and the planned harness names. No
// role may let a bundle write to one of them.
var harnessComponents = []string{"cell-identity", "cell-ops", "mesh-view", "envd", "gateway", "cell-controller"}

func TestPolicyInvariants(t *testing.T) {
	p := bundle.DefaultPolicy()
	var harnessNS []string
	for _, r := range p.Roles {
		harnessNS = append(harnessNS, r.HarnessNamespaces...)
	}
	for name, cl := range p.Classes {
		for _, ns := range slices.Concat(cl.ObjectNamespaces, cl.DestinationNamespaces) {
			if slices.Contains(harnessNS, ns) {
				t.Errorf("class %s names the harness namespace %s", name, ns)
			}
		}
		for _, ns := range cl.ObjectNamespaces {
			if !slices.Contains(cl.DestinationNamespaces, ns) {
				t.Errorf("class %s has object namespace %s outside its destinations", name, ns)
			}
		}
	}
	for role, r := range p.Roles {
		for comp, class := range r.Components {
			if slices.Contains(harnessComponents, comp) {
				t.Errorf("role %s lists the harness component %s", role, comp)
			}
			if _, ok := p.Classes[class]; !ok {
				t.Errorf("role %s: %s has the unknown class %s", role, comp, class)
			}
		}
		for _, a := range r.AppComponents {
			if p.Classes[r.Components[a]].Project != "cell-app" {
				t.Errorf("role %s: app component %s is not in the app class", role, a)
			}
		}
	}
}

func TestAllowJSONShape(t *testing.T) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(allowFile, &top); err != nil {
		t.Fatal(err)
	}
	if len(top) != 3 {
		t.Errorf("top-level keys %v", top)
	}
	for _, k := range []string{"version", "classes", "roles"} {
		if _, ok := top[k]; !ok {
			t.Errorf("no %q key", k)
		}
	}
	if _, ok := top["flows"]; ok {
		t.Error("allow.json has a flows key")
	}
	var roles map[string]map[string]json.RawMessage
	if err := json.Unmarshal(top["roles"], &roles); err != nil {
		t.Fatal(err)
	}
	for role, r := range roles {
		for _, k := range []string{"components", "harnessNamespaces", "harnessClusterObjects", "meshGuarded", "appComponents", "appProjects", "planePolicies"} {
			if _, ok := r[k]; !ok {
				t.Errorf("role %s has no %q", role, k)
			}
		}
		if _, ok := r["flows"]; ok {
			t.Errorf("role %s has a flows key", role)
		}
	}
	sum := sha256.Sum256(allowFile)
	if bundle.AllowSHA256() != hex.EncodeToString(sum[:]) {
		t.Error("AllowSHA256 is not the digest of allow.json")
	}
}

func TestParsePolicyRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"unknown_member": `{"version":1,"classes":{},"roles":{},"flows":[]}`,
		"version_2":      `{"version":2,"classes":{},"roles":{}}`,
		"unknown_class":  `{"version":1,"classes":{},"roles":{"cell":{"components":{"a":"nope"}}}}`,
		"not_json":       `x`,
	} {
		if _, err := bundle.ParsePolicy([]byte(in)); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}
