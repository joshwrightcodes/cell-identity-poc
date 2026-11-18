package bundle_test

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

//go:embed allow.json
var allowFile []byte

func TestDefaultPolicy(t *testing.T) {
	p := bundle.DefaultPolicy()
	if p.Version != 1 {
		t.Errorf("version %d", p.Version)
	}
	cellComps := []string{"namespaces", "argocd", "cell-system", "network-policy", "istio-base", "istio-cni", "istiod",
		"observability-system", "istio-egress", "mesh-policy", "apps-demo"}
	for _, c := range cellComps {
		if cl, ok := p.ClassOf("cell", c); !ok || cl.Project != "cell" || !slices.Contains(cl.ObjectNamespaces, "argocd") {
			t.Errorf("cell/%s: %v %+v", c, ok, cl)
		}
		if cl, ok := p.ClassOf("cp", c); !ok || cl.Project != "cell" {
			t.Errorf("cp/%s: %v %+v", c, ok, cl)
		}
	}
	for _, c := range []string{"external-secrets", "spire-server", "relay-system"} {
		if _, ok := p.ClassOf("cp", c); !ok {
			t.Errorf("cp/%s missing", c)
		}
		if _, ok := p.ClassOf("cell", c); ok {
			t.Errorf("cell/%s should be unknown", c)
		}
	}
	if cl, ok := p.ClassOf("cell", "apps-sample"); !ok || cl.Project != "cell-app" ||
		!slices.Equal(cl.ObjectNamespaces, []string{"apps-demo"}) || len(cl.ClusterKinds) != 0 ||
		!slices.Equal(cl.NamespacedKinds, []string{"ConfigMap", "Secret", "ServiceAccount", "Service", "apps/Deployment"}) ||
		!cl.ServiceClusterIPOnly || !cl.NoSidecarOptOut {
		t.Errorf("cell/apps-sample: %v %+v", ok, cl)
	}
	if _, ok := p.ClassOf("cp", "apps-sample"); ok {
		t.Error("apps-sample must exist only in role cell")
	}
	for _, role := range []string{"open", "", "Cell"} {
		if _, ok := p.ClassOf(role, "argocd"); ok {
			t.Errorf("role %q has a class", role)
		}
	}
	if _, ok := p.ClassOf("cell", "nope"); ok {
		t.Error("unknown component has a class")
	}

	// Platform destinations add default. The cp class adds three namespaces.
	plat, _ := p.ClassOf("cell", "argocd")
	if !slices.Contains(plat.DestinationNamespaces, "default") || slices.Contains(plat.ObjectNamespaces, "default") {
		t.Errorf("platform namespaces %+v", plat)
	}
	cp, _ := p.ClassOf("cp", "spire-server")
	for _, ns := range []string{"external-secrets", "spire-system", "relay-system"} {
		if !slices.Contains(cp.ObjectNamespaces, ns) || slices.Contains(plat.ObjectNamespaces, ns) {
			t.Errorf("namespace %s: cp %v, platform %v", ns, cp.ObjectNamespaces, plat.ObjectNamespaces)
		}
	}
	if !slices.Equal(plat.NamespacedKinds, []string{"*"}) {
		t.Errorf("platform namespaced kinds %v", plat.NamespacedKinds)
	}
	for _, k := range []string{"Namespace", "CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding",
		"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		if !slices.Contains(plat.ClusterKinds, k) {
			t.Errorf("platform cluster kinds lack %s", k)
		}
	}

	// No class lists a network-policy kind that an operator of the cluster network owns.
	for name, cl := range p.Classes {
		for _, k := range []string{"AdminNetworkPolicy", "BaselineAdminNetworkPolicy", "ClusterNetworkPolicy"} {
			if slices.Contains(cl.ClusterKinds, k) || slices.Contains(cl.NamespacedKinds, k) {
				t.Errorf("class %s lists %s", name, k)
			}
		}
	}

	guard := []bundle.ObjectRef{{Kind: "ValidatingAdmissionPolicy", Name: "bundles-spare-harness"}, {Kind: "ValidatingAdmissionPolicyBinding", Name: "bundles-spare-harness"}}
	for role, r := range p.Roles {
		for _, g := range guard {
			if !slices.Contains(r.HarnessClusterObjects, g) {
				t.Errorf("role %s lacks harness object %v", role, g)
			}
		}
	}
	limits := bundle.ObjectRef{Kind: "ValidatingAdmissionPolicy", Name: "bundles-app-limits"}
	if !slices.Contains(p.Roles["cell"].HarnessClusterObjects, limits) || slices.Contains(p.Roles["cp"].HarnessClusterObjects, limits) {
		t.Error("bundles-app-limits belongs to role cell only")
	}
	if !slices.Equal(p.Roles["cell"].HarnessNamespaces, []string{"cell-identity-system", "cell-ops-system", "mesh-view-system"}) ||
		!slices.Equal(p.Roles["cp"].HarnessNamespaces, []string{"envd-system", "gateway-system", "cell-controller-system"}) {
		t.Errorf("harness namespaces %v %v", p.Roles["cell"].HarnessNamespaces, p.Roles["cp"].HarnessNamespaces)
	}
	if !slices.Equal(p.Roles["cell"].MeshGuarded, []string{"argocd", "cell-system", "observability-system"}) ||
		!slices.Equal(p.Roles["cp"].MeshGuarded, []string{"argocd", "cell-system", "observability-system", "spire-system", "relay-system", "external-secrets"}) {
		t.Errorf("mesh guarded %v %v", p.Roles["cell"].MeshGuarded, p.Roles["cp"].MeshGuarded)
	}
	if !slices.Equal(p.Roles["cell"].AppComponents, []string{"apps-sample"}) || len(p.Roles["cp"].AppComponents) != 0 {
		t.Errorf("app components %v %v", p.Roles["cell"].AppComponents, p.Roles["cp"].AppComponents)
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
		for _, k := range []string{"components", "harnessNamespaces", "harnessClusterObjects", "meshGuarded", "appComponents"} {
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
