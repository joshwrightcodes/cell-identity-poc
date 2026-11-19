package bundle

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExpectedAppProjectSpec(t *testing.T) {
	p := DefaultPolicy()
	app, err := ExpectedAppProjectSpec("cell", "cell-app", p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(app)
	for _, frag := range []string{
		`"namespace":"apps-demo"`, `"kind":"Deployment"`, `"group":"apps"`, `"kind":"ConfigMap"`,
		`"name":"bundles-app-limits"`, `"name":"bundles-spare-harness"`, `oci://127.0.0.1:5000/bundles/*`,
	} {
		if !strings.Contains(string(b), frag) {
			t.Errorf("cell-app spec lacks %s: %s", frag, b)
		}
	}
	if strings.Contains(string(b), `"namespace":"argocd"`) {
		t.Errorf("cell-app reaches argocd: %s", b)
	}
	plat, err := ExpectedAppProjectSpec("cell", "cell", p)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := plat["destinations"].([]any); len(d) != len(p.Classes["platform"].DestinationNamespaces) {
		t.Errorf("destinations = %v", plat["destinations"])
	}
	cp, err := ExpectedAppProjectSpec("cp", "cell", p)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := json.Marshal(cp)
	if strings.Contains(string(cb), "bundles-app-limits") || !strings.Contains(string(cb), "spire-system") {
		t.Errorf("cp spec = %s", cb)
	}
	for _, c := range [][2]string{{"cp", "cell-app"}, {"cell", "default"}, {"open", "cell"}, {"nope", "cell"}} {
		if _, err := ExpectedAppProjectSpec(c[0], c[1], p); err == nil {
			t.Errorf("%v has an expected spec", c)
		}
	}
}

// The specs are written out in full, so that a change to the function or to allow.json shows here.
// Each was checked by hand against the class table of the plan.
func TestExpectedAppProjectSpecGolden(t *testing.T) {
	golden := []struct{ role, project, spec string }{
		{"cell", "cell", `{"clusterResourceBlacklist":[{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicy","name":"bundles-spare-harness"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicyBinding","name":"bundles-spare-harness"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicy","name":"bundles-app-limits"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicyBinding","name":"bundles-app-limits"}],"clusterResourceWhitelist":[{"group":"","kind":"Namespace"},{"group":"apiextensions.k8s.io","kind":"CustomResourceDefinition"},{"group":"rbac.authorization.k8s.io","kind":"ClusterRole"},{"group":"rbac.authorization.k8s.io","kind":"ClusterRoleBinding"},{"group":"admissionregistration.k8s.io","kind":"ValidatingWebhookConfiguration"},{"group":"admissionregistration.k8s.io","kind":"MutatingWebhookConfiguration"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicy"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicyBinding"}],"destinations":[{"namespace":"argocd","server":"https://kubernetes.default.svc"},{"namespace":"cell-system","server":"https://kubernetes.default.svc"},{"namespace":"istio-system","server":"https://kubernetes.default.svc"},{"namespace":"istio-egress","server":"https://kubernetes.default.svc"},{"namespace":"observability-system","server":"https://kubernetes.default.svc"},{"namespace":"apps-demo","server":"https://kubernetes.default.svc"},{"namespace":"default","server":"https://kubernetes.default.svc"}],"namespaceResourceWhitelist":[{"group":"*","kind":"*"}],"sourceRepos":["oci://127.0.0.1:5000/bundles/*"]}`},
		{"cell", "cell-app", `{"clusterResourceBlacklist":[{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicy","name":"bundles-spare-harness"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicyBinding","name":"bundles-spare-harness"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicy","name":"bundles-app-limits"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicyBinding","name":"bundles-app-limits"}],"destinations":[{"namespace":"apps-demo","server":"https://kubernetes.default.svc"}],"namespaceResourceWhitelist":[{"group":"","kind":"ConfigMap"},{"group":"","kind":"Secret"},{"group":"","kind":"ServiceAccount"},{"group":"","kind":"Service"},{"group":"apps","kind":"Deployment"}],"sourceRepos":["oci://127.0.0.1:5000/bundles/*"]}`},
		{"cp", "cell", `{"clusterResourceBlacklist":[{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicy","name":"bundles-spare-harness"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicyBinding","name":"bundles-spare-harness"}],"clusterResourceWhitelist":[{"group":"","kind":"Namespace"},{"group":"apiextensions.k8s.io","kind":"CustomResourceDefinition"},{"group":"rbac.authorization.k8s.io","kind":"ClusterRole"},{"group":"rbac.authorization.k8s.io","kind":"ClusterRoleBinding"},{"group":"admissionregistration.k8s.io","kind":"ValidatingWebhookConfiguration"},{"group":"admissionregistration.k8s.io","kind":"MutatingWebhookConfiguration"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicy"},{"group":"admissionregistration.k8s.io","kind":"ValidatingAdmissionPolicyBinding"}],"destinations":[{"namespace":"argocd","server":"https://kubernetes.default.svc"},{"namespace":"cell-system","server":"https://kubernetes.default.svc"},{"namespace":"istio-system","server":"https://kubernetes.default.svc"},{"namespace":"istio-egress","server":"https://kubernetes.default.svc"},{"namespace":"observability-system","server":"https://kubernetes.default.svc"},{"namespace":"apps-demo","server":"https://kubernetes.default.svc"},{"namespace":"default","server":"https://kubernetes.default.svc"},{"namespace":"external-secrets","server":"https://kubernetes.default.svc"},{"namespace":"spire-system","server":"https://kubernetes.default.svc"},{"namespace":"relay-system","server":"https://kubernetes.default.svc"}],"namespaceResourceWhitelist":[{"group":"*","kind":"*"}],"sourceRepos":["oci://127.0.0.1:5000/bundles/*"]}`},
	}
	for _, g := range golden {
		spec, err := ExpectedAppProjectSpec(g.role, g.project, DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != g.spec {
			t.Errorf("%s/%s spec changed:\n got %s\nwant %s", g.role, g.project, got, g.spec)
		}
	}
}

// TestExpectedAppProjectSpecOneClassPerProject checks that two classes of one role that name the same
// project give an error, not the spec of whichever class a map walk meets first.
func TestExpectedAppProjectSpecOneClassPerProject(t *testing.T) {
	raw, err := json.Marshal(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	wide := p.Classes["app"]
	wide.DestinationNamespaces = append([]string{"argocd"}, wide.DestinationNamespaces...)
	p.Classes["app-wide"] = wide
	p.Roles["cell"].Components["extra"] = "app-wide"
	for range 20 {
		if spec, err := ExpectedAppProjectSpec("cell", "cell-app", p); err == nil {
			t.Fatalf("two classes for project cell-app gave a spec: %v", spec["destinations"])
		}
	}
	if _, err := ExpectedAppProjectSpec("cell", "cell", p); err != nil {
		t.Fatalf("project cell has one class: %v", err)
	}
}
