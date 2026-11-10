package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"testing"
)

// TestAppsNamespaceRenders checks, in every cluster, the objects that move the child Applications to
// argocd-apps: the namespace, its default deny, the AppProject source namespace, the Argo CD
// setting, the admission policy and its binding, and the restart checksum on the controller.
func TestAppsNamespaceRenders(t *testing.T) {
	params, err := os.ReadFile("../../components/argocd/argocd-cmd-params-cm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(params)
	wantSum := hex.EncodeToString(sum[:])

	for _, cr := range renderAll(t) {
		t.Run(cr.name, func(t *testing.T) {
			byComponent := map[string]map[string]object{}
			for _, c := range cr.components {
				objs := map[string]object{}
				for _, o := range c.objs {
					objs[objName(o)] = o
				}
				byComponent[c.name] = objs
			}

			ns := byComponent["namespaces"]["Namespace argocd-apps"]
			if ns == nil {
				t.Fatal("the namespaces component renders no Namespace argocd-apps")
			}
			for label, want := range map[string]string{"istio-injection": "disabled", "pod-security.kubernetes.io/enforce": "restricted"} {
				if got, _ := lookup(ns, "metadata", "labels", label); got != want {
					t.Errorf("Namespace argocd-apps label %s = %v, want %s", label, got, want)
				}
			}
			if byComponent["network-policy"]["NetworkPolicy argocd-apps/default-deny"] == nil {
				t.Error("the network-policy component renders no default-deny in argocd-apps")
			}

			argo := byComponent["argocd"]
			if got := get[string](t, argo["ConfigMap argocd/argocd-cmd-params-cm"], "data", "application.namespaces"); got != "argocd-apps" {
				t.Errorf("application.namespaces = %q, want argocd-apps", got)
			}
			if got := fmt.Sprint(get[[]any](t, argo["AppProject argocd/cell"], "spec", "sourceNamespaces")); got != "[argocd-apps]" {
				t.Errorf("AppProject cell sourceNamespaces = %s, want [argocd-apps]", got)
			}
			ctrl := argo["StatefulSet argocd/argocd-application-controller"]
			if got := get[string](t, ctrl, "spec", "template", "metadata", "annotations", "poc.internal/cmd-params-sha256"); got != wantSum {
				t.Errorf("controller poc.internal/cmd-params-sha256 = %s, want %s, the SHA-256 of components/argocd/argocd-cmd-params-cm.yaml", got, wantSum)
			}

			policy := argo["ValidatingAdmissionPolicy argocd-apps-no-secrets"]
			if policy == nil {
				t.Fatal("the argocd component renders no ValidatingAdmissionPolicy argocd-apps-no-secrets")
			}
			rule := get[[]any](t, policy, "spec", "matchConstraints", "resourceRules")[0]
			if got := fmt.Sprint(get[[]any](t, rule, "resources")); got != "[secrets]" {
				t.Errorf("the policy matches resources %s, want [secrets]", got)
			}
			ops := []string{}
			for _, op := range get[[]any](t, rule, "operations") {
				ops = append(ops, op.(string))
			}
			if !slices.Contains(ops, "CREATE") {
				t.Errorf("the policy matches operations %v, want CREATE", ops)
			}
			if got := get[string](t, get[[]any](t, policy, "spec", "validations")[0], "expression"); got != "false" {
				t.Errorf("the policy expression is %q, want false, so that it denies every Secret", got)
			}
			binding := argo["ValidatingAdmissionPolicyBinding argocd-apps-no-secrets"]
			if binding == nil {
				t.Fatal("the argocd component renders no binding argocd-apps-no-secrets")
			}
			if got := fmt.Sprint(get[[]any](t, binding, "spec", "validationActions")); got != "[Deny]" {
				t.Errorf("the binding actions are %s, want [Deny]", got)
			}
			if got := get[string](t, binding, "spec", "matchResources", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); got != "argocd-apps" {
				t.Errorf("the binding selects the namespace %q, want argocd-apps", got)
			}
		})
	}
}
