package render

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestArgocdGuardsRender checks, in every cluster, the objects that keep argocd closed: the
// admission policy and binding that allow three Secrets, the policy and binding that require the
// project cell or cell-app, the locked AppProject default, and the absence of the settings and the namespace
// that older cells used for child Applications.
func TestArgocdGuardsRender(t *testing.T) {
	rootFile, err := os.ReadFile("../../bootstrap/root.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rootApp, err := parseDocs(string(rootFile))
	if err != nil || len(rootApp) != 1 {
		t.Fatalf("read bootstrap/root.yaml: %d objects, %v", len(rootApp), err)
	}
	if got, _ := lookup(rootApp[0], "metadata", "labels", "argocd-agent.argoproj-labs.io/ignore-sync"); got != "true" {
		t.Errorf("the root Application ignore-sync label = %v, want \"true\"", got)
	}

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

			argo := byComponent["argocd"]
			if v, ok := lookup(argo["ConfigMap argocd/argocd-cmd-params-cm"], "data", "application.namespaces"); ok {
				t.Errorf("application.namespaces = %v, want it unset", v)
			}
			if v, ok := lookup(argo["AppProject argocd/cell"], "spec", "sourceNamespaces"); ok {
				t.Errorf("AppProject cell sourceNamespaces = %v, want it unset", v)
			}
			// Case cell-app: the project of the app class carries no sourceNamespaces either, and the guard names it.
			if app := argo["AppProject argocd/cell-app"]; app != nil {
				if v, ok := lookup(app, "spec", "sourceNamespaces"); ok {
					t.Errorf("AppProject cell-app sourceNamespaces = %v, want it unset", v)
				}
			} else if roleOf[cr.name] == "cell" {
				t.Error("a cell renders no AppProject cell-app")
			}
			if msg, _ := lookup(get[[]any](t, argo["ValidatingAdmissionPolicy argocd-cell-project"], "spec", "validations")[0], "message"); !strings.Contains(fmt.Sprint(msg), "cell-app") {
				t.Errorf("the project guard message is %v, want it to name cell-app", msg)
			}
			ctrl := argo["StatefulSet argocd/argocd-application-controller"]
			if v, ok := lookup(ctrl, "spec", "template", "metadata", "annotations", "poc.internal/cmd-params-sha256"); ok {
				t.Errorf("the controller carries poc.internal/cmd-params-sha256 = %v", v)
			}

			policy := argo["ValidatingAdmissionPolicy argocd-secrets-allowed"]
			if policy == nil {
				t.Fatal("the argocd component renders no ValidatingAdmissionPolicy argocd-secrets-allowed")
			}
			rule := get[[]any](t, policy, "spec", "matchConstraints", "resourceRules")[0]
			if got := fmt.Sprint(get[[]any](t, rule, "resources")); got != "[secrets]" {
				t.Errorf("the policy matches resources %s, want [secrets]", got)
			}
			if got := fmt.Sprint(get[[]any](t, rule, "operations")); got != "[CREATE UPDATE]" {
				t.Errorf("the policy matches operations %s, want [CREATE UPDATE]", got)
			}
			if got := fmt.Sprint(get[[]any](t, rule, "apiGroups")); got != "[]" {
				t.Errorf("the policy matches apiGroups %s, want the core group [\"\"]", got)
			}
			if got := get[string](t, policy, "spec", "failurePolicy"); got != "Fail" {
				t.Errorf("the policy failurePolicy is %s, want Fail", got)
			}
			validations := get[[]any](t, policy, "spec", "validations")
			if len(validations) != 1 {
				t.Fatalf("the policy has %d validations, want 1", len(validations))
			}
			if got, want := get[string](t, validations[0], "expression"), "object.metadata.name in ['argocd-redis', 'argocd-secret', 'bundle-store']"; got != want {
				t.Errorf("the policy expression is %q, want %q", got, want)
			}
			binding := argo["ValidatingAdmissionPolicyBinding argocd-secrets-allowed"]
			if binding == nil {
				t.Fatal("the argocd component renders no binding argocd-secrets-allowed")
			}
			if got := fmt.Sprint(get[[]any](t, binding, "spec", "validationActions")); got != "[Deny]" {
				t.Errorf("the binding actions are %s, want [Deny]", got)
			}
			if got := get[string](t, binding, "spec", "policyName"); got != "argocd-secrets-allowed" {
				t.Errorf("the binding names the policy %q, want argocd-secrets-allowed", got)
			}
			if got := get[string](t, binding, "spec", "matchResources", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); got != "argocd" {
				t.Errorf("the binding selects the namespace %q, want argocd", got)
			}

			project := argo["ValidatingAdmissionPolicy argocd-cell-project"]
			if project == nil {
				t.Fatal("the argocd component renders no ValidatingAdmissionPolicy argocd-cell-project")
			}
			prule := get[[]any](t, project, "spec", "matchConstraints", "resourceRules")[0]
			if got := fmt.Sprint(get[[]any](t, prule, "resources"), get[[]any](t, prule, "apiGroups"), get[[]any](t, prule, "operations")); got != "[applications] [argoproj.io] [CREATE UPDATE]" {
				t.Errorf("the project policy matches %s, want applications of argoproj.io on CREATE and UPDATE", got)
			}
			var exprs []string
			for _, v := range get[[]any](t, project, "spec", "validations") {
				exprs = append(exprs, get[string](t, v, "expression"))
			}
			if want := []string{"object.spec.project in ['cell', 'cell-app']"}; !slices.Equal(exprs, want) || get[string](t, project, "spec", "failurePolicy") != "Fail" {
				t.Errorf("the project policy has %q with failurePolicy %v, want %q and Fail", exprs, lookupOr(project, "spec", "failurePolicy"), want)
			}
			pb := argo["ValidatingAdmissionPolicyBinding argocd-cell-project"]
			if pb == nil || fmt.Sprint(lookupOr(pb, "spec", "validationActions")) != "[Deny]" ||
				fmt.Sprint(lookupOr(pb, "spec", "matchResources", "namespaceSelector")) != "map[matchLabels:map[kubernetes.io/metadata.name:argocd]]" {
				t.Errorf("the project binding is %v, want Deny for argocd", pb)
			}

			def := argo["AppProject argocd/default"]
			if def == nil {
				t.Fatal("the argocd component renders no AppProject default")
			}
			if got, _ := lookup(def, "metadata", "labels", "argocd-agent.argoproj-labs.io/ignore-sync"); got != "true" {
				t.Errorf("AppProject default ignore-sync label = %v, want \"true\"", got)
			}
			for _, field := range []string{"sourceRepos", "destinations", "clusterResourceWhitelist", "namespaceResourceWhitelist"} {
				if v, ok := lookup(def, "spec", field); !ok || len(v.([]any)) != 0 {
					t.Errorf("AppProject default %s = %v, want an empty list", field, v)
				}
			}
			if got, _ := lookup(argo["ConfigMap argocd/argocd-cm"], "data", "admin.enabled"); got != "false" {
				t.Errorf("argocd-cm admin.enabled = %v, want \"false\"", got)
			}
		})
	}
}
