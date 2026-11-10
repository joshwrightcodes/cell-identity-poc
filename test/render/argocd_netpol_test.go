package render

import (
	"fmt"
	"testing"
)

const notLgtmSelector = "map[matchExpressions:[map[key:app.kubernetes.io/name operator:NotIn values:[lgtm]]]]"

const notAgentSelector = "map[matchExpressions:[map[key:app.kubernetes.io/name operator:NotIn values:[argocd-agent]]]]"

// TestArgocdPoliciesExcludeTheAgent checks, in every cluster, that the namespace policies of argocd
// leave out the pod of the Argo CD Agent, so that its own policy bounds it. Only the default deny
// and the DNS rule select every pod. The bundle store admits only the repo server.
func TestArgocdPoliciesExcludeTheAgent(t *testing.T) {
	for _, cr := range renderAll(t) {
		t.Run(cr.name, func(t *testing.T) {
			var policies map[string]object
			for _, c := range cr.components {
				if c.name != "network-policy" && c.name != "observability-system" {
					continue
				}
				if policies == nil {
					policies = map[string]object{}
				}
				for _, o := range c.objs {
					policies[objName(o)] = o
				}
			}
			if policies == nil {
				t.Fatal("no network-policy component")
			}
			for name, o := range policies {
				if o["kind"] != "NetworkPolicy" || lookupOr(o, "metadata", "namespace") != "argocd" {
					continue
				}
				sel := fmt.Sprint(lookupOr(o, "spec", "podSelector"))
				switch name {
				case "NetworkPolicy argocd/default-deny", "NetworkPolicy argocd/allow-dns":
					if sel != "map[]" {
						t.Errorf("%s selects %s, want every pod", name, sel)
					}
				case "NetworkPolicy argocd/argocd", "NetworkPolicy argocd/allow-from-nodes":
					if sel != notAgentSelector {
						t.Errorf("%s selects %s, want every pod except argocd-agent", name, sel)
					}
				default:
					t.Errorf("unexpected policy %s in argocd", name)
				}
			}
			if policies["NetworkPolicy argocd/argocd"] == nil || policies["NetworkPolicy argocd/allow-from-nodes"] == nil {
				t.Fatalf("the policies argocd and allow-from-nodes are missing in %s", cr.name)
			}
			for _, name := range []string{"cell-system", "istio-system", "apps-demo"} {
				if p := policies["NetworkPolicy "+name+"/allow-from-nodes"]; p == nil || fmt.Sprint(lookupOr(p, "spec", "podSelector")) != "map[]" {
					t.Errorf("allow-from-nodes in %s changed: %v", name, p)
				}
			}
			// The store probes itself inside its pod, so no node address reaches it.
			if p := policies["NetworkPolicy observability-system/allow-from-nodes"]; p == nil || fmt.Sprint(lookupOr(p, "spec", "podSelector")) != notLgtmSelector {
				t.Errorf("allow-from-nodes in observability-system selects %v, want every pod except lgtm", p)
			}
			store := policies["NetworkPolicy cell-system/bundle-store"]
			if store == nil {
				t.Fatal("no policy bundle-store")
			}
			from := get[[]any](t, get[[]any](t, store, "spec", "ingress")[0], "from")
			if len(from) != 1 || fmt.Sprint(lookupOr(from[0], "podSelector", "matchLabels")) != "map[app.kubernetes.io/name:argocd-repo-server]" ||
				fmt.Sprint(lookupOr(from[0], "namespaceSelector", "matchLabels")) != "map[kubernetes.io/metadata.name:argocd]" {
				t.Errorf("the bundle store admits %v, want only argocd-repo-server of argocd", from)
			}
		})
	}
}
