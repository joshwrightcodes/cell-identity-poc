//go:build e2e

package e2e

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

const (
	controllerPod  = "argocd-application-controller-0"
	cmdParamsCM    = "argocd-cmd-params-cm"
	secretsPolicy  = "argocd-secrets-allowed"
	agentRole      = "argocd-agent"
	agentAccount   = "system:serviceaccount:argocd:argocd-agent"
	checksumNotice = "poc.internal/cmd-params-sha256"
)

var allowedSecrets = []string{"argocd-redis", "argocd-secret", "bundle-store"}

// applicationNames lists the Applications of a namespace, sorted.
func applicationNames(t *testing.T, cluster, ns string) []string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "get", "applications.argoproj.io", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		t.Fatal(err)
	}
	names := strings.Fields(out)
	slices.Sort(names)
	return names
}

// TestM3ArgocdHoldsOnlyAllowedSecrets checks, in each base-cell cluster, that argocd holds the root
// Application and one Application per component and no other Application anywhere, that argocd
// holds only the three allowed Secrets, that the admission policy denies any other Secret there,
// and that no setting of application.namespaces remains.
// In a cluster with the agent, the agent can list and watch Secrets in argocd and cannot get one.
func TestM3ArgocdHoldsOnlyAllowedSecrets(t *testing.T) {
	for _, cluster := range clustersWith(t, "") {
		t.Run(cluster, func(t *testing.T) {
			want := []string{"root"}
			for name := range publishedDigests(t, cluster) {
				if name != "root" {
					want = append(want, name)
				}
			}
			slices.Sort(want)
			if got := applicationNames(t, cluster, "argocd"); !slices.Equal(got, want) {
				t.Errorf("argocd holds the Applications %v, want root and one for each component: %v", got, want)
			}
			all, err := kubectl(t, cluster, "", "get", "applications.argoproj.io", "-A", "-o", "jsonpath={range .items[*]}{.metadata.namespace}{\"\\n\"}{end}")
			if err != nil {
				t.Fatal(err)
			}
			for _, ns := range strings.Fields(all) {
				// The principal in management keeps the mirror of each cell in the namespace of its agent.
				if ns != "argocd" && !(cluster == mgmtCluster && strings.HasPrefix(ns, pocEnv+"-")) {
					t.Errorf("an Application lives in the namespace %s, outside argocd", ns)
				}
			}

			names, err := kubectl(t, cluster, "", "-n", "argocd", "get", "secrets", "-o", "jsonpath={.items[*].metadata.name}")
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range strings.Fields(names) {
				if !slices.Contains(allowedSecrets, name) {
					t.Errorf("argocd holds the Secret %s, outside the allowed set %v", name, allowedSecrets)
				}
			}

			// A server dry run reaches admission and stores nothing.
			out, err := kubectl(t, cluster, "", "-n", "argocd", "create", "secret", "generic", "m3-other", "--from-literal=k=v", "--dry-run=server")
			if err == nil {
				t.Fatalf("kubectl create secret m3-other --dry-run=server in argocd succeeded: %s", out)
			}
			if !strings.Contains(err.Error(), secretsPolicy) {
				t.Errorf("the denial does not name the policy %s: %v", secretsPolicy, err)
			}
			for _, name := range allowedSecrets {
				_, err := kubectl(t, cluster, "", "-n", "argocd", "create", "secret", "generic", name, "--from-literal=k=v", "--dry-run=server")
				if err != nil && strings.Contains(err.Error(), secretsPolicy) {
					t.Errorf("the policy denied the allowed Secret %s: %v", name, err)
				}
			}

			cm, err := kubectl(t, cluster, "", "-n", "argocd", "get", "configmap", cmdParamsCM, "-o", "json")
			if err != nil {
				t.Fatal(err)
			}
			var params struct {
				Data map[string]string `json:"data"`
			}
			if err := json.Unmarshal([]byte(cm), &params); err != nil {
				t.Fatal(err)
			}
			if v, ok := params.Data["application.namespaces"]; ok {
				t.Errorf("%s sets application.namespaces to %q", cmdParamsCM, v)
			}
			ann, err := kubectl(t, cluster, "", "-n", "argocd", "get", "statefulset", "argocd-application-controller", "-o", "jsonpath={.spec.template.metadata.annotations}")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ann, checksumNotice) {
				t.Errorf("the controller template still carries %s: %s", checksumNotice, ann)
			}
			if out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "pod", controllerPod, "-o", "jsonpath={.status.phase}"); err != nil || out != "Running" {
				t.Errorf("%s is %q (%v), want Running", controllerPod, out, err)
			}

			if !slices.Contains(viewCells(t), cluster) {
				return
			}
			rules, err := kubectl(t, cluster, "", "-n", "argocd", "get", "role", agentRole, "-o", "json")
			if err != nil {
				t.Fatal(err)
			}
			var role struct {
				Rules []struct {
					Resources []string `json:"resources"`
					Verbs     []string `json:"verbs"`
				} `json:"rules"`
			}
			if err := json.Unmarshal([]byte(rules), &role); err != nil {
				t.Fatal(err)
			}
			var secretVerbs []string
			for _, r := range role.Rules {
				if slices.Contains(r.Resources, "secrets") {
					secretVerbs = append(secretVerbs, r.Verbs...)
				}
			}
			slices.Sort(secretVerbs)
			if !slices.Equal(secretVerbs, []string{"list", "watch"}) {
				t.Errorf("the Role %s grants %v on Secrets, want [list watch]", agentRole, secretVerbs)
			}
			for verb, want := range map[string]string{"get": "no", "list": "yes", "watch": "yes"} {
				got, _ := kubectl(t, cluster, "", "auth", "can-i", verb, "secrets", "-n", "argocd", "--as="+agentAccount)
				if strings.TrimSpace(got) != want {
					t.Errorf("can-i %s secrets in argocd as the agent: %q, want %q", verb, strings.TrimSpace(got), want)
				}
			}
		})
	}
}
