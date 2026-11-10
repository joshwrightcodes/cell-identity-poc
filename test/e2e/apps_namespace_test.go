//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const (
	appsNamespace  = "argocd-apps"
	controllerPod  = "argocd-application-controller-0"
	cmdParamsCM    = "argocd-cmd-params-cm"
	appsPolicyName = "argocd-apps-no-secrets"
)

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

// TestM3AppsNamespaceHoldsNoSecrets checks, in each base-cell cluster, that argocd-apps holds one
// Application per component and no Secret, that argocd holds only the root Application, that the
// admission policy denies a Secret in argocd-apps, and that the application controller started
// after the last change of argocd-cmd-params-cm: it runs the StatefulSet revision whose template
// carries the checksum of the file that holds the setting.
func TestM3AppsNamespaceHoldsNoSecrets(t *testing.T) {
	for _, cluster := range clustersWith(t, "") {
		t.Run(cluster, func(t *testing.T) {
			var want []string
			for name := range publishedDigests(t, cluster) {
				if name != "root" {
					want = append(want, name)
				}
			}
			slices.Sort(want)
			if got := applicationNames(t, cluster, appsNamespace); !slices.Equal(got, want) {
				t.Errorf("%s holds the Applications %v, want one for each component: %v", appsNamespace, got, want)
			}
			if got := applicationNames(t, cluster, "argocd"); !slices.Equal(got, []string{"root"}) {
				t.Errorf("argocd holds the Applications %v, want only root", got)
			}
			secrets, err := kubectl(t, cluster, "", "-n", appsNamespace, "get", "secrets", "-o", "name")
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(secrets) != "" {
				t.Errorf("%s holds Secrets: %s", appsNamespace, secrets)
			}

			// A server dry run reaches admission and stores nothing.
			out, err := kubectl(t, cluster, "", "-n", appsNamespace, "create", "secret", "generic", "x", "--from-literal=k=v", "--dry-run=server")
			if err == nil {
				t.Fatalf("kubectl create secret --dry-run=server in %s succeeded: %s", appsNamespace, out)
			}
			if !strings.Contains(err.Error(), appsPolicyName) {
				t.Errorf("the denial does not name the policy %s: %v", appsPolicyName, err)
			}

			cm, err := kubectl(t, cluster, "", "-n", "argocd", "get", "configmap", cmdParamsCM, "-o", "jsonpath={.data.application\\.namespaces}")
			if err != nil {
				t.Fatal(err)
			}
			if cm != appsNamespace {
				t.Errorf("%s application.namespaces is %q, want %q", cmdParamsCM, cm, appsNamespace)
			}

			// The ConfigMap has no change time that tells a data change from a change of field
			// owner, because Argo CD takes the fields after the bootstrap apply. So the check
			// follows the content: the controller pod belongs to the current StatefulSet revision,
			// and that revision carries the checksum of the file that holds the setting.
			sts, err := kubectl(t, cluster, "", "-n", "argocd", "get", "statefulset", "argocd-application-controller", "-o", "json")
			if err != nil {
				t.Fatal(err)
			}
			var set struct {
				Spec struct {
					Template struct {
						Metadata struct {
							Annotations map[string]string `json:"annotations"`
						} `json:"metadata"`
					} `json:"template"`
				} `json:"spec"`
				Status struct {
					UpdateRevision string `json:"updateRevision"`
				} `json:"status"`
			}
			if err := json.Unmarshal([]byte(sts), &set); err != nil {
				t.Fatal(err)
			}
			params, err := os.ReadFile("../../components/argocd/argocd-cmd-params-cm.yaml")
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(params)
			if got, want := set.Spec.Template.Metadata.Annotations["poc.internal/cmd-params-sha256"], hex.EncodeToString(sum[:]); got != want {
				t.Errorf("the controller template carries cmd-params-sha256 %q, want %s", got, want)
			}
			pod, err := kubectl(t, cluster, "", "-n", "argocd", "get", "pod", controllerPod, "-o", "jsonpath={.metadata.labels.controller-revision-hash}")
			if err != nil {
				t.Fatal(err)
			}
			if pod != set.Status.UpdateRevision {
				t.Errorf("%s runs revision %q, want the current revision %q", controllerPod, pod, set.Status.UpdateRevision)
			}
		})
	}
}
