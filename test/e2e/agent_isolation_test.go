//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// podIP returns the address of the first pod that matches a label in a namespace.
func podIP(t *testing.T, cluster, ns, label string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "get", "pods", "-l", label, "-o", "jsonpath={.items[0].status.podIP}")
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("no pod with label %s in %s/%s: %v", label, cluster, ns, err)
	}
	return strings.TrimSpace(out)
}

// connectsFrom reports whether a TCP connection from a running container to addr:port succeeds
// within three seconds. kubectl exec runs the probe inside the existing pod.
func connectsFrom(t *testing.T, cluster, ns, workload, container, addr string, port int) bool {
	t.Helper()
	var script []string
	if container == agentDeployment {
		script = []string{"nc", "-z", "-w", "3", addr, fmt.Sprint(port)}
	} else {
		script = []string{"timeout", "3", "bash", "-c", fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", addr, port)}
	}
	args := append([]string{"-n", ns, "exec", workload, "-c", container, "--"}, script...)
	_, err := kubectl(t, cluster, "", args...)
	t.Logf("TCP from %s/%s %s to %s:%d: connected=%v", cluster, ns, workload, addr, port, err == nil)
	return err == nil
}

// TestM3AgentPodIsolation checks, in each cell, that the policy of the agent pod bounds it. Every
// probe runs from a running container with kubectl exec, so it changes nothing.
//   - The agent reaches its own Redis, and nothing else of argocd, and not the bundle store.
//   - No pod reaches the metrics port 8181, or the health and profiling port 8002 of the agent: not
//     the repo server, and not a pod of another namespace.
//   - Only the repo server reaches the bundle store, not the application controller.
func TestM3AgentPodIsolation(t *testing.T) {
	for _, cell := range viewCells(t) {
		t.Run(cell, func(t *testing.T) {
			// The cells share no state, and each fresh namespace takes about 25 seconds.
			t.Parallel()
			agent := podIP(t, cell, "argocd", "app.kubernetes.io/name=argocd-agent")
			redis := podIP(t, cell, "argocd", "app.kubernetes.io/name=argocd-redis")
			repo := podIP(t, cell, "argocd", "app.kubernetes.io/name=argocd-repo-server")
			ctrl := podIP(t, cell, "argocd", "app.kubernetes.io/name=argocd-application-controller")
			store := podIP(t, cell, "cell-system", "app.kubernetes.io/name=bundle-store")

			// Controls first, so a refusal cannot come from a broken probe.
			if !connectsFrom(t, cell, "argocd", "deploy/argocd-agent", agentDeployment, redis, 6379) {
				t.Fatal("the agent cannot reach argocd-redis, the control probe failed")
			}
			if !connectsFrom(t, cell, "argocd", "deploy/argocd-repo-server", "argocd-repo-server", store, 5000) {
				t.Fatal("the repo server cannot reach the bundle store, the control probe failed")
			}
			for _, tc := range []struct {
				name, addr string
				port       int
			}{
				{"bundle store", store, 5000},
				{"repo server", repo, 8081},
				{"application controller", ctrl, 8082},
			} {
				if connectsFrom(t, cell, "argocd", "deploy/argocd-agent", agentDeployment, tc.addr, tc.port) {
					t.Errorf("the agent reaches the %s on %d", tc.name, tc.port)
				}
			}
			for _, port := range []int{8002, 8181} {
				if connectsFrom(t, cell, "argocd", "deploy/argocd-repo-server", "argocd-repo-server", agent, port) {
					t.Errorf("the repo server reaches the agent on %d", port)
				}
				if connectsFrom(t, cell, "argocd", "statefulset/argocd-application-controller", "argocd-application-controller", agent, port) {
					t.Errorf("the application controller reaches the agent on %d", port)
				}
				if err := probeFromFreshNamespace(t, cell, agent, port, 3*time.Second); err != nil {
					t.Errorf("a pod of a fresh namespace reaches the agent on %d: %v", port, err)
				}
			}
			if connectsFrom(t, cell, "argocd", "statefulset/argocd-application-controller", "argocd-application-controller", store, 5000) {
				t.Error("the application controller reaches the bundle store")
			}
		})
	}
}

// TestM3AgentCannotWriteApplications checks that the agent ServiceAccount has no write verb on
// Applications, and cannot touch the root Application. The view sends no write event, so the
// agent needs none.
func TestM3AgentCannotWriteApplications(t *testing.T) {
	for _, cell := range viewCells(t) {
		t.Run(cell, func(t *testing.T) {
			for _, verb := range []string{"create", "update", "patch", "delete", "deletecollection"} {
				for _, name := range []string{"", "root", "argocd"} {
					args := []string{"auth", "can-i", verb, "applications.argoproj.io", "-n", "argocd", "--as=" + agentAccount}
					if name != "" {
						args = []string{"auth", "can-i", verb, "applications.argoproj.io/" + name, "-n", "argocd", "--as=" + agentAccount}
					}
					got, _ := kubectl(t, cell, "", args...)
					if strings.TrimSpace(got) != "no" {
						t.Errorf("can-i %s applications %s as the agent: %q, want no", verb, name, strings.TrimSpace(got))
					}
				}
			}
			for _, verb := range []string{"get", "list", "watch"} {
				got, _ := kubectl(t, cell, "", "auth", "can-i", verb, "applications.argoproj.io", "-n", "argocd", "--as="+agentAccount)
				if strings.TrimSpace(got) != "yes" {
					t.Errorf("can-i %s applications as the agent: %q, want yes", verb, strings.TrimSpace(got))
				}
			}
		})
	}
}
