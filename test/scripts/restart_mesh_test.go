package scripts

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// meshKubectl stands in for kubectl in the cluster of restart-mesh.sh. Two namespaces are injected,
// and each has Deployments. A pod starts with the UID u1. After the script deletes the pods of a
// Deployment, the pod has the UID u2. Every istio-proxy has the cluster ID of STUB_CLUSTER_ID.
const meshKubectl = `#!/usr/bin/env bash
set -uo pipefail
state="$STUB_STATE"
args=("$@")
# Drop --context <name>.
if [[ "${args[0]}" == --context ]]; then args=("${args[@]:2}"); fi
echo "${args[*]}" >>"$state/argv.log"
ns=""
if [[ "${args[0]}" == -n ]]; then ns="${args[1]}"; args=("${args[@]:2}"); fi
cmd="${args[*]}"
case "$cmd" in
  "get namespaces -l istio-injection=enabled -o jsonpath={.items[*].metadata.name}") echo "${STUB_INJECTED-apps-demo istio-egress}" ;;
  "get deployments -o jsonpath={.items[*].metadata.name}")
    case "$ns" in apps-demo) echo "echo client" ;; istio-egress) echo "istio-egressgateway" ;; esac ;;
  "get deployment "*" -o json") echo "{\"spec\":{\"selector\":{\"matchLabels\":{\"app\":\"${args[2]}\"}}}}" ;;
  "get pods -l "*" -o jsonpath={.items[*].metadata.uid}") [[ -e "$state/deleted-${args[3]#app=}" ]] && echo u2 || echo u1 ;;
  "delete pods -l "*) touch "$state/deleted-${args[3]#app=}" ;;
  "get pods -l "*" -o json")
    app="${args[3]#app=}"
    [[ -e "$state/deleted-$app" ]] && uid=u2 || uid=u1
    echo "{\"items\":[{\"metadata\":{\"uid\":\"$uid\"},\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\"}]}}]}" ;;
  "rollout status "*) echo "rolled out" ;;
  "get pods -o json")
    echo "{\"items\":[{\"metadata\":{\"name\":\"echo-1\"},\"spec\":{\"initContainers\":[{\"name\":\"istio-proxy\",\"env\":[{\"name\":\"ISTIO_META_CLUSTER_ID\",\"value\":\"$STUB_CLUSTER_ID\"}]}],\"containers\":[{\"name\":\"echo\"}]}},
      {\"metadata\":{\"name\":\"gw-1\"},\"spec\":{\"containers\":[{\"name\":\"istio-proxy\",\"env\":[{\"name\":\"ISTIO_META_CLUSTER_ID\",\"value\":\"$STUB_CLUSTER_ID\"}]}]}},
      {\"metadata\":{\"name\":\"plain-1\"},\"spec\":{\"containers\":[{\"name\":\"curl\"}]}},
      {\"metadata\":{\"name\":\"old-1\",\"deletionTimestamp\":\"2026-01-01T00:00:00Z\"},\"spec\":{\"containers\":[{\"name\":\"istio-proxy\",\"env\":[{\"name\":\"ISTIO_META_CLUSTER_ID\",\"value\":\"Kubernetes\"}]}]}}]}" ;;
  *) echo "unexpected kubectl call: $cmd" >&2; exit 2 ;;
esac
`

func meshRun(t *testing.T, env ...string) (stdout string, code int, argv string) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	bin, state := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(meshKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../scripts/restart-mesh.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cell-1",
		"STUB_STATE=" + state, "STUB_CLUSTER_ID=dev-cell-1"}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	log, _ := os.ReadFile(filepath.Join(state, "argv.log"))
	return out.String(), code, string(log)
}

// TestRestartMeshDeletesPodsAndChecksClusterIDs checks that the task deletes the pods of every
// Deployment in each injected namespace, never writes a pod template annotation, and prints one JSON
// line with the cluster IDs of the live sidecars.
func TestRestartMeshDeletesPodsAndChecksClusterIDs(t *testing.T) {
	out, code, argv := meshRun(t)
	if code != 0 {
		t.Fatalf("exit %d, output %q", code, out)
	}
	m := oneJSONLine(t, out)
	if m["cluster"] != "dev-cell-1" || m["proxies"] != float64(4) || toJSON(m["cluster_ids"]) != `["dev-cell-1"]` {
		t.Errorf("output %v, want cluster dev-cell-1, 4 proxies (two in each namespace) and the cluster ID dev-cell-1 only", m)
	}
	if got := toJSON(m["restarted"]); got != `["apps-demo/echo","apps-demo/client","istio-egress/istio-egressgateway"]` {
		t.Errorf("restarted %s, want every Deployment of the injected namespaces", got)
	}
	for _, app := range []string{"echo", "client", "istio-egressgateway"} {
		if !strings.Contains(argv, "delete pods -l app="+app) {
			t.Errorf("the task did not delete the pods of %s:\n%s", app, argv)
		}
	}
	for _, banned := range []string{"rollout restart", " patch ", " annotate ", " apply "} {
		if strings.Contains(argv, banned) {
			t.Errorf("the task ran %q, which writes a field that Argo CD then sees as drift:\n%s", banned, argv)
		}
	}
}

// TestRestartMeshFailsOnAnotherClusterID checks that one sidecar with another cluster ID fails the
// task with one JSON error line that names the pod and the ID.
func TestRestartMeshFailsOnAnotherClusterID(t *testing.T) {
	out, code, _ := meshRun(t, "STUB_CLUSTER_ID=Kubernetes")
	m := oneJSONLine(t, out)
	msg, _ := m["error"].(string)
	if code != 1 || m["level"] != "ERROR" || !strings.Contains(msg, "apps-demo/echo-1=Kubernetes") || !strings.Contains(msg, "dev-cell-1") {
		t.Errorf("exit %d, output %v, want status 1 and an error that names apps-demo/echo-1=Kubernetes", code, m)
	}
}

// TestRestartMeshFailsWithNoInjectedNamespace checks that a cluster with no injected namespace fails
// with one JSON error line and restarts nothing.
func TestRestartMeshFailsWithNoInjectedNamespace(t *testing.T) {
	out, code, argv := meshRun(t, "STUB_INJECTED=")
	m := oneJSONLine(t, out)
	if code != 1 || !strings.Contains(m["error"].(string), "istio-injection=enabled") || strings.Contains(argv, "delete") {
		t.Errorf("exit %d, output %v, argv %q", code, m, argv)
	}
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(b)
}
