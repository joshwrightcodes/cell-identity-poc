package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// sharedKubectl serves a namespace that a harness component shares with Argo CD objects, as
// argocd and observability-system do in the cells. Deployment celld carries the harness label of
// cell-identity. Deployment argocd-repo-server belongs to an Argo CD Application. Every call goes to
// $STUB_LOG. STUB_OWNED makes the namespace the harness namespace of the component, so Argo CD
// objects in it are extra. STUB_EXTRA adds a labelled ConfigMap that the bundle does not hold.
// STUB_NS_MANAGER sets the field manager of the Namespace.
const sharedKubectl = `#!/usr/bin/env bash
set -euo pipefail
echo "kubectl $*" >>"$STUB_LOG"
args=" $* "
labelled='{"metadata":{"name":"celld","labels":{"cell.poc.internal/harness":"cell-identity"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"celld"}}}}'
argo='{"metadata":{"name":"argocd-repo-server","annotations":{"argocd.argoproj.io/tracking-id":"argocd:apps/Deployment:shared/argocd-repo-server"},"managedFields":[{"manager":"argocd-controller","operation":"Apply"}]},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"argocd-repo-server"}}}}'
case "$args" in
  *" get deployments -l cell.poc.internal/harness=cell-identity -o name "*) echo deployment.apps/celld ;;
  *" get deployments -o name "*) printf 'deployment.apps/argocd-repo-server\ndeployment.apps/celld\n' ;;
  *" get Deployment -o json --show-managed-fields "*) echo "{\"items\":[$labelled,$argo]}" ;;
  *" get ConfigMap -o json --show-managed-fields "*)
    cm='{"metadata":{"name":"spire-agent","labels":{"cell.poc.internal/harness":"cell-identity"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]}}'
    argocm='{"metadata":{"name":"argocd-cm","managedFields":[{"manager":"argocd-controller","operation":"Apply"}]}}'
    extra=""
    [[ -z "${STUB_EXTRA:-}" ]] || extra=',{"metadata":{"name":"left-over","labels":{"cell.poc.internal/harness":"cell-identity"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]}}'
    echo "{\"items\":[$cm,$argocm$extra]}" ;;
  *" get namespace shared -o json --show-managed-fields "*)
    echo "{\"metadata\":{\"name\":\"shared\",\"managedFields\":[{\"manager\":\"${STUB_NS_MANAGER:-argocd-controller}\",\"operation\":\"Apply\"}]}}" ;;
  *" get deployment.apps/celld -o json "*) echo "$labelled" ;;
  *" get deployment.apps/argocd-repo-server -o json "*) echo "$argo" ;;
  *" get pods -l "*" -o jsonpath="*) echo old-uid ;;
  *" get pods -l "*" -o json "*)
    echo '{"items":[{"metadata":{"uid":"new-uid"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  *" delete pods -l "*) ;;
  *" rollout status "*) ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// harnessBundle is the bundle of cell-identity in the shared namespace. STUB_OWNED adds its Namespace.
func harnessBundle(owned bool) string {
	b := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: celld
  namespace: shared
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-agent
  namespace: shared
`
	if owned {
		b = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: shared\n---\n" + b
	}
	return b
}

// runHarnessScript runs a bash snippet after it sources scripts/lib.sh for dev-cell-1, with the
// fake kubectl and a build directory that holds the cell-identity bundle. It returns the output
// and the kubectl calls.
func runHarnessScript(t *testing.T, owned bool, snippet string, env ...string) (string, string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(sharedKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	build := filepath.Join(dir, "build")
	bundle := filepath.Join(build, "dev-cell-1", "bundles", "cell-identity")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte(harnessBundle(owned)), 0o644); err != nil {
		t.Fatal(err)
	}
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(dir, "kubectl.log")
	cmd := exec.Command("bash", "-c", `source "$1"; `+snippet, "_", lib)
	cmd.Env = append([]string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "POC_BUILD_ROOT=" + build, "STUB_LOG=" + logFile}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	calls, _ := os.ReadFile(logFile)
	return out.String(), string(calls), err
}

// A harness component can share its namespace with Argo CD objects. Only its own labelled
// Deployments belong to it.
func TestHarnessDeploymentsAreTheLabelledOnes(t *testing.T) {
	out, calls, err := runHarnessScript(t, false, `harness_deployments cell-identity shared`)
	if err != nil || strings.TrimSpace(out) != "deployment.apps/celld" {
		t.Fatalf("err %v, output %q, calls:\n%s; want only deployment.apps/celld", err, out, calls)
	}
}

// cell:up waits only for the rollouts of the labelled Deployments.
func TestHarnessRolloutWaitSkipsOtherDeployments(t *testing.T) {
	out, calls, err := runHarnessScript(t, false, `harness_rollout_wait cell-identity shared`)
	if err != nil {
		t.Fatalf("err %v, output %q, calls:\n%s", err, out, calls)
	}
	if !strings.Contains(calls, "rollout status deployment.apps/celld") || strings.Contains(calls, "argocd-repo-server") {
		t.Fatalf("calls:\n%s\nwant a rollout wait for celld only", calls)
	}
}

// cell:restart restarts only the labelled Deployments, never the objects that Argo CD owns.
func TestRestartSkipsDeploymentsOfOtherOwners(t *testing.T) {
	script, err := filepath.Abs("../../scripts/restart.sh")
	if err != nil {
		t.Fatal(err)
	}
	out, calls, err := runHarnessScript(t, false, `"$RESTART_SCRIPT"`, "RESTART_SCRIPT="+script)
	if err != nil {
		t.Fatalf("restart failed: %v\n%s\ncalls:\n%s", err, out, calls)
	}
	if !strings.Contains(calls, "delete pods -l app.kubernetes.io/name=celld") {
		t.Fatalf("calls:\n%s\nwant a restart of celld", calls)
	}
	if strings.Contains(calls, "argocd-repo-server") {
		t.Fatalf("restart touched an Argo CD Deployment:\n%s", calls)
	}
}

// In a shared namespace, cell:verify compares only the objects with the harness label of the
// component, and skips the field managers of the Namespace, which the component does not hold.
func TestHarnessObjectsInASharedNamespace(t *testing.T) {
	out, calls, err := runHarnessScript(t, false, `check_harness_objects cell-identity shared`)
	if err != nil {
		t.Fatalf("check failed in a shared namespace: %v\n%s\ncalls:\n%s", err, out, calls)
	}
	out, _, err = runHarnessScript(t, false, `check_harness_objects cell-identity shared`, "STUB_EXTRA=1")
	if err == nil || !strings.Contains(out, "left-over") {
		t.Fatalf("err %v, output %q; want a failure that names the labelled ConfigMap left-over", err, out)
	}
}

// In the namespace of the component, every object that another manager wrote is extra, and the
// Namespace must have only the kubectl apply manager, as in M2.
func TestHarnessObjectsInAnOwnedNamespace(t *testing.T) {
	out, _, err := runHarnessScript(t, true, `check_harness_objects cell-identity shared`, "STUB_NS_MANAGER=kubectl")
	if err == nil || !strings.Contains(out, "argocd-repo-server") || !strings.Contains(out, "argocd-cm") {
		t.Fatalf("err %v, output %q; want a failure that names the Argo CD objects", err, out)
	}
	out, _, err = runHarnessScript(t, true, `check_harness_objects cell-identity shared`)
	if err == nil || !strings.Contains(out, "Namespace/shared has the field manager argocd-controller") {
		t.Fatalf("err %v, output %q; want a failure that names the Namespace manager", err, out)
	}
}
