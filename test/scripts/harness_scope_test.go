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
// cell-identity. Deployment argocd-repo-server belongs to an Argo CD Application, and ConfigMap
// link-config to another harness component. Every call goes to $STUB_LOG.
//   - STUB_EXTRA adds a ConfigMap with the label of cell-identity that the bundle does not hold.
//   - STUB_NS_MANAGER sets the field manager of the Namespace.
//   - STUB_FOREIGN_MANAGER gives ConfigMap spire-agent a second field manager, argocd-controller.
//   - STUB_NO_LABEL makes the labelled workload list empty, and STUB_LIST_FAIL makes it fail.
//   - STUB_LIVE is the answer to "get -f <bundle>", the live objects of the bundle.
//   - STUB_IMPOSTOR adds a pod that runs as celld: "unlabelled" or "foreign-owner".
const sharedKubectl = `#!/usr/bin/env bash
set -euo pipefail
echo "kubectl $*" >>"$STUB_LOG"
args=" $* "
labelled='{"metadata":{"name":"celld","labels":{"cell.poc.internal/harness":"cell-identity"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"celld"}}}}'
argo='{"metadata":{"name":"argocd-repo-server","annotations":{"argocd.argoproj.io/tracking-id":"argocd:apps/Deployment:shared/argocd-repo-server"},"managedFields":[{"manager":"argocd-controller","operation":"Apply"}]},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"argocd-repo-server"}}}}'
case "$args" in
  *" get deployments,statefulsets -l cell.poc.internal/harness=cell-identity -o name "*)
    [[ -z "${STUB_LIST_FAIL:-}" ]] || { echo "error: the server is unavailable" >&2; exit 1; }
    [[ -n "${STUB_NO_LABEL:-}" ]] || echo deployment.apps/celld ;;
  *" get deployments -o name "*|*" get deployments,statefulsets -o name "*) printf 'deployment.apps/argocd-repo-server\ndeployment.apps/celld\n' ;;
  *" get Deployment -o json --show-managed-fields "*) echo "{\"items\":[$labelled,$argo]}" ;;
  *" get ConfigMap -o json --show-managed-fields "*)
    managers='{"manager":"kubectl","operation":"Apply"}'
    [[ -z "${STUB_FOREIGN_MANAGER:-}" ]] || managers="$managers"',{"manager":"argocd-controller","operation":"Update"}'
    cm='{"kind":"ConfigMap","metadata":{"name":"spire-agent","labels":{"cell.poc.internal/harness":"cell-identity"},"managedFields":['"$managers"']}}'
    argocm='{"metadata":{"name":"argocd-cm","managedFields":[{"manager":"argocd-controller","operation":"Apply"}]}}'
    linkcm='{"metadata":{"name":"link-config","labels":{"cell.poc.internal/harness":"link"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]}}'
    extra=""
    [[ -z "${STUB_EXTRA:-}" ]] || extra=',{"metadata":{"name":"left-over","labels":{"cell.poc.internal/harness":"cell-identity"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]}}'
    echo "{\"items\":[$cm,$argocm,$linkcm$extra]}" ;;
  *" get namespace shared -o json --show-managed-fields "*)
    echo "{\"metadata\":{\"name\":\"shared\",\"managedFields\":[{\"manager\":\"${STUB_NS_MANAGER:-argocd-controller}\",\"operation\":\"Apply\"}]}}" ;;
  *" get -f "*" -o json --ignore-not-found "*) printf '%s' "${STUB_LIVE:-}" ;;
  *" apply --server-side "*) ;;
  *" get deployment.apps/celld -o json "*) echo "$labelled" ;;
  *" get deployment.apps/argocd-repo-server -o json "*) echo "$argo" ;;
  *" get pods -l "*" -o jsonpath="*) echo old-uid ;;
  *" get pods -l "*" -o json "*)
    echo '{"items":[{"metadata":{"uid":"new-uid"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  *" get pods -o json "*)
    pods='{"metadata":{"name":"celld-7d9-abcde","labels":{"cell.poc.internal/harness":"cell-identity"},"ownerReferences":[{"kind":"ReplicaSet","name":"celld-7d9","controller":true}]},"spec":{"serviceAccountName":"celld"}}'
    case "${STUB_IMPOSTOR:-}" in
      unlabelled) pods="$pods"',{"metadata":{"name":"impostor","ownerReferences":[{"kind":"ReplicaSet","name":"impostor-5c4","controller":true}]},"spec":{"serviceAccountName":"celld"}}' ;;
      foreign-owner) pods="$pods"',{"metadata":{"name":"impostor","labels":{"cell.poc.internal/harness":"cell-identity"},"ownerReferences":[{"kind":"ReplicaSet","name":"impostor-5c4","controller":true}]},"spec":{"serviceAccountName":"celld"}}' ;;
    esac
    echo "{\"items\":[$pods]}" ;;
  *" get replicasets -o json "*)
    echo '{"items":[{"metadata":{"name":"celld-7d9","ownerReferences":[{"kind":"Deployment","name":"celld","controller":true}]}},{"metadata":{"name":"impostor-5c4","ownerReferences":[{"kind":"Deployment","name":"impostor","controller":true}]}}]}' ;;
  *" rollout status "*|*" delete pods -l "*) ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// harnessBundle is the bundle of cell-identity in namespace ns. owned adds its Namespace.
func harnessBundle(owned bool, ns string) string {
	b := strings.ReplaceAll(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: celld
  namespace: NS
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-agent
  namespace: NS
`, "NS", ns)
	if owned {
		b = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + ns + "\n---\n" + b
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
	// STUB_BUNDLE_NS renders the bundle into another namespace, for scripts that read HARNESS_COMPONENTS.
	ns := "shared"
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "STUB_BUNDLE_NS="); ok {
			ns = v
		}
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte(harnessBundle(owned, ns)), 0o644); err != nil {
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
// workloads belong to it.
func TestHarnessWorkloadsAreTheLabelledOnes(t *testing.T) {
	out, calls, err := runHarnessScript(t, false, `harness_workloads cell-identity shared`)
	if err != nil || strings.TrimSpace(out) != "deployment.apps/celld" {
		t.Fatalf("err %v, output %q, calls:\n%s; want only deployment.apps/celld", err, out, calls)
	}
}

// A lost label or a failed API call must stop cell:up and cell:restart, not turn them into no-ops.
func TestHarnessWorkloadsFailClosed(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"STUB_NO_LABEL=1", "holds the workloads '' with the label cell.poc.internal/harness=cell-identity, and the bundle cell-identity renders 'deployment.apps/celld'"},
		{"STUB_LIST_FAIL=1", "could not list the Deployments and StatefulSets of cell-identity in shared"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			out, calls, err := runHarnessScript(t, false, `list="$(harness_workloads cell-identity shared)" || exit 1; echo "listed: $list"`, tc.env)
			if err == nil || !strings.Contains(out, tc.want) || strings.Contains(out, "listed:") {
				t.Fatalf("err %v, output %q, calls:\n%s; want a stop that says %q", err, out, calls, tc.want)
			}
			out, calls, err = runHarnessScript(t, false, `harness_rollout_wait cell-identity shared; echo waited`, tc.env)
			if err == nil || strings.Contains(out, "waited") || strings.Contains(calls, "rollout status") {
				t.Fatalf("rollout wait: err %v, output %q, calls:\n%s; want a stop before any rollout wait", err, out, calls)
			}
		})
	}
}

// cell:up waits only for the rollouts of the labelled workloads.
func TestHarnessRolloutWaitSkipsOtherDeployments(t *testing.T) {
	out, calls, err := runHarnessScript(t, false, `harness_rollout_wait cell-identity shared`)
	if err != nil {
		t.Fatalf("err %v, output %q, calls:\n%s", err, out, calls)
	}
	if !strings.Contains(calls, "rollout status deployment.apps/celld") || strings.Contains(calls, "argocd-repo-server") {
		t.Fatalf("calls:\n%s\nwant a rollout wait for celld only", calls)
	}
}

// cell:restart restarts only the labelled workloads, never the objects that Argo CD owns, and it
// stops when the labelled workloads differ from the bundle.
func TestRestartSkipsDeploymentsOfOtherOwners(t *testing.T) {
	script, err := filepath.Abs("../../scripts/restart.sh")
	if err != nil {
		t.Fatal(err)
	}
	out, calls, err := runHarnessScript(t, false, `"$RESTART_SCRIPT"`, "RESTART_SCRIPT="+script, "STUB_BUNDLE_NS=cell-identity-system")
	if err != nil {
		t.Fatalf("restart failed: %v\n%s\ncalls:\n%s", err, out, calls)
	}
	if !strings.Contains(calls, "delete pods -l app.kubernetes.io/name=celld") {
		t.Fatalf("calls:\n%s\nwant a restart of celld", calls)
	}
	if strings.Contains(calls, "argocd-repo-server") {
		t.Fatalf("restart touched an Argo CD Deployment:\n%s", calls)
	}
	out, calls, err = runHarnessScript(t, false, `"$RESTART_SCRIPT"`, "RESTART_SCRIPT="+script, "STUB_BUNDLE_NS=cell-identity-system", "STUB_NO_LABEL=1")
	if err == nil || strings.Contains(calls, "delete pods") || !strings.Contains(out, "Run: CELL=dev-cell-1 mise run cell:up") {
		t.Fatalf("err %v, output %q, calls:\n%s; want a stop with no pod deleted", err, out, calls)
	}
}

// harness_apply refuses an object that another owner holds, before the apply. An object of an
// Application that the current root no longer holds is the M2 migration case: the harness takes it.
func TestHarnessApplyRefusesObjectsOfOtherOwners(t *testing.T) {
	live := func(meta string) string {
		return `{"kind":"List","items":[{"kind":"Deployment","metadata":{"name":"celld","namespace":"shared"}},{"kind":"ConfigMap","metadata":{"name":"spire-agent","namespace":"shared",` + meta + `}}]}`
	}
	for _, tc := range []struct{ name, meta, want string }{
		{"Application of the root", `"annotations":{"argocd.argoproj.io/tracking-id":"network-policy:/ConfigMap:shared/spire-agent"}`, "ConfigMap/spire-agent in shared belongs to the Argo CD Application network-policy"},
		{"other component", `"labels":{"cell.poc.internal/harness":"link"}`, "ConfigMap/spire-agent in shared carries the label cell.poc.internal/harness=link"},
		{"owner reference", `"ownerReferences":[{"kind":"Deployment","name":"argocd-server"}]`, "ConfigMap/spire-agent in shared has the owner Deployment/argocd-server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, err := runHarnessScript(t, false, `harness_apply cell-identity`, "STUB_LIVE="+live(tc.meta))
			if err == nil || !strings.Contains(out, tc.want) || !strings.Contains(out, "Then run: CELL=dev-cell-1 mise run cell:up") {
				t.Fatalf("err %v, output %q; want a stop that says %q", err, out, tc.want)
			}
			if strings.Contains(calls, " apply ") {
				t.Fatalf("harness_apply applied the bundle after a conflict:\n%s", calls)
			}
		})
	}
	for _, tc := range []struct{ name, live string }{
		{"no live object", ""},
		{"own objects", live(`"labels":{"cell.poc.internal/harness":"cell-identity"}`)},
		{"Application that the root no longer holds", live(`"annotations":{"argocd.argoproj.io/tracking-id":"cell-identity:/ConfigMap:shared/spire-agent"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, err := runHarnessScript(t, false, `harness_apply cell-identity`, "STUB_LIVE="+tc.live)
			if err != nil || !strings.Contains(calls, "apply --server-side --force-conflicts -f") {
				t.Fatalf("err %v, output %q, calls:\n%s; want an apply", err, out, calls)
			}
		})
	}
}

// A pod that runs as a plane ServiceAccount gets the plane SVID, so it must belong to the harness
// component through its label and its controller.
func TestPlanePodsMustBelongToTheHarness(t *testing.T) {
	snippet := `HARNESS_COMPONENTS=("cell-identity:shared"); SPIRE_LOCAL_WORKLOADS="celld=shared/celld"; check_plane_pods`
	out, calls, err := runHarnessScript(t, false, snippet)
	if err != nil {
		t.Fatalf("check failed with only the harness pod: %v\n%s\ncalls:\n%s", err, out, calls)
	}
	for _, tc := range []struct{ impostor, want string }{
		{"unlabelled", "pod shared/impostor runs as celld, and carries no cell.poc.internal/harness of a harness or link component in shared"},
		{"foreign-owner", "pod shared/impostor runs as celld, and its controller 'Deployment/impostor' is no workload of the bundle cell-identity in shared"},
	} {
		t.Run(tc.impostor, func(t *testing.T) {
			out, _, err := runHarnessScript(t, false, snippet, "STUB_IMPOSTOR="+tc.impostor)
			if err == nil || !strings.Contains(out, tc.want) || strings.Contains(out, "celld-7d9-abcde") {
				t.Fatalf("err %v, output %q; want a failure that names only the impostor: %q", err, out, tc.want)
			}
		})
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
	// ConfigMap link-config carries the label of another component, so the check ignores it.
	if strings.Contains(out, "link-config") {
		t.Fatalf("output %q names link-config, which belongs to another component", out)
	}
	out, _, err = runHarnessScript(t, false, `check_harness_objects cell-identity shared`, "STUB_FOREIGN_MANAGER=1")
	if err == nil || !strings.Contains(out, "ConfigMap/spire-agent has the field manager argocd-controller (Update object)") {
		t.Fatalf("err %v, output %q; want a failure that names the second field manager", err, out)
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

// mgmt:rotate-ca refuses a server with an upstream authority, and a cluster with no server, before
// it calls the cluster.
func TestRotateCARefusesOtherServers(t *testing.T) {
	script, err := filepath.Abs("../../scripts/mgmt-rotate-ca.sh")
	if err != nil {
		t.Fatal(err)
	}
	for cell, want := range map[string]string{
		"dev-cp":     "has an upstream authority, which signs each new CA. Run: CELL=dev-cp mise run pki:rotate-intermediate",
		"dev-cell-1": "runs no SPIRE server in harness/topology.yaml. Run: CELL=management mise run mgmt:rotate-ca",
	} {
		t.Run(cell, func(t *testing.T) {
			out, calls, err := runHarnessScript(t, false, `CELL="$ROTATE_CELL" "$ROTATE_SCRIPT"`, "ROTATE_SCRIPT="+script, "ROTATE_CELL="+cell)
			if err == nil || !strings.Contains(out, want) || calls != "" {
				t.Fatalf("err %v, output %q, kubectl calls %q; want a stop that says %q and no call", err, out, calls, want)
			}
		})
	}
}
