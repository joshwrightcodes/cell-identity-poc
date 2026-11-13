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

// pruneKubectl lists objects like kubectl does: "get <Kind> -A -l <label>=<value> -o json" gives the items of $STUB_DIR/objects.json
// with that kind and that label value, and nothing else. It logs each delete.
const pruneKubectl = `#!/usr/bin/env bash
kind="" selector=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[i]}" in
    get) kind="${args[i+1]}" ;;
    -l) selector="${args[i+1]}" ;;
  esac
done
case " $* " in
  *" get "*)
    jq -c --arg kind "$kind" --arg key "${selector%%=*}" --arg val "${selector#*=}" \
      '{items: [.items[] | select(.kind == $kind and .metadata.labels[$key] == $val)]}' "$STUB_DIR/objects.json" ;;
  *" delete "*) echo "kubectl $*" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const pruneRender = `apiVersion: v1
kind: Namespace
metadata:
  name: mgmt-system
---
apiVersion: v1
kind: Service
metadata:
  name: mgmt-api
  namespace: mgmt-system
  labels:
    cell.poc.internal/harness: mgmt-api
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mgmt-intent
  namespace: mgmt-system
  labels:
    cell.poc.internal/harness: mgmt-api
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kept-role
  labels:
    cell.poc.internal/harness: mgmt-api
`

const pruneObjects = `{"items": [
 {"kind":"Service","metadata":{"name":"mgmt-bind","namespace":"mgmt-system","labels":{"cell.poc.internal/harness":"mgmt-api"}}},
 {"kind":"Service","metadata":{"name":"mgmt-api","namespace":"mgmt-system","labels":{"cell.poc.internal/harness":"mgmt-api"}}},
 {"kind":"ConfigMap","metadata":{"name":"mgmt-intent","namespace":"mgmt-system","labels":{"cell.poc.internal/harness":"mgmt-api"}}},
 {"kind":"ConfigMap","metadata":{"name":"mgmt-signing-pub","namespace":"mgmt-system","labels":{"cell.poc.internal/harness":"mgmt-api","poc.internal/made-by":"mgmtd"}}},
 {"kind":"ConfigMap","metadata":{"name":"peer-root","namespace":"other-system","labels":{"cell.poc.internal/harness":"envd"}}},
 {"kind":"ConfigMap","metadata":{"name":"cell-records","namespace":"spire-system"}},
 {"kind":"Service","metadata":{"name":"unlabelled","namespace":"mgmt-system"}},
 {"kind":"ClusterRole","metadata":{"name":"kept-role","labels":{"cell.poc.internal/harness":"mgmt-api"}}},
 {"kind":"ClusterRole","metadata":{"name":"gone-role","labels":{"cell.poc.internal/harness":"mgmt-api"}}},
 {"kind":"Namespace","metadata":{"name":"gone-namespace","labels":{"cell.poc.internal/harness":"mgmt-api"}}},
 {"kind":"Job","metadata":{"name":"gone-job","namespace":"mgmt-system","labels":{"cell.poc.internal/harness":"mgmt-api"}}}
]}`

// TestHarnessPrune: harness_prune deletes an object of a prunable kind that carries the label of the component, that the render does
// not hold, and that has no marker label poc.internal/made-by. An object in the render, an object with the marker, an object with the
// label of another component, an object with no harness label, and an object of a kind outside HARNESS_PRUNE_KINDS all stay.
func TestHarnessPrune(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness"} {
		copyFiles(t, root, d)
	}
	stub := filepath.Join(root, "stub")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"bin/kubectl": pruneKubectl, "stub/objects.json": pruneObjects, "stub/render.yaml": pruneRender} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; harness_prune mgmt-api "$2"`, "_", root, filepath.Join(stub, "render.yaml"))
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=management",
		"POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_DIR=" + stub}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("harness_prune: %v\n%s", err, errOut.String())
	}
	calls, _ := os.ReadFile(filepath.Join(stub, "calls"))
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != 2 {
		t.Fatalf("harness_prune ran %d deletes, want 2 (Service mgmt-bind and ClusterRole gone-role):\n%s", len(lines), calls)
	}
	if !strings.Contains(lines[0], "-n mgmt-system delete Service mgmt-bind ") {
		t.Errorf("the first delete is %q, want Service mgmt-bind in mgmt-system", lines[0])
	}
	if !strings.Contains(lines[1], "delete ClusterRole gone-role ") || strings.Contains(lines[1], " -n ") {
		t.Errorf("the second delete is %q, want ClusterRole gone-role with no namespace", lines[1])
	}
	for _, kept := range []string{"mgmt-api ", "mgmt-intent", "mgmt-signing-pub", "peer-root", "cell-records", "unlabelled", "kept-role", "gone-namespace", "gone-job"} {
		if strings.Contains(string(calls), kept) {
			t.Errorf("harness_prune deleted %q:\n%s", kept, calls)
		}
	}
	var pruned []string
	for _, l := range strings.Split(strings.TrimSpace(errOut.String()), "\n") {
		if strings.Contains(l, "pruned ") {
			pruned = append(pruned, l)
		}
	}
	if len(pruned) != 2 || !strings.Contains(pruned[0], "pruned Service mgmt-system/mgmt-bind") || !strings.Contains(pruned[1], "pruned ClusterRole gone-role") {
		t.Errorf("the output has %d pruned lines, want one for Service mgmt-system/mgmt-bind and one for ClusterRole gone-role:\n%s", len(pruned), errOut.String())
	}
}
