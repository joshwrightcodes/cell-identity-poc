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
 {"kind":"Service","metadata":{"name":"mgmt-api","namespace":"other-system","labels":{"cell.poc.internal/harness":"mgmt-api"}}},
 {"kind":"ConfigMap","metadata":{"name":"mgmt-api","namespace":"mgmt-system","labels":{"cell.poc.internal/harness":"mgmt-api"}}},
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
	calls, errOut, err := runPrune(t, pruneRender)
	if err != nil {
		t.Fatalf("harness_prune: %v\n%s", err, errOut)
	}
	lines := strings.Split(strings.TrimSpace(calls), "\n")
	want := []string{
		"-n mgmt-system delete Service mgmt-bind ",
		"-n other-system delete Service mgmt-api ",  // the same name in another namespace
		"-n mgmt-system delete ConfigMap mgmt-api ", // the same name and namespace of another kind
		"delete ClusterRole gone-role ",
	}
	if len(lines) != len(want) {
		t.Fatalf("harness_prune ran %d deletes, want %d:\n%s", len(lines), len(want), calls)
	}
	for i, w := range want {
		if !strings.Contains(lines[i], w) {
			t.Errorf("delete %d is %q, want it to hold %q", i+1, lines[i], w)
		}
	}
	if strings.Contains(lines[3], " -n ") {
		t.Errorf("the ClusterRole delete is %q, want no namespace", lines[3])
	}
	for _, kept := range []string{"mgmt-intent", "mgmt-signing-pub", "peer-root", "cell-records", "unlabelled", "kept-role", "gone-namespace", "gone-job"} {
		if strings.Contains(calls, kept) {
			t.Errorf("harness_prune deleted %q:\n%s", kept, calls)
		}
	}
	if strings.Contains(calls, "-n mgmt-system delete Service mgmt-api ") {
		t.Errorf("harness_prune deleted Service mgmt-api in mgmt-system, which the render holds:\n%s", calls)
	}
	var pruned []string
	for _, l := range strings.Split(strings.TrimSpace(errOut), "\n") {
		if strings.Contains(l, "pruned ") {
			pruned = append(pruned, l)
		}
	}
	if len(pruned) != 4 || !strings.Contains(pruned[0], "pruned Service mgmt-system/mgmt-bind") || !strings.Contains(pruned[3], "pruned ClusterRole gone-role") {
		t.Errorf("the output has %d pruned lines, want 4 that start with Service mgmt-system/mgmt-bind and end with ClusterRole gone-role:\n%s", len(pruned), errOut)
	}
}

// TestHarnessPruneFailsClosed: a render that yq cannot read, and a render with no object, each stop harness_prune with a message and
// delete nothing, though every live object of the component then looks absent from the render.
func TestHarnessPruneFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct{ render, want string }{
		"unreadable render": {"kind: [unclosed\n  - : :\n", "could not read the objects"},
		"empty render":      {"", "holds no object"},
		"comments only":     {"# nothing here\n", "holds no object"},
	} {
		t.Run(name, func(t *testing.T) {
			calls, errOut, err := runPrune(t, tc.render)
			if err == nil || !strings.Contains(errOut, tc.want) {
				t.Fatalf("err %v, output %q; want a failure that says %q", err, errOut, tc.want)
			}
			if calls != "" {
				t.Errorf("harness_prune deleted objects though it could not trust the render:\n%s", calls)
			}
		})
	}
}

// runPrune runs harness_prune for mgmt-api with render as the rendered file, and returns the deletes that the fake kubectl logged.
func runPrune(t *testing.T, render string) (calls, stderr string, err error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	stub := filepath.Join(root, "stub")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"bin/kubectl": pruneKubectl, "stub/objects.json": pruneObjects, "stub/render.yaml": render} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; harness_prune mgmt-api "$2"`, "_", root, filepath.Join(stub, "render.yaml"))
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=management",
		"POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_DIR=" + stub}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	b, _ := os.ReadFile(filepath.Join(stub, "calls"))
	return string(b), errOut.String(), err
}
