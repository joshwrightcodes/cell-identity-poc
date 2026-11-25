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

// viewKubectl serves central-view-system of management. The bundle holds AppProject default and
// ConfigMap peer-root. STUB_PROJECTS and STUB_CONFIGMAPS add live objects, as JSON list items.
const viewKubectl = `#!/usr/bin/env bash
set -euo pipefail
args=" $* "
own='"labels":{"cell.poc.internal/harness":"central-view"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]'
case "$args" in
  *" -n central-view-system get AppProject -o json --show-managed-fields "*)
    echo "{\"items\":[{\"metadata\":{\"name\":\"default\",$own}}${STUB_PROJECTS:-}]}" ;;
  *" -n central-view-system get ConfigMap -o json --show-managed-fields "*)
    echo "{\"items\":[{\"metadata\":{\"name\":\"peer-root\",$own}}${STUB_CONFIGMAPS:-}]}" ;;
  *" get Namespace -l cell.poc.internal/harness=central-view -o json --show-managed-fields "*)
    echo "{\"items\":[{\"metadata\":{\"name\":\"central-view-system\",$own}}]}" ;;
  *" get namespace central-view-system -o json --show-managed-fields "*)
    echo "{\"metadata\":{\"name\":\"central-view-system\",$own}}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const viewBundle = `apiVersion: v1
kind: Namespace
metadata:
  name: central-view-system
---
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: default
  namespace: central-view-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: peer-root
  namespace: central-view-system
`

// project returns a live AppProject list item with the given managers and labels.
func project(name, managers, labels string) string {
	return `,{"metadata":{"name":"` + name + `","labels":{` + labels + `},"managedFields":[` + managers + `]}}`
}

// The principal creates a project with the field manager foo and updates it as argocd-agent.
const principalManager = `{"manager":"foo","operation":"Update"},{"manager":"argocd-agent","operation":"Update"}`

// TestHarnessObjectsSkipOnlyThePrincipalProjects runs check_harness_objects for central-view in
// management. Only an AppProject <agent>-<project> of an agent of VIEW_CELLS, with the principal as
// its only field manager and no harness label, may stay outside the bundle.
func TestHarnessObjectsSkipOnlyThePrincipalProjects(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, projects, configmaps, want string
	}{
		{name: "projects of both agents", projects: project("dev-dev-cell-1-cell", principalManager, "") + project("dev-dev-cell-2-cell", principalManager, "")},
		{name: "a project with the harness label of the cell copy", projects: project("dev-dev-cell-1-cell", principalManager, `"cell.poc.internal/harness":"argocd-agent"`)},
		{name: "a project of no agent", projects: project("evil", principalManager, ""), want: "'default evil'"},
		{name: "a project of an agent outside VIEW_CELLS", projects: project("dev-dev-cell-3-cell", principalManager, ""), want: "'default dev-dev-cell-3-cell'"},
		{name: "the agent name alone", projects: project("dev-dev-cell-1", principalManager, ""), want: "'default dev-dev-cell-1'"},
		{name: "a second field manager", projects: project("dev-dev-cell-1-cell", principalManager+`,{"manager":"kubectl-edit","operation":"Update"}`, ""), want: "'default dev-dev-cell-1-cell'"},
		{name: "another field manager", projects: project("dev-dev-cell-1-cell", `{"manager":"kubectl-client-side-apply","operation":"Update"}`, ""), want: "'default dev-dev-cell-1-cell'"},
		{name: "the harness label of central-view", projects: project("dev-dev-cell-1-cell", principalManager, `"cell.poc.internal/harness":"central-view"`), want: "'default dev-dev-cell-1-cell'"},
		{name: "the harness label of another component", projects: project("dev-dev-cell-1-cell", principalManager, `"cell.poc.internal/harness":"cell-identity"`), want: "'default dev-dev-cell-1-cell'"},
		{name: "another kind with the principal manager", configmaps: project("dev-dev-cell-1-cell", principalManager, ""), want: "'dev-dev-cell-1-cell peer-root'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(viewKubectl), 0o755); err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(dir, "build", "management", "bundles", "central-view")
			if err := os.MkdirAll(bundle, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte(viewBundle), 0o644); err != nil {
				t.Fatal(err)
			}
			lib, err := filepath.Abs("../../scripts/lib.sh")
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `source "$1"; check_harness_objects central-view central-view-system`, "_", lib)
			cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_PROJECTS=" + tc.projects, "STUB_CONFIGMAPS=" + tc.configmaps}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err = cmd.Run()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("check failed: %v\n%s", err, out.String())
				}
				return
			}
			if err == nil || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("err %v, output %q; want a failure that names %s", err, out.String(), tc.want)
			}
		})
	}
}
