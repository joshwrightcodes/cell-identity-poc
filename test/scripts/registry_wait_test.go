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

// waitKubectl answers the reads of registry_wait and of harness_prune, and logs every call to $STUB_LOG.
//   - $STUB_CM is a file with the JSON of ConfigMap cell-registry. When it is absent, the get fails as the API server does.
//   - $STUB_CM_LATE is a file that the second read of the ConfigMap returns, when the first one failed.
const waitKubectl = `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
case " $* " in
  *" get configmap cell-registry "*)
    n=$(( $(cat "$STUB_LOG.n" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$STUB_LOG.n"
    if [[ -n "${STUB_CM_LATE:-}" && "$n" -ge 2 ]]; then cat "$STUB_CM_LATE"; exit 0; fi
    if [[ -f "$STUB_CM" ]]; then cat "$STUB_CM"; exit 0; fi
    echo 'Error from server (NotFound): configmaps "cell-registry" not found' >&2; exit 1 ;;
  *" -A -l "*) echo '{"items":[]}' ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

func registryJSON(madeBy string, cells ...string) string {
	data := []string{`"signers.pub":"key\n"`}
	for _, c := range cells {
		data = append(data, `"`+c+`.dsse.json":"{}"`)
	}
	labels := ""
	if madeBy != "" {
		labels = `"poc.internal/made-by":"` + madeBy + `"`
	}
	return `{"metadata":{"name":"cell-registry","labels":{` + labels + `}},"data":{` + strings.Join(data, ",") + `}}`
}

// runWait sources scripts/lib.sh for management and runs the snippet with the fake kubectl.
func runWait(t *testing.T, snippet string, files map[string]string, env ...string) (out, calls string, err error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(waitKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLiveStubs(t, dir)
	build := filepath.Join(dir, "build")
	bundle := filepath.Join(build, "management", "bundles", "central-view")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: registry-signer\n  namespace: central-view-system\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(dir, "kubectl.log")
	cmd := exec.Command("bash", "-c", `source "$1"; `+snippet, "_", lib)
	cmd.Env = append([]string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=management",
		"POC_BUILD_ROOT=" + build, "STUB_LOG=" + logFile, "STUB_CM=" + filepath.Join(dir, "cm.json"), "STUB_CM_LATE=" + filepath.Join(dir, "late.json")}, env...)
	if _, ok := files["late.json"]; !ok {
		cmd.Env = append(cmd.Env, "STUB_CM_LATE=")
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err = cmd.Run()
	b, _ := os.ReadFile(logFile)
	return buf.String(), string(b), err
}

// TestRegistryWait: registry_wait passes for a ConfigMap that carries the label made-by=mgmtd and a record of each cell
// with the cell-identity set. It fails after the wait, with the cell:up command of each cell that has no record, for a
// ConfigMap that is absent, one without the marker, one with no record (an empty registry), and one that lacks a cell.
// It also passes when the ConfigMap appears during the wait.
func TestRegistryWait(t *testing.T) {
	both := registryJSON("mgmtd", "dev-cell-1", "dev-cell-2")
	for _, tc := range []struct {
		name  string
		files map[string]string
		env   []string
		want  []string // text of the failure, nil when the wait passes
	}{
		{name: "published", files: map[string]string{"cm.json": both}},
		{name: "appears during the wait", files: map[string]string{"late.json": both}, env: []string{"REGISTRY_WAIT_SECONDS=20"}},
		{name: "absent", env: []string{"REGISTRY_WAIT_SECONDS=0"},
			want: []string{"does not exist, so mgmtd has not published it", "CELL=dev-cell-1 mise run cell:up, so its celld binds", "CELL=dev-cell-2 mise run cell:up, so its celld binds", "mise run mgmt -- status"}},
		{name: "no marker", files: map[string]string{"cm.json": registryJSON("", "dev-cell-1", "dev-cell-2")}, env: []string{"REGISTRY_WAIT_SECONDS=0"},
			want: []string{"has no label poc.internal/made-by=mgmtd"}},
		{name: "marker of another writer", files: map[string]string{"cm.json": registryJSON("celld", "dev-cell-1", "dev-cell-2")}, env: []string{"REGISTRY_WAIT_SECONDS=0"},
			want: []string{"has no label poc.internal/made-by=mgmtd"}},
		{name: "no record", files: map[string]string{"cm.json": registryJSON("mgmtd")}, env: []string{"REGISTRY_WAIT_SECONDS=0"},
			want: []string{"holds no record", "CELL=dev-cell-1 mise run cell:up, so its celld binds"}},
		{name: "one cell has no record", files: map[string]string{"cm.json": registryJSON("mgmtd", "dev-cell-1")}, env: []string{"REGISTRY_WAIT_SECONDS=0"},
			want: []string{"has no record of: dev-cell-2", "CELL=dev-cell-2 mise run cell:up, so its celld binds"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := runWait(t, `source "$ROOT/components/lib/registry.sh"; registry_wait central-view-system`, tc.files, tc.env...)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("registry_wait fails: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("registry_wait passes, want a failure with %q", tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output %q lacks %q", out, w)
				}
			}
			if strings.Contains(out, "CELL=dev-cell-1 mise run cell:up") && tc.name == "one cell has no record" {
				t.Errorf("output %q names a cell that has a record", out)
			}
		})
	}
}

// TestHarnessApplyWaitsForRegistryBeforePrune: harness_apply of each view component applies, waits for the registry that
// mgmtd publishes in the namespace of the component, and only then prunes. An old render left the registry with the harness
// label, so a prune before the wait would delete it. When the registry never comes, the apply fails and the prune does not
// run. Another component does not wait.
func TestHarnessApplyWaitsForRegistryBeforePrune(t *testing.T) {
	stubs := `harness_conflicts() { :; }; apply_bundle() { echo "STEP apply $1" >>"$STUB_LOG"; }; release_from_argocd() { :; }; `
	// bundle copies the fixture bundle of central-view to the bundle of another component.
	bundle := func(comp string) string {
		if comp == "central-view" {
			return ""
		}
		return `mkdir -p "$BUNDLES/` + comp + `"; cp "$BUNDLES/central-view/manifests.yaml" "$BUNDLES/` + comp + `/manifests.yaml"; `
	}
	for _, c := range []struct{ comp, ns string }{
		{"central-view", "central-view-system"},
		{"telemetry-gateway", "observability-system"},
		{"mesh-view-hub", "mesh-view-system"},
	} {
		t.Run(c.comp+"/published", func(t *testing.T) {
			out, calls, err := runWait(t, stubs+bundle(c.comp)+"harness_apply "+c.comp, map[string]string{"cm.json": registryJSON("mgmtd", "dev-cell-1", "dev-cell-2")})
			if err != nil {
				t.Fatalf("harness_apply fails: %v\n%s", err, out)
			}
			apply := strings.Index(calls, "STEP apply "+c.comp)
			wait := strings.Index(calls, "-n "+c.ns+" get configmap cell-registry")
			prune := strings.Index(calls, "-A -l cell.poc.internal/harness="+c.comp)
			if apply < 0 || wait < apply || prune < wait {
				t.Fatalf("the order is apply %d, wait %d, prune %d; want apply, then the wait in %s, then the prune:\n%s", apply, wait, prune, c.ns, calls)
			}
		})
		t.Run(c.comp+"/never published", func(t *testing.T) {
			out, calls, err := runWait(t, stubs+bundle(c.comp)+"harness_apply "+c.comp, nil, "REGISTRY_WAIT_SECONDS=0")
			if err == nil || !strings.Contains(out, "CELL=dev-cell-1 mise run cell:up, so its celld binds") {
				t.Fatalf("err %v, output %q; want a failure that names cell:up", err, out)
			}
			if strings.Contains(calls, "-A -l cell.poc.internal/harness="+c.comp) {
				t.Errorf("the prune ran though the registry never came:\n%s", calls)
			}
		})
	}
	t.Run("another component does not wait", func(t *testing.T) {
		out, calls, err := runWait(t, stubs+bundle("envd")+"harness_apply envd", nil, "REGISTRY_WAIT_SECONDS=0")
		if err != nil || strings.Contains(calls, "cell-registry") {
			t.Fatalf("err %v, output %q, calls:\n%s\nwant no wait for the registry", err, out, calls)
		}
	})
}
