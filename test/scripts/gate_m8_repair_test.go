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

// m8RepairKubectl answers the reads and deletions of gate-m8-repair.sh. Every call goes to $STUB_DIR/calls.
//   - STUB_NS_<cluster> lists the namespaces of a cluster as name:label words, and STUB_APPS_<cluster> the Applications of argocd the same
//     way, where label is true or false. A deletion adds the object to $STUB_DIR/deleted, and it then disappears from the list, unless STUB_STUCK is set.
//   - STUB_MARKER lists the clusters that hold ConfigMap apps-demo/m8-marker, and STUB_STATE_<cluster> is the content of state.json of ConfigMap bundle-state.
//   - Any other call fails.
const m8RepairKubectl = `#!/usr/bin/env bash
cluster="${2#kind-}"
var="${cluster//-/_}"
echo "kubectl $*" >>"$STUB_DIR/calls"
listing() { # listing <variable> <kind>
  local items=() word name label
  for word in ${!1:-}; do
    name="${word%%:*}"; label="${word##*:}"
    grep -qx -- "$cluster $2 $name" "$STUB_DIR/deleted" 2>/dev/null && continue
    items+=("$(jq -nc --arg n "$name" --arg l "$label" '{metadata:{name:$n,labels:(if $l == "true" then {"cell.poc.internal/e2e":"true"} else {} end)}}')")
  done
  printf '%s\n' "${items[@]}" | jq -sc 'map(select(. != null)) | {items: .}'
}
case " $* " in
  *" get namespaces -o json"*) v="STUB_NS_$var"; listing "$v" namespace ;;
  *" -n argocd get applications -o json"*) v="STUB_APPS_$var"; listing "$v" application ;;
  *" get configmap bundle-state "*) v="STUB_STATE_$var"; printf '%s' "${!v:-}" ;;
  *" -n apps-demo get configmap m8-marker "*)
    if [[ " ${STUB_MARKER:-} " == *" $cluster "* ]] && ! grep -qx -- "$cluster configmap m8-marker" "$STUB_DIR/deleted" 2>/dev/null; then echo configmap/m8-marker; fi ;;
  *" delete namespace "*) [[ -n "${STUB_STUCK:-}" ]] || echo "$cluster namespace $5" >>"$STUB_DIR/deleted" ;;
  *" delete application "*) [[ -n "${STUB_STUCK:-}" ]] || echo "$cluster application $7" >>"$STUB_DIR/deleted" ;;
  *" delete configmap m8-marker "*) echo "$cluster configmap m8-marker" >>"$STUB_DIR/deleted" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// m8RepairMise records mise run bundle -- repair and publish. STUB_PUBLISH_FAIL names a target whose publish fails.
const m8RepairMise = `#!/usr/bin/env bash
echo "mise $*" >>"$STUB_DIR/calls"
case "$*" in
  "run bundle -- repair --target "*) echo '{"repaired":true}' ;;
  "run bundle -- publish --target "*" --wait")
    target="$6"
    [[ "$target" != "${STUB_PUBLISH_FAIL:-none}" ]] || { echo "error: the set of $target ended refused" >&2; exit 1; }
    echo '{"outcome":"applied"}' ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

// m8RepairRun runs gate-m8-repair.sh with the stubs. recorded is the content of build/gate/m8-bundles, and an empty string writes no file. It returns
// the output, the calls that the stubs logged, the directory of the run and the exit status.
func m8RepairRun(t *testing.T, recorded string, env []string, args ...string) (out, calls, dir string, code int) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir = t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range withLive(map[string]string{"kubectl": m8RepairKubectl, "mise": m8RepairMise}) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if recorded != "" {
		if err := os.MkdirAll(filepath.Join(dir, "build", "gate"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "build", "gate", "m8-bundles"), []byte(recorded), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script, err := filepath.Abs("../../scripts/gate-m8-repair.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "POC_BUILD_ROOT=" + filepath.Join(dir, "build"),
		"STUB_DIR=" + dir, "GATE_M8_WAIT=1", "GATE_M8_POLL=1"}, env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	b, _ := os.ReadFile(filepath.Join(dir, "calls"))
	return buf.String(), string(b), dir, code
}

// m8Healthy is the state of a target that needs no repair.
const m8Healthy = `{"source":"signed","state":"healthy","root":{"digest":"sha256:11"}}`

// m8RolledBack is the state of a target whose rollback ended rolled_back. failed adds the detail rollback_unhealthy of a rollback that did not finish.
func m8RolledBack(failed bool) string {
	detail := "argocd:Synced/Degraded"
	if failed {
		detail = "rollback_unhealthy"
	}
	return `{"source":"signed","state":"rolled_back","result":{"outcome":"rolled_back","reason":"unhealthy","detail":"` + detail + `"}}`
}

// at returns the position of the first call that holds text, or -1.
func at(calls, text string) int { return strings.Index(calls, text) }

// TestGateM8RepairDeletesProbes: the m8-* namespaces with the label cell.poc.internal/e2e=true and the e2e Applications m8-* are probes of a gate:m8
// run. The script deletes them in each cluster with a bundle role. It never touches an object without the label, another prefix, the
// Application apps-sample, or a cluster without a bundle role.
func TestGateM8RepairDeletesProbes(t *testing.T) {
	_, calls, _, code := m8RepairRun(t, "", []string{
		"STUB_NS_dev_cell_1=m8-aa:true m8-keep:false m7-bb:true default:false", "STUB_NS_dev_cp=m8-cc:true", "STUB_NS_rogue=m8-dd:true", "STUB_NS_management=m8-ee:true",
		"STUB_APPS_dev_cell_2=m8-project-probe:true m8-nolabel:false root:false",
	})
	if code != 0 {
		t.Fatalf("exit %d, calls:\n%s", code, calls)
	}
	for _, want := range []string{"--context kind-dev-cell-1 delete namespace m8-aa", "--context kind-dev-cp delete namespace m8-cc", "--context kind-dev-cell-2 -n argocd delete application m8-project-probe"} {
		if !strings.Contains(calls, want) {
			t.Errorf("the calls lack %q:\n%s", want, calls)
		}
	}
	for _, deny := range []string{"m8-keep", "m7-bb", "m8-nolabel", "delete application root", "m8-dd", "m8-ee"} {
		if strings.Contains(calls, deny) {
			t.Errorf("the calls hold %q, which the script must not touch:\n%s", deny, calls)
		}
	}
	if strings.Contains(calls, "mise ") {
		t.Errorf("the script published or repaired with nothing to restore:\n%s", calls)
	}
}

// TestGateM8RepairRepairsBeforePublish: a target in rolled_back with rollback_unhealthy gets mise run bundle -- repair --target <t> first, and then its set is
// published again. A target in rolled_back with another detail is published and not repaired.
func TestGateM8RepairRepairsBeforePublish(t *testing.T) {
	out, calls, _, code := m8RepairRun(t, "", []string{"STUB_STATE_dev_cell_2=" + m8RolledBack(true), "STUB_STATE_dev_cell_1=" + m8RolledBack(false),
		"STUB_STATE_dev_cp=" + m8Healthy})
	if code != 0 {
		t.Fatalf("exit %d:\n%s\ncalls:\n%s", code, out, calls)
	}
	repair, publish := at(calls, "mise run bundle -- repair --target dev-cell-2\n"), at(calls, "mise run bundle -- publish --target dev-cell-2 --wait\n")
	if repair < 0 || publish < 0 || repair > publish {
		t.Errorf("repair of dev-cell-2 at %d, publish at %d, want the repair first:\n%s", repair, publish, calls)
	}
	if at(calls, "publish --target dev-cell-1 --wait") < 0 || at(calls, "repair --target dev-cell-1") >= 0 {
		t.Errorf("dev-cell-1 (rolled_back with no rollback_unhealthy) must be published and not repaired:\n%s", calls)
	}
	if at(calls, "--target dev-cp") >= 0 {
		t.Errorf("dev-cp is healthy and was not recorded, so it needs no publish:\n%s", calls)
	}
	// A repair of a target must come before the publish of any target, because a repair can change what the others read.
	if first := at(calls, "publish --target"); first < repair {
		t.Errorf("a publish at %d came before the repair at %d:\n%s", first, repair, calls)
	}
}

// TestGateM8RepairRestoresMarkedTargets: each target in build/gate/m8-bundles, each target with the Application apps-sample or ConfigMap
// apps-demo/m8-marker, and each target in rolled_back gets mise run bundle -- publish --target <t> --wait, dev-cp first. The marker goes after the
// publish. A target with none of the signs gets nothing, and the record of the run goes when every publish ended applied.
func TestGateM8RepairRestoresMarkedTargets(t *testing.T) {
	out, calls, dir, code := m8RepairRun(t, "dev-cell-1\ndev-cp\n", []string{"STUB_APPS_dev_cell_2=apps-sample:false", "STUB_MARKER=dev-cell-2 dev-cp",
		"STUB_STATE_dev_cell_1=" + m8Healthy, "STUB_STATE_dev_cell_2=" + m8Healthy, "STUB_STATE_dev_cp=" + m8Healthy})
	if code != 0 {
		t.Fatalf("exit %d:\n%s\ncalls:\n%s", code, out, calls)
	}
	cp, c1, c2 := at(calls, "publish --target dev-cp --wait"), at(calls, "publish --target dev-cell-1 --wait"), at(calls, "publish --target dev-cell-2 --wait")
	if cp < 0 || c1 < 0 || c2 < 0 || cp > c1 || cp > c2 {
		t.Errorf("publish of dev-cp at %d, dev-cell-1 at %d, dev-cell-2 at %d, want all three and dev-cp first:\n%s", cp, c1, c2, calls)
	}
	for _, tc := range []struct{ cluster, publish string }{{"dev-cp", "publish --target dev-cp --wait"}, {"dev-cell-2", "publish --target dev-cell-2 --wait"}} {
		pub, del := at(calls, tc.publish), at(calls, "--context kind-"+tc.cluster+" -n apps-demo delete configmap m8-marker")
		if del < 0 || del < pub {
			t.Errorf("the marker of %s must go after its publish: publish at %d, delete at %d:\n%s", tc.cluster, pub, del, calls)
		}
	}
	if at(calls, "--context kind-dev-cell-1 -n apps-demo delete configmap") >= 0 {
		t.Errorf("dev-cell-1 holds no marker, so nothing goes:\n%s", calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "build", "gate", "m8-bundles")); err == nil {
		t.Error("build/gate/m8-bundles stays after every publish ended applied")
	}

	// A publish that fails is an error, and it keeps the record, so that the next run restores again.
	out, _, dir, code = m8RepairRun(t, "dev-cell-1\n", []string{"STUB_STATE_dev_cell_1=" + m8Healthy, "STUB_PUBLISH_FAIL=dev-cell-1"})
	if code != 1 || !strings.Contains(out, "dev-cell-1") {
		t.Errorf("a failed publish gave exit %d and %q, want exit 1 that names dev-cell-1", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "build", "gate", "m8-bundles")); err != nil {
		t.Error("build/gate/m8-bundles went although a publish failed")
	}
}

// TestGateM8CheckNamesRepair: --check reports each trace of a gate:m8 run with the command that repairs it, exits 1, and changes nothing. A clean
// harness gives exit 0.
func TestGateM8CheckNamesRepair(t *testing.T) {
	const repair = "Run: mise run gate:m8:repair"
	for _, tc := range []struct {
		name     string
		recorded string
		env      []string
		code     int
		want     []string
	}{
		{name: "clean", env: []string{"STUB_STATE_dev_cell_1=" + m8Healthy, "STUB_STATE_dev_cp=" + m8Healthy}},
		{name: "a rollback that did not finish", code: 1, env: []string{"STUB_STATE_dev_cell_2=" + m8RolledBack(true)},
			want: []string{"dev-cell-2", "rollback_unhealthy", repair}},
		{name: "a rolled_back set", code: 1, env: []string{"STUB_STATE_dev_cell_1=" + m8RolledBack(false)}, want: []string{"dev-cell-1", "rolled_back", repair}},
		{name: "a probe namespace", code: 1, env: []string{"STUB_NS_dev_cp=m8-aa:true"}, want: []string{"dev-cp holds the test namespace m8-aa", repair}},
		{name: "a probe Application", code: 1, env: []string{"STUB_APPS_dev_cell_1=m8-project-probe:true"}, want: []string{"dev-cell-1 holds the test Application m8-project-probe", repair}},
		{name: "the Application apps-sample", code: 1, env: []string{"STUB_APPS_dev_cell_1=apps-sample:false"}, want: []string{"dev-cell-1 holds the Application apps-sample", repair}},
		{name: "the marker ConfigMap", code: 1, env: []string{"STUB_MARKER=dev-cell-2"}, want: []string{"dev-cell-2 holds the ConfigMap apps-demo/m8-marker", repair}},
		{name: "a target of an aborted run", code: 1, recorded: "dev-cell-2\n", want: []string{"dev-cell-2", "build/gate/m8-bundles", repair}},
		{name: "another prefix and no label are no drift", env: []string{"STUB_NS_dev_cell_1=m7-aa:true m8-bb:false"}},
		{name: "kind fails", code: 1, env: []string{"STUB_KIND_FAIL=1"}, want: []string{"error: could not list the clusters. Run: mise run harness:status"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, dir, code := m8RepairRun(t, tc.recorded, tc.env, "--check")
			if code != tc.code {
				t.Fatalf("exit %d, want %d\n%s\ncalls %s", code, tc.code, out, calls)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output %q lacks %q", out, w)
				}
			}
			for _, mutating := range []string{" delete ", "mise "} {
				if strings.Contains(calls, mutating) {
					t.Errorf("--check changed something (%q):\n%s", mutating, calls)
				}
			}
			if tc.recorded != "" {
				if _, err := os.Stat(filepath.Join(dir, "build", "gate", "m8-bundles")); err != nil {
					t.Error("--check removed build/gate/m8-bundles")
				}
			}
		})
	}
}

// TestGateM8RepairLeftovers: a probe namespace that stays after the deletion is an error that names it.
func TestGateM8RepairLeftovers(t *testing.T) {
	out, _, _, code := m8RepairRun(t, "", []string{"STUB_NS_dev_cell_1=m8-aa:true", "STUB_STUCK=1"})
	if code != 1 || !strings.Contains(out, "dev-cell-1 m8-aa") {
		t.Errorf("exit %d and %q, want exit 1 that names dev-cell-1 m8-aa", code, out)
	}
}
