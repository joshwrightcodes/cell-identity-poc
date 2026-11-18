package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// m7RepairKubectl answers the reads and deletions of gate-m7-repair.sh. STUB_NS_<cluster> (dashes as underscores) lists the
// namespaces of a cluster as name:label words, where label is true or false. A deletion is logged, and the namespace then disappears from
// the list, unless STUB_STUCK is set. STUB_REGISTRY_PODS lists the pods of the registry test in rogue/default, and a deletion removes
// them the same way. Any other call fails.
const m7RepairKubectl = `#!/usr/bin/env bash
cluster="${2#kind-}"
var="STUB_NS_${cluster//-/_}"
case " $* " in
  *" get namespaces -o json"*)
    items=()
    for word in ${!var:-}; do
      name="${word%%:*}"; label="${word##*:}"
      grep -qx -- "$cluster $name" "$STUB_DIR/deleted" 2>/dev/null && continue
      items+=("$(jq -nc --arg n "$name" --arg l "$label" '{metadata:{name:$n,labels:(if $l == "true" then {"cell.poc.internal/e2e":"true"} else {} end)}}')")
    done
    printf '%s\n' "${items[@]}" | jq -sc 'map(select(. != null)) | {items: .}' ;;
  *" get pods -l cell.poc.internal/m7-registry -o name"*)
    for name in ${STUB_REGISTRY_PODS:-}; do
      grep -qx -- "$name" "$STUB_DIR/deleted_pods" 2>/dev/null || echo "pod/$name"
    done ;;
  *" delete pod/"*)
    echo "kubectl $*" >>"$STUB_DIR/calls"
    [[ -n "${STUB_STUCK:-}" ]] || echo "${6#pod/}" >>"$STUB_DIR/deleted_pods" ;;
  *" delete namespace "*)
    echo "kubectl $*" >>"$STUB_DIR/calls"
    [[ -n "${STUB_STUCK:-}" ]] || echo "$cluster $5" >>"$STUB_DIR/deleted" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestGateM7Repair: the m7-* namespaces with the label cell.poc.internal/e2e=true are drift in every cluster. With --check each cluster
// that holds one makes exit 1, and the output names the namespace and the repair command. With no flag the script deletes them and waits
// until they are gone. A namespace without the label, and one with another prefix, is never touched. A namespace that does not go
// away is an error.
func TestGateM7Repair(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string
		code  int
		want  []string
		calls []string
		deny  []string
	}{
		{name: "check: nothing left", args: []string{"--check"}},
		{name: "check: a registry test pod", args: []string{"--check"}, code: 1, env: []string{"STUB_REGISTRY_PODS=probe-1"},
			want: []string{"rogue holds the registry test pod probe-1 in default. Run: mise run gate:m7:repair"}},
		{name: "repair: deletes the registry test pods", env: []string{"STUB_REGISTRY_PODS=probe-1 probe-2"},
			calls: []string{"--context kind-rogue -n default delete pod/probe-1", "delete pod/probe-2"}},
		{name: "repair: a registry test pod that stays is an error", code: 1, calls: []string{"delete pod/probe-1"}, env: []string{"STUB_REGISTRY_PODS=probe-1", "STUB_STUCK=1"},
			want: []string{"still exist: rogue pod/probe-1"}},
		{name: "check: kind fails", args: []string{"--check"}, code: 1, env: []string{"STUB_KIND_FAIL=1"},
			want: []string{"error: could not list the clusters. Run: mise run harness:status"}},
		{name: "check: m7 namespaces in two clusters", args: []string{"--check"}, code: 1,
			env: []string{"STUB_NS_dev_cell_1=m7-aa:true", "STUB_NS_rogue=m7-bb:true m7-cc:true"},
			want: []string{"dev-cell-1 holds the test namespace m7-aa. Run: mise run gate:m7:repair",
				"rogue holds the test namespace m7-bb. Run: mise run gate:m7:repair", "rogue holds the test namespace m7-cc."}},
		{name: "check: another prefix and no label are no drift", args: []string{"--check"},
			env: []string{"STUB_NS_dev_cell_1=m6-aa:true m7-bb:false default:false"}},
		{name: "repair: deletes the m7 namespaces", env: []string{"STUB_NS_dev_cell_1=m7-aa:true m6-zz:true", "STUB_NS_dev_cp=m7-bb:true"},
			calls: []string{"--context kind-dev-cell-1 delete namespace m7-aa", "--context kind-dev-cp delete namespace m7-bb"}, deny: []string{"m6-zz"}},
		{name: "repair: leaves a namespace without the label", env: []string{"STUB_NS_dev_cell_1=m7-aa:false"}, deny: []string{"m7-aa"}},
		{name: "repair: a namespace that stays is an error", code: 1, env: []string{"STUB_NS_dev_cell_1=m7-aa:true", "STUB_STUCK=1"},
			calls: []string{"delete namespace m7-aa"}, want: []string{"error: after 1s these namespaces and pods (cluster, name) still exist: dev-cell-1 m7-aa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out, errOut, code := runScript(t, "gate-m7-repair.sh", withLive(map[string]string{"kubectl": m7RepairKubectl}),
				append([]string{"STUB_DIR=" + dir, "GATE_M7_WAIT=1", "GATE_M7_POLL=1"}, tc.env...), tc.args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(out+errOut, w) {
					t.Errorf("output %q lacks %q", out+errOut, w)
				}
			}
			b, _ := os.ReadFile(filepath.Join(dir, "calls"))
			for _, c := range tc.calls {
				if !strings.Contains(string(b), c) {
					t.Errorf("calls %q lack %q", b, c)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(string(b), d) {
					t.Errorf("calls %q hold %q, which the script must not touch", b, d)
				}
			}
			if len(tc.calls) == 0 && len(b) != 0 {
				t.Errorf("unexpected calls %q", b)
			}
		})
	}
}
