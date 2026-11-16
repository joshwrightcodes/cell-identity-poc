package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// m5RepairKubectl answers the reads of gate-m5-repair.sh. The replicas of celld come from STUB_CELLD_<CLUSTER> (dashes as
// underscores, default 1), and STUB_CELLD_ABSENT lists the clusters with no celld. STUB_GW_REPLICAS gives the replicas of the gateway,
// and STUB_NAMESPACES the JSON list of namespaces. A deletion or a rollout is logged.
const m5RepairKubectl = `#!/usr/bin/env bash
case " $* " in
  *" get statefulset cell-gateway "*) printf '%s' "${STUB_GW_REPLICAS:-1}" ;;
  *" get deployment celld "*)
    cluster="${2#kind-}"; var="STUB_CELLD_${cluster//-/_}"
    [[ " ${STUB_CELLD_ABSENT:-} " != *" $cluster "* ]] || exit 1
    printf '%s' "${!var:-1}" ;;
  *" get namespaces -o json"*) if [[ -n "${STUB_NAMESPACES:-}" ]]; then echo "$STUB_NAMESPACES"; else echo '{"items":[]}'; fi ;;
  *" delete namespace "*) echo "kubectl $*" >>"$STUB_DIR/calls" ;;
  *" rollout status "*) echo "kubectl $*" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// m5RepairGw stands in for gw.sh. status prints STUB_GW_STATUS, by default one stream for each cell. STUB_GW_FAIL makes it fail.
const m5RepairGw = `#!/usr/bin/env bash
[[ "$1" == status ]] || { echo "unexpected gw call: $*" >&2; exit 2; }
[[ -z "${STUB_GW_FAIL:-}" ]] || { echo '{"level":"ERROR","msg":"gw failed","error":"pod cell-gateway-0 is absent or not Ready"}'; exit 1; }
if [[ -n "${STUB_GW_STATUS:-}" ]]; then echo "$STUB_GW_STATUS"; else echo '{"epoch":1,"streams":{"dev-cell-1":1,"dev-cell-2":2}}'; fi
`

// TestGateM5RepairCelldReplicas: a run of TestM5ReplicaCap that stops early leaves three celld replicas in a cell. With --check the
// script names each such cell and the repair command, and with no flag it sets the replicas back to 1 through
// harness-replicas.sh and waits for the rollout. A cell with one replica needs nothing.
func TestGateM5RepairCelldReplicas(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string
		code  int
		want  []string
		calls []string
		deny  []string
	}{
		{name: "check: all at one replica"},
		{name: "check: dev-cell-2 has three", args: []string{"--check"}, env: []string{"STUB_CELLD_dev_cell_2=3"}, code: 1,
			want: []string{"Deployment celld in dev-cell-2 has 3 replicas. Run: mise run gate:m5:repair"}, deny: []string{"dev-cell-1 has"}},
		{name: "repair: dev-cell-2 has three", env: []string{"STUB_CELLD_dev_cell_2=3"},
			calls: []string{"harness-replicas dev-cell-2 cell-identity-system deployment/celld 1", "kubectl --context kind-dev-cell-2 -n cell-identity-system rollout status deployment/celld"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, body string) string {
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
				return p
			}
			write("repair-m4", "#!/usr/bin/env bash\nexit 0\n")
			write("gw", m5RepairGw)
			write("replicas", "#!/usr/bin/env bash\necho \"harness-replicas $*\" >>\"$STUB_DIR/calls\"\n")
			args := tc.args
			out, errOut, code := runScript(t, "gate-m5-repair.sh", map[string]string{"kubectl": m5RepairKubectl},
				append([]string{"STUB_DIR=" + dir, "GATE_M4_REPAIR=" + filepath.Join(dir, "repair-m4"), "HARNESS_REPLICAS=" + filepath.Join(dir, "replicas"), "GW_SCRIPT=" + filepath.Join(dir, "gw"), "GATE_M5_STREAM_WAIT=2"}, tc.env...), args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("stdout %q lacks %q", out, w)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(out, d) {
					t.Errorf("stdout %q holds %q", out, d)
				}
			}
			b, _ := os.ReadFile(filepath.Join(dir, "calls"))
			for _, c := range tc.calls {
				if !strings.Contains(string(b), c) {
					t.Errorf("calls %q lack %q", b, c)
				}
			}
			if len(tc.calls) == 0 && len(b) != 0 {
				t.Errorf("unexpected calls %q", b)
			}
		})
	}
}

// TestGateM5RepairStreams: each celld must hold a stream at the gateway. The repair cannot open one, so the script reports a cell
// with no stream, and a gateway that does not answer, in both modes, with CELL=<cell> mise run cell:up, and exits 1.
func TestGateM5RepairStreams(t *testing.T) {
	noStream := `STUB_GW_STATUS={"epoch":1,"streams":{"dev-cell-1":1,"dev-cell-2":0}}`
	for _, tc := range []struct {
		name string
		args []string
		env  []string
		code int
		want []string
		deny []string
	}{
		{name: "check: every cell streams"},
		{name: "check: dev-cell-2 has no stream", args: []string{"--check"}, env: []string{noStream}, code: 1,
			want: []string{"holds no stream of dev-cell-2. Run: CELL=dev-cell-2 mise run cell:up"}, deny: []string{"stream of dev-cell-1"}},
		{name: "check: the cell is absent from the streams", args: []string{"--check"}, env: []string{`STUB_GW_STATUS={"epoch":1,"streams":{"dev-cell-1":1}}`}, code: 1,
			want: []string{"holds no stream of dev-cell-2. Run: CELL=dev-cell-2 mise run cell:up"}},
		{name: "check: the gateway does not answer", args: []string{"--check"}, env: []string{"STUB_GW_FAIL=1"}, code: 1,
			want: []string{"gateway status failed", "pod cell-gateway-0 is absent or not Ready"}},
		{name: "repair: dev-cell-2 has no stream", env: []string{noStream}, code: 1,
			want: []string{"holds no stream of dev-cell-2. Run: CELL=dev-cell-2 mise run cell:up"}},
		{name: "repair: every cell streams"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{"repair-m4": "#!/usr/bin/env bash\nexit 0\n", "replicas": "#!/usr/bin/env bash\nexit 0\n", "gw": m5RepairGw} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			out, errOut, code := runScript(t, "gate-m5-repair.sh", map[string]string{"kubectl": m5RepairKubectl},
				append([]string{"STUB_DIR=" + dir, "GATE_M4_REPAIR=" + filepath.Join(dir, "repair-m4"), "HARNESS_REPLICAS=" + filepath.Join(dir, "replicas"),
					"GW_SCRIPT=" + filepath.Join(dir, "gw"), "GATE_M5_STREAM_WAIT=2"}, tc.env...), tc.args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("stdout %q lacks %q", out, w)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(out, d) {
					t.Errorf("stdout %q holds %q", out, d)
				}
			}
		})
	}
}

// TestGateM5RepairGatewayAndNamespaces: the replicas of the gateway and the m5-* test namespaces are drift. With --check each one makes
// exit 1 and names the repair command. With no flag the script repairs it, logs the call and exits 0. A namespace with another prefix
// is no drift. A problem that the repair cannot fix, an absent celld, still gives exit 1 after a later step repaired a namespace.
func TestGateM5RepairGatewayAndNamespaces(t *testing.T) {
	const m5ns = `STUB_NAMESPACES={"items":[{"metadata":{"name":"m5-x","labels":{"cell.poc.internal/e2e":"true"}}}]}`
	const m4ns = `STUB_NAMESPACES={"items":[{"metadata":{"name":"m4-x","labels":{"cell.poc.internal/e2e":"true"}}}]}`
	const unlabelled = `STUB_NAMESPACES={"items":[{"metadata":{"name":"m5-y","labels":{}}}]}`
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string
		code  int
		want  []string
		calls []string
	}{
		{name: "check: an m5 namespace", args: []string{"--check"}, env: []string{m5ns}, code: 1,
			want: []string{"holds the test namespaces m5-x. Run: mise run gate:m5:repair"}},
		{name: "check: a namespace with another prefix", args: []string{"--check"}, env: []string{m4ns}},
		{name: "check: an m5 namespace without the test label", args: []string{"--check"}, env: []string{unlabelled}},
		{name: "repair: an m5 namespace", env: []string{m5ns}, calls: []string{"delete namespace m5-x"}},
		{name: "repair: a namespace with another prefix", env: []string{m4ns}},
		{name: "check: the gateway has no replica", args: []string{"--check"}, env: []string{"STUB_GW_REPLICAS=0"}, code: 1,
			want: []string{"StatefulSet cell-gateway has 0 replicas. Run: mise run gate:m5:repair"}},
		{name: "repair: the gateway has no replica", env: []string{"STUB_GW_REPLICAS=0"},
			calls: []string{"harness-replicas dev-cp gateway-system statefulset/cell-gateway 1", "rollout status statefulset/cell-gateway"}},
		{name: "repair: celld is absent and a namespace is deleted after it", env: []string{"STUB_CELLD_ABSENT=dev-cell-2", m5ns}, code: 1,
			want: []string{"Deployment celld is absent in dev-cell-2. Run: CELL=dev-cell-2 mise run cell:up"}, calls: []string{"delete namespace m5-x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{"repair-m4": "#!/usr/bin/env bash\nexit 0\n", "gw": m5RepairGw,
				"replicas": "#!/usr/bin/env bash\necho \"harness-replicas $*\" >>\"$STUB_DIR/calls\"\n"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			out, errOut, code := runScript(t, "gate-m5-repair.sh", map[string]string{"kubectl": m5RepairKubectl},
				append([]string{"STUB_DIR=" + dir, "GATE_M4_REPAIR=" + filepath.Join(dir, "repair-m4"), "HARNESS_REPLICAS=" + filepath.Join(dir, "replicas"),
					"GW_SCRIPT=" + filepath.Join(dir, "gw"), "GATE_M5_STREAM_WAIT=2"}, tc.env...), tc.args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("stdout %q lacks %q", out, w)
				}
			}
			b, _ := os.ReadFile(filepath.Join(dir, "calls"))
			for _, c := range tc.calls {
				if !strings.Contains(string(b), c) {
					t.Errorf("calls %q lack %q", b, c)
				}
			}
			if len(tc.calls) == 0 && len(b) != 0 {
				t.Errorf("unexpected calls %q", b)
			}
		})
	}
}
