package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// m5RepairKubectl answers the reads of gate-m5-repair.sh. The replicas of celld come from STUB_CELLD_<CLUSTER> (dashes as
// underscores, default 1), and a deletion or a rollout is logged.
const m5RepairKubectl = `#!/usr/bin/env bash
case " $* " in
  *" get statefulset cell-gateway "*) printf 1 ;;
  *" get deployment celld "*)
    cluster="${2#kind-}"; var="STUB_CELLD_${cluster//-/_}"
    printf '%s' "${!var:-1}" ;;
  *" get namespaces -o json"*) echo '{"items":[]}' ;;
  *" rollout status "*) echo "kubectl $*" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
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
			write("replicas", "#!/usr/bin/env bash\necho \"harness-replicas $*\" >>\"$STUB_DIR/calls\"\n")
			args := tc.args
			out, errOut, code := runScript(t, "gate-m5-repair.sh", map[string]string{"kubectl": m5RepairKubectl},
				append([]string{"STUB_DIR=" + dir, "GATE_M4_REPAIR=" + filepath.Join(dir, "repair-m4"), "HARNESS_REPLICAS=" + filepath.Join(dir, "replicas")}, tc.env...), args...)
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
