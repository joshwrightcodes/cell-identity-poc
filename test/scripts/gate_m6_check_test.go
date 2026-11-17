package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// TestGateM6ImageCheck: gate.sh m6 compares the images of mgmtd, envd, the cell controller, the cell gateway and the SPIRE server plugin
// with build/images.env. It stops before the tests on a stale image and names the command that brings the workload up to date.
// The check runs after gate-m6-repair.sh --check, and a gate with every image current runs the tests with -run M6.
func TestGateM6ImageCheck(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, stale, want string
	}{
		{name: "healthy"},
		{name: "a stale mgmtd", stale: "mgmtd@mgmt-system",
			want: "Run: mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
		{name: "a stale envd", stale: "envd@envd-system",
			want: "Run: mise run images -- envd, then CELL=dev-cp mise run cell:up"},
		{name: "a stale cell controller", stale: "cell-controller@cell-controller-system",
			want: "Run: mise run images -- cell-controller, then CELL=dev-cp mise run cell:up"},
		{name: "a stale cell gateway", stale: "cellgw@gateway-system",
			want: "Run: mise run images -- cellgw, then CELL=dev-cp mise run cell:up"},
		{name: "a stale SPIRE server plugin", stale: "cluster-jwt-server@dev-cp",
			want: "Run: mise run images -- cluster-jwt-server, then CELL=dev-cp mise run cell:up"},
		{name: "a stale celld is left to the M5 check", stale: "celld@dev-cell-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newM5GateRoot(t, tc.stale)
			if err := os.WriteFile(filepath.Join(root, "scripts", "gate-m6-repair.sh"), []byte("#!/usr/bin/env bash\necho \"repair $*\" >>\"$STUB_LOG\"\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), "m6")
			cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_STALE=" + tc.stale}
			out, err := cmd.CombinedOutput()
			calls, _ := os.ReadFile(filepath.Join(root, "calls"))
			ran := strings.Contains(string(calls), "-run M6")
			if !strings.Contains(string(calls), "repair --check") {
				t.Errorf("gate-m6-repair.sh --check did not run first: calls %s", calls)
			}
			if tc.want == "" {
				if err != nil || !ran {
					t.Fatalf("err %v, ran %v, output %s\ncalls %s", err, ran, out, calls)
				}
				return
			}
			if err == nil || ran || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err %v, tests ran %v, output %s; want a stop before the tests that says %q", err, ran, out, tc.want)
			}
		})
	}
}

// m6RepairKubectl answers the reads of gate-m6-repair.sh. STUB_CC_REPLICAS gives the replicas of Deployment cell-controller (default 1),
// and STUB_CC_ABSENT makes the Deployment absent. The namespace list is empty. A rollout is logged.
const m6RepairKubectl = `#!/usr/bin/env bash
case " $* " in
  *" get deployment cell-controller "*)
    [[ -z "${STUB_CC_ABSENT:-}" ]] || { echo 'Error from server (NotFound): deployments.apps "cell-controller" not found' >&2; exit 1; }
    printf '%s' "${STUB_CC_REPLICAS:-1}" ;;
  *" get namespaces -o json"*) echo '{"items":[]}' ;;
  *" rollout status "*) echo "kubectl $*" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestGateM6RepairCellControllerReplicas: a test that scales the cell controller down and stops early leaves it at another number of
// replicas. With --check the script names the Deployment and the repair command, and with no flag it sets the replicas back to 1
// through harness-replicas.sh and waits for the rollout. One replica needs nothing, and an absent Deployment names cell:up.
func TestGateM6RepairCellControllerReplicas(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string
		code  int
		want  []string
		calls []string
	}{
		{name: "check: one replica", args: []string{"--check"}},
		{name: "check: none", args: []string{"--check"}, env: []string{"STUB_CC_REPLICAS=0"}, code: 1,
			want: []string{"Deployment cell-controller has 0 replicas. Run: mise run gate:m6:repair"}},
		{name: "check: absent", args: []string{"--check"}, env: []string{"STUB_CC_ABSENT=1"}, code: 1,
			want: []string{"Deployment cell-controller is absent in dev-cp. Run: CELL=dev-cp mise run cell:up"}},
		{name: "repair: none", env: []string{"STUB_CC_REPLICAS=0"},
			calls: []string{"harness-replicas dev-cp cell-controller-system deployment/cell-controller 1", "kubectl --context kind-dev-cp -n cell-controller-system rollout status deployment/cell-controller"}},
		{name: "repair: one replica"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{
				"repair-m5": "#!/usr/bin/env bash\nexit 0\n",
				"replicas":  "#!/usr/bin/env bash\necho \"harness-replicas $*\" >>\"$STUB_DIR/calls\"\n",
				"serve":     "#!/usr/bin/env bash\ncase \"$1\" in status) echo '{\"running\":true}' ;; steps) echo '{\"steps\":[]}' ;; esac\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			stubs := map[string]string{"kubectl": m6RepairKubectl}
			for name, body := range liveStubs {
				stubs[name] = body
			}
			out, errOut, code := runScript(t, "gate-m6-repair.sh", stubs,
				append([]string{"STUB_DIR=" + dir, "GATE_M5_REPAIR=" + filepath.Join(dir, "repair-m5"), "HARNESS_REPLICAS=" + filepath.Join(dir, "replicas"),
					"HOSTSVC_SERVE=" + filepath.Join(dir, "serve")}, tc.env...), tc.args...)
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
