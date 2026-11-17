package scripts

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
  *" get configmap cell-steps "*)
    [[ -n "${STUB_CELLSTEPS:-}" ]] || { echo 'Error from server (NotFound)' >&2; exit 1; }
    printf '%s' "$STUB_CELLSTEPS" ;;
  *" patch configmap cell-steps "*) echo "kubectl $*" >>"$STUB_DIR/calls" ;;
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

// TestGateM6RepairStraySteps: a test that patches key <cell>.step.json of ConfigMap cell-steps and stops early leaves it. The script
// compares the SHA-256 of each envelope payload with the stepSHA256 of the spec in the same ConfigMap. --check names a key that differs
// or that the spec does not index, and exits 1. A repair removes it with a merge patch. A key that matches stays.
func TestGateM6RepairStraySteps(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	payload := `{"id":"` + strings.Repeat("a", 32) + `"}`
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
	specPayload := func(entries string) string {
		return b64([]byte(`{"steps":[` + entries + `]}`))
	}
	cm := func(index string, key string, stepPayload string) string {
		spec, _ := json.Marshal(map[string]any{"payload": specPayload(index)})
		env, _ := json.Marshal(map[string]any{"payload": b64([]byte(stepPayload))})
		data := map[string]string{"spec-envelope.json": string(spec), key: string(env)}
		out, _ := json.Marshal(map[string]any{"data": data})
		return string(out)
	}
	entry := `{"name":"dev-cell-2","stepID":"x","stepSHA256":"` + sum + `"}`
	for _, tc := range []struct {
		name, cm string
		args     []string
		code     int
		want     string
		patched  bool
	}{
		{name: "check: the key is the indexed step", cm: cm(entry, "dev-cell-2.step.json", payload), args: []string{"--check"}},
		{name: "check: the payload differs", cm: cm(entry, "dev-cell-2.step.json", `{"id":"other"}`), args: []string{"--check"}, code: 1,
			want: "holds the key dev-cell-2.step.json, and it is not the step that the spec indexes. Run: mise run gate:m6:repair"},
		{name: "check: the spec indexes no step", cm: cm("", "dev-cell-2.step.json", payload), args: []string{"--check"}, code: 1,
			want: "holds the key dev-cell-2.step.json"},
		{name: "repair: the payload differs", cm: cm(entry, "dev-cell-2.step.json", `{"id":"other"}`), patched: true},
		{name: "repair: the key is the indexed step", cm: cm(entry, "dev-cell-2.step.json", payload)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{
				"repair-m5": "#!/usr/bin/env bash\nexit 0\n",
				"replicas":  "#!/usr/bin/env bash\nexit 0\n",
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
				[]string{"STUB_DIR=" + dir, "STUB_CELLSTEPS=" + tc.cm, "GATE_M5_REPAIR=" + filepath.Join(dir, "repair-m5"),
					"HARNESS_REPLICAS=" + filepath.Join(dir, "replicas"), "HOSTSVC_SERVE=" + filepath.Join(dir, "serve")}, tc.args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Errorf("stdout %q lacks %q", out, tc.want)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
			if got := strings.Contains(string(calls), `patch configmap cell-steps --type merge -p {"data":{"dev-cell-2.step.json":null}}`); got != tc.patched {
				t.Errorf("patch ran %v, want %v; calls %q", got, tc.patched, calls)
			}
		})
	}
}

// TestGateM6ProvisionGate: gate.sh m6-provision runs only TestProvisionFromPortal, with the go test timeout that gate_test_timeout derives from
// the provisional budget of 90 minutes and the floor of 150 minutes in harness/versions.env: twice the budget, 180 minutes. It runs gate-m6-repair.sh --check and the image check of gate m6 first, and stops on a stale image. The
// pattern of gate m6 does not match the provision test, because that test deletes both cells.
func TestGateM6ProvisionGate(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, milestone, stale, want string
	}{
		{name: "healthy", milestone: "m6-provision"},
		{name: "a stale cell controller", milestone: "m6-provision", stale: "cell-controller@cell-controller-system",
			want: "Run: mise run images -- cell-controller, then CELL=dev-cp mise run cell:up"},
		{name: "a stale mgmtd", milestone: "m6-provision", stale: "mgmtd@mgmt-system",
			want: "Run: mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newM5GateRoot(t, tc.stale)
			if err := os.WriteFile(filepath.Join(root, "scripts", "gate-m6-repair.sh"), []byte("#!/usr/bin/env bash\necho \"repair $*\" >>\"$STUB_LOG\"\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "scripts", "gate-token-scan.sh"), []byte("#!/usr/bin/env bash\necho \"scan $*\" >>\"$STUB_LOG\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), tc.milestone)
			cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_STALE=" + tc.stale}
			out, err := cmd.CombinedOutput()
			calls, _ := os.ReadFile(filepath.Join(root, "calls"))
			if !strings.Contains(string(calls), "repair --check") {
				t.Errorf("gate-m6-repair.sh --check did not run first: calls %s", calls)
			}
			ran := strings.Contains(string(calls), "-run ^TestProvisionFromPortal$")
			if scanned := strings.Contains(string(calls), "scan 2026-11-16T01:02:03Z"); tc.want == "" && !scanned {
				t.Errorf("the token scan did not run after the tests: calls %s", calls)
			}
			if tc.want == "" {
				if err != nil || !ran || !strings.Contains(string(calls), "-timeout 180m") || strings.Contains(string(calls), "-run M6") {
					t.Fatalf("err %v, ran %v, output %s\ncalls %s\nwant the provision test alone with a timeout of 180m", err, ran, out, calls)
				}
				return
			}
			if err == nil || ran || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err %v, tests ran %v, output %s; want a stop before the tests that says %q", err, ran, out, tc.want)
			}
		})
	}
	if regexp.MustCompile("M6").MatchString("TestProvisionFromPortal") {
		t.Error("the pattern M6 of gate m6 matches TestProvisionFromPortal")
	}
}

// TestGateM6ProvisionTimeoutFloor: the go test timeout of gate:m6:provision is never below 150 minutes, whatever budget Task 11 sets,
// because the waits of TestProvisionFromPortal sum to 89 minutes and the two cell:down calls come on top.
func TestGateM6ProvisionTimeoutFloor(t *testing.T) {
	testtool.Need(t, "bash")
	versions, _ := filepath.Abs("../../harness/versions.env")
	lib, _ := filepath.Abs("../../scripts/lib.sh")
	for budget, want := range map[string]string{"": "150", "50": "150", "75": "150", "90": "180"} {
		cmd := exec.Command("bash", "-c", `source "$1"; source "$2"; gate_test_timeout "$3" "${GATE_M6_PROVISION_TEST_TIMEOUT_MINUTES:-}"`, "bash", lib, versions, budget)
		cmd.Env = append(os.Environ(), "CELL=dev-cell-1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("the go test timeout of gate:m6:provision with the budget %q is %s minutes, want %s", budget, got, want)
		}
	}
	out, err := exec.Command("bash", "-c", `source "$1"; printf '%s %s' "$GATE_M6_PROVISION_BUDGET_MINUTES" "$GATE_M6_PROVISION_TEST_TIMEOUT_MINUTES"`, "bash", versions).Output()
	if err != nil || string(out) != "90 150" {
		t.Errorf("versions.env sets the provision budget and timeout %q (%v), want \"90 150\"", out, err)
	}
}
