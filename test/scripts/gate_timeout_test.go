package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// TestGateTestTimeout pins the go test timeout that gate.sh derives from each budget: twice the budget,
// with a floor of 30 minutes.
func TestGateTestTimeout(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "bash")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, budget, floor, want string }{
		{"m2 floor of 60 minutes", "14", "60", "60"},
		{"a budget above half the floor doubles", "40", "60", "80"},
		{"m1 keeps the floor", "3", "", "30"},
		{"m2 keeps the floor", "14", "", "30"},
		{"15 minutes is the break-even", "15", "", "30"},
		{"16 minutes doubles", "16", "", "32"},
		{"m3 doubles", "64", "", "128"},
		{"empty budget keeps the floor", "", "", "30"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `source "$1" && gate_test_timeout "$2" "$3"`, "bash", lib, tc.budget, tc.floor)
			cmd.Env = append(os.Environ(), "CELL=dev-cell-1")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("gate_test_timeout %q: %v", tc.budget, err)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Fatalf("gate_test_timeout %q = %s, want %s", tc.budget, got, tc.want)
			}
		})
	}
}

// TestGateScriptUsesDerivedTimeout makes sure gate.sh passes the derived value to go test.
func TestGateScriptUsesDerivedTimeout(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../scripts/gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`gate_test_timeout "$budget_minutes" "${!timeout_var:-}"`, `-timeout "${test_timeout}m"`} {
		if !strings.Contains(s, want) {
			t.Errorf("gate.sh lacks %s", want)
		}
	}
}

// A live gate fails at once, with the copy command, when the build output of another checkout is missing.
func TestGateNeedsTheBuildOutput(t *testing.T) {
	t.Parallel()
	build := t.TempDir()
	_, errOut, code := runScript(t, "gate.sh", withLive(nil), []string{"POC_BUILD_ROOT=" + build}, "m4")
	if code != 1 || !strings.Contains(errOut, "images.env is missing") || !strings.Contains(errOut, "cp <that checkout>/build/images.env") {
		t.Fatalf("exit %d, stderr %q; want a failure that names build/images.env and the copy command", code, errOut)
	}
	if err := os.WriteFile(filepath.Join(build, "images.env"), []byte("# commit x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut, code = runScript(t, "gate.sh", withLive(nil), []string{"POC_BUILD_ROOT=" + build}, "m4")
	if code != 1 || !strings.Contains(errOut, "is missing. Copy it from the checkout") || !strings.Contains(errOut, "cp -R <that checkout>/build/") {
		t.Fatalf("exit %d, stderr %q; want a failure that names the cluster directory", code, errOut)
	}
}

// TestGateM2TimeoutCoversTheRepair: the cleanup of the key rotation test runs a repair that is bounded at 41 minutes, so the go test timeout of
// gate:m2 must be above that bound plus the test bodies (5 minutes for the key rotation test and 8 for the others).
func TestGateM2TimeoutCoversTheRepair(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "bash")
	versions, _ := filepath.Abs("../../harness/versions.env")
	lib, _ := filepath.Abs("../../scripts/lib.sh")
	cmd := exec.Command("bash", "-c", `source "$1"; source "$2"; gate_test_timeout "$GATE_M2_BUDGET_MINUTES" "${GATE_M2_TEST_TIMEOUT_MINUTES:-}"`, "bash", lib, versions)
	cmd.Env = append(os.Environ(), "CELL=dev-cell-1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got < "54" || len(got) != 2 {
		t.Errorf("the go test timeout of gate:m2 is %s minutes, want at least 54 (41 for the repair, 13 for the tests)", got)
	}
}
