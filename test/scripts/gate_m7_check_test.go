package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// runGateM7 runs gate.sh m7 in a stub root. stale names a workload that runs another image, and hit makes the token scan fail. It returns
// the output, the calls that the stubs logged and the error.
func runGateM7(t *testing.T, stale, repair string, hit bool) (out, calls string, err error) {
	t.Helper()
	return runGateM7With(t, stale, repair, m6RepairOK, hit)
}

// runGateM7With is runGateM7 with the body of the gate-m6-repair.sh stub.
func runGateM7With(t *testing.T, stale, repair, m6Repair string, hit bool) (out, calls string, err error) {
	t.Helper()
	return runGateM7Registry(t, stale, repair, m6Repair, hit, `["PATH=/bin","REGISTRY_STORAGE_DELETE_ENABLED=false"]`)
}

// m7Docker stands in for docker: the time of the node, the address of a node container, and the environment of registry-mirror, which
// STUB_REGISTRY_ENV gives as JSON. STUB_REGISTRY_FAIL makes the inspect of the registry fail.
const m7Docker = `#!/usr/bin/env bash
case "$*" in
  "inspect -f {{json .Config.Env}} registry-mirror")
    [[ -z "${STUB_REGISTRY_FAIL:-}" ]] || { echo "Error: No such container: registry-mirror" >&2; exit 1; }
    echo "$STUB_REGISTRY_ENV" ;;
  "exec dev-cp-control-plane date -u +%Y-%m-%dT%H:%M:%SZ") echo 2026-11-16T01:02:03Z ;;
  "inspect "*) echo 172.18.0.9 ;;
  *) exit 2 ;;
esac
`

// runGateM7Registry is runGateM7With with the environment that docker inspect reports for registry-mirror. An empty value makes the
// inspect fail.
func runGateM7Registry(t *testing.T, stale, repair, m6Repair string, hit bool, registryEnv string) (out, calls string, err error) {
	t.Helper()
	root := newM5GateRoot(t, stale)
	if err := os.WriteFile(filepath.Join(root, "bin", "docker"), []byte(m7Docker), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(root, "scripts", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("gate-m7-repair.sh", repair)
	write("gate-m6-repair.sh", m6Repair)
	write("gate-token-scan.sh", `#!/usr/bin/env bash
echo "scan $*" >>"$STUB_LOG"
[[ -z "$STUB_HIT" ]] || { echo "a token is in the log: dev-cp ns/pod container line 7"; exit 1; }
`)
	h := ""
	if hit {
		h = "1"
	}
	cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), "m7")
	cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_STALE=" + stale, "STUB_HIT=" + h,
		"STUB_REGISTRY_ENV=" + registryEnv}
	if registryEnv == "" {
		cmd.Env = append(cmd.Env, "STUB_REGISTRY_FAIL=1")
	}
	b, err := cmd.CombinedOutput()
	c, _ := os.ReadFile(filepath.Join(root, "calls"))
	return string(b), string(c), err
}

const m6RepairOK = "#!/usr/bin/env bash\necho \"m6 repair $*\" >>\"$STUB_LOG\"\nexit 0\n"

const m7RepairOK = "#!/usr/bin/env bash\necho \"m7 repair $*\" >>\"$STUB_LOG\"\nexit 0\n"

// TestGateM7ImageCheck: gate.sh m7 runs gate-m6-repair.sh --check, then gate-m7-repair.sh --check, and then the image check of M6 with celld of each live cell added. A
// stale image stops the run before the tests and names the command that updates the workload.
func TestGateM7ImageCheck(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct{ name, stale, want string }{
		{name: "healthy"},
		{name: "a stale mgmtd", stale: "mgmtd@mgmt-system", want: "Run: mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
		{name: "a stale cell gateway", stale: "cellgw@gateway-system", want: "Run: mise run images -- cellgw, then CELL=dev-cp mise run cell:up"},
		{name: "a stale celld", stale: "celld@dev-cell-1", want: "Run: mise run images -- celld cluster-jwt-agent, then CELL=dev-cell-1 mise run cell:up"},
		{name: "a stale celld in the second cell", stale: "celld@dev-cell-2", want: "Run: mise run images -- celld cluster-jwt-agent, then CELL=dev-cell-2 mise run cell:up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, err := runGateM7(t, tc.stale, m7RepairOK, false)
			ran := strings.Contains(calls, "-run ^TestM7")
			if m6, m7 := strings.Index(calls, "m6 repair --check"), strings.Index(calls, "m7 repair --check"); m6 < 0 || m7 < 0 || m6 > m7 {
				t.Errorf("gate-m6-repair.sh --check and then gate-m7-repair.sh --check must run: calls %s", calls)
			}
			if tc.want == "" {
				if err != nil || !ran {
					t.Fatalf("err %v, ran %v, output %s\ncalls %s", err, ran, out, calls)
				}
				return
			}
			if err == nil || ran || !strings.Contains(out, tc.want) {
				t.Fatalf("err %v, tests ran %v, output %s; want a stop before the tests that says %q", err, ran, out, tc.want)
			}
		})
	}
}

// TestGateM7RepairCheckStops: a failed repair check stops the gate before the tests.
func TestGateM7RepairCheckStops(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	out, calls, err := runGateM7(t, "", "#!/usr/bin/env bash\necho 'dev-cell-1 holds the test namespace m7-aa. Run: mise run gate:m7:repair'\nexit 1\n", false)
	if err == nil || strings.Contains(calls, "-run ^TestM7") || !strings.Contains(out, "Run: mise run gate:m7:repair") {
		t.Fatalf("err %v, output %s, calls %s; want a stop before the tests", err, out, calls)
	}
}

// TestGateM7TokenScan: after the tests, gate.sh m7 scans the logs with the start time of the run. A hit fails the gate.
func TestGateM7TokenScan(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	for _, hit := range []bool{false, true} {
		out, calls, err := runGateM7(t, "", m7RepairOK, hit)
		if !strings.Contains(calls, "-run ^TestM7") || !strings.Contains(calls, "scan 2026-11-16T01:02:03Z") {
			t.Fatalf("hit %v: the tests or the scan did not run: calls %s\noutput %s", hit, calls, out)
		}
		if hit && (err == nil || !strings.Contains(out, "a token is in the log: dev-cp ns/pod container line 7") || !strings.Contains(out, "FAIL")) {
			t.Errorf("err %v, output %s; want a failure that holds the line of the scan", err, out)
		}
		if !hit && err != nil {
			t.Errorf("err %v, output %s; want a pass", err, out)
		}
	}
}

// TestGateM7OpenProvisionStep: an open provisioning step makes gate-m6-repair.sh --check fail, and gate.sh m7 stops before the M7 check and
// the tests.
func TestGateM7OpenProvisionStep(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	m6 := "#!/usr/bin/env bash\necho \"m6 repair $*\" >>\"$STUB_LOG\"\necho 'step provision-1 is open. Run: mise run gate:m6:repair'\nexit 1\n"
	out, calls, err := runGateM7With(t, "", m7RepairOK, m6, false)
	if err == nil || strings.Contains(calls, "-run ^TestM7") || strings.Contains(calls, "m7 repair") || !strings.Contains(out, "Run: mise run gate:m6:repair") {
		t.Fatalf("err %v, output %s, calls %s; want a stop before the M7 check and the tests", err, out, calls)
	}
}

// TestGateM7PatternAndTimeout: the tests run with the anchored pattern ^TestM7, so no other test that holds M7 in its name runs, and with
// the provisional go test timeout of 90 minutes from harness/versions.env.
func TestGateM7PatternAndTimeout(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	_, calls, err := runGateM7(t, "", m7RepairOK, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls, "-run ^TestM7\n") || !strings.Contains(calls, "-timeout 40m ") {
		t.Errorf("the go test call lacks the pattern ^TestM7 at its end or the timeout of 40 minutes: %s", calls)
	}
}

// TestGateM7RegistryDeletesOff: before the tests, gate.sh m7 requires that registry-mirror runs with deletes off, because the registry
// test deletes a manifest by digest. A mirror with deletes on, or no mirror, stops the gate with the command that recreates it.
func TestGateM7RegistryDeletesOff(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct{ name, env, want string }{
		{name: "deletes off", env: `["REGISTRY_STORAGE_DELETE_ENABLED=false"]`},
		{name: "no setting", env: `["PATH=/bin"]`, want: "Run: mise run hostsvc -- up"},
		{name: "deletes on", env: `["REGISTRY_STORAGE_DELETE_ENABLED=true"]`, want: "Run: mise run hostsvc -- up"},
		{name: "no container", env: "", want: "could not read the container registry-mirror"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, err := runGateM7Registry(t, "", m7RepairOK, m6RepairOK, false, tc.env)
			ran := strings.Contains(calls, "-run ^TestM7")
			if tc.want == "" {
				if err != nil || !ran {
					t.Fatalf("err %v, ran %v, output %s", err, ran, out)
				}
				return
			}
			if err == nil || ran || !strings.Contains(out, tc.want) {
				t.Fatalf("err %v, tests ran %v, output %s; want a stop before the tests that says %q", err, ran, out, tc.want)
			}
		})
	}
}
