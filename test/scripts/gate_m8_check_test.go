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

const m8RepairOK = "#!/usr/bin/env bash\necho \"m8 repair $*\" >>\"$STUB_LOG\"\nexit 0\n"

// runGateM8 runs gate.sh m8 in a stub root. stale names a workload that runs another image, hit makes the token scan fail, and env adds variables. It returns
// the output, the calls that the stubs logged, the root and the error. The stub of go fails a call with -json when STUB_GO_FAIL is set.
func runGateM8(t *testing.T, stale, m7Repair, m8Repair string, hit bool, env ...string) (out, calls, root string, err error) {
	t.Helper()
	return runGateM8Edit(t, nil, stale, m7Repair, m8Repair, hit, env...)
}

// runGateM8Edit is runGateM8 with a function that changes the root before the run, for example harness/versions.env.
func runGateM8Edit(t *testing.T, edit func(root string), stale, m7Repair, m8Repair string, hit bool, env ...string) (out, calls, root string, err error) {
	t.Helper()
	root = newM5GateRoot(t, stale)
	if edit != nil {
		edit(root)
	}
	write := func(path, body string) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	kubectl, rerr := os.ReadFile(filepath.Join(root, "bin", "kubectl"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	const clients = `*" get deployment/argocd-agent-principal "*|*" get deployment/telemetry-gateway "*|*" get deployment/mesh-view-hub "*) one cell-proxy cell-proxy ;;`
	if !strings.Contains(string(kubectl), clients) {
		t.Fatal("the kubectl stub of newM5GateRoot changed, so the M8 workloads cannot join it")
	}
	write("bin/kubectl", strings.Replace(string(kubectl), clients, `*" get statefulset/bundle-store "*|*" get deployment/argocd-repo-server "*) one cell-proxy cell-proxy ;;
	  `+clients, 1))
	write("bin/go", "#!/usr/bin/env bash\necho \"go $*\" >>\"$STUB_LOG\"\n[[ -z \"${STUB_GO_FAIL:-}\" || \" $* \" != *\" -json \"* ]] || exit 1\n")
	write("scripts/gate-m6-repair.sh", m6RepairOK)
	write("scripts/gate-m7-repair.sh", m7Repair)
	write("scripts/gate-m8-repair.sh", m8Repair)
	write("scripts/gate-token-scan.sh", `#!/usr/bin/env bash
echo "scan $*" >>"$STUB_LOG"
[[ -z "$STUB_HIT" ]] || { echo "a token is in the log: dev-cp ns/pod container line 7"; exit 1; }
`)
	h := ""
	if hit {
		h = "1"
	}
	cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), "m8")
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_STALE=" + stale, "STUB_HIT=" + h}, env...)
	b, err := cmd.CombinedOutput()
	c, _ := os.ReadFile(filepath.Join(root, "calls"))
	return string(b), string(c), root, err
}

// TestGateM8RunsChecksInOrder: gate.sh m8 runs gate-m6-repair.sh --check, gate-m7-repair.sh --check, gate-m8-repair.sh --check and the image check, and
// then the tests. A failed check stops the run before the tests and before the later checks.
func TestGateM8RunsChecksInOrder(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	_, calls, _, err := runGateM8(t, "", m7RepairOK, m8RepairOK, false)
	if err != nil {
		t.Fatalf("the gate failed: %v\ncalls %s", err, calls)
	}
	m6, m7, m8, run := at(calls, "m6 repair --check"), at(calls, "m7 repair --check"), at(calls, "m8 repair --check"), at(calls, "-run ^TestM8")
	if m6 < 0 || m7 < m6 || m8 < m7 || run < m8 {
		t.Errorf("want the checks of M6, M7 and M8 in this order and then the tests (m6 %d, m7 %d, m8 %d, tests %d):\n%s", m6, m7, m8, run, calls)
	}

	for _, tc := range []struct {
		name, m7, m8, deny string
	}{
		{name: "the M7 check fails", m7: "#!/usr/bin/env bash\necho 'dev-cell-1 holds the test namespace m7-aa. Run: mise run gate:m7:repair'\nexit 1\n", m8: m8RepairOK, deny: "m8 repair"},
		{name: "the M8 check fails", m7: m7RepairOK, m8: "#!/usr/bin/env bash\necho 'dev-cell-2 is in rolled_back. Run: mise run gate:m8:repair'\nexit 1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, _, err := runGateM8(t, "", tc.m7, tc.m8, false)
			if err == nil || strings.Contains(calls, "-run ^TestM8") || !strings.Contains(out, "Run: mise run gate:m") {
				t.Fatalf("err %v, output %s, calls %s; want a stop before the tests that names the repair", err, out, calls)
			}
			if tc.deny != "" && strings.Contains(calls, tc.deny) {
				t.Errorf("calls %s hold %q after a failed check", calls, tc.deny)
			}
		})
	}
}

// TestGateM8Pattern: the tests run with the anchored pattern ^TestM8, so no other test that holds M8 in its name runs. They run with -short, which
// skips the long tests, unless GATE_M8_LONG=1.
func TestGateM8Pattern(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name  string
		env   []string
		short bool
	}{
		{name: "short by default", short: true},
		{name: "GATE_M8_LONG=1 runs the long tests", env: []string{"GATE_M8_LONG=1"}},
		{name: "GATE_M8_LONG=0 stays short", env: []string{"GATE_M8_LONG=0"}, short: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, calls, _, err := runGateM8(t, "", m7RepairOK, m8RepairOK, false, tc.env...)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(calls, "-run ^TestM8") {
				t.Errorf("the go test call lacks the pattern ^TestM8: %s", calls)
			}
			line := ""
			for _, l := range strings.Split(calls, "\n") {
				if strings.Contains(l, "-json") {
					line = l
				}
			}
			if got := strings.Contains(line, " -short"); got != tc.short {
				t.Errorf("-short is %v in %q, want %v", got, line, tc.short)
			}
		})
	}
}

// TestGateM8ImageCheck: the image check of M7, and cell-proxy in bundle-store-0 and argocd-repo-server of dev-cp and of each live cell, stop the run before the tests and name
// the command that updates the workload.
func TestGateM8ImageCheck(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct{ name, stale, want string }{
		{name: "healthy"},
		{name: "a stale envd", stale: "envd@envd-system", want: "Run: mise run images -- envd, then CELL=dev-cp mise run cell:up"},
		{name: "a stale celld", stale: "celld@dev-cell-2", want: "Run: mise run images -- celld cluster-jwt-agent, then CELL=dev-cell-2 mise run cell:up"},
		{name: "a stale cell-proxy in bundle-store of the cells and dev-cp", stale: "cell-proxy@cell-system",
			want: "Run: mise run images -- cell-proxy, then CELL=dev-cell-1 mise run cell:up"},
		{name: "a stale cell-proxy in the repo server of dev-cp", stale: "cell-proxy@dev-cp", want: "Run: mise run images -- cell-proxy, then CELL=dev-cp mise run cell:up"},
		{name: "a stale cell-proxy in the repo server of a cell", stale: "cell-proxy@dev-cell-2", want: "Run: mise run images -- cell-proxy, then CELL=dev-cell-2 mise run cell:up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, _, err := runGateM8(t, tc.stale, m7RepairOK, m8RepairOK, false)
			ran := strings.Contains(calls, "-run ^TestM8")
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

// TestGateM8TokenScan: after the tests, gate.sh m8 scans the logs with the start time of the run, and a hit fails the gate.
func TestGateM8TokenScan(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, hit := range []bool{false, true} {
		out, calls, _, err := runGateM8(t, "", m7RepairOK, m8RepairOK, hit)
		if !strings.Contains(calls, "-run ^TestM8") || !strings.Contains(calls, "scan 2026-11-16T01:02:03Z") {
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

// TestGateM8Record: build/gate/m8-bundles lists the targets that a test changed. A run whose tests pass removes it, because each test restored its
// target. A run whose tests fail keeps it, so that the next check names gate:m8:repair.
func TestGateM8Record(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, fail := range []bool{false, true} {
		root := ""
		env := []string{}
		if fail {
			env = append(env, "STUB_GO_FAIL=1")
		}
		// The record is written by the tests, so the stub of go writes it for the run.
		out, calls, root, err := runGateM8WithRecord(t, env)
		_, statErr := os.Stat(filepath.Join(root, "build", "gate", "m8-bundles"))
		if fail && (err == nil || statErr != nil) {
			t.Errorf("failing tests: err %v, stat %v, want a failed gate that keeps the record\n%s\n%s", err, statErr, out, calls)
		}
		if !fail && (err != nil || statErr == nil || !os.IsNotExist(statErr)) {
			t.Errorf("passing tests: err %v, stat %v, want a pass that removes the record\n%s\n%s", err, statErr, out, calls)
		}
	}
}

// runGateM8WithRecord is runGateM8 with a stub of go that writes build/gate/m8-bundles during the test run.
func runGateM8WithRecord(t *testing.T, env []string) (out, calls, root string, err error) {
	t.Helper()
	root = newM5GateRoot(t, "")
	for name, body := range map[string]string{
		"scripts/gate-m6-repair.sh":  m6RepairOK,
		"scripts/gate-m7-repair.sh":  m7RepairOK,
		"scripts/gate-m8-repair.sh":  m8RepairOK,
		"scripts/gate-token-scan.sh": "#!/usr/bin/env bash\nexit 0\n",
		"bin/go": "#!/usr/bin/env bash\necho \"go $*\" >>\"$STUB_LOG\"\n" +
			"if [[ \" $* \" == *\" -json \"* ]]; then mkdir -p \"$POC_BUILD_ROOT/gate\"; echo dev-cell-1 >>\"$POC_BUILD_ROOT/gate/m8-bundles\"; [[ -z \"${STUB_GO_FAIL:-}\" ]] || exit 1; fi\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	kubectl, rerr := os.ReadFile(filepath.Join(root, "bin", "kubectl"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	const clients = `*" get deployment/argocd-agent-principal "*|*" get deployment/telemetry-gateway "*|*" get deployment/mesh-view-hub "*) one cell-proxy cell-proxy ;;`
	patched := strings.Replace(string(kubectl), clients, `*" get statefulset/bundle-store "*|*" get deployment/argocd-repo-server "*) one cell-proxy cell-proxy ;;
	  `+clients, 1)
	if err := os.WriteFile(filepath.Join(root, "bin", "kubectl"), []byte(patched), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), "m8")
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_STALE="}, env...)
	b, err := cmd.CombinedOutput()
	c, _ := os.ReadFile(filepath.Join(root, "calls"))
	return string(b), string(c), root, err
}

// m8TokenKubectl answers the reads of gate-token-scan.sh for the pods of the bundle store. Each cluster holds bundle-store-0 in cell-system, with the
// containers bundle-store (a registry image) and store-proxy (an image that the image pattern of the scan does not match), and argocd-repo-server-0 in argocd, with the containers argocd-repo-server and
// store-token (the same kind of image). The log of a container comes from $STUB_DIR/log-<pod>-<container>.
const m8TokenKubectl = `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_DIR/calls"
case " $* " in
  *" get pods -A -o json "*)
    cat <<'JSON'
{"items":[
 {"metadata":{"namespace":"cell-system","name":"bundle-store-0"},"spec":{"containers":[{"name":"bundle-store","image":"docker.io/library/registry:3"},{"name":"store-proxy","image":"localhost:5001/store-gateway@sha256:cc"}]},"status":{"containerStatuses":[{"name":"bundle-store","restartCount":0},{"name":"store-proxy","restartCount":0}]}},
 {"metadata":{"namespace":"argocd","name":"argocd-repo-server-0"},"spec":{"containers":[{"name":"argocd-repo-server","image":"quay.io/argoproj/argocd:v3"},{"name":"store-token","image":"localhost:5001/store-gateway@sha256:cc"}]},"status":{"containerStatuses":[{"name":"argocd-repo-server","restartCount":0},{"name":"store-token","restartCount":0}]}}
]}
JSON
    ;;
  *" logs "*)
    pod=""; container=""; prev=""
    for a in "$@"; do [[ "$prev" == -c ]] && container="$a"; [[ "$a" == bundle-store-0 || "$a" == argocd-repo-server-0 ]] && pod="$a"; prev="$a"; done
    echo "logs $pod $container" >>"$STUB_DIR/reads"
    cat "$STUB_DIR/log-$pod-$container" 2>/dev/null || true ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestTokenScanReadsStoreLogs: the scan reads the logs of the containers store-proxy (bundle-store-0) and store-token (argocd-repo-server) in each cluster, and
// the files build/gate/m8-* that a gate:m8 run leaves. A compact JWS in any of them fails the scan with the place and the line number, and never prints the line.
func TestTokenScanReadsStoreLogs(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	const jws = "eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ.eyJhdWQiOlsibWdtdCJdfQ.c2ln"
	for _, tc := range []struct {
		name  string
		logs  map[string]string
		files map[string]string
		// unreadable names a file of build/gate whose mode is set to 0 after it is written.
		unreadable string
		code       int
		want       []string
		deny       []string
		reads      []string
	}{
		{name: "clean logs and files", logs: map[string]string{"log-bundle-store-0-store-proxy": "ok\n", "log-argocd-repo-server-0-store-token": "ok\n"},
			files: map[string]string{"m8-bundles": "dev-cell-1\ndev-cp\n"}, reads: []string{"logs bundle-store-0 store-proxy", "logs argocd-repo-server-0 store-token"}},
		{name: "a token in the store proxy log", logs: map[string]string{"log-bundle-store-0-store-proxy": "ok\nrejected " + jws + "\n"}, code: 1,
			want: []string{"cell-system/bundle-store-0 store-proxy line 2"}, deny: []string{jws}},
		{name: "a token in the token client log", logs: map[string]string{"log-argocd-repo-server-0-store-token": jws + "\n"}, code: 1,
			want: []string{"argocd/argocd-repo-server-0 store-token line 1"}, deny: []string{jws}},
		{name: "a token in a file of gate:m8", files: map[string]string{"m8-bundles": "dev-cell-1\n", "m8-output": "ok\n" + jws + "\n"}, code: 1,
			want: []string{"build/gate/m8-output line 2"}, deny: []string{jws, "m8-bundles line"}},
		{name: "a private key in a file of gate:m8", files: map[string]string{"m8-key": "-----BEGIN PRIVATE KEY-----\n"}, code: 1,
			want: []string{"build/gate/m8-key line 1"}, deny: []string{"BEGIN PRIVATE"}},
		{name: "an unreadable file of gate:m8 fails", files: map[string]string{"m8-secret": jws + "\n"}, unreadable: "m8-secret", code: 1,
			want: []string{"cannot read build/gate/m8-secret"}, deny: []string{jws}},
		{name: "a file of another gate is not scanned", files: map[string]string{"m6-steps": jws + "\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, build, steps := t.TempDir(), t.TempDir(), t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range withLive(map[string]string{"kubectl": m8TokenKubectl}) {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for name, body := range tc.logs {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Join(build, "gate"), 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range tc.files {
				if err := os.WriteFile(filepath.Join(build, "gate", name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.unreadable != "" {
				p := filepath.Join(build, "gate", tc.unreadable)
				if err := os.Chmod(p, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
			}
			script, err := filepath.Abs("../../scripts/gate-token-scan.sh")
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", script, "2026-11-15T01:02:03Z")
			cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "POC_BUILD_ROOT=" + build,
				"STUB_DIR=" + dir, "HOSTSVC_STEPS_DIR=" + steps}
			var buf bytes.Buffer
			cmd.Stdout, cmd.Stderr = &buf, &buf
			code := 0
			if err := cmd.Run(); err != nil {
				ee, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				code = ee.ExitCode()
			}
			if code != tc.code {
				t.Fatalf("exit %d, want %d\n%s", code, tc.code, buf.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(buf.String(), w) {
					t.Errorf("output %q lacks %q", buf.String(), w)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(buf.String(), d) {
					t.Errorf("the output holds %q", d)
				}
			}
			reads, _ := os.ReadFile(filepath.Join(dir, "reads"))
			for _, r := range tc.reads {
				if !strings.Contains(string(reads), r) {
					t.Errorf("reads %q lack %q", reads, r)
				}
			}
		})
	}
}

// TestGateM8RefusesEmptyBudget: the M8 waits are longer than the floor of the Go timeout, and a timeout skips every cleanup. So gate.sh m8 stops before any check and test
// when GATE_M8_BUDGET_MINUTES or GATE_M8_TEST_TIMEOUT_MINUTES is empty, and names the variable.
func TestGateM8RefusesEmptyBudget(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, name := range []string{"GATE_M8_BUDGET_MINUTES", "GATE_M8_TEST_TIMEOUT_MINUTES"} {
		t.Run(name, func(t *testing.T) {
			edit := func(root string) {
				p := filepath.Join(root, "harness", "versions.env")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				var lines []string
				for _, l := range strings.Split(string(b), "\n") {
					if strings.HasPrefix(l, name+"=") {
						l = name + "= # <set in the live part>"
					}
					lines = append(lines, l)
				}
				if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, calls, _, err := runGateM8Edit(t, edit, "", m7RepairOK, m8RepairOK, false)
			if err == nil || !strings.Contains(out, name+" is empty in harness/versions.env") || strings.Contains(calls, "-run ^TestM8") || strings.Contains(calls, "repair --check") {
				t.Fatalf("err %v, output %s, calls %s; want a stop that names %s before every check and test", err, out, calls, name)
			}
		})
	}
}

// TestGateM8Versions: harness/versions.env holds the limits of M8 that the live runs set. The budget is 1.5 times the slower of two clean
// runs (4007 s), rounded up to 5 minutes, and the Go test timeout is twice the budget. No line keeps the provisional mark.
func TestGateM8Versions(t *testing.T) {
	b, err := os.ReadFile("../../harness/versions.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GATE_M8_BUDGET_MINUTES=105", "GATE_M8_TEST_TIMEOUT_MINUTES=210"} {
		if !strings.Contains(string(b), "\n"+want+"\n") {
			t.Errorf("harness/versions.env lacks the line %q", want)
		}
	}
	if strings.Contains(string(b), "<set in the live part>") {
		t.Error("harness/versions.env still marks a limit as set in the live part")
	}
}
