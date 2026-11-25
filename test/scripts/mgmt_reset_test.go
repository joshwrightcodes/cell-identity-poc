package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// resetKubectl stands for kubectl in management. It keeps the replicas of StatefulSet mgmtd in $STUB_DIR/replicas, and it
// logs each call after the context. STUB_JOB_FAIL makes the Job fail, STUB_JOB_HANG keeps it running, and STUB_CREATE_FAIL
// makes the create fail. STUB_GET_ERROR makes every pod read fail with a connection error, and STUB_POD_STUCK keeps
// mgmtd-0 listed after the scale to 0.
const resetKubectl = `#!/usr/bin/env bash
shift 2
echo "$*" >>"$STUB_DIR/calls"
replicas() { cat "$STUB_DIR/replicas" 2>/dev/null || echo 1; }
case "$*" in
  *"get statefulset mgmtd"*) echo "registry.test/mgmtd@sha256:abc" ;;
  *"patch statefulset/mgmtd"*) echo "$*" | sed -n 's/.*"replicas":\([0-9]*\).*/\1/p' >"$STUB_DIR/replicas" ;;
  *"get pod mgmtd-0 -o jsonpath"*) [[ "$(replicas)" == 1 ]] && echo True ;;
  *"get pod mgmtd-0"*)
    [[ -z "${STUB_GET_ERROR:-}" ]] || { echo "Unable to connect to the server" >&2; exit 1; }
    if [[ "$(replicas)" == 1 || -n "${STUB_POD_STUCK:-}" ]]; then echo pod/mgmtd-0; fi ;;
  *"create -f -"*) cat >"$STUB_DIR/job.yaml"; [[ -z "${STUB_CREATE_FAIL:-}" ]] || { echo "denied" >&2; exit 1; } ;;
  *"get job "*)
    if [[ -n "${STUB_JOB_HANG:-}" ]]; then echo "/"; elif [[ -n "${STUB_JOB_FAIL:-}" ]]; then echo "/1"; else echo "1/"; fi ;;
  *"logs job/"*)
    if [[ -n "${STUB_JOB_FAIL:-}" ]]; then echo '{"level":"ERROR","msg":"mgmtd failed","error":"data directory: no such file"}'
    else echo '{"moved":[{"from":"/var/lib/mgmtd/state.json","to":"/var/lib/mgmtd/state.json.reset-1"},{"from":"/var/lib/mgmtd/ed25519.key","to":"/var/lib/mgmtd/ed25519.key.reset-1"}]}'; fi ;;
  *"delete job"*) ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

func resetRun(t *testing.T, env ...string) (out, errOut string, code int, calls []string) {
	t.Helper()
	dir := t.TempDir()
	out, errOut, code = runScript(t, "mgmt.sh", map[string]string{"kubectl": resetKubectl, "kind": stubKind, "docker": stubDocker}, append([]string{"STUB_DIR=" + dir, "MGMT_RESET_WAIT=4"}, env...), "reset-state")
	b, _ := os.ReadFile(filepath.Join(dir, "calls"))
	calls = strings.Split(strings.TrimSpace(string(b)), "\n")
	if y, err := os.ReadFile(filepath.Join(dir, "job.yaml")); err == nil {
		calls = append(calls, "JOB "+strings.Join(strings.Fields(string(y)), " "))
	}
	return
}

// indexOf returns the position of the first call that holds sub, or -1.
func indexOf(calls []string, sub string) int {
	for i, c := range calls {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

func TestResetStateOrderAndNextCommands(t *testing.T) {
	t.Parallel()
	out, errOut, code, calls := resetRun(t)
	if code != 0 {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
	down, create, del, up := indexOf(calls, `"replicas":0`), indexOf(calls, "create -f -"), indexOf(calls, "delete job"), indexOf(calls, `"replicas":1`)
	if down < 0 || !(down < create && create < del && del < up) {
		t.Fatalf("order: scale 0 at %d, create at %d, delete at %d, scale 1 at %d\n%s", down, create, del, up, strings.Join(calls, "\n"))
	}
	job := calls[len(calls)-1]
	for _, want := range []string{"image: \"registry.test/mgmtd@sha256:abc\"", "args: [reset-state, --data-dir=/var/lib/mgmtd]", "claimName: state-mgmtd-0", "automountServiceAccountToken: false"} {
		if !strings.Contains(job, want) {
			t.Errorf("the Job lacks %q:\n%s", want, job)
		}
	}
	lines := jsonLines(t, out)
	if len(lines) != 1 || lines[0]["reset"] != true {
		t.Fatalf("stdout %q, want one JSON line with reset true", out)
	}
	next, _ := lines[0]["next"].([]any)
	want := []any{"CELL=dev-cp mise run cell:up", "CELL=dev-cell-1 mise run cell:up", "CELL=dev-cell-2 mise run cell:up",
		"mise run portal -- request --cell dev-cell-1 --cell dev-cell-2", "mise run portal -- wait --cell dev-cell-1 --cell dev-cell-2", "CELL=management mise run cell:link"}
	if !reflect.DeepEqual(next, want) {
		t.Fatalf("next %v, want the cell:up of dev-cp and of each live cell, the portal request and wait for them, and then the cell:link of management: %v", next, want)
	}
	// A new state holds no request, so each bind gets cell_unknown until the portal asks again. With no live cell, nothing is requested.
	out, _, code, _ = resetRun(t, "STUB_KIND=management dev-cp rogue")
	if code != 0 {
		t.Fatalf("exit %d with no live cell", code)
	}
	next, _ = jsonLines(t, out)[0]["next"].([]any)
	if want := []any{"CELL=dev-cp mise run cell:up", "CELL=management mise run cell:link"}; !reflect.DeepEqual(next, want) {
		t.Fatalf("next %v with no live cell, want %v", next, want)
	}
	if moved, _ := lines[0]["moved"].([]any); len(moved) != 2 {
		t.Fatalf("moved %v, want two files", lines[0]["moved"])
	}
}

func TestResetStateFailuresPrintOneErrorLine(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, env, step string
	}{
		{"create fails", "STUB_CREATE_FAIL=1", "create-job"},
		{"job fails", "STUB_JOB_FAIL=1", "run-job"},
		{"job hangs", "STUB_JOB_HANG=1", "run-job"},
		{"mgmtd-0 does not stop", "STUB_POD_STUCK=1", "wait-stop"},
		{"a kubectl error is not a missing pod", "STUB_GET_ERROR=1", "wait-stop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, code, calls := resetRun(t, tc.env)
			lines := jsonLines(t, out)
			if code != 1 || len(lines) != 1 || lines[0]["level"] != "ERROR" || lines[0]["step"] != tc.step {
				t.Fatalf("exit %d, stdout %q; want one error line at step %s", code, out, tc.step)
			}
			// After a failed move, mgmtd runs again with the state as it was.
			if last := indexOf(calls, `"replicas":1`); last < indexOf(calls, `"replicas":0`) || last < 0 {
				t.Fatalf("mgmtd was not scaled back to 1:\n%s", strings.Join(calls, "\n"))
			}
		})
	}
}

// mgmt.sh must print one JSON error line when kubectl exec fails and prints nothing, and it must pass the output
// and the exit code of a command that printed its own error line.
func TestMgmtExecFailurePrintsOneErrorLine(t *testing.T) {
	t.Parallel()
	const kubectl = `#!/usr/bin/env bash
case "$*" in
  *"get pod mgmtd-0"*) echo True ;;
  *" exec mgmtd-0 "*)
    if [[ -n "${STUB_EXEC_LINE:-}" ]]; then echo '{"level":"ERROR","msg":"mgmtd failed","error":"conflict"}'; exit 1; fi
    echo "error: unable to upgrade connection" >&2; exit 1 ;;
esac
`
	out, errOut, code := runScript(t, "mgmt.sh", map[string]string{"kubectl": kubectl}, nil, "status")
	lines := jsonLines(t, out)
	if code != 1 || len(lines) != 1 || lines[0]["level"] != "ERROR" || lines[0]["kubectl_exit"] != float64(1) ||
		!strings.Contains(lines[0]["error"].(string), "mise run harness:status") {
		t.Fatalf("exit %d, stdout %q, stderr %q; want one error line with the exit code and the next command", code, out, errOut)
	}
	out, _, code = runScript(t, "mgmt.sh", map[string]string{"kubectl": kubectl}, []string{"STUB_EXEC_LINE=1"}, "status")
	if code != 1 || strings.TrimSpace(out) != `{"level":"ERROR","msg":"mgmtd failed","error":"conflict"}` {
		t.Fatalf("exit %d, stdout %q; want the line of mgmtd unchanged", code, out)
	}
}

func TestResetStateInvalidWaitPrintsOneErrorLine(t *testing.T) {
	t.Parallel()
	out, _, code, calls := resetRun(t, "MGMT_RESET_WAIT=soon")
	lines := jsonLines(t, out)
	if code != 1 || len(lines) != 1 || lines[0]["level"] != "ERROR" || lines[0]["step"] != "read-wait" {
		t.Fatalf("exit %d, stdout %q; want one error line at step read-wait", code, out)
	}
	if calls[0] != "" {
		t.Fatalf("kubectl ran before the check:\n%s", strings.Join(calls, "\n"))
	}
}

func TestResetStateHintsNameMiseTasksOnly(t *testing.T) {
	t.Parallel()
	for _, env := range []string{"STUB_POD_STUCK=1", "STUB_JOB_FAIL=1", "STUB_JOB_HANG=1"} {
		out, _, _, _ := resetRun(t, env)
		for _, l := range jsonLines(t, out) {
			if next, _ := l["next"].(string); next != "" && !strings.HasPrefix(next, "mise run ") {
				t.Errorf("%s: hint %q is not a mise task", env, next)
			}
		}
	}
}

// An interrupt while the Job runs scales mgmtd back to 1 and deletes the Job.
func TestResetStateInterruptScalesMgmtdBack(t *testing.T) {
	t.Parallel()
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			dir := t.TempDir()
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(resetKubectl), 0o755); err != nil {
				t.Fatal(err)
			}
			writeLiveStubs(t, bin)
			path, err := filepath.Abs("../../scripts/mgmt.sh")
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", path, "reset-state")
			cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"POC_BUILD_ROOT=" + filepath.Join(bin, "build"), "STUB_DIR=" + dir, "STUB_JOB_HANG=1", "MGMT_RESET_WAIT=60"}
			var out bytes.Buffer
			cmd.Stdout = &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			deadline := time.Now().Add(20 * time.Second)
			for {
				b, _ := os.ReadFile(filepath.Join(dir, "calls"))
				if strings.Contains(string(b), "get job") {
					break
				}
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					t.Fatalf("the script never reached the Job wait:\n%s", b)
				}
				time.Sleep(100 * time.Millisecond)
			}
			_ = cmd.Process.Signal(sig)
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatal("the script did not stop after the signal")
			}
			b, _ := os.ReadFile(filepath.Join(dir, "calls"))
			calls := strings.Split(strings.TrimSpace(string(b)), "\n")
			if last := indexOf(calls, `"replicas":1`); last < indexOf(calls, `"replicas":0`) || last < 0 {
				t.Fatalf("mgmtd was not scaled back to 1 after %s:\n%s", sig, b)
			}
			if indexOf(calls, "delete job") < 0 {
				t.Fatalf("the Job was not deleted after %s:\n%s", sig, b)
			}
		})
	}
}

// A worktree has no .envrc.local, because git ignores it. secrets:connect names the cause and the fix.
func TestSecretsConnectNamesAnAbsentEnvrcLocal(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), ".envrc.local")
	_, errOut, code := runScript(t, "secrets-connect.sh", nil,
		[]string{"CELL=dev-cp", "POC_ENVRC_LOCAL=" + missing})
	if code == 0 || !strings.Contains(errOut, missing+" is absent") && !strings.Contains(errOut, "POC_ENVRC_LOCAL names "+missing) {
		t.Fatalf("exit %d, stderr %q; want the absent file named", code, errOut)
	}
	if !strings.Contains(errOut, "set up the clusters") || !strings.Contains(errOut, "POC_ENVRC_LOCAL") {
		t.Fatalf("stderr %q lacks the fix", errOut)
	}
}
