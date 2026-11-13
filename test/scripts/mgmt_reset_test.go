package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetKubectl stands for kubectl in management. It keeps the replicas of StatefulSet mgmtd in $STUB_DIR/replicas, and it
// logs each call after the context. STUB_JOB_FAIL makes the Job fail, STUB_JOB_HANG keeps it running, and STUB_CREATE_FAIL
// makes the create fail.
const resetKubectl = `#!/usr/bin/env bash
shift 2
echo "$*" >>"$STUB_DIR/calls"
replicas() { cat "$STUB_DIR/replicas" 2>/dev/null || echo 1; }
case "$*" in
  *"get statefulset mgmtd"*) echo "registry.test/mgmtd@sha256:abc" ;;
  *"patch statefulset/mgmtd"*) echo "$*" | sed -n 's/.*"replicas":\([0-9]*\).*/\1/p' >"$STUB_DIR/replicas" ;;
  *"get pod mgmtd-0 -o jsonpath"*) [[ "$(replicas)" == 1 ]] && echo True ;;
  *"get pod mgmtd-0"*) [[ "$(replicas)" == 1 ]] ;;
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
	out, errOut, code = runScript(t, "mgmt.sh", map[string]string{"kubectl": resetKubectl}, append([]string{"STUB_DIR=" + dir, "MGMT_RESET_WAIT=4"}, env...), "reset-state")
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
	if len(next) != 2 || next[0] != "CELL=dev-cp mise run cell:up" || next[1] != "CELL=management mise run cell:link" {
		t.Fatalf("next %v, want the cell:up of dev-cp and then the cell:link of management", next)
	}
	if moved, _ := lines[0]["moved"].([]any); len(moved) != 2 {
		t.Fatalf("moved %v, want two files", lines[0]["moved"])
	}
}

func TestResetStateFailuresPrintOneErrorLine(t *testing.T) {
	for _, tc := range []struct {
		name, env, step string
	}{
		{"create fails", "STUB_CREATE_FAIL=1", "create-job"},
		{"job fails", "STUB_JOB_FAIL=1", "run-job"},
		{"job hangs", "STUB_JOB_HANG=1", "run-job"},
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
	if code != 1 || len(lines) != 1 || lines[0]["level"] != "ERROR" || lines[0]["kubectl_exit"] != "1" ||
		!strings.Contains(lines[0]["error"].(string), "mise run harness:status") {
		t.Fatalf("exit %d, stdout %q, stderr %q; want one error line with the exit code and the next command", code, out, errOut)
	}
	out, _, code = runScript(t, "mgmt.sh", map[string]string{"kubectl": kubectl}, []string{"STUB_EXEC_LINE=1"}, "status")
	if code != 1 || strings.TrimSpace(out) != `{"level":"ERROR","msg":"mgmtd failed","error":"conflict"}` {
		t.Fatalf("exit %d, stdout %q; want the line of mgmtd unchanged", code, out)
	}
}
