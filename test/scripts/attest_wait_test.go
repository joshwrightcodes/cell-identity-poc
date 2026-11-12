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

const attestKubectl = `#!/usr/bin/env bash
d="$STUB_DIR"
echo "kubectl $*" >>"$d/calls"
case " $* " in
  *" get configmap cell-records "*) [[ -f "$d/cell-records.json" ]] || exit 1; cat "$d/cell-records.json" ;;
  *" logs spire-server-0 "*) cat "$d/server.log" ;;
  *" logs deploy/celld "*) cat "$d/celld.log" ;;
  *" logs mgmtd-0 "*) cat "$d/mgmtd.log" ;;
  *" get pods -l app.kubernetes.io/name=celld "*) cat "$d/pods.json" ;;
  *" delete pod "*) echo "delete $*" >>"$d/deleted" ;;
  *" rollout status "*) exit "${STUB_ROLLOUT_RC:-0}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const attestMise = `#!/usr/bin/env bash
echo "mise $*" >>"$STUB_DIR/calls"
[[ "$1 $2 $3 $4" == "run mgmt -- status" ]] || { echo "unexpected mise call: $*" >&2; exit 2; }
[[ -f "$STUB_DIR/status.json" ]] || exit 1
cat "$STUB_DIR/status.json"
`

// TestAttestWaitStages runs attest-wait.sh with fake mise and kubectl. A healthy state passes the four stages. Each
// failing stage prints its name, the reason and the next command, and exits 1. When mgmt -- status does not answer,
// the script prints the link command as a warning and exits 0 with no wait. A spire-agent in CrashLoopBackOff gets
// its pod deleted once.
func TestAttestWaitStages(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	stub := filepath.Join(root, "stub")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"kubectl": attestKubectl, "mise": attestMise} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	status := func(bound bool) string {
		b := "false"
		if bound {
			b = "true"
		}
		return `{"signed":{"epoch":1,"counter":7},"lastRefusal":{"reason":"spec_invalid","revision":{"epoch":1,"counter":7}},"storeError":"update refused",` +
			`"cells":[{"name":"dev-cell-1","bound":` + b + `,"record":{"epoch":1,"counter":7}},{"name":"dev-cell-2","bound":true,"record":{"epoch":1,"counter":7}}]}`
	}
	records := func(counter string) string {
		return `{"metadata":{"annotations":{"poc.internal/spec-epoch":"1","poc.internal/spec-counter":"` + counter + `"}}}`
	}
	healthy := map[string]string{
		"status.json":       status(true),
		"cell-records.json": records("7"),
		"server.log":        `{"msg":"records reloaded","cells":["dev-cell-1","dev-cell-2"]}` + "\n",
		"celld.log":         `{"msg":"bind refused","cell":"dev-cell-1"}` + "\n",
		"mgmtd.log":         `{"msg":"bind_denied","reason":"cell_unknown","cell":"dev-cell-1"}` + "\n",
		"pods.json":         `{"items":[{"metadata":{"name":"celld-abc"},"status":{"containerStatuses":[{"name":"spire-agent","state":{"running":{}}}]}}]}`,
	}
	for _, tc := range []struct {
		name   string
		change map[string]string // an empty value removes the file
		env    []string
		code   int // 0 or 1
		want   []string
		deny   []string
		check  func(t *testing.T, calls, deleted string)
	}{
		{name: "healthy", want: []string{"stage bound took", "stage applied took", "stage reloaded took", "stage ready took"}, deny: []string{"error:"}},
		{name: "management does not answer", change: map[string]string{"status.json": ""}, want: []string{"warning: attest-wait dev-cell-1", "CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
			deny: []string{"stage bound"}, check: func(t *testing.T, calls, _ string) {
				if strings.Contains(calls, "kubectl") {
					t.Errorf("the script called kubectl with no management plane:\n%s", calls)
				}
			}},
		{name: "management prints no JSON", change: map[string]string{"status.json": "not json"}, want: []string{"warning: attest-wait dev-cell-1", "CELL=management LINK_ONLY=mgmt-api mise run cell:link"}, deny: []string{"stage bound"}},
		{name: "not bound", change: map[string]string{"status.json": status(false)}, code: 1,
			want: []string{"stage bound failed", "Last celld bind log line: {\"msg\":\"bind refused\"", "Last mgmtd denial for dev-cell-1: {\"msg\":\"bind_denied\",\"reason\":\"cell_unknown\"", "Next: mise x -- kubectl --context kind-dev-cell-1 -n cell-identity-system logs deploy/celld -c celld, and mise run mgmt -- status"}},
		{name: "not applied", change: map[string]string{"cell-records.json": records("6")}, code: 1,
			want: []string{"stage applied failed", "does not reach the revision 1/7", `lastRefusal: {"reason":"spec_invalid"`, "storeError: update refused", "Next: mise x -- kubectl --context kind-dev-cp -n envd-system logs deploy/envd -c envd"}},
		{name: "no ConfigMap yet", change: map[string]string{"cell-records.json": ""}, code: 1, want: []string{"stage applied failed"}},
		{name: "a later revision counts", change: map[string]string{"cell-records.json": records("9")}, want: []string{"stage applied took"}},
		{name: "not reloaded", change: map[string]string{"server.log": `{"msg":"records reloaded","cells":["dev-cell-2"]}` + "\n"}, code: 1,
			want: []string{"stage reloaded failed", "kubelet syncs the ConfigMap volume", "verify row 1", "CELL=dev-cp mise run cell:restart"}},
		{name: "not ready", env: []string{"STUB_ROLLOUT_RC=1"}, code: 1, want: []string{"stage ready failed", "did not finish its rollout"}},
		{name: "a crash-looping agent", change: map[string]string{"pods.json": `{"items":[{"metadata":{"name":"celld-abc"},"status":{"containerStatuses":[{"name":"spire-agent","state":{"waiting":{"reason":"CrashLoopBackOff"}}},{"name":"celld","state":{"running":{}}}]}}]}`},
			want: []string{"CrashLoopBackOff, so the pod is deleted once (verify row 2)", "stage ready took"}, check: func(t *testing.T, _, deleted string) {
				if n := strings.Count(deleted, "delete pod celld-abc"); n != 1 {
					t.Errorf("the pod was deleted %d times, want once:\n%s", n, deleted)
				}
			}},
		{name: "a crash-looping celld container only", change: map[string]string{"pods.json": `{"items":[{"metadata":{"name":"celld-abc"},"status":{"containerStatuses":[{"name":"celld","state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}]}`},
			want: []string{"stage ready took"}, check: func(t *testing.T, _, deleted string) {
				if deleted != "" {
					t.Errorf("a pod was deleted for a crash of celld:\n%s", deleted)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range healthy {
				files[k] = v
			}
			for k, v := range tc.change {
				files[k] = v
			}
			for _, f := range []string{"calls", "deleted"} {
				_ = os.Remove(filepath.Join(stub, f))
			}
			for k, v := range files {
				p := filepath.Join(stub, k)
				_ = os.Remove(p)
				if v != "" {
					if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			cmd := exec.Command(filepath.Join(root, "scripts", "attest-wait.sh"), "dev-cell-1")
			cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cell-1",
				"POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_DIR=" + stub, "ATTEST_POLL=1", "ATTEST_BOUND_WAIT=1", "ATTEST_APPLIED_WAIT=1",
				"ATTEST_RELOADED_WAIT=1", "ATTEST_READY_WAIT=5"}, tc.env...)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			exit := 0
			if err != nil {
				ee, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				exit = ee.ExitCode()
			}
			if exit != tc.code {
				t.Fatalf("exit %d, want %d\n%s", exit, tc.code, out.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
			for _, w := range tc.deny {
				if strings.Contains(out.String(), w) {
					t.Errorf("output holds %q:\n%s", w, out.String())
				}
			}
			if tc.check != nil {
				calls, _ := os.ReadFile(filepath.Join(stub, "calls"))
				deleted, _ := os.ReadFile(filepath.Join(stub, "deleted"))
				tc.check(t, string(calls), string(deleted))
			}
		})
	}
}
