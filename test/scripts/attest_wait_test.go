package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const attestKubectl = `#!/usr/bin/env bash
d="$STUB_DIR"
echo "kubectl $*" >>"$d/calls"
case " $* " in
  *" get configmap cell-records "*) [[ -f "$d/cell-records.json" ]] || exit 1; cat "$d/cell-records.json" ;;
  *" logs spire-server-0 "*)
    n="$(sed -n 's/.*--tail=\([0-9]*\).*/\1/p' <<<"$*")"
    if [[ -n "$n" ]]; then tail -n "$n" "$d/server.log"; else cat "$d/server.log"; fi ;;
  *" logs deploy/celld "*) cat "$d/celld.log" ;;
  *" logs deploy/envd "*) cat "$d/envd.log" 2>/dev/null || true ;;
  *" get configmap peer-root "*) [[ -f "$d/no-peer-root" ]] || echo configmap/peer-root ;;
  *" get pods -l app.kubernetes.io/name=celld "*) cat "$d/pods.json" ;;
  *" delete pod "*) echo "delete $*" >>"$d/deleted" ;;
  *" wait --for=delete "*) echo "wait $*" >>"$d/deleted" ;;
  *" rollout status "*) exit "${STUB_ROLLOUT_RC:-0}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const attestMise = `#!/usr/bin/env bash
echo "mise $*" >>"$STUB_DIR/calls"
if [[ "$1 $2 $3 $4" == "run hostsvc -- facts" ]]; then cat "$STUB_DIR/facts.json"; exit 0; fi
if [[ "$1 $2 $3 $4" == "run gw -- status" ]]; then cat "$STUB_DIR/gw-status.json"; exit 0; fi
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
	for name, body := range map[string]string{"kubectl": attestKubectl, "mise": attestMise, "docker": nodeClockDocker} {
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
			`"cells":[{"name":"dev-cell-1","bound":` + b + `,"kids":["a","b"],"record":{"epoch":1,"counter":7},"lastRefusal":{"kind":"bind","reason":"not_bound","at":"2026-11-14T01:00:00Z"}},{"name":"dev-cell-2","bound":true,"record":{"epoch":1,"counter":7}}]}`
	}
	records := func(counter string) string {
		return `{"metadata":{"annotations":{"poc.internal/spec-epoch":"1","poc.internal/spec-counter":"` + counter + `"}},"data":{"spec-envelope.json":"{}","dev-cell-1.dsse.json":"{}","dev-cell-2.dsse.json":"{}"}}`
	}
	healthy := map[string]string{
		"status.json":       status(true),
		"facts.json":        `{"nodeIP":"10.9.0.1","jwks":{"keys":[{"kid":"b"},{"kid":"a"}]}}`,
		"cell-records.json": records("7"),
		"server.log":        `{"msg":"records reloaded","spec_epoch":1,"spec_counter":7,"cells":["dev-cell-1","dev-cell-2"]}` + "\n",
		"celld.log":         `{"msg":"bind refused","cell":"dev-cell-1"}` + "\n",
		"gw-status.json":    `{"epoch":1,"lastBindRefusal":{"dev-cell-1":{"reason":"nonce_invalid","requestId":"00000000000000aa","at":"2026-11-14T01:00:00Z"}}}`,
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
		{name: "management does not answer", change: map[string]string{"status.json": ""}, want: []string{"warning: attest-wait dev-cell-1", "CELL=management LINK_ONLY=mgmt-api mise run cell:link", "\nskipped\n"},
			deny: []string{"stage bound"}, check: func(t *testing.T, calls, _ string) {
				if strings.Contains(calls, "kubectl") {
					t.Errorf("the script called kubectl with no management plane:\n%s", calls)
				}
			}},
		{name: "management prints no JSON", change: map[string]string{"status.json": "not json"}, want: []string{"warning: attest-wait dev-cell-1", "CELL=management LINK_ONLY=mgmt-api mise run cell:link"}, deny: []string{"stage bound"}},
		{name: "not bound", change: map[string]string{"status.json": status(false)}, code: 1,
			want: []string{"stage bound failed", "Last celld bind log line: {\"msg\":\"bind refused\"",
				`Last gateway bind refusal for dev-cell-1: {"reason":"nonce_invalid","requestId":"00000000000000aa"`,
				`Last mgmtd refusal for dev-cell-1: {"kind":"bind","reason":"not_bound"`,
				"Next: mise x -- kubectl --context kind-dev-cell-1 -n cell-identity-system logs deploy/celld -c celld, and mise run mgmt -- status"},
			deny: []string{"CELL=dev-cp mise run cell:up"}},
		{name: "the gateway refused the bind source", change: map[string]string{"status.json": status(false), "gw-status.json": `{"epoch":1,"lastBindRefusal":{"dev-cell-1":{"reason":"source_mismatch","requestId":"00000000000000bb","at":"2099-01-01T00:00:00Z"}}}`}, code: 1,
			want: []string{"stage bound failed", `Last gateway bind refusal for dev-cell-1: {"reason":"source_mismatch"`, "Next: CELL=dev-cp mise run cell:up, then mise x -- kubectl"}},
		{name: "a fresh refusal on a node clock that lags the Mac counts as new", env: []string{"STUB_CLOCK_SKEW=300"},
			change: map[string]string{"status.json": status(false), "gw-status.json": `{"epoch":1,"lastBindRefusal":{"dev-cell-1":{"reason":"source_mismatch","at":"` + time.Now().Add(-290*time.Second).UTC().Format(time.RFC3339) + `"}}}`}, code: 1,
			want: []string{"stage bound failed", "Next: CELL=dev-cp mise run cell:up, then mise x -- kubectl"}},
		{name: "the gateway does not know the cell", change: map[string]string{"status.json": status(false), "gw-status.json": `{"epoch":1,"lastBindRefusal":{"dev-cell-1":{"reason":"cell_unknown","at":"2099-01-01T00:00:00.5Z"}}}`}, code: 1,
			want: []string{"stage bound failed", `"reason":"cell_unknown"`, "Next: CELL=dev-cp mise run cell:up, then mise x -- kubectl"}},
		{name: "an old gateway refusal prints no cell:up hint", change: map[string]string{"status.json": status(false), "gw-status.json": `{"epoch":1,"lastBindRefusal":{"dev-cell-1":{"reason":"source_mismatch","at":"2020-01-01T00:00:00Z"}}}`}, code: 1,
			want: []string{"stage bound failed", `"reason":"source_mismatch"`}, deny: []string{"CELL=dev-cp mise run cell:up"}},
		{name: "the gateway refusal of another cell does not count", change: map[string]string{"status.json": status(false), "gw-status.json": `{"epoch":1,"lastBindRefusal":{"dev-cell-2":{"reason":"source_mismatch"}}}`}, code: 1,
			want: []string{"stage bound failed", "Last gateway bind refusal for dev-cell-1: \"none\""}, deny: []string{"CELL=dev-cp mise run cell:up"}},
		{name: "the gateway status does not answer", change: map[string]string{"status.json": status(false), "gw-status.json": "not json"}, code: 1,
			want: []string{"stage bound failed", "Last mgmtd refusal for dev-cell-1:"}, deny: []string{"CELL=dev-cp mise run cell:up"}},
		{name: "not applied", change: map[string]string{"cell-records.json": records("6")}, code: 1,
			want: []string{"stage applied failed", "does not reach the revision 1/7", `lastRefusal: {"reason":"spec_invalid"`, "storeError: update refused", "Next: mise x -- kubectl --context kind-dev-cp -n envd-system logs deploy/envd -c envd"}},
		{name: "mgmtd has no root of dev-cp", change: map[string]string{"cell-records.json": records("6"), "no-peer-root": "1"}, code: 1,
			want: []string{"stage applied failed", "Next: CELL=management LINK_ONLY=mgmt-api mise run cell:link, then mise x -- kubectl --context kind-dev-cp -n envd-system logs deploy/envd"}},
		{name: "envd logs a TLS refusal", change: map[string]string{"cell-records.json": records("6"), "envd.log": `{"msg":"pull failed","error":"remote error: tls: bad certificate"}` + "\n"}, code: 1,
			want: []string{"stage applied failed", "Next: CELL=management LINK_ONLY=mgmt-api mise run cell:link, then", "bad certificate"}},
		{name: "no ConfigMap yet", change: map[string]string{"cell-records.json": ""}, code: 1, want: []string{"stage applied failed"}},
		{name: "a later revision counts", change: map[string]string{"cell-records.json": records("9")}, want: []string{"stage applied took"}},
		{name: "the reload line is far back in the log", change: map[string]string{"server.log": `{"msg":"records reloaded","spec_epoch":1,"spec_counter":7,"cells":["dev-cell-1"]}` + "\n" + strings.Repeat(`{"msg":"attested"}`+"\n", 700)},
			want: []string{"stage reloaded took"}},
		{name: "the server started with the records in place", change: map[string]string{"server.log": `{"msg":"configured","records":2,"spec_epoch":1,"spec_counter":7}` + "\n" + strings.Repeat(`{"msg":"attested"}`+"\n", 700)},
			want: []string{"stage reloaded took"}},
		{name: "the server started with fewer records than the ConfigMap holds", change: map[string]string{"server.log": `{"msg":"configured","records":1,"spec_epoch":1,"spec_counter":7}` + "\n"}, code: 1,
			want: []string{"stage reloaded failed"}},
		{name: "an old reload line that names the cell", change: map[string]string{"server.log": `{"msg":"records reloaded","spec_epoch":1,"spec_counter":3,"cells":["dev-cell-1"]}` + "\n"}, code: 1,
			want: []string{"stage reloaded failed", "revision 1/7", "log of the server since the last record change"}},
		{name: "an old reload line of an earlier epoch", change: map[string]string{"server.log": `{"msg":"records reloaded","spec_epoch":0,"spec_counter":99,"cells":["dev-cell-1"]}` + "\n"}, code: 1,
			want: []string{"stage reloaded failed"}},
		{name: "a later epoch counts", change: map[string]string{"server.log": `{"msg":"records reloaded","spec_epoch":2,"spec_counter":1,"cells":["dev-cell-1"]}` + "\n"},
			want: []string{"stage reloaded took"}},
		{name: "a configured line below the revision", change: map[string]string{"server.log": `{"msg":"configured","records":2,"spec_epoch":1,"spec_counter":3}` + "\n"}, code: 1,
			want: []string{"stage reloaded failed"}},
		{name: "a configured line with no revision", change: map[string]string{"server.log": `{"msg":"configured","records":2}` + "\n"}, code: 1,
			want: []string{"stage reloaded failed"}},
		{name: "the status kids are from before a rebuild", change: map[string]string{"facts.json": `{"nodeIP":"10.9.0.1","jwks":{"keys":[{"kid":"new"}]}}`}, code: 1,
			want: []string{"stage bound failed"}},
		{name: "the ConfigMap holds no record of the cell", change: map[string]string{"cell-records.json": `{"metadata":{"annotations":{"poc.internal/spec-epoch":"1","poc.internal/spec-counter":"7"}},"data":{"spec-envelope.json":"{}","dev-cell-2.dsse.json":"{}"},"x":1}`, "server.log": `{"msg":"configured","records":1}` + "\n"}, code: 1,
			want: []string{"stage reloaded failed"}},
		{name: "not reloaded", change: map[string]string{"server.log": `{"msg":"records reloaded","cells":["dev-cell-2"]}` + "\n"}, code: 1,
			want: []string{"stage reloaded failed", "kubelet syncs the ConfigMap volume", "verify row 1", "CELL=dev-cp mise run cell:restart"}},
		{name: "not ready", env: []string{"STUB_ROLLOUT_RC=1"}, code: 1, want: []string{"stage ready failed", "did not finish its rollout"}},
		{name: "a crash-looping agent", change: map[string]string{"pods.json": `{"items":[{"metadata":{"name":"celld-abc"},"status":{"containerStatuses":[{"name":"spire-agent","state":{"waiting":{"reason":"CrashLoopBackOff"}}},{"name":"celld","state":{"running":{}}}]}}]}`},
			want: []string{"CrashLoopBackOff, so the pod is deleted once (verify row 2)", "stage ready took"}, check: func(t *testing.T, _, deleted string) {
				if n := strings.Count(deleted, "delete pod celld-abc"); n != 1 {
					t.Errorf("the pod was deleted %d times, want once:\n%s", n, deleted)
				}
				if !strings.Contains(deleted, "wait --for=delete pod/celld-abc") {
					t.Errorf("the script did not wait for the old pod to go away:\n%s", deleted)
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
			for _, f := range []string{"calls", "deleted", "no-peer-root", "envd.log"} {
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
