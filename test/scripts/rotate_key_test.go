package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const rotateKeyKubectl = `#!/usr/bin/env bash
case " $* " in
  *" get configmap mgmt-signing-pub "*)
    echo "kubectl $*" >>"$STUB_DIR/calls"
    case "$*" in
      *'next\.pub'*) if [[ -n "${STUB_NEXT_STALE:-}" ]]; then printf ''; else printf '%s' "$STUB_NEW_PUB"; fi ;;
      *) if [[ -n "${STUB_PUB_STALE:-}" ]]; then printf '%s' "$STUB_OLD_PUB"; else printf '%s' "$STUB_NEW_PUB"; fi ;;
    esac ;;
  *" rollout status deployment/celld "*)
    echo "kubectl $*" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// The fake kind lists STUB_KIND (default: management, dev-cp and both cells), and fails with STUB_KIND_FAIL. The fake docker gives each
// node container an address on the network kind, as live_cells reads it.
const rotateKeyKind = `#!/usr/bin/env bash
[[ "$*" == "get clusters" ]] || exit 2
[[ -z "${STUB_KIND_FAIL:-}" ]] || exit 1
printf '%s\n' ${STUB_KIND:-management dev-cp dev-cell-1 dev-cell-2}
`

const rotateKeyDocker = `#!/usr/bin/env bash
[[ "$1 $2" == "inspect -f" ]] || exit 2
echo 172.18.0.5
`

// The fake mise answers mgmt -- pubkey, mgmt -- status and mgmt -- rotate-key with each flag, and logs each cell command with the CELL
// variable. After a commit or an emergency rotation, pubkey answers the new key. STUB_STAGE_FAIL makes --stage fail. STUB_ROTATE_FAIL
// makes the commit or the emergency rotation fail with nothing changed. STUB_ROTATE_PUBLISH_FAIL makes it fail after the rotation, with
// rotated:true in its error line, as mgmtd does when the publish of the public key fails. STUB_FAIL names one cell command that fails,
// and STUB_FAIL_AT its occurrence (default 1). hostsvc:serve -- sync is logged, and STUB_SYNC_FAIL makes its STUB_SYNC_FAIL_AT occurrence
// fail (default 1). hostsvc:serve -- stages prints STUB_STAGES (the lines of the running stages, none by default), and fails with STUB_STEPS_FAIL. It prints a task header and a warning on standard error. Each cell command
// records CLUSTER_LOCK_WAIT in the file lockwait.
const rotateKeyMise = `#!/usr/bin/env bash
case "$*" in
  "run mgmt -- pubkey")
    echo "mgmt pubkey" >>"$STUB_DIR/calls"
    if [[ -e "$STUB_DIR/rotated" ]]; then
      [[ -z "${STUB_PUBKEY_FAIL_AFTER:-}" ]] || { echo "exec failed" >&2; exit 1; }
      pub="$STUB_NEW_PUB"
    else pub="$STUB_OLD_PUB"; fi
    printf '{"spec.pub":"%s"}\n' "$pub" ;;
  "run mgmt -- status")
    [[ -z "${STUB_STATUS_FAIL:-}" ]] || { echo "exec failed" >&2; exit 1; }
    # stagedKey is the SHA-256 of the staged key, which is the new key. STUB_STAGED_OTHER replaces it.
    staged="${STUB_STAGED_OTHER:-$(printf '%s' "$STUB_NEW_PUB" | base64 -d | shasum -a 256 | cut -d' ' -f1)}"
    printf '{"signed":{"epoch":2,"counter":1},"stagedKey":"%s"}\n' "$staged" ;;
  "run mgmt -- rotate-key --stage")
    echo "mgmt rotate-key --stage" >>"$STUB_DIR/calls"
    if [[ -n "${STUB_STAGE_FAIL:-}" ]]; then echo '{"level":"ERROR","msg":"mgmtd failed","error":"conflict","reason":"conflict"}'; exit 1; fi
    printf '{"next.pub":"%s","staged":true,"seq":8}\n' "$STUB_NEW_PUB" ;;
  "run mgmt -- rotate-key --commit"|"run mgmt -- rotate-key --emergency")
    echo "mgmt rotate-key ${5}" >>"$STUB_DIR/calls"
    if [[ -n "${STUB_ROTATE_FAIL:-}" ]]; then echo '{"level":"ERROR","msg":"mgmtd failed","error":"conflict","reason":"conflict"}'; exit 1; fi
    touch "$STUB_DIR/rotated"
    if [[ -n "${STUB_ROTATE_LOST:-}" ]]; then exit 1; fi
    if [[ -n "${STUB_ROTATE_PUBLISH_FAIL:-}" ]]; then echo '{"level":"ERROR","msg":"mgmtd failed","error":"the key rotated, but its public half did not publish: api down","rotated":true}'; exit 1; fi
    # STUB_COMMIT_OTHER makes the commit answer a key that the stage did not make.
    printf '{"spec.pub":"%s","signed":{"epoch":2,"counter":1},"seq":9}\n' "${STUB_COMMIT_OTHER:-$STUB_NEW_PUB}" ;;
  "run hostsvc:serve -- sync")
    echo "hostsvc sync" >>"$STUB_DIR/calls"
    if [[ -n "${STUB_SYNC_FAIL:-}" && "$(grep -cxF "hostsvc sync" "$STUB_DIR/calls")" == "${STUB_SYNC_FAIL_AT:-1}" ]]; then echo "sync failed" >&2; exit 1; fi ;;
  "run hostsvc:serve -- stages")
    echo "hostsvc stages" >>"$STUB_DIR/calls"
    # The real mise prints the task header on standard error, and a run of mise can print warnings there too.
    echo "[hostsvc:serve] \$ scripts/hostsvc-serve.sh stages" >&2
    echo "mise WARN a warning on standard error" >&2
    [[ -z "${STUB_STEPS_FAIL:-}" ]] || { echo "no admin socket" >&2; exit 1; }
    [[ -z "${STUB_STAGES:-}" ]] || printf '%s\n' "$STUB_STAGES" ;;
  "run cell:up"|"run cell:link"|"run cell:verify")
    label="CELL=$CELL ${HARNESS_ONLY:+HARNESS_ONLY=$HARNESS_ONLY }$*"
    echo "$label" >>"$STUB_DIR/calls"
    echo "${CLUSTER_LOCK_WAIT:-unset}" >>"$STUB_DIR/lockwait"
    if [[ "$label" == "${STUB_FAIL:-}" ]]; then
      n="$(grep -cxF "$label" "$STUB_DIR/calls")"
      if [[ "$n" == "${STUB_FAIL_AT:-1}" ]]; then echo "the step failed" >&2; exit 1; fi
    fi ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

// TestRotateKeyOrder: mise run mgmt -- rotate-signing-key follows the overlap order: stage the next key, wait for next.pub in
// mgmt-signing-pub, run cell:up for each cluster with cell-identity, commit, wait for the new key, render dev-cp and management, run the
// cell passes again, and verify both clusters. --emergency skips the stage and the first cell pass. --step runs one step. It prints one
// JSON line with the fingerprints, the new epoch and the run time. A failure prints the commands that are left, from the failed one on,
// and one JSON error line.
func TestRotateKeyOrder(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash", "base64", "shasum")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	stub, bin := filepath.Join(root, "stub"), filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"kubectl": rotateKeyKubectl, "mise": rotateKeyMise, "kind": rotateKeyKind, "docker": rotateKeyDocker} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	oldPub, newPub := base64.StdEncoding.EncodeToString(oldKey), base64.StdEncoding.EncodeToString(newKey)
	sha := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	run := func(script string, args []string, env ...string) (stdout, stderr string, err error) {
		_ = os.Remove(filepath.Join(stub, "calls"))
		_ = os.Remove(filepath.Join(stub, "rotated"))
		_ = os.Remove(filepath.Join(stub, "lockwait"))
		cmd := exec.Command(filepath.Join(root, "scripts", script), args...)
		if script == "mgmt.sh" {
			cmd = exec.Command(filepath.Join(root, "scripts", script), append([]string{"rotate-signing-key"}, args...)...)
		}
		cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "POC_BUILD_ROOT=" + filepath.Join(root, "build"),
			"STUB_DIR=" + stub, "STUB_OLD_PUB=" + oldPub, "STUB_NEW_PUB=" + newPub}, env...)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err = cmd.Run()
		return out.String(), errOut.String(), err
	}
	callLog := func() []string {
		b, _ := os.ReadFile(filepath.Join(stub, "calls"))
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	waitCmd := func(key string) string {
		return "mise x -- kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath={.data." + key + "}"
	}
	// A step is what the script runs: its name in the error line, the command that a person runs, and the call that the stub logs.
	type step struct{ name, cmd, call string }
	kubectlCall := func(key string) string {
		return "kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath={.data." + key + "}"
	}
	up := func(cell string) step {
		return step{"cell:up-" + cell, "CELL=" + cell + " mise run cell:up", "CELL=" + cell + " run cell:up"}
	}
	stage := step{"stage", "mise run mgmt -- rotate-key --stage", "mgmt rotate-key --stage"}
	nextWait := step{"next-published", waitCmd(`next\.pub`), kubectlCall(`next\.pub`)}
	commit := step{"commit", "mise run mgmt -- rotate-key --commit", "mgmt rotate-key --commit"}
	emergency := step{"emergency", "mise run mgmt -- rotate-key --emergency", "mgmt rotate-key --emergency"}
	specWait := step{"publish", waitCmd(`spec\.pub`), kubectlCall(`spec\.pub`)}
	devCP := up("dev-cp")
	link := step{"cell:link-management", "CELL=management mise run cell:link", "CELL=management run cell:link"}
	rollout := func(cell string) step {
		c := "mise x -- kubectl --context kind-" + cell + " -n cell-identity-system rollout status deployment/celld --timeout=300s"
		return step{"rollout-" + cell, c, "kubectl --context kind-" + cell + " -n cell-identity-system rollout status deployment/celld --timeout=300s"}
	}
	verifyMgmt := step{"cell:verify-management", "CELL=management mise run cell:verify", "CELL=management run cell:verify"}
	verifyCP := step{"cell:verify-dev-cp", "CELL=dev-cp mise run cell:verify", "CELL=dev-cp run cell:verify"}
	cell1, cell2 := up("dev-cell-1"), up("dev-cell-2")
	roll1, roll2 := rollout("dev-cell-1"), rollout("dev-cell-2")
	// The host service learns each key through sync, and the cell controller and envd of dev-cp get their renders before the planes.
	const syncCmd = "mise run hostsvc:serve -- sync"
	syncStaged := step{"hostsvc-sync-staged", syncCmd, "hostsvc sync"}
	syncNew := step{"hostsvc-sync-new", syncCmd, "hostsvc sync"}
	ctlNext := step{"cell-controller-next", "CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:up", "CELL=dev-cp HARNESS_ONLY=cell-controller run cell:up"}
	envdRender := step{"envd-render", "CELL=dev-cp HARNESS_ONLY=envd mise run cell:up", "CELL=dev-cp HARNESS_ONLY=envd run cell:up"}
	ctlRender := step{"cell-controller-render", "CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:up", "CELL=dev-cp HARNESS_ONLY=cell-controller run cell:up"}
	overlap := []step{stage, nextWait, syncStaged, ctlNext, cell1, cell2, commit, specWait, syncNew, envdRender, ctlRender, devCP, link, cell1, cell2, roll1, roll2, verifyMgmt, verifyCP}
	emergencyOrder := []step{emergency, specWait, syncNew, envdRender, ctlRender, devCP, link, cell1, cell2, roll1, roll2, verifyMgmt, verifyCP}
	// A run reads the steps of the host service first, then the public key of mgmtd.
	calls := func(steps []step) []string {
		got := []string{"hostsvc stages", "mgmt pubkey"}
		for _, s := range steps {
			got = append(got, s.call)
		}
		return got
	}
	type result struct {
		Rotated bool     `json:"rotated"`
		Staged  bool     `json:"staged"`
		Old     string   `json:"old_key_sha256"`
		New     string   `json:"new_key_sha256"`
		Epoch   int      `json:"epoch"`
		Seconds *int     `json:"seconds"`
		Key     string   `json:"key_sha256"`
		Level   string   `json:"level"`
		Error   string   `json:"error"`
		Step    string   `json:"step"`
		Left    []string `json:"remaining"`
	}
	oneLine := func(t *testing.T, out string) result {
		t.Helper()
		var res result
		if strings.Count(out, "\n") != 1 || json.Unmarshal([]byte(out), &res) != nil {
			t.Fatalf("standard output is %q, want one JSON line", out)
		}
		return res
	}
	sameCalls := func(t *testing.T, got, want []string) {
		t.Helper()
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}

	t.Run("order through mgmt.sh", func(t *testing.T) {
		out, errOut, err := run("mgmt.sh", nil)
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		sameCalls(t, callLog(), calls(overlap))
		res := oneLine(t, out)
		if !res.Rotated || res.Epoch != 2 || res.Old != sha(oldKey) || res.New != sha(newKey) || res.Seconds == nil {
			t.Fatalf("result %+v, want rotated, epoch 2, the SHA-256 of each key and the run time", res)
		}
	})

	t.Run("emergency skips the stage and the first cell pass", func(t *testing.T) {
		out, errOut, err := run("mgmt-rotate-key.sh", []string{"--emergency"})
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		sameCalls(t, callLog(), calls(emergencyOrder))
		if res := oneLine(t, out); !res.Rotated || res.Epoch != 2 || res.Old != sha(oldKey) || res.New != sha(newKey) || res.Seconds == nil {
			t.Fatalf("result %+v, want rotated, epoch 2 and the SHA-256 of each key", res)
		}
	})

	// --step runs one step. The planes step runs only the two plane renders, and no verify.
	for _, tc := range []struct {
		step  string
		order []step
		check func(*testing.T, result)
	}{
		{"stage", []step{stage, nextWait, syncStaged, ctlNext}, func(t *testing.T, r result) {
			if r.Rotated || !r.Staged || r.Old != sha(oldKey) || r.New != sha(newKey) {
				t.Errorf("result %+v, want staged and not rotated, with the fingerprints of the live and the staged key", r)
			}
		}},
		{"cells", []step{cell1, cell2}, func(t *testing.T, r result) {
			if r.Rotated || r.Key != sha(oldKey) {
				t.Errorf("result %+v, want not rotated with the key fingerprint", r)
			}
		}},
		{"commit", []step{nextWait, commit, specWait, syncNew}, func(t *testing.T, r result) {
			if !r.Rotated || r.Epoch != 2 || r.New != sha(newKey) {
				t.Errorf("result %+v, want rotated at epoch 2", r)
			}
		}},
		{"planes", []step{envdRender, ctlRender, devCP, link}, func(t *testing.T, r result) {
			if r.Rotated || r.Key != sha(oldKey) {
				t.Errorf("result %+v, want not rotated with the key fingerprint", r)
			}
		}},
	} {
		t.Run("step "+tc.step, func(t *testing.T) {
			out, errOut, err := run("mgmt-rotate-key.sh", []string{"--step", tc.step})
			if err != nil {
				t.Fatalf("%v\n%s", err, errOut)
			}
			sameCalls(t, callLog(), calls(tc.order))
			res := oneLine(t, out)
			if res.Seconds == nil {
				t.Error("the result holds no run time")
			}
			tc.check(t, res)
		})
	}

	// The commit step alone refuses a next.pub that does not hash to stagedKey, before the key changes.
	t.Run("step commit with a next.pub that mgmtd did not stage", func(t *testing.T) {
		out, _, err := run("mgmt-rotate-key.sh", []string{"--step", "commit"}, "STUB_STAGED_OTHER="+strings.Repeat("0", 64))
		var line map[string]any
		if err == nil || json.Unmarshal([]byte(out), &line) != nil || !strings.Contains(fmt.Sprint(line["error"]), "has the SHA-256") {
			t.Fatalf("err %v, stdout %q; want one error line that names the hashes", err, out)
		}
		for _, c := range callLog() {
			if strings.Contains(c, "rotate-key") {
				t.Errorf("%q ran after the check failed", c)
			}
		}
	})

	// A failed status read after the stage prints one JSON error line.
	t.Run("step stage with a failed status read", func(t *testing.T) {
		out, _, err := run("mgmt-rotate-key.sh", []string{"--step", "stage"}, "STUB_STATUS_FAIL=1")
		var line map[string]any
		if err == nil || strings.Count(out, "\n") != 1 || json.Unmarshal([]byte(out), &line) != nil || line["level"] != "ERROR" {
			t.Fatalf("err %v, stdout %q; want one JSON error line", err, out)
		}
	})

	t.Run("bad arguments", func(t *testing.T) {
		for _, args := range [][]string{{"--step"}, {"--step", "verify"}, {"--step", "stage", "x"}, {"--emergency", "x"}, {"--now"}} {
			if out, _, err := run("mgmt-rotate-key.sh", args); err == nil || strings.Contains(strings.Join(callLog(), "\n"), "rotate-key") {
				t.Errorf("arguments %v: err %v, calls %q, stdout %q; want a refusal before any call", args, err, callLog(), out)
			}
		}
	})

	// A failure prints one JSON error line with the failed step, rotated, the fingerprints and the commands that are left, and the same
	// commands as text on standard error. rotated is true only once the commit went through. A failed stage has no new fingerprint.
	type failure struct {
		name  string
		order []step
		at    int // the index of the failed step in order
		env   []string
		args  []string
	}
	// find returns the index of the nth step (1-based) of order with the name.
	find := func(order []step, name string, nth int) int {
		for i, s := range order {
			if s.name == name {
				if nth--; nth == 0 {
					return i
				}
			}
		}
		t.Fatalf("no step %s (%d) in the order", name, nth)
		return -1
	}
	failures := []failure{
		{"stage fails", overlap, find(overlap, "stage", 1), []string{"STUB_STAGE_FAIL=1"}, nil},
		{"next key not published", overlap, find(overlap, "next-published", 1), []string{"STUB_NEXT_STALE=1", "MGMT_ROTATE_KEY_WAIT=1"}, nil},
		{"sync of the staged key fails", overlap, find(overlap, "hostsvc-sync-staged", 1), []string{"STUB_SYNC_FAIL=1", "STUB_SYNC_FAIL_AT=1"}, nil},
		{"render of the cell controller with the staged key fails", overlap, find(overlap, "cell-controller-next", 1),
			[]string{"STUB_FAIL=CELL=dev-cp HARNESS_ONLY=cell-controller run cell:up", "STUB_FAIL_AT=1"}, nil},
		{"first pass, dev-cell-1 fails", overlap, find(overlap, "cell:up-dev-cell-1", 1), []string{"STUB_FAIL=CELL=dev-cell-1 run cell:up", "STUB_FAIL_AT=1"}, nil},
		{"first pass, dev-cell-2 fails", overlap, find(overlap, "cell:up-dev-cell-2", 1), []string{"STUB_FAIL=CELL=dev-cell-2 run cell:up", "STUB_FAIL_AT=1"}, nil},
		{"commit fails", overlap, find(overlap, "commit", 1), []string{"STUB_ROTATE_FAIL=1"}, nil},
		{"new key not published", overlap, find(overlap, "publish", 1), []string{"STUB_PUB_STALE=1", "MGMT_ROTATE_KEY_WAIT=1"}, nil},
		{"sync of the new key fails", overlap, find(overlap, "hostsvc-sync-new", 1), []string{"STUB_SYNC_FAIL=1", "STUB_SYNC_FAIL_AT=2"}, nil},
		{"render of envd fails", overlap, find(overlap, "envd-render", 1), []string{"STUB_FAIL=CELL=dev-cp HARNESS_ONLY=envd run cell:up"}, nil},
		{"render of the cell controller fails", overlap, find(overlap, "cell-controller-render", 1),
			[]string{"STUB_FAIL=CELL=dev-cp HARNESS_ONLY=cell-controller run cell:up", "STUB_FAIL_AT=2"}, nil},
		{"dev-cp step fails", overlap, find(overlap, "cell:up-dev-cp", 1), []string{"STUB_FAIL=CELL=dev-cp run cell:up"}, nil},
		{"link step fails", overlap, find(overlap, "cell:link-management", 1), []string{"STUB_FAIL=CELL=management run cell:link"}, nil},
		{"second pass, dev-cell-1 fails", overlap, find(overlap, "cell:up-dev-cell-1", 2), []string{"STUB_FAIL=CELL=dev-cell-1 run cell:up", "STUB_FAIL_AT=2"}, nil},
		{"second pass, dev-cell-2 fails", overlap, find(overlap, "cell:up-dev-cell-2", 2), []string{"STUB_FAIL=CELL=dev-cell-2 run cell:up", "STUB_FAIL_AT=2"}, nil},
		{"management verify fails", overlap, find(overlap, "cell:verify-management", 1), []string{"STUB_FAIL=CELL=management run cell:verify"}, nil},
		{"last verify fails", overlap, find(overlap, "cell:verify-dev-cp", 1), []string{"STUB_FAIL=CELL=dev-cp run cell:verify"}, nil},
		{"emergency: sync of the new key fails", emergencyOrder, find(emergencyOrder, "hostsvc-sync-new", 1), []string{"STUB_SYNC_FAIL=1", "STUB_SYNC_FAIL_AT=1"}, []string{"--emergency"}},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, err := run("mgmt-rotate-key.sh", tc.args, tc.env...)
			if err == nil {
				t.Fatalf("the script succeeded, want a failure; stdout %q", out)
			}
			failed := tc.order[tc.at]
			// A failed commit changes nothing, so rotated is true only from the wait for the new key on.
			rotated := tc.at >= find(tc.order, "publish", 1)
			newFP := sha(newKey)
			if failed.name == "stage" {
				newFP = ""
			}
			res := oneLine(t, out)
			if res.Level != "ERROR" || res.Rotated != rotated || res.Step != failed.name || res.Old != sha(oldKey) || res.New != newFP {
				t.Errorf("the error line is %+v, want level ERROR, rotated %v, step %s and the fingerprints %s and %s", res, rotated, failed.name, sha(oldKey), newFP)
			}
			want := "the signing key did not rotate, because"
			if rotated {
				want = "the signing key rotated, but"
			}
			if !strings.Contains(res.Error, want) {
				t.Errorf("error %q lacks %q", res.Error, want)
			}
			var left []string
			for _, s := range tc.order[tc.at:] {
				left = append(left, s.cmd)
			}
			if strings.Join(res.Left, "\n") != strings.Join(left, "\n") {
				t.Errorf("remaining %q, want %q", res.Left, left)
			}
			for _, w := range left {
				if !strings.Contains(errOut, "  "+w) {
					t.Errorf("stderr lacks the remaining command %q:\n%s", w, errOut)
				}
			}
			got := callLog()
			polled := failed.name == "next-published" || failed.name == "publish"
			if !polled {
				// The failed step is the last call, and no later step ran. A failed commit reads the key again once.
				want := calls(tc.order[:tc.at+1])
				if failed.name == "commit" {
					want = append(want, "mgmt pubkey")
				}
				sameCalls(t, got, want)
			} else {
				ran := calls(tc.order[:tc.at])
				if strings.Join(got[:len(ran)], "\n") != strings.Join(ran, "\n") {
					t.Errorf("calls:\n%s\nwant a start of:\n%s", strings.Join(got, "\n"), strings.Join(ran, "\n"))
				}
				for _, c := range got[len(ran):] {
					if strings.Contains(c, "cell:") || strings.Contains(c, "rotate-key") {
						t.Errorf("%q ran before the key was published", c)
					}
				}
			}
			if strings.Contains(out+errOut, oldPub) || strings.Contains(out+errOut, newPub) {
				t.Errorf("the output holds a public key, want fingerprints only")
			}
		})
	}

	// The same failure of a step in the emergency run reports the commands from that step on, with the emergency rotation first.
	t.Run("emergency: the cell pass fails", func(t *testing.T) {
		out, _, err := run("mgmt-rotate-key.sh", []string{"--emergency"}, "STUB_FAIL=CELL=dev-cell-2 run cell:up")
		res := oneLine(t, out)
		if err == nil || !res.Rotated || res.Step != "cell:up-dev-cell-2" || strings.Join(res.Left, "|") != strings.Join([]string{cell2.cmd, roll1.cmd, roll2.cmd, verifyMgmt.cmd, verifyCP.cmd}, "|") {
			t.Fatalf("err %v, line %+v; want rotated, the failed step and the commands from it on", err, res)
		}
	})

	// A commit that answers another key than the staged one is a failure: the run did not rotate to the key that it staged, and no
	// cell pass runs after it.
	t.Run("commit answers another key than the staged one", func(t *testing.T) {
		other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
		out, errOut, err := run("mgmt-rotate-key.sh", nil, "STUB_COMMIT_OTHER="+other, "MGMT_ROTATE_KEY_WAIT=1")
		res := oneLine(t, out)
		if err == nil || res.Level != "ERROR" || res.Step != "commit" || !strings.Contains(res.Error, "not the key that this run staged") {
			t.Fatalf("err %v, line %+v, stderr %q; want a failure at the commit that names the staged key", err, res, errOut)
		}
		for _, c := range callLog() {
			if strings.Contains(c, "cell:link") || strings.Contains(c, "cell:verify") {
				t.Errorf("%q ran after a commit of the wrong key", c)
			}
		}
	})

	t.Run("rotate-key fails with nothing changed", func(t *testing.T) {
		for _, args := range [][]string{nil, {"--emergency"}} {
			out, errOut, err := run("mgmt-rotate-key.sh", args, "STUB_ROTATE_FAIL=1")
			res := oneLine(t, out)
			if err == nil || res.Level != "ERROR" || res.Rotated || !strings.Contains(res.Error, "mgmtd ctl rotate-key") {
				t.Fatalf("args %v: err %v, stdout %q, stderr %q; want one JSON error line without rotated", args, err, out, errOut)
			}
			for _, c := range callLog() {
				if strings.Contains(c, "cell:up") && !strings.Contains(strings.Join(args, " "), "--emergency") {
					continue
				}
				if strings.Contains(c, "cell:link") || strings.Contains(c, "cell:verify") {
					t.Fatalf("%q ran after a failed rotation", c)
				}
			}
		}
	})

	// The key rotated, but the answer of the exec was lost: no output at all. The script reads the key again and goes on.
	t.Run("rotated and the answer was lost", func(t *testing.T) {
		for _, args := range [][]string{nil, {"--emergency"}} {
			out, errOut, err := run("mgmt-rotate-key.sh", args, "STUB_ROTATE_LOST=1")
			if err != nil {
				t.Fatalf("args %v: %v\n%s", args, err, errOut)
			}
			if res := oneLine(t, out); !res.Rotated || res.New != sha(newKey) || res.Epoch != 2 {
				t.Fatalf("result %+v, want rotated with the new key at epoch 2", res)
			}
		}
	})

	// The key rotated and the new key cannot be read: the error line holds rotated as a JSON boolean.
	t.Run("rotated is a boolean when the key cannot be read", func(t *testing.T) {
		out, _, err := run("mgmt-rotate-key.sh", []string{"--emergency"}, "STUB_ROTATE_PUBLISH_FAIL=1", "STUB_PUBKEY_FAIL_AFTER=1")
		var line map[string]any
		if err == nil || json.Unmarshal([]byte(out), &line) != nil || line["rotated"] != true {
			t.Fatalf("err %v, stdout %q; want one error line with rotated true as a boolean", err, out)
		}
	})

	// The key rotated and the publish failed: the ctl error line says rotated:true, so the script goes on with the wait and the renders.
	t.Run("rotated but not published", func(t *testing.T) {
		out, errOut, err := run("mgmt-rotate-key.sh", nil, "STUB_ROTATE_PUBLISH_FAIL=1")
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		res := oneLine(t, out)
		if !res.Rotated || res.New != sha(newKey) || res.Old != sha(oldKey) || res.Epoch != 2 {
			t.Fatalf("result %+v, want rotated with both fingerprints at epoch 2", res)
		}
		got := callLog()
		if got[len(got)-1] != "CELL=dev-cp run cell:verify" {
			t.Fatalf("calls %q, want the script to finish every step", got)
		}
	})

	// The cell passes and the planes take the lock of their clusters, and an admit stage holds the lock of dev-cp for up to 45 minutes. So
	// the script refuses to start while the journal shows a stage, before it changes anything, unless --force.
	const running = "0123456789abcdef0123456789abcdef dev-cell-2 admitting"
	t.Run("a stage that runs refuses every mode", func(t *testing.T) {
		for _, args := range [][]string{nil, {"--emergency"}, {"--step", "stage"}, {"--step", "cells"}, {"--step", "commit"}, {"--step", "planes"}} {
			out, errOut, err := run("mgmt-rotate-key.sh", args, "STUB_STAGES="+running)
			var line map[string]any
			if err == nil || json.Unmarshal([]byte(out), &line) != nil || line["level"] != "ERROR" ||
				!strings.Contains(fmt.Sprint(line["error"]), "a step runs a stage: 0123456789abcdef0123456789abcdef dev-cell-2 admitting") ||
				!strings.Contains(fmt.Sprint(line["error"]), "--force") {
				t.Fatalf("args %v: err %v, stdout %q, stderr %q; want one error line that names the stage and --force", args, err, out, errOut)
			}
			sameCalls(t, callLog(), []string{"hostsvc stages"})
		}
	})

	// A run with no stage works although the task prints a header and a warning on standard error.
	t.Run("the task header on standard error does not break the read", func(t *testing.T) {
		if out, errOut, err := run("mgmt-rotate-key.sh", nil); err != nil {
			t.Fatalf("%v\n%s\n%s", err, out, errOut)
		}
	})

	t.Run("a failed read of the steps refuses", func(t *testing.T) {
		out, _, err := run("mgmt-rotate-key.sh", nil, "STUB_STEPS_FAIL=1")
		var line map[string]any
		if err == nil || json.Unmarshal([]byte(out), &line) != nil || !strings.Contains(fmt.Sprint(line["error"]), "cannot tell whether a step runs a stage") || !strings.Contains(fmt.Sprint(line["error"]), "--force") {
			t.Fatalf("err %v, stdout %q; want one error line that says the read failed and names --force", err, out)
		}
		sameCalls(t, callLog(), []string{"hostsvc stages"})
	})

	// --force skips the read and makes each cell command wait up to 900 s for the lock of a stage. Without it no command waits.
	t.Run("force goes on and waits for the lock", func(t *testing.T) {
		for _, args := range [][]string{{"--force"}, {"--force", "--emergency"}, {"--emergency", "--force"}, {"--step", "planes", "--force"}} {
			out, errOut, err := run("mgmt-rotate-key.sh", args, "STUB_STAGES="+running)
			if err != nil {
				t.Fatalf("args %v: %v\n%s\n%s", args, err, out, errOut)
			}
			for _, c := range callLog() {
				if c == "hostsvc stages" {
					t.Errorf("args %v: the script read the steps although --force was given", args)
				}
			}
			b, _ := os.ReadFile(filepath.Join(stub, "lockwait"))
			for _, w := range strings.Fields(string(b)) {
				if w != "900" {
					t.Errorf("args %v: a cell command saw CLUSTER_LOCK_WAIT=%s, want 900", args, w)
				}
			}
			if len(strings.Fields(string(b))) == 0 {
				t.Errorf("args %v: no cell command ran", args)
			}
		}
		if _, errOut, err := run("mgmt-rotate-key.sh", nil); err != nil {
			t.Fatal(err, errOut)
		}
		b, _ := os.ReadFile(filepath.Join(stub, "lockwait"))
		for _, w := range strings.Fields(string(b)) {
			if w != "unset" {
				t.Errorf("without --force a cell command saw CLUSTER_LOCK_WAIT=%s, want none", w)
			}
		}
	})

	for _, args := range [][]string{{"--force", "--force"}, {"--force", "x"}, {"--step", "--force"}} {
		t.Run("bad arguments "+strings.Join(args, " "), func(t *testing.T) {
			if out, _, err := run("mgmt-rotate-key.sh", args); err == nil || strings.Contains(strings.Join(callLog(), "\n"), "rotate-key") {
				t.Errorf("err %v, calls %q, stdout %q; want a refusal before any call", err, callLog(), out)
			}
		})
	}

	// The cell passes and the rollout waits cover the live cells. A cell with no cluster gets no pass, and its next cell:up pins the live key.
	t.Run("an absent cell gets no pass", func(t *testing.T) {
		out, errOut, err := run("mgmt-rotate-key.sh", nil, "STUB_KIND=management dev-cp dev-cell-1")
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		var want []step
		for _, s := range overlap {
			if s.name != "cell:up-dev-cell-2" && s.name != "rollout-dev-cell-2" {
				want = append(want, s)
			}
		}
		sameCalls(t, callLog(), calls(want))
		if res := oneLine(t, out); !res.Rotated {
			t.Fatalf("result %+v, want rotated", res)
		}
	})

	t.Run("no live cell gives no cell pass", func(t *testing.T) {
		if _, errOut, err := run("mgmt-rotate-key.sh", nil, "STUB_KIND=management dev-cp"); err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		for _, c := range callLog() {
			if strings.Contains(c, "dev-cell") {
				t.Errorf("%q ran with no live cell", c)
			}
		}
	})

	// A kind that does not answer must not drop a cell from the pass, so the script stops before it changes anything.
	t.Run("kind that does not answer stops the run", func(t *testing.T) {
		out, _, err := run("mgmt-rotate-key.sh", nil, "STUB_KIND_FAIL=1")
		var line map[string]any
		if err == nil || json.Unmarshal([]byte(out), &line) != nil || line["level"] != "ERROR" || !strings.Contains(fmt.Sprint(line["error"]), "live cells") {
			t.Fatalf("err %v, stdout %q; want one error line about the live cells", err, out)
		}
		for _, c := range callLog() {
			if strings.Contains(c, "rotate-key") || strings.Contains(c, "cell:") {
				t.Errorf("%q ran although the live cells were unknown", c)
			}
		}
	})
}
