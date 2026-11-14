package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// The fake mise answers mgmt -- pubkey, mgmt -- status and mgmt -- rotate-key with each flag, and logs each cell command with the CELL
// variable. After a commit or an emergency rotation, pubkey answers the new key. STUB_STAGE_FAIL makes --stage fail. STUB_ROTATE_FAIL
// makes the commit or the emergency rotation fail with nothing changed. STUB_ROTATE_PUBLISH_FAIL makes it fail after the rotation, with
// rotated:true in its error line, as mgmtd does when the publish of the public key fails. STUB_FAIL names one cell command that fails,
// and STUB_FAIL_AT its occurrence (default 1).
const rotateKeyMise = `#!/usr/bin/env bash
case "$*" in
  "run mgmt -- pubkey")
    echo "mgmt pubkey" >>"$STUB_DIR/calls"
    if [[ -e "$STUB_DIR/rotated" ]]; then
      [[ -z "${STUB_PUBKEY_FAIL_AFTER:-}" ]] || { echo "exec failed" >&2; exit 1; }
      pub="$STUB_NEW_PUB"
    else pub="$STUB_OLD_PUB"; fi
    printf '{"spec.pub":"%s"}\n' "$pub" ;;
  "run mgmt -- status") echo '{"signed":{"epoch":2,"counter":1}}' ;;
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
    printf '{"spec.pub":"%s","signed":{"epoch":2,"counter":1},"seq":9}\n' "$STUB_NEW_PUB" ;;
  "run cell:up"|"run cell:link"|"run cell:verify")
    echo "CELL=$CELL $*" >>"$STUB_DIR/calls"
    if [[ "CELL=$CELL $*" == "${STUB_FAIL:-}" ]]; then
      n="$(grep -cxF "CELL=$CELL $*" "$STUB_DIR/calls")"
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
	for name, body := range map[string]string{"kubectl": rotateKeyKubectl, "mise": rotateKeyMise} {
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
	verifyMgmt := step{"cell:verify-management", "CELL=management mise run cell:verify", "CELL=management run cell:verify"}
	verifyCP := step{"cell:verify-dev-cp", "CELL=dev-cp mise run cell:verify", "CELL=dev-cp run cell:verify"}
	cell1, cell2 := up("dev-cell-1"), up("dev-cell-2")
	overlap := []step{stage, nextWait, cell1, cell2, commit, specWait, devCP, link, cell1, cell2, verifyMgmt, verifyCP}
	emergencyOrder := []step{emergency, specWait, devCP, link, cell1, cell2, verifyMgmt, verifyCP}
	calls := func(steps []step) []string {
		got := []string{"mgmt pubkey"}
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
		{"stage", []step{stage, nextWait}, func(t *testing.T, r result) {
			if r.Rotated || !r.Staged || r.Old != sha(oldKey) || r.New != sha(newKey) {
				t.Errorf("result %+v, want staged and not rotated, with the fingerprints of the live and the staged key", r)
			}
		}},
		{"cells", []step{cell1, cell2}, func(t *testing.T, r result) {
			if r.Rotated || r.Key != sha(oldKey) {
				t.Errorf("result %+v, want not rotated with the key fingerprint", r)
			}
		}},
		{"commit", []step{nextWait, commit, specWait}, func(t *testing.T, r result) {
			if !r.Rotated || r.Epoch != 2 || r.New != sha(newKey) {
				t.Errorf("result %+v, want rotated at epoch 2", r)
			}
		}},
		{"planes", []step{devCP, link}, func(t *testing.T, r result) {
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
	}
	failures := []failure{
		{"stage fails", overlap, 0, []string{"STUB_STAGE_FAIL=1"}},
		{"next key not published", overlap, 1, []string{"STUB_NEXT_STALE=1", "MGMT_ROTATE_KEY_WAIT=1"}},
		{"first pass, dev-cell-1 fails", overlap, 2, []string{"STUB_FAIL=CELL=dev-cell-1 run cell:up", "STUB_FAIL_AT=1"}},
		{"first pass, dev-cell-2 fails", overlap, 3, []string{"STUB_FAIL=CELL=dev-cell-2 run cell:up", "STUB_FAIL_AT=1"}},
		{"commit fails", overlap, 4, []string{"STUB_ROTATE_FAIL=1"}},
		{"new key not published", overlap, 5, []string{"STUB_PUB_STALE=1", "MGMT_ROTATE_KEY_WAIT=1"}},
		{"dev-cp step fails", overlap, 6, []string{"STUB_FAIL=CELL=dev-cp run cell:up"}},
		{"link step fails", overlap, 7, []string{"STUB_FAIL=CELL=management run cell:link"}},
		{"second pass, dev-cell-1 fails", overlap, 8, []string{"STUB_FAIL=CELL=dev-cell-1 run cell:up", "STUB_FAIL_AT=2"}},
		{"second pass, dev-cell-2 fails", overlap, 9, []string{"STUB_FAIL=CELL=dev-cell-2 run cell:up", "STUB_FAIL_AT=2"}},
		{"management verify fails", overlap, 10, []string{"STUB_FAIL=CELL=management run cell:verify"}},
		{"last verify fails", overlap, 11, []string{"STUB_FAIL=CELL=dev-cp run cell:verify"}},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, err := run("mgmt-rotate-key.sh", nil, tc.env...)
			if err == nil {
				t.Fatalf("the script succeeded, want a failure; stdout %q", out)
			}
			failed := tc.order[tc.at]
			// A failed commit changes nothing, so rotated is true only from the wait for the new key on.
			rotated := tc.at >= 5
			newFP := sha(newKey)
			if tc.at == 0 {
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
			polled := tc.at == 1 || tc.at == 5
			if !polled {
				// The failed step is the last call, and no later step ran. A failed commit reads the key again once.
				want := calls(tc.order[:tc.at+1])
				if tc.at == 4 {
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
		if err == nil || !res.Rotated || res.Step != "cell:up-dev-cell-2" || strings.Join(res.Left, "|") != strings.Join([]string{cell2.cmd, verifyMgmt.cmd, verifyCP.cmd}, "|") {
			t.Fatalf("err %v, line %+v; want rotated, the failed step and the commands from it on", err, res)
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
}
