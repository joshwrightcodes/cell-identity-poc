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
    if [[ -n "${STUB_PUB_STALE:-}" ]]; then printf '%s' "$STUB_OLD_PUB"; else printf '%s' "$STUB_NEW_PUB"; fi ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// The fake mise answers mgmt -- pubkey, mgmt -- status and mgmt -- rotate-key, and logs each cell command with the CELL variable. After
// a rotation, pubkey answers the new key. STUB_ROTATE_FAIL makes rotate-key fail with nothing changed. STUB_ROTATE_PUBLISH_FAIL makes
// it fail after the rotation, with rotated:true in its error line, as mgmtd does when the publish of the public key fails.
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
  "run mgmt -- rotate-key")
    echo "mgmt rotate-key" >>"$STUB_DIR/calls"
    if [[ -n "${STUB_ROTATE_FAIL:-}" ]]; then echo '{"level":"ERROR","msg":"mgmtd failed","error":"conflict","reason":"conflict"}'; exit 1; fi
    touch "$STUB_DIR/rotated"
    if [[ -n "${STUB_ROTATE_LOST:-}" ]]; then exit 1; fi
    if [[ -n "${STUB_ROTATE_PUBLISH_FAIL:-}" ]]; then echo '{"level":"ERROR","msg":"mgmtd failed","error":"the key rotated, but its public half did not publish: api down","rotated":true}'; exit 1; fi
    printf '{"spec.pub":"%s","signed":{"epoch":2,"counter":1},"seq":9}\n' "$STUB_NEW_PUB" ;;
  "run cell:up"|"run cell:link"|"run cell:verify")
    echo "CELL=$CELL $*" >>"$STUB_DIR/calls"
    [[ "CELL=$CELL $*" != "${STUB_FAIL:-}" ]] || { echo "the step failed" >&2; exit 1; } ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

// TestRotateKeyOrder: mise run mgmt -- rotate-signing-key runs mgmtd ctl rotate-key, waits for mgmt-signing-pub to hold the new key,
// renders dev-cp and management, and verifies both, in that order. It prints one JSON line with the fingerprints and the new epoch. A
// failure after the first step prints the commands that are left, from the failed one on, and no JSON line.
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

	run := func(script string, env ...string) (stdout, stderr string, err error) {
		_ = os.Remove(filepath.Join(stub, "calls"))
		_ = os.Remove(filepath.Join(stub, "rotated"))
		cmd := exec.Command(filepath.Join(root, "scripts", script), "rotate-signing-key")
		if script == "mgmt-rotate-key.sh" {
			cmd = exec.Command(filepath.Join(root, "scripts", script))
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
	waitCmd := "mise x -- kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath={.data.spec\\.pub}"
	wantOrder := []string{
		"mgmt pubkey", "mgmt rotate-key",
		"kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath={.data.spec\\.pub}",
		"CELL=dev-cp run cell:up", "CELL=management run cell:link", "CELL=management run cell:verify", "CELL=dev-cp run cell:verify",
	}
	type result struct {
		Rotated bool     `json:"rotated"`
		Old     string   `json:"old_key_sha256"`
		New     string   `json:"new_key_sha256"`
		Epoch   int      `json:"epoch"`
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

	t.Run("order through mgmt.sh", func(t *testing.T) {
		out, errOut, err := run("mgmt.sh")
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		if got := callLog(); strings.Join(got, "\n") != strings.Join(wantOrder, "\n") {
			t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantOrder, "\n"))
		}
		res := oneLine(t, out)
		if !res.Rotated || res.Epoch != 2 || res.Old != sha(oldKey) || res.New != sha(newKey) {
			t.Fatalf("result %+v, want rotated, epoch 2 and the SHA-256 of each key", res)
		}
	})

	// A failure after the rotation prints one JSON error line with the failed step, rotated:true, both fingerprints and the commands
	// that are left, and the same commands as text on standard error.
	for _, tc := range []struct {
		name, fail, step string
		env              []string
		ran              int // calls of wantOrder that happen before the failure, the failed one included; 0 for a wait that polls
		left             []string
	}{
		{"dev-cp step fails", "CELL=dev-cp run cell:up", "cell:up-dev-cp", nil, 4,
			[]string{"CELL=dev-cp mise run cell:up", "CELL=management mise run cell:link", "CELL=management mise run cell:verify", "CELL=dev-cp mise run cell:verify"}},
		{"link step fails", "CELL=management run cell:link", "cell:link-management", nil, 5,
			[]string{"CELL=management mise run cell:link", "CELL=management mise run cell:verify", "CELL=dev-cp mise run cell:verify"}},
		{"management verify fails", "CELL=management run cell:verify", "cell:verify-management", nil, 6,
			[]string{"CELL=management mise run cell:verify", "CELL=dev-cp mise run cell:verify"}},
		{"last verify fails", "CELL=dev-cp run cell:verify", "cell:verify-dev-cp", nil, 7, []string{"CELL=dev-cp mise run cell:verify"}},
		{"key not published", "", "publish", []string{"STUB_PUB_STALE=1", "MGMT_ROTATE_KEY_WAIT=1"}, 0,
			[]string{waitCmd, "CELL=dev-cp mise run cell:up", "CELL=management mise run cell:link", "CELL=management mise run cell:verify", "CELL=dev-cp mise run cell:verify"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, err := run("mgmt-rotate-key.sh", append([]string{"STUB_FAIL=" + tc.fail}, tc.env...)...)
			if err == nil {
				t.Fatalf("the script succeeded, want a failure; stdout %q", out)
			}
			res := oneLine(t, out)
			if res.Level != "ERROR" || !res.Rotated || res.Step != tc.step || res.Old != sha(oldKey) || res.New != sha(newKey) ||
				!strings.Contains(res.Error, "the signing key rotated, but") {
				t.Errorf("the error line is %+v, want level ERROR, rotated true, step %s and both fingerprints", res, tc.step)
			}
			if strings.Join(res.Left, "\n") != strings.Join(tc.left, "\n") {
				t.Errorf("remaining %q, want %q", res.Left, tc.left)
			}
			for _, w := range tc.left {
				if !strings.Contains(errOut, "  "+w) {
					t.Errorf("stderr lacks the remaining command %q:\n%s", w, errOut)
				}
			}
			got := callLog()
			if tc.ran > 0 {
				if want := wantOrder[:tc.ran]; strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
				}
			} else {
				for _, c := range got {
					if strings.Contains(c, "cell:") {
						t.Errorf("%q ran before the new key was published", c)
					}
				}
			}
			if strings.Contains(out+errOut, oldPub) || strings.Contains(out+errOut, newPub) {
				t.Errorf("the output holds a public key, want fingerprints only")
			}
		})
	}

	t.Run("rotate-key fails with nothing changed", func(t *testing.T) {
		out, errOut, err := run("mgmt-rotate-key.sh", "STUB_ROTATE_FAIL=1")
		res := oneLine(t, out)
		if err == nil || res.Level != "ERROR" || res.Rotated || !strings.Contains(res.Error, "mgmtd ctl rotate-key failed") {
			t.Fatalf("err %v, stdout %q, stderr %q; want one JSON error line without rotated", err, out, errOut)
		}
		for _, c := range callLog() {
			if strings.Contains(c, "cell:") {
				t.Fatalf("%q ran after a failed rotation", c)
			}
		}
	})

	// The key rotated, but the answer of the exec was lost: no output at all. The script reads the key again and goes on.
	t.Run("rotated and the answer was lost", func(t *testing.T) {
		out, errOut, err := run("mgmt-rotate-key.sh", "STUB_ROTATE_LOST=1")
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		if res := oneLine(t, out); !res.Rotated || res.New != sha(newKey) || res.Epoch != 2 {
			t.Fatalf("result %+v, want rotated with the new key at epoch 2", res)
		}
	})

	// The key rotated and the new key cannot be read: the error line holds rotated as a JSON boolean.
	t.Run("rotated is a boolean when the key cannot be read", func(t *testing.T) {
		out, _, err := run("mgmt-rotate-key.sh", "STUB_ROTATE_PUBLISH_FAIL=1", "STUB_PUBKEY_FAIL_AFTER=1")
		var line map[string]any
		if err == nil || json.Unmarshal([]byte(out), &line) != nil || line["rotated"] != true {
			t.Fatalf("err %v, stdout %q; want one error line with rotated true as a boolean", err, out)
		}
	})

	// The key rotated and the publish failed: the ctl error line says rotated:true, so the script goes on with the wait and the renders.
	t.Run("rotated but not published", func(t *testing.T) {
		out, errOut, err := run("mgmt-rotate-key.sh", "STUB_ROTATE_PUBLISH_FAIL=1")
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
