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

// The fake mise answers mgmt -- pubkey and mgmt -- rotate-key, and logs each cell command with the CELL variable.
const rotateKeyMise = `#!/usr/bin/env bash
case "$*" in
  "run mgmt -- pubkey") echo "mgmt pubkey" >>"$STUB_DIR/calls"; printf '{"spec.pub":"%s"}\n' "$STUB_OLD_PUB" ;;
  "run mgmt -- rotate-key")
    echo "mgmt rotate-key" >>"$STUB_DIR/calls"
    if [[ -n "${STUB_ROTATE_FAIL:-}" ]]; then echo '{"level":"ERROR","msg":"mgmtd failed","error":"conflict"}'; exit 1; fi
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

	run := func(script string, env ...string) (stdout, stderr string, calls []string, err error) {
		_ = os.Remove(filepath.Join(stub, "calls"))
		cmd := exec.Command(filepath.Join(root, "scripts", script), "rotate-signing-key")
		if script == "mgmt-rotate-key.sh" {
			cmd = exec.Command(filepath.Join(root, "scripts", script))
		}
		cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "POC_BUILD_ROOT=" + filepath.Join(root, "build"),
			"STUB_DIR=" + stub, "STUB_OLD_PUB=" + oldPub, "STUB_NEW_PUB=" + newPub}, env...)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err = cmd.Run()
		b, _ := os.ReadFile(filepath.Join(stub, "calls"))
		return out.String(), errOut.String(), strings.Fields(strings.ReplaceAll(string(b), "\n", "\x00")), err
	}
	callLog := func() []string {
		b, _ := os.ReadFile(filepath.Join(stub, "calls"))
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	wantOrder := []string{
		"mgmt pubkey", "mgmt rotate-key",
		"kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath={.data.spec\\.pub}",
		"CELL=dev-cp run cell:up", "CELL=management run cell:link", "CELL=management run cell:verify", "CELL=dev-cp run cell:verify",
	}

	t.Run("order through mgmt.sh", func(t *testing.T) {
		out, errOut, _, err := run("mgmt.sh")
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		if got := callLog(); strings.Join(got, "\n") != strings.Join(wantOrder, "\n") {
			t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantOrder, "\n"))
		}
		var res struct {
			Rotated bool   `json:"rotated"`
			Old     string `json:"old_key_sha256"`
			New     string `json:"new_key_sha256"`
			Epoch   int    `json:"epoch"`
		}
		if strings.Count(out, "\n") != 1 || json.Unmarshal([]byte(out), &res) != nil {
			t.Fatalf("standard output is %q, want one JSON line", out)
		}
		if !res.Rotated || res.Epoch != 2 || res.Old != sha(oldKey) || res.New != sha(newKey) {
			t.Fatalf("result %+v, want rotated, epoch 2 and the SHA-256 of each key", res)
		}
	})

	for _, tc := range []struct {
		name, fail string
		env        []string
		left       []string
		notLeft    []string
	}{
		{"dev-cp step fails", "CELL=dev-cp run cell:up", nil, []string{"CELL=dev-cp mise run cell:up", "CELL=management mise run cell:link", "CELL=management mise run cell:verify", "CELL=dev-cp mise run cell:verify"}, nil},
		{"link step fails", "CELL=management run cell:link", nil, []string{"CELL=management mise run cell:link", "CELL=management mise run cell:verify", "CELL=dev-cp mise run cell:verify"}, []string{"cell:up"}},
		{"last verify fails", "CELL=dev-cp run cell:verify", nil, []string{"CELL=dev-cp mise run cell:verify"}, []string{"cell:up", "cell:link"}},
		{"key not published", "", []string{"STUB_PUB_STALE=1", "MGMT_ROTATE_KEY_WAIT=1"}, []string{"get configmap mgmt-signing-pub", "CELL=dev-cp mise run cell:up", "CELL=management mise run cell:link"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append([]string{"STUB_FAIL=" + tc.fail}, tc.env...)
			out, errOut, _, err := run("mgmt-rotate-key.sh", env...)
			if err == nil || out != "" {
				t.Fatalf("err %v, stdout %q; want a failure with no JSON line", err, out)
			}
			if !strings.Contains(errOut, "the signing key rotated, but") {
				t.Fatalf("stderr %q lacks the failure line", errOut)
			}
			for _, w := range tc.left {
				if !strings.Contains(errOut, "  "+w) && !strings.Contains(errOut, w) {
					t.Errorf("stderr lacks the remaining command %q:\n%s", w, errOut)
				}
			}
			for _, w := range tc.notLeft {
				if i := strings.Index(errOut, "Run these commands in order:"); i < 0 || strings.Contains(errOut[i:], w) {
					t.Errorf("the remaining commands hold %q, which already ran:\n%s", w, errOut)
				}
			}
			if got := callLog(); tc.fail != "" && len(got) < 4 {
				t.Errorf("calls %v: too few before the failure", got)
			}
		})
	}

	t.Run("rotate-key fails", func(t *testing.T) {
		out, errOut, _, err := run("mgmt-rotate-key.sh", "STUB_ROTATE_FAIL=1")
		if err == nil || strings.Count(out, "\n") != 1 || !strings.Contains(out, "mgmtd ctl rotate-key failed") {
			t.Fatalf("err %v, stdout %q, stderr %q; want one JSON error line", err, out, errOut)
		}
		for _, c := range callLog() {
			if strings.Contains(c, "cell:") {
				t.Fatalf("%q ran after a failed rotation", c)
			}
		}
	})
}
