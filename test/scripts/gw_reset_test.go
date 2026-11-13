package scripts

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const gwResetKubectl = `#!/usr/bin/env bash
case " $* " in
  *" get pod cell-gateway-0 --ignore-not-found "*) ;;
  *" get pod cell-gateway-0 -o jsonpath="*) printf 'True' ;;
  *" get deployment envd -o jsonpath="*) printf '%s' "${STUB_ENVD_READY:-1}" ;;
  *" delete pvc "*) echo "kubectl $*" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const gwResetReplicas = `#!/usr/bin/env bash
echo "harness-replicas $*" >>"$STUB_DIR/calls"
`

// gwResetStatus answers the first call with the old store and each later call with the new one.
const gwResetStatus = `#!/usr/bin/env bash
echo "gw $*" >>"$STUB_DIR/calls"
if [[ ! -f "$STUB_DIR/seen" ]]; then
  touch "$STUB_DIR/seen"
  echo '{"epoch":100,"syncedAt":"2026-11-14T00:00:00Z"}'
else
  echo '{"epoch":200,"syncedAt":"2026-11-14T00:05:00Z"}'
fi
`

// TestGwReset: gw-reset.sh sets the replicas of cell-gateway to 0 and deletes the volume claim, in this order, then sets the replicas to 1
// through harness-replicas.sh, and prints one JSON line with the old and the new epoch.
func TestGwReset(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness"} {
		copyFiles(t, root, d)
	}
	stub := filepath.Join(root, "stub")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"bin/kubectl": gwResetKubectl, "stub/replicas": gwResetReplicas, "stub/gw": gwResetStatus} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(env ...string) (string, string, string) {
		_ = os.Remove(filepath.Join(stub, "calls"))
		_ = os.Remove(filepath.Join(stub, "seen"))
		cmd := exec.Command(filepath.Join(root, "scripts", "gw-reset.sh"))
		cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "POC_BUILD_ROOT=" + filepath.Join(root, "build"),
			"STUB_DIR=" + stub, "HARNESS_REPLICAS=" + filepath.Join(stub, "replicas"), "GW_SCRIPT=" + filepath.Join(stub, "gw"), "GW_RESET_WAIT=10"}, env...)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		if err := cmd.Run(); err != nil {
			t.Fatalf("gw-reset.sh: %v\n%s%s", err, out.String(), errOut.String())
		}
		calls, _ := os.ReadFile(filepath.Join(stub, "calls"))
		return out.String(), errOut.String(), string(calls)
	}

	out, _, calls := run()
	want := []string{
		"gw status",
		"harness-replicas dev-cp gateway-system statefulset/cell-gateway 0",
		"kubectl --context kind-dev-cp -n gateway-system delete pvc store-cell-gateway-0 --ignore-not-found --wait=true --timeout=120s",
		"harness-replicas dev-cp gateway-system statefulset/cell-gateway 1",
		"gw status",
		"gw status",
	}
	if got := strings.Split(strings.TrimSpace(calls), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the commands ran in this order:\n%s\nwant\n%s", calls, strings.Join(want, "\n"))
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Fatalf("the output is not one line: %q", out)
	}
	var line struct {
		Level    string
		OldEpoch uint64
		NewEpoch uint64
	}
	if err := json.Unmarshal([]byte(out), &line); err != nil || line.Level != "INFO" || line.OldEpoch != 100 || line.NewEpoch != 200 {
		t.Errorf("the output %q is %+v (%v), want one JSON line with oldEpoch 100 and newEpoch 200", out, line, err)
	}

	// Without a ready envd, the script does not wait for a sync.
	_, _, calls = run("STUB_ENVD_READY=0")
	if n := strings.Count(calls, "gw status"); n != 2 {
		t.Errorf("with no ready envd the script read the status %d times, want 2 (before and after):\n%s", n, calls)
	}
}
