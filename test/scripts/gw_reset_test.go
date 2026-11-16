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
  *" get pod cell-gateway-0 --ignore-not-found "*)
    echo podcheck >>"$STUB_DIR/calls"
    n=$(cat "$STUB_DIR/n" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STUB_DIR/n"
    if ((n <= ${STUB_POD_CHECKS:-0})); then echo pod/cell-gateway-0; fi ;;
  *" get pod cell-gateway-0 -o jsonpath="*) printf 'True' ;;
  *" get deployment envd -o jsonpath="*) printf '%s' "${STUB_ENVD_READY:-1}" ;;
  *" delete pvc "*)
    [[ -z "${STUB_NO_PVC:-}" ]] || { echo 'Error from server (NotFound): persistentvolumeclaims "store-cell-gateway-0" not found' >&2; exit 1; }
    echo "kubectl $*" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const gwResetReplicas = `#!/usr/bin/env bash
echo "harness-replicas $*" >>"$STUB_DIR/calls"
`

// gwResetStatus answers the first call with the old store and each later call with the new one. The first STUB_ZERO_SYNCS calls after
// the first show a zero syncedAt, as a gateway with a new store that envd has not synced with.
const gwResetStatus = `#!/usr/bin/env bash
echo "gw $*" >>"$STUB_DIR/calls"
n=$(cat "$STUB_DIR/gn" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STUB_DIR/gn"
if ((n == 1)); then
  echo '{"epoch":100,"syncedAt":"2026-11-14T00:00:00Z"}'
elif ((n - 1 <= ${STUB_ZERO_SYNCS:-0})); then
  echo '{"epoch":200,"syncedAt":"0001-01-01T00:00:00Z"}'
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
	run := func(env ...string) (string, string, string, error) {
		_ = os.Remove(filepath.Join(stub, "calls"))
		_ = os.Remove(filepath.Join(stub, "seen"))
		_ = os.Remove(filepath.Join(stub, "gn"))
		_ = os.Remove(filepath.Join(stub, "n"))
		cmd := exec.Command(filepath.Join(root, "scripts", "gw-reset.sh"))
		cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "POC_BUILD_ROOT=" + filepath.Join(root, "build"),
			"STUB_DIR=" + stub, "HARNESS_REPLICAS=" + filepath.Join(stub, "replicas"), "GW_SCRIPT=" + filepath.Join(stub, "gw"), "GW_RESET_WAIT=10"}, env...)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		calls, _ := os.ReadFile(filepath.Join(stub, "calls"))
		return out.String(), errOut.String(), string(calls), err
	}

	out, errOut, calls, err := run()
	if err != nil {
		t.Fatalf("gw-reset.sh: %v\n%s%s", err, out, errOut)
	}
	want := []string{
		"gw status",
		"harness-replicas dev-cp gateway-system statefulset/cell-gateway 0",
		"podcheck",
		"kubectl --context kind-dev-cp -n gateway-system delete pvc store-cell-gateway-0 --wait=true --timeout=120s",
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

	// A zero syncedAt is no sync: the script polls until the time is set. Two zero answers make two more reads of the status.
	_, _, calls, err = run("STUB_ZERO_SYNCS=2")
	if err != nil {
		t.Fatalf("gw-reset.sh with a zero syncedAt: %v", err)
	}
	if n := strings.Count(calls, "gw status"); n != 5 {
		t.Errorf("with two zero syncedAt answers the script read the status %d times, want 5 (before, three polls, after):\n%s", n, calls)
	}

	// Without a ready envd, the script does not wait for a sync.
	_, _, calls, err = run("STUB_ENVD_READY=0")
	if err != nil {
		t.Fatalf("gw-reset.sh with no ready envd: %v", err)
	}
	if n := strings.Count(calls, "gw status"); n != 2 {
		t.Errorf("with no ready envd the script read the status %d times, want 2 (before and after):\n%s", n, calls)
	}
}

// TestGwResetWaitsForThePodAndNeedsTheClaim: the volume claim goes only after the pod is gone, and a missing claim ends the script with
// one JSON error line and no delete that looks like a success.
func TestGwResetWaitsForThePodAndNeedsTheClaim(t *testing.T) {
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
	run := func(env ...string) (string, string, error) {
		for _, f := range []string{"calls", "seen", "n"} {
			_ = os.Remove(filepath.Join(stub, f))
		}
		cmd := exec.Command(filepath.Join(root, "scripts", "gw-reset.sh"))
		cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "POC_BUILD_ROOT=" + filepath.Join(root, "build"),
			"STUB_DIR=" + stub, "HARNESS_REPLICAS=" + filepath.Join(stub, "replicas"), "GW_SCRIPT=" + filepath.Join(stub, "gw"), "GW_RESET_WAIT=20"}, env...)
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		calls, _ := os.ReadFile(filepath.Join(stub, "calls"))
		return out.String(), string(calls), err
	}
	_, calls, err := run("STUB_POD_CHECKS=2")
	if err != nil {
		t.Fatalf("gw-reset.sh: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(calls), "\n")
	del := slicesIndexContains(lines, "delete pvc")
	if del < 0 || strings.Count(strings.Join(lines[:del], "\n"), "podcheck") != 3 {
		t.Errorf("the claim was deleted before the pod was gone (3 checks expected before the delete):\n%s", calls)
	}
	out, calls, err := run("STUB_NO_PVC=1")
	if err == nil {
		t.Fatalf("gw-reset.sh succeeded with no claim:\n%s", out)
	}
	var line struct{ Level, Error string }
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &line) != nil || line.Level != "ERROR" || !strings.Contains(line.Error, "store-cell-gateway-0") {
		t.Errorf("the output %q is no JSON error line that names the claim", out)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Errorf("the output is not one line: %q", out)
	}
	if !strings.Contains(calls, "statefulset/cell-gateway 1") {
		t.Errorf("the replicas did not return to 1 after the failure:\n%s", calls)
	}
}

func slicesIndexContains(lines []string, sub string) int {
	for i, l := range lines {
		if strings.Contains(l, sub) {
			return i
		}
	}
	return -1
}
