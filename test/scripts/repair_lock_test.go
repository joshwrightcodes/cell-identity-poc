package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// runRepair runs scripts/gate-m2-repair.sh with a lock directory whose pid file holds pid, and with
// docker and kubectl stubs that fail at once.
func runRepair(t *testing.T, pid int, args ...string) (string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir := t.TempDir()
	for _, tool := range []string{"docker", "kubectl"} {
		if err := os.WriteFile(filepath.Join(dir, tool), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	lock := filepath.Join(dir, "lock")
	if err := os.Mkdir(lock, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../scripts/gate-m2-repair.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script, args...)
	cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GATE_M2_REPAIR_LOCK=" + lock}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return out.String(), err
}

func TestRepairRefusesToRunBesideAnotherRepair(t *testing.T) {
	t.Parallel()
	// The holder shows the command name of a repair, as ps prints it.
	holder := exec.Command("bash", "-c", "exec -a gate-m2-repair.sh sleep 60")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Process.Kill(); _ = holder.Wait() })
	for _, args := range [][]string{nil, {"--check"}} {
		out, err := runRepair(t, holder.Process.Pid, args...)
		want := "a repair already runs as process " + strconv.Itoa(holder.Process.Pid)
		if err == nil || !strings.Contains(out, want) {
			t.Fatalf("repair %v: err %v, output %q; want a refusal that names the process", args, err, out)
		}
	}
}

// A PID can be reused by another process after a repair ends without its cleanup. A lock whose
// process is no repair counts as stale.
func TestRepairTakesOverALockOfAnotherProcess(t *testing.T) {
	t.Parallel()
	other := exec.Command("sleep", "60")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	out, err := runRepair(t, other.Process.Pid, "--check")
	if strings.Contains(out, "already runs") {
		t.Fatalf("the check refused a lock of a process that is no repair: %q (err %v)", out, err)
	}
}

// A lock without a live process is left from a repair that ended without its cleanup.
func TestRepairTakesOverAStaleLock(t *testing.T) {
	t.Parallel()
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	out, err := runRepair(t, gone.Process.Pid)
	if err == nil {
		t.Fatal("the repair succeeded against failing stubs")
	}
	if strings.Contains(out, "already runs") {
		t.Fatalf("the repair refused a stale lock: %q", out)
	}
}
