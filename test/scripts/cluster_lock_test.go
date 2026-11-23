package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// lockRun sources scripts/lib.sh with POC_BUILD_ROOT=build and runs the snippet. The snippet runs in one shell, so a lock that
// it takes belongs to that shell.
func lockRun(t *testing.T, build, snippet string, env ...string) (string, error) {
	t.Helper()
	testtool.Need(t, "yq", "bash")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; `+snippet, "_", lib)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cell-1", "POC_BUILD_ROOT=" + build}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return out.String(), err
}

// holder starts a process whose command line shows a harness script, as ps prints it, and writes it as the holder of the
// lock of cluster. It stands for a cell:up that runs. A holder with another program name, or a pid that ended, is stale.
func holder(t *testing.T, build, cluster, program, step string, seconds int) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("bash", "-c", "exec -a "+program+" sleep "+strconv.Itoa(seconds))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	dir := filepath.Join(build, "locks", cluster+".lock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"pid": strconv.Itoa(cmd.Process.Pid), "step": step} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return cmd
}

// TestClusterLock: cluster_lock keeps one run for each cluster, and the lock directory lives outside build/<cluster>.
func TestClusterLock(t *testing.T) {
	t.Parallel()
	t.Run("mkdir -p: the lock needs no build directory, and make none for the cluster", func(t *testing.T) {
		build := filepath.Join(t.TempDir(), "build")
		out, err := lockRun(t, build, `cluster_lock dev-cell-1; test -f "$BUILD_ROOT/locks/dev-cell-1.lock/pid" && echo held; echo "$POC_HELD_LOCKS"`)
		if err != nil || !strings.Contains(out, "held") || !strings.Contains(out, "dev-cell-1") {
			t.Fatalf("err %v, output %q; want a held lock and POC_HELD_LOCKS", err, out)
		}
		// cell:down deletes build/<cluster>, and gate.sh reads its presence as a set up cluster, so the lock must not create it.
		if _, err := os.Stat(filepath.Join(build, "dev-cell-1")); err == nil {
			t.Fatal("cluster_lock made build/dev-cell-1")
		}
		if _, err := os.Stat(filepath.Join(build, "locks", "dev-cell-1.lock")); err == nil {
			t.Fatal("the lock outlived the shell that took it")
		}
	})

	t.Run("a live holder fails at once and names its pid and step", func(t *testing.T) {
		build := t.TempDir()
		h := holder(t, build, "dev-cell-1", "up.sh", strings.Repeat("a", 32), 60)
		begin := time.Now()
		out, err := lockRun(t, build, `cluster_lock dev-cell-1; echo took-it`)
		if err == nil || strings.Contains(out, "took-it") {
			t.Fatalf("a second run took the lock: %v\n%s", err, out)
		}
		for _, want := range []string{"cluster dev-cell-1 is locked by process " + strconv.Itoa(h.Process.Pid), "step " + strings.Repeat("a", 32)} {
			if !strings.Contains(out, want) {
				t.Errorf("output %q lacks %q", out, want)
			}
		}
		if d := time.Since(begin); d > 5*time.Second {
			t.Errorf("the refusal took %s, want it at once", d)
		}
		// The lock of the holder stays.
		if _, err := os.Stat(filepath.Join(build, "locks", "dev-cell-1.lock", "pid")); err != nil {
			t.Fatal("the refused run removed the lock of the holder")
		}
	})

	t.Run("each harness script counts as a holder", func(t *testing.T) {
		for _, program := range []string{"up.sh", "link.sh", "down.sh", "restart.sh", "/repo/scripts/up.sh"} {
			build := t.TempDir()
			holder(t, build, "dev-cell-1", program, "", 60)
			if out, err := lockRun(t, build, `cluster_lock dev-cell-1`); err == nil {
				t.Errorf("%s: the second run took the lock of a live harness script:\n%s", program, out)
			}
		}
	})

	t.Run("a holder that is no harness script, or that ended, is taken over", func(t *testing.T) {
		build := t.TempDir()
		holder(t, build, "dev-cell-1", "sleep-not-a-script", "", 60)
		if out, err := lockRun(t, build, `cluster_lock dev-cell-1; echo took-it`); err != nil || !strings.Contains(out, "took-it") {
			t.Fatalf("a pid of another program kept the lock: %v\n%s", err, out)
		}
		gone := exec.Command("true")
		if err := gone.Run(); err != nil {
			t.Fatal(err)
		}
		build = t.TempDir()
		dir := filepath.Join(build, "locks", "dev-cell-1.lock")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pid"), []byte(strconv.Itoa(gone.Process.Pid)), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := lockRun(t, build, `cluster_lock dev-cell-1; echo took-it`); err != nil || !strings.Contains(out, "took-it") {
			t.Fatalf("a lock of an ended run kept the lock: %v\n%s", err, out)
		}
	})

	t.Run("CLUSTER_LOCK_WAIT waits for the holder to end", func(t *testing.T) {
		build := t.TempDir()
		holder(t, build, "dev-cell-1", "link.sh", "", 2)
		begin := time.Now()
		out, err := lockRun(t, build, `cluster_lock dev-cell-1; echo took-it`, "CLUSTER_LOCK_WAIT=30", "CLUSTER_LOCK_POLL=0.2")
		if err != nil || !strings.Contains(out, "took-it") {
			t.Fatalf("the wait did not end with the lock: %v\n%s", err, out)
		}
		if d := time.Since(begin); d < time.Second {
			t.Errorf("the run took the lock after %s, but the holder ran 2 s", d)
		}
	})

	t.Run("CLUSTER_LOCK_WAIT ends with the holder still there", func(t *testing.T) {
		build := t.TempDir()
		h := holder(t, build, "dev-cell-1", "up.sh", "", 60)
		out, err := lockRun(t, build, `cluster_lock dev-cell-1; echo took-it`, "CLUSTER_LOCK_WAIT=1", "CLUSTER_LOCK_POLL=0.2")
		if err == nil || strings.Contains(out, "took-it") || !strings.Contains(out, "after 1s") || !strings.Contains(out, strconv.Itoa(h.Process.Pid)) {
			t.Fatalf("err %v, output %q; want a failure after the wait that names the holder", err, out)
		}
	})

	t.Run("a nested call re-enters through POC_HELD_LOCKS", func(t *testing.T) {
		build := t.TempDir()
		holder(t, build, "dev-cell-1", "up.sh", "", 60)
		out, err := lockRun(t, build, `cluster_lock dev-cell-1; echo nested-ok`, "POC_HELD_LOCKS=dev-cp dev-cell-1")
		if err != nil || !strings.Contains(out, "nested-ok") {
			t.Fatalf("a child of the holder was refused: %v\n%s", err, out)
		}
		// The child does not own the lock, so it does not release it.
		if _, err := os.Stat(filepath.Join(build, "locks", "dev-cell-1.lock", "pid")); err != nil {
			t.Fatal("the nested call removed the lock of its parent")
		}
		// Another cluster is not covered.
		if out, err = lockRun(t, build, `cluster_lock dev-cell-2; echo took-it`, "POC_HELD_LOCKS=dev-cell-1"); err != nil || !strings.Contains(out, "took-it") {
			t.Fatalf("another cluster: %v\n%s", err, out)
		}
	})

	t.Run("a child process tree re-enters, and the parent releases", func(t *testing.T) {
		build := t.TempDir()
		out, err := lockRun(t, build, `cluster_lock dev-cell-1; bash -c 'source "$1"; cluster_lock dev-cell-1; echo child-ok; test -d "$BUILD_ROOT/locks/dev-cell-1.lock" && echo child-saw-lock' _ "$ROOT/scripts/lib.sh"`)
		if err != nil || !strings.Contains(out, "child-ok") || !strings.Contains(out, "child-saw-lock") {
			t.Fatalf("err %v, output %q; want the child to pass through the lock of its parent", err, out)
		}
		if _, err := os.Stat(filepath.Join(build, "locks", "dev-cell-1.lock")); err == nil {
			t.Fatal("the lock outlived its process tree")
		}
	})

	t.Run("release lets the next run in, and clears POC_HELD_LOCKS", func(t *testing.T) {
		build := t.TempDir()
		out, err := lockRun(t, build, `cluster_lock dev-cell-1; cluster_lock_release; echo "held='$POC_HELD_LOCKS'"; test -d "$BUILD_ROOT/locks/dev-cell-1.lock" || echo released`)
		if err != nil || !strings.Contains(out, "held=''") || !strings.Contains(out, "released") {
			t.Fatalf("err %v, output %q", err, out)
		}
	})

	t.Run("the lock keeps the exit trap of the script", func(t *testing.T) {
		build := t.TempDir()
		out, err := lockRun(t, build, `trap 'echo script-trap-ran' EXIT; cluster_lock dev-cell-1`)
		if err != nil || !strings.Contains(out, "script-trap-ran") {
			t.Fatalf("err %v, output %q; want the trap of the script to run too", err, out)
		}
		if _, err := os.Stat(filepath.Join(build, "locks", "dev-cell-1.lock")); err == nil {
			t.Fatal("the lock outlived the shell")
		}
	})
}
