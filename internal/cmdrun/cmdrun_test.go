//go:build unix

package cmdrun

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunCapturesOutputAndStatus(t *testing.T) {
	res, err := Run(10*time.Second, "", []string{"CELL=x"}, "bash", "-c", `echo "out $CELL"; echo err >&2; exit 3`)
	if err != nil || res.Code != 3 || res.Stdout != "out x\n" || res.Stderr != "err\n" {
		t.Fatalf("got %+v, %v; want status 3 with both streams", res, err)
	}
}

// TestRunKillsTheProcessGroup starts a child that keeps the output pipes open, as a mise task does. A command
// that only kills its own process would wait for the child, up to its 60 seconds.
func TestRunKillsTheProcessGroup(t *testing.T) {
	pidFile := t.TempDir() + "/child.pid"
	start := time.Now()
	res, err := Run(500*time.Millisecond, "", nil, "bash", "-c", `sleep 60 & echo $! >"$0"; wait`, pidFile)
	took := time.Since(start)
	if !errors.Is(err, ErrTimeout) || res.Code != -1 {
		t.Fatalf("got %+v, %v; want ErrTimeout and code -1", res, err)
	}
	if took > 10*time.Second {
		t.Fatalf("Run took %s for a limit of 500ms: the child kept the pipes open", took)
	}
	raw, rerr := os.ReadFile(pidFile)
	if rerr != nil {
		t.Fatal(rerr)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	deadline := time.Now().Add(3 * time.Second)
	for {
		if exec.Command("kill", "-0", strconv.Itoa(pid)).Run() != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the child %d is still alive after the kill of the group", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRunReportsAMissingCommand(t *testing.T) {
	if _, err := Run(time.Second, "", nil, "no-such-command-for-cmdrun"); err == nil || errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want a start error", err)
	}
}

// TestRunReturnsWhenAChildLeftTheGroup starts a child in a group of its own (job control), so the kill of the group
// does not reach it and it keeps the output pipes open. WaitDelay ends the wait.
func TestRunReturnsWhenAChildLeftTheGroup(t *testing.T) {
	pidFile := t.TempDir() + "/child.pid"
	start := time.Now()
	_, err := Run(300*time.Millisecond, "", nil, "bash", "-c", `set -m; sleep 40 & echo $! >"$0"; wait`, pidFile)
	took := time.Since(start)
	t.Cleanup(func() {
		if raw, rerr := os.ReadFile(pidFile); rerr == nil {
			_ = exec.Command("kill", strings.TrimSpace(string(raw))).Run()
		}
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	if limit := termGrace + waitDelay + 5*time.Second; took > limit {
		t.Fatalf("Run took %s, want a return within %s", took, limit)
	}
}

// TestRunSendsTermBeforeKill: a command that passes its limit gets SIGTERM first, so the EXIT trap of a script runs. A command that
// ignores SIGTERM gets SIGKILL after the grace time.
func TestRunSendsTermBeforeKill(t *testing.T) {
	old := termGrace
	termGrace = time.Second
	t.Cleanup(func() { termGrace = old })
	marker := t.TempDir() + "/trap"
	_, err := Run(500*time.Millisecond, "", nil, "bash", "-c", `trap 'echo cleaned >"$0"; exit 7' TERM; sleep 25 & wait`, marker)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	if raw, rerr := os.ReadFile(marker); rerr != nil || strings.TrimSpace(string(raw)) != "cleaned" {
		t.Errorf("the trap of the command did not run after the limit: %q, %v", raw, rerr)
	}

	pidFile := t.TempDir() + "/pid"
	start := time.Now()
	_, err = Run(300*time.Millisecond, "", nil, "bash", "-c", `trap '' TERM; echo $$ >"$0"; while :; do sleep 1; done`, pidFile)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("a command that ignores SIGTERM ran %s, want the SIGKILL after the grace time", took)
	}
	raw, _ := os.ReadFile(pidFile)
	deadline := time.Now().Add(3 * time.Second)
	for exec.Command("kill", "-0", strings.TrimSpace(string(raw))).Run() == nil {
		if time.Now().After(deadline) {
			t.Fatalf("the process %s is still alive after the grace time", raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestRunForwardsSignalsToTheGroup checks that a signal sent to the process reaches the command, which runs in a group
// of its own: a Ctrl-C of the test run must stop a running task, not leave it behind.
func TestRunForwardsSignalsToTheGroup(t *testing.T) {
	marker := t.TempDir() + "/term"
	done := make(chan Result, 1)
	go func() {
		res, _ := Run(30*time.Second, "", nil, "bash", "-c", `trap 'echo got >"$0"; exit 7' TERM; sleep 25 & wait`, marker)
		done <- res
	}()
	deadline := time.Now().Add(5 * time.Second)
	for activeGroups() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the command did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	forwardSignal(syscall.SIGTERM)
	select {
	case res := <-done:
		if res.Code != 7 {
			t.Errorf("the command ended with %+v, want status 7 from its trap", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the command did not stop after the signal")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the trap of the command did not run: %v", err)
	}
	if n := activeGroups(); n != 0 {
		t.Errorf("%d groups stay registered after the command ended", n)
	}
}
