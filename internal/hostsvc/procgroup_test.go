package hostsvc

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

func pidGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

func readPid(t *testing.T, path string) int {
	t.Helper()
	var pid int
	waitUntil(t, "pid file "+path, 5*time.Second, func() bool {
		b, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		pid = n
		return err == nil && n > 0
	})
	return pid
}

func TestStartGroup(t *testing.T) {
	testtool.Need(t, "sh")
	var out bytes.Buffer
	g, err := StartGroup([]string{"sh", "-c", "echo hello; echo err >&2; exit 3"}, os.Environ(), &out)
	if err != nil {
		t.Fatal(err)
	}
	if g.Pgid <= 1 || g.LeaderStart == "" {
		t.Errorf("group = %+v", g)
	}
	var ee *exec.ExitError
	if err := g.Wait(); !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Errorf("Wait = %v, want exit status 3", err)
	}
	if !strings.Contains(out.String(), "hello") || !strings.Contains(out.String(), "err") {
		t.Errorf("output = %q, want stdout and stderr", out.String())
	}
	if pgid, _ := syscall.Getpgid(os.Getpid()); pgid == g.Pgid {
		t.Error("the child shares the process group of the test")
	}
	waitUntil(t, "the group to be gone", 3*time.Second, func() bool { return !groupAlive(g.Pgid) })
}

func TestCaffeinated(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("caffeinate is a macOS tool")
	}
	testtool.Need(t, "caffeinate")
	got := caffeinated([]string{"mise", "run", "cell:up"})
	if len(got) != 5 || filepath.Base(got[0]) != "caffeinate" || got[1] != "-i" || got[2] != "mise" || got[4] != "cell:up" {
		t.Errorf("caffeinated = %v, want caffeinate -i then the command", got)
	}
	var out bytes.Buffer
	g, err := StartGroup([]string{"sh", "-c", "echo under-caffeinate"}, os.Environ(), &out)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Wait(); err != nil || !strings.Contains(out.String(), "under-caffeinate") {
		t.Errorf("Wait = %v, output %q", err, out.String())
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestGroupStopKillsTrapper(t *testing.T) {
	testtool.Need(t, "sh", "sleep")
	pidFile := filepath.Join(t.TempDir(), "sleep.pid")
	g, err := StartGroup([]string{"sh", "-c", `trap "" TERM; sleep 600 & echo $! > ` + pidFile + `; wait`}, os.Environ(), discard{})
	if err != nil {
		t.Fatal(err)
	}
	killGroupAtCleanup(t, g)
	sleeper := readPid(t, pidFile)
	g.Stop(300 * time.Millisecond)
	select {
	case <-g.Done():
	case <-time.After(12 * time.Second):
		t.Fatal("the group did not end within 12 s")
	}
	waitUntil(t, "the sleeper to exit", 5*time.Second, func() bool { return pidGone(sleeper) })
	if groupAlive(g.Pgid) {
		t.Error("a member of the group is still alive")
	}
}

func TestWaitKillsChildThatOutlivesLeader(t *testing.T) {
	testtool.Need(t, "sh", "sleep")
	pidFile := filepath.Join(t.TempDir(), "sleep.pid")
	g, err := StartGroup([]string{"sh", "-c", `sleep 600 & echo $! > ` + pidFile}, os.Environ(), discard{})
	if err != nil {
		t.Fatal(err)
	}
	killGroupAtCleanup(t, g)
	sleeper := readPid(t, pidFile)
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the sleeper to be killed when Wait returned", 5*time.Second, func() bool { return pidGone(sleeper) })
}

func TestOpenJournalReapsOrphanGroup(t *testing.T) {
	testtool.Need(t, "sh", "sleep")
	spawn := func(t *testing.T, script string) (<-chan struct{}, int, string) {
		t.Helper()
		cmd := exec.Command("sh", "-c", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		start, err := processStart(cmd.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		// The test is the parent of the leader, so it reaps the leader as soon as it ends: an
		// orphan of a dead host service has no parent that waits.
		waited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(waited) }()
		t.Cleanup(func() {
			if groupAlive(cmd.Process.Pid) {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			<-waited
		})
		return waited, cmd.Process.Pid, start
	}
	journalWith := func(t *testing.T, pgid int, start string) (*Journal, *syncBuf) {
		t.Helper()
		clock := newFakeClock()
		j, err := OpenJournal(t.TempDir(), clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		var logBuf syncBuf
		j.SetLogger(jsonLogger(&logBuf))
		e := testEntry(idN(1), "dev-cell-1", mgmtapi.StepAdmitting, clock.Now())
		e.Pgid, e.LeaderStart = pgid, start
		if err := j.Put(e); err != nil {
			t.Fatal(err)
		}
		return j, &logBuf
	}
	t.Run("leader_alive", func(t *testing.T) {
		waited, pgid, start := spawn(t, "sleep 600")
		j, logs := journalWith(t, pgid, start)
		j.Reap(KillOrphanGroup)
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
			t.Error("the orphan leader is still alive after Reap")
		}
		waitUntil(t, "the orphan group to be gone", 3*time.Second, func() bool { return !groupAlive(pgid) })
		if !strings.Contains(logs.String(), "orphan_reaped") {
			t.Errorf("log = %q, want orphan_reaped", logs.String())
		}
		if e, _ := j.Get(idN(1)); e.Status.State != mgmtapi.StepFailed || e.Status.Detail != "interrupted" {
			t.Errorf("entry = %+v", e.Status)
		}
	})
	t.Run("other_start_time_left_alone", func(t *testing.T) {
		_, pgid, _ := spawn(t, "sleep 600")
		j, logs := journalWith(t, pgid, "1.000000")
		j.Reap(KillOrphanGroup)
		time.Sleep(200 * time.Millisecond)
		if !groupAlive(pgid) {
			t.Fatal("a group whose leader start time differs was killed")
		}
		if strings.Contains(logs.String(), "orphan_reaped") {
			t.Errorf("log = %q, want no orphan_reaped", logs.String())
		}
		if e, _ := j.Get(idN(1)); e.Status.State != mgmtapi.StepFailed || e.Pgid != 0 {
			t.Errorf("entry = %+v pgid %d: the entry must still end failed", e.Status, e.Pgid)
		}
	})
	t.Run("leader_gone_members_live", func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "member.pid")
		waited, pgid, start := spawn(t, "sleep 600 & echo $! > "+pidFile)
		member := readPid(t, pidFile)
		<-waited
		if !groupAlive(pgid) {
			t.Fatal("test setup: the member is gone")
		}
		j, logs := journalWith(t, pgid, start)
		j.Reap(KillOrphanGroup)
		waitUntil(t, "the member to die", 5*time.Second, func() bool { return pidGone(member) })
		if !strings.Contains(logs.String(), "orphan_reaped") {
			t.Errorf("log = %q, want orphan_reaped", logs.String())
		}
	})
	t.Run("group_gone", func(t *testing.T) {
		waited, pgid, start := spawn(t, "exit 0")
		<-waited
		j, logs := journalWith(t, pgid, start)
		j.Reap(KillOrphanGroup)
		if e, _ := j.Get(idN(1)); e.Status.State != mgmtapi.StepFailed {
			t.Errorf("entry = %+v", e.Status)
		}
		if strings.Contains(logs.String(), "orphan_reaped") {
			t.Errorf("log = %q: a group that was already gone was not reaped", logs.String())
		}
	})
	t.Run("closed_entry_ends_final", func(t *testing.T) {
		_, pgid, start := spawn(t, "sleep 600")
		j, _ := journalWith(t, pgid, start)
		if _, _, err := j.Update(idN(1), func(e *JournalEntry) { e.ClosedIn = spec.Revision{Epoch: 1, Counter: 9} }); err != nil {
			t.Fatal(err)
		}
		j.Reap(KillOrphanGroup)
		e, _ := j.Get(idN(1))
		if e.Status.State != mgmtapi.StepFailedFinal || e.Status.Detail != "interrupted" || !e.Final() || !e.Status.RetryAt.IsZero() {
			t.Errorf("entry = %+v, want failed_final with interrupted", e.Status)
		}
	})
	t.Run("kill_error_holds_entry", func(t *testing.T) {
		j, logs := journalWith(t, 4242, "1.000000")
		j.Reap(func(int, string) error { return errors.New("operation not permitted") })
		e, _ := j.Get(idN(1))
		if e.Status.State != mgmtapi.StepAdmitting || e.Pgid != 4242 {
			t.Errorf("entry = %+v pgid %d: a group that may still run must not become retryable", e.Status, e.Pgid)
		}
		if !strings.Contains(logs.String(), "orphan_kill_failed") || strings.Contains(logs.String(), "orphan_reaped") {
			t.Errorf("log = %q", logs.String())
		}
	})
	t.Run("refuses_group_1", func(t *testing.T) {
		if err := KillOrphanGroup(1, "x"); err == nil {
			t.Error("KillOrphanGroup(1) did not refuse")
		}
		if err := KillOrphanGroup(0, "x"); err == nil {
			t.Error("KillOrphanGroup(0) did not refuse")
		}
	})
}
