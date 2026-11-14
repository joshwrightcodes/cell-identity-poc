package hostsvc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Group is a child process in its own process group, with the identity that lets a later run of
// the host service tell whether a recorded group is still the one that it started.
type Group struct {
	Pgid        int
	LeaderStart string

	cmd  *exec.Cmd
	done chan struct{}
	err  error

	stopOnce sync.Once
}

// caffeinated puts `caffeinate -i` in front of argv, so that the Mac does not sleep while the
// command runs. Where caffeinate is not on PATH, argv stays as it is.
func caffeinated(argv []string) []string {
	if p, err := exec.LookPath("caffeinate"); err == nil {
		return append([]string{p, "-i"}, argv...)
	}
	return argv
}

// StartGroup runs argv in a new process group under `caffeinate -i`, so that the Mac does not
// sleep during a stage. The output of the group goes to log. The caller must call Wait.
func StartGroup(argv, env []string, log io.Writer) (*Group, error) {
	if len(argv) == 0 {
		return nil, errors.New("no command")
	}
	argv = caffeinated(argv)
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = pw, pw
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	_ = pw.Close()
	g := &Group{Pgid: cmd.Process.Pid, cmd: cmd, done: make(chan struct{})}
	start, err := processStart(g.Pgid)
	if err != nil {
		_ = syscall.Kill(-g.Pgid, syscall.SIGKILL)
		_ = cmd.Wait()
		_ = pr.Close()
		return nil, fmt.Errorf("read start time of the leader: %w", err)
	}
	g.LeaderStart = start
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(log, pr)
		_ = pr.Close()
	}()
	go func() {
		g.err = cmd.Wait()
		// A member that ignored SIGTERM, or a child that outlived the leader, dies here.
		_ = syscall.Kill(-g.Pgid, syscall.SIGKILL)
		select {
		case <-copied:
		case <-time.After(2 * time.Second):
			_ = pr.Close()
			<-copied
		}
		close(g.done)
	}()
	return g, nil
}

// Wait blocks until the leader has exited and the output is copied. It returns the exit error.
// Every member of the group has received SIGKILL when Wait returns.
func (g *Group) Wait() error {
	<-g.done
	return g.err
}

// Done returns a channel that closes when Wait would return.
func (g *Group) Done() <-chan struct{} { return g.done }

// Stop sends SIGTERM to the whole group. When the leader is still alive after the given time, it
// sends SIGKILL to the whole group. It returns at once.
func (g *Group) Stop(after time.Duration) {
	g.stopOnce.Do(func() {
		_ = syscall.Kill(-g.Pgid, syscall.SIGTERM)
		go func() {
			t := time.NewTimer(after)
			defer t.Stop()
			select {
			case <-g.done:
			case <-t.C:
				_ = syscall.Kill(-g.Pgid, syscall.SIGKILL)
			}
		}()
	})
}

// groupAlive reports whether any process is left in group pgid.
func groupAlive(pgid int) bool {
	if pgid <= 1 {
		return false
	}
	err := syscall.Kill(-pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// KillOrphanGroup kills the group that a stopped host service left. leaderStart is the start time
// that StartGroup recorded. It returns ErrGroupGone when the group is already gone, and nil only
// after it killed a live group and the group has ended. It returns ErrLeaderChanged,
// and kills nothing, when a live leader has another start time. When the leader has gone but
// members live, the group is still ours, because no new process can take the id of a live group.
func KillOrphanGroup(pgid int, leaderStart string) error {
	if pgid <= 1 {
		return fmt.Errorf("refusing group %d", pgid)
	}
	if !groupAlive(pgid) {
		return ErrGroupGone
	}
	start, err := processStart(pgid)
	switch {
	case err == nil && start != leaderStart:
		return ErrLeaderChanged
	case err != nil && !errors.Is(err, errNoProcess):
		return err
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	for range 60 {
		if !groupAlive(pgid) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("group %d is still alive after SIGKILL", pgid)
}

var errNoProcess = errors.New("no such process")
