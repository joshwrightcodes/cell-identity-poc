//go:build unix

// Package cmdrun runs a command under a time limit and ends the whole process group when the limit passes.
// exec.CommandContext kills only the process that it started. A mise task starts children that keep the
// output pipes open, so Wait would block until the last child ends. The group gets SIGTERM first, so that an
// EXIT trap of a script runs, and SIGKILL after a grace time.
package cmdrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// waitDelay is how long Run waits for the output pipes after it killed the group.
const waitDelay = 5 * time.Second

// termGrace is the time between the SIGTERM and the SIGKILL that the group gets when the limit passes.
var termGrace = 10 * time.Second

var (
	groupsMu sync.Mutex
	groups   = map[int]struct{}{}
	watch    sync.Once
)

func activeGroups() int {
	groupsMu.Lock()
	defer groupsMu.Unlock()
	return len(groups)
}

// forwardSignal sends sig to each process group that Run started and that still runs.
func forwardSignal(sig syscall.Signal) {
	groupsMu.Lock()
	defer groupsMu.Unlock()
	for pgid := range groups {
		_ = syscall.Kill(-pgid, sig)
	}
}

// watchSignals forwards SIGINT and SIGTERM to the running groups, then ends the process by the same signal. A command
// in its own group no longer gets the Ctrl-C of the terminal, so without this a task that Run started would outlive
// the test run.
func watchSignals() {
	watch.Do(func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := (<-ch).(syscall.Signal)
			forwardSignal(sig)
			signal.Reset(sig)
			_ = syscall.Kill(os.Getpid(), sig)
		}()
	})
}

// ErrTimeout is the error of a command that did not end within its limit.
var ErrTimeout = errors.New("the command did not end within its limit")

// Result is what a command wrote and how it ended.
type Result struct {
	Stdout, Stderr string
	// Code is the exit status, or -1 when the command did not run to its end.
	Code int
}

// Run runs name with args in dir. It adds env to the environment of the process. SIGINT and SIGTERM that the process
// gets go to the group of the command first. A command that is still
// running after limit gets SIGTERM for its whole process group, and SIGKILL after termGrace. Run then returns ErrTimeout. A command that
// ends with a non-zero status gives that status in Result and no error. Any other failure is an error.
func Run(limit time.Duration, dir string, env []string, name string, args ...string) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var killTimer *time.Timer
	var timerMu sync.Mutex
	cmd.Cancel = func() error {
		pgid := cmd.Process.Pid
		err := syscall.Kill(-pgid, syscall.SIGTERM)
		timerMu.Lock()
		killTimer = time.AfterFunc(termGrace, func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
		timerMu.Unlock()
		return err
	}
	defer func() {
		timerMu.Lock()
		if killTimer != nil {
			killTimer.Stop()
		}
		timerMu.Unlock()
	}()
	cmd.WaitDelay = termGrace + waitDelay
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	watchSignals()
	err := cmd.Start()
	if err == nil {
		pgid := cmd.Process.Pid
		groupsMu.Lock()
		groups[pgid] = struct{}{}
		groupsMu.Unlock()
		defer func() {
			groupsMu.Lock()
			delete(groups, pgid)
			groupsMu.Unlock()
		}()
		err = cmd.Wait()
	}
	res := Result{Stdout: out.String(), Stderr: errBuf.String(), Code: -1}
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s: %w (%s)", name, ErrTimeout, limit)
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		res.Code = 0
	case errors.As(err, &ee):
		res.Code = ee.ExitCode()
	default:
		return res, err
	}
	return res, nil
}
