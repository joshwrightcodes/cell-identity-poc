// Package cmdrun runs a command under a time limit and ends the whole process group when the limit passes.
// exec.CommandContext kills only the process that it started. A mise task starts children that keep the
// output pipes open, so Wait would block until the last child ends.
package cmdrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// waitDelay is how long Run waits for the output pipes after it killed the group.
const waitDelay = 5 * time.Second

// ErrTimeout is the error of a command that did not end within its limit.
var ErrTimeout = errors.New("the command did not end within its limit")

// Result is what a command wrote and how it ended.
type Result struct {
	Stdout, Stderr string
	// Code is the exit status, or -1 when the command did not run to its end.
	Code int
}

// Run runs name with args in dir. It adds env to the environment of the process. A command that is still
// running after limit gets SIGKILL for its whole process group, and Run returns ErrTimeout. A command that
// ends with a non-zero status gives that status in Result and no error. Any other failure is an error.
func Run(limit time.Duration, dir string, env []string, name string, args ...string) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	err := cmd.Run()
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
