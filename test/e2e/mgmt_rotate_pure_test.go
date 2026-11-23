package e2e

// The pure part of the cleanup of TestM3MgmtCARotation. This file has no build tag and imports the standard library only.

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// rotateRefreshExit is the exit status of scripts/mgmt-rotate-ca.sh after a run that only refreshed the copies and prepared no new CA.
const rotateRefreshExit = 3

// rotateRefreshDone reports whether the run of scripts/mgmt-rotate-ca.sh in the resume state finished the refresh. Exit 0 and exit 3
// both finish it.
func rotateRefreshDone(err error) bool {
	if err == nil {
		return true
	}
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == rotateRefreshExit
}

// rotateRefreshLog returns the output of the script with no line that tells the reader to start a rotation. The refresh is finished, and
// the line of exit 3 is addressed to a person who wants a new CA.
func rotateRefreshLog(out string) string {
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.Contains(l, "NO NEW CA") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func TestRotateRefreshLog(t *testing.T) {
	got := rotateRefreshLog("step 4\nstep 5 is finished. NO NEW CA was prepared: run mise run mgmt:rotate-ca again\n")
	if got != "step 4" {
		t.Errorf("got %q", got)
	}
}

func TestRotateRefreshDone(t *testing.T) {
	run := func(code string) error { return exec.Command("bash", "-c", "exit "+code).Run() }
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"exit 0", run("0"), true},
		{"exit 3", run("3"), true},
		{"exit 1", run("1"), false},
		{"exit 2", run("2"), false},
		{"not an exit error", errors.New("start failed"), false},
	} {
		if got := rotateRefreshDone(tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
