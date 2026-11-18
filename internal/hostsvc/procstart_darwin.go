package hostsvc

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// processStart returns the start time of process pid, as "<seconds>.<microseconds>". It returns
// errNoProcess when the process does not exist.
func processStart(pid int) (string, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		// The kernel answers EIO for a pid that does not exist.
		if errors.Is(unix.Kill(pid, 0), unix.ESRCH) {
			return "", errNoProcess
		}
		return "", err
	}
	if int(kp.Proc.P_pid) != pid {
		return "", errNoProcess
	}
	tv := kp.Proc.P_starttime
	return fmt.Sprintf("%d.%06d", tv.Sec, tv.Usec), nil
}
