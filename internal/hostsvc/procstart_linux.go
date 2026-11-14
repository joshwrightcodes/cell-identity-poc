package hostsvc

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// processStart returns the start time of process pid in clock ticks since boot, from
// /proc/<pid>/stat. It returns errNoProcess when the process does not exist.
func processStart(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return "", errNoProcess
	}
	if err != nil {
		return "", err
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", errors.New("unexpected /proc stat format")
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 20 {
		return "", errors.New("unexpected /proc stat format")
	}
	return fields[19], nil
}
