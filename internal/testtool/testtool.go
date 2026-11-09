// Package testtool lets a test require host tools. Outside CI a missing tool skips the test. Under
// CI=true it fails the test, so a CI run cannot pass with tests that never ran.
package testtool

import (
	"os"
	"os/exec"
)

// TB is the part of testing.TB that Need uses.
type TB interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Need skips or fails the test when a tool is not on PATH.
func Need(t TB, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("CI") == "true" {
				t.Fatalf("%s is not on PATH, and CI=true does not allow a skip", tool)
				return
			}
			t.Skipf("%s is not on PATH; run the test through mise run test", tool)
			return
		}
	}
}
