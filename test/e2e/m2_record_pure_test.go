package e2e

// The pure rule of the M2 entries test for build/gate/m8-bundles. This file has no build tag and imports the standard library only.

import (
	"strings"
	"testing"
)

// m2RecordAfter returns the content of build/gate/m8-bundles that the entries test leaves. A passing test removes the line of the
// target when the test added it, and keeps every other line. A failed test, or a target that an earlier run listed, keeps the content.
func m2RecordAfter(content, target string, wasListed, passed bool) string {
	if wasListed || !passed {
		return content
	}
	var kept []string
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) != target && line != "" {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "\n") + "\n"
}

func TestM2RecordAfter(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		listed, pass  bool
		want          string
	}{
		{"passed and added by the test", "dev-cp\n", false, true, ""},
		{"passed, other target kept", "dev-cell-1\ndev-cp\n", false, true, "dev-cell-1\n"},
		{"failed keeps the record", "dev-cp\n", false, false, "dev-cp\n"},
		{"already listed before the test", "dev-cp\n", true, true, "dev-cp\n"},
	} {
		if got := m2RecordAfter(tc.content, "dev-cp", tc.listed, tc.pass); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
