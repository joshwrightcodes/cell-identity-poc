package scripts

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// sha256Call matches a call of the command sha256, as in `sha256 <file` or `| sha256`. macOS ships /sbin/sha256 and Linux does not, so
// a script that calls it must define the portable function sha256 itself or source lib.sh, which defines it.
var sha256Call = regexp.MustCompile(`(^|[|(]\s*|\$\()sha256(\s|\)|$)`)

var sha256Def = regexp.MustCompile(`(?m)^sha256\(\)\s*\{`)

// sourcesLib matches `source "<path>/lib.sh"` and the form `source "$(dirname "$0")/lib.sh"` of most scripts, whose path holds quotes.
var sourcesLib = regexp.MustCompile(`(?m)source\s+("[^"]*|"\$\(dirname "\$0"\))/?lib\.sh"`)

// TestScriptsHashPortably: every script that calls sha256 gets the portable function, so the call works on Linux as well as on the Mac.
func TestScriptsHashPortably(t *testing.T) {
	t.Parallel()
	lib, err := os.ReadFile("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	libDefines := sha256Def.Match(lib)
	files, err := filepath.Glob("../../scripts/*.sh")
	if err != nil || len(files) == 0 {
		t.Fatalf("no scripts: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		calls := false
		for _, line := range regexp.MustCompile(`\n`).Split(string(b), -1) {
			if !regexp.MustCompile(`^\s*#`).MatchString(line) && sha256Call.MatchString(line) {
				calls = true
				break
			}
		}
		if !calls {
			continue
		}
		if sha256Def.Match(b) || (libDefines && sourcesLib.Match(b)) {
			continue
		}
		t.Errorf("%s calls sha256 but neither defines it nor sources a lib.sh that defines it; Linux has no sha256 command", filepath.Base(f))
	}
}
