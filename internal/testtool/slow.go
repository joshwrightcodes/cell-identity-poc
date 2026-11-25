package testtool

import (
	"fmt"
	"os/exec"
)

// SlowWrapper returns an executable script that stands in for the tool name on PATH. It runs the real tool. When its arguments
// contain match, it prints the output of the tool one line at a time, with a pause of 0.2 s after each line, so a reader that stops
// at its first match closes the pipe before the next write. The script fails when the tool is not on PATH.
func SlowWrapper(name, match string) string {
	real, err := exec.LookPath(name)
	if err != nil {
		return fmt.Sprintf("#!/usr/bin/env bash\necho %q >&2\nexit 127\n", name+" is not on PATH")
	}
	return fmt.Sprintf(`#!/usr/bin/env bash
real=%q
if [[ "$*" == *%q* ]]; then
  out="$("$real" "$@")" || exit
  [[ -z "$out" ]] && exit 0
  while IFS= read -r line; do printf '%%s\n' "$line"; sleep 0.2; done <<<"$out"
  exit 0
fi
exec "$real" "$@"
`, real, match)
}
