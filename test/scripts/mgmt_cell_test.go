package scripts

import (
	"strings"
	"testing"
)

// mgmtCellKubectl answers the two calls of mgmt.sh and prints the context of each, so a test sees which cluster the script addressed.
const mgmtCellKubectl = `#!/usr/bin/env bash
echo "kubectl $*" >&2
case " $* " in
  *" get pod mgmtd-0 "*) printf True ;;
  *" exec "*) echo '{"ok":true}' ;;
  *) exit 2 ;;
esac
`

// TestMgmtTargetsManagement: mgmt.sh addresses mgmtd-0 in management, whatever CELL it inherits. scripts/ops.sh exports CELL=dev-cp and calls it.
func TestMgmtTargetsManagement(t *testing.T) {
	t.Parallel()
	for _, cell := range []string{"dev-cp", "dev-cell-1", "management"} {
		_, stderr, code := runScript(t, "mgmt.sh", map[string]string{"kubectl": mgmtCellKubectl}, []string{"CELL=" + cell}, "status")
		if code != 0 || !strings.Contains(stderr, "--context kind-management ") || strings.Contains(stderr, "kind-"+cell+" ") && cell != "management" {
			t.Errorf("CELL=%s: exit %d, calls %q; want every call on kind-management", cell, code, stderr)
		}
	}
}
