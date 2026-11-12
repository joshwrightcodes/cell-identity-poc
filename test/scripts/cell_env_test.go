package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// TestLibDropsTheSettingsOfAnotherCluster checks that lib.sh takes the cell settings from common.env
// and cells/$CELL.env alone. mgmt:rotate-ca runs cell:up for other clusters from a shell that holds the
// settings of management, and COLLECTOR_STORE of management made each of those clusters render a
// collector that exports to a store that it does not have.
func TestLibDropsTheSettingsOfAnotherCluster(t *testing.T) {
	testtool.Need(t, "yq", "bash")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ cell, want string }{
		{"dev-cell-1", "COLLECTOR_STORE=|VIEW_CELLS=|SPIRE_LOCAL_WORKLOADS=|CELL_NAME=dev-cell-1"},
		{"management", "COLLECTOR_STORE=lgtm.observability-system.svc.cluster.local:4317|VIEW_CELLS=dev-cell-1 dev-cell-2|SPIRE_LOCAL_WORKLOADS=argocd/principal=central-view-system/argocd-agent-principal telemetry=observability-system/telemetry-gateway kiali=mesh-view-system/mesh-view-hub api=mgmt-system/mgmtd|CELL_NAME=management"},
	} {
		t.Run(tc.cell, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `source "$1"; echo "COLLECTOR_STORE=${COLLECTOR_STORE:-}|VIEW_CELLS=${VIEW_CELLS:-}|SPIRE_LOCAL_WORKLOADS=${SPIRE_LOCAL_WORKLOADS:-}|CELL_NAME=$CELL_NAME"`, "_", lib)
			// The outer shell holds the settings of management and of a cluster that does not exist.
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=" + tc.cell,
				"COLLECTOR_STORE=leaked:4317", "VIEW_CELLS=leaked-cell", "SPIRE_LOCAL_WORKLOADS=leaked/path=ns/sa", "CELL_NAME=management"}
			var out, errOut bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errOut
			if err := cmd.Run(); err != nil {
				t.Fatalf("%v\n%s", err, errOut.String())
			}
			if got := strings.TrimSpace(out.String()); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
