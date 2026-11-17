package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// stubKind lists the kind clusters: STUB_KIND (space separated, "none" for no cluster), or the five clusters of the harness.
// STUB_KIND_FAIL makes it fail the way kind does when the container runtime does not answer.
const stubKind = `#!/usr/bin/env bash
[[ "$*" == "get clusters" ]] || exit 2
[[ -z "${STUB_KIND_FAIL:-}" ]] || { echo "failed to list clusters: cannot reach the runtime" >&2; exit 1; }
case "${STUB_KIND:-management dev-cp dev-cell-1 dev-cell-2 rogue}" in
  none) echo "No kind clusters found." >&2 ;;
  *) printf '%s\n' ${STUB_KIND:-management dev-cp dev-cell-1 dev-cell-2 rogue} ;;
esac
`

// stubDocker answers docker inspect for a node container: the address on the network kind, or nothing for the cells in
// STUB_NO_NODE_IP.
const stubDocker = `#!/usr/bin/env bash
[[ "$1" == inspect ]] || exit 2
name="${*: -1}"
cell="${name%-control-plane}"
if [[ " ${STUB_NO_NODE_IP:-} " == *" $cell "* ]]; then echo; exit 0; fi
case "$cell" in
  dev-cell-1) echo 172.18.0.5 ;;
  dev-cell-2) echo 172.18.0.6 ;;
  *) echo 172.18.0.9 ;;
esac
`

// liveStubs are the stubs of kind and docker that every script test needs where a script calls live_cells. A test must never
// reach the real kind or docker.
var liveStubs = map[string]string{"kind": stubKind, "docker": stubDocker}

// writeLiveStubs writes the kind and docker stubs into dir.
func writeLiveStubs(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range liveStubs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// liveCellsRun sources scripts/lib.sh and runs live_cells with the stubs of kind and docker.
func liveCellsRun(t *testing.T, env ...string) (string, string, error) {
	t.Helper()
	testtool.Need(t, "yq", "bash")
	bin := t.TempDir()
	writeLiveStubs(t, bin)
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; live_cells`, "_", lib)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cp",
		"POC_BUILD_ROOT=" + t.TempDir()}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

// TestLiveCells: live_cells prints the topology clusters with the cell-identity set whose kind cluster exists and whose node
// container has an address on the network kind, in topology order.
func TestLiveCells(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want []string
	}{
		{"both cells exist", nil, []string{"dev-cell-1", "dev-cell-2"}},
		{"one cell is absent", []string{"STUB_KIND=management dev-cp rogue dev-cell-2"}, []string{"dev-cell-2"}},
		{"the other cell is absent", []string{"STUB_KIND=management dev-cp rogue dev-cell-1"}, []string{"dev-cell-1"}},
		{"no cell exists", []string{"STUB_KIND=management dev-cp rogue"}, nil},
		{"no cluster exists", []string{"STUB_KIND=none"}, nil},
		{"a cluster with no node address is not live", []string{"STUB_NO_NODE_IP=dev-cell-1"}, []string{"dev-cell-2"}},
		{"a cluster whose name only contains a cell name is no cell", []string{"STUB_KIND=management dev-cp rogue dev-cell-1-old"}, nil},
		{"the order is the topology order", []string{"STUB_KIND=dev-cell-2 dev-cell-1 management"}, []string{"dev-cell-1", "dev-cell-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, err := liveCellsRun(t, tc.env...)
			if err != nil {
				t.Fatalf("live_cells failed: %v\n%s", err, errOut)
			}
			got := strings.Fields(out)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("live cells %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("kind does not answer", func(t *testing.T) {
		out, errOut, err := liveCellsRun(t, "STUB_KIND_FAIL=1")
		if err == nil || out != "" || !strings.Contains(errOut, "kind get clusters failed, so the live cells are unknown") {
			t.Fatalf("err %v, stdout %q, stderr %q; want a failure, never an empty list", err, out, errOut)
		}
	})
}
