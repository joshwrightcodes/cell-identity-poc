package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// publishNoCell runs publish.sh in a signed cluster with CELL unset, as a person who forgot it. The harness default is dev-cell-1.
func publishNoCell(t *testing.T, env ...string) (string, string, error) {
	t.Helper()
	r := newBundleRoot(t, "dev-cell-1")
	for _, name := range []string{"mise", "oras"} {
		if err := os.WriteFile(filepath.Join(r.dir, "bin", name), []byte(publishStubs[name]), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	out, errOut, log, err := r.run("publish.sh", append([]string{"CELL=", `STUB_STATE_JSON={"source":"signed","state":"healthy"}`}, env...))
	return out + errOut, log, err
}

// TestPublishUnsignedNeedsExplicitCell: BUNDLE_PUBLISH_UNSIGNED=1 overwrites a signed root, and lib.sh defaults an unset CELL to dev-cell-1, so the break
// glass without CELL would hit the wrong cluster. The script refuses it before it reads or changes anything, and prints the command with CELL=<cluster>.
// With CELL set it goes on. The refusal of a signed cluster names the same command.
func TestPublishUnsignedNeedsExplicitCell(t *testing.T) {
	out, log, err := publishNoCell(t, "BUNDLE_PUBLISH_UNSIGNED=1")
	if err == nil {
		t.Fatalf("publish.sh passed with no CELL:\n%s\n%s", out, log)
	}
	for _, want := range []string{"CELL=<cluster> BUNDLE_PUBLISH_UNSIGNED=1 mise run cell:publish"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(log, "kubectl") || strings.Contains(log, "bundlectl") || strings.Contains(log, "port-forward") {
		t.Errorf("publish.sh touched a cluster before it refused:\n%s", log)
	}
	out, log, err = publishVariant(t, "dev-cell-1", `STUB_STATE_JSON={"source":"signed","state":"healthy"}`, "BUNDLE_PUBLISH_UNSIGNED=1")
	if err != nil || !strings.Contains(log, "bundlectl -- bootstrap") {
		t.Errorf("with CELL set, the break glass must go on: err %v\n%s\n%s", err, out, log)
	}
	out, _, err = publishNoCell(t)
	if err == nil || !strings.Contains(out, "CELL=dev-cell-1 BUNDLE_PUBLISH_UNSIGNED=1 mise run cell:publish") {
		t.Errorf("the refusal of a signed cluster must name the break glass with CELL: err %v\n%s", err, out)
	}
}
