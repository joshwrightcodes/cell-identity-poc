package mgmt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

func TestFileStoreRefusesUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (&FileStore{Path: filepath.Join(dir, "state.json")}).Load(); err == nil {
		t.Fatal("a directory in place of the state file is accepted")
	}
}

func TestMetrics(t *testing.T) {
	r := newRig(t)
	r.mod = nil
	reader, meter := testMeter()
	r.mod = func(c *Config) { c.Meter = meter }
	r.restart(nil)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusAlreadyBound)
	r.clk.Advance(61e9)
	if _, err := r.plane.KeyCheck(t.Context(), cell1); err != nil {
		t.Fatal(err)
	}
	got := collect(t, reader)
	if got["mgmtd.bind.results/bound"] != 1 || got["mgmtd.bind.results/already_bound"] != 1 || got["mgmtd.keycheck.results/unchanged"] != 1 {
		t.Fatalf("counters %v", got)
	}
	r.plane.Report(mgmtapi.StatusReport{})
	if _, ok := collect(t, reader)["mgmtd.spec.revision.lag/"]; !ok {
		t.Fatal("no lag gauge")
	}
}
