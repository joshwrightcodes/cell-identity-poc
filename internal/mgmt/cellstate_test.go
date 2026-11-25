package mgmt

import (
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

func stateRig(t *testing.T, revoke bool) (*rig, func() map[string]int64, func() map[string]int64) {
	t.Helper()
	reader, meter := testMeter()
	r := revokeRig(t, func(c *Config) { c.Meter = meter }, cell1, cell2)
	if revoke {
		r.mustRevoke(cell2, RevokeResult{Cell: cell2, Revision: next(r.status().Signed)})
	}
	return r, func() map[string]int64 { return cellStates(t, reader) }, func() map[string]int64 { return collect(t, reader) }
}

func TestCellStateSeries(t *testing.T) {
	r, states, _ := stateRig(t, true)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	r.one(r.statusItem(cell1, r.signers[cell1]))
	want := map[string]int64{
		string(cell1) + "/true/false/":                          1,
		string(cell2) + "/false/true/" + mgmtapi.ReasonNoStatus: 1,
	}
	got := states()
	if len(got) != len(want) {
		t.Fatalf("series %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("series %v, want %v", got, want)
		}
	}
}

func TestCellStateReason(t *testing.T) {
	r, states, _ := stateRig(t, false)
	_ = r
	got := states()
	for _, c := range []string{string(cell1), string(cell2)} {
		if got[c+"/false/false/"+mgmtapi.ReasonNoStatus] != 1 {
			t.Fatalf("series %v lacks %s with reason %s", got, c, mgmtapi.ReasonNoStatus)
		}
	}
}

func TestCellStateMatchesValid(t *testing.T) {
	r, states, all := stateRig(t, true)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	r.one(r.statusItem(cell1, r.signers[cell1]))
	var trues int64
	for k, v := range states() {
		if strings.Split(k, "/")[1] == "true" {
			trues += v
		}
	}
	if gauge := all()["mgmtd.cells.valid/"]; trues != 1 || gauge != trues {
		t.Fatalf("valid series %d, mgmtd.cells.valid %d, want 1", trues, gauge)
	}
}
