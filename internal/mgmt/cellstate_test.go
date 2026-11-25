package mgmt

import (
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// stateRig returns a rig over both cells, bound, with a function that reads both metrics from one
// collection. With revoke set, cell2 is revoked in the newest signed spec.
func stateRig(t *testing.T, revoke bool) (*rig, func() (map[string]int64, int64)) {
	t.Helper()
	reader, meter := testMeter()
	r := revokeRig(t, func(c *Config) { c.Meter = meter }, cell1, cell2)
	if revoke {
		r.mustRevoke(cell2, RevokeResult{Cell: cell2, Revision: next(r.status().Signed)})
	}
	return r, func() (map[string]int64, int64) {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(t.Context(), &rm); err != nil {
			t.Fatal(err)
		}
		return cellStatesOf(rm), valueOf(rm, "mgmtd.cells.valid")
	}
}

func wantSeries(t *testing.T, got, want map[string]int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("series %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("series %v, want %v", got, want)
		}
	}
}

// TestCellStateSeries sets valid and revoked one at a time: cell1 is valid and not revoked, cell2 is
// valid and revoked, because ValidOf has no revoked rule.
func TestCellStateSeries(t *testing.T) {
	r, read := stateRig(t, true)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	r.one(r.statusItem(cell1, r.signers[cell1]))
	r.one(r.statusItem(cell2, r.signers[cell2]))
	got, _ := read()
	wantSeries(t, got, map[string]int64{
		cell1 + "/true/false/": 1,
		cell2 + "/true/true/":  1,
	})
}

// TestCellStateReason checks the label against the reason of validOf in each phase.
func TestCellStateReason(t *testing.T) {
	reader, meter := testMeter()
	r := newRig(t, cell1, cell2)
	r.mod = func(c *Config) { c.Meter = meter }
	r.restart(nil)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	read := func() map[string]int64 {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(t.Context(), &rm); err != nil {
			t.Fatal(err)
		}
		return cellStatesOf(rm)
	}
	check := func(phase, want1, want2 string) {
		t.Helper()
		for c, want := range map[string]string{cell1: want1, cell2: want2} {
			if got := cellStatus(r.status(), c).ValidReason; got != want {
				t.Fatalf("%s: validOf reason of %s is %q, want %q", phase, c, got, want)
			}
		}
		wantSeries(t, read(), map[string]int64{
			cell1 + "/false/false/" + want1: 1,
			cell2 + "/false/false/" + want2: 1,
		})
	}
	check("unreported", mgmtapi.ReasonRecordNotApplied, mgmtapi.ReasonNotBound)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	check("no status", mgmtapi.ReasonNoStatus, mgmtapi.ReasonNotBound)
	r.one(r.statusItem(cell1, r.signers[cell1]))
	r.clk.Advance(5 * time.Minute)
	check("stale", mgmtapi.ReasonStatusStale, mgmtapi.ReasonNotBound)
}

func TestCellStateMatchesValid(t *testing.T) {
	r, read := stateRig(t, true)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	r.one(r.statusItem(cell1, r.signers[cell1]))
	r.one(r.statusItem(cell2, r.signers[cell2]))
	states, gauge := read()
	var trues int64
	for k, v := range states {
		if strings.Split(k, "/")[1] == "true" {
			trues += v
		}
	}
	if trues != 2 || gauge != trues {
		t.Fatalf("valid series %d, mgmtd.cells.valid %d, want 2 from one collection", trues, gauge)
	}
}
