package mgmt

import (
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

func TestIfSeqGuardsKeyCheck(t *testing.T) {
	r := newRig(t, cell1, cell2, cell3)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	seq := r.status().Seq
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	calls := r.keys.count(cell1)
	if _, err := r.plane.IfSeq(seq).KeyCheck(t.Context(), cell1); ReasonOf(err) != mgmtapi.ReasonConflict {
		t.Fatalf("check on a stale version: %v", err)
	}
	if r.keys.count(cell1) != calls {
		t.Fatal("a stale check fetched keys")
	}

	// A change that lands while the fetch blocks makes the guarded check fail under the mutex.
	seq = r.status().Seq
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), cell1
	gate := r.keys.gate
	r.keys.mu.Unlock()
	type out struct {
		res CheckResult
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := r.plane.IfSeq(seq).KeyCheck(t.Context(), cell1)
		done <- out{res, err}
	}()
	for r.keys.count(cell1) == calls {
		time.Sleep(time.Millisecond)
	}
	r.mustBind(cell3, r.signers[cell3], mgmtapi.StatusBound)
	close(gate)
	if o := <-done; ReasonOf(o.err) != mgmtapi.ReasonConflict {
		t.Fatalf("check that raced a change: %v, %v", o.res, o.err)
	}
	if res, err := r.plane.IfSeq(r.status().Seq).KeyCheck(t.Context(), cell1); err != nil || res != CheckUnchanged {
		t.Fatalf("check on the current version: %v, %v", res, err)
	}
}
