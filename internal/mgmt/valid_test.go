package mgmt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

func TestValidRule(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	ok := ValidInput{
		Requested: true, Bound: true, Record: rev(1, 3), Applied: rev(1, 3), LastStatusAt: now.Add(-time.Second),
		KeysUpdatedAt: now.Add(-time.Hour), LastCheck: string(CheckUnchanged),
	}
	for _, tc := range []struct {
		name   string
		mod    func(*ValidInput)
		valid  bool
		reason string
	}{
		{"valid", func(*ValidInput) {}, true, ""},
		{"valid_applied_above_record", func(in *ValidInput) { in.Applied = rev(1, 9) }, true, ""},
		{"valid_applied_next_epoch", func(in *ValidInput) { in.Applied = rev(2, 1) }, true, ""},
		{"valid_no_check_yet", func(in *ValidInput) { in.LastCheck = "" }, true, ""},
		{"valid_other_checks", func(in *ValidInput) { in.LastCheck = string(CheckRateLimited) }, true, ""},
		{"valid_status_at_the_age_limit", func(in *ValidInput) { in.LastStatusAt = now.Add(-2 * time.Minute) }, true, ""},
		{"valid_status_at_the_skew_limit", func(in *ValidInput) { in.LastStatusAt = now.Add(60 * time.Second) }, true, ""},
		{"valid_status_at_the_rebind", func(in *ValidInput) { in.KeysUpdatedAt = in.LastStatusAt }, true, ""},
		{"not_requested", func(in *ValidInput) { in.Requested = false }, false, mgmtapi.ReasonNotRequested},
		{"not_requested_wins_over_not_bound", func(in *ValidInput) { in.Requested, in.Bound = false, false }, false, mgmtapi.ReasonNotRequested},
		{"not_bound", func(in *ValidInput) { in.Bound = false }, false, mgmtapi.ReasonNotBound},
		{"record_not_applied", func(in *ValidInput) { in.Applied = rev(1, 2) }, false, mgmtapi.ReasonRecordNotApplied},
		{"record_not_applied_epoch", func(in *ValidInput) { in.Applied = rev(0, 9) }, false, mgmtapi.ReasonRecordNotApplied},
		{"record_not_applied_wins_over_no_status", func(in *ValidInput) { in.Applied, in.LastStatusAt = rev(1, 2), time.Time{} }, false, mgmtapi.ReasonRecordNotApplied},
		{"no_status", func(in *ValidInput) { in.LastStatusAt = time.Time{} }, false, mgmtapi.ReasonNoStatus},
		{"status_before_rebind", func(in *ValidInput) { in.KeysUpdatedAt = in.LastStatusAt.Add(time.Nanosecond) }, false, mgmtapi.ReasonNoStatus},
		{"status_stale", func(in *ValidInput) { in.LastStatusAt = now.Add(-2*time.Minute - time.Nanosecond) }, false, mgmtapi.ReasonStatusStale},
		{"status_in_future", func(in *ValidInput) { in.LastStatusAt = now.Add(60*time.Second + time.Nanosecond) }, false, mgmtapi.ReasonStatusInFuture},
		{"keys_untrusted", func(in *ValidInput) { in.LastCheck = string(CheckKeysUntrusted) }, false, mgmtapi.ReasonKeysFailed},
		{"issuer_untrusted", func(in *ValidInput) { in.LastCheck = string(CheckIssuerUntrusted) }, false, mgmtapi.ReasonKeysFailed},
		{"issuer_unavailable", func(in *ValidInput) { in.LastCheck = string(CheckIssuerUnavailable) }, false, mgmtapi.ReasonKeysFailed},
		{"status_stale_wins_over_keys_failed", func(in *ValidInput) {
			in.LastStatusAt, in.LastCheck = now.Add(-time.Hour), string(CheckKeysUntrusted)
		}, false, mgmtapi.ReasonStatusStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := ok
			tc.mod(&in)
			if valid, reason := ValidOf(in, now); valid != tc.valid || reason != tc.reason {
				t.Fatalf("ValidOf = %v, %q; want %v, %q", valid, reason, tc.valid, tc.reason)
			}
		})
	}
}

// validRig returns a rig with cell1 bound, and its record applied.
func validRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	return r
}

var statusSeq uint64

func (r *rig) statusItem(cell string, sig *kubetoken.Signer) mgmtapi.ReportItem {
	statusSeq++
	b := op.Status{Cell: cell, Pod: "celld-0", PodUID: "pod-uid", Seq: statusSeq, At: r.clk.Now()}
	return r.item(cell, "status", b, sig, nil)
}

func (r *rig) valid(cell string) (bool, string) {
	c := cellStatus(r.status(), cell)
	return c.Valid, c.ValidReason
}

func TestValidIgnoresUnprovenStatus(t *testing.T) {
	r := validRig(t)
	if v, why := r.valid(cell1); v || why != mgmtapi.ReasonNoStatus {
		t.Fatalf("before any status: %v %q", v, why)
	}
	// A status whose token another cluster signed is refused, and proves nothing.
	out := r.one(r.statusItem(cell1, newSigner(t, "kid-1")))
	if out.Outcome != mgmtapi.OutcomeRefused {
		t.Fatalf("outcome %+v", out)
	}
	// So is a status of a cell that is not bound, and one for a cell the plane does not serve.
	if out := r.one(r.statusItem(cell2, r.signers[cell2])); out.Outcome != mgmtapi.OutcomeRefused || out.Reason != mgmtapi.ReasonNotBound {
		t.Fatalf("unbound cell: %+v", out)
	}
	if c := cellStatus(r.status(), cell1); !c.LastStatusAt.IsZero() {
		t.Fatalf("lastStatusAt %v from a refused item", c.LastStatusAt)
	}
	if v, why := r.valid(cell1); v || why != mgmtapi.ReasonNoStatus {
		t.Fatalf("after a refused status: %v %q", v, why)
	}
	if out := r.one(r.statusItem(cell1, r.signers[cell1])); out.Outcome != mgmtapi.OutcomeAccepted {
		t.Fatalf("outcome %+v", out)
	}
	if v, why := r.valid(cell1); !v || why != "" {
		t.Fatalf("after a proven status: %v %q", v, why)
	}
	// The status goes stale.
	r.clk.Advance(2*time.Minute + time.Second)
	if v, why := r.valid(cell1); v || why != mgmtapi.ReasonStatusStale {
		t.Fatalf("stale: %v %q", v, why)
	}
}

func TestValidAfterRebind(t *testing.T) {
	r := validRig(t)
	r.one(r.statusItem(cell1, r.signers[cell1]))
	if v, _ := r.valid(cell1); !v {
		t.Fatal("not valid before the rebind")
	}
	n := r.rekey(cell1, "kid-2")
	r.mustBind(cell1, n, mgmtapi.StatusKeysUpdated)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	if v, why := r.valid(cell1); v || why != mgmtapi.ReasonNoStatus {
		t.Fatalf("a status from before the rebind proves the new keys: %v %q", v, why)
	}
	if out := r.one(r.statusItem(cell1, n)); out.Outcome != mgmtapi.OutcomeAccepted {
		t.Fatalf("outcome %+v", out)
	}
	if v, why := r.valid(cell1); !v {
		t.Fatalf("after a new status: %v %q", v, why)
	}
}

func TestValidIgnoresStepStatus(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	id := r.stepOf(cell2).ID
	steps := func(state string) {
		r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last, Steps: []mgmtapi.StepStatus{{ID: id, Cell: cell2, State: state}}})
	}
	for _, state := range []string{mgmtapi.StepDone, mgmtapi.StepFailed, mgmtapi.StepRefused} {
		steps(state)
		if v, why := r.valid(cell2); v || why != mgmtapi.ReasonNotBound {
			t.Fatalf("a %s step made cell2 valid: %v %q", state, v, why)
		}
		if h := cellStatus(r.status(), cell2).Step.Host; h == nil || h.State != state {
			t.Fatalf("host status not shown: %+v", h)
		}
	}
	r.one(r.statusItem(cell1, r.signers[cell1]))
	steps(mgmtapi.StepFailedFinal)
	if v, why := r.valid(cell1); !v {
		t.Fatalf("a failed step of another cell broke cell1: %v %q", v, why)
	}
}

// InvalidSince is the time that a Status call or a gauge tick first observed the cell invalid.
func TestInvalidSinceIsFirstObserved(t *testing.T) {
	r := validRig(t)
	t0 := r.clk.Now()
	if c := cellStatus(r.status(), cell1); !c.InvalidSince.Equal(t0) {
		t.Fatalf("invalidSince %v, want %v", c.InvalidSince, t0)
	}
	r.clk.Advance(30 * time.Second)
	if c := cellStatus(r.status(), cell1); !c.InvalidSince.Equal(t0) {
		t.Fatalf("invalidSince moved to %v", c.InvalidSince)
	}
	r.one(r.statusItem(cell1, r.signers[cell1]))
	if c := cellStatus(r.status(), cell1); !c.Valid || !c.InvalidSince.IsZero() {
		t.Fatalf("valid cell: %+v", c)
	}
	r.clk.Advance(3 * time.Minute)
	t1 := r.clk.Now()
	if c := cellStatus(r.status(), cell1); c.Valid || !c.InvalidSince.Equal(t1) {
		t.Fatalf("invalid again: %+v, want since %v", c, t1)
	}
}

func TestInvalidSinceFromGaugeTick(t *testing.T) {
	reader, meter := testMeter()
	r := newRig(t)
	r.mod = func(c *Config) { c.Meter = meter }
	r.restart(nil)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	t0 := r.clk.Now()
	collect(t, reader) // a tick sees the cell invalid
	r.clk.Advance(time.Minute)
	if c := cellStatus(r.status(), cell1); !c.InvalidSince.Equal(t0) {
		t.Fatalf("invalidSince %v, want the gauge tick %v", c.InvalidSince, t0)
	}
}

func TestValidGauge(t *testing.T) {
	reader, meter := testMeter()
	r := newRig(t)
	r.mod = func(c *Config) { c.Meter = meter }
	r.restart(nil)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.plane.Report(mgmtapi.StatusReport{Applied: r.plane.snap.Load().st.Last})
	r.one(r.statusItem(cell1, r.signers[cell1]))
	if got := collect(t, reader)["mgmtd.cells.valid/"]; got != 1 {
		t.Fatalf("valid cells %d", got)
	}
	r.clk.Advance(5 * time.Minute)
	if got := collect(t, reader)["mgmtd.cells.valid/"]; got != 0 {
		t.Fatalf("valid cells %d after the status went stale", got)
	}
}

func TestStatusShowsRequestAndStep(t *testing.T) {
	r := newBareRig(t)
	if c := cellStatus(r.status(), cell1); c.Requested || c.Step != nil || c.Valid || c.ValidReason != mgmtapi.ReasonNotRequested {
		t.Fatalf("unrequested: %+v", c)
	}
	res := r.request(cell1)
	c := cellStatus(r.status(), cell1)
	ss := r.stepOf(cell1)
	if !c.Requested || c.RequestID != res.RequestID || !c.RequestedAt.Equal(r.clk.Now()) || c.Step == nil ||
		c.Step.ID != ss.ID || !c.Step.IssuedAt.Equal(ss.IssuedAt) || !c.Step.ExpiresAt.Equal(ss.ExpiresAt) || !c.Step.DoneAt.IsZero() {
		t.Fatalf("requested: %+v", c)
	}
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	if c := cellStatus(r.status(), cell1); c.Step == nil || !c.Step.DoneAt.Equal(r.clk.Now()) {
		t.Fatalf("closed: %+v", c.Step)
	}
}

func TestStatusSpecPushState(t *testing.T) {
	r := newBareRig(t)
	if st := r.status(); !st.HostSpecPushedAt.IsZero() || st.HostSpecPushError != "" {
		t.Fatalf("nil func: %+v", st)
	}
	at := r.clk.Now()
	r.mod = func(c *Config) { c.SpecPushState = func() (time.Time, string) { return at, "hostsvc_busy" } }
	r.restart(nil)
	if st := r.status(); !st.HostSpecPushedAt.Equal(at) || st.HostSpecPushError != "hostsvc_busy" {
		t.Fatalf("status %+v", st)
	}
	b, _ := json_(r.status())
	if !contains(b, `"hostSpecPushedAt"`) || !contains(b, `"hostSpecPushError"`) {
		t.Fatalf("%s", b)
	}
	r2 := newBareRig(t)
	if b, _ := json_(r2.status()); contains(b, "hostSpecPush") {
		t.Fatalf("empty fields are shown: %s", b)
	}
}

func TestReportStoresStepStatus(t *testing.T) {
	r := newBareRig(t, cell1, cell2, cell3)
	r.request(cell1, cell2, cell3)
	seq := r.plane.snapshotSeq()
	ids := map[string]string{cell1: r.stepOf(cell1).ID, cell2: r.stepOf(cell2).ID, cell3: r.stepOf(cell3).ID}
	var sts []mgmtapi.StepStatus
	for cell, detail := range map[string]string{cell1: step.DetailTimeout, cell2: step.DetailInterrupted, cell3: step.DetailStageFailed} {
		sts = append(sts, mgmtapi.StepStatus{
			ID: ids[cell], Cell: cell, State: mgmtapi.StepFailed, Stage: mgmtapi.StageAdmitting, Detail: detail,
			NodeIP: "172.18.0.5", Attempts: 2, RequestID: "0123456789abcdef", UpdatedAt: r.clk.Now(),
			LastHostError: &mgmtapi.HostErrorInfo{Reason: mgmtapi.ReasonHostsvcBusy, At: r.clk.Now()},
		})
	}
	r.plane.Report(mgmtapi.StatusReport{Steps: sts})
	for _, s := range sts {
		h := cellStatus(r.status(), s.Cell).Step.Host
		if h == nil || h.Detail != s.Detail || h.State != mgmtapi.StepFailed || h.Attempts != 2 || h.LastHostError == nil {
			t.Fatalf("%s: host %+v", s.Cell, h)
		}
	}
	// A report with no step list keeps what it knows, and a step that left is forgotten.
	r.plane.Report(mgmtapi.StatusReport{})
	if cellStatus(r.status(), cell1).Step.Host == nil {
		t.Fatal("a report without steps cleared the host status")
	}
	if _, err := r.plane.PortalRetry(t.Context(), cell1, testDigest); err != nil {
		t.Fatal(err)
	}
	if h := cellStatus(r.status(), cell1).Step.Host; h != nil {
		t.Fatalf("the host status of the old step shows on the new step: %+v", h)
	}
	r.plane.Report(mgmtapi.StatusReport{})
	if len(r.plane.rep.stepHost) != 2 {
		t.Fatalf("%d statuses kept", len(r.plane.rep.stepHost))
	}
	// The state version does not move with a report.
	if r.plane.snapshotSeq() != seq+1 {
		t.Fatalf("seq %d, want %d", r.plane.snapshotSeq(), seq+1)
	}
}

func TestReportStepStatusKeepsSeq(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	seq, state := r.plane.snapshotSeq(), r.stateBytes()
	for i := range 5 {
		r.plane.Report(mgmtapi.StatusReport{Steps: []mgmtapi.StepStatus{{ID: r.stepOf(cell1).ID, Cell: cell1, State: mgmtapi.StepCreating, Attempts: i % 3}}})
	}
	r.wantNoCommit(seq, "a step report")
	if string(r.stateBytes()) != string(state) {
		t.Fatal("a step report changed the state file")
	}
	if h := cellStatus(r.status(), cell1).Step.Host; h == nil || h.State != mgmtapi.StepCreating {
		t.Fatalf("host %+v", h)
	}
	r.restart(nil)
	if h := cellStatus(r.status(), cell1).Step.Host; h != nil {
		t.Fatalf("host status survived a restart: %+v", h)
	}
}

func TestReportRefusesStepStatusShape(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1, cell2)
	id1, id2 := r.stepOf(cell1).ID, r.stepOf(cell2).ID
	good := func() mgmtapi.StepStatus { return mgmtapi.StepStatus{ID: id1, Cell: cell1, State: mgmtapi.StepQueued} }
	for name, mod := range map[string]func(*mgmtapi.StepStatus){
		"unknown_id":     func(s *mgmtapi.StepStatus) { s.ID = "00000000000000000000000000000000" },
		"other_cell":     func(s *mgmtapi.StepStatus) { s.Cell = cell2 },
		"bad_id_shape":   func(s *mgmtapi.StepStatus) { s.ID = "ABC" },
		"bad_state":      func(s *mgmtapi.StepStatus) { s.State = "exploded" },
		"bad_stage":      func(s *mgmtapi.StepStatus) { s.Stage = "rm -rf /" },
		"stage_done":     func(s *mgmtapi.StepStatus) { s.Stage = "done" },
		"bad_reason":     func(s *mgmtapi.StepStatus) { s.Reason = "free text" },
		"bad_detail":     func(s *mgmtapi.StepStatus) { s.Detail = "\x1b[31mred" },
		"bad_host_error": func(s *mgmtapi.StepStatus) { s.LastHostError = &mgmtapi.HostErrorInfo{Reason: "free text"} },
		"host_error_step": func(s *mgmtapi.StepStatus) {
			s.LastHostError = &mgmtapi.HostErrorInfo{Reason: mgmtapi.ReasonStepInvalid}
		},
		"bad_request_id":    func(s *mgmtapi.StepStatus) { s.RequestID = "short" },
		"bad_node_ip":       func(s *mgmtapi.StepStatus) { s.NodeIP = "::1" },
		"too_many_attempts": func(s *mgmtapi.StepStatus) { s.Attempts = 4 },
	} {
		t.Run(name, func(t *testing.T) {
			s := good()
			mod(&s)
			r.plane.Report(mgmtapi.StatusReport{Steps: []mgmtapi.StepStatus{s}})
			if len(r.plane.rep.stepHost) != 0 {
				t.Fatalf("stored %+v", r.plane.rep.stepHost)
			}
		})
	}
	t.Run("at_most_32", func(t *testing.T) {
		var steps []mgmtapi.StepStatus
		for range 32 {
			steps = append(steps, mgmtapi.StepStatus{ID: "00000000000000000000000000000000", Cell: cell1, State: mgmtapi.StepQueued})
		}
		steps = append(steps, mgmtapi.StepStatus{ID: id2, Cell: cell2, State: mgmtapi.StepQueued})
		r.plane.Report(mgmtapi.StatusReport{Steps: steps})
		if len(r.plane.rep.stepHost) != 0 {
			t.Fatalf("the 33rd entry was stored: %+v", r.plane.rep.stepHost)
		}
		r.plane.Report(mgmtapi.StatusReport{Steps: steps[31:]})
		if len(r.plane.rep.stepHost) != 1 {
			t.Fatal("the 32nd entry was not stored")
		}
	})
}

func json_(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
