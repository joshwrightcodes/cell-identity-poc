package mgmt

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

var testDigest = strings.Repeat("a", 64)

func (r *rig) request(cells ...string) mgmtapi.PortalResult {
	r.t.Helper()
	res, err := r.plane.PortalRequest(r.t.Context(), cells, testDigest)
	if err != nil {
		r.t.Fatalf("PortalRequest(%v): %v", cells, err)
	}
	return res
}

// stepOf returns the state of the step of a cell, or nil.
func (r *rig) stepOf(cell string) *StepState {
	req := r.plane.snap.Load().st.Requests[cell]
	if req == nil {
		return nil
	}
	return req.Step
}

// specSteps returns the step index of the newest signed spec, by cell.
func (r *rig) specSteps() map[string]spec.StepEntry {
	r.t.Helper()
	l := r.plane.snap.Load().st.latest()
	s, _, err := spec.Verify(l.Bundle.Spec, []ed25519.PublicKey{r.plane.PublicKey()})
	if err != nil {
		r.t.Fatalf("spec does not verify: %v", err)
	}
	out := map[string]spec.StepEntry{}
	for _, e := range s.Steps {
		out[e.Name] = e
		env, ok := l.Bundle.Steps[e.Name]
		if !ok {
			r.t.Fatalf("bundle has no step envelope for %s", e.Name)
		}
		body, payload, err := step.Verify(env, []ed25519.PublicKey{r.plane.PublicKey()})
		if err != nil || body.ID != e.StepID || step.PayloadSHA256(payload) != e.StepSHA256 || body.Cell != e.Name {
			r.t.Fatalf("step envelope of %s does not match its index entry %+v: %+v, %v", e.Name, e, body, err)
		}
	}
	if len(l.Bundle.Steps) != len(s.Steps) {
		r.t.Fatalf("bundle holds %d step envelopes, the spec indexes %d", len(l.Bundle.Steps), len(s.Steps))
	}
	return out
}

func (r *rig) wantNoCommit(before uint64, what string) {
	r.t.Helper()
	if got := r.plane.snapshotSeq(); got != before {
		r.t.Fatalf("%s made a commit: seq %d, was %d", what, got, before)
	}
}

func TestLoadIntentCatalog(t *testing.T) {
	in, err := LoadIntent(writeIntent(t, goodIntent))
	if err != nil {
		t.Fatal(err)
	}
	want := step.ClusterRef{PodSubnet: "10.20.0.0/16", ServiceSubnet: "10.21.0.0/16", Issuer: "https://dev-cell-1.test"}
	if len(in.Cells) != 1 || in.Cells[0].Cluster != want {
		t.Fatalf("cells %+v", in.Cells)
	}
	cluster := `"cluster":{"podSubnet":"10.20.0.0/16","serviceSubnet":"10.21.0.0/16","issuer":"https://dev-cell-1.test"}`
	for name, body := range map[string]string{
		"no_cluster":     strings.Replace(goodIntent, `,`+cluster, "", 1),
		"empty_cluster":  strings.Replace(goodIntent, cluster, `"cluster":{}`, 1),
		"bad_subnet":     strings.Replace(goodIntent, "10.20.0.0/16", "10.20.0.0", 1),
		"bad_issuer":     strings.Replace(goodIntent, "https://dev-cell-1.test", "dev-cell-1", 1),
		"unknown_member": strings.Replace(goodIntent, `"issuer"`, `"extra":1,"issuer"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadIntent(writeIntent(t, body)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPortalRequestSignsSteps(t *testing.T) {
	r := newBareRig(t)
	if got := r.specSteps(); len(got) != 0 {
		t.Fatalf("steps before a request: %v", got)
	}
	r.clk.Advance(700 * time.Millisecond)
	res := r.request(cell2, cell1)
	if len(res.Steps) != 2 || len(res.AlreadyRequested) != 0 || res.RequestID == "" || res.Revision != rev(1, 2) {
		t.Fatalf("result %+v", res)
	}
	idx := r.specSteps()
	if len(idx) != 2 {
		t.Fatalf("index %v", idx)
	}
	for _, ps := range res.Steps {
		if idx[ps.Cell].StepID != ps.StepID {
			t.Fatalf("result names %+v, index %+v", ps, idx[ps.Cell])
		}
		body, _, err := step.Verify(r.plane.Spec().Steps[ps.Cell], []ed25519.PublicKey{r.plane.PublicKey()})
		if err != nil {
			t.Fatal(err)
		}
		issued := r.clk.Now().UTC().Truncate(time.Second)
		ic := r.plane.catalog[ps.Cell]
		if body.Env != "dev" || body.Kind != step.KindCellCreate || body.Version != 1 || body.KeyEpoch != 1 ||
			!body.IssuedAt.Equal(issued) || !body.ExpiresAt.Equal(issued.Add(step.DefaultTTL)) ||
			body.Cluster != ic.Cluster || body.BootstrapSHA256 != testDigest || body.IssuedAt.Location() != time.UTC {
			t.Fatalf("step body %+v", body)
		}
		ss := r.stepOf(ps.Cell)
		if ss.ID != ps.StepID || len(ss.KeysAtIssue) != 0 || ss.KeyEpoch != 1 || !ss.DoneAt.IsZero() {
			t.Fatalf("step state %+v", ss)
		}
	}
	if idx[cell1].StepID == idx[cell2].StepID {
		t.Fatal("two cells share a step ID")
	}
	// The request survives a restart, and the next spec keeps the steps.
	r.restart(nil)
	if got := r.specSteps(); len(got) != 2 {
		t.Fatalf("index after restart %v", got)
	}
}

func TestPortalRequestAllOrNothing(t *testing.T) {
	r := newBareRig(t)
	before, spBefore := r.plane.snapshotSeq(), marshal(t, r.plane.Spec())
	if _, err := r.plane.PortalRequest(t.Context(), []string{cell1, "no-such-cell"}, testDigest); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("err %v", err)
	}
	r.wantNoCommit(before, "a refused request")
	if marshal(t, r.plane.Spec()) != spBefore || len(r.plane.snap.Load().st.Requests) != 0 {
		t.Fatal("a refused request changed the plane")
	}
}

func TestPortalRequestRefusals(t *testing.T) {
	nine := []string{}
	for i := range 9 {
		nine = append(nine, fmt.Sprintf("c%d", i))
	}
	eight := nine[:8]
	for name, tc := range map[string]struct {
		cells  []string
		digest string
		reason string
	}{
		"cell_unknown":        {[]string{"nope"}, testDigest, mgmtapi.ReasonCellUnknown},
		"reserved_cell":       {[]string{"management"}, testDigest, mgmtapi.ReasonCellUnknown},
		"digest_short":        {[]string{cell1}, "abc", mgmtapi.ReasonBootstrapInvalid},
		"digest_upper":        {[]string{cell1}, strings.Repeat("A", 64), mgmtapi.ReasonBootstrapInvalid},
		"digest_empty":        {[]string{cell1}, "", mgmtapi.ReasonBootstrapInvalid},
		"too_many_cells":      {nine, testDigest, mgmtapi.ReasonTooManyCells},
		"too_many_cells_dups": {append(slices.Clone(eight), cell1), testDigest, mgmtapi.ReasonTooManyCells},
		"no_cells":            {nil, testDigest, mgmtapi.ReasonPayloadInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			r := newBareRig(t)
			before := r.plane.snapshotSeq()
			if _, err := r.plane.PortalRequest(t.Context(), tc.cells, tc.digest); ReasonOf(err) != tc.reason {
				t.Fatalf("err %v, want %s", err, tc.reason)
			}
			r.wantNoCommit(before, "a refused request")
		})
	}
	t.Run("eight_cells_pass_the_count", func(t *testing.T) {
		names := []string{}
		for i := range 8 {
			names = append(names, fmt.Sprintf("dev-cell-%d", i+1))
		}
		r := newBareRig(t, names...)
		if res := r.request(names...); len(res.Steps) != 8 {
			t.Fatalf("%+v", res)
		}
	})
}

func TestPortalRequestAlreadyRequested(t *testing.T) {
	r := newBareRig(t)
	first := r.request(cell1, cell2)
	before, spBefore := r.plane.snapshotSeq(), marshal(t, r.plane.Spec())
	res := r.request(cell1, cell2)
	if len(res.Steps) != 0 || !slices.Equal(res.AlreadyRequested, []string{cell1, cell2}) {
		t.Fatalf("result %+v", res)
	}
	r.wantNoCommit(before, "a request for requested cells")
	if marshal(t, r.plane.Spec()) != spBefore {
		t.Fatal("the spec changed")
	}
	if b, err := json.Marshal(res); err != nil || !strings.Contains(string(b), `"steps":[]`) {
		t.Fatalf("%s %v", b, err)
	}

	r = newBareRig(t, cell1, cell2, cell3)
	r.request(cell1)
	old := r.stepOf(cell1).ID
	res = r.request(cell1, cell3)
	if len(res.Steps) != 1 || res.Steps[0].Cell != cell3 || !slices.Equal(res.AlreadyRequested, []string{cell1}) {
		t.Fatalf("result %+v", res)
	}
	if r.stepOf(cell1).ID != old {
		t.Fatal("a requested cell got a new step")
	}
	_ = first
}

func TestPendingCellCanBind(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
}

func TestUnrequestedCellCannotBind(t *testing.T) {
	r := newBareRig(t)
	if _, err := r.plane.Nonce(cell1); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("nonce: %v", err)
	}
	n := r.nonce2(cell1)
	_, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: r.token(cell1, n, r.signers[cell1], nil)})
	if ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("bind: %v", err)
	}
	if r.keys.count(cell1) != 0 {
		t.Fatal("a refused bind fetched keys")
	}
}

// nonce2 issues a nonce for a cell that the plane does not serve one for, from the nonce source.
func (r *rig) nonce2(cell string) string {
	n, _ := r.plane.nonces.Issue(cell)
	return n
}

// rekey makes the cell publish a new key set that holds a key of kid, and returns its signer.
func (r *rig) rekey(cell, kid string) *kubetoken.Signer {
	s := newSigner(r.t, kid)
	r.keys.set(cell, r.keys.issuer(cell), r.signers[cell], s)
	r.clk.Advance(61 * time.Second)
	return s
}

func TestRecreateBoundCell(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	if s := r.stepOf(cell1); s.DoneAt.IsZero() {
		t.Fatal("the first bind did not close the step")
	}
	if got := r.specSteps(); len(got) != 0 {
		t.Fatalf("a closed step is still indexed: %v", got)
	}
	res, err := r.plane.PortalRecreate(t.Context(), cell1, testDigest)
	if err != nil || len(res.Steps) != 1 {
		t.Fatalf("recreate: %+v %v", res, err)
	}
	ss := r.stepOf(cell1)
	if ss.ID != res.Steps[0].StepID || !ss.open() || len(ss.KeysAtIssue) != 1 || !strings.HasPrefix(ss.KeysAtIssue[0], "kid-1:") {
		t.Fatalf("step %+v", ss)
	}
	if got := r.specSteps(); got[cell1].StepID != ss.ID {
		t.Fatalf("index %v", got)
	}
	// The recreated cluster has new keys. Its bind updates the keys and closes the step.
	n := r.rekey(cell1, "kid-2")
	r.keys.set(cell1, r.keys.issuer(cell1), n)
	r.mustBind(cell1, n, mgmtapi.StatusKeysUpdated)
	if !r.stepOf(cell1).DoneAt.Equal(r.clk.Now()) || len(r.specSteps()) != 0 {
		t.Fatalf("step %+v, index %v", r.stepOf(cell1), r.specSteps())
	}
	// A cell that is not requested, and a step that is still open, are refused.
	r2 := newBareRig(t)
	if _, err := r2.plane.PortalRecreate(t.Context(), cell1, testDigest); ReasonOf(err) != mgmtapi.ReasonNotRequested {
		t.Fatalf("not requested: %v", err)
	}
	r2.request(cell1)
	if _, err := r2.plane.PortalRecreate(t.Context(), cell1, testDigest); ReasonOf(err) != mgmtapi.ReasonStepOpen {
		t.Fatalf("step open: %v", err)
	}
	if _, err := r2.plane.PortalRecreate(t.Context(), cell1, "bad"); ReasonOf(err) != mgmtapi.ReasonBootstrapInvalid {
		t.Fatalf("digest: %v", err)
	}
	if _, err := r2.plane.PortalRecreate(t.Context(), "nope", testDigest); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("unknown: %v", err)
	}
}

func TestAlreadyBoundDoesNotCloseStep(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	if _, err := r.plane.PortalRecreate(t.Context(), cell1, testDigest); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(5 * time.Second)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusAlreadyBound)
	if s := r.stepOf(cell1); !s.open() {
		t.Fatalf("already_bound closed the step: %+v", s)
	}
	if len(r.specSteps()) != 1 {
		t.Fatal("the step left the spec")
	}
}

func TestBindOfOtherCellKeepsStep(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1, cell2)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	if !r.stepOf(cell1).open() || r.stepOf(cell2).open() {
		t.Fatalf("steps: %+v %+v", r.stepOf(cell1), r.stepOf(cell2))
	}
	if got := r.specSteps(); len(got) != 1 || got[cell1].StepID != r.stepOf(cell1).ID {
		t.Fatalf("index %v", got)
	}
}

func TestBindBeforeIssuedAtKeepsStep(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	n := r.nonce(cell1)
	tok := r.token(cell1, n, r.signers[cell1], func(c *kubetoken.Claims) { c.IssuedAt = r.clk.Now().Add(-10 * time.Second) })
	if resp, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: tok}); err != nil || resp.Status != mgmtapi.StatusBound {
		t.Fatalf("bind: %+v %v", resp, err)
	}
	if !r.stepOf(cell1).open() {
		t.Fatal("a token minted before the step closed it")
	}
	// The same cell with a token minted after the step closes it, through a new key.
	n2 := r.rekey(cell1, "kid-2")
	r.mustBind(cell1, n2, mgmtapi.StatusKeysUpdated)
	if !r.stepOf(cell1).DoneAt.Equal(r.clk.Now()) {
		t.Fatal("a later bind with new keys did not close the step")
	}
}

func TestBindSameSecondClosesStep(t *testing.T) {
	r := newBareRig(t)
	r.clk.Advance(500 * time.Millisecond)
	r.request(cell1)
	if r.stepOf(cell1).IssuedAt.Nanosecond() != 0 {
		t.Fatalf("issuedAt %v is not whole seconds", r.stepOf(cell1).IssuedAt)
	}
	n := r.nonce(cell1)
	iat := r.clk.Now().Truncate(time.Second)
	tok := r.token(cell1, n, r.signers[cell1], func(c *kubetoken.Claims) { c.IssuedAt = iat })
	if resp, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: tok}); err != nil || resp.Status != mgmtapi.StatusBound {
		t.Fatalf("bind: %+v %v", resp, err)
	}
	if r.stepOf(cell1).open() {
		t.Fatal("a token of the same second did not close the step")
	}
}

func TestBindSameKeysKeepsStep(t *testing.T) {
	issued := time.Unix(1_700_000_000, 0).UTC()
	s := &StepState{IssuedAt: issued, KeysAtIssue: []string{"kid-1:aaa", "kid-2:bbb"}}
	for name, tc := range map[string]struct {
		iat    time.Time
		proved []string
		want   bool
	}{
		"same_keys":        {issued, []string{"kid-1:aaa", "kid-2:bbb"}, false},
		"other_keys":       {issued, []string{"kid-1:aaa", "kid-3:ccc"}, true},
		"added_key":        {issued, []string{"kid-1:aaa", "kid-2:bbb", "kid-3:ccc"}, true},
		"same_kid_new_key": {issued, []string{"kid-1:aaa", "kid-2:zzz"}, true},
		"before_issued":    {issued.Add(-time.Second), []string{"kid-9:x"}, false},
		"after_issued":     {issued.Add(time.Hour), []string{"kid-9:x"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := stepCloses(s, tc.iat, tc.proved); got != tc.want {
				t.Fatalf("stepCloses = %v", got)
			}
		})
	}
	done := *s
	done.DoneAt = issued
	if stepCloses(&done, issued, []string{"kid-9:x"}) || stepCloses(nil, issued, nil) {
		t.Fatal("a closed or absent step closes")
	}
}

func TestBindThroughReportClosesStep(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	n := r.nonce(cell1)
	out := r.one(r.bindItem2(cell1, n))
	if out.Outcome != mgmtapi.OutcomeAccepted || out.Bind == nil || out.Bind.Status != mgmtapi.StatusBound {
		t.Fatalf("outcome %+v", out)
	}
	if r.stepOf(cell1).open() {
		t.Fatal("a bind item did not close the step")
	}
}

func (r *rig) bindItem2(cell, nonce string) mgmtapi.ReportItem {
	body := mgmtapi.BindRequest{Nonce: nonce, Token: r.token(cell, nonce, r.signers[cell], nil)}
	return mgmtapi.ReportItem{ID: "bind-1", Cell: cell, Kind: kindBind, Body: json.RawMessage(marshal(r.t, body))}
}

func (r *rig) hostStatus(cell, id, state string) mgmtapi.StepStatus {
	return mgmtapi.StepStatus{ID: id, Cell: cell, State: state, UpdatedAt: r.clk.Now()}
}

func TestRetryRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(r *rig, s *StepState)
	}{
		{"refused", func(r *rig, s *StepState) {
			st := r.hostStatus(cell1, s.ID, mgmtapi.StepRefused)
			st.Reason, st.Detail = mgmtapi.ReasonStepInvalid, step.DetailBootstrapMismatch
			r.plane.Report(mgmtapi.StatusReport{Steps: []mgmtapi.StepStatus{st}})
		}},
		{"failed", func(r *rig, s *StepState) {
			r.plane.Report(mgmtapi.StatusReport{Steps: []mgmtapi.StepStatus{r.hostStatus(cell1, s.ID, mgmtapi.StepFailed)}})
		}},
		{"failed_final", func(r *rig, s *StepState) {
			r.plane.Report(mgmtapi.StatusReport{Steps: []mgmtapi.StepStatus{r.hostStatus(cell1, s.ID, mgmtapi.StepFailedFinal)}})
		}},
		{"expired", func(r *rig, s *StepState) { r.clk.Advance(step.DefaultTTL + time.Minute) }},
		{"queued_unknown", func(r *rig, s *StepState) {}},
		{"running", func(r *rig, s *StepState) {
			r.plane.Report(mgmtapi.StatusReport{Steps: []mgmtapi.StepStatus{r.hostStatus(cell1, s.ID, mgmtapi.StepBootstrapping)}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newBareRig(t)
			r.request(cell1)
			old := *r.stepOf(cell1)
			tc.prep(r, &old)
			res, err := r.plane.PortalRetry(t.Context(), cell1, strings.Repeat("b", 64))
			if err != nil || len(res.Steps) != 1 {
				t.Fatalf("retry: %+v %v", res, err)
			}
			ns := r.stepOf(cell1)
			if ns.ID == old.ID || res.Steps[0].StepID != ns.ID || !ns.open() {
				t.Fatalf("new step %+v, old %s", ns, old.ID)
			}
			idx := r.specSteps()
			if len(idx) != 1 || idx[cell1].StepID != ns.ID {
				t.Fatalf("index %v still names the old step %s", idx, old.ID)
			}
			body, _, _ := step.Verify(r.plane.Spec().Steps[cell1], []ed25519.PublicKey{r.plane.PublicKey()})
			if body.BootstrapSHA256 != strings.Repeat("b", 64) {
				t.Fatalf("digest %s", body.BootstrapSHA256)
			}
			if c := cellStatus(r.status(), cell1); c.Step == nil || c.Step.ID != ns.ID || c.Step.Host != nil {
				t.Fatalf("status step %+v", c.Step)
			}
		})
	}
	t.Run("none", func(t *testing.T) {
		r := newBareRig(t)
		if _, err := r.plane.PortalRetry(t.Context(), cell1, testDigest); ReasonOf(err) != mgmtapi.ReasonNoStep {
			t.Fatalf("not requested: %v", err)
		}
		r.request(cell1)
		r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
		before := r.plane.snapshotSeq()
		if _, err := r.plane.PortalRetry(t.Context(), cell1, testDigest); ReasonOf(err) != mgmtapi.ReasonNoStep {
			t.Fatalf("closed step: %v", err)
		}
		r.wantNoCommit(before, "a refused retry")
		if _, err := r.plane.PortalRetry(t.Context(), "nope", testDigest); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
			t.Fatalf("unknown: %v", err)
		}
	})
}

func TestCancelDropsStep(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1, cell2)
	if _, err := r.plane.PortalCancel(t.Context(), cell1); err != nil {
		t.Fatal(err)
	}
	idx := r.specSteps()
	if len(idx) != 1 || idx[cell2].StepID == "" {
		t.Fatalf("index %v", idx)
	}
	if r.plane.snap.Load().st.Requests[cell1] == nil {
		t.Fatal("cancel removed the request")
	}
	before := r.plane.snapshotSeq()
	if _, err := r.plane.PortalCancel(t.Context(), cell1); ReasonOf(err) != mgmtapi.ReasonNoStep {
		t.Fatalf("second cancel: %v", err)
	}
	r.wantNoCommit(before, "a refused cancel")
	if _, err := r.plane.PortalCancel(t.Context(), "nope"); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("unknown: %v", err)
	}
	// A recreate after a cancel gives the cell a step again.
	if _, err := r.plane.PortalRecreate(t.Context(), cell1, testDigest); err != nil {
		t.Fatal(err)
	}
	if len(r.specSteps()) != 2 {
		t.Fatal("no step after the recreate")
	}
}

func TestWithdrawPendingCell(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1, cell2)
	res, err := r.plane.PortalWithdraw(t.Context(), []string{cell1})
	if err != nil || res.Revision != rev(1, 3) {
		t.Fatalf("withdraw: %+v %v", res, err)
	}
	if idx := r.specSteps(); len(idx) != 1 || idx[cell2].StepID == "" {
		t.Fatalf("index %v", idx)
	}
	if c := cellStatus(r.status(), cell1); c.Requested || c.Valid || c.ValidReason != mgmtapi.ReasonNotRequested || c.Step != nil {
		t.Fatalf("status %+v", c)
	}
	if _, err := r.plane.Nonce(cell1); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("nonce after withdraw: %v", err)
	}
	r.restart(nil)
	if r.plane.snap.Load().st.Requests[cell1] != nil {
		t.Fatal("the request came back after a restart")
	}
}

func TestWithdrawBoundCellsStaged(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	if _, err := r.plane.PortalRecreate(t.Context(), cell1, testDigest); err != nil {
		t.Fatal(err)
	}
	if len(r.specSteps()) != 1 {
		t.Fatal("no open step")
	}
	res, err := r.plane.PortalWithdraw(t.Context(), []string{cell1, cell2})
	if err != nil {
		t.Fatal(err)
	}
	if idx := r.specSteps(); len(idx) != 0 {
		t.Fatalf("the first commit still indexes a step: %v", idx)
	}
	s := r.verifySpec()
	if len(s.Cells) != 2 || len(s.Retired) != 0 || !slices.Equal(r.status().PendingDrops, []string{cell1, cell2}) {
		t.Fatalf("spec %+v, drops %v", s, r.status().PendingDrops)
	}
	// Each drop waits for envd to apply the revision before it.
	r.plane.Report(mgmtapi.StatusReport{Applied: res.Revision})
	if s := r.verifySpec(); len(s.Cells) != 1 || len(s.Retired) != 1 {
		t.Fatalf("after the first drop: %+v", s)
	}
}

func TestWithdrawTwice(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	if _, err := r.plane.PortalWithdraw(t.Context(), []string{cell1}); err != nil {
		t.Fatal(err)
	}
	before := r.plane.snapshotSeq()
	res, err := r.plane.PortalWithdraw(t.Context(), []string{cell1, cell2})
	if err != nil || len(res.Steps) != 0 {
		t.Fatalf("second withdraw: %+v %v", res, err)
	}
	r.wantNoCommit(before, "a withdraw of cells that are not requested")
	for name, tc := range map[string]struct {
		cells  []string
		reason string
	}{
		"unknown":  {[]string{"nope"}, mgmtapi.ReasonCellUnknown},
		"too_many": {[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, mgmtapi.ReasonTooManyCells},
	} {
		if _, err := r.plane.PortalWithdraw(t.Context(), tc.cells); ReasonOf(err) != tc.reason {
			t.Fatalf("%s: %v", name, err)
		}
	}
	r.wantNoCommit(before, "a refused withdraw")
}

func TestStateMigratesIntent(t *testing.T) {
	r := newRig(t, cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.plane.Wait()
	// A state that M5 saved has no requests field.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(r.stateBytes(), &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "requests")
	b, _ := json.Marshal(raw)
	if err := os.WriteFile(r.dir+"/state.json", b, 0o600); err != nil {
		t.Fatal(err)
	}
	r.restart(nil)
	st := r.plane.snap.Load().st
	if q := st.Requests[cell1]; q == nil || q.RequestID != "migrated" || q.Step != nil {
		t.Fatalf("bound cell: %+v", q)
	}
	if st.Requests[cell2] != nil {
		t.Fatal("a cell that never bound became a request")
	}
	if c := cellStatus(r.status(), cell1); !c.Requested || c.RequestID != "migrated" {
		t.Fatalf("status %+v", c)
	}
	if _, err := r.plane.Nonce(cell1); err != nil {
		t.Fatal(err)
	}
}

func TestStateMigratesIntentOnce(t *testing.T) {
	r := newRig(t, cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	if _, err := r.plane.PortalWithdraw(t.Context(), []string{cell1}); err != nil {
		t.Fatal(err)
	}
	if st := r.plane.snap.Load().st; st.Cells[cell1] == nil || len(st.Requests) != 1 {
		t.Fatal("setup: the withdrawn cell must stay in the state until its drop")
	}
	r.restart(nil)
	if r.plane.snap.Load().st.Requests[cell1] != nil {
		t.Fatal("a restart requested the withdrawn cell again")
	}
	// An empty requests map, as a state with no request writes it, does not migrate either.
	r2 := newBareRig(t)
	r2.mustBind2(t, cell1)
}

func (r *rig) mustBind2(t *testing.T, cell string) {
	t.Helper()
	r.request(cell)
	r.mustBind(cell, r.signers[cell], mgmtapi.StatusBound)
	if _, err := r.plane.PortalWithdraw(t.Context(), []string{cell}); err != nil {
		t.Fatal(err)
	}
	r.restart(nil)
	if r.plane.snap.Load().st.Requests[cell] != nil {
		t.Fatal("migrated twice")
	}
}

func TestCatalogDropWithdraws(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.restart(func(in *Intent) { in.Cells = in.Cells[:1] })
	if idx := r.specSteps(); len(idx) != 0 {
		t.Fatalf("the step of a cell that left the catalog is still indexed: %v", idx)
	}
	if c := cellStatus(r.status(), cell2); c.Requested || c.Step != nil {
		t.Fatalf("status %+v", c)
	}
	if _, err := r.plane.Nonce(cell2); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("nonce: %v", err)
	}
	if _, err := r.plane.PortalRequest(t.Context(), []string{cell2}, testDigest); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("request: %v", err)
	}
	if st := r.plane.snap.Load().st; st.Requests[cell2] != nil || st.Requests[cell1] == nil {
		t.Fatalf("requests after the drop: %v", st.Requests)
	}
	if _, err := r.plane.PortalWithdraw(t.Context(), []string{cell2}); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("withdraw of a cell outside the catalog: %v", err)
	}
}

func TestCatalogReAddSignsNoStep(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1, cell2)
	r.restart(func(in *Intent) { in.Cells = in.Cells[:1] })
	r.restart(func(in *Intent) { *in = testIntent(cell1, cell2) })
	if r.plane.snap.Load().st.Requests[cell2] != nil || len(r.specSteps()) != 1 {
		t.Fatalf("the re-added cell is requested again: %v, index %v", r.plane.snap.Load().st.Requests, r.specSteps())
	}
	if _, err := r.plane.Nonce(cell2); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("nonce: %v", err)
	}
	if c := cellStatus(r.status(), cell2); c.Requested || c.Step != nil || c.ValidReason != mgmtapi.ReasonNotRequested {
		t.Fatalf("status %+v", c)
	}
	if res := r.request(cell2); len(res.Steps) != 1 {
		t.Fatalf("a new request: %+v", res)
	}
}

func TestKeyCheckRechecksTheIntent(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.rekey(cell1, "kid-2")
	r.keys.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := r.plane.KeyCheck(t.Context(), cell1)
		done <- err
	}()
	for r.keys.count(cell1) < 2 {
		time.Sleep(time.Millisecond)
	}
	if _, err := r.plane.PortalWithdraw(t.Context(), []string{cell1}); err != nil {
		t.Fatal(err)
	}
	close(r.keys.gate)
	if err := <-done; ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("a key check that read the old intent: %v", err)
	}
	if c := r.plane.snap.Load().st.Cells[cell1]; strings.Contains(string(c.JWKS), "kid-2") {
		t.Fatal("the key check changed the record of a withdrawn cell")
	}
}

func TestRotateKeyResignsOpenSteps(t *testing.T) {
	for name, rotate := range map[string]func(r *rig) error{
		"rotate": func(r *rig) error { _, err := r.plane.RotateKey(t.Context()); return err },
		"commit_staged": func(r *rig) error {
			if _, err := r.plane.StageKey(t.Context()); err != nil {
				return err
			}
			_, err := r.plane.CommitStagedKey(t.Context())
			return err
		},
		"emergency": func(r *rig) error { _, err := r.plane.RotateKeyEmergency(t.Context()); return err },
	} {
		t.Run(name, func(t *testing.T) {
			r := newBareRig(t, cell1, cell2, cell3)
			r.request(cell1, cell2, cell3)
			r.mustBind(cell3, r.signers[cell3], mgmtapi.StatusBound) // closes the step of cell3
			r.clk.Advance(step.DefaultTTL + time.Hour)               // both open steps are expired
			before := map[string]spec.StepEntry{}
			maps := r.specSteps()
			for k, v := range maps {
				before[k] = v
			}
			old := map[string]step.Step{}
			for cell := range before {
				b, _, err := step.Verify(r.plane.Spec().Steps[cell], []ed25519.PublicKey{r.plane.PublicKey()})
				if err != nil {
					t.Fatal(err)
				}
				old[cell] = b
			}
			if len(before) != 2 {
				t.Fatalf("setup: %v", before)
			}
			oldPub := r.plane.PublicKey()
			if err := rotate(r); err != nil {
				t.Fatal(err)
			}
			after := r.specSteps()
			if len(after) != 2 {
				t.Fatalf("index after the rotation: %v", after)
			}
			for cell, was := range before {
				now := after[cell]
				if now.StepID != was.StepID || now.StepSHA256 == was.StepSHA256 {
					t.Fatalf("%s: before %+v, after %+v", cell, was, now)
				}
				env := r.plane.Spec().Steps[cell]
				if _, _, err := step.Verify(env, []ed25519.PublicKey{oldPub}); err == nil {
					t.Fatal("the step still verifies under the old key")
				}
				b, _, err := step.Verify(env, []ed25519.PublicKey{r.plane.PublicKey()})
				if err != nil {
					t.Fatal(err)
				}
				if b.KeyEpoch != 2 || !step.SameExceptEpoch(b, old[cell]) {
					t.Fatalf("%s: step %+v, was %+v", cell, b, old[cell])
				}
				ss := r.stepOf(cell)
				if ss.KeyEpoch != 2 || ss.PayloadSHA256 != now.StepSHA256 || !ss.IssuedAt.Equal(old[cell].IssuedAt) || !ss.ExpiresAt.Equal(old[cell].ExpiresAt) {
					t.Fatalf("%s: state %+v", cell, ss)
				}
			}
			if _, ok := after[cell3]; ok {
				t.Fatal("a closed step was indexed")
			}
		})
	}
}

func TestSignStepNotServed(t *testing.T) {
	r := newBareRig(t)
	before, spBefore := r.plane.snapshotSeq(), marshal(t, r.plane.Spec())
	body := step.Step{
		Env: "dev", Cell: cell1, Kind: step.KindCellCreate, Version: 1, IssuedAt: r.clk.Now(),
		ExpiresAt: r.clk.Now().Add(time.Hour), Cluster: testCluster(cell1), BootstrapSHA256: step.TestDigest,
	}
	env, err := r.plane.SignStep(t.Context(), body)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := step.Verify(env, []ed25519.PublicKey{r.plane.PublicKey()})
	if err != nil || got.ID == "" || got.KeyEpoch != 1 {
		t.Fatalf("step %+v %v", got, err)
	}
	r.wantNoCommit(before, "SignStep")
	if marshal(t, r.plane.Spec()) != spBefore || len(r.specSteps()) != 0 || len(r.plane.snap.Load().st.Requests) != 0 {
		t.Fatal("SignStep recorded or served the step")
	}
	body.ID = strings.Repeat("c", 32)
	env, err = r.plane.SignStep(t.Context(), body)
	if got, _, _ := step.Verify(env, []ed25519.PublicKey{r.plane.PublicKey()}); err != nil || got.ID != body.ID {
		t.Fatalf("a given ID is kept: %+v %v", got, err)
	}
}

func TestSignStepTestDigestOnly(t *testing.T) {
	r := newBareRig(t)
	body := step.Step{
		Env: "dev", Cell: cell1, Kind: step.KindCellCreate, Version: 1, IssuedAt: r.clk.Now(),
		ExpiresAt: r.clk.Now().Add(time.Hour), Cluster: testCluster(cell1), BootstrapSHA256: testDigest,
	}
	if _, err := r.plane.SignStep(t.Context(), body); ReasonOf(err) != mgmtapi.ReasonTestDigestOnly {
		t.Fatalf("err %v", err)
	}
	body.BootstrapSHA256 = ""
	if _, err := r.plane.SignStep(t.Context(), body); ReasonOf(err) != mgmtapi.ReasonTestDigestOnly {
		t.Fatalf("empty digest: %v", err)
	}
}

func TestOnSpecAfterCommit(t *testing.T) {
	var calls [][]byte
	r := newBareRig(t)
	r.mod = func(c *Config) { c.OnSpec = func(e []byte) { calls = append(calls, e) } }
	r.restart(nil)
	if len(calls) != 1 || string(calls[0]) != string(r.plane.snap.Load().st.latest().Bundle.Spec) {
		t.Fatalf("after NewPlane: %d calls", len(calls))
	}
	last := func() string { return string(calls[len(calls)-1]) }
	newest := func() string { return string(r.plane.snap.Load().st.latest().Bundle.Spec) }

	t.Run("commit_that_adds_only_a_step", func(t *testing.T) {
		n := len(calls)
		r.request(cell1)
		if len(calls) != n+1 || last() != newest() {
			t.Fatalf("%d calls, want %d", len(calls), n+1)
		}
		n = len(calls)
		r.request(cell1) // already requested: no commit, no call
		if len(calls) != n {
			t.Fatal("a call without a commit")
		}
	})
	t.Run("restore", func(t *testing.T) {
		r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
		if err := r.plane.Restore(1); err != nil {
			t.Fatal(err)
		}
		n := len(calls)
		if _, err := r.plane.PortalRequest(t.Context(), []string{cell2}, testDigest); ReasonOf(err) != mgmtapi.ReasonRestoreActive {
			t.Fatalf("request: %v", err)
		}
		if _, err := r.plane.PortalWithdraw(t.Context(), []string{cell1}); ReasonOf(err) != mgmtapi.ReasonRestoreActive {
			t.Fatalf("withdraw: %v", err)
		}
		if _, err := r.plane.PortalRecreate(t.Context(), cell1, testDigest); ReasonOf(err) != mgmtapi.ReasonRestoreActive {
			t.Fatalf("recreate: %v", err)
		}
		body := step.Step{Env: "dev", Cell: cell1, Kind: step.KindCellCreate, Version: 1, IssuedAt: r.clk.Now(), ExpiresAt: r.clk.Now().Add(time.Hour), Cluster: testCluster(cell1), BootstrapSHA256: step.TestDigest}
		if _, err := r.plane.SignStep(t.Context(), body); ReasonOf(err) != mgmtapi.ReasonRestoreActive {
			t.Fatalf("sign: %v", err)
		}
		if len(calls) != n {
			t.Fatalf("%d calls during the restore", len(calls)-n)
		}
		if _, err := r.plane.RotateKey(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(calls) != n+1 || last() != newest() {
			t.Fatalf("%d calls after the rotation, want %d", len(calls), n+1)
		}
	})
	t.Run("failed_save", func(t *testing.T) {
		n := len(calls)
		r.plane.cfg.Store = failStore{r.store}
		if _, err := r.plane.PortalRequest(t.Context(), []string{cell2}, testDigest); err == nil {
			t.Fatal("the save did not fail")
		}
		r.plane.cfg.Store = r.store
		if len(calls) != n {
			t.Fatal("a failed save called OnSpec")
		}
	})
}

type failStore struct{ Store }

func (failStore) Save(*State) error { return fmt.Errorf("disk full") }

func TestConcurrentPortalAndBind(t *testing.T) {
	t.Run("bind_read_the_old_intent", func(t *testing.T) {
		r := newBareRig(t)
		r.request(cell1)
		r.keys.gate = make(chan struct{})
		n := r.nonce(cell1)
		tok := r.token(cell1, n, r.signers[cell1], nil)
		done := make(chan error, 1)
		go func() {
			_, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: tok})
			done <- err
		}()
		for r.keys.count(cell1) == 0 {
			time.Sleep(time.Millisecond)
		}
		if _, err := r.plane.PortalWithdraw(t.Context(), []string{cell1}); err != nil {
			t.Fatal(err)
		}
		close(r.keys.gate)
		if err := <-done; ReasonOf(err) != mgmtapi.ReasonCellUnknown {
			t.Fatalf("a bind that read the old intent: %v", err)
		}
		if st := r.plane.snap.Load().st; st.Cells[cell1] != nil || len(st.PendingDrops) != 0 {
			t.Fatalf("the cell bound after its withdraw: %+v", st.Cells)
		}
	})
	t.Run("race", testPortalBindRace)
}

func testPortalBindRace(t *testing.T) {
	for range 20 {
		r := newBareRig(t)
		r.request(cell1)
		n := r.nonce(cell1)
		tok := r.token(cell1, n, r.signers[cell1], nil)
		done := make(chan error, 2)
		go func() {
			_, err := r.plane.PortalWithdraw(t.Context(), []string{cell1})
			done <- err
		}()
		go func() {
			_, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: tok})
			done <- err
		}()
		for range 2 {
			if err := <-done; err != nil && ReasonOf(err) != mgmtapi.ReasonCellUnknown {
				t.Fatalf("err %v", err)
			}
		}
		st := r.plane.snap.Load().st
		if st.Requests[cell1] != nil {
			t.Fatal("the request survived the withdraw")
		}
		if st.Cells[cell1] != nil {
			if !slices.Equal(st.PendingDrops, []string{cell1}) {
				t.Fatalf("a cell bound after its withdraw is not staged for a drop: %v", st.PendingDrops)
			}
		}
		if len(r.specSteps()) != 0 {
			t.Fatal("the withdrawn cell kept a step")
		}
		r.restart(nil)
	}
}

// A bind whose proven keys equal the keys at issue keeps the step, through the key check path.
func TestBindSameKeysKeepsStepViaKeyCheck(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	k1 := r.signers[cell1]
	r.mustBind(cell1, k1, mgmtapi.StatusBound)
	if _, err := r.plane.PortalRecreate(t.Context(), cell1, testDigest); err != nil {
		t.Fatal(err)
	}
	issuer := r.keys.issuer(cell1)
	k2 := newSigner(t, "kid-2")
	r.keys.set(cell1, issuer, k1, k2)
	r.clk.Advance(61 * time.Second)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUpdated {
		t.Fatalf("key check to both keys: %v %v", res, err)
	}
	r.keys.set(cell1, issuer, k2)
	r.clk.Advance(61 * time.Second)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUpdated {
		t.Fatalf("key check to kid-2: %v %v", res, err)
	}
	if jw := string(r.plane.snap.Load().st.Cells[cell1].JWKS); !strings.Contains(jw, "kid-2") || strings.Contains(jw, "kid-1") {
		t.Fatalf("the record does not hold only kid-2: %s", jw)
	}
	if !r.stepOf(cell1).open() {
		t.Fatal("a key check closed the step")
	}
	r.keys.set(cell1, issuer, k1)
	r.clk.Advance(61 * time.Second)
	r.mustBind(cell1, k1, mgmtapi.StatusKeysUpdated)
	if !r.stepOf(cell1).open() {
		t.Fatal("a bind that proved the keys at issue closed the step")
	}
	if len(r.specSteps()) != 1 {
		t.Fatal("the step left the spec")
	}
}

// Two binds with new keys read the old record. The second meets already_bound inside its commit,
// and that answer closes nothing.
func TestAlreadyBoundInCommitDoesNotCloseStep(t *testing.T) {
	r := newBareRig(t)
	r.request(cell1)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	if _, err := r.plane.PortalRecreate(t.Context(), cell1, testDigest); err != nil {
		t.Fatal(err)
	}
	k2 := r.rekey(cell1, "kid-2")
	before := r.stepOf(cell1).IssuedAt.Add(-10 * time.Second) // a token minted before the step
	r.keys.gate = make(chan struct{})
	type result struct {
		status string
		err    error
	}
	done := make(chan result, 2)
	bind := func() {
		n := r.nonce(cell1)
		tok := r.token(cell1, n, k2, func(c *kubetoken.Claims) { c.IssuedAt = before })
		resp, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: tok})
		done <- result{resp.Status, err}
	}
	base := r.keys.count(cell1)
	go bind()
	for r.keys.count(cell1) == base {
		time.Sleep(time.Millisecond)
	}
	go bind()
	time.Sleep(100 * time.Millisecond)
	close(r.keys.gate)
	got := map[string]int{}
	for range 2 {
		res := <-done
		if res.err != nil {
			t.Fatal(res.err)
		}
		got[res.status]++
	}
	if got[mgmtapi.StatusKeysUpdated] != 1 || got[mgmtapi.StatusAlreadyBound] != 1 {
		t.Fatalf("outcomes %v", got)
	}
	if !r.stepOf(cell1).open() {
		t.Fatal("the step closed")
	}
}

// specClosed returns the closed list of the newest spec.
func (r *rig) specClosed() []string {
	r.t.Helper()
	l := r.plane.snap.Load().st.latest()
	s, _, err := spec.Verify(l.Bundle.Spec, []ed25519.PublicKey{r.plane.PublicKey()})
	if err != nil {
		r.t.Fatalf("spec does not verify: %v", err)
	}
	return s.Closed
}

func TestSpecListsClosedStep(t *testing.T) {
	r := newBareRig(t, cell1, cell2)
	r.request(cell1, cell2)
	if got := r.specClosed(); len(got) != 0 {
		t.Fatalf("closed before a bind: %v", got)
	}
	id := r.stepOf(cell1).ID
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	if got := r.specClosed(); len(got) != 1 || got[0] != id {
		t.Fatalf("closed after the bind = %v, want [%s]", got, id)
	}
	if _, ok := r.specSteps()[cell1]; ok {
		t.Fatal("the closed step is still indexed")
	}
	// The ID stays for as long as the request names the step, through later commits and a rotation.
	if _, err := r.plane.PortalCancel(t.Context(), cell2); err != nil {
		t.Fatal(err)
	}
	if got := r.specClosed(); len(got) != 1 || got[0] != id {
		t.Fatalf("closed after a cancel of another cell = %v", got)
	}
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := r.specClosed(); len(got) != 1 || got[0] != id {
		t.Fatalf("closed after a rotation = %v", got)
	}
	r.restart(nil)
	if got := r.specClosed(); len(got) != 1 || got[0] != id {
		t.Fatalf("closed after a restart = %v", got)
	}
	// A recreate replaces the step, so the ID leaves the list.
	if _, err := r.plane.PortalRecreate(t.Context(), cell1, testDigest); err != nil {
		t.Fatal(err)
	}
	if got := r.specClosed(); len(got) != 0 {
		t.Fatalf("closed after a recreate = %v", got)
	}
}

func TestSpecClosedEndsOnWithdraw(t *testing.T) {
	r := newBareRig(t, cell1)
	r.request(cell1)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	if got := r.specClosed(); len(got) != 1 {
		t.Fatalf("closed = %v", got)
	}
	if _, err := r.plane.PortalWithdraw(t.Context(), []string{cell1}); err != nil {
		t.Fatal(err)
	}
	if got := r.specClosed(); len(got) != 0 {
		t.Fatalf("closed after a withdraw = %v", got)
	}
}

func TestSpecCancelAndRetryListNoClosed(t *testing.T) {
	r := newBareRig(t, cell1, cell2)
	r.request(cell1, cell2)
	if _, err := r.plane.PortalCancel(t.Context(), cell1); err != nil {
		t.Fatal(err)
	}
	if _, err := r.plane.PortalRetry(t.Context(), cell2, testDigest); err != nil {
		t.Fatal(err)
	}
	if got := r.specClosed(); len(got) != 0 {
		t.Fatalf("a cancel or a retry listed closed steps: %v", got)
	}
}
