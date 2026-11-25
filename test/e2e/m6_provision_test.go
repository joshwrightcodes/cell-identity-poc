//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	// m6ProvisionMarker exists while TestProvisionFromPortal has deleted the cells and not yet created them again. gate:m6:repair
	// restores the cells while it exists, and gate:m6 fails its check.
	m6ProvisionMarker = "../../build/gate/m6-provision"
	// provisionWithdrawWait bounds the staged drop of the records of withdrawn cells.
	provisionWithdrawWait = 5 * time.Minute
	// provisionStepsWait bounds both steps. The host runs one step at a time, and each admit stage renders dev-cp again.
	provisionStepsWait = 75 * time.Minute
	// cellDownWait bounds one cell:down.
	cellDownWait = 15 * time.Minute
)

// stageHeader is the first line of each stage in the log of a step: "== <stage> attempt <n> CELL=<cluster> at <RFC 3339>".
var stageHeader = regexp.MustCompile(`^== (\w+) attempt (\d+) CELL=(\S+) at (\S+)$`)

// miseRun runs `mise run <args>` with the extra environment, waits at most timeout, and returns the combined output.
func miseRun(t *testing.T, timeout time.Duration, env []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mise", append([]string{"run"}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// portalResult decodes the line that portal prints for a request.
func portalResult(t *testing.T, m map[string]any) mgmtapi.PortalResult {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var res mgmtapi.PortalResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("the portal answered %s, which is no result: %v", raw, err)
	}
	return res
}

// withdrawAndDelete withdraws the cells at the portal, waits until the live records list none of them, and deletes their clusters. The
// records drop in two stages: mgmtd commits the retirement, and the drop waits for an applied report of envd for that commit
// (M4 staged drop), so the wait reports pendingDrops when it ends. Every cell:down but the last skips the render of dev-cp and the
// link. The last one renders dev-cp and links management with no live cell.
func withdrawAndDelete(t *testing.T, cells ...string) {
	t.Helper()
	args := []string{"withdraw"}
	for _, c := range cells {
		args = append(args, "--cell", c)
	}
	if _, err := portal(t, args...); err != nil {
		t.Fatalf("withdraw %v: %v", cells, err)
	}
	waitFor(t, fmt.Sprintf("the records of %v to leave cell-records", cells), provisionWithdrawWait, func() (bool, string) {
		_, recs, err := readLiveRecords(t)
		if err != nil {
			return false, err.Error()
		}
		var held []string
		for _, c := range cells {
			if _, ok := recs[c]; ok {
				held = append(held, c)
			}
		}
		return len(held) == 0, fmt.Sprintf("cell-records still lists %v; pendingDrops of mgmt -- status: %v", held, mgmtStatus(t).PendingDrops)
	})
	for i, c := range cells {
		var env []string
		if i < len(cells)-1 {
			env = append(env, "CELL_DOWN_SKIP_RERENDER=1")
		}
		if out, err := miseRun(t, cellDownWait, append(env, "CELL="+c), "cell:down"); err != nil {
			t.Fatalf("cell:down of %s: %v\n%s", c, err, out)
		}
	}
}

// waitValid waits until mgmtd shows every cell as valid. The wait reports the reason of each cell that is not.
func waitValid(t *testing.T, cells []string, timeout time.Duration) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%v to be valid", cells), timeout, func() (bool, string) {
		st := mgmtStatus(t)
		var bad []string
		for _, c := range cells {
			found := false
			for _, cs := range st.Cells {
				if cs.Name == c {
					found = true
					if !cs.Valid {
						bad = append(bad, fmt.Sprintf("%s: valid false, reason %q, bound %v", c, cs.ValidReason, cs.Bound))
					}
				}
			}
			if !found {
				bad = append(bad, c+": not in mgmt -- status")
			}
		}
		return len(bad) == 0, strings.Join(bad, "; ")
	})
}

// stepLogSections reads the log of a step through `hostsvc:serve -- log` and splits it at the stage headers.
func stepLogSections(t *testing.T, id string) []stageSection {
	t.Helper()
	out, err := exec.Command("mise", "run", "hostsvc:serve", "--", "log", "--step", id).Output()
	if err != nil {
		t.Fatalf("mise run hostsvc:serve -- log --step %s: %v", id, err)
	}
	var sections []stageSection
	for line := range strings.SplitSeq(string(out), "\n") {
		if m := stageHeader.FindStringSubmatch(line); m != nil {
			at, _ := time.Parse(time.RFC3339, m[4])
			sections = append(sections, stageSection{stage: m[1], cluster: m[3], at: at})
			continue
		}
		if len(sections) > 0 {
			s := &sections[len(sections)-1]
			s.lines = append(s.lines, line)
		}
	}
	return sections
}

// injectStatus puts one status item of the cell into the outbox of the gateway, as dev-cp could, and waits until envd takes it. The token
// comes from token(audience), or is empty when token is nil.
func injectStatus(t *testing.T, cell string, token func(audience string) string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"at": time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	tok := ""
	if token != nil {
		tok = token(proof.ReportAudience(cell, gwapi.KindStatus, body))
	}
	waitItemTaken(t, injectItem(t, gwapi.Item{Kind: gwapi.KindStatus, Cell: cell, Body: body, Token: tok}))
}

// TestProvisionFromPortal: one portal request creates both cells, and checks 1 to 3 of the PoC hold. The test deletes both cells first,
// so it needs a live harness with both cells valid and no open step. It writes the marker build/gate/m6-provision before it deletes
// anything and removes it after step 10, so an interrupted run leaves the marker, and gate:m6:repair restores the cells. Each numbered
// step fails the test with the state that it saw.
func TestProvisionFromPortal(t *testing.T) {
	cells := clustersWith(t, agentCellSet)
	if len(cells) != 2 {
		t.Fatalf("the topology has the cells %v, and the test needs two", cells)
	}
	// Start from a harness that gate:m6 accepts.
	if _, err := os.Stat(m6ProvisionMarker); err == nil {
		t.Fatalf("%s exists, so an earlier run stopped early. Run: mise run gate:m6:repair", m6ProvisionMarker)
	}
	m6RequireNoSteps(t)
	if have := kindClusters(t); !slices.Contains(have, cells[0]) || !slices.Contains(have, cells[1]) {
		t.Fatalf("kind lists %v, and the test starts from both cells %v. Run: mise run portal -- request --cell %s --cell %s --wait", have, cells, cells[0], cells[1])
	}
	waitValid(t, cells, 2*time.Minute)

	// 1. The marker, then withdraw and delete both cells.
	if err := os.MkdirAll(filepath.Dir(m6ProvisionMarker), 0o755); err != nil {
		t.Fatal(err)
	}
	// The marker names the cells that the test deletes, one on each line, so that the repair touches only their steps.
	if err := os.WriteFile(m6ProvisionMarker, []byte(strings.Join(cells, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deleteStart := time.Now()
	withdrawAndDelete(t, cells...)
	t.Logf("withdraw and delete of %v took %s", cells, time.Since(deleteStart).Round(time.Second))

	// 2. No cluster, no request, empty admit lists, and a dev-cp that verifies.
	before := kindClusters(t)
	for _, c := range cells {
		if slices.Contains(before, c) {
			t.Fatalf("step 2: kind get clusters lists %v, and %s must be gone", before, c)
		}
	}
	for _, cs := range mgmtStatus(t).Cells {
		if slices.Contains(cells, cs.Name) && cs.Requested {
			t.Fatalf("step 2: mgmt -- status shows %s as requested: %+v", cs.Name, cs)
		}
	}
	sp, _, err := readLiveRecords(t)
	if err != nil {
		t.Fatalf("step 2: %v", err)
	}
	retired := map[string]spec.Revision{}
	for _, r := range sp.Retired {
		retired[r.Name] = r.Revision
	}
	for _, c := range cells {
		if _, ok := retired[c]; !ok {
			t.Fatalf("step 2: the spec lists the retired cells %v, and %s is not one of them (the drop writes the mark that step 10 compares)", sp.Retired, c)
		}
	}
	if out, err := miseRun(t, 10*time.Minute, []string{"CELL=dev-cp"}, "cell:verify"); err != nil || !regexp.MustCompile(`(?m)^PASS  The SPIRE server, relay and gateway admit lists`).MatchString(out) {
		t.Fatalf("step 2: cell:verify of dev-cp with no cell: %v, want a pass with the admit lists check\n%s", err, out)
	}

	// 3. cell:up of an absent cell is refused and creates nothing.
	if out, err := miseRun(t, 10*time.Minute, []string{"CELL=" + cells[0]}, "cell:up"); err == nil || !strings.Contains(out, "cell_needs_step") {
		t.Fatalf("step 3: cell:up of the absent %s: err %v, want a failure that says cell_needs_step\n%s", cells[0], err, out)
	}
	if after := kindClusters(t); !slices.Equal(after, before) {
		t.Fatalf("step 3: kind get clusters was %v and is %v after the refused cell:up", before, after)
	}

	// 4. One request names both cells: two step IDs, one revision, one commit, and the host service holds the revision.
	counterBefore := mgmtStatus(t).Signed.Counter
	args := []string{"request"}
	for _, c := range cells {
		args = append(args, "--cell", c)
	}
	m, err := portal(t, args...)
	if err != nil {
		t.Fatalf("step 4: %v", err)
	}
	res := portalResult(t, m)
	stepIDs := map[string]string{}
	for _, s := range res.Steps {
		if !isStepID(s.StepID) {
			t.Fatalf("step 4: the portal printed the step ID %q for %s", s.StepID, s.Cell)
		}
		stepIDs[s.Cell] = s.StepID
	}
	if len(res.Steps) != 2 || len(stepIDs) != 2 || stepIDs[cells[0]] == "" || stepIDs[cells[1]] == "" || res.Revision == (spec.Revision{}) {
		t.Fatalf("step 4: the portal printed %v, want one step for each of %v and one revision", m, cells)
	}
	if rose := mgmtStatus(t).Signed.Counter - counterBefore; rose != 1 {
		t.Fatalf("step 4: the signed counter rose by %d (from %d), want exactly 1", rose, counterBefore)
	}
	waitHostSpecAtLeast(t, res.Revision, time.Minute)

	// 5. The cell controller lists both steps.
	waitFor(t, "step-status to list both steps", 2*time.Minute, func() (bool, string) {
		listed := map[string]bool{}
		for _, e := range stepStatusEntries(t) {
			listed[e.ID] = true
		}
		return listed[stepIDs[cells[0]]] && listed[stepIDs[cells[1]]], fmt.Sprintf("step-status lists %v, want %v", listed, stepIDs)
	})

	// 6. While the first cell is unbound, a status item for it does not make it valid. dev-cp can inject any item, so mgmtd must refuse
	// each one with not_bound, whatever token it carries.
	var prevRefusal time.Time
	for _, tc := range []struct {
		name  string
		token func(string) string
	}{
		{"no token", nil},
		{"rogue token", func(audience string) string { return rogueToken(t, audience) }},
	} {
		if cs := cellStatusOf(t, cells[0]); cs.Bound || cs.Valid {
			t.Fatalf("step 6: %s is bound %v and valid %v before the %s item; the test needs an unbound cell", cells[0], cs.Bound, cs.Valid, tc.name)
		}
		injected := time.Now().Add(-logMargin)
		injectStatus(t, cells[0], tc.token)
		waitFor(t, "mgmtd to answer not_bound for the status item with "+tc.name, refusalWait, func() (bool, string) {
			cs := cellStatusOf(t, cells[0])
			if cs.Valid {
				t.Fatalf("step 6: %s is valid after a status item with %s: %+v", cells[0], tc.name, cs)
			}
			r := cs.LastRefusal
			if r == nil {
				return false, "no last refusal"
			}
			// The refusal has no item ID, so it must be newer than the one that ended the previous case.
			if freshRefusal(r, gwapi.KindStatus, mgmtapi.ReasonNotBound, injected, prevRefusal) {
				prevRefusal = r.At
				return true, ""
			}
			return false, fmt.Sprintf("last refusal %+v, injected after %s, previous refusal %s", *r, injected, prevRefusal)
		})
	}

	// 7. Check 1: both steps end done, each with the node address of its cluster, and each log shows the three stages in order.
	stepsStart := time.Now()
	// A step in the state failed is retried by the host service after its RetryAt, so only the final states end the wait early.
	final := map[string]bool{"failed_final": true, "refused": true, "cancelled": true}
	waitFor(t, "both steps to be done at the host service", provisionStepsWait, func() (bool, string) {
		steps := hostSteps(t)
		var seen []string
		done := 0
		for _, c := range cells {
			s, ok := steps[stepIDs[c]]
			if !ok {
				seen = append(seen, c+": no step "+stepIDs[c])
				continue
			}
			seen = append(seen, fmt.Sprintf("%s: %s %s attempts %d reason %q detail %q", c, s.State, s.Stage, s.Attempts, s.Reason, s.Detail))
			if s.State == "done" {
				done++
			} else if final[s.State] {
				t.Fatalf("step 7: the step %s of %s is %s at stage %s (reason %q, detail %q). Read: mise run hostsvc:serve -- log --step %s",
					s.ID, c, s.State, s.Stage, s.Reason, s.Detail, s.ID)
			}
		}
		return done == len(cells), strings.Join(seen, "; ")
	})
	t.Logf("both steps were done %s after the request", time.Since(stepsStart).Round(time.Second))
	steps := hostSteps(t)
	for _, c := range cells {
		id := stepIDs[c]
		if want := clusterFacts(t, c).NodeIP; steps[id].NodeIP != want || want == "" {
			t.Errorf("step 7: the step %s of %s has the nodeIP %q, and the node of the cluster has %q", id, c, steps[id].NodeIP, want)
		}
		secs := lastAttempts(stepLogSections(t, id))
		var order []string
		for _, s := range secs {
			order = append(order, s.stage+"@"+s.cluster)
		}
		wantOrder := []string{"creating@" + c, "admitting@" + cpClusterName, "bootstrapping@" + c}
		if !slices.Equal(order, wantOrder) {
			t.Errorf("step 7: the log of the step %s of %s has the stages %v, want %v", id, c, order, wantOrder)
			continue
		}
		for i, s := range secs {
			end := steps[id].UpdatedAt
			if i+1 < len(secs) {
				end = secs[i+1].at
			}
			t.Logf("verify row 4: %s stage %s took %s", c, s.stage, end.Sub(s.at).Round(time.Second))
		}
		// The child of the admit stage never reads .envrc.local, so up.sh logs that the secret store command is not set.
		if !strings.Contains(strings.Join(secs[1].lines, "\n"), "secret_token_cmd_set=false") {
			t.Errorf("step 7: the admitting section of the step %s of %s lacks secret_token_cmd_set=false:\n%s", id, c, strings.Join(secs[1].lines, "\n"))
		}
	}

	// 8. Check 2: each celld holds its SVID, each cell has a stream at the gateway, and mgmtd shows each cell bound with its step closed.
	for _, c := range cells {
		pods := celldPods(t, c)
		if len(pods) != 1 {
			t.Fatalf("step 8: %s runs %d celld pods, want 1", c, len(pods))
		}
		waitCelldSVID(t, c, pods[0])
		waitFor(t, "the gateway to hold a stream of "+c, 2*time.Minute, func() (bool, string) {
			s := gwStatus(t)
			return s.Streams[c] >= 1, fmt.Sprintf("streams %v", s.Streams)
		})
		waitFor(t, "mgmt -- status to show "+c+" bound with its step closed", 2*time.Minute, func() (bool, string) {
			cs := cellStatusOf(t, c)
			closed := cs.Step != nil && cs.Step.ID == stepIDs[c] && !cs.Step.DoneAt.IsZero()
			return cs.Bound && closed, fmt.Sprintf("bound %v, step %+v", cs.Bound, cs.Step)
		})
	}

	// 9. Check 3: both cells valid, and an operation applies in each.
	waitValid(t, cells, 5*time.Minute)
	for _, c := range cells {
		id := opCreate(t, c, "m6 provision "+c+" "+randomHex(t, 4), 0)
		waitFor(t, "operation "+id+" to be applied in "+c, 2*time.Minute, func() (bool, string) {
			v := opGet(t, id)
			return v.State == "final" && v.Final == op.OutcomeApplied, fmt.Sprintf("state %q final %q", v.State, v.Final)
		})
	}

	// 10. The records are above the retired marks, the spec indexes no step, and the admit lists hold both cells again.
	waitFor(t, "the live spec to hold both cells above their retired marks and no step", 2*time.Minute, func() (bool, string) {
		sp, recs, err := readLiveRecords(t)
		if err != nil {
			return false, err.Error()
		}
		var problems []string
		for _, c := range cells {
			rec, ok := recs[c]
			if !ok {
				problems = append(problems, c+" has no record")
				continue
			}
			if mark, ok := retired[c]; ok && (spec.Revision{Epoch: rec.Epoch, Counter: rec.Counter}).Compare(mark) <= 0 {
				problems = append(problems, fmt.Sprintf("%s has the record %d/%d, not above the retired mark %+v", c, rec.Epoch, rec.Counter, mark))
			}
			if rec.Revoked {
				problems = append(problems, c+" has a revoked record")
			}
		}
		if len(sp.Steps) != 0 {
			problems = append(problems, fmt.Sprintf("the spec indexes the steps %v", sp.Steps))
		}
		return len(problems) == 0, strings.Join(problems, "; ")
	})
	if out, err := miseRun(t, 10*time.Minute, []string{"CELL=dev-cp"}, "cell:verify"); err != nil || !regexp.MustCompile(`(?m)^PASS  The SPIRE server, relay and gateway admit lists`).MatchString(out) {
		t.Fatalf("step 10: cell:verify of dev-cp with both cells: %v, want a pass with the admit lists check\n%s", err, out)
	}
	// A cell that the portal creates starts with a bundle state of source bootstrap, and cell:verify fails that state. The signed
	// publish gives each cell a set that mgmtd signed, as harness:up does after the portal.
	publish := []string{"bundle", "--", "publish"}
	for _, c := range cells {
		publish = append(publish, "--target", c)
	}
	if out, err := miseRun(t, 15*time.Minute, nil, append(publish, "--wait")...); err != nil {
		t.Fatalf("step 10: publish a signed set to %v: %v\n%s", cells, err, out)
	}
	for _, c := range cells {
		if out, err := miseRun(t, 10*time.Minute, []string{"CELL=" + c}, "cell:verify"); err != nil {
			t.Fatalf("step 10: cell:verify of %s after the signed publish: %v\n%s", c, err, out)
		}
	}
	if err := os.Remove(m6ProvisionMarker); err != nil {
		t.Fatalf("step 10: remove the marker: %v", err)
	}
}
