//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// outboxKindsOf returns the kind of each item in the outbox of the gateway that has the operation ID id.
func outboxKindsOf(t *testing.T, id string) []string {
	t.Helper()
	var res struct {
		Items []struct {
			Kind string `json:"kind"`
			OpID string `json:"opId"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(gwCtl(t, "", "outbox")), &res); err != nil {
		t.Fatalf("cellgw ctl outbox is no list: %v", err)
	}
	var kinds []string
	for _, it := range res.Items {
		if it.OpID == id {
			kinds = append(kinds, it.Kind)
		}
	}
	return kinds
}

// gwQueueHas reports whether the queue of the gateway for cell holds a row of operation id, and the state of that row.
func gwQueueHas(t *testing.T, cell, id string) (bool, string) {
	t.Helper()
	var q struct {
		Items []struct {
			OpID  string `json:"opId"`
			State string `json:"state"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(gwCtl(t, "", "queue", "--cell", cell)), &q); err != nil {
		t.Fatalf("cellgw ctl queue --cell %s is no queue: %v", cell, err)
	}
	for _, it := range q.Items {
		if it.OpID == id {
			return true, it.State
		}
	}
	return false, ""
}

// TestGatewayVolumeLostDrill: the gateway loses its volume while work is in flight, and gw:reset recovers it. Run only by gate:m5:drill.
//
//  1. celld of the first cell goes to 0 replicas.
//  2. An operation X is signed, and the queue of the gateway shows it.
//  3. mgmtd goes to 0 replicas, so results stay in the outbox while envd keeps syncing.
//  4. celld returns, applies X, and the outbox of the gateway holds the result of X (an item of kind result with the ID of X).
//  5. mise run gw:reset replaces the volume, and the epoch rises.
//  6. mgmtd returns.
//
// Expected: the epoch is higher. celld resends the result, or claims X again and gets already_applied, whichever comes first, so the
// final result of X at mgmtd is applied or already_applied (the test logs which). The record of X reaches reported, the demo log holds one
// line for X, and harness:status exits 0.
func TestGatewayVolumeLostDrill(t *testing.T) {
	const mgmtd = "statefulset/mgmtd"
	cell := clustersWith(t, agentCellSet)[0]
	celld := "deployment/" + celldDeployment
	celldUp, mgmtdUp := false, false
	upCelld := func() {
		if !celldUp {
			celldUp = true
			setReplicas(t, cell, celldNamespace, celld, 1)
		}
	}
	upMgmtd := func() {
		if !mgmtdUp {
			mgmtdUp = true
			setReplicas(t, mgmtCluster, mgmtNamespace, mgmtd, 1)
		}
	}
	t.Cleanup(func() {
		upCelld()
		upMgmtd()
		deploymentRolledOut(t, cell, celldNamespace, celldDeployment)
		statefulSetReady(t, mgmtCluster, mgmtNamespace, "mgmtd")
	})

	setReplicas(t, cell, celldNamespace, celld, 0)
	id := opCreate(t, cell, "volume lost drill "+time.Now().UTC().Format(time.RFC3339), 30*time.Minute)
	waitFor(t, "the queue of the gateway to hold operation "+id, m5Wait, func() (bool, string) {
		ok, state := gwQueueHas(t, cell, id)
		return ok, "queue state " + state
	})

	setReplicas(t, mgmtCluster, mgmtNamespace, mgmtd, 0)
	setReplicas(t, cell, celldNamespace, celld, 1)
	celldUp = true
	waitFor(t, "the record op-"+id+" in "+cell+" to be applied", 5*time.Minute, func() (bool, string) {
		state := opRecordState(t, cell, id)
		return state == "applied", fmt.Sprintf("record %q", state)
	})
	// With mgmtd away, the status items of both cells fill the outbox too, so only an item of kind result with the ID of X shows that the
	// reset loses the result of X.
	waitFor(t, "the outbox of the gateway to hold the result of "+id, m5Wait, func() (bool, string) {
		kinds := outboxKindsOf(t, id)
		return slices.Contains(kinds, gwapi.KindResult), fmt.Sprintf("outbox items of %s: %v", id, kinds)
	})
	before := gwStatus(t).Epoch

	stdout, stderr, code := runMiseBounded(t, 10*time.Minute, "", "gw:reset")
	if code != 0 {
		t.Fatalf("mise run gw:reset exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var reset struct {
		OldEpoch uint64 `json:"oldEpoch"`
		NewEpoch uint64 `json:"newEpoch"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &reset); err != nil {
		t.Fatalf("gw:reset printed no JSON line: %q", stdout)
	}
	if reset.NewEpoch <= before || reset.NewEpoch <= reset.OldEpoch {
		t.Errorf("gw:reset reports epoch %d to %d, and the gateway had %d before, want a higher epoch", reset.OldEpoch, reset.NewEpoch, before)
	}
	if now := gwStatus(t).Epoch; now != reset.NewEpoch || now <= before {
		t.Errorf("the gateway reports epoch %d, want %d, above %d", now, reset.NewEpoch, before)
	}

	upMgmtd()
	statefulSetReady(t, mgmtCluster, mgmtNamespace, "mgmtd")
	waitOpReported(t, cell, id, 5*time.Minute)
	v := opGet(t, id)
	if v.State != "final" || !slices.Contains([]string{op.OutcomeApplied, op.OutcomeAlreadyApplied}, v.Final) {
		t.Errorf("mgmtd shows operation %s as state %q final %q, want final applied or already_applied", id, v.State, v.Final)
	}
	t.Logf("the final result of %s is %q (applied: celld resent its result; already_applied: celld claimed X again first)", id, v.Final)
	if n := demoLogCount(t, cell, id); n != 1 {
		t.Errorf("the demo log of %s holds %d lines for %s, want 1:\n%s", cell, n, id, strings.Join(demoLog(t, cell), "\n"))
	}

	deadline := time.Now().Add(statusRetryWindow)
	for attempt := 1; ; attempt++ {
		_, out, code := statusOnce(t)
		if code == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("harness:status exited %d after the drill, want 0:\n%s", code, out)
		}
		t.Logf("attempt %d: harness:status exited %d", attempt, code)
		time.Sleep(30 * time.Second)
	}
}
