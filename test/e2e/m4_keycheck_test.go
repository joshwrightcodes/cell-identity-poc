//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	// keyUpdateGap is KeyUpdateGap of mgmtd plus a second: a key check inside it answers rate_limited.
	keyUpdateGap = 61 * time.Second
	healWait     = 5 * time.Minute
)

// keyCheck runs mgmtd ctl keycheck for a cell and returns the result.
func keyCheck(t *testing.T, cell string) string {
	t.Helper()
	var r struct {
		Result string `json:"result"`
	}
	out := mgmtCtl(t, "keycheck", "--cell", cell)
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Result == "" {
		t.Fatalf("mgmtd ctl keycheck --cell %s printed %q, want a result", cell, out)
	}
	return r.Result
}

// cellStatusOf returns the status of one cell from mgmtd.
func cellStatusOf(t *testing.T, cell string) mgmt.CellStatus {
	t.Helper()
	for _, c := range mgmtStatus(t).Cells {
		if c.Name == cell {
			return c
		}
	}
	t.Fatalf("mgmtd shows no cell %s", cell)
	return mgmt.CellStatus{}
}

// serverPodUID returns the UID of the SPIRE server pod of dev-cp.
func serverPodUID(t *testing.T) string {
	t.Helper()
	uid, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "pod", spireServerPod, "-o", "jsonpath={.metadata.uid}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(uid)
}

// waitIssued runs attestprobe in a cell until it prints issued:, within the timeout.
func waitIssued(t *testing.T, cell string, timeout time.Duration) {
	t.Helper()
	waitFor(t, "attestprobe in "+cell+" to print issued:", timeout, func() (bool, string) {
		res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
		return strings.HasPrefix(res.out, "issued:"), res.out
	})
}

// afterRevision reports whether a is after b.
func afterRevision(a, b spec.Revision) bool { return a.Compare(b) > 0 }

// keyCheckAfterRotation runs a key check for a cell after rotateAPIKey and the update gap. The celld streams make the gateway hint
// mgmtd, which updates the record within about a minute of the rotation, so the check answers keys_updated, or unchanged when
// the hint was first. Either way the record must then list both key IDs, so that a token of the old key and one of the new key verify.
func keyCheckAfterRotation(t *testing.T, cell, oldKID, newKID string) {
	t.Helper()
	switch got := keyCheck(t, cell); got {
	case "keys_updated":
	case "unchanged":
		if kids := cellStatusOf(t, cell).Kids; !slices.Contains(kids, oldKID) || !slices.Contains(kids, newKID) {
			t.Fatalf("the key check of %s after the rotation answered unchanged, and the record lists %v, want %s and %s", cell, kids, oldKID, newKID)
		}
	default:
		t.Fatalf("the key check of %s after the rotation answered %q, want keys_updated or unchanged with both key IDs in the record", cell, got)
	}
}

// TestM4KeyCheckFollowsRotation rotates the service account key of dev-cell-1 with the M2 helpers, and restarts no celld pod. A
// key check first makes the record current and holds the periodic check back. With a record at one key, attestprobe fails with
// unknown_kid, unless a hint from a celld status report updated the record first (the hint comes about a minute after a rotation).
// After the update gap, a key check gives keys_updated, or unchanged with both key IDs already in the record, at a new revision.
// Then attestprobe is issued within five minutes, with a token from the new key, and the SPIRE server pod keeps its UID and
// logs 'records reloaded' since the rotation.
func TestM4KeyCheckFollowsRotation(t *testing.T) {
	const cell = rejectCell
	if res := keyCheck(t, cell); res != "unchanged" && res != "rate_limited" {
		t.Fatalf("the first key check of %s answered %q, want unchanged or rate_limited. Run: mise run gate:m4:repair", cell, res)
	}
	renderRegistryAtCleanup(t)
	first := time.Now()
	before := cellStatusOf(t, cell)
	if len(before.Kids) != 1 {
		t.Fatalf("the record of %s lists the key IDs %v, want one", cell, before.Kids)
	}
	uid := serverPodUID(t)

	rotatedAt := time.Now().Add(-logMargin)
	oldKID, newKID := rotateAPIKey(t, cell)
	res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
	if strings.HasPrefix(res.out, "issued:") {
		t.Logf("a hint from a celld report updated the record of %s before the probe ran: %s", cell, res.out)
	} else {
		expectRefusal(t, res, cell, "unknown_kid", []string{newKID})
	}

	if wait := keyUpdateGap - time.Since(first); wait > 0 {
		t.Logf("waiting %s, so that the key check falls outside the update gap", wait.Round(time.Second))
		time.Sleep(wait)
	}
	keyCheckAfterRotation(t, cell, oldKID, newKID)
	after := cellStatusOf(t, cell)
	if !slices.Contains(after.Kids, oldKID) || !slices.Contains(after.Kids, newKID) || len(after.Kids) != 2 || !afterRevision(after.Record, before.Record) {
		t.Errorf("after the key check the record of %s lists %v at %+v, want %s and %s at a revision after %+v", cell, after.Kids, after.Record, oldKID, newKID, before.Record)
	}
	waitIssued(t, cell, healWait)
	if got := serverPodUID(t); got != uid {
		t.Errorf("the pod %s has the UID %s after the update, and had %s before: the server restarted", spireServerPod, got, uid)
	}
	logs, err := serverLog(t, rotatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(matching(logs, func(l logLine) bool { return l.str("msg") == "records reloaded" })); n == 0 {
		t.Errorf("the SPIRE server log holds no 'records reloaded' line since the rotation")
	}
}

// TestM4BindHealsRotation rotates the service account key of dev-cell-1 again, after a key check and the update gap, with no further
// key check, so that neither the periodic check nor the gap falls inside the test. attestprobe fails with unknown_kid. A new
// celld pod binds with a token from the new key: the log of mgmtd then holds a bind with the result keys_updated for the cell,
// and within five minutes the new pod and attestprobe both attest.
func TestM4BindHealsRotation(t *testing.T) {
	t.Skip("the M4 bind path is gone, and a new celld cannot bind until Task 12. Task 15 removes this skip when it adds TestM5BindHealsRotation")
	const cell = rejectCell
	if res := keyCheck(t, cell); res != "unchanged" && res != "rate_limited" {
		t.Fatalf("the key check of %s answered %q, want unchanged or rate_limited. Run: mise run gate:m4:repair", cell, res)
	}
	renderRegistryAtCleanup(t)
	t.Logf("waiting %s, so that the update gap has passed before the rotation", keyUpdateGap)
	time.Sleep(keyUpdateGap)
	start := time.Now().Add(-logMargin)
	_, newKID := rotateAPIKey(t, cell)
	res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
	expectRefusal(t, res, cell, "unknown_kid", []string{newKID})

	pod := replaceCelldPod(t, cell)
	want := fmt.Sprintf("spiffe://%s/cell/%s/celld", spireTD, cell)
	waitFor(t, "the new celld pod to log "+want, healWait, func() (bool, string) {
		logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", pod.Metadata.Name, "-c", celldContainer)
		if err != nil {
			return false, err.Error()
		}
		return slices.Contains(celldSPIFFEIDs(logs), want), lastLines(logs, 3)
	})
	logs := mgmtdLog(t, start)
	if n := len(matching(logs, func(l logLine) bool {
		return l.str("msg") == "bind" && l.str("cell") == cell && l.str("result") == "keys_updated"
	})); n == 0 {
		t.Errorf("the mgmtd log holds no bind with the result keys_updated for %s since the rotation:\n%s", cell, lastLines(logs, 8))
	}
	waitIssued(t, cell, healWait)
}

// mgmtdLog returns the log of mgmtd since a time.
func mgmtdLog(t *testing.T, since time.Time) string {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "logs", mgmtdPod, "-c", "mgmtd", "--since-time="+since.UTC().Format(time.RFC3339))
	if err != nil {
		t.Logf("read the mgmtd log: %v", err)
	}
	return out
}

// makeRevision signs a new revision for a cell: a key check first, a rotation of the service account key with the M2 helpers, and
// after the update gap a key check that gives keys_updated, or unchanged when a hint updated the record first. The cleanup of rotateAPIKey repairs the API server when the test ends, and then the registries follow the record.
func makeRevision(t *testing.T, cell string) {
	t.Helper()
	if res := keyCheck(t, cell); res != "unchanged" && res != "rate_limited" {
		t.Fatalf("the key check of %s answered %q, want unchanged or rate_limited. Run: mise run gate:m4:repair", cell, res)
	}
	renderRegistryAtCleanup(t)
	first := time.Now()
	oldKID, newKID := rotateAPIKey(t, cell)
	if wait := keyUpdateGap - time.Since(first); wait > 0 {
		time.Sleep(wait)
	}
	keyCheckAfterRotation(t, cell, oldKID, newKID)
}
