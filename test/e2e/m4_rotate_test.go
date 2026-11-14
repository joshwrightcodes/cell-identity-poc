//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cmdrun"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// rotateWait bounds each call of rotate-signing-key: the cell passes, the render of dev-cp, the link of management and two verify runs.
const rotateWait = 45 * time.Minute

var recordKeysLine = regexp.MustCompile(`(?m)^\s*record_public_keys = \[(.*)\]$`)

// serverStart returns the start time of the spire-server container in dev-cp.
func serverStart(t *testing.T) time.Time {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "pod", spireServerPod, "-o",
		`jsonpath={.status.containerStatuses[?(@.name=="spire-server")].state.running.startedAt}`)
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("the start time of spire-server is %q: %v", out, err)
	}
	return at
}

// cellVerify runs `mise run cell:verify` for a cluster.
func cellVerify(t *testing.T, cell string) {
	t.Helper()
	res, err := cmdrun.Run(10*time.Minute, "../..", []string{"CELL=" + cell}, "mise", "run", "cell:verify")
	if err != nil || res.Code != 0 {
		t.Errorf("CELL=%s mise run cell:verify: %v (exit %d)\n%s%s", cell, err, res.Code, res.Stdout, res.Stderr)
	}
}

// rotateStep runs `mise run mgmt -- rotate-signing-key --step <name>` and returns the one JSON line that it prints.
func rotateStep(t *testing.T, name string) (out struct {
	Rotated bool   `json:"rotated"`
	Staged  bool   `json:"staged"`
	Old     string `json:"old_key_sha256"`
	New     string `json:"new_key_sha256"`
	Epoch   uint64 `json:"epoch"`
	Seconds int    `json:"seconds"`
}) {
	t.Helper()
	started := time.Now()
	res, err := cmdrun.Run(rotateWait, "", nil, "mise", "run", "mgmt", "--", "rotate-signing-key", "--step", name)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit status %d", res.Code)
	}
	t.Logf("rotate-signing-key --step %s took %s", name, time.Since(started).Round(time.Second))
	if err != nil {
		t.Fatalf("mise run mgmt -- rotate-signing-key --step %s: %v\nstdout: %s\nstderr (the remaining commands):\n%s", name, err, res.Stdout, res.Stderr)
	}
	if strings.Count(res.Stdout, "\n") != 1 || json.Unmarshal([]byte(res.Stdout), &out) != nil {
		t.Fatalf("standard output of --step %s is %q, want one JSON line. stderr:\n%s", name, res.Stdout, res.Stderr)
	}
	return out
}

// opKeys returns the keys of ConfigMap mgmt-op-key in a cell, by file name.
func opKeys(t *testing.T, cell string) map[string]string {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "get", "configmap", "mgmt-op-key", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &cm); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for name, v := range cm.Data {
		if strings.HasSuffix(name, ".pub") {
			keys[name] = strings.TrimSpace(v)
		}
	}
	return keys
}

// celldReplicas returns the replicas of Deployment celld in a cell.
func celldReplicas(t *testing.T, cell string) string {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "get", "deployment", celldDeployment, "-o", "jsonpath={.spec.replicas}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// TestRotationSigningKey runs the overlap rotation of `mise run mgmt -- rotate-signing-key` step by step, because each cell:up pass
// takes the replica field of celld back. (1) --step stage, then --step cells: mgmt-op-key of each cell holds the live key and the
// staged key. (2) celld of dev-cell-1 goes to no replica. (3) An operation X is signed, and the queue of the gateway holds X with the
// old key epoch. (4) --step commit and --step planes: the queue holds X with the new key epoch. (5) --step cells again drops the old
// key and restores celld. Then mgmt-op-key holds only the new key, celld applies X once, mgmtd shows X as applied, and a new operation
// applies. If the re-sign or the envelope swap is skipped, celld sees only the old-key envelope, refuses it with signature_invalid, and
// X stays open. Afterwards mgmt-signing-pub, record_public_keys of the SPIRE server and mgmt-spec-key of envd hold the new key,
// cell-records verifies under it at the new epoch, a new celld pod in each cell attests, and cell:verify passes for management and
// dev-cp. The test logs the time of each step and the attestation gap: the time from the start of the SPIRE server container to the
// first log line with the records of the new epoch. In that time the plugin holds no records, so a new pod cannot attest. The name is
// outside the pattern of gate:m4.
func TestRotationSigningKey(t *testing.T) {
	const cell = rejectCell
	closer := newOpCloser(t)
	before := mgmtStatus(t)
	oldPub := mgmtSigningPub(t)
	started := time.Now()

	// (1) The stage, and the first cell pass.
	staged := rotateStep(t, "stage")
	if staged.Rotated || !staged.Staged || staged.New == "" || staged.Old == staged.New {
		t.Fatalf("the stage printed %+v, want a staged key that differs from the live key", staged)
	}
	rotateStep(t, "cells")
	for _, c := range clustersWith(t, agentCellSet) {
		keys := opKeys(t, c)
		if len(keys) != 2 || keys["op.pub"] != oldPub || keys["op.next.pub"] == "" || keys["op.next.pub"] == oldPub {
			t.Errorf("after the first cell pass mgmt-op-key of %s holds %v, want op.pub = the live key and op.next.pub = the staged key", c, keys)
		}
	}

	// (2), (3) An operation that mgmtd signs under the old key waits in the queue while celld is down.
	setReplicas(t, cell, celldNamespace, "deployment/"+celldDeployment, 0)
	t.Cleanup(func() { setReplicas(t, cell, celldNamespace, "deployment/"+celldDeployment, 1) })
	line := "m5 rotation " + randomHex(t, 4)
	id := opCreate(t, cell, line, 30*time.Minute)
	closer.add(id)
	if v := opGet(t, id); v.KeyEpoch != before.Signed.Epoch {
		t.Fatalf("the operation %s has the key epoch %d, want %d", id, v.KeyEpoch, before.Signed.Epoch)
	}
	waitFor(t, "the queue of the gateway to hold "+id+" with the old key epoch", 3*time.Minute, func() (bool, string) {
		row := queueRow(t, cell, id)
		return row.OpID == id && row.KeyEpoch == before.Signed.Epoch, fmt.Sprintf("row %+v", row)
	})

	// (4) The commit and the planes: the re-sign gives X an envelope of the new epoch, and the gateway swaps the row.
	commit := rotateStep(t, "commit")
	if !commit.Rotated || commit.Epoch != before.Signed.Epoch+1 || commit.New != staged.New {
		t.Fatalf("the commit printed %+v, want the staged key at the epoch %d", commit, before.Signed.Epoch+1)
	}
	rotateStep(t, "planes")
	waitFor(t, "the queue of the gateway to hold "+id+" with the new key epoch", 5*time.Minute, func() (bool, string) {
		row := queueRow(t, cell, id)
		return row.OpID == id && row.KeyEpoch == commit.Epoch, fmt.Sprintf("row %+v", row)
	})

	// (5) The second cell pass drops the old key and restores celld.
	rotateStep(t, "cells")
	took := time.Since(started)
	t.Logf("the rotation took %s in all", took.Round(time.Second))
	newPub := mgmtSigningPub(t)
	if newPub == oldPub || newPub != ctlPub(t) {
		t.Errorf("mgmt-signing-pub holds %q, mgmtd holds %q, and the old key was %q", newPub, ctlPub(t), oldPub)
	}
	for _, c := range clustersWith(t, agentCellSet) {
		if keys := opKeys(t, c); len(keys) != 1 || keys["op.pub"] != newPub {
			t.Errorf("after the second cell pass mgmt-op-key of %s holds %v, want only op.pub = the new key", c, keys)
		}
	}
	if got := celldReplicas(t, cell); got != "1" {
		t.Errorf("the second cell pass left %s replicas of celld in %s, want 1", got, cell)
	}
	waitOpReported(t, cell, id, opWait)
	if n := demoLogCount(t, cell, id); n != 1 {
		t.Errorf("demo-log in %s holds %d lines of %s, want 1", cell, n, id)
	}
	if v := opGet(t, id); v.State != "final" || v.Final != op.OutcomeApplied {
		t.Errorf("mgmtd shows the operation %s as state %q final %q, want final applied", id, v.State, v.Final)
	}
	nextID, nextEnvelope := opSign(t, cell, "m5 rotation next "+randomHex(t, 4), 0)
	closer.add(nextID)
	enqueueSigned(t, cell, nextEnvelope, false)
	waitOpReported(t, cell, nextID, opWait)

	conf, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "configmap", "spire-server", "-o", `jsonpath={.data.server\.conf}`)
	if err != nil {
		t.Fatal(err)
	}
	if m := recordKeysLine.FindStringSubmatch(conf); m == nil || strings.Trim(m[1], `" `) != newPub {
		t.Errorf("record_public_keys of the SPIRE server is %v, want [%q]", m, newPub)
	}
	specKey, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "get", "configmap", "mgmt-spec-key", "-o", `jsonpath={.data.spec\.pub}`)
	if err != nil || strings.TrimSpace(specKey) != newPub {
		t.Errorf("mgmt-spec-key holds %q (%v), want the new key", specKey, err)
	}
	waitFor(t, "cell-records signed under the new key at the epoch "+fmt.Sprint(commit.Epoch), 3*time.Minute, func() (bool, string) {
		sp, _, err := readLiveRecords(t)
		if err != nil {
			return false, err.Error()
		}
		return sp.Revision.Epoch == commit.Epoch, fmt.Sprintf("cell-records at %+v", sp.Revision)
	})

	for _, cell := range clustersWith(t, agentCellSet) {
		pod := replaceCelldPod(t, cell)
		waitCelldSVID(t, cell, pod)
	}
	cellVerify(t, mgmtCluster)
	cellVerify(t, spireCluster)

	// The attestation gap.
	start := serverStart(t)
	logs, err := serverLog(t, start.Add(-logMargin))
	if err != nil {
		t.Fatal(err)
	}
	var first time.Time
	for _, l := range matching(logs, func(l logLine) bool {
		epoch, _ := l["spec_epoch"].(float64)
		records, _ := l["records"].(float64)
		return uint64(epoch) == commit.Epoch && (l.str("msg") == "records reloaded" || (l.str("msg") == "configured" && records > 0))
	}) {
		if at, err := time.Parse(time.RFC3339Nano, l.str("time")); err == nil && (first.IsZero() || at.Before(first)) {
			first = at
		}
	}
	if first.IsZero() {
		t.Errorf("the SPIRE server log holds no line with the records of the epoch %d since %s", commit.Epoch, start.Format(time.RFC3339))
		return
	}
	t.Logf("ATTESTATION_GAP_SECONDS=%.0f: the SPIRE server container started at %s and held the records of the epoch %d at %s",
		first.Sub(start).Seconds(), start.Format(time.RFC3339), commit.Epoch, first.Format(time.RFC3339))
}
