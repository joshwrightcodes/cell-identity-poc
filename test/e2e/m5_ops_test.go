//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	// opWait bounds the time from the enqueue of an operation to its final result at mgmtd. It covers a claim, an apply, a report
	// round of envd and the ack.
	opWait = 2 * time.Minute
	// statusFresh is the age that a status report may have: celld reports every 30 s, plus or minus 20%, and each report goes
	// through envd rounds of 10 s.
	statusFresh = 90 * time.Second
	opRecordKey = `{.data.record\.json}`
)

// opRecordState returns the state of the operation record op-<id> in cell, or "" when the record does not exist.
func opRecordState(t *testing.T, cell, id string) string {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", gatewayCellOps, "get", "configmap", "op-"+id, "--ignore-not-found", "-o", "jsonpath="+opRecordKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) == "" {
		return ""
	}
	var r struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("the record op-%s in %s is no JSON: %v", id, cell, err)
	}
	return r.State
}

// demoLogCount returns how many lines of demo-log in cell start with the operation ID.
func demoLogCount(t *testing.T, cell, id string) int {
	t.Helper()
	n := 0
	for _, l := range demoLog(t, cell) {
		if strings.HasPrefix(l, id+" ") {
			n++
		}
	}
	return n
}

// enqueueSigned puts an envelope that mgmtd signed (opSign) into the queue of the gateway for cell. The gateway wakes the stream of the cell.
func enqueueSigned(t *testing.T, cell string, envelope []byte, replay bool) {
	t.Helper()
	args := []string{"enqueue", "--cell", cell}
	if replay {
		args = append(args, "--replay")
	}
	if out := gwCtl(t, string(envelope), args...); !strings.HasPrefix(out, "{") {
		t.Fatalf("cellgw ctl enqueue printed %q, want one JSON line", out)
	}
}

// waitOpReported waits until the record op-<id> of cell is reported. At each look, a record in the state reported must already
// have a final result of applied at mgmtd. The state is read first and mgmtd second, so a final result that mgmtd holds later
// cannot excuse a record that was reported too early. It returns the states that it saw, in order.
func waitOpReported(t *testing.T, cell, id string, timeout time.Duration) []string {
	t.Helper()
	var seen []string
	waitFor(t, "the record op-"+id+" in "+cell+" to be reported", timeout, func() (bool, string) {
		state := opRecordState(t, cell, id)
		if len(seen) == 0 || seen[len(seen)-1] != state {
			seen = append(seen, state)
		}
		v := opGet(t, id)
		if state == "reported" {
			if v.Final != op.OutcomeApplied {
				t.Fatalf("the record op-%s in %s is reported, and mgmtd shows the operation as state %q final %q, want applied", id, cell, v.State, v.Final)
			}
			return true, ""
		}
		return false, fmt.Sprintf("record %q, mgmtd state %q final %q", state, v.State, v.Final)
	})
	return seen
}

// TestM5CelldStreams: the gateway holds an open stream for each cell, and a new celld pod replaces the stream of the old one, so the
// count returns to one.
func TestM5CelldStreams(t *testing.T) {
	for _, cell := range clustersWith(t, agentCellSet) {
		waitFor(t, "an open stream of "+cell+" at the gateway", m5Wait, func() (bool, string) {
			s := gwStatus(t)
			return s.Streams[cell] >= 1, fmt.Sprintf("streams %v", s.Streams)
		})
	}
	cell := clustersWith(t, agentCellSet)[len(clustersWith(t, agentCellSet))-1]
	started := time.Now().Add(-logMargin)
	pod := replaceCelldPod(t, cell)
	waitCelldSVID(t, cell, pod)
	// The gateway logs stream_open with the UID of the pod. The count is read only after that line, so a stream of the deleted pod,
	// or an earlier count of one, cannot stand in for the stream of the new pod.
	waitFor(t, "the gateway to log stream_open of the new celld pod "+pod.Metadata.Name+" of "+cell, m5Wait, func() (bool, string) {
		logs, err := kubectl(t, spireCluster, "", "-n", gatewayNamespace, "logs", gatewayPod, "-c", "cellgw", "--since-time="+started.UTC().Format(time.RFC3339))
		if err != nil {
			return false, err.Error()
		}
		n := len(matching(logs, func(l logLine) bool {
			return l.str("msg") == "stream_open" && l.str("cell") == cell && l.str("pod") == pod.Metadata.UID
		}))
		return n > 0, lastLines(logs, 2)
	})
	waitFor(t, "one open stream of "+cell+" at the gateway after the new pod opened its stream", m5Wait, func() (bool, string) {
		s := gwStatus(t)
		return s.Streams[cell] == 1, fmt.Sprintf("streams %v", s.Streams)
	})
}

// TestM5OpAppliesOnce: an operation that mgmtd signed and the gateway queued is applied once in the cell. The record reaches
// reported only after mgmtd shows the final result applied. The demo log holds one line of the operation. A second enqueue of the same envelope
// (replay) makes celld answer already_applied, changes nothing in the cell, and leaves the final result at mgmtd as it was.
func TestM5OpAppliesOnce(t *testing.T) {
	const cell = rejectCell
	line := "m5 applies once " + randomHex(t, 4)
	id, envelope := opSign(t, cell, line, 0)
	t.Cleanup(func() {
		if v := opGet(t, id); v.State != "final" {
			if _, err := mgmtCtlErr("op", "close", id); err != nil {
				t.Logf("could not close the operation %s: %v", id, err)
			}
		}
	})
	enqueueSigned(t, cell, envelope, false)
	seen := waitOpReported(t, cell, id, opWait)
	t.Logf("the record of %s went through %q", id, seen)
	if n := demoLogCount(t, cell, id); n != 1 {
		t.Errorf("demo-log in %s holds %d lines of %s, want 1", cell, n, id)
	}
	if !slices.Contains(demoLog(t, cell), id+" "+line) {
		t.Errorf("demo-log in %s lacks the line %q", cell, id+" "+line)
	}
	v := opGet(t, id)
	if v.Final != op.OutcomeApplied || v.Result == nil || v.Result.Cell != cell {
		t.Errorf("mgmtd shows %+v for %s, want a final result applied from %s", v, id, cell)
	}

	replayedAt := time.Now().Add(-logMargin)
	enqueueSigned(t, cell, envelope, true)
	waitCelldSaw(t, cell, replayedAt, id, op.OutcomeAlreadyApplied, "", opWait)
	if n := demoLogCount(t, cell, id); n != 1 {
		t.Errorf("after a replay demo-log in %s holds %d lines of %s, want 1", cell, n, id)
	}
	if got := opGet(t, id); got.Final != op.OutcomeApplied {
		t.Errorf("after a replay mgmtd shows the final result %q for %s, want applied", got.Final, id)
	}
	if got := opRecordState(t, cell, id); got != "reported" {
		t.Errorf("after a replay the record of %s is %q, want reported", id, got)
	}
}

// TestM5StatusReported: each celld pod reports its status, and mgmtd shows a recent status from a live pod of each cell.
func TestM5StatusReported(t *testing.T) {
	for _, cell := range clustersWith(t, agentCellSet) {
		t.Run(cell, func(t *testing.T) {
			waitFor(t, "a status report of "+cell+" within "+statusFresh.String(), 3*time.Minute, func() (bool, string) {
				c := cellStatusOf(t, cell)
				live := map[string]bool{}
				for _, p := range celldPods(t, cell) {
					live[p.Metadata.Name] = true
				}
				ok := time.Since(c.LastStatusAt) < statusFresh && live[c.LastStatusPod]
				return ok, fmt.Sprintf("last status at %s from %q, live pods %v", c.LastStatusAt, c.LastStatusPod, live)
			})
		})
	}
}

// TestM5BindThroughGateway: a new celld pod binds through the bind listener of the gateway: it logs bound, mgmtd shows the cell as bound
// with an issuer, and the gateway holds no bind refusal for the cell from after the pod started. The log of the pod names no node port of
// the old bind route.
func TestM5BindThroughGateway(t *testing.T) {
	cell := clustersWith(t, agentCellSet)[0]
	started := time.Now().Add(-logMargin)
	pod := replaceCelldPod(t, cell)
	waitFor(t, "the new celld pod in "+cell+" to log bound", healWait, func() (bool, string) {
		logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", pod.Metadata.Name, "-c", celldContainer)
		if err != nil {
			return false, err.Error()
		}
		return strings.Contains(logs, `"msg":"bound"`), lastLines(logs, 3)
	})
	c := cellStatusOf(t, cell)
	if !c.Bound || c.Issuer == "" {
		t.Errorf("mgmtd shows %+v for %s, want a bound cell with an issuer", c, cell)
	}
	if r, ok := gwStatus(t).LastBindRefusal[cell]; ok && r.At.After(started) {
		t.Errorf("the gateway refused a bind of %s at %s, after the pod started at %s: %s", cell, r.At, started, r.Reason)
	}
	logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", pod.Metadata.Name, "-c", celldContainer)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs, ":30447") {
		t.Errorf("the celld log of %s names the old bind port 30447:\n%s", cell, lastLines(logs, 5))
	}
	waitCelldSVID(t, cell, pod)
}

// TestM5ReplicaCap: with three celld pods in one cell, the gateway keeps two open streams (the replica cap) and refuses the third with
// replica_cap, which the pod logs. The cleanup returns the Deployment to one replica through scripts/harness-replicas.sh.
func TestM5ReplicaCap(t *testing.T) {
	cells := clustersWith(t, agentCellSet)
	cell := cells[len(cells)-1]
	target := "deployment/" + celldDeployment
	t.Cleanup(func() {
		setReplicas(t, cell, celldNamespace, target, 1)
		deploymentRolledOut(t, cell, celldNamespace, celldDeployment)
		waitFor(t, "one open stream of "+cell+" after the scale down", m5Wait, func() (bool, string) {
			s := gwStatus(t)
			return s.Streams[cell] == 1, fmt.Sprintf("streams %v", s.Streams)
		})
	})
	setReplicas(t, cell, celldNamespace, target, 3)
	waitFor(t, "three Running celld pods in "+cell, 5*time.Minute, func() (bool, string) {
		running := 0
		for _, p := range celldPods(t, cell) {
			if p.Status.Phase == "Running" {
				running++
			}
		}
		return running == 3, fmt.Sprintf("%d Running pods", running)
	})
	waitFor(t, "a celld pod of "+cell+" to log replica_cap", 5*time.Minute, func() (bool, string) {
		for _, p := range celldPods(t, cell) {
			logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", p.Metadata.Name, "-c", celldContainer)
			if err == nil && strings.Contains(logs, "replica_cap") {
				return true, ""
			}
		}
		return false, "no pod logs replica_cap"
	})
	// Each pod restarts its stream for a new SVID about every 27 s, so a sample can fall in a reconnect window. No sample may show more than
	// the cap, and at least one sample in 60 s must show exactly the cap.
	atCap := false
	for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(3 * time.Second) {
		n := gwStatus(t).Streams[cell]
		if n > 2 {
			t.Fatalf("the gateway holds %d streams of %s with three pods, want at most 2 (the replica cap)", n, cell)
		}
		atCap = atCap || n == 2
	}
	if !atCap {
		t.Errorf("no sample in 60 s showed 2 streams of %s with three pods", cell)
	}
}
