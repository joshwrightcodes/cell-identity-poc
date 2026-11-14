//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	soakDuration = 30 * time.Minute
	soakInterval = time.Minute
	// soakClaimGap is the bound on the time from the enqueue of an operation at the gateway to the first record of it in the cell.
	// The gateway wakes the stream at once, and celld also claims every 10 s.
	soakClaimGap = 15 * time.Second
	soakPoll     = 500 * time.Millisecond
)

// TestStreamSoakHalfHour: for 30 minutes, an operation for dev-cell-1 goes into the gateway queue each minute. Each one is applied
// once. The gap between the enqueue and the claim, seen as the first appearance of the record op-<id> in the cell, stays below 15 s.
// The test logs the maximum gap and the reconnect count of the celld streams of the cell (the lines "stream ended" and
// "stream restarts for a new SVID" of its log since the start), which are verify row 1. The test records the count and does
// not bound it: celld opens a new stream at each SVID update, and a short SVID lifetime makes that often.
func TestStreamSoakHalfHour(t *testing.T) {
	const cell = rejectCell
	started := time.Now().Add(-logMargin)
	deadline := time.Now().Add(soakDuration)
	var ids []string
	var maxGap time.Duration
	t.Cleanup(func() {
		for _, id := range ids {
			if v := opGet(t, id); v.State != "final" {
				if _, err := mgmtCtlErr("op", "close", id); err != nil {
					t.Logf("could not close the operation %s: %v", id, err)
				}
			}
		}
	})
	for n := 1; time.Now().Before(deadline); n++ {
		tick := time.Now()
		line := fmt.Sprintf("m5 soak %d %s", n, randomHex(t, 3))
		id, envelope := opSign(t, cell, line, 0)
		ids = append(ids, id)
		enqueuedAt := time.Now()
		enqueueSigned(t, cell, envelope, false)
		gap := waitRecordAppears(t, cell, id, enqueuedAt)
		maxGap = max(maxGap, gap)
		if gap >= soakClaimGap {
			t.Errorf("operation %d (%s): the record appeared %s after the enqueue, want less than %s", n, id, gap.Round(time.Millisecond), soakClaimGap)
		}
		waitOpReported(t, cell, id, opWait)
		if c := demoLogCount(t, cell, id); c != 1 {
			t.Errorf("operation %d (%s): demo-log holds %d lines of it, want 1", n, id, c)
		}
		if v := opGet(t, id); v.Final != op.OutcomeApplied {
			t.Errorf("operation %d (%s): mgmtd shows the final result %q, want applied", n, id, v.Final)
		}
		t.Logf("operation %d applied %s after the enqueue, claim gap %s", n, time.Since(enqueuedAt).Round(time.Millisecond), gap.Round(time.Millisecond))
		if rest := soakInterval - time.Since(tick); rest > 0 && time.Now().Add(rest).Before(deadline) {
			time.Sleep(rest)
		}
	}
	ended, restarted := celldReconnects(t, cell, started)
	t.Logf("verify row 1: %d operations in %s, maximum claim gap %s, %d stream failures and %d restarts for a new SVID of the celld stream of %s",
		len(ids), soakDuration, maxGap.Round(time.Millisecond), ended, restarted, cell)
	if c := cellStatusOf(t, cell); c.ForgedSeen != 0 {
		t.Errorf("mgmtd counts %d forged results for %s, want 0", c.ForgedSeen, cell)
	}
}

// waitRecordAppears polls for the record op-<id> in cell and returns the time from since to its first appearance, with the polling
// delay inside it.
func waitRecordAppears(t *testing.T, cell, id string, since time.Time) time.Duration {
	t.Helper()
	limit := since.Add(opWait)
	for time.Now().Before(limit) {
		if opRecordState(t, cell, id) != "" {
			return time.Since(since)
		}
		time.Sleep(soakPoll)
	}
	t.Fatalf("no record op-%s appeared in %s within %s of the enqueue", id, cell, opWait)
	return 0
}

// celldReconnects counts the log lines of the celld pods of cell since a time that show that a stream failed ("stream ended"),
// and that it restarted for a new SVID.
func celldReconnects(t *testing.T, cell string, since time.Time) (ended, restarted int) {
	t.Helper()
	for _, p := range celldPods(t, cell) {
		logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", p.Metadata.Name, "-c", celldContainer, "--since-time="+since.UTC().Format(time.RFC3339))
		if err != nil {
			t.Fatal(err)
		}
		for l := range strings.SplitSeq(logs, "\n") {
			switch {
			case strings.Contains(l, `"msg":"stream ended"`):
				ended++
			case strings.Contains(l, `"msg":"stream restarts for a new SVID"`):
				restarted++
			}
		}
	}
	return ended, restarted
}
