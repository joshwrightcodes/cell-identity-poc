//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gateway"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
)

const (
	refusalCell1 = "dev-cell-1"
	refusalCell2 = "dev-cell-2"
	// refusalWait bounds the time from an enqueue to a refusal that celld logs and that mgmtd counts.
	refusalWait = 60 * time.Second
	// forgedGap is longer than the 10 s that celld keeps between two results with an empty operation ID on one stream.
	forgedGap = 11 * time.Second
	// bindGap is the time between two subtests of the bind refusals.
	bindGap = 15 * time.Second
)

// cellToken runs kubectl create token with the admin kubeconfig of the cell, as the cell itself could, for the service account in the
// namespace and the pod that the token binds to. The token stays in memory.
func cellToken(t *testing.T, cell, namespace, serviceAccount, pod, podUID, audience string) string {
	t.Helper()
	tok, err := kubectl(t, cell, "", "-n", namespace, "create", "token", serviceAccount, "--audience", audience, "--duration", "10m",
		"--bound-object-kind", "Pod", "--bound-object-name", pod, "--bound-object-uid", podUID)
	if err != nil {
		t.Fatalf("the token of %s/%s in %s: %v", namespace, serviceAccount, cell, err)
	}
	return strings.TrimSpace(tok)
}

// livePod returns the name and UID of a Running pod of the app in the namespace of the cell, one that is not being deleted.
func livePod(t *testing.T, cell, namespace, app string) (name, uid string) {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", namespace, "get", "pods", "-l", "app.kubernetes.io/name="+app, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				Name, UID         string
				DeletionTimestamp *string `json:"deletionTimestamp"`
			} `json:"metadata"`
			Status struct{ Phase string } `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &pods); err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		if p.Status.Phase == "Running" && p.Metadata.DeletionTimestamp == nil {
			return p.Metadata.Name, p.Metadata.UID
		}
	}
	t.Fatalf("no running pod of %s in %s/%s", app, cell, namespace)
	return "", ""
}

// opCloser ends every operation of a test before the test returns, so that none stays open for the status of the harness, and drains
// each forged row that the test queued. One cleanup of the parent test waits for the last expiry, so the subtests do not wait one by one.
type opCloser struct {
	ids    []string
	drains []drain
}

// drain is a queue row of a cell whose envelope is forged. After the operation expires, the genuine envelope replaces the row.
type drain struct {
	cell, id string
	genuine  []byte
}

// newOpCloser registers the cleanup of t. Register it before any cleanup that celld needs, because cleanups run in reverse order.
func newOpCloser(t *testing.T) *opCloser {
	t.Helper()
	c := &opCloser{}
	t.Cleanup(func() { c.run(t) })
	return c
}

// add makes the cleanup close the operation, after its expiry, when mgmtd does not show it as final.
func (c *opCloser) add(id string) { c.ids = append(c.ids, id) }

// addForged also makes the cleanup replace the row of the cell for the operation with the genuine envelope.
func (c *opCloser) addForged(cell, id string, genuine []byte) {
	c.add(id)
	c.drains = append(c.drains, drain{cell, id, genuine})
}

func (c *opCloser) run(t *testing.T) {
	for _, id := range c.ids {
		v := opGet(t, id)
		if v.State == "final" {
			continue
		}
		// mgmtd closes an operation only after its expiry and a grace time of 60 s.
		waitFor(t, "operation "+id+" to be final or expired", time.Until(v.ExpiresAt)+3*time.Minute, func() (bool, string) {
			return opGet(t, id).State != "open", "state still open"
		})
	}
	for _, d := range c.drains {
		if queueRow(t, d.cell, d.id).State == gateway.StateDone {
			continue
		}
		// A replay deletes the row of the cell for the ID, so it replaces the held row. celld answers expired, which ends the row.
		enqueueSigned(t, d.cell, d.genuine, true)
	}
	for _, d := range c.drains {
		waitRowDone(t, d.cell, d.id)
	}
	// envd relays the result of celld to mgmtd every 10 s, so the result can make the operation final between the read and the close.
	for _, id := range c.ids {
		if opGet(t, id).State != "final" {
			if out, err := mgmtCtlErr("op", "close", id); err != nil && opGet(t, id).State != "final" {
				t.Errorf("could not close the operation %s: %v %s", id, err, out)
			}
		}
	}
}

// queueRow returns the only row of the cell for the operation ID in the queue of the gateway. It fails the test when there are two rows,
// and returns an empty entry when there is none.
func queueRow(t *testing.T, cell, id string) gateway.QueueEntry {
	t.Helper()
	var res struct {
		Items []gateway.QueueEntry `json:"items"`
	}
	if err := json.Unmarshal([]byte(gwCtl(t, "", "queue", "--cell", cell)), &res); err != nil {
		t.Fatalf("cellgw ctl queue is no list: %v", err)
	}
	var rows []gateway.QueueEntry
	for _, e := range res.Items {
		if e.OpID == id {
			rows = append(rows, e)
		}
	}
	if len(rows) > 1 {
		t.Fatalf("the queue of %s holds %d rows for %s, want one", cell, len(rows), id)
	}
	if len(rows) == 0 {
		return gateway.QueueEntry{}
	}
	return rows[0]
}

// waitRowDone waits until the row of the cell for the operation is done.
func waitRowDone(t *testing.T, cell, id string) {
	t.Helper()
	waitFor(t, "the queue row of "+cell+" for "+id+" to be done", 2*time.Minute, func() (bool, string) {
		r := queueRow(t, cell, id)
		return r.State == gateway.StateDone, fmt.Sprintf("state %q, claims %d", r.State, r.Claims)
	})
}

// operationOf decodes the signed payload of an envelope without checking it.
func operationOf(t *testing.T, envelope []byte) op.Operation {
	t.Helper()
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("the envelope is no JSON: %v", err)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var o op.Operation
	if err := json.Unmarshal(body, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// signedByRogue signs the operation with a new key that no cell trusts.
func signedByRogue(t *testing.T, o op.Operation) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := op.Sign(o, key)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// tamperedEnvelope changes the line in the payload of a genuine envelope and keeps its signature.
func tamperedEnvelope(t *testing.T, genuine []byte) []byte {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(genuine, &env); err != nil {
		t.Fatal(err)
	}
	o := operationOf(t, genuine)
	o.Args, _ = json.Marshal(map[string]string{"line": "tampered " + randomHex(t, 4)})
	body, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	env["payload"], _ = json.Marshal(base64.StdEncoding.EncodeToString(body))
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// unsignedEnvelope removes every signature of a genuine envelope.
func unsignedEnvelope(t *testing.T, genuine []byte) []byte {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(genuine, &env); err != nil {
		t.Fatal(err)
	}
	env["signatures"] = json.RawMessage("[]")
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// celldSaw reports whether a celld pod of the cell logged "operation result" since a time with the outcome and reason, for the
// operation: the ID is the op_id of the line, or its peeked_id when the signature failed.
func celldSaw(t *testing.T, cell string, since time.Time, id, outcome, reason string) (bool, string) {
	t.Helper()
	var last string
	for _, p := range celldPods(t, cell) {
		logs, err := podLog(t, cell, p.Metadata.Name, celldContainer, since)
		if err != nil {
			return false, err.Error()
		}
		for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "operation result" }) {
			last = fmt.Sprintf("%s/%s for %s%s", l.str("outcome"), l.str("reason"), l.str("op_id"), l.str("peeked_id"))
			if (l.str("op_id") == id || l.str("peeked_id") == id) && l.str("outcome") == outcome && l.str("reason") == reason {
				return true, ""
			}
		}
	}
	return false, "last operation result line: " + last
}

func waitCelldSaw(t *testing.T, cell string, since time.Time, id, outcome, reason string, timeout time.Duration) {
	t.Helper()
	waitFor(t, fmt.Sprintf("a celld log line of %s with %s %s for %s", cell, outcome, reason, id), timeout, func() (bool, string) {
		return celldSaw(t, cell, since, id, outcome, reason)
	})
}

// waitForgedSeen waits until mgmtd counts more forged_seen results of the cell than before. The count is a total with no operation ID, and
// its log line is rate limited, so a false forged_seen (the stream residual of poc-scope.md) can satisfy it. The celld log line, requireOpOpen
// and the unchanged demo log carry the claim of each subtest, and this wait shows only that mgmtd counted a forged result.
func waitForgedSeen(t *testing.T, cell string, before int, timeout time.Duration) {
	t.Helper()
	waitFor(t, "mgmtd to count a forged_seen result of "+cell+" above "+fmt.Sprint(before), timeout, func() (bool, string) {
		n := cellStatusOf(t, cell).ForgedSeen
		return n > before, fmt.Sprintf("forgedSeen %d", n)
	})
}

// requireNoRecord fails when the cell holds the record op-<id>.
func requireNoRecord(t *testing.T, cell, id string) {
	t.Helper()
	if s := opRecordState(t, cell, id); s != "" {
		t.Errorf("%s holds the record op-%s in the state %q, want none", cell, id, s)
	}
}

// requireDemoLog fails when demo-log of the cell differs from lines.
func requireDemoLog(t *testing.T, cell string, lines []string) {
	t.Helper()
	if got := demoLog(t, cell); !slices.Equal(got, lines) {
		t.Errorf("demo-log of %s changed: %d lines before, %d now", cell, len(lines), len(got))
	}
}

// requireOpOpen fails unless mgmtd shows the operation as open with no result.
func requireOpOpen(t *testing.T, id string) {
	t.Helper()
	if v := opGet(t, id); v.State != "open" || v.Final != "" || v.Result != nil || !v.ResultAt.IsZero() {
		t.Errorf("mgmtd shows the operation %s as state %q final %q result %v, want open with no result", id, v.State, v.Final, v.Result)
	}
}

// TestM5ForgedOpRefused: an envelope that a rogue key signed, one whose payload changed after the signing, and one with no signature are
// each refused by celld with signature_invalid. The demo log does not change, celld makes no record, and mgmtd counts one more forged_seen
// result for the cell. celld sends one result with an empty operation ID in each 10 s on a stream, so each subtest waits 11 s after the
// result of the one before.
func TestM5ForgedOpRefused(t *testing.T) {
	const cell = refusalCell1
	closer := newOpCloser(t)
	var last time.Time
	forged := map[string]func(t *testing.T, genuine []byte) []byte{
		"rogue_key": func(t *testing.T, genuine []byte) []byte { return signedByRogue(t, operationOf(t, genuine)) },
		"tampered":  tamperedEnvelope,
		"unsigned":  unsignedEnvelope,
	}
	for _, name := range []string{"rogue_key", "tampered", "unsigned"} {
		t.Run(name, func(t *testing.T) {
			id, genuine := opSign(t, cell, "m5 "+name+" "+randomHex(t, 4), time.Minute)
			closer.addForged(cell, id, genuine)
			time.Sleep(time.Until(last.Add(forgedGap)))
			before := demoLog(t, cell)
			seen := cellStatusOf(t, cell).ForgedSeen
			since := time.Now().Add(-logMargin)
			enqueueSigned(t, cell, forged[name](t, genuine), false)
			waitCelldSaw(t, cell, since, id, op.OutcomeRefused, op.ReasonSignatureInvalid, refusalWait)
			last = time.Now()
			waitForgedSeen(t, cell, seen, refusalWait)
			requireDemoLog(t, cell, before)
			requireNoRecord(t, cell, id)
			requireOpOpen(t, id)
		})
	}
}

// TestM5ForgedEnvelopeCannotCloseOp: with both celld at zero replicas, a rogue-signed envelope with the ID of the open operation X sits in
// the queue of dev-cell-1, and the genuine X sits in the queue of dev-cell-2. dev-cell-1 refuses the forged one with signature_invalid, and
// dev-cell-2 refuses X with wrong_target. mgmtd counts forged_seen for both cells, and X stays open. Then the genuine X goes into the queue of
// dev-cell-1: it is applied once there, and mgmtd closes X with that result.
func TestM5ForgedEnvelopeCannotCloseOp(t *testing.T) {
	target := "deployment/" + celldDeployment
	cells := []string{refusalCell1, refusalCell2}
	closer := newOpCloser(t)
	t.Cleanup(func() {
		for _, c := range cells {
			setReplicas(t, c, celldNamespace, target, 1)
		}
		for _, c := range cells {
			deploymentRolledOut(t, c, celldNamespace, celldDeployment)
		}
	})
	for _, c := range cells {
		setReplicas(t, c, celldNamespace, target, 0)
	}
	line := "m5 forged cannot close " + randomHex(t, 4)
	id := opCreate(t, refusalCell1, line, 5*time.Minute)
	genuine := []byte(opGet(t, id).Envelope)
	if len(genuine) == 0 {
		t.Fatalf("mgmtd gave no envelope for %s", id)
	}
	closer.addForged(refusalCell1, id, genuine)
	forged := signedByRogue(t, operationOf(t, genuine))
	seen1, seen2 := cellStatusOf(t, refusalCell1).ForgedSeen, cellStatusOf(t, refusalCell2).ForgedSeen
	before1, before2 := demoLog(t, refusalCell1), demoLog(t, refusalCell2)
	enqueueSigned(t, refusalCell1, forged, true)
	enqueueSigned(t, refusalCell2, genuine, true)

	since := time.Now().Add(-logMargin)
	for _, c := range cells {
		setReplicas(t, c, celldNamespace, target, 1)
	}
	waitCelldSaw(t, refusalCell1, since, id, op.OutcomeRefused, op.ReasonSignatureInvalid, 5*time.Minute)
	waitCelldSaw(t, refusalCell2, since, id, op.OutcomeRefused, op.ReasonWrongTarget, 5*time.Minute)
	waitForgedSeen(t, refusalCell1, seen1, refusalWait)
	waitForgedSeen(t, refusalCell2, seen2, refusalWait)
	requireOpOpen(t, id)
	requireDemoLog(t, refusalCell1, before1)
	requireDemoLog(t, refusalCell2, before2)
	requireNoRecord(t, refusalCell1, id)
	requireNoRecord(t, refusalCell2, id)

	enqueueSigned(t, refusalCell1, genuine, true)
	waitOpReported(t, refusalCell1, id, opWait)
	v := opGet(t, id)
	if v.Final != op.OutcomeApplied || v.Result == nil || v.Result.Cell != refusalCell1 {
		t.Errorf("mgmtd shows %+v for %s, want a final result applied from %s", v, id, refusalCell1)
	}
	if n := demoLogCount(t, refusalCell1, id); n != 1 {
		t.Errorf("demo-log of %s holds %d lines of %s, want 1", refusalCell1, n, id)
	}
	if n := demoLogCount(t, refusalCell2, id); n != 0 {
		t.Errorf("demo-log of %s holds %d lines of %s, want 0", refusalCell2, n, id)
	}
	waitRowDone(t, refusalCell1, id)
	waitRowDone(t, refusalCell2, id)
}

// waitEnvdSyncs waits until envd has synced with the gateway n more times, seen as n distinct values of the sync time.
func waitEnvdSyncs(t *testing.T, n int, timeout time.Duration) {
	t.Helper()
	last, seen := gwStatus(t).SyncedAt, 0
	waitFor(t, fmt.Sprintf("envd to sync with the gateway %d more times", n), timeout, func() (bool, string) {
		if at := gwStatus(t).SyncedAt; !at.Equal(last) {
			last, seen = at, seen+1
		}
		return seen >= n, fmt.Sprintf("%d syncs seen, last at %s", seen, last)
	})
}

// outboxHasOp reports whether the outbox of the gateway holds an item with the operation ID.
func outboxHasOp(t *testing.T, id string) bool {
	t.Helper()
	var res struct {
		Items []struct {
			OpID string `json:"opId"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(gwCtl(t, "", "outbox")), &res); err != nil {
		t.Fatalf("cellgw ctl outbox is no list: %v", err)
	}
	for _, it := range res.Items {
		if it.OpID == id {
			return true
		}
	}
	return false
}

// TestM5ReplayedOpAppliesOnce: after an operation is applied and reported, the same envelope queued again (replay) makes celld answer
// already_applied. The demo log keeps one line of the operation, mgmtd keeps the final result and its time, the record stays reported, and the
// answer of mgmtd (duplicate) takes the item out of the outbox of the gateway. The outbox check starts after three envd syncs that follow
// the celld log line, so that the absence does not come from an item that has not arrived yet.
func TestM5ReplayedOpAppliesOnce(t *testing.T) {
	const cell = refusalCell1
	id := opCreate(t, cell, "m5 replayed "+randomHex(t, 4), 2*time.Minute)
	newOpCloser(t).add(id)
	waitOpReported(t, cell, id, opWait)
	first := opGet(t, id)
	if first.Final != op.OutcomeApplied || len(first.Envelope) == 0 {
		t.Fatalf("mgmtd shows %+v for %s, want applied and an envelope", first, id)
	}
	since := time.Now().Add(-logMargin)
	enqueueSigned(t, cell, []byte(first.Envelope), true)
	waitCelldSaw(t, cell, since, id, op.OutcomeAlreadyApplied, "", refusalWait)
	// The item of the replay can leave the outbox before the first poll, so an absence alone proves nothing. The result of celld
	// reaches the outbox seconds after the log line, and envd takes it in its next round. Three rounds after the log line cover
	// the arrival, the peek and the ack of mgmtd. Only then does the absence count.
	waitEnvdSyncs(t, 3, m5Wait)
	waitFor(t, "the outbox of the gateway to hold no item of "+id, refusalWait, func() (bool, string) {
		return !outboxHasOp(t, id), "an item of the operation is still in the outbox"
	})
	if n := demoLogCount(t, cell, id); n != 1 {
		t.Errorf("demo-log of %s holds %d lines of %s, want 1", cell, n, id)
	}
	second := opGet(t, id)
	if second.Final != op.OutcomeApplied || !second.ResultAt.Equal(first.ResultAt) {
		t.Errorf("mgmtd shows the final result %q at %s after the replay, want applied at %s", second.Final, second.ResultAt, first.ResultAt)
	}
	if got := opRecordState(t, cell, id); got != "reported" {
		t.Errorf("the record of %s is %q after the replay, want reported", id, got)
	}
}

// TestM5ExpiredOpRefused: celld does not apply an operation after its expiry. It answers expired, the demo log does not change and no
// record exists.
func TestM5ExpiredOpRefused(t *testing.T) {
	const cell = refusalCell1
	id, envelope := opSign(t, cell, "m5 expired "+randomHex(t, 4), time.Second)
	newOpCloser(t).add(id)
	before := demoLog(t, cell)
	time.Sleep(3 * time.Second)
	since := time.Now().Add(-logMargin)
	enqueueSigned(t, cell, envelope, false)
	waitCelldSaw(t, cell, since, id, op.OutcomeExpired, "", refusalWait)
	requireDemoLog(t, cell, before)
	requireNoRecord(t, cell, id)
	waitFor(t, "mgmtd to show the operation "+id+" as not open", refusalWait, func() (bool, string) {
		v := opGet(t, id)
		return v.State != "open", "state " + v.State
	})
	if v := opGet(t, id); v.Final == op.OutcomeApplied {
		t.Errorf("mgmtd shows the expired operation %s as applied", id)
	}
}

// TestM5WrongTargetRefused: an envelope that is signed for dev-cell-1 and queued for dev-cell-2 (replay) is refused by celld of dev-cell-2
// with wrong_target. No demo log changes, no record exists, mgmtd counts forged_seen for dev-cell-2, and the operation stays open.
func TestM5WrongTargetRefused(t *testing.T) {
	id, envelope := opSign(t, refusalCell1, "m5 wrong target "+randomHex(t, 4), time.Minute)
	newOpCloser(t).add(id)
	before1, before2 := demoLog(t, refusalCell1), demoLog(t, refusalCell2)
	seen := cellStatusOf(t, refusalCell2).ForgedSeen
	since := time.Now().Add(-logMargin)
	enqueueSigned(t, refusalCell2, envelope, true)
	waitCelldSaw(t, refusalCell2, since, id, op.OutcomeRefused, op.ReasonWrongTarget, refusalWait)
	waitForgedSeen(t, refusalCell2, seen, refusalWait)
	requireOpOpen(t, id)
	requireDemoLog(t, refusalCell1, before1)
	requireDemoLog(t, refusalCell2, before2)
	requireNoRecord(t, refusalCell1, id)
	requireNoRecord(t, refusalCell2, id)
	waitRowDone(t, refusalCell2, id)
}

// resultBody returns the compact JSON of a result of the operation, as celld sends it.
func resultBody(t *testing.T, cell, id string, envelope []byte) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(op.Result{OpID: id, Cell: cell, Outcome: op.OutcomeApplied, At: time.Now().UTC().Truncate(time.Second),
		EnvelopeSHA256: op.EnvelopeSHA256(envelope)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// injectItem puts one item into the outbox of the gateway and returns its ID. The item leaves the outbox when envd takes it.
func injectItem(t *testing.T, it gwapi.Item) string {
	t.Helper()
	raw, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}
	var added struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(gwCtl(t, string(raw), "inject")), &added); err != nil || added.ID == "" {
		t.Fatalf("cellgw ctl inject gave no item ID: %v", err)
	}
	return added.ID
}

// waitItemTaken waits until envd has taken the item out of the outbox.
func waitItemTaken(t *testing.T, itemID string) {
	t.Helper()
	waitFor(t, "envd to take the injected item "+itemID+" out of the outbox", m5Wait, func() (bool, string) {
		return !slices.Contains(outboxIDs(t), itemID), "the item is still in the outbox"
	})
}

// retryCounts returns the value of each series of mgmtd.report.retry_unknown_kid for the cell in the metric store, by its labels. A
// restart of mgmtd resets the counter under the same labels, so the window is short: it holds only the points of the running process.
func retryCounts(t *testing.T, cell string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, s := range promSamplesFrom(t, fmt.Sprintf(`mgmtd_report_retry_unknown_kid_total{cell=%q}`, cell), "now-2m") {
		out[fmt.Sprint(s.labels)] = s.last
	}
	return out
}

// retryRise returns how much the series of retryCounts rose since before. A series that is new counts from zero.
func retryRise(before, now map[string]float64) float64 {
	var rise float64
	for k, v := range now {
		rise += max(0, v-before[k])
	}
	return rise
}

// TestM5DevCPCannotPoseOnReports: dev-cp can inject any item into the outbox of the gateway, and the item still needs the proof of the pod
// for its exact body. The operation of each subtest is signed and not served, so celld never applies it. mgmtd refuses an item with no token
// (proof_missing), with a token for another body, another kind or another subject, and it answers retry with unknown_kid for a token of a
// key that the record of the cell does not hold (a rogue cluster, and the other cell). None of them gives the operation a result. The
// control, a token of the real celld pod for the exact body, is accepted.
func TestM5DevCPCannotPoseOnReports(t *testing.T) {
	const cell = refusalCell1
	podName, podUID := livePod(t, cell, celldNamespace, celldDeployment)
	otherPod, otherUID := livePod(t, refusalCell2, celldNamespace, celldDeployment)
	otelPod, otelUID := livePod(t, cell, streamAccount["otel"].ns, streamAccount["otel"].app)
	audience := func(kind string, body []byte) string { return proof.ReportAudience(cell, kind, body) }

	type pose struct {
		name string
		// token returns the token of the item for its body.
		token func(body []byte) string
		// refusal is the reason and detail that mgmtd keeps as the last refusal of the cell, or empty for a retry.
		reason, detail string
		retry          bool
	}
	poses := []pose{
		{name: "no_token", token: func([]byte) string { return "" }, reason: mgmtapi.ReasonProofMissing},
		{name: "rogue_key", retry: true, token: func(body []byte) string { return rogueToken(t, audience("result", body)) }},
		{name: "other_body", reason: mgmtapi.ReasonProofInvalid, detail: string(clusterjwt.WrongAudience), token: func([]byte) string {
			return cellToken(t, cell, celldNamespace, celldAccount, podName, podUID, audience("result", []byte(`{"cell":"`+cell+`","other":"body"}`)))
		}},
		{name: "other_kind", reason: mgmtapi.ReasonProofInvalid, detail: string(clusterjwt.WrongAudience), token: func(body []byte) string {
			return cellToken(t, cell, celldNamespace, celldAccount, podName, podUID, audience("status", body))
		}},
		{name: "other_subject", reason: mgmtapi.ReasonProofInvalid, detail: "subject_mismatch", token: func(body []byte) string {
			a := streamAccount["otel"]
			return cellToken(t, cell, a.ns, a.account, otelPod, otelUID, audience("result", body))
		}},
		{name: "other_cell", retry: true, token: func(body []byte) string {
			return cellToken(t, refusalCell2, celldNamespace, celldAccount, otherPod, otherUID, audience("result", body))
		}},
	}
	closer := newOpCloser(t)
	for _, p := range poses {
		t.Run(p.name, func(t *testing.T) {
			// The operation must stay open for the waits of the subtest, so its lifetime is long.
			id, envelope := opSign(t, cell, "m5 pose "+p.name+" "+randomHex(t, 4), 4*time.Minute)
			closer.add(id)
			body := resultBody(t, cell, id, envelope)
			token := p.token(body)
			before := cellStatusOf(t, cell)
			beforeMetric := retryCounts(t, cell)
			if p.name == "rogue_key" {
				// mgmtd queues at most one hint check for each cell in 60 s.
				waitFor(t, "the last hint check of "+cell+" to be older than 70 s", 3*time.Minute, func() (bool, string) {
					at := cellStatusOf(t, cell).HintAt
					return time.Since(at) > 70*time.Second, "hintAt " + at.String()
				})
				before = cellStatusOf(t, cell)
				beforeMetric = retryCounts(t, cell)
			}
			injected := time.Now().Add(-logMargin)
			waitItemTaken(t, injectItem(t, gwapi.Item{Kind: gwapi.KindResult, Cell: cell, OpID: id, Body: body, Token: token}))
			if p.retry {
				waitFor(t, "the retry_unknown_kid counter of "+cell+" to rise by one", 3*time.Minute, func() (bool, string) {
					n := retryRise(beforeMetric, retryCounts(t, cell))
					return n >= 1, fmt.Sprintf("counter rose by %v", n)
				})
				if n := retryRise(beforeMetric, retryCounts(t, cell)); n != 1 {
					t.Errorf("the retry_unknown_kid counter of %s rose by %v, want 1", cell, n)
				}
				after := cellStatusOf(t, cell)
				if p.name == "rogue_key" && !after.HintAt.After(before.HintAt) {
					t.Errorf("hintAt of %s is %s, want a hint check after %s", cell, after.HintAt, before.HintAt)
				}
				if after.ForgedSeen != before.ForgedSeen {
					t.Errorf("forgedSeen of %s moved from %d to %d", cell, before.ForgedSeen, after.ForgedSeen)
				}
				if (after.LastRefusal == nil) != (before.LastRefusal == nil) || (after.LastRefusal != nil && !after.LastRefusal.At.Equal(before.LastRefusal.At)) {
					t.Errorf("lastRefusal of %s moved from %+v to %+v for a retry", cell, before.LastRefusal, after.LastRefusal)
				}
			} else {
				waitFor(t, fmt.Sprintf("mgmtd to keep the refusal %s %s of %s", p.reason, p.detail, cell), refusalWait, func() (bool, string) {
					r := cellStatusOf(t, cell).LastRefusal
					if r == nil {
						return false, "no last refusal"
					}
					ok := r.Kind == "result" && r.Reason == p.reason && r.Detail == p.detail && r.At.After(injected)
					return ok, fmt.Sprintf("last refusal %+v", *r)
				})
			}
			requireOpOpen(t, id)
		})
	}
	t.Run("real_token", func(t *testing.T) {
		id, envelope := opSign(t, cell, "m5 pose real token "+randomHex(t, 4), 4*time.Minute)
		closer.add(id)
		body := resultBody(t, cell, id, envelope)
		token := cellToken(t, cell, celldNamespace, celldAccount, podName, podUID, audience("result", body))
		waitItemTaken(t, injectItem(t, gwapi.Item{Kind: gwapi.KindResult, Cell: cell, OpID: id, Body: body, Token: token}))
		waitFor(t, "mgmtd to accept the result of "+id, refusalWait, func() (bool, string) {
			v := opGet(t, id)
			return v.State == "final", "state " + v.State
		})
		if v := opGet(t, id); v.Final != op.OutcomeApplied || v.Result == nil || v.Result.Cell != cell {
			t.Errorf("mgmtd shows %+v for %s, want a final result applied from %s", v, id, cell)
		}
	})
}

// denialRun runs the Job and returns its lines and the request ID of its last line, which must be denied:<request ID>.
func denialRun(t *testing.T, j probeJob) ([]string, string) {
	t.Helper()
	lines := j.run1(t)
	m := denialLine.FindStringSubmatch(lastLine(t, lines))
	if m == nil {
		t.Fatalf("the last line is %q, want denied:<request ID> with 16 hex digits", lastLine(t, lines))
	}
	return lines, m[1]
}

// TestM5BindFloodOtherCellRefused: a Job in dev-cell-1 posts 50 binds for dev-cell-2 through the bind listener of the gateway. The source
// address is the node of dev-cell-1, so each post is refused with HTTP 403 (the probe prints denied) and the gateway log names
// source_mismatch. A new celld pod of dev-cell-2 then binds with already_bound.
func TestM5BindFloodOtherCellRefused(t *testing.T) {
	const from, target = refusalCell1, refusalCell2
	needAttestprobeImage(t)
	ns := m5Namespace(t, from)
	copyTrustBundle(t, from, ns)
	secret := tokenSecret(t, from, ns, "not.a.token")
	flood := bindProbe(t, from, ns, "default", "--cell", target, "--variant", "good", "--nonce", "x", "--token-file", "/run/attestprobe/token")
	flood.secret = secret
	flood.completions, flood.parallelism, flood.backoffLimit = 50, 2, 10
	started := time.Now().Add(-logMargin)
	flood.start(t)
	succeeded, failed, done := flood.wait(t, 10*time.Minute)
	t.Logf("the flood Job: %d pods succeeded, %d failed, complete %t", succeeded, failed, done)
	if !done || succeeded != 50 {
		t.Errorf("%d of the 50 binds finished", succeeded)
	}
	logs, err := kubectl(t, from, "", "-n", ns, "logs", "-l", probeLabel+"="+flood.run, "--max-log-requests=50", "--tail=-1")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(logs, "denied:"); n != 50 {
		t.Errorf("%d of the 50 pods printed denied, want 50", n)
	}
	gwLogs, err := kubectl(t, spireCluster, "", "-n", gatewayNamespace, "logs", gatewayPod, "-c", "cellgw", "--since-time="+started.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	if len(matching(gwLogs, func(l logLine) bool {
		return l.str("msg") == "bind_denied" && l.str("reason") == gwapi.ReasonSourceMismatch
	})) == 0 {
		t.Errorf("the cellgw log holds no bind_denied line with source_mismatch")
	}
	pod := replaceCelldPod(t, target)
	waitFor(t, "the new celld pod of "+target+" to log a bind with the status already_bound", 2*time.Minute, func() (bool, string) {
		out, err := kubectl(t, target, "", "-n", celldNamespace, "logs", pod.Metadata.Name, "-c", celldContainer)
		if err != nil {
			return false, err.Error()
		}
		return len(matching(out, func(l logLine) bool { return l.str("msg") == "bound" && l.str("status") == mgmtapi.StatusAlreadyBound })) > 0, lastLines(out, 2)
	})
}

// TestM5BindRefusalsLive: bind requests from Jobs in dev-cell-1 through the bind listener of the gateway. The gateway refuses a token for
// another subject, another nonce or the attestation audience (token_invalid), and a request for an unknown cell (source_mismatch). Each prints denied and a
// request ID, and the cellgw log line with that ID holds the reason. A reused nonce and a good request print bound:already_bound. A token that
// a rogue cluster signed and a token with an unknown key ID pass the precheck of the gateway, and mgmtd refuses them with token_invalid, which
// shows as the last refusal of the cell. The record revisions of both cells do not change.
func TestM5BindRefusalsLive(t *testing.T) {
	const cell = rejectCell
	needAttestprobeImage(t)
	revisions := recordRevisions(t)
	ns := bindNamespace(t, cell)

	last := time.Now()
	// denied runs a one-pod Job and checks that the gateway log explains its refusal.
	denied := func(t *testing.T, j probeJob, reason string, details ...string) []string {
		t.Helper()
		time.Sleep(time.Until(last.Add(bindGap)))
		start := time.Now().Add(-logMargin)
		lines, id := denialRun(t, j)
		last = time.Now()
		l := gatewayDenial(t, id, start)
		if l.str("reason") != reason || (len(details) > 0 && !slices.Contains(details, l.str("detail"))) {
			t.Errorf("the cellgw line for %s has reason %q and detail %q, want %s and one of %v", id, l.str("reason"), l.str("detail"), reason, details)
		}
		t.Logf("request %s: reason %s, detail %q", id, l.str("reason"), l.str("detail"))
		return lines
	}
	// deniedByMgmtd runs a Job whose bind passes the gateway and checks that mgmtd keeps a bind refusal after the start.
	deniedByMgmtd := func(t *testing.T, j probeJob, details ...string) {
		t.Helper()
		time.Sleep(time.Until(last.Add(bindGap)))
		start := time.Now().Add(-logMargin)
		_, id := denialRun(t, j)
		last = time.Now()
		waitFor(t, "mgmtd to keep a bind refusal of "+cell+" after the request "+id, 2*time.Minute, func() (bool, string) {
			r := cellStatusOf(t, cell).LastRefusal
			if r == nil {
				return false, "no last refusal"
			}
			ok := r.Kind == "bind" && r.Reason == mgmtapi.ReasonTokenInvalid && slices.Contains(details, r.Detail) && r.At.After(start)
			return ok, fmt.Sprintf("last refusal %+v", *r)
		})
	}

	t.Run("other_subject", func(t *testing.T) {
		denied(t, bindProbe(t, cell, ns, celldAccount, "--cell", cell, "--variant", "good"), gwapi.ReasonTokenInvalid, "subject_not_allowed")
	})
	t.Run("other_nonce", func(t *testing.T) {
		denied(t, bindProbe(t, cell, celldNamespace, celldAccount, "--cell", cell, "--variant", "other-nonce"), gwapi.ReasonTokenInvalid, "wrong_audience")
	})
	t.Run("attest_audience", func(t *testing.T) {
		denied(t, bindProbe(t, cell, celldNamespace, celldAccount, "--cell", cell, "--variant", "attest-audience"), gwapi.ReasonTokenInvalid, "wrong_audience")
	})
	t.Run("reused_nonce", func(t *testing.T) {
		time.Sleep(time.Until(last.Add(bindGap)))
		lines := bindProbe(t, cell, celldNamespace, celldAccount, "--cell", cell, "--variant", "good", "--reuse-nonce").run1(t)
		last = time.Now()
		want := "bound:" + mgmtapi.StatusAlreadyBound
		if len(lines) != 3 || !nonceLine.MatchString(lines[0]) || lines[1] != want || lines[2] != want {
			t.Errorf("the reuse printed %q, want a nonce and %s twice", lines, want)
		}
	})
	t.Run("unknown_cell", func(t *testing.T) {
		secret := tokenSecret(t, cell, ns, "not.a.token")
		j := bindProbe(t, cell, ns, "default", "--cell", "dev-cell-9", "--variant", "good", "--nonce", "x", "--token-file", "/run/attestprobe/token")
		j.secret = secret
		denied(t, j, gwapi.ReasonSourceMismatch)
	})
	t.Run("good", func(t *testing.T) {
		time.Sleep(time.Until(last.Add(bindGap)))
		lines := bindProbe(t, cell, celldNamespace, celldAccount, "--cell", cell, "--variant", "good").run1(t)
		last = time.Now()
		if len(lines) != 2 || !nonceLine.MatchString(lines[0]) || lines[1] != "bound:"+mgmtapi.StatusAlreadyBound {
			t.Errorf("a good bind printed %q, want a nonce line and bound:already_bound", lines)
		}
	})
	t.Run("rogue_token", func(t *testing.T) {
		// The nonce lives for a short time, so the quiet time passes before the nonce request.
		time.Sleep(time.Until(last.Add(bindGap)))
		nonce, audience := nonceFor(t, cell, celldNamespace, celldAccount, cell)
		secret := tokenSecret(t, cell, ns, rogueToken(t, audience))
		j := bindProbe(t, cell, ns, "default", "--cell", cell, "--variant", "good", "--nonce", nonce, "--token-file", "/run/attestprobe/token")
		j.secret = secret
		// Which check refuses the token depends on the key of the rogue cluster and the keys that mgmtd holds for the cell: the key ID can
		// be unknown, the signature can fail, or (as live run 16:14 UTC showed) the signature can verify and the issuer differ.
		deniedByMgmtd(t, j, "unknown_kid", "bad_signature", "issuer_mismatch")
	})
	t.Run("unknown_kid", func(t *testing.T) {
		// The nonce lives for a short time, so the quiet time passes before the nonce request.
		time.Sleep(time.Until(last.Add(bindGap)))
		nonce, audience := nonceFor(t, cell, celldNamespace, celldAccount, cell)
		secret := tokenSecret(t, cell, ns, forgedToken(t, cellStatusOf(t, cell).Issuer, audience))
		j := bindProbe(t, cell, ns, "default", "--cell", cell, "--variant", "good", "--nonce", nonce, "--token-file", "/run/attestprobe/token")
		j.secret = secret
		deniedByMgmtd(t, j, "unknown_kid")
	})

	for name, rev := range revisions {
		if now := recordRevisions(t)[name]; now != rev {
			t.Errorf("the record of %s moved from %+v to %+v during the refusals", name, rev, now)
		}
	}
}
