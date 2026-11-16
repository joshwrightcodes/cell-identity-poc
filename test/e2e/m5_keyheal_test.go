//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	// rotationHealWait is the time that celld of a rotated cell needs to stream again: its hello tokens carry the new key ID, the
	// gateway turns the refused hello into a hint, and mgmtd checks the keys at once.
	rotationHealWait = 3 * time.Minute
	// registryReloadWait is the time from the update of a cell record to the line "registry reloaded" in each cell-proxy server.
	registryReloadWait = 3 * time.Minute
	// uplinkWait is the time from the delete of the otel-uplink pod to a marker of its new pod in Grafana.
	uplinkWait = 5 * time.Minute
)

// holdCelldDown sets celld of a cell to no replica and restores one replica when the test ends. Register it before rotateAPIKey,
// so that the repair of the API server runs first.
func holdCelldDown(t *testing.T, cell string) {
	t.Helper()
	setReplicas(t, cell, celldNamespace, "deployment/"+celldDeployment, 0)
	t.Cleanup(func() { setReplicas(t, cell, celldNamespace, "deployment/"+celldDeployment, 1) })
}

// requireCurrentRecord runs a manual key check of the cell, which always fetches, so that its record holds the keys that the API
// server publishes and the periodic check of mgmtd is 15 minutes away.
func requireCurrentRecord(t *testing.T, cell string) time.Time {
	t.Helper()
	if res := keyCheck(t, cell); res != "unchanged" && res != "rate_limited" {
		t.Fatalf("the key check of %s answered %q, want unchanged or rate_limited. Run: mise run gate:m4:repair", cell, res)
	}
	return time.Now()
}

// waitUpdateGap waits until the update gap of mgmtd has passed since a key check, so that the next key update is not rate limited.
func waitUpdateGap(t *testing.T, since time.Time) {
	t.Helper()
	if wait := keyUpdateGap - time.Since(since); wait > 0 {
		t.Logf("waiting %s, so that the update gap has passed before the rotation", wait.Round(time.Second))
		time.Sleep(wait)
	}
}

// keyCheckLines returns the key_check lines of mgmtd for a cell since a time.
func keyCheckLines(t *testing.T, since time.Time, cell string) []logLine {
	t.Helper()
	return matching(mgmtdLog(t, since), func(l logLine) bool { return l.str("msg") == "key_check" && l.str("cell") == cell })
}

// keysUpdatedLines returns the lines of mgmtd for a cell since a time that show a record update: a key_check line with the result
// keys_updated, and a bind line with the result keys_updated. Each is tagged with the path that wrote the key.
func keysUpdatedLines(t *testing.T, since time.Time, cell string) (lines []logLine, paths []string) {
	t.Helper()
	for _, l := range matching(mgmtdLog(t, since), func(l logLine) bool {
		return (l.str("msg") == "key_check" || l.str("msg") == "bind") && l.str("cell") == cell && l.str("result") == "keys_updated"
	}) {
		lines = append(lines, l)
		paths = append(paths, l.str("msg"))
	}
	return lines, paths
}

func lineTime(l logLine) time.Time {
	at, _ := time.Parse(time.RFC3339Nano, l.str("time"))
	return at
}

// firstRefusalAt returns the time of the first line of the SPIRE server log that refuses the key ID of the cell as unknown_kid.
func firstRefusalAt(t *testing.T, since time.Time, cell, kid string) time.Time {
	t.Helper()
	logs, err := serverLog(t, since)
	if err != nil {
		t.Fatal(err)
	}
	var first time.Time
	for _, l := range matching(logs, func(l logLine) bool {
		return l.str("msg") == refusedMsg && l.str("reason") == "unknown_kid" && l.str("cell") == cell && l.str("kid") == kid
	}) {
		if at := lineTime(l); !at.IsZero() && (first.IsZero() || at.Before(first)) {
			first = at
		}
	}
	if first.IsZero() {
		t.Fatalf("the SPIRE server log holds no unknown_kid refusal of %s for the key %s since %s", cell, kid, since.Format(time.RFC3339))
	}
	return first
}

// waitControllerManager waits until kube-controller-manager of the cell is Ready and renews its leader lease. Each switch of the
// service account key restarts the API server, and the controller manager can lose its lease and restart. Its restart backoff grows
// to five minutes after many restarts, and in that time no Job creates a pod, so a probe Job would hang.
func waitControllerManager(t *testing.T, cell string) {
	t.Helper()
	pod := "kube-controller-manager-" + cell + "-control-plane"
	waitFor(t, "kube-controller-manager of "+cell+" to be Ready and to renew its lease", 8*time.Minute, func() (bool, string) {
		ready, err := kubectl(t, cell, "", "-n", "kube-system", "get", "pod", pod, "-o", "jsonpath={.status.containerStatuses[0].ready}")
		if err != nil || strings.TrimSpace(ready) != "true" {
			return false, fmt.Sprintf("ready %q, %v", ready, err)
		}
		renewed, err := kubectl(t, cell, "", "-n", "kube-system", "get", "lease", "kube-controller-manager", "-o", "jsonpath={.spec.renewTime}")
		if err != nil {
			return false, err.Error()
		}
		at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(renewed))
		if err != nil {
			return false, fmt.Sprintf("renewTime %q: %v", renewed, err)
		}
		// renewTime comes from the clock of the VM, so the present comes from the node too. After a sleep of the Mac the clocks differ.
		nowOut, err := dockerExec(t, cell+"-control-plane", "", "date", "+%s")
		if err != nil {
			return false, "read the time of the node: " + err.Error()
		}
		nowSec, err := strconv.ParseInt(strings.TrimSpace(nowOut), 10, 64)
		if err != nil {
			return false, fmt.Sprintf("the node time %q: %v", nowOut, err)
		}
		age := time.Unix(nowSec, 0).Sub(at)
		return age < 20*time.Second, "lease renewed " + age.Round(time.Second).String() + " ago on the node clock"
	})
}

// TestM5UnknownKidTriggersKeyCheck: the plugin of the SPIRE server hints mgmtd when it refuses a token with an unknown key ID, so
// the record of the cell follows a rotation of its service account key without the periodic check. celld of the cell is down for
// the test, because the gateway turns a refused hello into a hint too, and a report with unknown_kid queues one. A manual key
// check 61 s before the rotation keeps the periodic check of mgmtd out of the window. The first attestprobe is refused with
// unknown_kid. Then attestprobe is issued within five minutes, and the mgmtd log holds a key check through a hint with the result
// keys_updated, after the refusal. The test logs the time from the first refusal to issued (verify row 5).
func TestM5UnknownKidTriggersKeyCheck(t *testing.T) {
	const cell = rejectCell
	holdCelldDown(t, cell)
	checked := requireCurrentRecord(t, cell)
	waitRegistryAtCleanup(t)
	before := cellStatusOf(t, cell)

	// celld is down, so the first hint can come only after the first probe. The update gap therefore needs no wait before the switch.
	start := time.Now().Add(-logMargin)
	oldKID, newKID := rotateAPIKey(t, cell)
	waitUpdateGap(t, checked)
	res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
	expectRefusal(t, res, cell, "unknown_kid", []string{newKID})
	refusedAt := firstRefusalAt(t, res.start, cell, newKID)

	var issuedAt time.Time
	waitFor(t, "attestprobe in "+cell+" to print issued: after the unknown_kid refusal", healWait, func() (bool, string) {
		got := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
		if strings.HasPrefix(got.out, "issued:") {
			issuedAt = time.Now()
			return true, ""
		}
		return false, got.out
	})
	t.Logf("UNKNOWN_KID_TO_ISSUED_SECONDS=%.0f: the first refusal was at %s, and attestprobe was issued at %s",
		issuedAt.Sub(refusedAt).Seconds(), refusedAt.Format(time.RFC3339), issuedAt.Format(time.RFC3339))

	var hintAt time.Time
	for _, l := range keyCheckLines(t, start, cell) {
		if l.str("via") == "hint" && l.str("result") == "keys_updated" {
			hintAt = lineTime(l)
			break
		}
	}
	if hintAt.IsZero() {
		t.Fatalf("the mgmtd log holds no key check of %s through a hint with the result keys_updated since the rotation:\n%s", cell, lastLines(mgmtdLog(t, start), 8))
	}
	if hintAt.Before(refusedAt) {
		t.Errorf("the hint check ran at %s, before the first refusal at %s", hintAt.Format(time.RFC3339Nano), refusedAt.Format(time.RFC3339Nano))
	}
	t.Logf("UNKNOWN_KID_TO_KEYS_UPDATED_SECONDS=%.0f", hintAt.Sub(refusedAt).Seconds())
	after := cellStatusOf(t, cell)
	if !slices.Contains(after.Kids, oldKID) || !slices.Contains(after.Kids, newKID) || len(after.Kids) != 2 || !afterRevision(after.Record, before.Record) {
		t.Errorf("the record of %s lists %v at %+v, want %s and %s at a revision after %+v", cell, after.Kids, after.Record, oldKID, newKID, before.Record)
	}
}

// TestM5HintFloodNoLockout: a pod in dev-cell-2 floods the SPIRE server with forged unknown_kid attempts that name dev-cell-1, with a
// token that the cluster rogue signed. The flood starts after dev-cell-1 switches its service account key, so a forged hint can itself
// make the check that updates the record of the victim: the check reads the live keys. The test does not show that a hint before the
// switch spends the budget. It checks that the flood does not keep the record from following: the plugin writes at most one hint for a
// cell each minute, and mgmtd runs at most one hint check for it each minute. celld of dev-cell-1 is held at 0, so no gateway hello,
// report or bind can make a hint. Each round runs one forged attempt and one genuine probe of dev-cell-1. The genuine probe must be
// issued within eight minutes of the switch. The mgmtd log then holds one hint check of dev-cell-1 with keys_updated, any others with
// unchanged, at most one for each minute since the first forged attempt, and none closer than 55 s. The record of dev-cell-2 keeps its
// revision.
func TestM5HintFloodNoLockout(t *testing.T) {
	const victim, attacker = rejectCell, "dev-cell-2"
	holdCelldDown(t, victim)
	checked := requireCurrentRecord(t, victim)
	requireCurrentRecord(t, attacker)
	waitRegistryAtCleanup(t)
	attackerBefore := cellStatusOf(t, attacker)

	token := rogueToken(t, clusterjwt.Audience(pocEnv, victim))
	secret := tokenSecret(t, attacker, celldNamespace, token)
	start := time.Now().Add(-logMargin)
	oldKID, newKID, switchedAt := rotateAPIKeyAt(t, victim, checked)

	forged := probe{cell: attacker, claimCell: victim, namespace: celldNamespace, account: celldAccount, variant: "good", tokenSecret: secret}
	genuine := probe{cell: victim, namespace: celldNamespace, account: celldAccount, variant: "good"}
	const minAttempts = 6
	floodStart := time.Now()
	attempts := 0
	var issuedAt time.Time
	flood := func() {
		attempts++
		res := runAttestProbe(t, forged)
		if want := "denied:nodeattestor(cluster_jwt): unknown_kid"; res.out != want {
			t.Fatalf("forged attempt %d for %s: attestprobe printed %q, want %q", attempts, victim, res.out, want)
		}
	}
	for issuedAt.IsZero() {
		if time.Since(switchedAt) > healWait+3*time.Minute {
			t.Fatalf("%s was not issued within %s of the switch, with %d forged attempts running", victim, time.Since(switchedAt).Round(time.Second), attempts)
		}
		flood()
		if got := runAttestProbe(t, genuine); strings.HasPrefix(got.out, "issued:") {
			issuedAt = time.Now()
		}
	}
	for attempts < minAttempts {
		flood()
	}
	t.Logf("%s was issued %s after the switch, with %d forged attempts in %s", victim, issuedAt.Sub(switchedAt).Round(time.Second), attempts, time.Since(floodStart).Round(time.Second))

	victimStatus := cellStatusOf(t, victim)
	if !slices.Contains(victimStatus.Kids, oldKID) || !slices.Contains(victimStatus.Kids, newKID) {
		t.Errorf("the record of %s lists %v, want %s and %s", victim, victimStatus.Kids, oldKID, newKID)
	}
	// The hint checks of the victim: the first updates the keys, and the others find nothing. At most one for each minute, and none
	// closer than the gap of the plugin and of mgmtd (60 s, with a margin for the clock of the log line).
	var hintTimes []time.Time
	updated := 0
	for _, l := range keyCheckLines(t, start, victim) {
		if l.str("via") != "hint" {
			continue
		}
		hintTimes = append(hintTimes, lineTime(l))
		if l.str("result") == "keys_updated" {
			updated++
		} else if l.str("result") != "unchanged" {
			t.Errorf("a hint check of %s gave %q, want keys_updated or unchanged: %v", victim, l.str("result"), l)
		}
	}
	if updated != 1 {
		t.Errorf("%d hint checks of %s gave keys_updated, want 1", updated, victim)
	}
	if limit := int(time.Since(floodStart)/time.Minute) + 2; len(hintTimes) > limit {
		t.Errorf("the flood caused %d hint checks of %s in %s, want at most %d", len(hintTimes), victim, time.Since(floodStart).Round(time.Second), limit)
	}
	for i := 1; i < len(hintTimes); i++ {
		if gap := hintTimes[i].Sub(hintTimes[i-1]); gap < 55*time.Second {
			t.Errorf("two hint checks of %s ran %s apart, want at least 55 s", victim, gap.Round(time.Second))
		}
	}
	t.Logf("the flood caused %d hint checks of %s at %v", len(hintTimes), victim, hintTimes)
	after := cellStatusOf(t, attacker)
	if afterRevision(after.Record, attackerBefore.Record) || !slices.Equal(after.Kids, attackerBefore.Kids) {
		t.Errorf("the record of %s changed during the flood: %v at %+v, was %v at %+v", attacker, after.Kids, after.Record, attackerBefore.Kids, attackerBefore.Record)
	}
}

// readyPodUIDs returns the UIDs of the Ready pods with the app label in a namespace of a cluster, and none on an error.
func readyPodUIDs(t *testing.T, cluster, ns, app string) []string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "get", "pods", "-l", "app.kubernetes.io/name="+app, "-o", "json")
	if err != nil {
		return nil
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				UID     string  `json:"uid"`
				Deleted *string `json:"deletionTimestamp"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct{ Type, Status string } `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(out), &pods) != nil {
		return nil
	}
	var uids []string
	for _, p := range pods.Items {
		if p.Metadata.Deleted != nil {
			continue
		}
		for _, c := range p.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				uids = append(uids, p.Metadata.UID)
			}
		}
	}
	return uids
}

// TestM5ProofFollowsKeyRotation: after the service account key of dev-cell-1 rotates, every consumer of its record follows within
// minutes, with no re-link and no restart.
//   - mgmtd updates the record (keys_updated) within three minutes. Two paths heal it: the hint check that the gateway starts from the
//     hello of celld, and the bind of the new celld pod. The first keys_updated line of either path counts, and the test logs which one
//     (KEYS_UPDATED_BY). TestM5UnknownKidTriggersKeyCheck covers the hint path alone. The periodic check does not run in that window:
//     a manual check 61 s before the rotation holds it back.
//   - Each cell-proxy server of management logs "registry reloaded" within three minutes of the update (verify row 8).
//   - celld streams again within three minutes of the switch of the key, and an operation that is created then applies once.
//   - The otel-uplink pod of dev-cell-1 is deleted. A marker that the collector sends through its new pod reaches Grafana within
//     five minutes of the delete.
//   - A new celld pod binds with a token of the new key: its log holds "bound" with the status already_bound or keys_updated, the
//     record lists both key IDs, and attestprobe is issued. One rotation serves both the proof and the bind checks.
//
// The cleanup of rotateAPIKey repairs the API server.
func TestM5ProofFollowsKeyRotation(t *testing.T) {
	const cell = rejectCell
	closer := newOpCloser(t)
	checked := requireCurrentRecord(t, cell)
	waitRegistryAtCleanup(t)
	before := cellStatusOf(t, cell)

	// celld is up, so the gateway can hint within seconds of the switch. The update gap passes before the switch, and the wait
	// overlaps the set-up of the rotation.
	start := time.Now().Add(-logMargin)
	rotateStart := time.Now()
	oldKID, newKID, rotatedAt := rotateAPIKeyAt(t, cell, checked)
	t.Logf("rotated the key of %s in %s, and switched it at %s", cell, time.Since(rotateStart).Round(time.Second), rotatedAt.Format(time.RFC3339))

	// Two paths heal the record after one switch: the hint check that the gateway starts, and the bind of the new celld pod. The
	// first to write the new key counts, and the other then finds "unchanged" or "already_bound".
	var updatedAt time.Time
	var updatedBy string
	waitFor(t, "mgmtd to update the record of "+cell+" with the new key after the switch", max(time.Until(rotatedAt.Add(rotationHealWait)), 30*time.Second), func() (bool, string) {
		lines, paths := keysUpdatedLines(t, start, cell)
		for i, l := range lines {
			if at := lineTime(l); updatedAt.IsZero() || at.Before(updatedAt) {
				updatedAt, updatedBy = at, paths[i]
			}
		}
		if !updatedAt.IsZero() {
			return true, ""
		}
		return false, fmt.Sprintf("key checks: %d", len(keyCheckLines(t, start, cell)))
	})
	t.Logf("KEYS_UPDATED_BY=%s", updatedBy)
	for _, l := range keyCheckLines(t, start, cell) {
		if l.str("via") == "periodic" {
			t.Errorf("a periodic key check of %s ran in the window: %v", cell, l)
		}
	}
	after := cellStatusOf(t, cell)
	if !slices.Contains(after.Kids, oldKID) || !slices.Contains(after.Kids, newKID) || !afterRevision(after.Record, before.Record) {
		t.Errorf("the record of %s lists %v at %+v, want %s and %s at a revision after %+v", cell, after.Kids, after.Record, oldKID, newKID, before.Record)
	}
	t.Logf("KEYS_UPDATED_SECONDS=%.0f after the switch of the key", updatedAt.Sub(rotatedAt).Seconds())
	if d := updatedAt.Sub(rotatedAt); d > rotationHealWait {
		t.Errorf("mgmtd updated the record of %s %s after the switch, want at most %s (verify row 8)", cell, d.Round(time.Second), rotationHealWait)
	}

	// The registry servers.
	var slowest time.Duration
	for _, s := range poseStreams {
		pod := s.pod(t)
		var at time.Time
		waitFor(t, "the cell-proxy server "+s.name+" to log registry reloaded after the record update", registryReloadWait, func() (bool, string) {
			logs, err := kubectl(t, mgmtCluster, "", "-n", s.namespace, "logs", pod, "-c", "cell-proxy", "--since-time="+updatedAt.Add(-time.Second).UTC().Format(time.RFC3339))
			if err != nil {
				return false, err.Error()
			}
			for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "registry reloaded" }) {
				if got := lineTime(l); !got.Before(updatedAt.Add(-time.Second)) {
					at = got
					return true, ""
				}
			}
			return false, lastLines(logs, 2)
		})
		took := at.Sub(updatedAt)
		t.Logf("REGISTRY_RELOAD_SECONDS %s=%.0f", s.name, took.Seconds())
		if took > registryReloadWait {
			t.Errorf("the cell-proxy server %s reloaded the registry %s after the record update, want at most %s (verify row 8)", s.name, took.Round(time.Second), registryReloadWait)
		}
		slowest = max(slowest, took)
	}
	t.Logf("REGISTRY_RELOAD_SLOWEST_SECONDS=%.0f", slowest.Seconds())

	// celld streams again, and an operation applies.
	waitFor(t, "celld of "+cell+" to hold a stream at the gateway", max(time.Until(rotatedAt.Add(rotationHealWait)), 30*time.Second), func() (bool, string) {
		s := gwStatus(t)
		return s.Streams[cell] >= 1, fmt.Sprintf("streams %v", s.Streams)
	})
	id, envelope := opSign(t, cell, "m5 proof follows rotation "+randomHex(t, 4), 0)
	closer.add(id)
	enqueueSigned(t, cell, envelope, false)
	waitOpReported(t, cell, id, opWait)
	if n := demoLogCount(t, cell, id); n != 1 {
		t.Errorf("demo-log in %s holds %d lines of %s, want 1", cell, n, id)
	}
	if v := opGet(t, id); v.Final != op.OutcomeApplied {
		t.Errorf("mgmtd shows the final result %q for %s, want applied", v.Final, id)
	}

	// The uplink pod attests with the new key, and its telemetry reaches the store.
	old := readyPodUIDs(t, cell, obsNamespace, "otel-uplink")
	deletedAt := time.Now()
	if _, err := kubectl(t, cell, "", "-n", obsNamespace, "delete", "pod", "-l", "app.kubernetes.io/name=otel-uplink", "--wait=false"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a new Ready otel-uplink pod in "+cell, uplinkWait, func() (bool, string) {
		now := readyPodUIDs(t, cell, obsNamespace, "otel-uplink")
		for _, uid := range now {
			if !slices.Contains(old, uid) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("Ready pods %v, old %v", now, old)
	})
	marker := "m5heal" + randomHex(t, 4)
	conn := plaintextConn(t, portForward(t, cell, obsNamespace, "svc/otel-collector", 4317))
	sendSignals(t, conn, &resourcepb.Resource{Attributes: []*commonpb.KeyValue{strAttr("service.name", "heal-"+marker[len("m5heal"):])}}, marker)
	metric := "m3_spoof_" + marker
	waitFor(t, "the marker "+marker+" in Prometheus through the new otel-uplink pod", max(time.Until(deletedAt.Add(uplinkWait)), 30*time.Second), func() (bool, string) {
		s := promSamples(t, fmt.Sprintf(`{__name__=%q}`, metric))
		if len(s) == 1 {
			requireRow(t, "the marker series", s[0].labels, rowOf(cell))
		}
		return len(s) == 1, fmt.Sprintf("%d series", len(s))
	})
	t.Logf("UPLINK_MARKER_SECONDS=%.0f after the delete of the pod", time.Since(deletedAt).Seconds())

	// A new celld pod binds with a token of the new key. mgmtd logs no line for already_bound, so the proof is the line "bound" of
	// the pod itself (internal/bind/client.go), with the status already_bound (a hint came first) or keys_updated.
	pod := replaceCelldPod(t, cell)
	waitCelldSVID(t, cell, pod)
	waitFor(t, "the new celld pod "+pod.Metadata.Name+" to log bound with the status already_bound or keys_updated", healWait, func() (bool, string) {
		logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", pod.Metadata.Name, "-c", celldContainer)
		if err != nil {
			return false, err.Error()
		}
		var seen []string
		for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "bound" }) {
			seen = append(seen, l.str("status"))
			if st := l.str("status"); st == "already_bound" || st == "keys_updated" {
				return true, ""
			}
		}
		return false, fmt.Sprintf("bound lines %v: %s", seen, lastLines(logs, 2))
	})
	if st := cellStatusOf(t, cell); !slices.Contains(st.Kids, oldKID) || !slices.Contains(st.Kids, newKID) {
		t.Errorf("the record of %s lists %v after the bind, want %s and %s", cell, st.Kids, oldKID, newKID)
	}
	waitIssued(t, cell, healWait)
}
