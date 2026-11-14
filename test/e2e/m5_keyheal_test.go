//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
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

// freshCNIToken restarts istio-cni-node in the cell and waits for its rollout. The pod reads a projected token that the kubelet
// replaces after 48 minutes. When that replacement falls into a rotation of the service account key, the new token is signed by the
// test key. The repair then removes that key, the plugin gets Unauthorized, and no pod of the cell gets a sandbox until the pod
// of istio-cni-node restarts. A fresh pod keeps its first token for longer than any test here lasts.
func freshCNIToken(t *testing.T, cell string) {
	t.Helper()
	if _, err := kubectl(t, cell, "", "-n", "istio-system", "delete", "pod", "-l", "k8s-app=istio-cni-node", "--wait=true", "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
	if _, err := kubectl(t, cell, "", "-n", "istio-system", "rollout", "status", "daemonset/istio-cni-node", "--timeout=180s"); err != nil {
		t.Fatalf("istio-cni-node in %s did not finish its rollout: %v", cell, err)
	}
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
		return time.Since(at) < 20*time.Second, "lease renewed " + time.Since(at).Round(time.Second).String() + " ago"
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
	waitUpdateGap(t, checked)

	start := time.Now().Add(-logMargin)
	oldKID, newKID := rotateAPIKey(t, cell)
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

// TestM5HintFloodNoLockout: a flood of forged unknown_kid attempts for dev-cell-2, from a token that the cluster rogue signed, must
// not stop the key update of dev-cell-1. dev-cell-1 rotates its service account key. While six forged attempts for dev-cell-2 run,
// attestprobe of dev-cell-1 must be issued within five minutes. The hints of the flood stay bounded: the mgmtd log holds at
// most one hint check of dev-cell-2 for each minute since the first forged attempt and one more, no two less than 55 s apart,
// each with the result unchanged, and the record of dev-cell-2 keeps its revision.
func TestM5HintFloodNoLockout(t *testing.T) {
	const victim, flooded = rejectCell, "dev-cell-2"
	checked := requireCurrentRecord(t, victim)
	requireCurrentRecord(t, flooded)
	waitRegistryAtCleanup(t)
	floodedBefore := cellStatusOf(t, flooded)
	waitUpdateGap(t, checked)

	token := rogueToken(t, clusterjwt.Audience(pocEnv, flooded))
	secret := tokenSecret(t, flooded, celldNamespace, token)
	start := time.Now().Add(-logMargin)
	oldKID, newKID := rotateAPIKey(t, victim)

	const attempts = 6
	floodStart := time.Now()
	for i := range attempts {
		res := runAttestProbe(t, probe{cell: flooded, namespace: celldNamespace, account: celldAccount, variant: "good", tokenSecret: secret})
		if want := "denied:nodeattestor(cluster_jwt): unknown_kid"; res.out != want {
			t.Fatalf("forged attempt %d for %s: attestprobe printed %q, want %q", i+1, flooded, res.out, want)
		}
	}
	t.Logf("%d forged attempts for %s took %s", attempts, flooded, time.Since(floodStart).Round(time.Second))
	waitIssued(t, victim, healWait)
	t.Logf("%s attested %s after the rotation", victim, time.Since(start).Round(time.Second))

	victimStatus := cellStatusOf(t, victim)
	if !slices.Contains(victimStatus.Kids, oldKID) || !slices.Contains(victimStatus.Kids, newKID) {
		t.Errorf("the record of %s lists %v, want %s and %s", victim, victimStatus.Kids, oldKID, newKID)
	}
	// The hint checks that the flood caused: at most one for each minute since the first forged attempt, and no two closer than the
	// gap of the plugin and of mgmtd (60 s, with a margin for the clock of the log line).
	var hintTimes []time.Time
	for _, l := range keyCheckLines(t, floodStart.Add(-logMargin), flooded) {
		if l.str("via") != "hint" {
			continue
		}
		hintTimes = append(hintTimes, lineTime(l))
		if l.str("result") != "unchanged" {
			t.Errorf("a hint check of %s during the flood gave %q, want unchanged: %v", flooded, l.str("result"), l)
		}
	}
	if limit := int(time.Since(floodStart)/time.Minute) + 1; len(hintTimes) > limit {
		t.Errorf("the flood of %s caused %d hint checks in %s, want at most %d", flooded, len(hintTimes), time.Since(floodStart).Round(time.Second), limit)
	}
	for i := 1; i < len(hintTimes); i++ {
		if gap := hintTimes[i].Sub(hintTimes[i-1]); gap < 55*time.Second {
			t.Errorf("two hint checks of %s ran %s apart, want at least 55 s", flooded, gap.Round(time.Second))
		}
	}
	t.Logf("the flood of %s caused %d hint checks at %v", flooded, len(hintTimes), hintTimes)
	after := cellStatusOf(t, flooded)
	if afterRevision(after.Record, floodedBefore.Record) || !slices.Equal(after.Kids, floodedBefore.Kids) {
		t.Errorf("the record of %s changed during the flood: %v at %+v, was %v at %+v", flooded, after.Kids, after.Record, floodedBefore.Kids, floodedBefore.Record)
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
//   - mgmtd updates the record (keys_updated) within three minutes, because the new hello tokens of celld make the gateway hint.
//     The periodic check does not run in that window: a manual check 61 s before the rotation holds it back.
//   - Each cell-proxy server of management logs "registry reloaded" within three minutes of the update (verify row 8).
//   - celld streams again within three minutes of the rotation, and an operation that is created then applies once.
//   - The otel-uplink pod of dev-cell-1 is deleted. A marker that the collector sends through its new pod reaches Grafana within
//     five minutes of the delete.
//
// The cleanup of rotateAPIKey repairs the API server.
func TestM5ProofFollowsKeyRotation(t *testing.T) {
	const cell = rejectCell
	closer := newOpCloser(t)
	checked := requireCurrentRecord(t, cell)
	waitRegistryAtCleanup(t)
	before := cellStatusOf(t, cell)
	waitUpdateGap(t, checked)

	start := time.Now().Add(-logMargin)
	rotateStart := time.Now()
	oldKID, newKID := rotateAPIKey(t, cell)
	rotatedAt := time.Now()
	t.Logf("rotated the key of %s in %s", cell, rotatedAt.Sub(rotateStart).Round(time.Second))

	var updatedAt time.Time
	waitFor(t, "mgmtd to update the record of "+cell+" with the new key after the rotation", rotationHealWait, func() (bool, string) {
		for _, l := range keyCheckLines(t, start, cell) {
			if l.str("result") == "keys_updated" {
				updatedAt = lineTime(l)
				return true, ""
			}
		}
		return false, fmt.Sprintf("key checks: %d", len(keyCheckLines(t, start, cell)))
	})
	for _, l := range keyCheckLines(t, start, cell) {
		if l.str("via") == "periodic" {
			t.Errorf("a periodic key check of %s ran in the window: %v", cell, l)
		}
	}
	after := cellStatusOf(t, cell)
	if !slices.Contains(after.Kids, oldKID) || !slices.Contains(after.Kids, newKID) || !afterRevision(after.Record, before.Record) {
		t.Errorf("the record of %s lists %v at %+v, want %s and %s at a revision after %+v", cell, after.Kids, after.Record, oldKID, newKID, before.Record)
	}
	t.Logf("KEYS_UPDATED_SECONDS=%.0f after the start of the rotation (%.0f after rotateAPIKey returned)", updatedAt.Sub(rotateStart).Seconds(), updatedAt.Sub(rotatedAt).Seconds())

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
}

// TestM5BindHealsRotation: a new celld pod binds with a token from a rotated key. attestprobe of dev-cell-1 right after the rotation
// is refused with unknown_kid, or issued when a hint already updated the record, because the hint check of the plugin or of the
// gateway can come before the bind. A new celld pod then gets its SVID within five minutes, and the mgmtd log holds a bind of the
// cell with the result keys_updated, or, when a hint came first, a hint check with keys_updated since the rotation (the bind then
// answers already_bound, which mgmtd does not log). In both cases the record lists both key IDs, and attestprobe is issued.
func TestM5BindHealsRotation(t *testing.T) {
	const cell = rejectCell
	checked := requireCurrentRecord(t, cell)
	waitRegistryAtCleanup(t)
	waitUpdateGap(t, checked)

	start := time.Now().Add(-logMargin)
	oldKID, newKID := rotateAPIKey(t, cell)
	res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
	if strings.HasPrefix(res.out, "issued:") {
		t.Logf("a hint updated the record of %s before the probe ran: %s", cell, res.out)
	} else {
		expectRefusal(t, res, cell, "unknown_kid", []string{newKID})
	}

	pod := replaceCelldPod(t, cell)
	want := fmt.Sprintf("spiffe://%s/cell/%s/celld", spireTD, cell)
	waitFor(t, "the new celld pod to log "+want, healWait, func() (bool, string) {
		logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", pod.Metadata.Name, "-c", celldContainer)
		if err != nil {
			return false, err.Error()
		}
		return slices.Contains(celldSPIFFEIDs(logs), want), lastLines(logs, 3)
	})
	// mgmtd logs a bind only when it changes something: a bind that finds the keys already in the record answers already_bound and
	// leaves no line. So the heal is either a bind line with the result keys_updated, or a hint check with keys_updated since
	// the rotation, which came before the bind.
	logs := mgmtdLog(t, start)
	var results []string
	healed := false
	for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "bind" && l.str("cell") == cell }) {
		results = append(results, l.str("result"))
		if l.str("result") == "keys_updated" {
			healed = true
		}
	}
	for _, l := range keyCheckLines(t, start, cell) {
		if l.str("via") == "hint" && l.str("result") == "keys_updated" {
			healed = true
			results = append(results, "hint:keys_updated")
		}
	}
	if !healed {
		t.Errorf("the mgmtd log holds no bind of %s with the result keys_updated, and no hint check with keys_updated, since the rotation. Results: %v\n%s",
			cell, results, lastLines(logs, 8))
	}
	t.Logf("the key update of %s came through %v", cell, results)
	st := cellStatusOf(t, cell)
	if !slices.Contains(st.Kids, oldKID) || !slices.Contains(st.Kids, newKID) {
		t.Errorf("the record of %s lists %v, want %s and %s", cell, st.Kids, oldKID, newKID)
	}
	waitIssued(t, cell, healWait)
}
