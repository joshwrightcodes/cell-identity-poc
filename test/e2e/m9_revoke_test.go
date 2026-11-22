//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gateway"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

const (
	m9Cell    = "dev-cell-2"
	m9Witness = "dev-cell-1"
	// m9IslandRefuseBound is verify row 8: the time from revoke -- local to the refusals of the gateway and of the plugin.
	m9IslandRefuseBound = 2 * time.Minute
	// m9HeldBound is the time from revoke -- local to the entry in the overlay of envd.
	m9HeldBound = 30 * time.Second
	// m9AdoptBound is the time from the heal to the adoption of the entry and its settle: a connected check of 2 minutes, one revision
	// for each applied revision, and the drain of row 9 (10 minutes).
	m9AdoptBound = 10 * time.Minute
	// m9IslandHold is the hold of the cut of the island test, plus the 15 minutes of the timer of the node.
	m9IslandHold = 20 * time.Minute
)

// TestM9ConnectedRevocation revokes dev-cell-2 through mgmtd while the environment is connected, and checks each enforcement point.
// The cleanup un-revokes the cell, restarts it, and waits until it is valid.
func TestM9ConnectedRevocation(t *testing.T) {
	m9RequireStart(t, m9Cell)
	before := mgmtStatus(t).Signed
	// The cleanups run in reverse order: the restore of the cell first, and the close of the operation after it.
	closer := newOpCloser(t)
	m9RestoreCell(t, m9Cell, false)
	otherBefore := m9BannedSet(t, m9Witness)

	start := m9Now(t)
	res := m9Revoke(t, m9Cell)
	t.Logf("mgmt -- revoke --cell %s: %+v", m9Cell, res)
	var recordAt time.Time
	inPod := func(t *testing.T) time.Time {
		if recordAt.IsZero() {
			recordAt = m9RecordInPod(t, start, m9RecordBound)
			t.Logf("RECORD_IN_POD_SECONDS=%.0f", recordAt.Sub(start).Seconds())
		}
		return recordAt
	}

	t.Run("gateway_refuses", func(t *testing.T) {
		ended, hello := m9GatewayRefuses(t, m9Cell, start, max(time.Until(start.Add(m9GatewayBound)), 30*time.Second))
		t.Logf("GATEWAY_STREAM_ENDED_SECONDS=%.0f GATEWAY_HELLO_REFUSED_SECONDS=%.0f", ended.Sub(start).Seconds(), hello.Sub(start).Seconds())
		for what, at := range map[string]time.Time{"ended the open stream": ended, "refused a new hello": hello} {
			if d := at.Sub(start); d > m9GatewayBound {
				t.Errorf("the gateway %s %s after the revocation, want at most %s", what, d.Round(time.Second), m9GatewayBound)
			}
		}
	})

	t.Run("plugin_refuses", func(t *testing.T) {
		if d := inPod(t).Sub(start); d > m9PluginBound {
			t.Errorf("the record reached the pod of the SPIRE server %s after the revocation, want at most %s", d.Round(time.Second), m9PluginBound)
		}
		m9PluginRefuses(t, m9Cell, clusterjwt.SourceRecord, start, max(time.Until(start.Add(m9PluginBound)), 30*time.Second))
	})

	t.Run("agents_banned", func(t *testing.T) {
		m9AgentsBanned(t, m9Cell, m9Witness, clusterjwt.SourceRecord, inPod(t), start, otherBefore)
	})

	t.Run("streams_closed", func(t *testing.T) { m9StreamsClosed(t, m9Cell, start) })

	t.Run("next_revision", func(t *testing.T) {
		// Row 37: an unrelated revision, here a new key of dev-cell-1 in its record, keeps dev-cell-2 refused.
		s0 := mgmtStatus(t)
		makeRevision(t, m9Witness)
		s1 := mgmtStatus(t)
		if !afterRevision(s1.Signed, s0.Signed) {
			t.Fatalf("mgmtd signed %v after the key change of %s, want a revision after %v", s1.Signed, m9Witness, s0.Signed)
		}
		waitApplied(t, s1.Signed.Counter, 2*time.Minute)
		if c, ok := m9CellStatus(mgmtStatus(t), m9Cell); !ok || !c.Revoked {
			t.Errorf("after revision %v mgmtd shows %s with revoked %v, want true", s1.Signed, m9Cell, c.Revoked)
		}
		if _, cells, err := readLiveRecords(t); err != nil || !cells[m9Cell].Revoked {
			t.Errorf("after revision %v the record of %s is revoked %v (%v), want true", s1.Signed, m9Cell, cells[m9Cell].Revoked, err)
		}
		// The plugin pod sees cell-records after the kubelet sync, so wait until it shows the new revision before the probe.
		after := m9PluginAtRevision(t, s1.Signed, m9RecordBound)
		m9PluginRefuses(t, m9Cell, clusterjwt.SourceRecord, after, m9PluginBound)
		m9GatewayHelloRefused(t, m9Cell, after, m9GatewayBound)
	})

	// no_lease shows that the row stays unleased. celld cannot hold a stream of the revoked cell, so it does not tell the lease rule
	// of the gateway (ClaimLive) from the refusal of the stream.
	t.Run("no_lease", func(t *testing.T) {
		id, envelope := opSign(t, m9Cell, "m9 revoked "+randomHex(t, 4), 3*time.Minute)
		closer.add(id)
		enqueueSigned(t, m9Cell, envelope, false)
		for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
			row := queueRow(t, m9Cell, id)
			if row.State != gateway.StateQueued || row.Claims != 0 || row.Holder != "" {
				t.Fatalf("the queue row of %s for %s is %+v, want queued with no claim and no holder", m9Cell, id, row)
			}
		}
	})

	t.Run("serves_customers", func(t *testing.T) {
		echoTraffic(t, m9Cell, 5)
	})

	t.Run("restore_refused", func(t *testing.T) {
		out, err := mgmtCtlErr("restore", "--revision", strconv.FormatUint(before.Counter, 10))
		if err == nil {
			// A restore that mgmtd accepted would serve the cell as not revoked. Make mgmtd serve the latest revision again.
			t.Cleanup(func() {
				if o, err := mgmtCtlErr("restore", "--revision", "latest"); err != nil {
					t.Errorf("restore --revision latest: %v: %s. Run: mise run gate:m9:repair", err, o)
				}
			})
			t.Fatalf("mgmt -- restore --revision %d was accepted (%s), want restore_past_revocation", before.Counter, out)
		}
		var f struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal([]byte(m9LastLine(out)), &f) != nil || f.Reason != mgmtapi.ReasonRestorePastRevocation {
			t.Errorf("mgmt -- restore --revision %d printed %q, want reason %s", before.Counter, out, mgmtapi.ReasonRestorePastRevocation)
		}
	})
}

// m9StreamsClosed is row 28. Each cell-proxy server of management (view, telemetry, mesh) closes the live connections of the cell
// within 5 seconds of its log line "registry reloaded" that adopts the revoked record. A connection that the server closed for the
// revocation logs "connection closed" with the reason cell_revoked. The clocks of the pods and of the Mac come from one VM, so the
// times compare.
func m9StreamsClosed(t *testing.T, cell string, start time.Time) {
	t.Helper()
	for _, s := range poseStreams {
		t.Run(s.name, func(t *testing.T) {
			pod := s.pod(t)
			var reloadAt time.Time
			var lines []logLine
			waitFor(t, "the cell-proxy server "+s.name+" to log registry reloaded with a revoked record after the revocation", registryReloadWait, func() (bool, string) {
				logs, err := kubectl(t, mgmtCluster, "", "-n", s.namespace, "logs", pod, "-c", "cell-proxy", "--since=2h")
				if err != nil {
					return false, err.Error()
				}
				// The revoked count of the last reload before the revocation is the baseline.
				baseline := 0.0
				var reloads []logLine
				for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "registry reloaded" }) {
					if lineTime(l).Before(start.Add(-logMargin)) {
						baseline = number(l, "revoked")
					} else {
						reloads = append(reloads, l)
					}
				}
				for _, l := range reloads {
					if number(l, "revoked") > baseline {
						if at := lineTime(l); reloadAt.IsZero() || at.Before(reloadAt) {
							reloadAt = at
						}
					}
				}
				if reloadAt.IsZero() {
					return false, fmt.Sprintf("baseline revoked %v, %d reloads since the revocation, last lines: %s", baseline, len(reloads), lastLines(logs, 2))
				}
				lines = matching(logs, func(l logLine) bool {
					return l.str("msg") == "connection closed" && l.str("reason") == "cell_revoked" && l.str("cell") == cell
				})
				return true, ""
			})
			// The closes follow the reload within a second. Wait out the bound, and read the log once more.
			time.Sleep(m9CloseBound + time.Second)
			logs := m9PodLog(t, mgmtCluster, s.namespace, pod, "cell-proxy", reloadAt.Add(-logMargin))
			lines = matching(logs, func(l logLine) bool {
				return l.str("msg") == "connection closed" && l.str("reason") == "cell_revoked" && l.str("cell") == cell
			})
			var worst time.Duration
			n := 0
			for _, l := range lines {
				d := lineTime(l).Sub(reloadAt)
				if d < -logMargin || d > time.Minute {
					continue
				}
				n++
				worst = max(worst, d)
			}
			t.Logf("CLOSE_SECONDS %s=%.1f over %d connections of %s, registry reloaded %.0f s after the revocation", s.name, worst.Seconds(), n, cell, reloadAt.Sub(start).Seconds())
			switch {
			case n == 0:
				t.Errorf("the cell-proxy server %s logged no \"connection closed\" with reason cell_revoked for %s around its reload at %s, want one for each live connection of the cell",
					s.name, cell, reloadAt.UTC().Format(time.RFC3339Nano))
			case worst > m9CloseBound:
				t.Errorf("the cell-proxy server %s closed a connection of %s %s after its registry reloaded, want at most %s (row 28)", s.name, cell, worst.Round(100*time.Millisecond), m9CloseBound)
			}
		})
	}
}

// m9InputEnvelope returns the envelope of key <id>.json of ConfigMap envd-system/local-revocations in dev-cp. It is public data.
func m9InputEnvelope(t *testing.T, id string) string {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "get", "configmap", "local-revocations", "-o", "jsonpath={.data."+strings.ReplaceAll(id+".json", ".", `\.`)+"}")
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("ConfigMap local-revocations holds no key %s.json: %v", id, err)
	}
	return strings.TrimSpace(out)
}

// m9PatchInput sets (value) or deletes (empty value) one key of ConfigMap envd-system/local-revocations, with the field manager operator.
func m9PatchInput(t *testing.T, key, value string) {
	t.Helper()
	var v any = value
	if value == "" {
		v = nil
	}
	patch, err := json.Marshal(map[string]any{"data": map[string]any{key: v}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "patch", "configmap", "local-revocations", "--type=merge", "--field-manager=operator", "-p", string(patch)); err != nil {
		t.Errorf("patch key %s of ConfigMap local-revocations: %v", key, err)
	}
}

// m9RecordRevision returns "<epoch>.<counter>" of the record of the cell that envd holds.
func m9RecordRevision(t *testing.T, cell string) string {
	t.Helper()
	data, _, _, err := recordsConfigMap(t)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(data[cell+".dsse.json"]), &env); err != nil {
		t.Fatalf("the record of %s is no envelope: %v", cell, err)
	}
	p, err := base64Decode(env.Payload)
	if err != nil {
		t.Fatalf("the payload of the record of %s is not base64: %v", cell, err)
	}
	var rec struct {
		Epoch   uint64 `json:"epoch"`
		Counter uint64 `json:"counter"`
	}
	if err := json.Unmarshal(p, &rec); err != nil || rec.Epoch == 0 || rec.Counter == 0 {
		t.Fatalf("the record of %s holds epoch %d and counter %d: %v", cell, rec.Epoch, rec.Counter, err)
	}
	return fmt.Sprintf("%d.%d", rec.Epoch, rec.Counter)
}

// m9ForgedEnvelope makes an entry for the cell that a key made in this test signs. operatorctl keygen prints the seed on standard
// output. The seed stays in this process: it goes from the pipe of keygen to the pipe of operatorctl sign, and no file, argument, log
// line or message holds it. The public file of keygen holds the public key only, in a directory of the test.
func m9ForgedEnvelope(t *testing.T, cell, record string) string {
	t.Helper()
	keygen := exec.Command("mise", "run", "operatorctl", "--", "keygen", "--public-file", filepath.Join(t.TempDir(), "forged.pub"))
	seed, err := keygen.Output()
	if err != nil || len(seed) == 0 {
		t.Fatalf("operatorctl keygen made no key: %v", err)
	}
	defer clear(seed)
	sign := exec.Command("mise", "run", "operatorctl", "--", "sign", "--env", pocEnv, "--cell", cell, "--record", record)
	sign.Stdin = bytes.NewReader(seed)
	var stderr bytes.Buffer
	sign.Stderr = &stderr
	out, err := sign.Output()
	if err != nil {
		t.Fatalf("operatorctl sign with the forged key: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	envelope := strings.TrimSpace(string(out))
	if !strings.HasPrefix(envelope, "{") {
		t.Fatal("operatorctl sign printed no envelope")
	}
	return envelope
}

// m9TrustSnapshot returns the digest of each part of the trust state that a rotation of the operator key would change: the spec
// that envd holds (the envd revision), each record, the pins of envd, of the gateway and of the SPIRE server, the key of
// operator-pub, and key.env. Key local-revocations.json is not part of it, because the overlay changes by design.
func m9TrustSnapshot(t *testing.T) map[string]string {
	t.Helper()
	snap := map[string]string{}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	data, _, _, err := recordsConfigMap(t)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range data {
		if k != "local-revocations.json" {
			snap["cell-records/"+k] = sum(v)
		}
	}
	get := func(cluster, ns, name, jsonpath string) string {
		out, err := kubectl(t, cluster, "", "-n", ns, "get", "configmap", name, "--ignore-not-found", "-o", "jsonpath="+jsonpath)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	snap["pin/envd"] = get(spireCluster, envdNamespace, "operator-key", `{.data.keys\.pub}`)
	snap["pin/gateway"] = get(spireCluster, gatewayNamespace, "operator-key", `{.data.keys\.pub}`)
	snap["pin/server"] = strings.Join(regexp.MustCompile(`(?m)^[ \t]*operator_public_keys[ \t]*=[ \t]*\[[^\]]*\]`).FindAllString(get(spireCluster, spireNamespace, "spire-server", `{.data.server\.conf}`), -1), "\n")
	snap["pin/mgmtd"] = get(mgmtCluster, mgmtNamespace, "operator-key", `{.data.keys\.pub}`)
	snap["operator-pub"] = get(mgmtCluster, mgmtNamespace, "operator-pub", "{.data}")
	if k, err := os.ReadFile(m9OperatorKeyEnv); err == nil {
		snap["key.env"] = string(k)
	}
	return snap
}

// m9ErrorLine returns the text of the "error" field of the last JSON line of out that has one.
func m9ErrorLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var e struct {
			Error string `json:"error"`
		}
		if strings.HasPrefix(lines[i], "{") && json.Unmarshal([]byte(lines[i]), &e) == nil && e.Error != "" {
			return e.Error
		}
	}
	return ""
}

// TestM9LocalRevocationDuringIsland revokes dev-cell-2 on the Mac while dev-cp is cut from management. envd holds the signed entry,
// and the gateway and the plugin refuse the cell with source overlay. After the heal, mgmtd adopts the entry, and the next revision
// settles it.
func TestM9LocalRevocationDuringIsland(t *testing.T) {
	keySHA := m9OperatorKeySHA256(t)
	m9RequireStart(t, m9Cell)
	m9RequireNoEntries(t)
	// Registered before the cut: the heal runs first, then the restore of the cell.
	m9RestoreCell(t, m9Cell, true)
	otherBefore := m9BannedSet(t, m9Witness)
	cut := cutLink(t, spireCluster, mgmtCluster, "both", m9IslandHold)

	m9MarkRevoked(t, m9Cell)
	start := m9Now(t)
	out, err := miseRun(t, 5*time.Minute, nil, "revoke", "--", "local", "--cell", m9Cell)
	if err != nil {
		t.Fatalf("mise run revoke -- local --cell %s: %v\n%s", m9Cell, err, out)
	}
	local := lastJSONLine(t, out)
	id, _ := local["id"].(string)
	if local["cell"] != m9Cell || len(id) != 16 {
		t.Fatalf("revoke -- local printed %v, want the cell %s and an entry ID of 16 hex characters", local, m9Cell)
	}
	envelope := m9InputEnvelope(t, id)
	t.Logf("entry %s signed for %s at the record %v", id, m9Cell, local["record"])
	var recordAt time.Time
	inPod := func(t *testing.T) time.Time {
		if recordAt.IsZero() {
			recordAt = m9RecordInPod(t, start, m9RecordBound)
			t.Logf("OVERLAY_IN_POD_SECONDS=%.0f", recordAt.Sub(start).Seconds())
		}
		return recordAt
	}

	t.Run("held", func(t *testing.T) {
		waitFor(t, "envd to hold the entry "+id+" of "+m9Cell, m9HeldBound, func() (bool, string) {
			held := m9Held(t)
			return held[m9Cell] == id, fmt.Sprintf("envd holds %v", held)
		})
		if st := m9EntryOf(t, id); st != "held" {
			t.Errorf("revoke -- list shows the entry %s as %q, want held", id, st)
		}
		t.Logf("HELD_SECONDS=%.0f", time.Since(start).Seconds())
	})

	t.Run("gateway_refuses", func(t *testing.T) {
		ended, hello := m9GatewayRefuses(t, m9Cell, start, max(time.Until(start.Add(m9IslandRefuseBound)), 30*time.Second))
		t.Logf("GATEWAY_STREAM_ENDED_SECONDS=%.0f GATEWAY_HELLO_REFUSED_SECONDS=%.0f", ended.Sub(start).Seconds(), hello.Sub(start).Seconds())
		for what, at := range map[string]time.Time{"ended the open stream": ended, "refused a new hello": hello} {
			if d := at.Sub(start); d > m9IslandRefuseBound {
				t.Errorf("the gateway %s %s after revoke -- local, want at most %s (verify row 8)", what, d.Round(time.Second), m9IslandRefuseBound)
			}
		}
	})

	t.Run("plugin_refuses", func(t *testing.T) {
		if d := inPod(t).Sub(start); d > m9IslandRefuseBound {
			t.Errorf("the overlay reached the pod of the SPIRE server %s after revoke -- local, want at most %s (verify row 8)", d.Round(time.Second), m9IslandRefuseBound)
		}
		m9PluginRefuses(t, m9Cell, clusterjwt.SourceOverlay, start, max(time.Until(start.Add(m9IslandRefuseBound)), 30*time.Second))
	})

	t.Run("agents_banned", func(t *testing.T) {
		m9AgentsBanned(t, m9Cell, m9Witness, clusterjwt.SourceOverlay, inPod(t), start, otherBefore)
	})

	t.Run("forged_refused", func(t *testing.T) {
		key := randomHex(t, 8) + ".json"
		t.Cleanup(func() { m9PatchInput(t, key, "") })
		forged := m9ForgedEnvelope(t, m9Witness, m9RecordRevision(t, m9Witness))
		since := m9Now(t)
		m9PatchInput(t, key, forged)
		waitFor(t, "the envd log to hold revocation_refused with the reason revocation_invalid", 2*time.Minute, func() (bool, string) {
			logs := m9PodLog(t, spireCluster, envdNamespace, "deploy/"+envdDeployment, envdDeployment, since.Add(-logMargin))
			n := len(matching(logs, func(l logLine) bool {
				return l.str("msg") == "revocation_refused" && l.str("reason") == "revocation_invalid"
			}))
			return n > 0, fmt.Sprintf("%d lines, last lines: %s", n, lastLines(logs, 2))
		})
		if held := m9Held(t); held[m9Witness] != "" {
			t.Errorf("envd holds the entry %s for %s, which a key of the test signed", held[m9Witness], m9Witness)
		}
		if res := runAttestProbe(t, probe{cell: m9Witness, namespace: celldNamespace, account: celldAccount, variant: "good"}); !strings.HasPrefix(res.out, "issued:") {
			t.Errorf("attestprobe in %s printed %q after the forged entry, want issued:", m9Witness, res.out)
		}
		logs := m9PodLog(t, spireCluster, gatewayNamespace, gatewayPod, "cellgw", since.Add(-logMargin))
		if n := len(matching(logs, func(l logLine) bool {
			return l.str("msg") == "stream_refused" && l.str("cell") == m9Witness && l.str("reason") == "cell_revoked"
		})); n > 0 {
			t.Errorf("the gateway refused %s with cell_revoked %d times after the forged entry, want none", m9Witness, n)
		}
		if now := m9BannedSet(t, m9Witness); !slices.Equal(now, otherBefore) {
			t.Errorf("the banned agents of %s changed from %v to %v after the forged entry, want no change", m9Witness, otherBefore, now)
		}
	})

	t.Run("no_trust_change", func(t *testing.T) {
		canary := filepath.Join(t.TempDir(), "secret-manager-called")
		// The commands do not touch a secret manager. If the script reached one, it would create the canary file and fail.
		env := []string{
			"POC_SECRET_READ_CMD=touch '" + canary + "'; exit 1",
			"POC_SECRET_WRITE_CMD=touch '" + canary + "'; exit 1",
			"POC_OPERATOR_KEY=m9-canary",
		}
		before := m9TrustSnapshot(t)
		out, err := miseRun(t, 5*time.Minute, env, "operator:rotate-key")
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatalf("mise run operator:rotate-key gave %v, want exit status 1\n%s", err, out)
		}
		msg := m9ErrorLine(out)
		t.Logf("operator:rotate-key refused: %s", msg)
		named := false
		for _, want := range []string{"connected environment", "cut of the partition tool"} {
			named = named || strings.Contains(msg, want)
		}
		if !named {
			t.Errorf("the refusal %q names neither the missing connection nor the cut", msg)
		}
		if _, err := os.Stat(canary); err == nil {
			t.Error("operator:rotate-key called the secret manager before it refused")
		}
		if after := m9TrustSnapshot(t); !reflect.DeepEqual(before, after) {
			for k := range before {
				if before[k] != after[k] {
					t.Errorf("%s changed during the refused rotation", k)
				}
			}
			for k := range after {
				if _, ok := before[k]; !ok {
					t.Errorf("%s appeared during the refused rotation", k)
				}
			}
		}
	})

	cut.Heal(t)
	if !cut.healed {
		t.Fatalf("the cut %s is not healed, so the rest of the test cannot run", cut.Tag)
	}
	healedAt := m9Now(t)

	adopted := t.Run("adopted", func(t *testing.T) {
		waitFor(t, "mgmtd to adopt the entry "+id+" and sign the record of "+m9Cell+" as revoked", m9AdoptBound, func() (bool, string) {
			s, err := m9Status()
			if err != nil {
				return false, err.Error()
			}
			c, _ := m9CellStatus(s, m9Cell)
			var event *mgmtapi.RevocationEvent
			for i := range s.Revocations {
				if e := &s.Revocations[i]; e.Cell == m9Cell && e.Kind == mgmtapi.RevocationRevoke && e.EntryID == id {
					event = e
				}
			}
			if event == nil || !c.Revoked {
				return false, fmt.Sprintf("revoked %v, mirror event %v, pending %v", c.Revoked, event, s.PendingRevokes)
			}
			switch {
			case event.Source != mgmtapi.RevocationSourceOperator, event.OperatorKeySHA256 != keySHA:
				t.Errorf("the mirror names source %q and key %q for the entry %s, want %q and %q", event.Source, event.OperatorKeySHA256, id, mgmtapi.RevocationSourceOperator, keySHA)
			case c.RevokedBy != mgmtapi.RevocationSourceOperator, c.RevokedEntryID != id, c.RevokedKeySHA256 != keySHA:
				t.Errorf("the status of %s names %q, entry %q and key %q, want %q, %q and %q", m9Cell, c.RevokedBy, c.RevokedEntryID, c.RevokedKeySHA256, mgmtapi.RevocationSourceOperator, id, keySHA)
			}
			return true, ""
		})
		waitFor(t, "the record of "+m9Cell+" in cell-records to be revoked", 2*time.Minute, func() (bool, string) {
			_, cells, err := readLiveRecords(t)
			if err != nil {
				return false, err.Error()
			}
			return cells[m9Cell].Revoked, fmt.Sprintf("revoked %v", cells[m9Cell].Revoked)
		})
		t.Logf("ADOPTED_SECONDS=%.0f after the heal", time.Since(healedAt).Seconds())
	})
	adoptedAt := m9Now(t)

	t.Run("stays_refused", func(t *testing.T) {
		// Row 757: after the revision that revokes the cell, the cell stays refused, and envd settles the entry.
		m9PluginRefuses(t, m9Cell, clusterjwt.SourceRecord, healedAt, m9PluginBound+m9RecordBound)
		m9GatewayHelloRefused(t, m9Cell, adoptedAt, m9GatewayBound)
		waitFor(t, "envd to settle the entry "+id, 2*time.Minute, func() (bool, string) {
			held := m9Held(t)
			st := m9EntryOf(t, id)
			return held[m9Cell] == "" && st == "settled", fmt.Sprintf("envd holds %v, revoke -- list shows %q", held, st)
		})
		logs := m9PodLog(t, spireCluster, envdNamespace, "deploy/"+envdDeployment, envdDeployment, healedAt.Add(-logMargin))
		if _, _, ok := m9FirstLine(logs, func(l logLine) bool {
			return l.str("msg") == "revocation_settled" && l.str("id") == id && l.str("cause") == "revoked"
		}); !ok {
			t.Errorf("the envd log holds no revocation_settled line for %s with the cause revoked since the heal", id)
		}
	})

	t.Run("replay_refused", func(t *testing.T) {
		if !adopted {
			t.Skip("the entry was not adopted, so there is nothing to replay")
		}
		m9Unrevoke(t, m9Cell)
		since := m9Now(t)
		// The same entry goes in again, whether or not the key is still in the ConfigMap.
		m9PatchInput(t, id+".json", envelope)
		waitFor(t, "the envd log to hold revocation_refused revocation_stale for the entry "+id, 3*time.Minute, func() (bool, string) {
			logs := m9PodLog(t, spireCluster, envdNamespace, "deploy/"+envdDeployment, envdDeployment, since.Add(-logMargin))
			n := len(matching(logs, func(l logLine) bool {
				return l.str("msg") == "revocation_refused" && l.str("reason") == "revocation_stale" && l.str("id") == id
			}))
			return n > 0, fmt.Sprintf("%d lines, last lines: %s", n, lastLines(logs, 2))
		})
		if st := m9EntryOf(t, id); st != "stale" {
			t.Errorf("revoke -- list shows the replayed entry %s as %q, want stale", id, st)
		}
		if held := m9Held(t); held[m9Cell] != "" {
			t.Errorf("envd holds the entry %s for %s again after the un-revoke", held[m9Cell], m9Cell)
		}
		s := mgmtStatus(t)
		if c, _ := m9CellStatus(s, m9Cell); c.Revoked || len(s.PendingRevokes) > 0 {
			t.Errorf("after the replay mgmtd shows %s revoked %v with %d pending revokes, want not revoked and none", m9Cell, c.Revoked, len(s.PendingRevokes))
		}
		waitIssued(t, m9Cell, m9RecordBound+m9PluginBound)
	})
}
