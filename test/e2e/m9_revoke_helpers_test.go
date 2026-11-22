//go:build e2e

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gateway"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	// m9RevokedFile lists the cells that a test revoked, one cell on each line. A test writes the cell before it revokes it, so
	// gate:m9:repair can run mgmt -- unrevoke for it after an aborted run.
	m9RevokedFile = "../../build/gate/m9-revoked"
	// m9OperatorKeyEnv holds OPERATOR_KEY_NAME and OPERATOR_KEY_SHA256 of the operator key. Both are public data.
	m9OperatorKeyEnv = "../../build/operator/key.env"
	// m9PluginBound is the time from a revocation to the first refusal of the plugin (plan: Task 18, plugin_refuses).
	m9PluginBound = 90 * time.Second
	// m9BanBound is the time from the record in the pod to the ban of every agent of the cell (plan: Task 18, agents_banned).
	m9BanBound = 100 * time.Second
	// m9CloseBound is the time from the log line "registry reloaded" to the close of every connection of the cell (row 28).
	m9CloseBound = 5 * time.Second
	// m9GatewayBound is the time from a revocation to the refusals of the gateway. The plan gives no value for the connected
	// case, so it takes the 2 minutes of verify row 8.
	m9GatewayBound = 2 * time.Minute
	// m9RecordBound is the time from a revocation to the record in the plugin pod: the kubelet sync of the ConfigMap volume.
	m9RecordBound = 3 * time.Minute
	// m9ValidWait is the time that a cell has to be valid again after the cleanup.
	m9ValidWait = 10 * time.Minute
	// m9RestartBound bounds the restart of the harness Deployments of one cell.
	m9RestartBound = 10 * time.Minute
	// m9ConnectedWithin is how recent the status report of envd must be for mgmtd to count as connected.
	m9ConnectedWithin = 2 * time.Minute
)

// m9Marked reports whether build/gate/m9-revoked lists the cell.
func m9Marked(cell string) bool {
	data, err := os.ReadFile(m9RevokedFile)
	return err == nil && slices.Contains(strings.Fields(string(data)), cell)
}

// m9MarkRevoked writes the cell to build/gate/m9-revoked, once. Call it before the first command that can revoke the cell.
func m9MarkRevoked(t *testing.T, cell string) {
	t.Helper()
	if m9Marked(cell) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m9RevokedFile), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(m9RevokedFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, werr := f.WriteString(cell + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		t.Fatalf("record %s in build/gate/m9-revoked: %v", cell, werr)
	}
}

// m9ClearRevoked removes the cell from build/gate/m9-revoked, and the file when it holds no other cell.
func m9ClearRevoked(cell string) error {
	data, err := os.ReadFile(m9RevokedFile)
	if err != nil {
		return nil
	}
	var rest []string
	for _, c := range strings.Fields(string(data)) {
		if c != cell {
			rest = append(rest, c)
		}
	}
	if len(rest) == 0 {
		return os.Remove(m9RevokedFile)
	}
	return os.WriteFile(m9RevokedFile, []byte(strings.Join(rest, "\n")+"\n"), 0o644)
}

// m9Revoke revokes the cell through mgmtd (mise run mgmt -- revoke), after it wrote the cell to build/gate/m9-revoked.
func m9Revoke(t *testing.T, cell string) mgmt.RevokeResult {
	t.Helper()
	m9MarkRevoked(t, cell)
	var res mgmt.RevokeResult
	if err := json.Unmarshal([]byte(mgmtCtl(t, "revoke", "--cell", cell)), &res); err != nil || res.Cell != cell {
		t.Fatalf("mgmt -- revoke --cell %s printed no result for the cell: %v", cell, err)
	}
	return res
}

// m9UnrevokeErr runs mgmt -- unrevoke for the cell. It returns the printed line, and the reason of a refusal.
func m9UnrevokeErr(cell string) (out, reason string, err error) {
	out, err = mgmtCtlErr("unrevoke", "--cell", cell)
	if err != nil {
		var f struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal([]byte(m9LastLine(out)), &f)
		reason = f.Reason
	}
	return out, reason, err
}

// m9Unrevoke un-revokes the cell through mgmtd and fails the test when mgmtd refuses.
func m9Unrevoke(t *testing.T, cell string) {
	t.Helper()
	if out, reason, err := m9UnrevokeErr(cell); err != nil {
		t.Fatalf("mgmt -- unrevoke --cell %s: %v (reason %q)\n%s", cell, err, reason, out)
	}
}

func m9LastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// m9Status reads the status of mgmtd without failing the test, for polls and cleanups.
func m9Status() (mgmt.Status, error) {
	var s mgmt.Status
	out, err := mgmtCtlErr("status")
	if err != nil {
		return s, fmt.Errorf("mgmt -- status: %w: %s", err, out)
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return s, fmt.Errorf("mgmt -- status is no status object: %w", err)
	}
	return s, nil
}

// m9CellStatus returns the entry of the cell in a status.
func m9CellStatus(s mgmt.Status, cell string) (mgmt.CellStatus, bool) {
	for _, c := range s.Cells {
		if c.Name == cell {
			return c, true
		}
	}
	return mgmt.CellStatus{}, false
}

// m9Connected reports whether mgmtd counts the environment as connected: a status report of envd within 2 minutes, and the applied
// revision equal to the signed one. The text says what it saw.
func m9Connected(s mgmt.Status) (bool, string) {
	age := time.Since(s.LastReportAt)
	return !s.LastReportAt.IsZero() && age <= m9ConnectedWithin && s.Applied == s.Signed,
		fmt.Sprintf("last report %s ago, applied %v, signed %v", age.Round(time.Second), s.Applied, s.Signed)
}

// m9RequireStart makes sure that the cell can be revoked: the image of attestprobe is known, mgmtd counts the environment as
// connected, the cell is valid and not revoked, and the gateway holds a stream of the cell.
func m9RequireStart(t *testing.T, cell string) {
	t.Helper()
	needAttestprobeImage(t)
	s, err := m9Status()
	if err != nil {
		t.Fatal(err)
	}
	if ok, seen := m9Connected(s); !ok {
		t.Fatalf("mgmtd does not count the environment as connected (%s). Run: mise run gate:m9:repair", seen)
	}
	c, ok := m9CellStatus(s, cell)
	switch {
	case !ok:
		t.Fatalf("mgmtd shows no cell %s", cell)
	case c.Revoked:
		t.Fatalf("%s is revoked before the test. Run: mise run gate:m9:repair", cell)
	case !c.Valid:
		t.Fatalf("%s is not valid before the test (%s)", cell, c.ValidReason)
	}
	waitFor(t, "the gateway to hold a stream of "+cell, 2*time.Minute, func() (bool, string) {
		st := gwStatus(t)
		return st.Streams[cell] >= 1, fmt.Sprintf("streams %v", st.Streams)
	})
}

// m9RestoreCell registers the cleanup of a test that revokes the cell. Register it before every other cleanup of the test (they run
// in reverse order), and before the cut, so that the heal runs first. It acts only when build/gate/m9-revoked lists the cell. It
//  1. waits until mgmtd holds no queued revoke of the cell, and (local) until envd holds no entry for it, because mgmtd adopts each
//     entry and un-revoke refuses an entry that is held;
//  2. runs mgmt -- unrevoke, which a cell that is not revoked answers with not_revoked;
//  3. (local) runs revoke -- clean;
//  4. runs CELL=<cell> mise run cell:restart, because the banned agents of the cell never renew;
//  5. waits until the cell is valid and not revoked, within 10 minutes, and then removes the cell from build/gate/m9-revoked.
//
// A step that fails reports an error and does not stop the next step, and the file keeps the cell, so gate:m9:repair can recover.
func m9RestoreCell(t *testing.T, cell string, local bool) {
	t.Helper()
	t.Cleanup(func() {
		if !m9Marked(cell) {
			return
		}
		// An adoption after a failure in the island needs the adoption bound, then the settle and the unrevoke.
		deadline := time.Now().Add(m9ValidWait)
		if local {
			deadline = time.Now().Add(m9AdoptBound + 5*time.Minute)
		}
		fail := false
		report := func(format string, args ...any) {
			fail = true
			t.Errorf(format+". Run: mise run gate:m9:repair", args...)
		}
		// 1 and 2.
		for {
			s, err := m9Status()
			if err == nil {
				queued := slices.ContainsFunc(s.PendingRevokes, func(p mgmt.PendingRevoke) bool { return p.Cell == cell })
				held := local && (m9EntryState(t, cell, "held") || m9EntryState(t, cell, "pending"))
				if !queued && !held {
					_, reason, uerr := m9UnrevokeErr(cell)
					if uerr == nil || reason == "not_revoked" {
						break
					}
					if reason != "not_connected" && reason != "overlay_held" {
						report("cleanup: mgmt -- unrevoke --cell %s: %v (reason %q)", cell, uerr, reason)
						break
					}
				}
			}
			if time.Now().After(deadline) {
				report("cleanup: %s stayed revoked, queued or held until the deadline (last status error: %v)", cell, err)
				break
			}
			time.Sleep(5 * time.Second)
		}
		// The plugin must hold the unrevoked record before the agents attest again, or they retry against a refusal.
		m9WaitPluginAtSigned(t, 5*time.Minute)
		// 3.
		if local {
			if out, err := miseRun(t, 2*time.Minute, nil, "revoke", "--", "clean"); err != nil {
				report("cleanup: revoke -- clean: %v\n%s", err, out)
			}
		}
		// 4.
		if out, err := miseRun(t, m9RestartBound, []string{"CELL=" + cell}, "cell:restart"); err != nil {
			report("cleanup: CELL=%s mise run cell:restart: %v\n%s", cell, err, out)
		}
		// 5. The cell has m9ValidWait from the end of the restart.
		validBy := time.Now().Add(m9ValidWait)
		for last := "no status"; ; time.Sleep(5 * time.Second) {
			s, err := m9Status()
			if err == nil {
				c, ok := m9CellStatus(s, cell)
				if ok && c.Valid && !c.Revoked {
					break
				}
				last = fmt.Sprintf("known %v, valid %v, revoked %v, reason %q", ok, c.Valid, c.Revoked, c.ValidReason)
			} else {
				last = err.Error()
			}
			if time.Now().After(validBy) {
				report("cleanup: %s is not valid %s after the restart (%s)", cell, m9ValidWait, last)
				break
			}
		}
		if !fail {
			if err := m9ClearRevoked(cell); err != nil {
				t.Errorf("cleanup: remove %s from build/gate/m9-revoked: %v", cell, err)
			}
		}
	})
}

// m9EntryState reports whether revoke -- list shows an entry of the cell in the state.
func m9EntryState(t *testing.T, cell, state string) bool {
	out, err := miseRun(t, 2*time.Minute, nil, "revoke", "--", "list")
	if err != nil {
		return false
	}
	for l := range strings.SplitSeq(out, "\n") {
		var e struct {
			Cell  string `json:"cell"`
			State string `json:"state"`
		}
		if json.Unmarshal([]byte(l), &e) == nil && e.Cell == cell && e.State == state {
			return true
		}
	}
	return false
}

// m9Entry is one line of revoke -- list.
type m9Entry struct {
	Key   string `json:"key"`
	ID    string `json:"id"`
	Cell  string `json:"cell"`
	State string `json:"state"`
}

// m9ListEntries runs revoke -- list and returns its lines.
func m9ListEntries(t *testing.T) []m9Entry {
	t.Helper()
	out, err := miseRun(t, 2*time.Minute, nil, "revoke", "--", "list")
	if err != nil {
		t.Fatalf("mise run revoke -- list: %v\n%s", err, out)
	}
	var es []m9Entry
	for l := range strings.SplitSeq(out, "\n") {
		var e m9Entry
		if strings.HasPrefix(l, "{") && json.Unmarshal([]byte(l), &e) == nil && e.Key != "" {
			es = append(es, e)
		}
	}
	return es
}

// m9EntryOf returns the state of the entry with the ID in revoke -- list, or "absent".
func m9EntryOf(t *testing.T, id string) string {
	t.Helper()
	for _, e := range m9ListEntries(t) {
		if e.ID == id {
			return e.State
		}
	}
	return "absent"
}

// m9Held returns the cell and the ID of each entry that envd holds, from key local-revocations.json of ConfigMap cell-records.
func m9Held(t *testing.T) map[string]string {
	t.Helper()
	data, _, _, err := recordsConfigMap(t)
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]string{}
	raw := data["local-revocations.json"]
	if raw == "" {
		return held
	}
	var envelopes []struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(raw), &envelopes); err != nil {
		t.Fatalf("key local-revocations.json of %s is no JSON array: %v", recordsMap, err)
	}
	for _, e := range envelopes {
		p, err := base64Decode(e.Payload)
		var entry struct {
			ID   string `json:"id"`
			Cell string `json:"cell"`
		}
		if err != nil || json.Unmarshal(p, &entry) != nil {
			t.Fatalf("an envelope in local-revocations.json has no readable payload: %v", err)
		}
		held[entry.Cell] = entry.ID
	}
	return held
}

// m9PodLog returns the log of one container since a time.
func m9PodLog(t *testing.T, cluster, ns, pod, container string, since time.Time) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "logs", pod, "-c", container, "--since-time="+since.UTC().Format(time.RFC3339))
	if err != nil {
		t.Logf("read the log of %s/%s %s: %v", ns, pod, container, err)
	}
	return out
}

// m9FirstLine returns the line of the logs with the earliest time that keep accepts.
func m9FirstLine(logs string, keep func(logLine) bool) (logLine, time.Time, bool) {
	var first logLine
	var at time.Time
	for _, l := range matching(logs, keep) {
		if lt := lineTime(l); first == nil || lt.Before(at) {
			first, at = l, lt
		}
	}
	return first, at, first != nil
}

func number(l logLine, key string) float64 {
	n, _ := l[key].(float64)
	return n
}

// m9GatewayRefuses waits until the log of the gateway holds the refusal of the open stream of the cell with the reason cell_revoked
// (stream_refused with the pod of the stream) since a time, and until a new hello that the test makes (m9GatewayHello) gets a
// refused frame cell_revoked. It returns the time of each on the clock of the node, which the caller compares with the start.
func m9GatewayRefuses(t *testing.T, cell string, since time.Time, wait time.Duration) (ended, hello time.Time) {
	t.Helper()
	waitFor(t, "the gateway log to hold stream_refused cell_revoked with the pod of the open stream of "+cell, wait, func() (bool, string) {
		logs := m9PodLog(t, spireCluster, gatewayNamespace, gatewayPod, "cellgw", since.Add(-logMargin))
		l, at, ok := m9FirstLine(logs, func(l logLine) bool {
			_, withPod := l["pod"]
			return l.str("msg") == "stream_refused" && l.str("cell") == cell && l.str("reason") == "cell_revoked" && withPod
		})
		ended = at
		return ok, fmt.Sprintf("no such line in %d log bytes, last lines: %s (%v)", len(logs), lastLines(logs, 2), l)
	})
	return ended, m9GatewayHelloRefused(t, cell, since, wait)
}

// m9RecordInPod waits until the plugin log "records reloaded" shows the revocation since a time, and returns the time of that line:
// a changed record (connected) or an overlay entry (island). It is the moment at which the pod holds the revocation.
func m9RecordInPod(t *testing.T, since time.Time, wait time.Duration) time.Time {
	t.Helper()
	var at time.Time
	waitFor(t, "the plugin log of the SPIRE server to show a reload with a changed record or an overlay entry", wait, func() (bool, string) {
		logs := m9PodLog(t, spireCluster, spireNamespace, spireServerPod, "spire-server", since.Add(-logMargin))
		l, lt, ok := m9FirstLine(logs, func(l logLine) bool {
			return l.str("msg") == "records reloaded" && (number(l, "changed") >= 1 || number(l, "overlay") >= 1)
		})
		at = lt
		return ok, fmt.Sprintf("%d bytes of log, last reload line %v", len(logs), l)
	})
	return at
}

// m9PluginRefuses runs attestprobe in the cell until it prints denied with the reason revoked and the log of the plugin holds the
// refusal of the cell with the source (record or overlay) since a time, within the wait. The record takes precedence over the overlay
// in the plugin, so a poll that follows the settle of an entry asks for source record.
func m9PluginRefuses(t *testing.T, cell, source string, since time.Time, wait time.Duration) {
	t.Helper()
	want := "denied:nodeattestor(cluster_jwt): " + string(clusterjwt.Revoked)
	waitFor(t, "attestprobe in "+cell+" to print "+want+", with a plugin log line of source "+source, wait, func() (bool, string) {
		res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
		if res.out != want {
			return false, "attestprobe printed " + res.out
		}
		logs := m9PodLog(t, spireCluster, spireNamespace, spireServerPod, "spire-server", since.Add(-logMargin))
		var sources []string
		for _, l := range matching(logs, func(l logLine) bool {
			return l.str("msg") == refusedMsg && l.str("cell") == cell && l.str("reason") == "revoked"
		}) {
			sources = append(sources, l.str("source"))
		}
		return slices.Contains(sources, source), fmt.Sprintf("attestprobe was refused, and the plugin log names the sources %v", sources)
	})
}

// m9GatewayHelloRefused waits until a new hello of the cell, made in the test, gets a refused frame cell_revoked, and until the
// gateway log holds a stream_refused line with no pod for it. It returns the time of the answer on the clock of the node.
func m9GatewayHelloRefused(t *testing.T, cell string, since time.Time, wait time.Duration) time.Time {
	t.Helper()
	var at time.Time
	waitFor(t, "the gateway to answer a new hello of "+cell+" with a refused frame cell_revoked", wait, func() (bool, string) {
		reason, err := m9GatewayHello(t, cell)
		if err != nil || reason != "cell_revoked" {
			return false, fmt.Sprintf("reason %q, error %v", reason, err)
		}
		at = m9Now(t)
		logs := m9PodLog(t, spireCluster, gatewayNamespace, gatewayPod, "cellgw", since.Add(-logMargin))
		n := len(matching(logs, func(l logLine) bool {
			_, withPod := l["pod"]
			return l.str("msg") == "stream_refused" && l.str("cell") == cell && l.str("reason") == "cell_revoked" && !withPod
		}))
		return n > 0, "the frame was cell_revoked, and the gateway log holds no stream_refused line without a pod"
	})
	return at
}

// m9Agent is one agent that the SPIRE server lists.
type m9Agent struct {
	ID     string
	Banned bool
}

// m9AgentsOf lists the cluster_jwt agents of the cell, from spire-server agent list. Banned and expired agents stay listed.
func m9AgentsOf(t *testing.T, cell string) []m9Agent {
	t.Helper()
	out, err := spireServer(t, "agent", "list", "-socketPath", spireSocket, "-output", "json")
	if err != nil {
		t.Fatalf("spire-server agent list: %v", err)
	}
	var res struct {
		Agents []struct {
			ID struct {
				TrustDomain string `json:"trust_domain"`
				Path        string `json:"path"`
			} `json:"id"`
			Banned bool `json:"banned"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode agent list: %v", err)
	}
	var agents []m9Agent
	for _, a := range res.Agents {
		if strings.HasPrefix(a.ID.Path, "/spire/agent/cluster_jwt/"+cell+"/") {
			agents = append(agents, m9Agent{ID: "spiffe://" + a.ID.TrustDomain + a.ID.Path, Banned: a.Banned})
		}
	}
	return agents
}

// m9BannedSet returns the IDs of the banned agents of the cell.
func m9BannedSet(t *testing.T, cell string) []string {
	t.Helper()
	var ids []string
	for _, a := range m9AgentsOf(t, cell) {
		if a.Banned {
			ids = append(ids, a.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

// m9AgentsBanned checks the ban of the cell. The record is in the pod at recordAt (m9RecordInPod). Every cluster_jwt agent of the
// cell must be banned within m9BanBound of that time, and the log of the agent-ban container must name the source for each ban. No
// agent of the other cell may be banned, beyond those that were banned before (otherBefore).
func m9AgentsBanned(t *testing.T, cell, other, source string, recordAt time.Time, since time.Time, otherBefore []string) {
	t.Helper()
	if len(m9AgentsOf(t, cell)) == 0 {
		t.Fatalf("the SPIRE server lists no cluster_jwt agent of %s, so the ban has nothing to show", cell)
	}
	wait := max(time.Until(recordAt.Add(m9BanBound)), 20*time.Second)
	waitFor(t, "every cluster_jwt agent of "+cell+" to be banned", wait, func() (bool, string) {
		var open []string
		for _, a := range m9AgentsOf(t, cell) {
			if !a.Banned {
				open = append(open, a.ID)
			}
		}
		return len(open) == 0, fmt.Sprintf("%d agents not banned: %v", len(open), open)
	})
	logs := m9PodLog(t, spireCluster, spireNamespace, spireServerPod, "agent-ban", since.Add(-logMargin))
	var last time.Time
	bans := matching(logs, func(l logLine) bool { return l.str("msg") == "agent_banned" })
	for _, l := range bans {
		switch l.str("cell") {
		case cell:
			if l.str("source") != source {
				t.Errorf("agent-ban banned %v for %s with source %q, want %q", l["agent_id"], cell, l.str("source"), source)
			}
			if at := lineTime(l); at.After(last) {
				last = at
			}
		case other:
			t.Errorf("agent-ban banned %v of %s, which is not revoked", l["agent_id"], other)
		}
	}
	if last.IsZero() {
		t.Errorf("the agent-ban log holds no agent_banned line for %s since %s", cell, since.UTC().Format(time.RFC3339))
	} else {
		took := last.Sub(recordAt)
		t.Logf("AGENT_BAN_SECONDS=%.0f from the record in the pod to the last ban of %s", took.Seconds(), cell)
		if took > m9BanBound {
			t.Errorf("the last ban of %s came %s after the record reached the pod, want at most %s", cell, took.Round(time.Second), m9BanBound)
		}
	}
	if now := m9BannedSet(t, other); !slices.Equal(now, otherBefore) {
		t.Errorf("the banned agents of %s changed from %v to %v, want no change", other, otherBefore, now)
	}
}

// m9OperatorKeySHA256 returns OPERATOR_KEY_SHA256 from build/operator/key.env.
func m9OperatorKeySHA256(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(m9OperatorKeyEnv)
	if err != nil {
		t.Fatalf("read build/operator/key.env: %v. The owner creates the operator key with: mise run operator:create-key", err)
	}
	for l := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(l, "OPERATOR_KEY_SHA256="); ok && v != "" {
			return v
		}
	}
	t.Fatal("build/operator/key.env holds no OPERATOR_KEY_SHA256")
	return ""
}

// base64Decode decodes the standard or the URL form of base64, with or without padding.
func base64Decode(s string) ([]byte, error) {
	if p, err := base64.StdEncoding.DecodeString(s); err == nil {
		return p, nil
	}
	if p, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return p, nil
	}
	if p, err := base64.URLEncoding.DecodeString(s); err == nil {
		return p, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// m9PluginRevision returns the newest spec revision that the plugin log of the SPIRE server shows in "records reloaded". It does not
// fail the test, so a cleanup can use it.
func m9PluginRevision() (epoch, counter uint64, err error) {
	out, err := command("", "kubectl", "--context", "kind-"+spireCluster, "-n", spireNamespace, "logs", spireServerPod, "-c", "spire-server", "--since=2h")
	if err != nil {
		return 0, 0, err
	}
	for _, l := range matching(out, func(l logLine) bool { return l.str("msg") == "records reloaded" }) {
		e, c := uint64(number(l, "spec_epoch")), uint64(number(l, "spec_counter"))
		if e > epoch || (e == epoch && c > counter) {
			epoch, counter = e, c
		}
	}
	return epoch, counter, nil
}

// m9WaitPluginAtSigned waits, without failing the test, until envd applied the revision that mgmtd signed and the plugin holds it.
// A timeout is logged only, because the cleanup goes on with the restart.
func m9WaitPluginAtSigned(t *testing.T, wait time.Duration) {
	t.Helper()
	end := time.Now().Add(wait)
	last := ""
	for time.Now().Before(end) {
		if s, err := m9Status(); err == nil {
			e, c, perr := m9PluginRevision()
			last = fmt.Sprintf("signed %v, applied %v, plugin %d.%d (%v)", s.Signed, s.Applied, e, c, perr)
			if s.Applied == s.Signed && perr == nil && (e > s.Signed.Epoch || (e == s.Signed.Epoch && c >= s.Signed.Counter)) {
				return
			}
		}
		time.Sleep(5 * time.Second)
	}
	t.Logf("cleanup: the plugin did not reach the signed revision in %s (%s)", wait, last)
}

// m9PluginAtRevision waits until the plugin log "records reloaded" shows a spec at or after rev (row 37: the plugin holds the new
// revision), and returns the time of the check on the clock of the node.
func m9PluginAtRevision(t *testing.T, rev spec.Revision, wait time.Duration) time.Time {
	t.Helper()
	waitFor(t, fmt.Sprintf("the plugin of the SPIRE server to reload records at the spec revision %d.%d or later", rev.Epoch, rev.Counter), wait, func() (bool, string) {
		e, c, err := m9PluginRevision()
		return err == nil && (e > rev.Epoch || (e == rev.Epoch && c >= rev.Counter)), fmt.Sprintf("the plugin shows %d.%d (%v)", e, c, err)
	})
	return m9Now(t)
}

var m9Offset struct {
	set bool
	d   time.Duration
}

// m9Now is the time of the node on the clock scale of the Mac: --since-time filters by the clock of the node, so each time that a
// test compares with a log line comes from here. It reads dev-cp-control-plane once.
func m9Now(t *testing.T) time.Time {
	t.Helper()
	if !m9Offset.set {
		out, err := command("", "docker", "exec", spireCluster+"-control-plane", "date", "+%s.%N")
		if err != nil {
			t.Fatalf("read the clock of %s-control-plane: %v", spireCluster, err)
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
		if err != nil {
			t.Fatalf("the clock of %s-control-plane printed %q", spireCluster, out)
		}
		m9Offset.d = time.Duration(f*float64(time.Second)) - time.Duration(time.Now().UnixNano())
		m9Offset.set = true
		t.Logf("the clock of %s-control-plane is %s ahead of the Mac", spireCluster, m9Offset.d.Round(time.Millisecond))
	}
	return time.Now().Add(m9Offset.d)
}

// m9RequireNoEntries fails when ConfigMap local-revocations holds an entry, because the single refusal line of envd for a reason
// would then come from that entry, and replay_refused would wait for a line that never comes.
func m9RequireNoEntries(t *testing.T) {
	t.Helper()
	if es := m9ListEntries(t); len(es) > 0 {
		t.Fatalf("ConfigMap envd-system/local-revocations holds %d entries from an earlier run (%+v). Run: mise run revoke -- clean", len(es), es)
	}
}

// m9GatewayHello makes a new hello of the cell in the test, not through celld: it mints a celld SVID of the cell in dev-cp, opens
// the stream through a port-forward of svc/cell-gateway-stream, and reads the first frame. The gateway checks the record and the
// overlay before it reads the hello, so a revoked cell gets a refused frame with no token. A celld of a banned cell holds no valid
// SVID after one lifetime, and the gateway then fails the handshake without a log line, so the test cannot use celld here. It returns
// the reason of the refused frame, or the type of another frame.
func m9GatewayHello(t *testing.T, cell string) (string, error) {
	t.Helper()
	cert := senderCert(t, "spiffe://"+envTrustDomain+"/cell/"+cell+"/"+gateway.CelldRole)
	roots := x509.NewCertPool()
	for _, c := range bundleRoots(t, envCluster) {
		roots.AddCert(c)
	}
	conf := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			var chain []*x509.Certificate
			for _, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				chain = append(chain, c)
			}
			inter := x509.NewCertPool()
			for _, c := range chain[1:] {
				inter.AddCert(c)
			}
			_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			return err
		},
	}
	addr := portForward(t, envCluster, gatewayNamespace, "svc/cell-gateway-stream", 8450)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: conf, ForceAttemptHTTP2: true}, Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	pr, pw := io.Pipe()
	defer pw.Close()
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+gwapi.StreamPath(cell), pr)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the gateway answered %s", resp.Status)
	}
	f, err := gwapi.NewDecoder(resp.Body).Decode()
	if err != nil {
		return "", err
	}
	if f.Type != gwapi.TypeRefused {
		return "frame " + f.Type, nil
	}
	return f.Reason, nil
}
