//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// m15Show is the time that an event may take to reach a dashboard.
const m15Show = 60 * time.Second

// m15Target looks up one target of the committed dashboards by dashboard uid, panel title and refId. It returns the bare query.
func m15FindTarget(t *testing.T, dashboard, panel, ref string) m15Target {
	t.Helper()
	for _, tg := range m15Targets(t, loadM15Dashboards(t)) {
		if tg.Dashboard == dashboard && tg.Panel == panel && tg.RefID == ref {
			return tg
		}
	}
	t.Fatalf("the committed dashboards have no target %s of the panel %q in %s", ref, panel, dashboard)
	return m15Target{}
}

// m15Read runs the bare query of a target as an instant query and returns its series. An instant query has no step of 15 seconds, which
// a range query adds to each bound of this test.
func m15Read(t *testing.T, dashboard, panel, ref string) []sample {
	t.Helper()
	q := map[string]any{"refId": "A", "datasource": map[string]string{"uid": "prometheus", "type": "prometheus"},
		"expr": m15FindTarget(t, dashboard, panel, ref).Expr, "instant": true, "range": false}
	body, err := json.Marshal(map[string]any{"queries": []any{q}, "from": "now-1h", "to": "now"})
	if err != nil {
		t.Fatal(err)
	}
	code, resp := grafanaCall(t, m15Creds(t), "POST", "/api/ds/query", string(body))
	if code != 200 {
		t.Fatalf("instant query of %s %q: HTTP %d: %.300s", dashboard, panel, code, resp)
	}
	var out []sample
	for _, f := range framesOf(t, resp) {
		if len(f.Schema.Fields) < 2 || len(f.Data.Values) < 2 || len(f.Data.Values[1]) == 0 {
			continue
		}
		var vals []*float64
		if err := json.Unmarshal(mustJSON(t, f.Data.Values[1]), &vals); err != nil {
			t.Fatalf("decode the values of a frame: %v", err)
		}
		for i := len(vals) - 1; i >= 0; i-- {
			if vals[i] != nil {
				out = append(out, sample{labels: f.Schema.Fields[1].Labels, last: *vals[i]})
				break
			}
		}
	}
	return out
}

var m15CredsOnce struct {
	sync.Once
	v string
}

// m15Creds reads the admin credentials once.
func m15Creds(t *testing.T) string {
	t.Helper()
	m15CredsOnce.Do(func() { m15CredsOnce.v = "admin:" + grafanaPassword(t) })
	return m15CredsOnce.v
}

// m15SeriesNow reports whether the bare query of an event target returns a value now, and it waits up to limit.
func m15SeriesNow(t *testing.T, creds, dashboard, panel string, limit time.Duration) {
	t.Helper()
	tg := m15FindTarget(t, dashboard, panel, "A")
	body, err := m15Query(tg)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the event target "+tg.Name()+" to return a series", limit, func() (bool, string) {
		code, resp := grafanaCall(t, creds, "POST", "/api/ds/query", body)
		if code != 200 {
			return false, fmt.Sprintf("HTTP %d", code)
		}
		return m15FramesHaveValue(resp)
	})
}

// m15Total sums the last values of the series, and it reads no series as 0.
func m15Total(ss []sample) float64 {
	var sum float64
	for _, s := range ss {
		sum += s.last
	}
	return sum
}

// m15ByLabel sums the last values of the series that carry label=value.
func m15ByLabel(ss []sample, label, value string) (sum float64, found bool) {
	for _, s := range ss {
		if s.labels[label] == value {
			sum, found = sum+s.last, true
		}
	}
	return sum, found
}

// m15Within polls check every 5 seconds for up to limit from began. It logs the delay as name=seconds. When the limit passes, it fails the
// test and returns false, so that the caller can stop a step that depends on the check.
func m15Within(t *testing.T, name, what string, began time.Time, limit time.Duration, check func() (bool, string)) bool {
	t.Helper()
	var seen string
	for {
		ok, s := check()
		if ok {
			d := time.Since(began)
			t.Logf("%s=%.0f", name, d.Seconds())
			if m15Late(d, limit) {
				t.Errorf("%s showed after %s, over the limit of %s", what, d.Round(time.Second), limit)
				return false
			}
			return true
		}
		seen = s
		if time.Since(began) > limit {
			t.Errorf("%s did not show within %s: %s", what, limit, seen)
			return false
		}
		time.Sleep(5 * time.Second)
	}
}

// TestM15EventsShow makes a revoke, a cut and a key rotation, one at a time, and checks that each shows on its dashboard within a minute.
// It logs each measured delay. After the subtests it checks that the event targets of the panels they touched return a series.
func TestM15EventsShow(t *testing.T) {
	creds := m15RequireGrafana(t)

	t.Run("revoke", func(t *testing.T) {
		const cell = m9Cell
		m9RequireStart(t, cell)
		// Cleanups run in reverse order, so this check runs after the restore of the cell: State reads valid again within a minute.
		t.Cleanup(func() {
			m15Within(t, "CELLS_STATE_VALID_AGAIN_SECONDS", `"Cells" State of `+cell+" to read valid after the restore", time.Now(), m15Show, func() (bool, string) {
				v, ok := m15ByLabel(m15Read(t, "poc-cell-health", "Cells", "A"), "cluster", cell)
				return ok && v == 1, fmt.Sprintf("State value %v (found %v)", v, ok)
			})
		})
		m9RestoreCell(t, cell, false)
		validBefore := m15Total(m15Read(t, "poc-cell-health", "Cells valid", "A"))
		bansBefore := m15Total(m15Read(t, "poc-spiffe", "Agent bans", "A"))
		start := m9Now(t)
		revokedAt := time.Now()
		m9Revoke(t, cell)
		m15Within(t, "CELLS_STATE_REVOKED_SECONDS", `"Cells" State of `+cell+" to read revoked", revokedAt, m15Show, func() (bool, string) {
			ss := m15Read(t, "poc-cell-health", "Cells", "A")
			v, ok := m15ByLabel(ss, "cluster", cell)
			return ok && v == 3, fmt.Sprintf("State value %v (found %v)", v, ok)
		})
		m15Within(t, "CELLS_VALID_DROPS_SECONDS", `"Cells valid" to drop after the revoke`, revokedAt, m15Show, func() (bool, string) {
			now := m15Total(m15Read(t, "poc-cell-health", "Cells valid", "A"))
			return now < validBefore, fmt.Sprintf("%v, was %v", now, validBefore)
		})
		m15SeriesNow(t, creds, "poc-cell-health", "Revoked cells", time.Minute)
		var banAt time.Time
		waitFor(t, "the first agent_banned line of "+cell, m9BanBound+m9PluginBound, func() (bool, string) {
			logs := m9PodLog(t, spireCluster, spireNamespace, spireServerPod, "agent-ban", start.Add(-logMargin))
			_, at, ok := m9FirstLine(logs, func(l logLine) bool { return l.str("msg") == "agent_banned" && l.str("cell") == cell })
			banAt = at
			return ok, "no line yet"
		})
		m15Within(t, "AGENT_BANS_RISE_SECONDS", `"Agent bans" to rise after the first ban line`, banAt, m15Show, func() (bool, string) {
			now := m15Total(m15Read(t, "poc-spiffe", "Agent bans", "A"))
			return now > bansBefore, fmt.Sprintf("%v, was %v", now, bansBefore)
		})
	})

	t.Run("cut", func(t *testing.T) {
		const cell = m9Cell
		m9RequireStart(t, cell)
		streams := func() (float64, bool) {
			return m15ByLabel(m15Read(t, "poc-cell-health", "Cells", "D"), "cluster", cell)
		}
		// The restart of the revoke cleanup closes the stream, and Prometheus can read 0 or nothing for a short time after the new stream opens.
		waitFor(t, "the Stream column of "+cell+" to read at least 1 before the cut", 90*time.Second, func() (bool, string) {
			v, ok := streams()
			return ok && v >= 1, fmt.Sprintf("Stream %v (found %v)", v, ok)
		})
		// The proof below needs a fresh export age before the cut. At 30 s or less before it, and a threshold of at least 25 s above that value, the
		// pass can only come from the cut.
		var before float64
		waitFor(t, `"Last telemetry" of `+cell+" to read at most 30 s before the cut", time.Minute, func() (bool, string) {
			v, ok := m15ByLabel(m15Read(t, "poc-cell-health", "Cells", "H"), "cluster", cell)
			before = v
			return ok && v <= 30, fmt.Sprintf("seconds since the last export %v (found %v)", v, ok)
		})
		threshold := max(30, before+25)
		t.Logf("LAST_TELEMETRY_BEFORE_CUT_SECONDS=%.0f THRESHOLD_SECONDS=%.0f", before, threshold)
		// The cut takes effect while the partition command runs, so the bound counts from its start and the log names the command time.
		cutAt := time.Now()
		c := cutLink(t, cell, spireCluster, "both", 4*time.Minute)
		t.Logf("CUT_COMMAND_SECONDS=%.0f", time.Since(cutAt).Seconds())
		// The proof of "within one minute" is read on the connected side. A cut holds the telemetry of the cut cell in its own queue, so its
		// upstream age cannot reach Grafana. The telemetry gateway in management exports cellproxy.gateway.last_export.time every 10 s
		// (OTEL_METRIC_EXPORT_INTERVAL in components/telemetry-gateway/gateway.yaml), and the "Last telemetry" column of "Cells" shows the
		// seconds since the last export of the sender. The value passes 30 s within 30 s of the cut, and the next gateway export, the store
		// write and one poll add at most 20 s. The Stream column follows later, because the gateway ends a silent stream after 30 s and the
		// panel keeps the last sample for 1 minute (ruling B2).
		m15Within(t, "LAST_TELEMETRY_ABOVE_THRESHOLD_SECONDS", fmt.Sprintf(`"Last telemetry" of %s to rise above %.0f s`, cell, threshold), cutAt, m15Show, func() (bool, string) {
			v, ok := m15ByLabel(m15Read(t, "poc-cell-health", "Cells", "H"), "cluster", cell)
			return ok && v > threshold, fmt.Sprintf("seconds since the last export %v (found %v)", v, ok)
		})
		// A series that no longer reports leaves the panel, and a cell that mgmtd still lists reads 0, so absent and 0 both mean down.
		m15Within(t, "STREAM_DOWN_SECONDS", `"Stream" of `+cell+" to read down", cutAt, 2*time.Minute, func() (bool, string) {
			v, ok := streams()
			return !ok || v == 0, fmt.Sprintf("Stream %v", v)
		})
		if !m15Within(t, "A2_FIRE_SECONDS", "rule A2 to fire for "+cell, cutAt, 4*time.Minute, func() (bool, string) {
			return m15Firing(m15Alerts(t, creds), "Island started", "cluster", cell, false), "not firing"
		}) {
			t.Fatal("rule A2 did not fire, so the clear check has nothing to clear")
		}
		m15SeriesNow(t, creds, "poc-cell-health", "Islands now", time.Minute)
		c.Heal(t)
		healedAt := time.Now()
		m15Within(t, "A2_CLEAR_SECONDS", "rule A2 to clear for "+cell, healedAt, 4*time.Minute, func() (bool, string) {
			return !m15Firing(m15Alerts(t, creds), "Island started", "cluster", cell, false), "still firing"
		})
	})

	t.Run("key_rotation", func(t *testing.T) {
		const cell = rejectCell
		holdCelldDown(t, cell)
		checked := requireCurrentRecord(t, cell)
		waitRegistryAtCleanup(t)
		hint := func() float64 {
			v, _ := m15ByLabel(promSamples(t, `sum by (via) (last_over_time(mgmtd_keycheck_results_total{k8s_cluster_name="management", service_name!="m15-synthetic"}[1h]))`), "via", "hint")
			return v
		}
		reasonNow := func() float64 {
			v, _ := m15ByLabel(m15Read(t, "poc-spiffe", "Attestation refusals by reason", "A"), "reason", "unknown_kid")
			return v
		}
		reasonBefore, hintsBefore := reasonNow(), hint()
		retriesBefore := m15Total(m15Read(t, "poc-spiffe", "unknown_kid hints per hour", "A"))

		_, newKID := rotateAPIKey(t, cell)
		waitUpdateGap(t, checked)
		res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
		expectRefusal(t, res, cell, "unknown_kid", []string{newKID})
		refusedAt := firstRefusalAt(t, res.start, cell, newKID)

		m15Within(t, "UNKNOWN_KID_REASON_SECONDS", `"Attestation refusals by reason" to show unknown_kid`, refusedAt, m15Show, func() (bool, string) {
			now := reasonNow()
			return now > reasonBefore, fmt.Sprintf("unknown_kid %v, was %v", now, reasonBefore)
		})
		// The panel "unknown_kid hints per hour" reads the retry counter of mgmtd. A hint check does not always retry a report item, so
		// the test asserts the counter of the hint checks and logs the panel value.
		m15Within(t, "KEYCHECK_HINT_SECONDS", "the counter of hint key checks to rise", refusedAt, m15Show, func() (bool, string) {
			now := hint()
			return now > hintsBefore, fmt.Sprintf("hint checks %v, was %v", now, hintsBefore)
		})
		t.Logf("HINTS_PANEL_RETRIES before=%v after=%v", retriesBefore, m15Total(m15Read(t, "poc-spiffe", "unknown_kid hints per hour", "A")))
	})

	// V7: each event target of the panels above returns a series. The gauge targets "Revoked cells" and "Islands now" are checked inside
	// revoke and cut, before the restore and the heal, and the two counters are checked here. The targets of F21 have no live check.
	t.Run("event_targets_return_series", func(t *testing.T) {
		for _, w := range [][2]string{{"poc-spiffe", "Agent bans"}, {"poc-spiffe", "Attestation refusals by reason"}} {
			m15SeriesNow(t, creds, w[0], w[1], 2*time.Minute)
		}
		var none []string
		for _, tg := range m15Targets(t, loadM15Dashboards(t)) {
			if tg.EventOnly && !slices.Contains([]string{"Agent bans", "Attestation refusals by reason"}, tg.Panel) {
				none = append(none, tg.Name())
			}
		}
		t.Logf("event targets with no live check in this test (F21 and the gauges):\n%s", strings.Join(none, "\n"))
	})
}
