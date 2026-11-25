//go:build e2e

package e2e

import (
	"fmt"
	"slices"
	"strings"
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

// m15Read runs the bare query of a target and returns its series.
func m15Read(t *testing.T, dashboard, panel, ref string) []sample {
	t.Helper()
	return promSamples(t, m15FindTarget(t, dashboard, panel, ref).Expr)
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

// m15Within polls check every 5 seconds for up to limit from began. It logs the delay as name=seconds and fails the test when the limit passes.
func m15Within(t *testing.T, name, what string, began time.Time, limit time.Duration, check func() (bool, string)) {
	t.Helper()
	var seen string
	for {
		ok, s := check()
		if ok {
			t.Logf("%s=%.0f", name, time.Since(began).Seconds())
			return
		}
		seen = s
		if time.Since(began) > limit {
			t.Errorf("%s did not show within %s: %s", what, limit, seen)
			return
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
		m9RestoreCell(t, cell, false)
		bansBefore := m15Total(m15Read(t, "poc-spiffe", "Agent bans", "A"))
		start := m9Now(t)
		m9Revoke(t, cell)
		revokedAt := time.Now()
		m15Within(t, "CELLS_STATE_REVOKED_SECONDS", `"Cells" State of `+cell+" to read revoked", revokedAt, m15Show, func() (bool, string) {
			ss := m15Read(t, "poc-cell-health", "Cells", "A")
			v, ok := m15ByLabel(ss, "cluster", cell)
			return ok && v == 3, fmt.Sprintf("State value %v (found %v)", v, ok)
		})
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
		if v, ok := streams(); !ok || v < 1 {
			t.Fatalf("the Stream column of %s reads %v (found %v) before the cut, want at least 1", cell, v, ok)
		}
		c := cutLink(t, cell, spireCluster, "both", 4*time.Minute)
		cutAt := time.Now()
		// A series that no longer reports leaves the panel, and a cell that mgmtd still lists reads 0, so absent and 0 both mean down.
		m15Within(t, "STREAM_DOWN_SECONDS", `"Stream" of `+cell+" to read down", cutAt, m15Show, func() (bool, string) {
			v, ok := streams()
			return !ok || v == 0, fmt.Sprintf("Stream %v", v)
		})
		m15Within(t, "A2_FIRE_SECONDS", "rule A2 to fire for "+cell, cutAt, 4*time.Minute, func() (bool, string) {
			return m15Firing(m15Alerts(t, creds), "Island started", "cluster", cell), "not firing"
		})
		c.Heal(t)
		healedAt := time.Now()
		m15Within(t, "A2_CLEAR_SECONDS", "rule A2 to clear for "+cell, healedAt, 4*time.Minute, func() (bool, string) {
			return !m15Firing(m15Alerts(t, creds), "Island started", "cluster", cell), "still firing"
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

	// V7: each event target of the panels above returns a series after the events. A gauge target ("Revoked cells", "Islands now") is empty
	// again after the restore, and the targets of F21 have no live check, so only the two counters are asserted.
	t.Run("event_targets_return_series", func(t *testing.T) {
		for _, w := range [][2]string{{"poc-spiffe", "Agent bans"}, {"poc-spiffe", "Attestation refusals by reason"}} {
			tg := m15FindTarget(t, w[0], w[1], "A")
			body, err := m15Query(tg)
			if err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the event target "+tg.Name()+" to return a series", 2*time.Minute, func() (bool, string) {
				code, resp := grafanaCall(t, creds, "POST", "/api/ds/query", body)
				if code != 200 {
					return false, fmt.Sprintf("HTTP %d", code)
				}
				return m15FramesHaveValue(resp)
			})
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
