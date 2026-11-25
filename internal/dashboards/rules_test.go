package dashboards

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func ruleByUID(t *testing.T, uid string) Rule {
	t.Helper()
	for _, r := range Rules().Groups[0].Rules {
		if r.UID == uid {
			return r
		}
	}
	t.Fatalf("no rule %s", uid)
	return Rule{}
}

func ruleExpr(r Rule) string {
	for _, q := range r.Data {
		if q.RefID == "A" {
			return q.Model["expr"].(string)
		}
	}
	return ""
}

func TestEightRules(t *testing.T) {
	f := Rules()
	if f.APIVersion != 1 || len(f.Groups) != 1 {
		t.Fatalf("file = %+v", f)
	}
	g := f.Groups[0]
	if g.Name != "cell-identity" || g.Folder != "Cell identity PoC alerts" || g.Interval != "30s" || g.OrgID != 1 {
		t.Errorf("group = %+v", g)
	}
	want := []struct {
		uid, title, hold, sev, eval string
		threshold                   float64
	}{
		{"poc-svid-low", "SVID under a quarter of its lifetime", "5m", "warning", "lt", 0.25},
		{"poc-island", "Island started", "0s", "warning", "gt", 120},
		{"poc-intermediate-ca", "Intermediate CA under 7 days", "0s", "critical", "lt", 604800},
		{"poc-attest-refusals", "Attestation refusals over 10 in 5 minutes", "0s", "warning", "gt", 10},
		{"poc-set-not-applied", "Set not applied, or a rollback", "0s", "warning", "gt", 0},
		{"poc-collector-queue", "Collector queue over 80% of its cap", "1m", "warning", "gt", 0.8},
		{"poc-tag-overwrite", "Source tag overwritten", "0s", "critical", "gt", 0},
		{"poc-tunnel-down", "Kiali tunnel down", "5m", "warning", "lt", 1},
	}
	if len(g.Rules) != len(want) {
		t.Fatalf("%d rules, want %d", len(g.Rules), len(want))
	}
	for i, w := range want {
		r := g.Rules[i]
		if r.UID != w.uid || r.Title != w.title || r.For != w.hold || r.Labels["severity"] != w.sev {
			t.Errorf("rule %d = %s %q for %s severity %s", i, r.UID, r.Title, r.For, r.Labels["severity"])
		}
		if r.Condition != "C" || r.NoDataState != "OK" || r.ExecErrState != "Error" || r.Annotations["summary"] == "" || len(r.Data) != 2 {
			t.Errorf("%s: settings = %+v", r.UID, r)
		}
		a, c := r.Data[0], r.Data[1]
		if a.RefID != "A" || a.DatasourceUID != "prometheus" || a.RelativeTimeRange == nil || c.RefID != "C" || c.DatasourceUID != "__expr__" || c.Model["type"] != "threshold" || c.Model["expression"] != "A" {
			t.Errorf("%s: data = %+v", r.UID, r.Data)
		}
		ev := c.Model["conditions"].([]any)[0].(map[string]any)["evaluator"].(map[string]any)
		if ev["type"] != w.eval || ev["params"].([]float64)[0] != w.threshold {
			t.Errorf("%s: evaluator = %v, want %s %v", r.UID, ev, w.eval, w.threshold)
		}
	}
}

func TestIslandRuleReadsGateway(t *testing.T) {
	expr := ruleExpr(ruleByUID(t, "poc-island"))
	for _, part := range []string{
		`cellproxy_gateway_last_export_time_seconds{k8s_cluster_name="management", signal="metrics"}`,
		`celld_upstream_age_seconds{platform_cell!=""}`,
		`envd_upstream_age_seconds{k8s_cluster_name="dev-cp"}`,
	} {
		if !strings.Contains(expr, part) {
			t.Errorf("A2 lacks %s: %s", part, expr)
		}
	}
	if strings.Contains(expr, SyntheticService) || strings.Contains(expr, "$cell") || strings.Contains(expr, "$cluster") {
		t.Errorf("A2 uses a dashboard filter or variable: %s", expr)
	}
}

func TestRuleQueriesNameKnownMetrics(t *testing.T) {
	if err := CheckQueries(nil, Rules()); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range Rules().Groups[0].Rules {
		ms, err := MetricNames(ruleExpr(r))
		if err != nil || len(ms) == 0 {
			t.Fatalf("%s: names %v, error %v", r.UID, ms, err)
		}
		for _, n := range ms {
			names[n] = true
		}
	}
	if !names["trust_ca_not_after_seconds"] || !names["cell_proxy_tunnel_up"] {
		t.Errorf("names = %v", names)
	}
	bad := mutateRules(func(r *Rule) { r.Data[0].Model["expr"] = `min(cell_proxy_tunnel_down)` })
	wantError(t, CheckQueries(nil, bad), "cell_proxy_tunnel_down")
}

// ruleGroupLabels is the label that a selector of each rule may name when it pins no cluster.
var ruleGroupLabels = map[string]string{
	"poc-svid-low": "platform_cell", "poc-island": "platform_cell", "poc-intermediate-ca": "trust_domain",
	"poc-attest-refusals": "k8s_cluster_name", "poc-set-not-applied": "k8s_cluster_name", "poc-collector-queue": "k8s_cluster_name",
	"poc-tag-overwrite": "k8s_cluster_name", "poc-tunnel-down": "k8s_cluster_name",
}

func TestRuleSelectorsNameEmitterOrGroupLabel(t *testing.T) {
	for _, r := range Rules().Groups[0].Rules {
		sels, err := Selectors(ruleExpr(r))
		if err != nil {
			t.Fatalf("%s: %v", r.UID, err)
		}
		for _, s := range sels {
			ok := false
			for _, m := range s.Matchers {
				if m.Label == "k8s_cluster_name" || m.Label == ruleGroupLabels[r.UID] {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s: selector %s names no cluster and no group label", r.UID, s.Name)
			}
		}
	}
}

func TestRuleFileParses(t *testing.T) {
	if err := CheckParse(nil, Rules()); err != nil {
		t.Fatal(err)
	}
	data, err := marshal(Rules())
	if err != nil {
		t.Fatal(err)
	}
	var back RuleFile
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Groups) != 1 || len(back.Groups[0].Rules) != 8 {
		t.Errorf("round trip lost rules: %+v", back)
	}
	seen := map[string]bool{}
	for _, r := range back.Groups[0].Rules {
		if seen[r.UID] || !strings.HasPrefix(r.UID, "poc-") || len(r.UID) > 40 {
			t.Errorf("uid %q", r.UID)
		}
		seen[r.UID] = true
	}
}

func TestEventRulesCountANewSeries(t *testing.T) {
	for uid, born := range map[string]string{
		"poc-attest-refusals": Born(`cluster_jwt_attestations_total{k8s_cluster_name="dev-cp", result="refused"}`, "5m"),
		"poc-set-not-applied": Born(`bundle_apply_outcomes_total{outcome="rolled_back", k8s_cluster_name!=""}`, "10m"),
		"poc-tag-overwrite":   Born(`cellproxy_gateway_attribute_overwrites_total{k8s_cluster_name="management", sender_cluster!=""}`, "5m"),
	} {
		if expr := ruleExpr(ruleByUID(t, uid)); !strings.Contains(expr, born) || !strings.Contains(born, " unless ") || !strings.Contains(born, " offset ") {
			t.Errorf("%s lacks the new-series term: %s", uid, expr)
		}
	}
}

func TestEventPanelsCountANewSeries(t *testing.T) {
	n := 0
	for _, b := range Boards() {
		for _, p := range b.Panels {
			for _, tg := range p.Targets {
				e := tg.Expr
				if !tg.Instant || !strings.Contains(e, "increase(") || strings.Contains(e, "_bucket") || strings.Contains(e, "_sum") {
					continue
				}
				n++
				if !strings.Contains(e, " unless ") || !strings.Contains(e, " offset ") {
					t.Errorf("%s %q: no new-series term: %s", b.UID, p.Title, e)
				}
			}
		}
	}
	if n < 10 {
		t.Errorf("checked %d targets", n)
	}
}

func TestRulesKeepSyntheticMarkerAndSVIDFloor(t *testing.T) {
	for _, r := range Rules().Groups[0].Rules {
		if !strings.Contains(ruleExpr(r), "service_name") {
			t.Errorf("%s drops service_name", r.UID)
		}
	}
	if e := ruleExpr(ruleByUID(t, "poc-svid-low")); !strings.Contains(e, "clamp_min(celld_svid_lifetime_seconds") {
		t.Errorf("A1 has no floor on the lifetime: %s", e)
	}
}

// TestRuleFieldsMatchGrafana checks the fields that Grafana v13.2.4 reads from a provisioned rule.
func TestRuleFieldsMatchGrafana(t *testing.T) {
	data, err := marshal(Rules())
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	evaluators := map[string]bool{"gt": true, "lt": true, "eq": true, "ne": true, "gte": true, "lte": true, "within_range": true, "outside_range": true}
	integral := func(v any) bool { x, ok := v.(float64); return ok && x == float64(int(x)) }
	for _, g := range f["groups"].([]any) {
		gm := g.(map[string]any)
		if _, err := time.ParseDuration(gm["interval"].(string)); err != nil || gm["name"] == "" || gm["folder"] == "" || !integral(gm["orgId"]) {
			t.Errorf("group = %v", gm)
		}
		for _, r := range gm["rules"].([]any) {
			rm := r.(map[string]any)
			uid := rm["uid"]
			for _, k := range []string{"uid", "title", "condition", "for", "noDataState", "execErrState"} {
				if s, ok := rm[k].(string); !ok || s == "" {
					t.Errorf("%v: field %s = %v", uid, k, rm[k])
				}
			}
			if _, err := time.ParseDuration(rm["for"].(string)); err != nil {
				t.Errorf("%v: for: %v", uid, err)
			}
			refs := map[string]bool{}
			for _, q := range rm["data"].([]any) {
				qm := q.(map[string]any)
				ref, _ := qm["refId"].(string)
				refs[ref] = true
				if _, ok := qm["datasourceUid"].(string); !ok || qm["model"] == nil {
					t.Errorf("%v %s: query = %v", uid, ref, qm)
				}
				if rt, ok := qm["relativeTimeRange"].(map[string]any); ref == "A" && (!ok || !integral(rt["from"])) {
					t.Errorf("%v: relativeTimeRange = %v", uid, qm["relativeTimeRange"])
				}
				if m := qm["model"].(map[string]any); m["type"] == "threshold" {
					ev := m["conditions"].([]any)[0].(map[string]any)["evaluator"].(map[string]any)
					if !evaluators[ev["type"].(string)] {
						t.Errorf("%v: evaluator %v", uid, ev)
					}
				}
			}
			if !refs[rm["condition"].(string)] {
				t.Errorf("%v: condition names no refId", uid)
			}
		}
	}
}
