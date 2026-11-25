package dashboards

// Rule group settings.
const (
	ruleGroupName   = "cell-identity"
	ruleFolderTitle = "Cell identity PoC alerts"
	ruleInterval    = "30s"
	ruleRangeFrom   = 600
)

// ruleSpec is one alert rule of the table: the query A, the threshold of C and the settings.
type ruleSpec struct {
	uid, title, expr, evaluator, summary, severity, hold string
	threshold                                            float64
}

// islandRuleExpr is the query A of rule A2. It shares IslandAge with "Islands now", and it also reads the synthetic series of the gate.
func islandRuleExpr() string {
	return IslandAge(IslandScope{Cell: `platform_cell!=""`})
}

func ruleSpecs() []ruleSpec {
	return []ruleSpec{
		{"poc-svid-low", "SVID under a quarter of its lifetime",
			`min by (platform_cell) (celld_svid_remaining_seconds{platform_cell!=""} / celld_svid_lifetime_seconds{platform_cell!=""})`,
			"lt", "The SVID of cell {{ $labels.platform_cell }} has less than a quarter of its lifetime left.", "warning", "5m", 0.25},
		{"poc-island", "Island started", islandRuleExpr(),
			"gt", "Layer {{ $labels.cluster }} has lost its upstream for more than 2 minutes.", "warning", "0s", 120},
		{"poc-intermediate-ca", "Intermediate CA under 7 days",
			`min by (trust_domain) (` + fresh(`trust_ca_not_after_seconds{ca="intermediate", trust_domain!=""}`, freshSlow) + `) - time()`,
			"lt", "The intermediate CA of trust domain {{ $labels.trust_domain }} expires within 7 days.", "critical", "0s", 604800},
		{"poc-attest-refusals", "Attestation refusals over 10 in 5 minutes",
			`sum by (cell) (increase(cluster_jwt_attestations_total{k8s_cluster_name="dev-cp", result="refused"}[5m]))`,
			"gt", "The control plane refused more than 10 attestations of cell {{ $labels.cell }} in 5 minutes.", "warning", "0s", 10},
		{"poc-set-not-applied", "Set not applied, or a rollback",
			`count_over_time((count by (k8s_cluster_name) (argocd_app_info{job="argocd", sync_status!="Synced", k8s_cluster_name!=""}))[10m:1m]) >= 10 or ` +
				`sum by (k8s_cluster_name) (increase(bundle_apply_outcomes_total{outcome="rolled_back", k8s_cluster_name!=""}[10m])) > 0`,
			"gt", "Cluster {{ $labels.k8s_cluster_name }} has not applied the set for 10 minutes, or it rolled back.", "warning", "0s", 0},
		{"poc-collector-queue", "Collector queue over 80% of its cap",
			`max by (k8s_cluster_name, data_type) (otelcol_exporter_queue_size{k8s_cluster_name!=""} / otelcol_exporter_queue_capacity{k8s_cluster_name!=""})`,
			"gt", "The exporter queue of the collector in {{ $labels.k8s_cluster_name }} is over 80% of its cap.", "warning", "1m", 0.8},
		{"poc-tag-overwrite", "Source tag overwritten",
			`sum by (sender_cluster) (increase(cellproxy_gateway_attribute_overwrites_total{k8s_cluster_name="management", sender_cluster!=""}[5m]))`,
			"gt", "The telemetry gateway overwrote the source tag of sender {{ $labels.sender_cluster }}.", "critical", "0s", 0},
		{"poc-tunnel-down", "Kiali tunnel down",
			`min by (cell) (cell_proxy_tunnel_up{k8s_cluster_name="management", side="hub", cell!=""})`,
			"lt", "The Kiali tunnel of cell {{ $labels.cell }} is down.", "warning", "5m", 1},
	}
}

func (s ruleSpec) rule() Rule {
	return Rule{
		UID: s.uid, Title: s.title, Condition: "C", NoDataState: "OK", ExecErrState: "Error", For: s.hold,
		Data: []RuleQuery{
			{RefID: "A", DatasourceUID: DSPrometheus, RelativeTimeRange: &RelativeRange{From: ruleRangeFrom},
				Model: map[string]any{
					"refId": "A", "expr": s.expr, "instant": true, "intervalMs": 1000, "maxDataPoints": 43200,
					"datasource": map[string]any{"type": "prometheus", "uid": DSPrometheus},
				}},
			{RefID: "C", DatasourceUID: "__expr__",
				Model: map[string]any{
					"refId": "C", "type": "threshold", "expression": "A",
					"datasource": map[string]any{"type": "__expr__", "uid": "__expr__"},
					"conditions": []any{map[string]any{"evaluator": map[string]any{"type": s.evaluator, "params": []float64{s.threshold}}}},
				}},
		},
		Labels:      map[string]string{"severity": s.severity},
		Annotations: map[string]string{"summary": s.summary},
	}
}

// Rules returns the alert rule file that the generator writes.
func Rules() RuleFile {
	var rules []Rule
	for _, s := range ruleSpecs() {
		rules = append(rules, s.rule())
	}
	return RuleFile{APIVersion: 1, Groups: []RuleGroup{{
		OrgID: 1, Name: ruleGroupName, Folder: ruleFolderTitle, Interval: ruleInterval, Rules: rules,
	}}}
}
