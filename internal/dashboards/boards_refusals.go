package dashboards

import "fmt"

// refusalSource is one counter of refusals and the service that it names.
type refusalSource struct{ service, expr string }

func refusalSources() []refusalSource {
	inc := func(name string, matchers ...string) string {
		return fmt.Sprintf("sum(increase(%s[%s]))", S(name, matchers...), rng)
	}
	return []refusalSource{
		{"cellgw", inc("cellgw_refusals_total", pinCP)},
		{"envd spec", inc("envd_spec_refusals_total", pinCP)},
		{"envd revocations", inc("envd_revocations_refused_total", pinCP)},
		{"cellctl", inc("cellctl_refusals_total", pinCP)},
		{"store proxy", inc("store_proxy_denials_total", clusterRe)},
		{"cell proxy tunnel", inc("cell_proxy_tunnel_refused_requests_total", clusterRe)},
		{"telemetry gateway", inc("cellproxy_gateway_exports_denied_total", pinMgmt)},
		{"cluster_jwt", inc("cluster_jwt_attestations_total", pinCP, `result="refused"`)},
		{"relay", inc("relay_connections_total", pinCP, `result=~"overloaded|source_limit|upstream_write_failed"`)},
	}
}

func refusalsBoard() Dashboard {
	service := Variable{
		Name: "service", Label: "Service", Type: "query", Datasource: lokiDS, Query: "label_values(service_name)", Definition: "label_values(service_name)",
		Refresh: 1, Multi: true, IncludeAll: true, Sort: 1, Current: &Current{Text: "All", Value: "$__all"},
	}
	b := newBoard("refusals.json", "poc-refusals", "Refusals across the PoC", "24h", clusterVar("Cluster"), service)
	var targets []Target
	for _, r := range refusalSources() {
		targets = append(targets, event(instant(r.expr, r.service), false))
	}
	byService := barGauge("Refusals by service", "Refusals in the time range, one bar for each service. The variable Service filters the log table only.", 0, 0, 12, 10, "none", targets...)
	byService.FieldConfig.Defaults.Color = map[string]any{"mode": "fixed", "fixedColor": colWarning}
	b.add(byService)

	logs := newPanel("table", "Latest refusals", "Log lines of Loki that carry a reason. Lines with the reason library_log are debug lines and stay out.", 12, 0, 12, 10)
	logs.Datasource = lokiDS
	logs.Targets = []Target{{
		RefID: "A", QueryType: "range",
		Expr: `{k8s_cluster_name=~"$cluster", service_name=~"$service"} | reason != "" | reason != "library_log"`,
	}}
	logs.FieldConfig.Defaults = FieldDefaults{Custom: map[string]any{"align": "auto", "cellOptions": map[string]any{"type": "auto"}}}
	logs.Options = map[string]any{"showHeader": true, "sortBy": []map[string]any{{"displayName": "Time", "desc": true}}}
	logs.Transformations = []map[string]any{
		{"id": "extractFields", "options": map[string]any{"source": "labels", "format": "json"}},
		{"id": "filterFieldsByName", "options": map[string]any{"include": map[string]any{"names": []string{"timestamp", "Time", "service_name", "reason", "request_id"}}}},
		{"id": "organize", "options": map[string]any{
			"excludeByName": map[string]bool{},
			"indexByName":   map[string]int{"timestamp": 0, "Time": 0, "service_name": 1, "reason": 2, "request_id": 3},
			"renameByName":  map[string]string{"timestamp": "Time", "service_name": "Service", "reason": "Reason", "request_id": "Request ID"},
		}},
	}
	b.add(logs)
	return b.d
}
