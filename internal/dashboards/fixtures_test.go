package dashboards

import "math"

var (
	promDS = &Datasource{Type: "prometheus", UID: DSPrometheus}
	lokiDS = &Datasource{Type: "loki", UID: DSLoki}
)

// panel builds a panel with one Prometheus target.
func panel(id int, title string, x, y, w, h int, exprs ...string) Panel {
	p := Panel{ID: id, Type: "stat", Title: title, GridPos: GridPos{H: h, W: w, X: x, Y: y}, Datasource: promDS}
	for i, e := range exprs {
		p.Targets = append(p.Targets, Target{RefID: string(rune('A' + i)), Expr: e, Instant: true})
	}
	return p
}

// goodBoard is a board that passes every check. The checks of the real boards run on an empty list
// while no board exists yet, so each check also runs on this board and on the bad boards that mutate it.
func goodBoard() Dashboard {
	logs := panel(4, "Latest refusals", 0, 8, 24, 8)
	logs.Type = "table"
	logs.Datasource = lokiDS
	logs.Targets = []Target{{RefID: "A", Expr: `{k8s_cluster_name=~"$cluster"} | reason != ""`, QueryType: "range"}}
	return Dashboard{
		File: "good.json", UID: "poc-good", Title: "Good", SchemaVersion: 41, Time: TimeRange{From: "now-6h", To: "now"},
		Templating: Templating{List: []Variable{
			{Name: "cluster", Type: "query", Datasource: promDS, Query: `label_values(up{k8s_cluster_name=~".+"}, k8s_cluster_name)`, IncludeAll: true, Multi: true},
			{Name: "cell", Type: "query", Datasource: promDS, Query: `label_values(up{platform_plane="cell"}, platform_cell)`, IncludeAll: true, Multi: true},
		}},
		Panels: []Panel{
			panel(1, "Cells valid", 0, 0, 8, 4, `max(mgmtd_cells_valid{k8s_cluster_name="management"})`),
			panel(2, "SVID remaining", 8, 0, 16, 8, `celld_svid_remaining_seconds{platform_cell=~"$cell"}`),
			panel(3, "SVIDs issued", 0, 4, 8, 4,
				`sum by (k8s_cluster_name) (increase(spire_server_server_ca_sign_x509_svid_total{k8s_cluster_name=~"$cluster"}[10m]))`,
				`sum(increase(cellgw_refusals_total{k8s_cluster_name="dev-cp"}[$__range])) or vector(0)`),
			logs,
		},
	}
}

// goodRules is a rule file that passes every check.
func goodRules() RuleFile {
	return RuleFile{APIVersion: 1, Groups: []RuleGroup{{
		OrgID: 1, Name: "cell-identity", Folder: "Cell identity PoC alerts", Interval: "30s",
		Rules: []Rule{{
			UID: "poc-good-rule", Title: "Good rule", Condition: "C", NoDataState: "OK", ExecErrState: "Error", For: "5m",
			Data: []RuleQuery{
				{RefID: "A", DatasourceUID: DSPrometheus, RelativeTimeRange: &RelativeRange{From: 600},
					Model: map[string]any{"expr": `min by (cell) (cell_proxy_tunnel_up{k8s_cluster_name="management", side="hub"})`}},
				{RefID: "C", DatasourceUID: "__expr__", Model: map[string]any{"type": "threshold", "expression": "A"}},
			},
		}},
	}}}
}

// mutate returns a copy of the good board that the function changes.
func mutate(f func(*Dashboard)) []Dashboard {
	b := goodBoard()
	f(&b)
	return []Dashboard{b}
}

func mutateRules(f func(*Rule)) RuleFile {
	r := goodRules()
	f(&r.Groups[0].Rules[0])
	return r
}

var nan = math.NaN()
