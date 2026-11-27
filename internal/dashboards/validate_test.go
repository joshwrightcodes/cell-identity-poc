package dashboards

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wantError(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want one that contains %q", parts)
	}
	for _, p := range parts {
		if !strings.Contains(err.Error(), p) {
			t.Fatalf("error %q does not contain %q", err, p)
		}
	}
}

func TestEveryDashboardParses(t *testing.T) {
	t.Run("generated boards", func(t *testing.T) {
		if err := CheckLayout(Boards()); err != nil {
			t.Fatal(err)
		}
		if err := CheckParse(Boards(), Rules()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("good board", func(t *testing.T) {
		if err := CheckLayout([]Dashboard{goodBoard()}); err != nil {
			t.Fatal(err)
		}
		if err := CheckParse([]Dashboard{goodBoard()}, goodRules()); err != nil {
			t.Fatal(err)
		}
	})
	bad := map[string]struct {
		boards []Dashboard
		want   string
	}{
		"duplicate UID":              {append(mutate(func(*Dashboard) {}), func() Dashboard { b := goodBoard(); b.File = "other.json"; return b }()), `UID "poc-good" is not unique`},
		"duplicate file":             {append(mutate(func(*Dashboard) {}), func() Dashboard { b := goodBoard(); b.UID = "poc-other"; return b }()), "is not unique"},
		"panel past column 24":       {mutate(func(b *Dashboard) { b.Panels[0].GridPos = GridPos{H: 4, W: 8, X: 20, Y: 0} }), "outside the 24 columns"},
		"zero width":                 {mutate(func(b *Dashboard) { b.Panels[0].GridPos.W = 0 }), "outside the 24 columns"},
		"overlap":                    {mutate(func(b *Dashboard) { b.Panels[1].GridPos.X = 4 }), "overlaps panel"},
		"duplicate panel ID":         {mutate(func(b *Dashboard) { b.Panels[1].ID = 1 }), "panel ID 1 is not unique"},
		"unknown data source":        {mutate(func(b *Dashboard) { b.Panels[0].Datasource = &Datasource{Type: "tempo", UID: "tempo"} }), `data source UID "tempo"`},
		"unknown target data source": {mutate(func(b *Dashboard) { b.Panels[0].Targets[0].Datasource = &Datasource{Type: "x", UID: "other"} }), `data source UID "other"`},
		"panel and target without a data source": {mutate(func(b *Dashboard) {
			b.Panels[0].Datasource = nil
		}), "no data source on the target or the panel"},
		"variable without a data source": {mutate(func(b *Dashboard) { b.Templating.List[0].Datasource = nil }), "variable cluster: no data source"},
		"unknown variable data source":   {mutate(func(b *Dashboard) { b.Templating.List[0].Datasource = &Datasource{Type: "x", UID: "other"} }), `variable cluster`},
	}
	for name, tc := range bad {
		t.Run("bad: "+name, func(t *testing.T) { wantError(t, CheckLayout(tc.boards), tc.want) })
	}
	t.Run("bad: a value that JSON cannot carry", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) { b.Panels[0].FieldConfig.Defaults.Min = &nan })
		wantError(t, CheckParse(boards, goodRules()), "poc-good")
	})
	t.Run("bad: rules that JSON cannot carry", func(t *testing.T) {
		rules := mutateRules(func(r *Rule) { r.Data[0].Model["bad"] = make(chan int) })
		wantError(t, CheckParse(nil, rules), "rules")
	})
}

func TestVariablesNeedASourceOnlyWhenTheyQuery(t *testing.T) {
	t.Run("good: a custom and an interval variable have no data source", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) {
			b.Templating.List = append(b.Templating.List,
				Variable{Name: "kind", Type: "custom", Query: "a,b"}, Variable{Name: "step", Type: "interval", Query: "1m,5m"})
		})
		if err := CheckLayout(boards); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bad: a query variable with no data source", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) { b.Templating.List[0].Datasource = nil })
		wantError(t, CheckLayout(boards), "poc-good variable cluster", "no data source")
	})
}

func TestPanelQueriesNameKnownMetrics(t *testing.T) {
	t.Run("generated boards and rules", func(t *testing.T) {
		if err := CheckQueries(Boards(), Rules()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("good board and rules", func(t *testing.T) {
		if err := CheckQueries([]Dashboard{goodBoard()}, goodRules()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the Loki query is not read as PromQL", func(t *testing.T) {
		qs := promQueries([]Dashboard{goodBoard()}, RuleFile{})
		for _, q := range qs {
			if strings.Contains(q.Expr, "reason") {
				t.Fatalf("query %q is Loki", q.Expr)
			}
		}
		if len(qs) != 6 {
			t.Fatalf("got %d Prometheus queries, want 6 (two variables, four targets): %+v", len(qs), qs)
		}
	})
	t.Run("bad: unknown metric in a panel", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) {
			b.Panels[0].Targets[0].Expr = `max(mgmtd_cells_vaild{k8s_cluster_name="management"})`
		})
		wantError(t, CheckQueries(boards, goodRules()), `"mgmtd_cells_vaild" is not in the catalogue`, "Cells valid")
	})
	t.Run("bad: unknown metric in a variable", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) {
			b.Templating.List[1].Query = `label_values(upp{platform_plane="cell"}, platform_cell)`
		})
		wantError(t, CheckQueries(boards, goodRules()), `"upp"`, "variable cell")
	})
	t.Run("bad: unknown metric in a rule", func(t *testing.T) {
		rules := mutateRules(func(r *Rule) { r.Data[0].Model["expr"] = `min(cell_proxy_tunnel_down)` })
		wantError(t, CheckQueries(nil, rules), `"cell_proxy_tunnel_down"`, "poc-good-rule")
	})
	t.Run("bad: a histogram name without a suffix", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) {
			b.Panels[0].Targets[0].Expr = `histogram_quantile(0.5, bundle_apply_duration_seconds)`
		})
		wantError(t, CheckQueries(boards, goodRules()), `"bundle_apply_duration_seconds"`)
	})
	t.Run("good: a histogram series", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) {
			b.Panels[0].Targets[0].Expr = `histogram_quantile(0.5, sum by (le) (rate(bundle_apply_duration_seconds_bucket[$__rate_interval])))`
		})
		if err := CheckQueries(boards, goodRules()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bad: an expression that does not parse", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) {
			b.Panels[0].Targets[0].Expr = `max(mgmtd_cells_valid{k8s_cluster_name="management"}`
		})
		wantError(t, CheckQueries(boards, goodRules()), "Cells valid")
	})
	t.Run("bad: a metric that no binary exports", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) { b.Panels[0].Targets[0].Expr = `sum(increase(hostsvc_steps_total[$__range]))` })
		wantError(t, CheckQueries(boards, goodRules()), `"hostsvc_steps_total" is not exported`)
		rules := mutateRules(func(r *Rule) { r.Data[0].Model["expr"] = `sum(hostsvc_steps_total)` })
		wantError(t, CheckQueries(nil, rules), "not exported")
	})
	t.Run("bad: an expression with no metric", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) { b.Panels[0].Targets[0].Expr = `vector(1)` })
		wantError(t, CheckQueries(boards, goodRules()), "names no metric")
	})
}

func TestSelectorsPinEmitter(t *testing.T) {
	t.Run("generated boards and rules", func(t *testing.T) {
		if err := CheckSelectors(Boards(), Rules()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("good board and rules", func(t *testing.T) {
		if err := CheckSelectors([]Dashboard{goodBoard()}, goodRules()); err != nil {
			t.Fatal(err)
		}
	})
	setExpr := func(expr string) []Dashboard {
		return mutate(func(b *Dashboard) { b.Panels[0].Targets[0].Expr = expr })
	}
	t.Run("bad: a metric of dev-cp pinned to management", func(t *testing.T) {
		wantError(t, CheckSelectors(setExpr(`sum(cellgw_streams{k8s_cluster_name="management"})`), goodRules()),
			`cellgw_streams pins k8s_cluster_name="management"`, "dev-cp")
	})
	t.Run("bad: a metric of one cluster with no pin", func(t *testing.T) {
		wantError(t, CheckSelectors(setExpr(`max(mgmtd_cells_valid)`), goodRules()), `mgmtd_cells_valid has no k8s_cluster_name="management"`)
	})
	t.Run("bad: a metric of one cluster that takes the variable", func(t *testing.T) {
		wantError(t, CheckSelectors(setExpr(`max(mgmtd_cells_valid{k8s_cluster_name=~"$cluster"})`), goodRules()), "the only emitter")
	})
	t.Run("bad: a cell metric pinned to a cluster that runs no cell", func(t *testing.T) {
		wantError(t, CheckSelectors(setExpr(`celld_svid_remaining_seconds{k8s_cluster_name="dev-cp"}`), goodRules()), "celld_svid_remaining_seconds pins")
	})
	t.Run("bad: a pin in a rule", func(t *testing.T) {
		rules := mutateRules(func(r *Rule) {
			r.Data[0].Model["expr"] = `min by (cell) (cell_proxy_tunnel_up{k8s_cluster_name="dev-cp", side="hub"})`
		})
		wantError(t, CheckSelectors(nil, rules), "poc-good-rule", "cell_proxy_tunnel_up pins")
	})
	t.Run("bad: a metric of many clusters with no pin and no variable", func(t *testing.T) {
		for _, expr := range []string{
			`sum(argocd_app_info)`,
			`sum(argocd_app_info{job="argocd"})`,
			`min(celld_upstream_age_seconds)`,
			`min(istio_agent_cert_expiry_seconds{resource_name="default"})`,
		} {
			wantError(t, CheckSelectors(setExpr(expr), goodRules()), "comes from many clusters", "Cells valid")
		}
	})
	t.Run("bad: a pin to a cluster that is not a cell", func(t *testing.T) {
		wantError(t, CheckSelectors(setExpr(`celld_svid_remaining_seconds{k8s_cluster_name="dev-cp"}`), goodRules()), "pins")
	})
	t.Run("good: a matcher in the form ${cell} or ${cluster} follows the variable", func(t *testing.T) {
		for _, expr := range []string{
			`celld_upstream_age_seconds{platform_cell=~"${cell}"}`,
			`sum(argocd_app_info{k8s_cluster_name=~"${cluster}"})`,
			`min(celld_upstream_age_seconds{platform_cell="$cell"})`,
		} {
			if err := CheckSelectors(setExpr(expr), goodRules()); err != nil {
				t.Errorf("%s: %v", expr, err)
			}
		}
	})
	t.Run("bad: a negative matcher on the variable is no scope", func(t *testing.T) {
		for _, expr := range []string{
			`celld_upstream_age_seconds{platform_cell!~"$cell"}`,
			`sum(argocd_app_info{k8s_cluster_name!="${cluster}"})`,
		} {
			wantError(t, CheckSelectors(setExpr(expr), goodRules()), "comes from many clusters")
		}
	})
	t.Run("good: a rule and a variable query need no scope", func(t *testing.T) {
		rules := mutateRules(func(r *Rule) { r.Data[0].Model["expr"] = `min(celld_upstream_age_seconds{platform_cell!=""})` })
		boards := mutate(func(b *Dashboard) {
			b.Templating.List[1].Query = `label_values(celld_upstream_age_seconds, platform_cell)`
		})
		if err := CheckSelectors(boards, rules); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("good: a metric of many clusters takes the variable or a fixed emitter", func(t *testing.T) {
		for _, expr := range []string{
			`sum(argocd_app_info{k8s_cluster_name=~"$cluster"})`,
			`sum(argocd_app_info{k8s_cluster_name="dev-cp"})`,
			`sum(celld_svid_remaining_seconds{k8s_cluster_name="dev-cell-1"})`,
			`sum(cell_proxy_tunnel_up{k8s_cluster_name="dev-cell-2", side="cell"})`,
			`sum(argocd_app_info{sender_cluster=~"$cluster"})`,
			`max(cellproxy_gateway_slots_used{k8s_cluster_name="management", sender_cluster=~"$cluster"})`,
		} {
			if err := CheckSelectors(setExpr(expr), goodRules()); err != nil {
				t.Errorf("%s: %v", expr, err)
			}
		}
	})
}

func TestGeneratedFilesCurrent(t *testing.T) {
	t.Run("committed files match the generator", func(t *testing.T) {
		diff, err := Diff(filepath.Join(repoRoot, "components", "observability-store", "grafana"))
		if err != nil {
			t.Fatal(err)
		}
		if len(diff) > 0 {
			t.Fatalf("files differ from the generator output: %v. Run mise run obs:dashboards", diff)
		}
	})
	files, err := render([]Dashboard{goodBoard()}, goodRules())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := writeFiles(dir, files); err != nil {
		t.Fatal(err)
	}
	t.Run("fixture output is current", func(t *testing.T) {
		diff, err := diffFiles(dir, files)
		if err != nil || len(diff) != 0 {
			t.Fatalf("diff = %v, %v; want none", diff, err)
		}
	})
	t.Run("the output has the expected paths", func(t *testing.T) {
		for _, p := range []string{"dashboards/good.json", "alerting/rules.json", "provider.yaml"} {
			if _, ok := files[p]; !ok {
				t.Errorf("no file %s in %v", p, sortedKeys(files))
			}
		}
	})
	t.Run("bad: a changed dashboard file", func(t *testing.T) {
		path := filepath.Join(dir, "dashboards", "good.json")
		orig, _ := os.ReadFile(path)
		if err := os.WriteFile(path, append(orig, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		diff, _ := diffFiles(dir, files)
		if len(diff) != 1 || diff[0] != "dashboards/good.json" {
			t.Fatalf("diff = %v, want only dashboards/good.json", diff)
		}
		if err := os.WriteFile(path, orig, 0o644); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bad: a missing provider file", func(t *testing.T) {
		path := filepath.Join(dir, "provider.yaml")
		orig, _ := os.ReadFile(path)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		diff, _ := diffFiles(dir, files)
		if len(diff) != 1 || diff[0] != "provider.yaml" {
			t.Fatalf("diff = %v, want only provider.yaml", diff)
		}
		if err := os.WriteFile(path, orig, 0o644); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bad: a dashboard file that no board owns", func(t *testing.T) {
		stray := filepath.Join(dir, "dashboards", "old.json")
		if err := os.WriteFile(stray, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		diff, _ := diffFiles(dir, files)
		if len(diff) != 1 || diff[0] != "dashboards/old.json" {
			t.Fatalf("diff = %v, want only dashboards/old.json", diff)
		}
		if err := writeFiles(dir, files); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(stray); !os.IsNotExist(err) {
			t.Fatalf("write left the stray file: %v", err)
		}
	})
	t.Run("bad: a board that fails a check is not rendered", func(t *testing.T) {
		boards := mutate(func(b *Dashboard) { b.Panels[0].Targets[0].Expr = `max(no_such_metric)` })
		if _, err := render(boards, goodRules()); err == nil || !strings.Contains(err.Error(), "no_such_metric") {
			t.Fatalf("render error = %v, want one that names no_such_metric", err)
		}
	})
}
