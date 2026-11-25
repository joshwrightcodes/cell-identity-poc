package dashboards

import (
	"regexp"
	"strings"
	"testing"
)

func boardByUID(t *testing.T, uid string) Dashboard {
	t.Helper()
	for _, b := range Boards() {
		if b.UID == uid {
			return b
		}
	}
	t.Fatalf("no board %s", uid)
	return Dashboard{}
}

func panelByTitle(t *testing.T, b Dashboard, title string) Panel {
	t.Helper()
	for _, p := range b.Panels {
		if p.Title == title {
			return p
		}
	}
	t.Fatalf("board %s has no panel %q", b.UID, title)
	return Panel{}
}

func TestBoardsMatchMockup(t *testing.T) {
	want := []struct {
		file, uid, title, from string
		panels                 []string
	}{
		{"cell-health.json", "poc-cell-health", "Cell health overview", "now-6h", []string{
			"Cells valid", "Spec revision lag", "Gateway streams", "Outbox items", "Islands now", "Revoked cells", "Cells", "celld SVID remaining", "Upstream age by layer"}},
		{"spiffe.json", "poc-spiffe", "SPIFFE and SPIRE", "now-24h", []string{
			"Attestations", "Refused attestations", "Agents per cell", "Intermediate CA expires", "Key checks", "Agent bans",
			"Attestation refusals by reason", "SVIDs issued per 10 min", "unknown_kid hints per hour", "Trust anchors"}},
		{"argocd-bundles.json", "poc-argocd-bundles", "Argo CD and bundle sets", "now-7d", []string{
			"Applications synced", "Applications healthy", "Rollbacks 7 days", "Store denials", "Signed sets by target", "Sync time after a tag move", "Sync operations per hour"}},
		{"mesh.json", "poc-mesh", "Mesh and Kiali", "now-6h", []string{
			"mTLS share of requests", "Request success", "Kiali tunnels up", "Shortest proxy cert life", "Requests per second by mesh", "Tunnel answers to Kiali"}},
		{"islands.json", "poc-islands", "Islands and revocation", "now-24h", []string{
			"Link state by layer", "Outbox during the island", "dev-cp collector queue", "Overlay entries", "Revoked streams closed"}},
		{"refusals.json", "poc-refusals", "Refusals across the PoC", "now-24h", []string{"Refusals by service", "Latest refusals"}},
		{"work.json", "poc-work", "Work and provisioning steps", "now-24h", []string{
			"Queue depth", "Claims 24 h", "Throttled reports", "Steps in flight", "Operation results by outcome", "Step stages, last provision"}},
		{"telemetry.json", "poc-telemetry", "Telemetry pipeline", "now-6h", []string{
			"Exports accepted", "Source tags overwritten", "Upstream failures", "Relay slots used", "Seconds since the last export, by sender"}},
	}
	boards := Boards()
	if len(boards) != len(want) {
		t.Fatalf("%d boards, want %d", len(boards), len(want))
	}
	for i, w := range want {
		b := boards[i]
		if b.File != w.file || b.UID != w.uid || b.Title != w.title || b.Time.From != w.from || b.Time.To != "now" {
			t.Errorf("board %d = %s %s %q %+v, want %s %s %q %s", i, b.File, b.UID, b.Title, b.Time, w.file, w.uid, w.title, w.from)
		}
		var got []string
		for _, p := range b.Panels {
			got = append(got, p.Title)
		}
		if strings.Join(got, "|") != strings.Join(w.panels, "|") {
			t.Errorf("%s panels = %q, want %q", b.UID, got, w.panels)
		}
	}
}

func TestStatRowFirst(t *testing.T) {
	for _, b := range Boards() {
		n := 0
		for _, p := range b.Panels {
			if p.GridPos.Y == 0 && p.Type == "stat" {
				n++
			}
		}
		switch b.UID {
		case "poc-islands", "poc-refusals":
			if b.Panels[0].Type == "stat" {
				t.Errorf("%s starts with a stat", b.UID)
			}
		default:
			if n < 4 || n > 6 {
				t.Errorf("%s has %d stats at y 0, want 4 to 6", b.UID, n)
			}
			for i := 0; i < n; i++ {
				if b.Panels[i].Type != "stat" || b.Panels[i].GridPos.Y != 0 {
					t.Errorf("%s panel %d is %s at y %d, want a stat at y 0", b.UID, i, b.Panels[i].Type, b.Panels[i].GridPos.Y)
				}
			}
		}
	}
}

func TestClusterColours(t *testing.T) {
	want := map[string]string{"dev-cell-1": colCell1, "dev-cell-2": colCell2, "dev-cp": colCP}
	names := []string{"{{platform_cell}}", "{{k8s_cluster_name}}", "{{sender_cluster}}", "{{cell}}"}
	coloured := 0
	for _, b := range Boards() {
		for _, p := range b.Panels {
			got := map[string]string{}
			for _, o := range p.FieldConfig.Overrides {
				if _, ok := want[o.Matcher.Options]; !ok {
					continue
				}
				if o.Matcher.ID != "byName" {
					t.Errorf("%s %q: override of %s uses %s", b.UID, p.Title, o.Matcher.Options, o.Matcher.ID)
				}
				for _, pr := range o.Properties {
					if pr.ID == "color" {
						got[o.Matcher.Options] = pr.Value.(map[string]any)["fixedColor"].(string)
					}
				}
			}
			for name, colour := range got {
				if colour != want[name] {
					t.Errorf("%s %q: %s has colour %s, want %s", b.UID, p.Title, name, colour, want[name])
				}
			}
			if p.Type != "timeseries" && p.Type != "bargauge" {
				continue
			}
			perCluster := false
			for _, tg := range p.Targets {
				for _, n := range names {
					perCluster = perCluster || strings.Contains(tg.LegendFormat, n)
				}
			}
			if perCluster {
				coloured++
				for name := range want {
					if _, ok := got[name]; !ok {
						t.Errorf("%s %q: series are per cluster but %s has no colour", b.UID, p.Title, name)
					}
				}
			}
		}
	}
	if coloured < 6 {
		t.Errorf("only %d per-cluster panels carry the cluster colours", coloured)
	}
}

var eventWrapRE = regexp.MustCompile(`^\((.+)\) or (on\(\) )?vector\(0\)$`)

func TestEventOnlyFallback(t *testing.T) {
	n := 0
	for _, b := range Boards() {
		for _, p := range b.Panels {
			for _, tg := range p.Targets {
				m := eventWrapRE.FindStringSubmatch(tg.Expr)
				where := b.UID + " " + p.Title + " " + tg.RefID
				if tg.EventOnly != (m != nil) {
					t.Errorf("%s: EventOnly = %v, but the expression wrap is %v: %s", where, tg.EventOnly, m != nil, tg.Expr)
				}
				if m == nil {
					continue
				}
				n++
				if names, err := MetricNames(m[1]); err != nil || len(names) == 0 {
					t.Errorf("%s: the bare expression names no metric: %v", where, err)
				}
				if tg.Instant == false && tg.Range == false {
					t.Errorf("%s: the target is neither instant nor range", where)
				}
			}
		}
	}
	if n < 20 {
		t.Errorf("%d EventOnly targets, want the event counters of the boards", n)
	}
}

func TestKialiLink(t *testing.T) {
	b := boardByUID(t, "poc-mesh")
	if len(b.Links) != 1 || b.Links[0].Title != "Open in Kiali" || b.Links[0].URL != "http://127.0.0.1:20001/kiali" || !b.Links[0].TargetBlank {
		t.Errorf("links = %+v, want one link Open in Kiali to http://127.0.0.1:20001/kiali", b.Links)
	}
	for _, o := range Boards() {
		if o.UID != "poc-mesh" && len(o.Links) > 0 {
			t.Errorf("%s has links %+v", o.UID, o.Links)
		}
	}
}

func TestEveryBoardHasTheClusterVariable(t *testing.T) {
	for _, b := range Boards() {
		if len(b.Templating.List) == 0 || b.Templating.List[0].Name != "cluster" {
			t.Errorf("%s: first variable is not cluster", b.UID)
		}
		for _, v := range b.Templating.List {
			if !v.IncludeAll {
				t.Errorf("%s variable %s has no All", b.UID, v.Name)
			}
		}
	}
	for _, uid := range []string{"poc-cell-health", "poc-spiffe", "poc-mesh", "poc-islands", "poc-work"} {
		found := false
		for _, v := range boardByUID(t, uid).Templating.List {
			found = found || v.Name == "cell"
		}
		if !found {
			t.Errorf("%s has no cell variable", uid)
		}
	}
}

// TestNoSyntheticSeries checks that no selector of a board reads the synthetic series of the gate.
// The variables cluster and cell read up, and the synthetic series never carry up.
func TestNoSyntheticSeries(t *testing.T) {
	for _, q := range promQueries(Boards(), RuleFile{}) {
		sels, err := Selectors(q.Expr)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sels {
			if s.Name == "up" {
				continue
			}
			ok := false
			for _, m := range s.Matchers {
				ok = ok || (m.Label == "service_name" && m.Op == "!=" && m.Value == SyntheticService)
			}
			if !ok {
				t.Errorf("%s: %s does not leave out service_name=%q", q.Where, s.Name, SyntheticService)
			}
		}
	}
}

func TestVanishingGaugesAreFresh(t *testing.T) {
	gauges := []string{"cellgw_streams", "agentban_agents", "mgmtd_cell_state", "trust_ca_not_after_seconds", "bundle_set_applied_seconds", "cellctl_steps_open", "cellgw_queue_depth"}
	seen := map[string]int{}
	for _, q := range promQueries(Boards(), RuleFile{}) {
		for _, g := range gauges {
			all := strings.Count(q.Expr, g+"{")
			wrapped := len(regexp.MustCompile(`last_over_time\(`+g+`\{[^}]*\}\[[0-9]+[sm]\]\)`).FindAllString(q.Expr, -1))
			if q.Kind == kindVariable {
				continue
			}
			if all != wrapped {
				t.Errorf("%s: %d reads of %s, %d with last_over_time", q.Where, all, g, wrapped)
			}
			seen[g] += all
		}
	}
	for _, g := range gauges {
		if seen[g] == 0 {
			t.Errorf("no panel reads %s", g)
		}
	}
}

func TestDescriptionsNameTheMetrics(t *testing.T) {
	for _, b := range Boards() {
		for _, p := range b.Panels {
			if p.Datasource.UID != DSPrometheus {
				continue
			}
			for _, tg := range p.Targets {
				names, _ := MetricNames(tg.Expr)
				for _, n := range names {
					if !strings.Contains(p.Description, n) {
						t.Errorf("%s %q: the description does not name %s", b.UID, p.Title, n)
					}
				}
			}
		}
	}
}

func TestSpecificPanels(t *testing.T) {
	t.Run("unknown_kid reads the report retry counter", func(t *testing.T) {
		p := panelByTitle(t, boardByUID(t, "poc-spiffe"), "unknown_kid hints per hour")
		if !strings.Contains(p.Targets[0].Expr, "mgmtd_report_retry_unknown_kid_total") || strings.Contains(p.Targets[0].Expr, "keycheck") {
			t.Errorf("expr = %s", p.Targets[0].Expr)
		}
	})
	t.Run("revoke reach is left for M14", func(t *testing.T) {
		for _, b := range Boards() {
			for _, p := range b.Panels {
				if strings.Contains(strings.ToLower(p.Title), "revoke reach") {
					t.Errorf("%s has the panel %q", b.UID, p.Title)
				}
			}
		}
	})
	t.Run("latest refusals drops library_log", func(t *testing.T) {
		p := panelByTitle(t, boardByUID(t, "poc-refusals"), "Latest refusals")
		if p.Datasource.UID != DSLoki || !strings.Contains(p.Targets[0].Expr, `reason != "library_log"`) {
			t.Errorf("panel = %+v", p.Targets)
		}
	})
	t.Run("signed sets sort by the numeric Applied time and show bootstrap", func(t *testing.T) {
		p := panelByTitle(t, boardByUID(t, "poc-argocd-bundles"), "Signed sets by target")
		sort := p.Options["sortBy"].([]map[string]any)
		if len(sort) != 1 || sort[0]["displayName"] != "Applied" {
			t.Errorf("sortBy = %v", sort)
		}
		found := false
		for _, o := range p.FieldConfig.Overrides {
			if o.Matcher.Options != "Set" {
				continue
			}
			for _, pr := range o.Properties {
				m := pr.Value.([]map[string]any)[0]["options"].(map[string]any)["0.0"].(map[string]any)
				found = m["text"] == "bootstrap"
			}
		}
		if !found {
			t.Errorf("no mapping of version 0.0 to bootstrap on the column Set: %+v", p.FieldConfig.Overrides)
		}
	})
	t.Run("islands now shares the expression of rule A2", func(t *testing.T) {
		rule := IslandAge(IslandScope{Cell: `platform_cell!=""`})
		if !strings.Contains(rule, `celld_upstream_age_seconds{platform_cell!=""}`) || strings.Contains(rule, "m15-synthetic") || strings.Contains(rule, "$") && !strings.Contains(rule, `"$1"`) {
			t.Errorf("rule expression = %s", rule)
		}
		p := panelByTitle(t, boardByUID(t, "poc-cell-health"), "Islands now")
		if !strings.Contains(p.Targets[0].Expr, IslandAge(islandBoard())+" > 120") {
			t.Errorf("expr = %s", p.Targets[0].Expr)
		}
	})
	t.Run("cell state sorts by number", func(t *testing.T) {
		p := panelByTitle(t, boardByUID(t, "poc-cell-health"), "Cells")
		if len(p.Targets) != 9 || p.Targets[0].Format != "table" {
			t.Errorf("cells table has %d targets", len(p.Targets))
		}
	})
}

func TestBoardsPassEveryCheck(t *testing.T) {
	if err := Check(Boards(), Rules()); err != nil {
		t.Fatal(err)
	}
}

func TestEventCountersFallBackToZero(t *testing.T) {
	want := map[string][]string{
		"poc-cell-health":    {"Islands now", "Revoked cells"},
		"poc-spiffe":         {"Attestations", "Refused attestations", "Agent bans", "Attestation refusals by reason", "unknown_kid hints per hour"},
		"poc-argocd-bundles": {"Rollbacks 7 days", "Store denials"},
		"poc-islands":        {"Overlay entries", "Revoked streams closed"},
		"poc-refusals":       {"Refusals by service"},
		"poc-work":           {"Queue depth", "Claims 24 h", "Throttled reports", "Steps in flight", "Step stages, last provision"},
		"poc-telemetry":      {"Source tags overwritten", "Upstream failures"},
	}
	for uid, titles := range want {
		b := boardByUID(t, uid)
		for _, title := range titles {
			p := panelByTitle(t, b, title)
			any := false
			for _, tg := range p.Targets {
				any = any || tg.EventOnly
			}
			if !any {
				t.Errorf("%s %q has no EventOnly target", uid, title)
			}
		}
	}
}
