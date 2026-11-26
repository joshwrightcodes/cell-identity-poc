package dashboards

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
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
		{"argocd-bundles.json", "poc-argocd-bundles", "Argo CD and bundle sets", "now-48h", []string{
			"Applications synced", "Applications healthy", "Rollbacks 48 h", "Store denials", "Signed sets by target", "Sync time after a tag move", "Sync operations per hour"}},
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
	// The 15 s exporters get 1m, the 60 s exporters 2m.
	gauges := map[string]string{
		"cellgw_streams": "1m", "agentban_agents": "1m", "mgmtd_cell_state": "1m", "cellgw_queue_depth": "1m",
		"trust_ca_not_after_seconds": "2m", "bundle_set_applied_seconds": "2m", "cellctl_steps_open": "2m",
	}
	seen := map[string]int{}
	for _, q := range promQueries(Boards(), RuleFile{}) {
		if q.Kind == kindVariable {
			continue
		}
		for g, window := range gauges {
			all := strings.Count(q.Expr, g+"{")
			wrapped := len(regexp.MustCompile(`last_over_time\(`+g+`\{[^}]*\}\[`+window+`\]\)`).FindAllString(q.Expr, -1))
			stamped := len(regexp.MustCompile(`timestamp\(`+g+`\{[^}]*\}\)`).FindAllString(q.Expr, -1))
			if all != wrapped+stamped {
				t.Errorf("%s: %d reads of %s, %d with last_over_time over %s and %d inside timestamp()", q.Where, all, g, wrapped, window, stamped)
			}
			seen[g] += all
		}
	}
	for g := range gauges {
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
	t.Run("cell state and applied sets keep the newest series", func(t *testing.T) {
		for _, c := range []struct{ name, expr, by, metric string }{
			{"newest cell state", newest(S("mgmtd_cell_state", pinMgmt, `revoked="false"`), S("mgmtd_cell_state", pinMgmt), freshFast, "cell"), "cell", "mgmtd_cell_state"},
			{"cells valid", cellCount(`valid="true"`, `revoked="false"`), "cell", "mgmtd_cell_state"},
			{"state column", stateOf(), "cell", "mgmtd_cell_state"},
		} {
			if !strings.Contains(c.expr, " and on("+c.by+") (timestamp("+c.metric+"{") || !strings.Contains(c.expr, "== on("+c.by+") group_left max by ("+c.by+") (timestamp("+c.metric+"{") {
				t.Errorf("%s does not keep the newest series: %s", c.name, c.expr)
			}
		}
		b := boardByUID(t, "poc-argocd-bundles")
		sets := panelByTitle(t, b, "Signed sets by target")
		if !strings.Contains(sets.Targets[0].Expr, "group_left max by (k8s_cluster_name, role) (timestamp(bundle_set_applied_seconds{") {
			t.Errorf("Signed sets does not keep the newest set of each applier: %s", sets.Targets[0].Expr)
		}
		cells := panelByTitle(t, boardByUID(t, "poc-cell-health"), "Cells")
		found := false
		for _, tg := range cells.Targets {
			found = found || strings.Contains(tg.Expr, "group_left max by (k8s_cluster_name, role) (timestamp(bundle_set_applied_seconds{")
		}
		if !found {
			t.Error("the Bundle applied column does not keep the newest set of each applier")
		}
	})
	t.Run("mesh shares guard the form", func(t *testing.T) {
		b := boardByUID(t, "poc-mesh")
		for title, bad := range map[string]string{"mTLS share of requests": `connection_security_policy!="mutual_tls"`, "Request success": `response_code=~"5.."`} {
			p := panelByTitle(t, b, title)
			e := p.Targets[0].Expr
			for _, want := range []string{bad, " or vector(0)) / (", " > 0)) or (0 * ", " - 1)) and on() count(last_over_time(", "[2m])"} {
				if !strings.Contains(e, want) {
					t.Errorf("%s lacks %q: %s", title, want, e)
				}
			}
			if !strings.Contains(fmt.Sprint(p.FieldConfig.Defaults.Mappings), "no requests") {
				t.Errorf("%s has no mapping of -1 to no requests", title)
			}
		}
	})
	t.Run("apply time guards the count and maps -1", func(t *testing.T) {
		p := panelByTitle(t, boardByUID(t, "poc-argocd-bundles"), "Signed sets by target")
		var expr string
		for _, tg := range p.Targets {
			if strings.Contains(tg.Expr, "bundle_sync_delay_seconds_sum") {
				expr = tg.Expr
			}
		}
		for _, want := range []string{"bundle_sync_delay_seconds_count", " > 0)) or (0 * max by", ") - 1)", " unless "} {
			if !strings.Contains(expr, want) {
				t.Errorf("apply time lacks %q: %s", want, expr)
			}
		}
		found := false
		for _, o := range p.FieldConfig.Overrides {
			found = found || (o.Matcher.Options == "Apply time" && strings.Contains(fmt.Sprint(o.Properties), "no sync"))
		}
		if !found {
			t.Error("the Apply time column has no mapping of -1 to no sync")
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
		if !strings.Contains(rule, `celld_upstream_age_seconds{platform_cell!=""}`) || strings.Contains(rule, "m15-synthetic") || regexp.MustCompile(`\$\{?(cell|cluster)`).MatchString(rule) {
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
		"poc-argocd-bundles": {"Rollbacks 48 h", "Store denials"},
		"poc-islands":        {"Overlay entries", "Revoked streams closed"},
		"poc-refusals":       {"Refusals by service"},
		"poc-work":           {"Operation results by outcome", "Queue depth", "Claims 24 h", "Throttled reports", "Steps in flight", "Step stages, last provision"},
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

func TestQueueCapIsOneQueue(t *testing.T) {
	p := panelByTitle(t, boardByUID(t, "poc-islands"), "dev-cp collector queue")
	n := 0
	for _, tg := range p.Targets {
		if tg.LegendFormat == "cap" {
			n++
			if strings.Contains(tg.Expr, "sum(") || !strings.Contains(tg.Expr, "max(") {
				t.Errorf("the cap adds the queues of the signals: %s", tg.Expr)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d cap targets, want 1", n)
	}
}

func TestStepsInFlightCoverEveryOpenState(t *testing.T) {
	var kind Variable
	for _, v := range boardByUID(t, "poc-work").Templating.List {
		if v.Name == "kind" {
			kind = v
		}
	}
	got := strings.Split(kind.Query, ",")
	open := []string{mgmtapi.StepQueued, mgmtapi.StepCreating, mgmtapi.StepAdmitting, mgmtapi.StepBootstrapping, mgmtapi.StepFailed}
	sort.Strings(got)
	sort.Strings(open)
	if strings.Join(got, ",") != strings.Join(open, ",") {
		t.Errorf("kind lists %v, the open states are %v", got, open)
	}
}

func TestCellCountsCountEachCellOnce(t *testing.T) {
	b := boardByUID(t, "poc-cell-health")
	for _, title := range []string{"Cells valid", "Revoked cells"} {
		for _, tg := range panelByTitle(t, b, title).Targets {
			if strings.Contains(tg.Expr, "mgmtd_cell_state") && !strings.Contains(tg.Expr, "count by (cell)") {
				t.Errorf("%s: %s counts series, not cells", title, tg.Expr)
			}
		}
	}
	for _, tg := range panelByTitle(t, b, "Revoked cells").Targets {
		if tg.LegendFormat == "overlay held" && tg.EventOnly {
			t.Error("overlay held is a live gauge and must not be EventOnly")
		}
	}
}

func TestTablesKeepNAAndMockupColumns(t *testing.T) {
	cells := panelByTitle(t, boardByUID(t, "poc-cell-health"), "Cells")
	for _, o := range cells.FieldConfig.Overrides {
		for _, pr := range o.Properties {
			if pr.ID != "mappings" {
				continue
			}
			ms := pr.Value.([]map[string]any)
			if ms[len(ms)-1]["type"] != "special" {
				t.Errorf("override %s replaces the n/a mapping", o.Matcher.Options)
			}
		}
	}
	order := func(p Panel) []string {
		var rename map[string]string
		var index map[string]int
		for _, tr := range p.Transformations {
			if tr["id"] == "organize" {
				rename = tr["options"].(map[string]any)["renameByName"].(map[string]string)
				index = tr["options"].(map[string]any)["indexByName"].(map[string]int)
			}
		}
		out := make([]string, len(index))
		for src, i := range index {
			out[i] = rename[src]
		}
		for len(out) > 0 && out[len(out)-1] == "" {
			out = out[:len(out)-1]
		}
		return out
	}
	for _, c := range []struct {
		board, title string
		want         []string
	}{
		{"poc-spiffe", "Trust anchors", []string{"Trust domain", "CA", "Expires", "Root", "Pinned by"}},
		{"poc-argocd-bundles", "Signed sets by target", []string{"Target", "Set", "Root digest", "Applied", "Apply time", "Result"}},
	} {
		got := order(panelByTitle(t, boardByUID(t, c.board), c.title))
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s columns = %v, want %v", c.title, got, c.want)
		}
	}
}
