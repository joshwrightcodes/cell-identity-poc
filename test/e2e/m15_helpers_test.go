package e2e

// The helpers of the M15 dashboard tests. This file has no build tag and imports the standard library only, so the pure test at its end
// runs with no cluster (go test -run TestM15DashboardFilesParse ./test/e2e/).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	m15DashboardGlob = "../../components/observability-store/grafana/dashboards/*.json"
	m15RulesFile     = "../../components/observability-store/grafana/alerting/rules.json"
)

// m15Dashboard is one committed dashboard file. Panels keeps the decoded panels for the comparison with the Grafana copy.
type m15Dashboard struct {
	UID    string
	File   string
	Panels []map[string]any
}

// m15Target is one query of one panel of a committed dashboard.
type m15Target struct {
	Dashboard  string
	Panel      string
	PanelID    int
	RefID      string
	Datasource string
	Expr       string
	Instant    bool
	Range      bool
	Format     string
	QueryType  string
	EventOnly  bool
}

// Name is the subtest name of the target, and it names the dashboard, the panel and the query.
func (t m15Target) Name() string {
	return fmt.Sprintf("%s/%d %s/%s", t.Dashboard, t.PanelID, strings.NewReplacer(" ", "_", "/", "_").Replace(t.Panel), t.RefID)
}

// loadM15Dashboards reads every committed dashboard file, in file name order.
func loadM15Dashboards(t testing.TB) []m15Dashboard {
	t.Helper()
	files, err := filepath.Glob(m15DashboardGlob)
	if err != nil || len(files) == 0 {
		t.Fatalf("no dashboard files match %s: %v", m15DashboardGlob, err)
	}
	slices.Sort(files)
	var out []m15Dashboard
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			UID    string           `json:"uid"`
			Panels []map[string]any `json:"panels"`
		}
		if err := json.Unmarshal(raw, &d); err != nil || d.UID == "" {
			t.Fatalf("decode %s: uid %q, error %v", f, d.UID, err)
		}
		out = append(out, m15Dashboard{UID: d.UID, File: f, Panels: d.Panels})
	}
	return out
}

// m15RuleUIDs returns the uid of each committed alert rule.
func m15RuleUIDs(t testing.TB) []string {
	t.Helper()
	raw, err := os.ReadFile(m15RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Groups []struct {
			Rules []struct {
				UID string `json:"uid"`
			} `json:"rules"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode %s: %v", m15RulesFile, err)
	}
	var uids []string
	for _, g := range f.Groups {
		for _, r := range g.Rules {
			uids = append(uids, r.UID)
		}
	}
	return uids
}

// m15Walk returns the panels of a dashboard and the panels nested inside them.
func m15Walk(panels []map[string]any) []map[string]any {
	var out []map[string]any
	for _, p := range panels {
		out = append(out, p)
		if inner, ok := p["panels"].([]any); ok {
			var sub []map[string]any
			for _, x := range inner {
				if m, ok := x.(map[string]any); ok {
					sub = append(sub, m)
				}
			}
			out = append(out, m15Walk(sub)...)
		}
	}
	return out
}

var m15Variable = regexp.MustCompile(`\$(__rate_interval|__range|cluster|cell|kind|service|trust_domain)\b`)

// m15Unresolved matches a variable of Grafana that m15Substitute does not know. A label_replace group such as $1 does not match.
var m15Unresolved = regexp.MustCompile(`\$[A-Za-z_]\w*`)

// m15Substitute replaces each variable that the generator emits. Every selector variable becomes .+, so the query reads every cluster,
// cell, step state, service and trust domain. It fails the test on any other variable.
func m15Substitute(t testing.TB, expr string) string {
	t.Helper()
	out := m15Variable.ReplaceAllStringFunc(expr, func(v string) string {
		switch v {
		case "$__range":
			return "1h"
		case "$__rate_interval":
			return "2m"
		}
		return ".+"
	})
	if m := m15Unresolved.FindString(out); m != "" {
		t.Fatalf("the query has the variable %s, which the test does not replace: %s", m, expr)
	}
	return out
}

// m15StripEvent removes the fallback that internal/dashboards adds to an event query, so that a bare query shows whether a series exists.
// It strips ") or on() vector(0)" and ") or vector(0)" and the opening bracket of the pair, and it returns the query unchanged otherwise.
func m15StripEvent(expr string) string {
	for _, suffix := range []string{") or on() vector(0)", ") or vector(0)"} {
		if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, suffix) {
			return strings.TrimSuffix(strings.TrimPrefix(expr, "("), suffix)
		}
	}
	return expr
}

// m15Targets returns each target of each panel of the committed dashboards, with the variables replaced.
func m15Targets(t testing.TB, dashboards []m15Dashboard) []m15Target {
	t.Helper()
	var out []m15Target
	for _, d := range dashboards {
		for _, p := range m15Walk(d.Panels) {
			raw, _ := json.Marshal(p)
			var pp struct {
				ID         int    `json:"id"`
				Title      string `json:"title"`
				Datasource *struct {
					UID string `json:"uid"`
				} `json:"datasource"`
				Targets []struct {
					RefID      string `json:"refId"`
					Expr       string `json:"expr"`
					Instant    bool   `json:"instant"`
					Range      bool   `json:"range"`
					Format     string `json:"format"`
					QueryType  string `json:"queryType"`
					EventOnly  bool   `json:"eventOnly"`
					Datasource *struct {
						UID string `json:"uid"`
					} `json:"datasource"`
				} `json:"targets"`
			}
			if err := json.Unmarshal(raw, &pp); err != nil {
				t.Fatalf("decode a panel of %s: %v", d.UID, err)
			}
			for _, tg := range pp.Targets {
				ds := ""
				switch {
				case tg.Datasource != nil:
					ds = tg.Datasource.UID
				case pp.Datasource != nil:
					ds = pp.Datasource.UID
				}
				expr := tg.Expr
				if tg.EventOnly {
					expr = m15StripEvent(expr)
				}
				out = append(out, m15Target{
					Dashboard: d.UID, Panel: pp.Title, PanelID: pp.ID, RefID: tg.RefID, Datasource: ds,
					Expr: m15Substitute(t, expr), Instant: tg.Instant, Range: tg.Range, Format: tg.Format, QueryType: tg.QueryType, EventOnly: tg.EventOnly,
				})
			}
		}
	}
	return out
}

// m15Query builds the body of one /api/ds/query call for a target over the last hour.
func m15Query(tg m15Target) (string, error) {
	q := map[string]any{"refId": "A", "datasource": map[string]string{"uid": tg.Datasource, "type": tg.Datasource}}
	switch tg.Datasource {
	case "prometheus":
		q["expr"], q["instant"], q["range"], q["intervalMs"], q["maxDataPoints"] = tg.Expr, tg.Instant, tg.Range, 15000, 1000
		if tg.Format != "" {
			q["format"] = tg.Format
		}
	case "loki":
		qt := tg.QueryType
		if qt == "" {
			qt = "range"
		}
		q["expr"], q["queryType"], q["maxLines"] = tg.Expr, qt, 200
	default:
		return "", fmt.Errorf("the data source %q is not prometheus or loki", tg.Datasource)
	}
	body, err := json.Marshal(map[string]any{"queries": []any{q}, "from": "now-1h", "to": "now"})
	return string(body), err
}

// m15FramesHaveValue reports whether an answer of /api/ds/query has a frame with a value, and describes what it saw when it has not.
// A frame counts when a column after the time column holds a non-null value, or when a single-column frame has any row.
func m15FramesHaveValue(resp []byte) (bool, string) {
	var r struct {
		Results map[string]struct {
			Error  string `json:"error"`
			Frames []struct {
				Data struct {
					Values [][]json.RawMessage `json:"values"`
				} `json:"data"`
			} `json:"frames"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return false, fmt.Sprintf("undecodable answer: %v", err)
	}
	a, ok := r.Results["A"]
	if !ok {
		return false, fmt.Sprintf("no result A: %.200s", resp)
	}
	if a.Error != "" {
		return false, "query error: " + a.Error
	}
	for _, f := range a.Frames {
		for i, col := range f.Data.Values {
			if i == 0 && len(f.Data.Values) > 1 {
				continue
			}
			for _, v := range col {
				if s := strings.TrimSpace(string(v)); s != "" && s != "null" {
					return true, ""
				}
			}
		}
	}
	return false, fmt.Sprintf("%d frames, none with a value", len(a.Frames))
}

// m15Late reports whether a check that passed after elapsed missed its limit.
func m15Late(elapsed, limit time.Duration) bool { return elapsed > limit }

func TestM15Late(t *testing.T) {
	if !m15Late(2*time.Minute, time.Minute) || m15Late(59*time.Second, time.Minute) || m15Late(time.Minute, time.Minute) {
		t.Error("m15Late must be true over the limit and false at or under it")
	}
}

func TestM15DashboardFilesParse(t *testing.T) {
	ds := loadM15Dashboards(t)
	targets := m15Targets(t, ds)
	if len(ds) != 8 || len(targets) == 0 {
		t.Fatalf("found %d dashboards and %d targets", len(ds), len(targets))
	}
	if n := len(m15RuleUIDs(t)); n != 8 {
		t.Fatalf("found %d alert rules, want 8", n)
	}
	for _, tg := range targets {
		if strings.Contains(tg.Expr, "$") && !strings.Contains(tg.Expr, "$1") {
			t.Errorf("%s keeps a variable: %s", tg.Name(), tg.Expr)
		}
		if _, err := m15Query(tg); err != nil {
			t.Errorf("%s: %v", tg.Name(), err)
		}
	}
	if got := m15StripEvent("(sum(x)) or vector(0)"); got != "sum(x)" {
		t.Errorf("strip of the plain wrap gave %q", got)
	}
	if got := m15StripEvent("(sum by (a) (x)) or on() vector(0)"); got != "sum by (a) (x)" {
		t.Errorf("strip of the grouped wrap gave %q", got)
	}
}
