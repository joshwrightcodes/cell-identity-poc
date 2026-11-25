package dashboards

import (
	"fmt"
	"sort"
	"strings"
)

// Colours of the approved mockup, on the dark theme.
const (
	colCell1 = "#3987e5"
	colCell2 = "#d95926"
	colCP    = "#199e70"

	colGood    = "#0ca30c"
	colWarning = "#fab219"
	colSerious = "#ec835a"
	colCrit    = "#d03b3b"
	colNeutral = "#6e7f96"
)

// SyntheticService is the service name of the synthetic series that the gate pushes. No panel reads it.
const SyntheticService = "m15-synthetic"

const (
	pinMgmt   = `k8s_cluster_name="management"`
	pinCP     = `k8s_cluster_name="dev-cp"`
	clusterRe = `k8s_cluster_name=~"$cluster"`
	cellRe    = `platform_cell=~"$cell"`
	notSynth  = `service_name!="` + SyntheticService + `"`

	rng  = "$__range"
	rate = "$__rate_interval"

	// freshFast is the window for gauges that the 15 s exporters report.
	// OTLP series get no staleness marker, so a gauge that vanishes or changes labels would keep its last value for the 5 minute lookback.
	// last_over_time returns a series only when it has a sample in the window, and it works for instant and range queries.
	freshFast = "1m"
	// freshSlow is the window for gauges that report at the SDK default of 60 s.
	freshSlow = "2m"
)

// S writes a selector with the matchers and the filter that leaves out the synthetic series of the gate.
func S(name string, matchers ...string) string {
	ms := append(append([]string{}, matchers...), notSynth)
	return name + "{" + strings.Join(ms, ", ") + "}"
}

// fresh keeps only the series of a selector that have a sample in the window.
func fresh(selector, window string) string {
	return fmt.Sprintf("last_over_time(%s[%s])", selector, window)
}

// Born returns the increase of a counter in the window, and it counts a series that the window creates as its full value.
// A counter has no series before its first event, and the first sample of a new series holds the count, so increase alone reads 0 for it.
// A series that was absent at the start of the window comes first, because or keeps the left side.
func Born(selector, window string) string {
	return "((" + selector + " unless " + selector + " offset " + window + ") or increase(" + selector + "[" + window + "]))"
}

// gw is the last export time of the telemetry gateway for the metrics signal.
func gw(extra ...string) string {
	return S("cellproxy_gateway_last_export_time_seconds", append([]string{pinMgmt, `signal="metrics"`}, extra...)...)
}

// IslandScope narrows the layers of IslandAge. An empty field adds no matcher. Extra goes on every selector.
type IslandScope struct {
	Sender, Cell, Env, Extra string
	// KeepService groups by service_name too, so an alert instance keeps the marker of a synthetic series.
	KeepService bool
}

// IslandAge returns the upstream age in seconds of each layer, keyed by the label cluster.
// The dashboards and the alert rule A2 share it, so "Islands now" and the rule agree.
func IslandAge(sc IslandScope) string {
	sel := func(name string, ms ...string) string {
		var all []string
		for _, m := range ms {
			if m != "" {
				all = append(all, m)
			}
		}
		if sc.Extra != "" {
			all = append(all, sc.Extra)
		}
		return name + "{" + strings.Join(all, ", ") + "}"
	}
	by := "cluster"
	if sc.KeepService {
		by += ", service_name"
	}
	return `max by (` + by + `) (` +
		`label_replace(time() - ` + sel("cellproxy_gateway_last_export_time_seconds", pinMgmt, `signal="metrics"`, sc.Sender) + `, "cluster", "$1", "sender_cluster", "(.+)") or ` +
		`label_replace(` + sel("celld_upstream_age_seconds", sc.Cell) + `, "cluster", "$1", "platform_cell", "(.+)") or ` +
		`label_replace(` + sel("envd_upstream_age_seconds", pinCP, sc.Env) + `, "cluster", "$1", "k8s_cluster_name", "(.+)"))`
}

// islandBoard is the scope of the dashboards.
func islandBoard() IslandScope {
	return IslandScope{Sender: `sender_cluster=~"$cluster"`, Cell: cellRe, Env: clusterRe, Extra: notSynth}
}

var (
	promDS = &Datasource{Type: "prometheus", UID: DSPrometheus}
	lokiDS = &Datasource{Type: "loki", UID: DSLoki}
)

// Variables.

func clusterVar(label string) Variable {
	return queryVar("cluster", label, `label_values(up{k8s_cluster_name=~".+"}, k8s_cluster_name)`)
}

func cellVar() Variable {
	return queryVar("cell", "Cell", `label_values(up{platform_plane="cell"}, platform_cell)`)
}

func queryVar(name, label, query string) Variable {
	return Variable{
		Name: name, Label: label, Type: "query", Datasource: promDS, Query: query, Definition: query,
		Refresh: 1, Multi: true, IncludeAll: true, Sort: 1, Current: &Current{Text: "All", Value: "$__all"},
	}
}

// Targets.

// instant is a query that returns its last value, for stats, bar gauges and tables.
func instant(expr, legend string) Target {
	return Target{Expr: expr, Instant: true, LegendFormat: legend}
}

// series is a range query.
func series(expr, legend string) Target { return Target{Expr: expr, Range: true, LegendFormat: legend} }

// event wraps a query that counts events, so that it reads 0 before the first event.
// A query with no grouping labels falls back with a plain vector(0). A grouped query falls back only when it is empty.
func event(t Target, grouped bool) Target {
	if grouped {
		t.Expr = "(" + t.Expr + ") or on() vector(0)"
	} else {
		t.Expr = "(" + t.Expr + ") or vector(0)"
	}
	t.EventOnly = true
	return t
}

// Panels.

func ptr[T any](v T) *T { return &v }

type step struct {
	v float64
	c string
}

// thresholds returns the steps of a panel. The first colour is the base.
func thresholds(base string, steps ...step) *Thresholds {
	t := &Thresholds{Mode: "absolute", Steps: []ThresholdStep{{Color: base}}}
	for _, s := range steps {
		t.Steps = append(t.Steps, ThresholdStep{Color: s.c, Value: ptr(s.v)})
	}
	return t
}

func newPanel(typ, title, desc string, x, y, w, h int, targets ...Target) Panel {
	return Panel{
		Type: typ, Title: title, Description: desc, GridPos: GridPos{H: h, W: w, X: x, Y: y}, Datasource: promDS,
		Targets: targets, FieldConfig: FieldConfig{Overrides: []Override{}},
	}
}

// stat builds a stat panel. A panel with several targets shows each value with its legend.
func stat(title, desc string, x, y, w, h int, unit string, th *Thresholds, targets ...Target) Panel {
	p := newPanel("stat", title, desc, x, y, w, h, targets...)
	p.FieldConfig.Defaults = FieldDefaults{Unit: unit, Color: map[string]any{"mode": "thresholds"}, Thresholds: th}
	text := "auto"
	if len(targets) > 1 {
		text = "value_and_name"
	}
	p.Options = map[string]any{
		"reduceOptions": map[string]any{"calcs": []string{"lastNotNull"}, "fields": "", "values": false},
		"colorMode":     "background", "graphMode": "none", "textMode": text, "orientation": "auto", "justifyMode": "center",
	}
	return p
}

func timeSeries(title, desc string, x, y, w, h int, unit string, targets ...Target) Panel {
	p := newPanel("timeseries", title, desc, x, y, w, h, targets...)
	p.FieldConfig.Defaults = FieldDefaults{Unit: unit, Color: map[string]any{"mode": "palette-classic"},
		Custom: map[string]any{"drawStyle": "line", "lineWidth": 2, "fillOpacity": 10, "showPoints": "never", "spanNulls": false}}
	p.Options = map[string]any{
		"legend":  map[string]any{"displayMode": "list", "placement": "bottom", "showLegend": true},
		"tooltip": map[string]any{"mode": "multi", "sort": "desc"},
	}
	return p
}

func barGauge(title, desc string, x, y, w, h int, unit string, targets ...Target) Panel {
	p := newPanel("bargauge", title, desc, x, y, w, h, targets...)
	p.FieldConfig.Defaults = FieldDefaults{Unit: unit, Color: map[string]any{"mode": "palette-classic"}, Min: ptr(0.0)}
	p.Options = map[string]any{
		"displayMode": "gradient", "orientation": "horizontal", "showUnfilled": true, "valueMode": "color",
		"reduceOptions": map[string]any{"calcs": []string{"lastNotNull"}, "fields": "", "values": false},
	}
	return p
}

// clusterColours is the override list that gives each cluster its colour by series name.
func clusterColours() []Override {
	var out []Override
	for _, c := range []struct{ name, colour string }{{"dev-cell-1", colCell1}, {"dev-cell-2", colCell2}, {"dev-cp", colCP}} {
		out = append(out, colourOf(c.name, c.colour))
	}
	return out
}

func colourOf(name, colour string) Override {
	return Override{
		Matcher:    FieldMatcher{ID: "byName", Options: name},
		Properties: []Property{{ID: "color", Value: map[string]any{"mode": "fixed", "fixedColor": colour}}},
	}
}

// dashed draws the series of that name as a dashed line in the colour.
func dashed(name, colour string) Override {
	o := colourOf(name, colour)
	o.Properties = append(o.Properties,
		Property{ID: "custom.lineStyle", Value: map[string]any{"fill": "dash", "dash": []int{10, 10}}},
		Property{ID: "custom.fillOpacity", Value: 0})
	return o
}

// coloured gives the panel the cluster colours and the extra overrides.
func coloured(p Panel, extra ...Override) Panel {
	p.FieldConfig.Overrides = append(append(p.FieldConfig.Overrides, clusterColours()...), extra...)
	return p
}

// constLine returns a query for a horizontal line of the value. It reads the selector only to find the time range.
func constLine(selector string, v float64) string {
	return fmt.Sprintf("0 * max(%s) + %g", selector, v)
}

// valueMap maps a value to a text.
func valueMap(kind string, entries ...[3]string) map[string]any {
	opts := map[string]any{}
	for i, e := range entries {
		opts[e[0]] = map[string]any{"text": e[1], "color": e[2], "index": i}
	}
	return map[string]any{"type": kind, "options": opts}
}

// tableColumn is one column of a joined table. Each column is an instant query that carries the key label.
// Labels lists label columns of the query as pairs of the label and the column title. LabelMap applies to them.
type tableColumn struct {
	Title    string
	Expr     string
	Unit     string
	Labels   [][2]string
	Map      map[string]any
	LabelMap map[string]any
}

// nullAsNA shows an empty value as n/a. A mapping in an override replaces the default mappings, so each override adds it again.
func nullAsNA() map[string]any {
	return map[string]any{"type": "special", "options": map[string]any{"match": "null+nan", "result": map[string]any{"text": "n/a", "color": colNeutral, "index": 99}}}
}

// setOrder keeps only the columns with the titles, in that order.
func setOrder(p Panel, titles ...string) Panel {
	var rename map[string]string
	for _, t := range p.Transformations {
		if t["id"] == "organize" {
			rename = t["options"].(map[string]any)["renameByName"].(map[string]string)
		}
	}
	index := map[string]int{}
	var keep []string
	for source, title := range rename {
		for i, want := range titles {
			if title == want {
				index[source] = i
				keep = append(keep, source)
			}
		}
	}
	sort.Strings(keep)
	for _, t := range p.Transformations {
		switch t["id"] {
		case "filterFieldsByName":
			t["options"].(map[string]any)["include"] = map[string]any{"names": keep}
		case "organize":
			t["options"].(map[string]any)["indexByName"] = index
		}
	}
	return p
}

func mappingOverride(name string, m map[string]any) Override {
	return Override{
		Matcher:    FieldMatcher{ID: "byName", Options: name},
		Properties: []Property{{ID: "mappings", Value: []map[string]any{m, nullAsNA()}}},
	}
}

// table builds a table that joins its queries on the key label, or shows its one query as it is when the key is empty.
// Label columns come from the labels of the queries.
func table(title, desc string, x, y, w, h int, key, keyTitle, sortBy string, cols ...tableColumn) Panel {
	p := newPanel("table", title, desc, x, y, w, h)
	rename := map[string]string{}
	index := map[string]int{}
	var keep []string
	order := 0
	if key != "" {
		rename[key], index[key], keep, order = keyTitle, 0, []string{key}, 1
	}
	for i, c := range cols {
		p.Targets = append(p.Targets, Target{Expr: c.Expr, Instant: true, Format: "table"})
		for _, l := range c.Labels {
			rename[l[0]], index[l[0]] = l[1], order
			order++
			keep = append(keep, l[0])
			if c.LabelMap != nil {
				p.FieldConfig.Overrides = append(p.FieldConfig.Overrides, mappingOverride(l[1], c.LabelMap))
			}
		}
		ref := "Value #" + string(rune('A'+i))
		rename[ref], index[ref] = c.Title, order
		order++
		keep = append(keep, ref)
		ov := Override{Matcher: FieldMatcher{ID: "byName", Options: c.Title}}
		if c.Unit != "" {
			ov.Properties = append(ov.Properties, Property{ID: "unit", Value: c.Unit})
		}
		if c.Map != nil {
			ov.Properties = append(ov.Properties, Property{ID: "mappings", Value: []map[string]any{c.Map, nullAsNA()}})
		}
		if len(ov.Properties) > 0 {
			p.FieldConfig.Overrides = append(p.FieldConfig.Overrides, ov)
		}
	}
	if len(cols) == 1 {
		// A single query names its value field Value.
		rename["Value"], index["Value"], keep = cols[0].Title, index["Value #A"], append(keep, "Value")
	}
	p.FieldConfig.Defaults = FieldDefaults{
		Custom:   map[string]any{"align": "auto", "cellOptions": map[string]any{"type": "auto"}},
		Mappings: []map[string]any{nullAsNA()},
	}
	p.Options = map[string]any{"showHeader": true, "sortBy": []map[string]any{{"displayName": sortBy, "desc": false}}}
	if key != "" {
		p.Transformations = append(p.Transformations, map[string]any{"id": "joinByField", "options": map[string]any{"byField": key, "mode": "outer"}})
	}
	p.Transformations = append(p.Transformations,
		map[string]any{"id": "filterFieldsByName", "options": map[string]any{"include": map[string]any{"names": keep}}},
		map[string]any{"id": "organize", "options": map[string]any{"excludeByName": map[string]bool{}, "indexByName": index, "renameByName": rename}})
	return p
}

// board collects the panels of a dashboard and gives each an ID and a reference ID for each target.
type board struct{ d Dashboard }

func newBoard(file, uid, title, from string, vars ...Variable) *board {
	return &board{d: Dashboard{
		File: file, UID: uid, Title: title, Tags: []string{"cell-identity-poc"}, Editable: false, GraphTooltip: 1, Refresh: "30s",
		SchemaVersion: 41, Time: TimeRange{From: "now-" + from, To: "now"}, Timezone: "browser",
		Templating: Templating{List: vars}, Panels: []Panel{},
	}}
}

// add appends a panel. The description gains the names of the metrics that the panel reads.
func (b *board) add(p Panel) {
	p.ID = len(b.d.Panels) + 1
	var names []string
	seen := map[string]bool{}
	for i := range p.Targets {
		p.Targets[i].RefID = string(rune('A' + i))
		if p.Targets[i].Datasource == nil && p.Datasource != nil && p.Datasource.UID == DSPrometheus {
			if got, err := MetricNames(p.Targets[i].Expr); err == nil {
				for _, n := range got {
					if !seen[n] {
						seen[n] = true
						names = append(names, n)
					}
				}
			}
		}
	}
	if len(names) > 0 {
		p.Description += " Reads " + strings.Join(names, ", ") + "."
	}
	b.d.Panels = append(b.d.Panels, p)
}

// col returns the x position and the width of column i of n equal columns.
func col(i, n int) (x, w int) {
	w = gridColumns / n
	return i * w, w
}

// Boards returns the dashboards that the generator writes.
func Boards() []Dashboard {
	return []Dashboard{
		cellHealthBoard(), spiffeBoard(), argocdBoard(), meshBoard(), islandsBoard(), refusalsBoard(), workBoard(), telemetryBoard(),
	}
}
