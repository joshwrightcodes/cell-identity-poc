package dashboards

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// gridColumns is the width of the Grafana grid.
const gridColumns = 24

// Rules returns the alert rule file that the generator writes.
func Rules() RuleFile { return RuleFile{APIVersion: 1, Groups: []RuleGroup{}} }

// promQuery is one PromQL expression with the place that holds it.
type promQuery struct {
	Where string
	Expr  string
	Kind  string
}

// Kinds of promQuery.
const (
	kindVariable = "variable"
	kindPanel    = "panel"
	kindRule     = "rule"
)

var labelValuesRE = regexp.MustCompile(`^label_values\((.*),\s*[A-Za-z_][A-Za-z0-9_]*\)$`)

// promQueries returns every PromQL expression of the dashboards and the rules.
// Targets of other data sources, such as Loki, are not PromQL and do not appear.
func promQueries(boards []Dashboard, rules RuleFile) []promQuery {
	var out []promQuery
	for _, b := range boards {
		for _, v := range b.Templating.List {
			if v.Datasource != nil && v.Datasource.UID == DSPrometheus {
				expr := v.Query
				if m := labelValuesRE.FindStringSubmatch(expr); m != nil {
					expr = m[1]
				}
				out = append(out, promQuery{fmt.Sprintf("%s variable %s", b.UID, v.Name), expr, kindVariable})
			}
		}
		for _, p := range b.Panels {
			for _, t := range p.Targets {
				ds := t.Datasource
				if ds == nil {
					ds = p.Datasource
				}
				if ds != nil && ds.UID == DSPrometheus {
					out = append(out, promQuery{fmt.Sprintf("%s panel %q target %s", b.UID, p.Title, t.RefID), t.Expr, kindPanel})
				}
			}
		}
	}
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			for _, q := range r.Data {
				if q.DatasourceUID != DSPrometheus {
					continue
				}
				expr, _ := q.Model["expr"].(string)
				out = append(out, promQuery{fmt.Sprintf("rule %s query %s", r.UID, q.RefID), expr, kindRule})
			}
		}
	}
	return out
}

// CheckLayout checks the structure of the dashboards: unique UIDs, panels inside the grid with no overlap, and known data sources.
func CheckLayout(boards []Dashboard) error {
	var errs []error
	uids := map[string]bool{}
	files := map[string]bool{}
	okDS := func(where string, d *Datasource) {
		if d != nil && d.UID != DSPrometheus && d.UID != DSLoki {
			errs = append(errs, fmt.Errorf("%s: data source UID %q is not %s or %s", where, d.UID, DSPrometheus, DSLoki))
		}
	}
	for _, b := range boards {
		if b.UID == "" || b.Title == "" {
			errs = append(errs, fmt.Errorf("dashboard %q has no UID or no title", b.File))
		}
		if uids[b.UID] {
			errs = append(errs, fmt.Errorf("dashboard UID %q is not unique", b.UID))
		}
		uids[b.UID] = true
		if b.File == "" || files[b.File] {
			errs = append(errs, fmt.Errorf("dashboard %s has no file name, or its file name %q is not unique", b.UID, b.File))
		}
		files[b.File] = true
		for _, v := range b.Templating.List {
			okDS(b.UID+" variable "+v.Name, v.Datasource)
			if v.Type == "query" && v.Datasource == nil {
				errs = append(errs, fmt.Errorf("%s variable %s: no data source", b.UID, v.Name))
			}
		}
		ids := map[int]bool{}
		for i, p := range b.Panels {
			where := fmt.Sprintf("%s panel %q", b.UID, p.Title)
			if ids[p.ID] {
				errs = append(errs, fmt.Errorf("%s: panel ID %d is not unique", where, p.ID))
			}
			ids[p.ID] = true
			g := p.GridPos
			if g.W <= 0 || g.H <= 0 || g.X < 0 || g.Y < 0 || g.X+g.W > gridColumns {
				errs = append(errs, fmt.Errorf("%s: grid position %+v is outside the %d columns", where, g, gridColumns))
			}
			for _, q := range b.Panels[:i] {
				o := q.GridPos
				if g.X < o.X+o.W && o.X < g.X+g.W && g.Y < o.Y+o.H && o.Y < g.Y+g.H {
					errs = append(errs, fmt.Errorf("%s: overlaps panel %q", where, q.Title))
				}
			}
			okDS(where, p.Datasource)
			for _, t := range p.Targets {
				okDS(where+" target "+t.RefID, t.Datasource)
				if t.Datasource == nil && p.Datasource == nil {
					errs = append(errs, fmt.Errorf("%s target %s: no data source on the target or the panel", where, t.RefID))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// CheckQueries checks that every PromQL expression parses and names only metrics of the catalogue.
func CheckQueries(boards []Dashboard, rules RuleFile) error {
	names := known()
	var errs []error
	for _, q := range promQueries(boards, rules) {
		got, err := MetricNames(q.Expr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", q.Where, err))
			continue
		}
		if len(got) == 0 {
			errs = append(errs, fmt.Errorf("%s: the expression names no metric", q.Where))
		}
		for _, n := range got {
			m, ok := names[n]
			if !ok {
				errs = append(errs, fmt.Errorf("%s: metric %q is not in the catalogue", q.Where, n))
			} else if m.NotExported {
				errs = append(errs, fmt.Errorf("%s: metric %q is not exported by any binary today", q.Where, n))
			}
		}
	}
	return errors.Join(errs...)
}

// CheckSelectors checks the selector rule: a selector pins the cluster that emits the metric.
// A metric that one cluster emits takes k8s_cluster_name="<cluster>". A metric of many clusters may pin only a cluster that emits it.
func CheckSelectors(boards []Dashboard, rules RuleFile) error {
	names := known()
	var errs []error
	for _, q := range promQueries(boards, rules) {
		sels, err := Selectors(q.Expr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", q.Where, err))
			continue
		}
		for _, s := range sels {
			m, ok := names[s.Name]
			if !ok {
				continue
			}
			pin := ""
			scoped := false
			for _, mt := range s.Matchers {
				if mt.Label == "k8s_cluster_name" && mt.Op == "=" {
					pin = mt.Value
				}
				if scopeLabels[mt.Label] && (mt.Op == "=" || mt.Op == "=~") && followsScope(mt.Value) {
					scoped = true
				}
			}
			if pin != "" && !emits(m, pin) {
				errs = append(errs, fmt.Errorf("%s: %s pins k8s_cluster_name=%q, but the metric comes from %s", q.Where, s.Name, pin, strings.Join(m.Clusters, ", ")))
			}
			oneEmitter := len(m.Clusters) == 1 && m.Clusters[0] != ClusterCell && m.Clusters[0] != ClusterHost
			if pin == "" && oneEmitter {
				errs = append(errs, fmt.Errorf("%s: %s has no k8s_cluster_name=%q, which is the only emitter", q.Where, s.Name, m.Clusters[0]))
			}
			// A panel that reads a metric of many emitters must pin one emitter or follow a dashboard variable.
			// Variable queries and rules cannot use the dashboard variables.
			if q.Kind == kindPanel && !oneEmitter && pin == "" && !scoped {
				errs = append(errs, fmt.Errorf("%s: %s comes from many clusters and its selector has neither a k8s_cluster_name pin nor a $cluster or $cell matcher", q.Where, s.Name))
			}
		}
	}
	return errors.Join(errs...)
}

// followsScope reports whether a matcher value uses the variable cluster or cell, in the form $name or ${name}.
func followsScope(value string) bool {
	for _, name := range []string{"cluster", "cell"} {
		if strings.Contains(value, "$"+name) || strings.Contains(value, "${"+name) {
			return true
		}
	}
	return false
}

// scopeLabels are the labels whose matcher may follow the dashboard variables.
var scopeLabels = map[string]bool{"k8s_cluster_name": true, "platform_cell": true, "cell": true, "sender_cluster": true}

// emits reports whether the cluster is an emitter of the metric. A cell cluster is named dev-cell-<n>.
func emits(m Metric, cluster string) bool {
	return contains(m.Clusters, cluster) || (contains(m.Clusters, ClusterCell) && strings.HasPrefix(cluster, "dev-cell-"))
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// CheckParse marshals each dashboard and the rule file to JSON and reads the output back.
func CheckParse(boards []Dashboard, rules RuleFile) error {
	var errs []error
	for _, b := range boards {
		data, err := json.Marshal(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b.UID, err))
			continue
		}
		var back Dashboard
		if err := json.Unmarshal(data, &back); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b.UID, err))
		}
	}
	data, err := json.Marshal(rules)
	if err == nil {
		var back RuleFile
		err = json.Unmarshal(data, &back)
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("rules: %w", err))
	}
	return errors.Join(errs...)
}

// Check runs every check and joins the errors.
func Check(boards []Dashboard, rules RuleFile) error {
	return errors.Join(CheckLayout(boards), CheckParse(boards, rules), CheckQueries(boards, rules), CheckSelectors(boards, rules))
}

// sortedKeys returns the keys of a map in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
