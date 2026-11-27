package dashboards

import (
	"reflect"
	"strings"
	"testing"
)

func TestMetricNames(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want []string
	}{
		{"bare selector", `up`, []string{"up"}},
		{"selector with matchers", `cellgw_streams{k8s_cluster_name="dev-cp", cell=~"$cell"}`, []string{"cellgw_streams"}},
		{"range and rate", `sum(rate(istio_requests_total{reporter="destination"}[$__rate_interval]))`, []string{"istio_requests_total"}},
		{"range variable", `sum(increase(store_proxy_denials_total[$__range]))`, []string{"store_proxy_denials_total"}},
		{"by list", `sum by (k8s_cluster_name, le) (increase(a_bucket[5m]))`, []string{"a_bucket"}},
		{"without list after the operand", `max(m_one) without (instance, job)`, []string{"m_one"}},
		{"on and group_left", `a_one * on (cell) group_left (zone) b_two`, []string{"a_one", "b_two"}},
		{"ignoring", `a_one / ignoring(le) b_two`, []string{"a_one", "b_two"}},
		{"label_replace strings", `label_replace(time() - GW_name, "cluster", "$1", "sender_cluster", "(.+)")`, []string{"GW_name"}},
		{"string that looks like a metric", `label_replace(m_one, "service", "not_a_metric_total", "", "")`, []string{"m_one"}},
		{"bool", `(time() - m_one) > bool 120`, []string{"m_one"}},
		{"numbers", `0.25 * m_one + 1e3 - 0x10 + .5`, []string{"m_one"}},
		{"functions and vector", `sum(m_one) or vector(0)`, []string{"m_one"}},
		{"histogram quantile", `histogram_quantile(0.5, sum by (le) (rate(h_bucket[$__rate_interval])))`, []string{"h_bucket"}},
		{"subquery", `count_over_time((count by (k8s_cluster_name) (argocd_app_info{sync_status!="Synced"}))[10m:1m]) >= 10`, []string{"argocd_app_info"}},
		{"variables", `m_one{cell="$cell", cluster=~"${cluster}"} - $__range`, []string{"m_one"}},
		{"offset and at", `m_one offset 5m + m_two @ 100`, []string{"m_one", "m_two"}},
		{"duplicates once", `m_one / m_one`, []string{"m_one"}},
		{"colon names", `job:rate:sum`, []string{"job:rate:sum"}},
		{"unless and atan2", `a_one unless b_two`, []string{"a_one", "b_two"}},
		{"single quotes and backticks", `m_one{a='x{', b=` + "`y}`" + `}`, []string{"m_one"}},
		{"matcher with a brace in the value", `m_one{a="}"} + m_two`, []string{"m_one", "m_two"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MetricNames(tc.expr)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("MetricNames(%q) = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}

func TestMetricNamesRejectsBrokenExpressions(t *testing.T) {
	for _, expr := range []string{`sum(m_one`, `m_one)`, `m_one{a="b"`, `m_one{a="b}`, `m_one{a}`, `m_one[5m`, `label_replace(m_one, "a`} {
		if got, err := MetricNames(expr); err == nil {
			t.Errorf("MetricNames(%q) = %v, want an error", expr, got)
		}
	}
}

func TestSelectorsKeepMatchers(t *testing.T) {
	sels, err := Selectors(`sum(m_one{k8s_cluster_name="dev-cp", cell=~"$cell", reason!=""}) / m_two`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Selector{
		{Name: "m_one", Matchers: []Matcher{{"k8s_cluster_name", "=", "dev-cp"}, {"cell", "=~", "$cell"}, {"reason", "!=", ""}}},
		{Name: "m_two"},
	}
	if !reflect.DeepEqual(sels, want) {
		t.Fatalf("Selectors = %+v, want %+v", sels, want)
	}
}

func TestPlanQueriesParse(t *testing.T) {
	// Forms from the panel table of the plan.
	exprs := map[string]string{
		`max(mgmtd_cells_valid{k8s_cluster_name="management"})`:                                                                                              "mgmtd_cells_valid",
		`(min(trust_ca_not_after_seconds{trust_domain="dev.env.poc.internal", ca="intermediate"}) - time()) / 86400`:                                         "trust_ca_not_after_seconds",
		`sum by (reason) (increase(cluster_jwt_attestations_total{k8s_cluster_name="dev-cp", result="refused"}[$__range]))`:                                  "cluster_jwt_attestations_total",
		`max by (cluster) (label_replace(time() - cellproxy_gateway_last_export_time_seconds{signal="metrics"}, "cluster", "$1", "sender_cluster", "(.+)"))`: "cellproxy_gateway_last_export_time_seconds",
	}
	for expr, first := range exprs {
		got, err := MetricNames(expr)
		if err != nil || len(got) == 0 || got[0] != first || strings.Contains(strings.Join(got, " "), "cluster ") {
			t.Errorf("MetricNames(%q) = %v, %v; want %s first", expr, got, err, first)
		}
	}
}
