//go:build e2e

package e2e

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	m15PushEvery = 15 * time.Second
	// m15RotatedMarker records that the test rotated the intermediate CA of dev-cp, so that the repair can tell.
	m15RotatedMarker = "../../build/gate/m15-intermediate-rotated"
	m15RotateBound   = 40 * time.Minute
	m15WeekSeconds   = 7 * 24 * 3600
)

// m15Alert is one alert instance of /api/prometheus/grafana/api/v1/alerts.
type m15Alert struct {
	Labels map[string]string `json:"labels"`
	State  string            `json:"state"`
}

func m15Alerts(t *testing.T, creds string) []m15Alert {
	t.Helper()
	code, body := grafanaCall(t, creds, "GET", "/api/prometheus/grafana/api/v1/alerts", "")
	if code != 200 {
		t.Fatalf("GET alerts: HTTP %d: %.300s", code, body)
	}
	var r struct {
		Data struct {
			Alerts []m15Alert `json:"alerts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode the alerts: %v: %.300s", err, body)
	}
	return r.Data.Alerts
}

// m15Firing reports whether an alert of the rule title has the label value and the synthetic marker, in the state Alerting.
func m15Firing(alerts []m15Alert, title, label, value string) bool {
	for _, a := range alerts {
		if a.Labels["alertname"] == title && a.Labels[label] == value && a.Labels["synthetic"] == "true" &&
			(strings.EqualFold(a.State, "alerting") || strings.EqualFold(a.State, "firing")) {
			return true
		}
	}
	return false
}

// m15Push sends the series to the OTLP HTTP port of the collector in lgtm-0 with curl.
func m15Push(t *testing.T, series []m15Synth, start time.Time) {
	t.Helper()
	body, err := m15Request(series, start, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out, err := kubectl(t, mgmtCluster, string(body), "-n", obsNamespace, "exec", "-i", lgtmPod, "-c", lgtmContainer, "--",
		"curl", "-sS", "--max-time", "20", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
		"-H", "Content-Type: application/x-protobuf", "--data-binary", "@-", "http://127.0.0.1:4318/v1/metrics")
	if err != nil || strings.TrimSpace(out) != "200" {
		t.Fatalf("push of %d synthetic series: HTTP %q, error %v", len(series), out, err)
	}
}

// m15Rule is one row of the table of the plan. fire and clear return the series for the value v, which is m15-<hex>.
type m15Rule struct {
	id, title, label    string
	fire, clear         func(v string) []m15Synth
	fireWait, clearWait time.Duration
}

func m15Cell(inst string, v float64, cell string) m15Synth {
	return m15Synth{Instrument: inst, Value: v, Resource: map[string]string{"platform.cell": cell}}
}

// The brief gives each wait as the hold of the rule plus 3 minutes, and 13 minutes for A5. A counter rule clears only when its window
// has passed, so the clear wait of A4 and A7 is the 5 minute window plus 3 minutes, and that of A5 is 13 minutes.
func m15Rules() []m15Rule {
	const slack = 3 * time.Minute
	counter := func(inst string, val float64, res, attrs map[string]string) func(string) []m15Synth {
		return func(v string) []m15Synth {
			r, a := map[string]string{}, map[string]string{}
			for k, x := range res {
				r[k] = strings.ReplaceAll(x, "{v}", v)
			}
			for k, x := range attrs {
				a[k] = strings.ReplaceAll(x, "{v}", v)
			}
			return []m15Synth{{Instrument: inst, Value: val, Resource: r, Attrs: a}}
		}
	}
	tunnel := func(val float64) func(string) []m15Synth {
		return func(v string) []m15Synth {
			return []m15Synth{{Instrument: "cell_proxy.tunnel.up", Value: val,
				Resource: map[string]string{"k8s.cluster.name": "management"}, Attrs: map[string]string{"side": "hub", "cell": v}}}
		}
	}
	ca := func(days int) func(string) []m15Synth {
		return func(v string) []m15Synth {
			at := float64(time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix())
			return []m15Synth{{Instrument: "trust.ca.not_after", Value: at, Resource: map[string]string{"k8s.cluster.name": v},
				Attrs: map[string]string{"ca": "intermediate", "trust.domain": v}}}
		}
	}
	queue := func(size float64) func(string) []m15Synth {
		return func(v string) []m15Synth {
			res := map[string]string{"k8s.cluster.name": v}
			at := map[string]string{"data_type": "metrics"}
			return []m15Synth{
				{Instrument: "otelcol_exporter_queue_size", Value: size, Resource: res, Attrs: at},
				{Instrument: "otelcol_exporter_queue_capacity", Value: 100, Resource: res, Attrs: at},
			}
		}
	}
	svid := func(remaining float64) func(string) []m15Synth {
		return func(v string) []m15Synth {
			return []m15Synth{m15Cell("celld.svid.remaining", remaining, v), m15Cell("celld.svid.lifetime", 60, v)}
		}
	}
	age := func(a float64) func(string) []m15Synth {
		return func(v string) []m15Synth { return []m15Synth{m15Cell("celld.upstream.age", a, v)} }
	}
	refused := counter("cluster_jwt.attestations", 20, map[string]string{"k8s.cluster.name": "dev-cp"}, map[string]string{"result": "refused", "cell": "{v}"})
	rolledBack := counter("bundle.apply.outcomes", 1, map[string]string{"k8s.cluster.name": "{v}"}, map[string]string{"outcome": "rolled_back"})
	overwrite := counter("cellproxy.gateway.attribute.overwrites", 3, map[string]string{"k8s.cluster.name": "management"}, map[string]string{"sender.cluster": "{v}"})
	return []m15Rule{
		{"A1", "SVID under a quarter of its lifetime", "platform_cell", svid(10), svid(50), 5*time.Minute + slack, slack},
		{"A2", "Island started", "cluster", age(200), age(5), slack, slack},
		{"A3", "Intermediate CA under 7 days", "trust_domain", ca(3), ca(30), slack, slack},
		{"A4", "Attestation refusals over 10 in 5 minutes", "cell", refused, refused, slack, 5*time.Minute + slack},
		{"A5", "Set not applied, or a rollback", "k8s_cluster_name", rolledBack, rolledBack, 13 * time.Minute, 13 * time.Minute},
		{"A6", "Collector queue over 80% of its cap", "k8s_cluster_name", queue(90), queue(10), time.Minute + slack, slack},
		{"A7", "Source tag overwritten", "sender_cluster", overwrite, overwrite, slack, 5*time.Minute + slack},
		{"A8", "Kiali tunnel down", "cell", tunnel(0), tunnel(1), 5*time.Minute + slack, slack},
	}
}

var m15RotateOnce sync.Once

// m15RotateIntermediate rotates the intermediate CA of dev-cp when it has under 7 days left, because a real A3 alert would fire from then
// on. It writes build/gate/m15-intermediate-rotated first, so that the repair knows the rotation ran. It rotates at most once.
func m15RotateIntermediate(t *testing.T) {
	t.Helper()
	m15RotateOnce.Do(func() {
		left := promSamples(t, `min(last_over_time(trust_ca_not_after_seconds{ca="intermediate", service_name!="m15-synthetic"}[2m])) - time()`)
		if len(left) == 0 || left[0].last >= m15WeekSeconds {
			return
		}
		t.Logf("the intermediate CA has %.1f days left, so the test rotates it with pki:rotate-intermediate", left[0].last/86400)
		if err := os.MkdirAll(filepath.Dir(m15RotatedMarker), 0o755); err != nil {
			t.Error(err)
			return
		}
		if err := os.WriteFile(m15RotatedMarker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
			t.Error(err)
			return
		}
		if out, err := miseRun(t, m15RotateBound, []string{"CELL=dev-cp"}, "pki:rotate-intermediate"); err != nil {
			t.Errorf("pki:rotate-intermediate: %v\n%s", err, out)
		}
	})
}

// TestM15AlertRulesFireAndClear pushes the fire series of each rule every 15 seconds under its own m15-<hex> value, waits until the
// Grafana alert list shows an alert of the rule for that value with the marker synthetic=true, then pushes the clear series and waits
// until the alert is gone. The counters of A4, A5 and A7 start at their fire value, with no 0 sample before, so the first-event path of
// Born is tested. Their clear series keep the value, and the alert clears when the window passes.
func TestM15AlertRulesFireAndClear(t *testing.T) {
	creds := m15RequireGrafana(t)
	start := time.Now().Add(-time.Minute)
	for _, r := range m15Rules() {
		t.Run(r.id, func(t *testing.T) {
			t.Parallel()
			v := "m15-" + randomHex(t, 4)
			t.Cleanup(func() {
				if r.id != "A4" && r.id != "A5" && r.id != "A7" {
					body, err := m15Request(r.clear(v), start, time.Now())
					if err == nil {
						_, _ = kubectl(t, mgmtCluster, string(body), "-n", obsNamespace, "exec", "-i", lgtmPod, "-c", lgtmContainer, "--",
							"curl", "-sS", "--max-time", "20", "-o", "/dev/null", "-X", "POST", "-H", "Content-Type: application/x-protobuf",
							"--data-binary", "@-", "http://127.0.0.1:4318/v1/metrics")
					}
				}
			})
			phase := func(what string, series func(string) []m15Synth, bound time.Duration, done func([]m15Alert) bool) time.Duration {
				began := time.Now()
				for {
					m15Push(t, series(v), start)
					if done(m15Alerts(t, creds)) {
						return time.Since(began)
					}
					if time.Since(began) > bound {
						t.Fatalf("%s: rule %s (%s) did not %s for %s within %s", r.id, r.id, r.title, what, v, bound)
					}
					time.Sleep(m15PushEvery)
				}
			}
			took := phase("fire", r.fire, r.fireWait, func(a []m15Alert) bool { return m15Firing(a, r.title, r.label, v) })
			t.Logf("%s FIRE_SECONDS=%.0f", r.id, took.Seconds())
			if r.id == "A3" {
				m15RotateIntermediate(t)
			}
			took = phase("clear", r.clear, r.clearWait, func(a []m15Alert) bool { return !m15Firing(a, r.title, r.label, v) })
			t.Logf("%s CLEAR_SECONDS=%.0f", r.id, took.Seconds())
		})
	}
	t.Run("no_synthetic_in_variables", func(t *testing.T) {
		t.Parallel()
		waitFor(t, "a synthetic series in Prometheus", 3*time.Minute, func() (bool, string) {
			s := promSamples(t, `count({service_name="m15-synthetic"})`)
			return len(s) > 0 && s[0].last > 0, "no synthetic series yet"
		})
		time.Sleep(time.Minute)
		leak := regexp.MustCompile(`m15-[0-9a-f]{8}`)
		for _, d := range loadM15Dashboards(t) {
			raw, err := os.ReadFile(d.File)
			if err != nil {
				t.Fatal(err)
			}
			var f struct {
				Templating struct {
					List []struct {
						Name, Type, Query string
					} `json:"list"`
				} `json:"templating"`
			}
			if err := json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			for _, v := range f.Templating.List {
				if v.Type != "query" {
					continue
				}
				m := regexp.MustCompile(`^label_values\((?:(.*),\s*)?(\w+)\)$`).FindStringSubmatch(v.Query)
				if m == nil {
					t.Errorf("%s variable %s has the query %q, which the test cannot run", d.UID, v.Name, v.Query)
					continue
				}
				path := "/api/datasources/uid/prometheus/resources/api/v1/label/" + m[2] + "/values"
				if m[1] != "" {
					path += "?match[]=" + url.QueryEscape(m[1])
				}
				code, body := grafanaCall(t, creds, "GET", path, "")
				if code != 200 {
					t.Errorf("%s variable %s: HTTP %d: %.200s", d.UID, v.Name, code, body)
					continue
				}
				if hit := leak.FindString(string(body)); hit != "" {
					t.Errorf("%s variable %s lists the synthetic value %s", d.UID, v.Name, hit)
				}
			}
		}
		// The panels leave the synthetic series out too. The expression of each target names m15-synthetic in its filter, so the check removes that word first.
		for _, tg := range m15Targets(t, loadM15Dashboards(t)) {
			if tg.Datasource != "prometheus" {
				continue
			}
			body, err := m15Query(tg)
			if err != nil {
				t.Fatal(err)
			}
			code, resp := grafanaCall(t, creds, "POST", "/api/ds/query", body)
			if code != 200 {
				continue
			}
			if hit := leak.FindString(strings.ReplaceAll(string(resp), "m15-synthetic", "")); hit != "" {
				t.Errorf("%s shows the synthetic value %s", tg.Name(), hit)
			}
		}
	})
}
