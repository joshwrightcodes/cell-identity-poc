//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// m15DataWait bounds the wait for the data of the panels. The harness has run for a while before the gate starts, so the wait covers the
// export interval of the OpenTelemetry SDK of each component and the first scrape.
const m15DataWait = 10 * time.Minute

// m15RequireGrafana skips the test when no harness answers, so the test also builds and runs on a Mac with no clusters.
func m15RequireGrafana(t *testing.T) string {
	t.Helper()
	if _, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "get", "pod", lgtmPod, "-o", "name"); err != nil {
		t.Skipf("no harness answers (pod %s in %s): %v", lgtmPod, obsNamespace, err)
	}
	return "admin:" + grafanaPassword(t)
}

// normalizeJSON decodes and encodes a value, so that two values compare by content.
func normalizeJSON(t *testing.T, v any) any {
	t.Helper()
	var out any
	if err := json.Unmarshal(mustJSON(t, v), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestM15Provisioned checks that Grafana holds each committed dashboard as a provisioned dashboard with the committed panels, that the
// API refuses to delete one, and that the eight committed alert rules have the provenance file.
func TestM15Provisioned(t *testing.T) {
	creds := m15RequireGrafana(t)
	for _, d := range loadM15Dashboards(t) {
		t.Run(d.UID, func(t *testing.T) {
			path := "/api/dashboards/uid/" + url.PathEscape(d.UID)
			code, body := grafanaCall(t, creds, "GET", path, "")
			if code != 200 {
				t.Fatalf("GET %s: HTTP %d: %.300s", path, code, body)
			}
			var got struct {
				Meta struct {
					Provisioned bool `json:"provisioned"`
				} `json:"meta"`
				Dashboard struct {
					Panels []map[string]any `json:"panels"`
				} `json:"dashboard"`
			}
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			if !got.Meta.Provisioned {
				t.Errorf("%s has meta.provisioned false", d.UID)
			}
			want, have := normalizeJSON(t, d.Panels).([]any), normalizeJSON(t, got.Dashboard.Panels).([]any)
			if len(want) != len(have) {
				t.Errorf("%s has %d panels in Grafana and %d in %s", d.UID, len(have), len(want), d.File)
			}
			for i := range want {
				if i < len(have) && !reflect.DeepEqual(want[i], have[i]) {
					t.Errorf("panel %d of %s differs from %s", i, d.UID, d.File)
				}
			}
			dcode, dbody := grafanaCall(t, creds, "DELETE", path, "")
			if dcode >= 200 && dcode < 300 {
				t.Errorf("DELETE %s succeeded with HTTP %d: %.200s", path, dcode, dbody)
			}
			if code, _ := grafanaCall(t, creds, "GET", path, ""); code != 200 {
				t.Errorf("%s is gone after the refused delete: HTTP %d", d.UID, code)
			}
		})
	}
	t.Run("rules", func(t *testing.T) {
		code, body := grafanaCall(t, creds, "GET", "/api/v1/provisioning/alert-rules", "")
		if code != 200 {
			t.Fatalf("GET alert-rules: HTTP %d: %.300s", code, body)
		}
		var rules []struct {
			UID        string `json:"uid"`
			Provenance string `json:"provenance"`
		}
		if err := json.Unmarshal(body, &rules); err != nil {
			t.Fatalf("decode the alert rules: %v", err)
		}
		prov := map[string]string{}
		for _, r := range rules {
			prov[r.UID] = r.Provenance
		}
		want := m15RuleUIDs(t)
		if len(want) != 8 {
			t.Fatalf("the committed file has %d rules, want 8", len(want))
		}
		for _, uid := range want {
			if p, ok := prov[uid]; !ok {
				t.Errorf("rule %s is not in Grafana", uid)
			} else if p != "file" {
				t.Errorf("rule %s has provenance %q, want file", uid, p)
			}
		}
	})
}

// TestM15PanelsReturnData runs each target of each committed panel over the last hour through /api/ds/query. A target returns a frame with
// a value, or the test retries it for up to m15DataWait. An event target runs bare, with the fallback of the generator removed, so it may
// return nothing. A Loki target is an event panel too, because a fresh harness can have no refusal in the last hour. The test logs its name and passes it, and the hermetic catalogue check of internal/dashboards stays its only guard.
func TestM15PanelsReturnData(t *testing.T) {
	creds := m15RequireGrafana(t)
	targets := m15Targets(t, loadM15Dashboards(t))
	deadline := time.Now().Add(m15DataWait)
	for _, tg := range targets {
		t.Run(tg.Name(), func(t *testing.T) {
			body, err := m15Query(tg)
			if err != nil {
				t.Fatal(err)
			}
			var seen string
			for {
				code, resp := grafanaCall(t, creds, "POST", "/api/ds/query", body)
				ok, failed := false, false
				if code == 200 {
					ok, seen = m15FramesHaveValue(resp)
					failed = strings.HasPrefix(seen, "query error") || strings.HasPrefix(seen, "undecodable") || strings.HasPrefix(seen, "no result")
				} else {
					seen, failed = fmt.Sprintf("HTTP %d: %.200s", code, resp), true
				}
				if ok {
					return
				}
				if (tg.EventOnly || tg.Datasource == "loki") && !failed {
					t.Logf("event or log target with no data, not checked live: %s (%s)", tg.Name(), seen)
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("no data for %s after %s: %s\nquery: %s", tg.Name(), m15DataWait, seen, tg.Expr)
				}
				time.Sleep(10 * time.Second)
			}
		})
	}
	if !slices.ContainsFunc(targets, func(tg m15Target) bool { return tg.EventOnly }) {
		t.Error("the committed dashboards have no event target, so the catalogue changed shape")
	}
}
