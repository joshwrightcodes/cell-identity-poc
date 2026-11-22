package scripts

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// statusEntry is an entry envelope for the stub of operatorctl verify in harness:status: it verifies when sig is "good".
func statusEntry(id, cell string, issued time.Time, sig string) string {
	payload, _ := json.Marshal(map[string]any{"id": id, "env": "dev", "cell": cell, "record": map[string]any{"epoch": 2, "counter": 5},
		"issuedAt": issued.UTC().Format(time.RFC3339)})
	env, _ := json.Marshal(map[string]any{"payloadType": "x", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{map[string]any{"sig": sig}}})
	return string(env)
}

// statusInputs is ConfigMap envd-system/local-revocations with the given key and envelope pairs.
func statusInputs(pairs ...string) string {
	data := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		data[pairs[i]] = pairs[i+1]
	}
	b, _ := json.Marshal(map[string]any{"data": data})
	return string(b)
}

// statusHeld is ConfigMap cell-records with the given envelopes in the overlay.
func statusHeld(envelopes ...string) string {
	raw := make([]json.RawMessage, 0, len(envelopes))
	for _, e := range envelopes {
		raw = append(raw, json.RawMessage(e))
	}
	arr, _ := json.Marshal(raw)
	b, _ := json.Marshal(map[string]any{"data": map[string]string{"local-revocations.json": string(arr)}})
	return string(b)
}

func statusPod(ready bool, restarts int) string {
	b, _ := json.Marshal(map[string]any{"status": map[string]any{"containerStatuses": []any{
		map[string]any{"name": "spire-server", "ready": true, "restartCount": 0},
		map[string]any{"name": "agent-ban", "ready": ready, "restartCount": restarts}}}})
	return string(b)
}

// TestStatusIslandFields: the dev-cp object reports island.environment, island.cells, overlay, bans and svidTTL. A cut environment and a
// cell with no stream are information: neither adds a problem.
func TestStatusIslandFields(t *testing.T) {
	t.Parallel()
	field := func(o map[string]any, path ...string) any {
		var v any = o
		for _, p := range path {
			m, _ := v.(map[string]any)
			v = m[p]
		}
		return v
	}
	byName, _, _, code := runStatus(t)
	dev := byName["dev-cp"]
	if code != 0 {
		t.Fatalf("a healthy run exits %d, want 0", code)
	}
	if field(dev, "island", "environment") != false || len(field(dev, "island", "cells").([]any)) != 0 {
		t.Errorf("healthy island = %v, want environment false and no cell", dev["island"])
	}
	if b := field(dev, "bans", "ready"); b != true || field(dev, "bans", "restarts") != float64(0) {
		t.Errorf("bans = %v, want ready true and no restart", dev["bans"])
	}
	if ttl, _ := dev["svidTTL"].(map[string]any); ttl["live"] != "1m" || ttl["file"] != "1m" || ttl["marker"] != nil {
		t.Errorf("svidTTL = %v, want live 1m, file 1m, no marker", dev["svidTTL"])
	}
	if ov, _ := dev["overlay"].(map[string]any); len(ov["held"].([]any)) != 0 || len(ov["inputs"].([]any)) != 0 {
		t.Errorf("overlay = %v, want empty held and inputs", dev["overlay"])
	}

	// mgmtd answers, and its newest report of envd is 5 minutes old: the environment is an island. The management object fails on the
	// missing report, and the dev-cp object stays ok.
	byName, _, _, _ = runStatus(t, "STUB_MGMT_STATUS="+healthyPlane(func(m map[string]any) { m["lastReportAt"] = timeAgo(5 * time.Minute) }))
	dev = byName["dev-cp"]
	if field(dev, "island", "environment") != true || dev["ok"] != true {
		t.Errorf("a report from 5 minutes ago: island = %v, ok = %v, want environment true and ok", dev["island"], dev["ok"])
	}
	// A report 100 seconds old is no island.
	byName, _, _, _ = runStatus(t, "STUB_MGMT_STATUS="+healthyPlane(func(m map[string]any) { m["lastReportAt"] = timeAgo(100 * time.Second) }))
	if field(byName["dev-cp"], "island", "environment") != false {
		t.Errorf("a report from 100 seconds ago: island = %v, want environment false", byName["dev-cp"]["island"])
	}
	// mgmtd does not answer: the environment is not reported as an island.
	byName, _, _, _ = runStatus(t, "STUB_MGMT_RC=1")
	if field(byName["dev-cp"], "island", "environment") != false {
		t.Errorf("mgmtd down: island = %v, want environment false", byName["dev-cp"]["island"])
	}

	// A live cell with no open stream at the gateway.
	byName, _, _, _ = runStatus(t, "STUB_GW_STATUS="+healthyGateway(func(m map[string]any) { m["streams"] = map[string]any{"dev-cell-1": 1, "dev-cell-2": 0} }),
		"STUB_MGMT_STATUS="+healthyPlane(func(m map[string]any) {
			m["cells"] = []any{planeCell("dev-cell-1", nil), planeCell("dev-cell-2", map[string]any{"bound": false})}
		}))
	dev = byName["dev-cp"]
	if cells := strs(field(dev, "island", "cells")); len(cells) != 1 || cells[0] != "dev-cell-2" {
		t.Errorf("island.cells = %v, want [dev-cell-2]", cells)
	}
	if strings.Contains(problemsOf(dev), "island") {
		t.Errorf("an island adds a problem: %s", problemsOf(dev))
	}

	// The marker of the slow tier shows in svidTTL, and a changed lifetime shows in live.
	byName, _, _, _ = runStatus(t, "STUB_SERVER_CONF=      agent_ttl = \"1h\"")
	if ttl, _ := byName["dev-cp"]["svidTTL"].(map[string]any); ttl["live"] != "1h" || ttl["file"] != "1m" {
		t.Errorf("svidTTL = %v, want live 1h and file 1m", byName["dev-cp"]["svidTTL"])
	}
}

// TestStatusM9Conditions: each M9 condition of harness:status. An entry that does not verify, a ban container that is not Ready and a
// cell that the overlay holds for more than 10 minutes while connected fail the run and sit in the problems of dev-cp. The other
// states do not.
func TestStatusM9Conditions(t *testing.T) {
	t.Parallel()
	const id = "0123456789abcdef"
	for _, tc := range []struct {
		name string
		env  func() []string
		want []string // empty: the run passes
		deny []string
	}{
		{name: "a valid entry in the inputs passes", env: func() []string {
			return []string{"STUB_LOCAL_REVOCATIONS=" + statusInputs(id+".json", statusEntry(id, "dev-cell-2", time.Now(), "good"))}
		}},
		{name: "an entry that does not verify", env: func() []string {
			return []string{"STUB_LOCAL_REVOCATIONS=" + statusInputs(id+".json", statusEntry(id, "dev-cell-2", time.Now(), "bad"))}
		}, want: []string{id + ".json", "envd refuses it", "mise run revoke -- list"}},
		{name: "an entry under another key than its id", env: func() []string {
			return []string{"STUB_LOCAL_REVOCATIONS=" + statusInputs("other.json", statusEntry(id, "dev-cell-2", time.Now(), "good"))}
		}, want: []string{"other.json", "not <id>.json"}},
		{name: "an entry that names another env", env: func() []string {
			payload, _ := json.Marshal(map[string]any{"id": id, "env": "prod", "cell": "dev-cell-2", "record": map[string]any{"epoch": 2, "counter": 5}, "issuedAt": time.Now().UTC().Format(time.RFC3339)})
			env, _ := json.Marshal(map[string]any{"payloadType": "x", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{map[string]any{"sig": "good"}}})
			return []string{"STUB_LOCAL_REVOCATIONS=" + statusInputs(id+".json", string(env))}
		}, want: []string{"names the env prod"}},
		{name: "no operator key pinned in envd", env: func() []string {
			return []string{"STUB_LOCAL_REVOCATIONS=" + statusInputs(id+".json", statusEntry(id, "dev-cell-2", time.Now(), "good")), `STUB_ENVD_PIN={"data":{"keys.pub":""}}`}
		}, want: []string{"envd pins no operator key"}},
		{name: "the ban container is not Ready", env: func() []string { return []string{"STUB_SPIRE_POD=" + statusPod(false, 0)} },
			want: []string{"agent-ban", "not Ready", "CELL=dev-cp mise run cell:restart"}},
		{name: "the ban container is absent", env: func() []string {
			return []string{`STUB_SPIRE_POD={"status":{"containerStatuses":[{"name":"spire-server","ready":true,"restartCount":0}]}}`}
		}, want: []string{"agent-ban", "not Ready"}},
		{name: "a ban container that restarted and is Ready is no status problem", env: func() []string { return []string{"STUB_SPIRE_POD=" + statusPod(true, 3)} }},
		{name: "a cell held in the overlay for 11 minutes while connected", env: func() []string {
			return []string{"STUB_CELL_RECORDS=" + statusHeld(statusEntry(id, "dev-cell-2", time.Now().Add(-11*time.Minute), "good"))}
		}, want: []string{"holds the entry " + id + " for dev-cell-2", "more than 10 minutes", "mise run mgmt -- status"}},
		{name: "a cell held in the overlay for 5 minutes", env: func() []string {
			return []string{"STUB_CELL_RECORDS=" + statusHeld(statusEntry(id, "dev-cell-2", time.Now().Add(-5*time.Minute), "good"))}
		}},
		{name: "a cell held for 11 minutes while not connected is no problem of the overlay", env: func() []string {
			return []string{"STUB_CELL_RECORDS=" + statusHeld(statusEntry(id, "dev-cell-2", time.Now().Add(-11*time.Minute), "good")),
				"STUB_MGMT_STATUS=" + healthyPlane(func(m map[string]any) { m["lastReportAt"] = timeAgo(5 * time.Minute) })}
		}, deny: []string{"holds the entry"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			byName, _, _, code := runStatus(t, tc.env()...)
			problems := problemsOf(byName["dev-cp"])
			for _, d := range tc.deny {
				if strings.Contains(problems, d) {
					t.Errorf("the problems of dev-cp %q hold %q", problems, d)
				}
			}
			if len(tc.want) == 0 {
				if len(tc.deny) == 0 && (code != 0 || byName["dev-cp"]["ok"] != true) {
					t.Errorf("exit %d, problems %q, want a pass", code, problems)
				}
				return
			}
			if code != 1 || byName["dev-cp"]["ok"] != false {
				t.Errorf("exit %d, ok %v, want exit 1 and a failed dev-cp object", code, byName["dev-cp"]["ok"])
			}
			for _, w := range tc.want {
				if !strings.Contains(problems, w) {
					t.Errorf("the problems of dev-cp %q lack %q", problems, w)
				}
			}
		})
	}
}
