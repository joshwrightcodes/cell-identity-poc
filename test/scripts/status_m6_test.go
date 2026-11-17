package scripts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// journalRow is one entry of the journal that the host service keeps on the Mac. heartbeat is the age of the heartbeat on the clock of the
// Mac (0 writes none), and stage is the age of the last header line of the step log (0 writes no log).
type journalRow struct {
	id, cell, state string
	heartbeat       time.Duration
	stage           time.Duration
	// ranAdmit marks that the admitting stage ran (stageRuns), and header names the stage of the log header when it differs from state.
	ranAdmit bool
	header   string
}

// writeJournal writes journal.json and the step logs of the rows into a new directory, and returns it. The heartbeat gets an offset
// of +11:00, as the host service writes a time in the zone of the Mac, and the log header gets UTC, as the actor writes it.
func writeJournal(t *testing.T, rows ...journalRow) string {
	t.Helper()
	dir := t.TempDir()
	zone := time.FixedZone("AEDT", 11*3600)
	var entries []map[string]any
	for _, r := range rows {
		e := map[string]any{"status": map[string]any{"id": r.id, "cell": r.cell, "state": r.state}}
		if r.ranAdmit {
			e["stageRuns"] = map[string]int{"admitting": 1}
		}
		hdr := r.state
		if r.header != "" {
			hdr = r.header
		}
		if r.heartbeat > 0 {
			e["heartbeatAt"] = time.Now().Add(-r.heartbeat).In(zone).Format(time.RFC3339Nano)
		}
		entries = append(entries, e)
		if r.stage > 0 {
			header := "== " + hdr + " attempt 1 CELL=" + r.cell + " at " + time.Now().Add(-r.stage).UTC().Format(time.RFC3339) + "\nsecret-looking line eyJ.eyJ.\n"
			if err := os.WriteFile(filepath.Join(dir, r.id+".log"), []byte(header), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	body, _ := json.Marshal(map[string]any{"entries": entries})
	if err := os.WriteFile(filepath.Join(dir, "journal.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// hostStatus is the status that the host service reported for a step, as mgmt -- status shows it in cells[].step.host.
func hostStatus(id, cell, state string, over map[string]any) map[string]any {
	h := map[string]any{"id": id, "cell": cell, "state": state, "stage": state, "reason": "", "detail": "", "requestId": "r1", "nodeIP": "", "attempts": 1,
		"updatedAt": timeAgo(20 * time.Second)}
	for k, v := range over {
		h[k] = v
	}
	return h
}

// stepCell is a cell of mgmt -- status with an open step that expires in expires, and the host status of that step. A nil host leaves it out.
func stepCell(name, id string, bound bool, expires time.Duration, host map[string]any) map[string]any {
	step := map[string]any{"id": id, "issuedAt": timeAgo(10 * time.Minute), "expiresAt": timeAgo(-expires)}
	if host != nil {
		step["host"] = host
	}
	return planeCell(name, map[string]any{"bound": bound, "valid": false, "step": step, "invalidSince": timeAgo(2 * time.Minute)})
}

// stepStatusAt is the content of key status.json of ConfigMap step-status, written ago ago on the clock of the node.
func stepStatusAt(ago time.Duration) string {
	return `STUB_STEP_STATUS={"at":"` + timeAgo(ago) + `","steps":[]}`
}

func problemsOf(m map[string]any) string { return strings.Join(strs(m["problems"]), "\n") }

// TestStatusProvisioning checks each condition of provisioning: the exit status is 1, the problem sits in the object of the cluster that it
// names, and it ends with the command to run. A condition that is not met leaves the exit status at 0.
func TestStatusProvisioning(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	cells := func(a, b map[string]any) string {
		return healthyPlane(func(m map[string]any) { m["cells"] = []any{a, b} })
	}
	healthyCell := func(n string) map[string]any { return planeCell(n, nil) }
	openAdmitting := func() map[string]any {
		return stepCell("dev-cell-2", id, true, time.Hour, hostStatus(id, "dev-cell-2", "admitting", nil))
	}
	withHost := func(over map[string]any) string {
		return cells(healthyCell("dev-cell-1"), stepCell("dev-cell-2", id, true, time.Hour, hostStatus(id, "dev-cell-2", "admitting", over)))
	}
	const verifyCP = "FAIL  The SPIRE server, relay and gateway admit lists, and the --cell-node arguments, equal the node addresses of the live cells\n"
	type provCase struct {
		name    string
		rows    []journalRow
		env     []string
		cluster string   // the object that carries the problem; empty when the run must pass
		want    []string // substrings of the problems
		deny    []string // substrings that no problem holds
	}
	// The table is built again for each case, because its times are ages from the moment of the build, and a slow run must not age them.
	build := func() []provCase {
		return []provCase{
			{name: "invalid for more than 5 minutes with no open step", cluster: "dev-cell-1",
				env:  []string{"STUB_MGMT_STATUS=" + cells(planeCell("dev-cell-1", map[string]any{"valid": false, "validReason": "status_stale", "invalidSince": timeAgo(6 * time.Minute)}), healthyCell("dev-cell-2"))},
				want: []string{"dev-cell-1 has been invalid since", "status_stale", "no step is open", "Run: CELL=dev-cell-1 mise run cell:verify"}},
			{name: "invalid for less than 5 minutes is a wait",
				env: []string{"STUB_MGMT_STATUS=" + cells(planeCell("dev-cell-1", map[string]any{"valid": false, "invalidSince": timeAgo(4 * time.Minute)}), healthyCell("dev-cell-2"))}},
			{name: "invalid for a long time while another cell is admitted is a wait",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "admitting", heartbeat: 10 * time.Second, stage: 7 * time.Minute}},
				env: []string{"STUB_MGMT_STATUS=" + cells(planeCell("dev-cell-1", map[string]any{"valid": false, "invalidSince": timeAgo(20 * time.Minute)}), openAdmitting()),
					stepStatusAt(20 * time.Second)}},
			{name: "invalid for a long time while the journal alone shows an admit stage is a wait",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "admitting", heartbeat: 10 * time.Second, stage: 7 * time.Minute}},
				env:  []string{"STUB_MGMT_STATUS=" + cells(planeCell("dev-cell-1", map[string]any{"valid": false, "invalidSince": timeAgo(20 * time.Minute)}), healthyCell("dev-cell-2"))}},
			{name: "invalid for a long time, and an admit stage ended 2 minutes ago, is a wait",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "done", ranAdmit: true, header: "bootstrapping", stage: 2 * time.Minute}},
				env:  []string{"STUB_MGMT_STATUS=" + cells(planeCell("dev-cell-1", map[string]any{"valid": false, "invalidSince": timeAgo(20 * time.Minute)}), healthyCell("dev-cell-2"))}},
			{name: "invalid for a long time, and an admit stage ended 8 minutes ago", cluster: "dev-cell-1",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "done", ranAdmit: true, header: "bootstrapping", stage: 8 * time.Minute}},
				env:  []string{"STUB_MGMT_STATUS=" + cells(planeCell("dev-cell-1", map[string]any{"valid": false, "invalidSince": timeAgo(20 * time.Minute)}), healthyCell("dev-cell-2"))},
				want: []string{"dev-cell-1 has been invalid since"}},
			{name: "a failed step that the controller sends again soon is a wait", cluster: "dev-cell-2",
				env:  []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"state": "failed", "reason": "stage_failed", "retryAt": timeAgo(-4 * time.Minute)}), stepStatusAt(20 * time.Second)},
				want: []string{"is failed (stage_failed)", "sends it again at", "Wait until then"}, deny: []string{"portal -- retry"}},
			{name: "a failed step that stays failed past its retry time", cluster: "dev-cell-2",
				env:  []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"state": "failed", "reason": "stage_failed", "retryAt": timeAgo(2 * time.Minute)}), stepStatusAt(20 * time.Second)},
				want: []string{"is failed (stage_failed)", "Run: mise run portal -- retry --cell dev-cell-2"}},
			{name: "an open step that has expired", cluster: "dev-cell-2",
				env: []string{"STUB_MGMT_STATUS=" + cells(healthyCell("dev-cell-1"), stepCell("dev-cell-2", id, true, -time.Minute, hostStatus(id, "dev-cell-2", "queued", nil))),
					stepStatusAt(20 * time.Second)},
				want: []string{"open step " + id + " of dev-cell-2 expired at", "Run: mise run portal -- retry --cell dev-cell-2"}},
			{name: "a failed step", cluster: "dev-cell-2",
				env:  []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"state": "failed", "reason": "stage_failed"}), stepStatusAt(20 * time.Second)},
				want: []string{"is failed (stage_failed)", "Run: mise run portal -- retry --cell dev-cell-2"}},
			{name: "a failed_final step", cluster: "dev-cell-2",
				env:  []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"state": "failed_final"}), stepStatusAt(20 * time.Second)},
				want: []string{"is failed_final", "Run: mise run portal -- retry --cell dev-cell-2"}},
			{name: "a refused step", cluster: "dev-cell-2",
				env:  []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"state": "refused", "reason": "step_invalid"}), stepStatusAt(20 * time.Second)},
				want: []string{"is refused (step_invalid)", "Run: mise run portal -- retry --cell dev-cell-2"}},
			{name: "the host status of an older step never counts", cluster: "",
				env: []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"id": "ffffffffffffffffffffffffffffffff", "state": "failed_final"}), stepStatusAt(20 * time.Second)}},
			{name: "a heartbeat older than 2 minutes", cluster: "dev-cell-2",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "creating", heartbeat: 3 * time.Minute, stage: 4 * time.Minute}},
				env:  []string{"STUB_MGMT_STATUS=" + openStepPlane(id), stepStatusAt(20 * time.Second)},
				want: []string{"step " + id + " of dev-cell-2 is in the stage creating", "heartbeat is 18", "Run: mise run hostsvc:serve -- restart --force"}},
			{name: "a stage past its timeout plus 5 minutes", cluster: "dev-cell-2",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "bootstrapping", heartbeat: 10 * time.Second, stage: 51 * time.Minute}},
				env:  []string{"STUB_MGMT_STATUS=" + openStepPlane(id), stepStatusAt(20 * time.Second)},
				want: []string{"has run the stage bootstrapping for 51 minutes", "timeout of 45 minutes plus 5", "Run: mise run hostsvc:serve -- restart --force"}},
			{name: "a live heartbeat over a 5 minute stage passes",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "admitting", heartbeat: 20 * time.Second, stage: 6 * time.Minute}},
				env:  []string{"STUB_MGMT_STATUS=" + openStepPlane(id), stepStatusAt(20 * time.Second)}},
			{name: "a stage just under its limit passes",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "admitting", heartbeat: 20 * time.Second, stage: 34 * time.Minute}},
				env:  []string{"STUB_MGMT_STATUS=" + openStepPlane(id), stepStatusAt(20 * time.Second)}},
			{name: "a queued entry has no heartbeat to check",
				rows: []journalRow{{id: id, cell: "dev-cell-2", state: "queued", heartbeat: 3 * time.Hour}},
				env:  []string{"STUB_MGMT_STATUS=" + openStepPlane(id), stepStatusAt(20 * time.Second)}},
			{name: "step-status older than 90 seconds while a step is open", cluster: "dev-cp",
				env:  []string{"STUB_MGMT_STATUS=" + openStepPlane(id), stepStatusAt(2 * time.Minute)},
				want: []string{"step-status of the cell controller is from", "more than 90 seconds old", "Run: CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:restart"}},
			{name: "no step-status while a step is open", cluster: "dev-cp",
				env:  []string{"STUB_MGMT_STATUS=" + openStepPlane(id)},
				want: []string{"step-status of the cell controller is absent", "Run: CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:restart"}},
			{name: "a host error that started more than 2 minutes ago, untrusted", cluster: "dev-cell-2",
				env:  []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"lastHostError": map[string]any{"reason": "hostsvc_untrusted", "at": timeAgo(3 * time.Minute)}}), stepStatusAt(20 * time.Second)},
				want: []string{"has not trusted the host service since", "Run: mise run hostsvc:serve -- restart"}},
			{name: "a host error that started more than 2 minutes ago, unavailable", cluster: "dev-cell-2",
				env:  []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"lastHostError": map[string]any{"reason": "hostsvc_unavailable", "at": timeAgo(3 * time.Minute)}}), stepStatusAt(20 * time.Second)},
				want: []string{"has not reached the host service since", "hostsvc_unavailable", "Run: mise run hostsvc:serve -- status"}},
			{name: "a host error from the last minute is a wait",
				env: []string{"STUB_MGMT_STATUS=" + withHost(map[string]any{"lastHostError": map[string]any{"reason": "hostsvc_unavailable", "at": timeAgo(time.Minute)}}), stepStatusAt(20 * time.Second)}},
			{name: "a requested cell with no cluster and no open step", cluster: "dev-cell-2", env: []string{"STUB_KIND=management dev-cp dev-cell-1 rogue"},
				want: []string{"dev-cell-2 is requested and has no cluster", "Run: mise run portal -- recreate --cell dev-cell-2"}},
			{name: "a requested cell with no cluster and an open step is a wait",
				env: []string{"STUB_KIND=management dev-cp dev-cell-1 rogue", "STUB_MGMT_STATUS=" + cells(healthyCell("dev-cell-1"), stepCell("dev-cell-2", id, false, time.Hour, hostStatus(id, "dev-cell-2", "creating", nil))),
					stepStatusAt(20 * time.Second)}},
			{name: "a live cell that is not requested", cluster: "dev-cell-2",
				env:  []string{"STUB_MGMT_STATUS=" + cells(healthyCell("dev-cell-1"), planeCell("dev-cell-2", map[string]any{"requested": false}))},
				want: []string{"dev-cell-2 has a cluster and is not requested", "Run: mise run portal -- request --cell dev-cell-2, or run: CELL=dev-cell-2 mise run cell:down"}},
			{name: "a cell that is neither requested nor live", cluster: "dev-cell-2",
				env:  []string{"STUB_KIND=management dev-cp dev-cell-1 rogue", "STUB_MGMT_STATUS=" + cells(healthyCell("dev-cell-1"), planeCell("dev-cell-2", map[string]any{"requested": false, "bound": false}))},
				want: []string{"dev-cell-2 is neither requested nor live", "Run: mise run portal -- request --cell dev-cell-2 --wait"}},
			{name: "the admit lists differ", cluster: "dev-cp", env: []string{"STUB_VERIFY_dev_cp=" + verifyCP},
				want: []string{"admit lists of dev-cp differ", "Run: CELL=dev-cp mise run cell:up"}},
			{name: "the host service has no dev-root.crt", cluster: "management",
				env:  []string{`STUB_SERVE_PATCH={"dev_root_sha256":""}`},
				want: []string{"no dev-root.crt", "Run: mise run hostsvc:serve -- sync"}},
			{name: "the keys of the host service differ", cluster: "management",
				env:  []string{`STUB_SERVE_PATCH={"keys":["ab"]}`},
				want: []string{"host service trusts the keys", "Run: mise run hostsvc:serve -- sync"}},
			{name: "the host service holds the staged key too",
				env: []string{"STUB_MGMT_STATUS=" + healthyPlane(func(m map[string]any) { m["stagedKey"] = "cd" }),
					`STUB_SERVE_PATCH={"keys":["cd","` + stubPubSHA + `"]}`}},
			{name: "the spec revision of the host service is behind for more than 2 minutes", cluster: "management",
				env: []string{"STUB_MGMT_STATUS=" + healthyPlane(func(m map[string]any) { m["hostSpecPushedAt"] = timeAgo(5 * time.Minute) }),
					`STUB_SERVE_PATCH={"spec_revision":{"epoch":1,"counter":3}}`},
				want: []string{"knows the spec revision", "for more than 2 minutes", "Run: mise run hostsvc:serve -- sync, or run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"}},
			{name: "a spec revision that was pushed a moment ago is a wait",
				env: []string{`STUB_SERVE_PATCH={"spec_revision":{"epoch":1,"counter":3}}`}},
		}
	}
	for i := range build() {
		t.Run(build()[i].name, func(t *testing.T) {
			tc := build()[i]
			dir := writeJournal(t, tc.rows...)
			byName, lines, stderr, code := runStatus(t, append([]string{"HOSTSVC_STEPS_DIR=" + dir}, tc.env...)...)
			if tc.cluster == "" {
				if code != 0 {
					t.Fatalf("exit %d, want 0: %v\n%s", code, lines, stderr)
				}
				return
			}
			got := problemsOf(byName[tc.cluster])
			if code != 1 || byName[tc.cluster]["ok"] != false {
				t.Fatalf("exit %d, ok %v, problems %q; want exit 1 and ok false", code, byName[tc.cluster]["ok"], got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("problems of %s %q lack %q", tc.cluster, got, w)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(got, d) {
					t.Errorf("problems of %s %q hold %q", tc.cluster, got, d)
				}
			}
			if strings.ContainsAny(got, "<>") {
				t.Errorf("problems %q hold a placeholder, and each command must work as printed", got)
			}
			if strings.Contains(stderr+got, "secret-looking") || strings.Contains(stderr+got, "eyJ.") {
				t.Errorf("the output holds a line of a step log")
			}
			for c, m := range byName {
				if c != tc.cluster && m["ok"] != true && c != "management" {
					t.Errorf("the object of %s is not ok, and only %s has a bad value: %v", c, tc.cluster, m["problems"])
				}
			}
		})
	}
}

// openStepPlane is a plane with one open step of dev-cell-2 that has not failed and expires in an hour.
func openStepPlane(id string) string {
	return healthyPlane(func(m map[string]any) {
		m["cells"] = []any{planeCell("dev-cell-1", nil), stepCell("dev-cell-2", id, true, time.Hour, hostStatus(id, "dev-cell-2", "admitting", nil))}
	})
}

// TestStatusAbsentCell checks the object of a cell with no cluster: absent, and no read of a cluster that does not exist. It holds only the
// problems of provisioning, and the M5 problem "is not bound" never names a cell that has no cluster.
func TestStatusAbsentCell(t *testing.T) {
	dir := writeJournal(t)
	// The sources report what is true for a cell with no cluster: no agent, no sample, no Kiali cluster and no tunnel.
	absentSources := []string{"HOSTSVC_STEPS_DIR=" + dir, "STUB_KIND=management dev-cp dev-cell-1 rogue",
		"STUB_PRINCIPAL=" + `{"client":"dev-dev-cell-1","msg":"An agent connected to the subscription stream"}`,
		"STUB_SAMPLES=" + `{"data":{"result":[{"metric":{"k8s_cluster_name":"management"},"value":[0,"5"]},{"metric":{"k8s_cluster_name":"dev-cp"},"value":[0,"4"]},{"metric":{"k8s_cluster_name":"dev-cell-1"},"value":[0,"6"]}]}}`,
		"STUB_KIALI_CONF=" + `{"clusters":{"dev-cell-1":{"accessible":true},"management":{"accessible":true}}}`,
		"STUB_HUB=" + `{"cells":{"dev-cell-1":{"up":true}}}`}
	withPlane := func(plane string, more ...string) []string {
		return append(append([]string{"STUB_MGMT_STATUS=" + plane}, absentSources...), more...)
	}
	byName, lines, stderr, code := runStatus(t, withPlane(healthyPlane(func(m map[string]any) {
		m["cells"] = []any{planeCell("dev-cell-1", nil), planeCell("dev-cell-2", map[string]any{"bound": false, "valid": false})}
	}))...)
	if len(lines) != 4 || code != 1 {
		t.Fatalf("exit %d with %d objects, want exit 1 and 4 objects\n%s", code, len(lines), stderr)
	}
	absent := byName["dev-cell-2"]
	if got := keys(absent); strings.Join(got, ",") != "absent,cluster,ok,problems" || absent["absent"] != true || absent["ok"] != false {
		t.Errorf("object of the absent cell %v, want only absent, cluster, ok and problems, with absent true", absent)
	}
	if got := problemsOf(absent); got != "the cell dev-cell-2 is requested and has no cluster, and no step is open. Run: mise run portal -- recreate --cell dev-cell-2" {
		t.Errorf("problems of the absent cell %q", got)
	}
	if got := problemsOf(byName["management"]); byName["management"]["ok"] != true {
		t.Errorf("management problems %q for an absent cell, want none: no agent, sample or tunnel exists for it, and cell:up refuses it", got)
	}
	// A cell that is absent and has no problem keeps its object, and the whole status exits 0.
	byName, _, _, code = runStatus(t, withPlane(healthyPlane(func(m map[string]any) {
		m["cells"] = []any{planeCell("dev-cell-1", nil), stepCell("dev-cell-2", "0123456789abcdef0123456789abcdef", false, time.Hour, nil)}
	}), stepStatusAt(20*time.Second))...)
	if code != 0 || byName["dev-cell-2"]["absent"] != true || byName["dev-cell-2"]["ok"] != true {
		t.Errorf("exit %d and object %v, want an absent cell with ok true while its step creates it, and exit 0", code, byName["dev-cell-2"])
	}
	// A live cell that is not bound keeps the M5 hint.
	byName, _, _, _ = runStatus(t, "HOSTSVC_STEPS_DIR="+dir, "STUB_MGMT_STATUS="+healthyPlane(func(m map[string]any) {
		m["cells"] = []any{planeCell("dev-cell-1", nil), planeCell("dev-cell-2", map[string]any{"bound": false, "lastCheck": ""})}
	}))
	if got := problemsOf(byName["management"]); !strings.Contains(got, "dev-cell-2 is not bound. Run: CELL=dev-cell-2 mise run cell:up") {
		t.Errorf("management problems %q lack the M5 hint for a live cell", got)
	}
	// While a stage of that cell runs, the hint names the stage and does not compete for the cluster lock.
	id := "0123456789abcdef0123456789abcdef"
	byName, _, _, _ = runStatus(t, "HOSTSVC_STEPS_DIR="+writeJournal(t, journalRow{id: id, cell: "dev-cell-2", state: "bootstrapping", heartbeat: 10 * time.Second, stage: time.Minute}),
		stepStatusAt(20*time.Second), "STUB_MGMT_STATUS="+healthyPlane(func(m map[string]any) {
			m["cells"] = []any{planeCell("dev-cell-1", nil), stepCell("dev-cell-2", id, false, time.Hour, hostStatus(id, "dev-cell-2", "bootstrapping", nil))}
		}))
	got := problemsOf(byName["management"])
	if !strings.Contains(got, "dev-cell-2 is not bound while its stage bootstrapping runs. Wait for the stage") || strings.Contains(got, "cell:up") {
		t.Errorf("management problems %q, want the stage name and no cell:up", got)
	}
}

// TestStatusMarkerNamesTheRepair: a cell that is neither requested nor live gives gate:m6:repair while the provision marker exists.
func TestStatusMarkerNamesTheRepair(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "gate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "gate", "m6-provision"), []byte("dev-cell-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	byName, _, _, code := runStatus(t, "POC_BUILD_ROOT="+root, "HOSTSVC_STEPS_DIR="+writeJournal(t), "STUB_KIND=management dev-cp dev-cell-1 rogue",
		"STUB_MGMT_STATUS="+healthyPlane(func(m map[string]any) {
			m["cells"] = []any{planeCell("dev-cell-1", nil), planeCell("dev-cell-2", map[string]any{"requested": false, "bound": false})}
		}))
	if got := problemsOf(byName["dev-cell-2"]); code != 1 || !strings.Contains(got, "neither requested nor live. Run: mise run gate:m6:repair") {
		t.Errorf("exit %d and problems %q, want the repair command", code, got)
	}
}

// TestStatusUsesTwoClocks: the journal holds times of the Mac, and mgmtd holds times of the VM. With a node clock 10 minutes ahead of the
// Mac, a journal heartbeat that is 30 seconds old on the Mac passes, and a cell status that is 20 seconds old on the node passes. With a node
// clock 10 minutes behind, a stage that began 40 minutes ago on the Mac is over its 35 minute limit, and the script says so.
func TestStatusUsesTwoClocks(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	plane := func(skew time.Duration) string {
		// A time that is d old on the node is d - skew old on the Mac, where skew is how far the node runs ahead.
		vm := func(d time.Duration) string { return timeAgo(d - skew) }
		return healthyPlane(func(m map[string]any) {
			m["lastReportAt"] = vm(10 * time.Second)
			m["hostSpecPushedAt"] = vm(30 * time.Second)
			m["cells"] = []any{planeCell("dev-cell-1", map[string]any{"lastStatusAt": vm(20 * time.Second)}),
				planeCell("dev-cell-2", map[string]any{"lastStatusAt": vm(20 * time.Second), "bound": true, "valid": false, "invalidSince": vm(time.Minute),
					"step": map[string]any{"id": id, "issuedAt": vm(5 * time.Minute), "expiresAt": vm(-time.Hour), "host": hostStatus(id, "dev-cell-2", "admitting", nil)}})}
		})
	}
	gw := func(skew time.Duration) string {
		return healthyGateway(func(m map[string]any) { m["syncedAt"] = timeAgo(10*time.Second - skew) })
	}
	ahead := 10 * time.Minute
	byName, lines, stderr, code := runStatus(t, "STUB_CLOCK_SKEW=-600", "STUB_STEP_STATUS="+`{"at":"`+timeAgo(20*time.Second-ahead)+`","steps":[]}`,
		"HOSTSVC_STEPS_DIR="+writeJournal(t, journalRow{id: id, cell: "dev-cell-2", state: "admitting", heartbeat: 30 * time.Second, stage: 6 * time.Minute}),
		"STUB_MGMT_STATUS="+plane(ahead), "STUB_GW_STATUS="+gw(ahead))
	if code != 0 {
		t.Fatalf("exit %d with a node clock 10 minutes ahead, want 0: %v\n%s", code, lines, stderr)
	}
	_ = byName
	behind := -10 * time.Minute
	byName, _, _, code = runStatus(t, "STUB_CLOCK_SKEW=600", "STUB_STEP_STATUS="+`{"at":"`+timeAgo(20*time.Second-behind)+`","steps":[]}`,
		"HOSTSVC_STEPS_DIR="+writeJournal(t, journalRow{id: id, cell: "dev-cell-2", state: "admitting", heartbeat: 30 * time.Second, stage: 40 * time.Minute}),
		"STUB_MGMT_STATUS="+plane(behind), "STUB_GW_STATUS="+gw(behind))
	if got := problemsOf(byName["dev-cell-2"]); code != 1 || !strings.Contains(got, "has run the stage admitting for 40 minutes") {
		t.Errorf("exit %d and problems %q with a node clock 10 minutes behind, want the stage that is over its limit on the clock of the Mac", code, got)
	}
}

// TestStatusJournalCorrupt: a journal that does not parse gives one problem with the reset command, and the other objects stay readable.
func TestStatusJournalCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "journal.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	byName, lines, _, code := runStatus(t, "HOSTSVC_STEPS_DIR="+dir)
	if got := problemsOf(byName["management"]); code != 1 || len(lines) != 4 || !strings.Contains(got, "journal of the host service does not parse. Run: mise run hostsvc:serve -- steps --reset") {
		t.Errorf("exit %d, %d objects and problems %q, want the reset command", code, len(lines), got)
	}
}

// TestStatusKindDown: with no answer from kind, the script prints one JSON error line and exits 1, because the live cells are unknown.
func TestStatusKindDown(t *testing.T) {
	out, _, code := runScript(t, "status.sh", map[string]string{"kubectl": statusKubectlStub, "mise": statusMiseStub, "docker": nodeClockDocker, "kind": stubKind}, []string{"STUB_KIND_FAIL=1"})
	lines := jsonLines(t, out)
	if code != 1 || len(lines) != 1 || lines[0]["level"] != "ERROR" || !strings.Contains(lines[0]["error"].(string), "which cells are live") {
		t.Errorf("exit %d and output %q, want one JSON error line", code, out)
	}
}
