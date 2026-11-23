package scripts

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// harnessUpHint is the list of commands that harness:up prints after a failed step, from the first step that its first line
// names. Steps 1 and 2 of the order (the host service and the images) are not in it. TestHarnessUpHintListsAllSteps uses it too.
var harnessUpHint = []string{
	"CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up",
	"CELL=management LINK_ONLY=mgmt-api mise run cell:link",
	"CELL=dev-cp mise run cell:up",
	"CELL=management LINK_ONLY=mgmt-api mise run cell:link",
	"mise run portal -- request --cell dev-cell-1 --cell dev-cell-2",
	"mise run portal -- wait --cell dev-cell-1 --cell dev-cell-2",
	"CELL=management mise run cell:link",
	"mise run bundle -- publish --target dev-cp --target dev-cell-1 --target dev-cell-2 --wait",
}

// hintLines returns the commands that follow the hint line of harness.sh in its standard error.
func hintLines(t *testing.T, errOut string) []string {
	t.Helper()
	_, hint, ok := strings.Cut(errOut, "Fix the cause, then run these commands in this order:\n")
	if !ok {
		t.Fatalf("no hint in\n%s", errOut)
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(hint), "\n") {
		got = append(got, strings.TrimSpace(l))
	}
	return got
}

// TestHarnessUpOrderM6: harness:up creates cells only through the portal. The host service creates management, dev-cp and rogue,
// and the images follow. Then come the cell:up of management, the first link of mgmt-api, the cell:up of dev-cp, the second link
// of mgmt-api, one portal request that names both cells, one portal wait, the full link of management, and the signed publish for both
// cells (TestHarnessUpPublishesTargets). No cell gets cell:up.
// The request runs on every call, even when both cells are requested already, because mgmtd answers alreadyRequested (ruling m6).
func TestHarnessUpOrderM6(t *testing.T) {
	t.Parallel()
	root, calls := harnessRoot(t)
	log, errOut, err := runHarness(t, root, calls, "up")
	if err != nil {
		t.Fatalf("harness up failed: %v\n%s", err, errOut)
	}
	want := []string{
		"mise run hostsvc -- up | CELL=dev-cell-1 LINK_ONLY= SKIP=",
		"mise run images | CELL=dev-cell-1 LINK_ONLY= SKIP=",
		"mise run cell:up | CELL=management LINK_ONLY= SKIP=1",
		"mise run cell:link | CELL=management LINK_ONLY=mgmt-api SKIP=",
		"mise run cell:up | CELL=dev-cp LINK_ONLY= SKIP=",
		"mise run cell:link | CELL=management LINK_ONLY=mgmt-api SKIP=",
		"mise run portal -- request --cell dev-cell-1 --cell dev-cell-2 | CELL=dev-cell-1 LINK_ONLY= SKIP=",
		"mise run portal -- wait --cell dev-cell-1 --cell dev-cell-2 | CELL=dev-cell-1 LINK_ONLY= SKIP=",
		"mise run cell:link | CELL=management LINK_ONLY= SKIP=",
		harnessUpPublish,
	}
	if got := strings.Split(strings.TrimSpace(log), "\n"); !slices.Equal(got, want) {
		t.Fatalf("calls\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, "cell:up") && strings.Contains(l, "CELL=dev-cell-") {
			t.Errorf("harness up runs %q: a cell exists only through its step", l)
		}
	}

	// A step that fails prints itself and every later step. A failed request lists the wait as well, and a failed wait lists
	// only the wait and the link, so a person who reruns the list ends with both cells valid.
	for _, tc := range []struct {
		name string
		env  string
		from int
	}{
		{"request fails", "STUB_FAIL_ARGS=run portal -- request", 4},
		{"wait fails", "STUB_FAIL_ARGS=run portal -- wait", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, calls := harnessRoot(t)
			_, errOut, err := runHarness(t, root, calls, "up", tc.env)
			if err == nil {
				t.Fatal("harness up passed with a failing portal step")
			}
			if got := hintLines(t, errOut); !slices.Equal(got, harnessUpHint[tc.from:]) {
				t.Fatalf("hint\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(harnessUpHint[tc.from:], "\n"))
			}
		})
	}
}

// m6RestoreMise stands in for mise. It logs each call with the CELL of the step. mgmt -- status prints STUB_MGMT_STATUS, except for
// the first STUB_PENDING_POLLS calls, which print STUB_MGMT_STATUS_PENDING, and except after the link, which prints STUB_BOUND_STATUS. A call that starts with STUB_FAIL_ARGS fails.
const m6RestoreMise = `#!/usr/bin/env bash
echo "mise $* | CELL=${CELL:-}" >>"$STUB_DIR/calls"
[[ -z "${STUB_FAIL_ARGS:-}" || "$*" != "$STUB_FAIL_ARGS"* ]] || exit 1
if [[ "$*" == "run mgmt -- status" ]]; then
  n=$(($(cat "$STUB_DIR/polls" 2>/dev/null || echo 0) + 1)); echo "$n" >"$STUB_DIR/polls"
  if ((n <= ${STUB_PENDING_POLLS:-0})); then printf '%s\n' "$STUB_MGMT_STATUS_PENDING"
  elif grep -q '^mise run cell:link' "$STUB_DIR/calls"; then printf '%s\n' "$STUB_BOUND_STATUS"
  else printf '%s\n' "$STUB_MGMT_STATUS"; fi
fi
exit 0
`

// TestRepairRestoresCells: gate:m6:repair restores the cells while build/gate/m6-provision exists. With the marker it does not run the
// M5 repair first, because a half-built cell counts as live and has no celld. It cancels the open step of each cell that the marker
// names, deletes that half-built cluster through cell:down, and syncs the host service. Then it waits until mgmtd holds no pending drop
// of a cell, runs one portal request for the catalog cells that are not requested, a recreate for each cancelled cell, one wait for
// every catalog cell, the link of management and the M5 repair (its stream wait), and it removes the marker last, after each cell is
// bound with no open step. With no marker it requests nothing. --check fails while the marker exists. A step of a cell that the marker
// does not name is never cancelled.
func TestRepairRestoresCells(t *testing.T) {
	t.Parallel()
	bound := func(c1, c2 string) string {
		return `{"pendingDrops":[],"cells":[{"name":"dev-cell-1",` + c1 + `},{"name":"dev-cell-2",` + c2 + `}]}`
	}
	const (
		okCell  = `"requested":true,"bound":true,"step":{"id":"s","doneAt":"2026-11-17T00:00:00Z"}`
		gone    = `"requested":false,"bound":false`
		openCel = `"requested":true,"bound":false,"step":{"id":"s"}`
	)
	bothWithdrawn, oneRequested := bound(gone, gone), bound(okCell, gone)
	allGood := bound(okCell, okCell)
	const status = "mise run mgmt -- status | CELL=dev-cp"
	const reqBoth = "mise run portal -- request --cell dev-cell-1 --cell dev-cell-2 | CELL=dev-cp"
	const wait = "mise run portal -- wait --cell dev-cell-1 --cell dev-cell-2 | CELL=dev-cp"
	const link = "mise run cell:link | CELL=management"
	const openSteps1 = `{"steps":[{"id":"a","cell":"dev-cell-1","state":"creating"}]}`
	restore := []string{"serve sync", status, reqBoth, wait, link, "repair-m5", status}
	for _, tc := range []struct {
		name    string
		marker  string
		args    []string
		env     []string
		status  string
		pending string
		code    int
		calls   []string
		kept    bool
		want    string
		// timed marks a row whose wait ends by the clock. The script counts whole seconds, so the number of polls before the bound depends on
		// where the first poll falls in a second, and the row accepts one poll or more.
		timed bool
	}{
		{name: "two withdrawn cells", marker: "dev-cell-1\ndev-cell-2\n", status: bothWithdrawn, calls: restore},
		{name: "one cell is requested already", marker: "dev-cell-1\ndev-cell-2\n", status: oneRequested, calls: []string{"serve sync", status,
			"mise run portal -- request --cell dev-cell-2 | CELL=dev-cp", wait, link, "repair-m5", status}},
		{name: "no marker", status: allGood, calls: []string{"repair-m5", "serve sync", status}},
		{name: "no marker and a live cell that is not requested", status: oneRequested, code: 1, calls: []string{"repair-m5", "serve sync", status}, want: "dev-cell-2 has a cluster and is not requested"},
		{name: "check with the marker", marker: "dev-cell-1\n", args: []string{"--check"}, status: bothWithdrawn, code: 1, kept: true,
			calls: []string{"repair-m5 --check"}, want: "build/gate/m6-provision exists"},
		{name: "check with no marker", args: []string{"--check"}, status: allGood, calls: []string{"repair-m5 --check", status}},
		{name: "a wait that fails keeps the marker", marker: "dev-cell-1\ndev-cell-2\n", status: bothWithdrawn, code: 1, kept: true,
			env: []string{"STUB_FAIL_ARGS=run portal -- wait"}, calls: restore[:4]},
		{name: "a request that fails keeps the marker", marker: "dev-cell-1\ndev-cell-2\n", status: bothWithdrawn, code: 1, kept: true,
			env: []string{"STUB_FAIL_ARGS=run portal -- request"}, calls: restore[:3]},
		{name: "a stream wait that fails keeps the marker", marker: "dev-cell-1\ndev-cell-2\n", status: bothWithdrawn, code: 1, kept: true,
			env: []string{"STUB_M5_FAIL=1"}, calls: restore[:6]},
		// An interrupt in the creating stage, before the node of the cell has an address: no cluster, an open step.
		{name: "interrupt in creating", marker: "dev-cell-1\ndev-cell-2\n", status: bound(openCel, gone), env: []string{"STUB_STEPS=" + openSteps1, "STUB_KIND=management dev-cp rogue dev-cell-2"},
			calls: []string{"mise run portal -- cancel --cell dev-cell-1 | CELL=dev-cp", "serve sync", status,
				"mise run portal -- request --cell dev-cell-2 | CELL=dev-cp", "mise run portal -- recreate --cell dev-cell-1 | CELL=dev-cp", wait, link, "repair-m5", status}},
		// An interrupt after the node has an address: the half-built cluster is live, and cell:down deletes it before anything else.
		{name: "interrupt after the node has an address", marker: "dev-cell-1\ndev-cell-2\n", status: bound(openCel, gone), env: []string{"STUB_STEPS=" + openSteps1},
			calls: []string{"mise run portal -- cancel --cell dev-cell-1 | CELL=dev-cp", "mise run cell:down | CELL=dev-cell-1", "serve sync", status,
				"mise run portal -- request --cell dev-cell-2 | CELL=dev-cp", "mise run portal -- recreate --cell dev-cell-1 | CELL=dev-cp", wait, link, "repair-m5", status}},
		{name: "a step of a cell that the marker does not name stays", marker: "dev-cell-2\n", status: bothWithdrawn, env: []string{"STUB_STEPS=" + openSteps1}, calls: restore},
		// An interrupt between the withdraw and the staged drop: the repair waits for the drop before it requests.
		{name: "a pending drop is awaited", marker: "dev-cell-1\ndev-cell-2\n", status: bothWithdrawn, pending: `{"pendingDrops":["dev-cell-1"],"cells":[]}`,
			env: []string{"STUB_PENDING_POLLS=2"}, calls: []string{"serve sync", status, status, status, reqBoth, wait, link, "repair-m5", status}},
		{name: "a pending drop that stays", marker: "dev-cell-1\ndev-cell-2\n", status: bothWithdrawn, pending: `{"pendingDrops":["dev-cell-1"],"cells":[]}`, code: 1, kept: true,
			env: []string{"STUB_PENDING_POLLS=99", "GATE_M6_DROP_WAIT=1"}, calls: []string{"serve sync", status}, want: "pending drop", timed: true},
		{name: "a cell that stays unbound keeps the marker", marker: "dev-cell-1\ndev-cell-2\n", status: bothWithdrawn, code: 1, kept: true,
			env: []string{"GATE_M6_BOUND_WAIT=1", "STUB_BOUND_STATUS=" + bothWithdrawn}, calls: append(slices.Clone(restore[:6]), status, status)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			steps := `{"steps":[]}`
			for _, e := range tc.env {
				if v, ok := strings.CutPrefix(e, "STUB_STEPS="); ok {
					steps = v
				}
			}
			for name, body := range map[string]string{
				"repair-m5": "#!/usr/bin/env bash\necho \"repair-m5 $*\" >>\"$STUB_DIR/calls\"\n[[ -z \"${STUB_M5_FAIL:-}\" ]] || exit 1\n",
				"serve":     "#!/usr/bin/env bash\necho \"serve $*\" >>\"$STUB_DIR/calls\"\ncase \"$1\" in status) echo '{\"running\":true}' ;; steps) printf '%s\\n' \"$STUB_STEPS\" ;; esac\n",
				"replicas":  "#!/usr/bin/env bash\nexit 0\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(dir, "build", "gate", "m6-provision")
			if tc.marker != "" {
				if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, []byte(tc.marker), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			pending := tc.pending
			if pending == "" {
				pending = tc.status
			}
			stubs := map[string]string{"kubectl": m6RepairKubectl, "mise": m6RestoreMise}
			for name, body := range liveStubs {
				stubs[name] = body
			}
			env := append([]string{"STUB_DIR=" + dir, "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_MGMT_STATUS=" + tc.status, "STUB_MGMT_STATUS_PENDING=" + pending,
				"STUB_STEPS=" + steps, "STUB_BOUND_STATUS=" + allGood, "GATE_M6_POLL=1", "GATE_M5_REPAIR=" + filepath.Join(dir, "repair-m5"), "HARNESS_REPLICAS=" + filepath.Join(dir, "replicas"),
				"HOSTSVC_SERVE=" + filepath.Join(dir, "serve")}, tc.env...)
			out, errOut, code := runScript(t, "gate-m6-repair.sh", stubs, env, tc.args...)
			if (code != 0) != (tc.code != 0) {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			raw, _ := os.ReadFile(filepath.Join(dir, "calls"))
			var got []string
			for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if strings.HasPrefix(l, "mise run mgmt") || strings.HasPrefix(l, "mise run portal") || strings.HasPrefix(l, "mise run cell:") ||
					strings.HasPrefix(l, "repair-m5") || strings.HasPrefix(l, "serve sync") {
					got = append(got, strings.TrimSpace(l))
				}
			}
			if tc.timed {
				got = slices.Compact(got)
			}
			if !slices.Equal(got, tc.calls) {
				t.Fatalf("calls\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.calls, "\n"))
			}
			if _, err := os.Stat(marker); (err == nil) != tc.kept && tc.marker != "" {
				t.Errorf("marker present %v, want %v", err == nil, tc.kept)
			}
			if tc.want != "" && !strings.Contains(out+errOut, tc.want) {
				t.Errorf("output %q lacks %q", out+errOut, tc.want)
			}
		})
	}
}
