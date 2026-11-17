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
// of mgmt-api, one portal request that names both cells, one portal wait, and the full link of management. No cell gets cell:up.
// The request runs on every call, even when both cells are requested already, because mgmtd answers alreadyRequested (ruling m6).
func TestHarnessUpOrderM6(t *testing.T) {
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

// m6RestoreMise stands in for mise. It logs each call with the CELL of the step. mgmt -- status prints STUB_MGMT_STATUS, and a call
// that starts with STUB_FAIL_ARGS fails.
const m6RestoreMise = `#!/usr/bin/env bash
echo "mise $* | CELL=${CELL:-}" >>"$STUB_DIR/calls"
[[ -z "${STUB_FAIL_ARGS:-}" || "$*" != "$STUB_FAIL_ARGS"* ]] || exit 1
[[ "$*" != "run mgmt -- status" ]] || printf '%s\n' "$STUB_MGMT_STATUS"
exit 0
`

// TestRepairRestoresCells: gate:m6:repair restores the cells while build/gate/m6-provision exists. After the M5 repair and the sync it
// runs one portal request for the catalog cells that are not requested, one wait for every catalog cell, the link of management and the
// M5 repair again (its stream wait), and it removes the marker last, so a failed stream wait keeps it. With no marker it requests nothing. --check fails while the marker
// exists. A wait that fails keeps the marker and runs no link.
func TestRepairRestoresCells(t *testing.T) {
	const bothWithdrawn = `{"cells":[{"name":"dev-cell-1","requested":false},{"name":"dev-cell-2","requested":false}]}`
	const oneRequested = `{"cells":[{"name":"dev-cell-1","requested":true},{"name":"dev-cell-2","requested":false}]}`
	restore := []string{
		"repair-m5",
		"serve sync",
		"mise run mgmt -- status | CELL=dev-cp",
		"mise run portal -- request --cell dev-cell-1 --cell dev-cell-2 | CELL=dev-cp",
		"mise run portal -- wait --cell dev-cell-1 --cell dev-cell-2 | CELL=dev-cp",
		"mise run cell:link | CELL=management",
		"repair-m5",
	}
	for _, tc := range []struct {
		name   string
		marker bool
		args   []string
		env    []string
		status string
		code   int
		calls  []string
		kept   bool
		want   string
	}{
		{name: "two withdrawn cells", marker: true, status: bothWithdrawn, calls: restore},
		{name: "one cell is requested already", marker: true, status: oneRequested, calls: []string{restore[0], restore[1], restore[2],
			"mise run portal -- request --cell dev-cell-2 | CELL=dev-cp", restore[4], restore[5], restore[6]}},
		{name: "no marker", status: bothWithdrawn, calls: restore[:2]},
		{name: "check with the marker", marker: true, args: []string{"--check"}, status: bothWithdrawn, code: 1, kept: true,
			calls: []string{"repair-m5 --check"}, want: "build/gate/m6-provision exists"},
		{name: "check with no marker", args: []string{"--check"}, status: bothWithdrawn, calls: []string{"repair-m5 --check"}},
		{name: "a wait that fails keeps the marker", marker: true, status: bothWithdrawn, code: 1, kept: true,
			env: []string{"STUB_FAIL_ARGS=run portal -- wait"}, calls: restore[:5]},
		{name: "a stream wait that fails keeps the marker", marker: true, status: bothWithdrawn, code: 1, kept: true,
			env: []string{"STUB_M5_FAIL_AGAIN=1"}, calls: restore},
		{name: "a request that fails keeps the marker", marker: true, status: bothWithdrawn, code: 1, kept: true,
			env: []string{"STUB_FAIL_ARGS=run portal -- request"}, calls: restore[:4]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{
				"repair-m5": "#!/usr/bin/env bash\necho \"repair-m5 $*\" >>\"$STUB_DIR/calls\"\n[[ -z \"${STUB_M5_FAIL_AGAIN:-}\" || $(grep -c '^repair-m5' \"$STUB_DIR/calls\") -lt 2 ]] || exit 1\n",
				"serve":     "#!/usr/bin/env bash\necho \"serve $*\" >>\"$STUB_DIR/calls\"\ncase \"$1\" in status) echo '{\"running\":true}' ;; steps) echo '{\"steps\":[]}' ;; esac\n",
				"replicas":  "#!/usr/bin/env bash\nexit 0\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(dir, "build", "gate", "m6-provision")
			if tc.marker {
				if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			stubs := map[string]string{"kubectl": m6RepairKubectl, "mise": m6RestoreMise}
			for name, body := range liveStubs {
				stubs[name] = body
			}
			out, errOut, code := runScript(t, "gate-m6-repair.sh", stubs,
				append([]string{"STUB_DIR=" + dir, "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_MGMT_STATUS=" + tc.status,
					"GATE_M5_REPAIR=" + filepath.Join(dir, "repair-m5"), "HARNESS_REPLICAS=" + filepath.Join(dir, "replicas"),
					"HOSTSVC_SERVE=" + filepath.Join(dir, "serve")}, tc.env...), tc.args...)
			if (code != 0) != (tc.code != 0) {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			raw, _ := os.ReadFile(filepath.Join(dir, "calls"))
			var got []string
			for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if strings.HasPrefix(l, "mise run mgmt") || strings.HasPrefix(l, "mise run portal") || strings.HasPrefix(l, "mise run cell:link") ||
					strings.HasPrefix(l, "repair-m5") || strings.HasPrefix(l, "serve sync") {
					got = append(got, strings.TrimSpace(l))
				}
			}
			if !slices.Equal(got, tc.calls) {
				t.Fatalf("calls\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.calls, "\n"))
			}
			if _, err := os.Stat(marker); (err == nil) != tc.kept && tc.marker {
				t.Errorf("marker present %v, want %v", err == nil, tc.kept)
			}
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Errorf("stdout %q lacks %q", out, tc.want)
			}
		})
	}
}
