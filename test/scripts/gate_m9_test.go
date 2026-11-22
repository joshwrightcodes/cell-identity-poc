package scripts

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// m9Tests are the tests of gate:m9 in the order of "The slow tier".
var m9Tests = []string{"TestM9LocalRevocationDuringIsland", "TestM9ConnectedRevocation", "TestM9OneWayPartitions",
	"TestM9KeyRotatedDuringEnvironmentIsland", "TestM9StoreLostDuringCellIsland", "TestM9IslandsHold"}

// m9SvidStub stands in for scripts/svid-ttl.sh in the gate tests. set writes the marker and the live lifetime, restore removes the marker and
// sets the live lifetime back to 1m. STUB_SET_SECONDS and STUB_RESTORE_SECONDS add to the clock. stub/svid-<command>-fail makes a command fail.
const m9SvidStub = `#!/usr/bin/env bash
d="$STUB_DIR"
echo "svid-ttl $*" >>"$d/calls"
m="$POC_BUILD_ROOT/gate/m9-svid-ttl"
[[ ! -e "$d/svid-$1-fail" ]] || { echo "error: svid-ttl $1 failed" >&2; exit 1; }
case "$1" in
  set) mkdir -p "$(dirname "$m")"; echo "$2" >"$m"; echo "$2" >"$d/live-ttl"; add="${STUB_SET_SECONDS:-0}" ;;
  restore) rm -f "$m"; echo 1m >"$d/live-ttl"; add="${STUB_RESTORE_SECONDS:-0}" ;;
  *) exit 2 ;;
esac
echo $(($(cat "$d/now") + add)) >"$d/now"
`

// m9ScanStub stands in for scripts/gate-token-scan.sh. stub/scan-hit makes it find a token.
const m9ScanStub = `#!/usr/bin/env bash
echo "scan $*" >>"$STUB_DIR/calls"
[[ ! -e "$STUB_DIR/scan-hit" ]] || { echo "a token is in the log: dev-cp ns/pod container line 7"; exit 1; }
`

// newGateM9Rig is an m9Rig with stubs for the scripts that gate.sh m9 calls: the repair checks of M6 to M9, svid-ttl.sh and the token scan.
// stub/<m>-check-fail makes the check of milestone <m> fail.
func newGateM9Rig(t *testing.T) *m9Rig {
	t.Helper()
	r := newM9Rig(t)
	for _, m := range []string{"m6", "m7", "m8", "m9"} {
		r.write("scripts/gate-"+m+"-repair.sh", fmt.Sprintf("#!/usr/bin/env bash\necho \"%[1]s repair $*\" >>\"$STUB_DIR/calls\"\n"+
			"[[ ! -e \"$STUB_DIR/%[1]s-check-fail\" ]] || { echo 'a trace of %[1]s. Run: mise run gate:%[1]s:repair'; exit 1; }\n", m))
	}
	r.write("scripts/svid-ttl.sh", m9SvidStub)
	r.write("scripts/gate-token-scan.sh", m9ScanStub)
	return r
}

// setVersion replaces one setting of harness/versions.env in the root.
func (r *m9Rig) setVersion(name, value string) {
	r.t.Helper()
	re := regexp.MustCompile(`(?m)^` + name + `=.*$`)
	body := r.read("harness/versions.env")
	if !re.MatchString(body) {
		r.t.Fatalf("harness/versions.env has no %s", name)
	}
	r.write("harness/versions.env", re.ReplaceAllString(body, name+"="+value))
}

// goRuns returns the go test calls with -json of the call log, in order.
func goRuns(calls string) []string {
	var out []string
	for _, l := range strings.Split(calls, "\n") {
		if strings.HasPrefix(l, "go test") && strings.Contains(l, " -json ") {
			out = append(out, l)
		}
	}
	return out
}

// TestFastGateRefusesSlowLifetime: every gate other than m9 dies while build/gate/m9-svid-ttl exists, or while the live agent_ttl of dev-cp
// differs from cells/dev-cp.env, and names mise run gate:m9:repair. It stops before the tests. A gate with the lifetime of the file runs.
func TestFastGateRefusesSlowLifetime(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, milestone, marker, live, want string
	}{
		{name: "m2 with the marker", milestone: "m2", marker: "1h", live: "1h", want: "build/gate/m9-svid-ttl"},
		{name: "m8 with the marker and the file lifetime live", milestone: "m8", marker: "1h", live: "1m", want: "build/gate/m9-svid-ttl"},
		{name: "m8 with agent_ttl 1h and no marker", milestone: "m8", live: "1h", want: "agent_ttl '1h'"},
		{name: "m8 after a restore that did not settle", milestone: "m8", marker: "restoring", live: "1m", want: "build/gate/m9-svid-ttl.restoring"},
		{name: "m1 with agent_ttl 1h and no marker", milestone: "m1", live: "1h", want: "agent_ttl '1h'"},
		{name: "m1 with the file lifetime", milestone: "m1", live: "1m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			switch tc.marker {
			case "":
			case "restoring":
				r.write("build/gate/m9-svid-ttl.restoring", "")
			default:
				r.marker(tc.marker)
			}
			r.state("live-ttl", tc.live+"\n")
			out, errOut, code := r.run("gate.sh", nil, tc.milestone)
			runs := goRuns(r.calls())
			if tc.want == "" {
				if code != 0 || len(runs) != 1 {
					t.Fatalf("exit %d, %d test runs, stdout %s\nstderr %s; want one passing run", code, len(runs), out, errOut)
				}
				return
			}
			if code == 0 || len(runs) != 0 || !strings.Contains(errOut, tc.want) || !strings.Contains(errOut, "mise run gate:m9:repair") {
				t.Fatalf("exit %d, %d test runs, stderr %q; want a stop before the tests that says %q and names mise run gate:m9:repair", code, len(runs), errOut, tc.want)
			}
		})
	}
}

// TestGateM9Order: gate.sh m9 runs Phase 0 (the repair checks of M6 to M9, the image checks and svid-ttl.sh set at GATE_M9_SVID_TTL), then each
// test of the list in its own go test invocation with -failfast, its own events file build/gate-m9-<test>.json and a token scan from its own
// start, then Phase 7 (svid-ttl.sh restore and harness:status). It stops at the first failure, and Phase 7 still runs, also after an
// interrupt or a failed switch. A failed check stops the run before the switch, with no Phase 7.
func TestGateM9Order(t *testing.T) {
	t.Parallel()
	t.Run("a passing run", func(t *testing.T) {
		t.Parallel()
		r := newGateM9Rig(t)
		out, errOut, code := r.run("gate.sh", []string{"STUB_TEST_SECONDS=600"}, "m9")
		if code != 0 {
			t.Fatalf("exit %d\nstdout %s\nstderr %s\ncalls %s", code, out, errOut, r.calls())
		}
		calls := r.calls()
		order := []int{callAt(calls, "m6 repair --check"), callAt(calls, "m7 repair --check"), callAt(calls, "m8 repair --check"), callAt(calls, "m9 repair --check"),
			callAt(calls, "svid-ttl set 1h")}
		for _, name := range m9Tests {
			order = append(order, callAt(calls, "go test", "-run ^"+name+"$"))
		}
		order = append(order, callAt(calls, "svid-ttl restore"), callAt(calls, "mise run harness:status"))
		for i := range order {
			if order[i] < 0 || (i > 0 && order[i] < order[i-1]) {
				t.Fatalf("step %d is out of order or missing (%v):\n%s", i, order, calls)
			}
		}
		if scan := callAt(calls, "scan "); scan < order[4] || scan > order[5] {
			t.Errorf("no token scan of Phase 0 between the switch and the first test:\n%s", calls)
		}
		runs := goRuns(calls)
		if len(runs) != len(m9Tests) {
			t.Fatalf("%d test runs, want %d:\n%s", len(runs), len(m9Tests), calls)
		}
		lines := strings.Split(calls, "\n")
		starts := map[string]bool{}
		for i, name := range m9Tests {
			if !strings.Contains(runs[i], " -failfast ") || !strings.Contains(runs[i], " -timeout 270m ") {
				t.Errorf("run %d %q lacks -failfast or -timeout 270m", i, runs[i])
			}
			if !strings.Contains(r.read("build/gate-m9-"+name+".json"), `"Test":"`+name+`"`) {
				t.Errorf("build/gate-m9-%s.json lacks the events of the test", name)
			}
			if !strings.Contains(out, "=== RUN   "+name) {
				t.Errorf("standard output lacks the text of %s", name)
			}
			at := callAt(calls, "go test", "-run ^"+name+"$")
			if at+1 >= len(lines) || !strings.HasPrefix(lines[at+1], "scan ") {
				t.Errorf("no token scan right after the run of %s:\n%s", name, calls)
				continue
			}
			starts[lines[at+1]] = true
		}
		if len(starts) != len(m9Tests) {
			t.Errorf("the scans share a start time, want one start for each invocation: %v", starts)
		}
		if strings.Contains(out+errOut, "not a slow-tier record") {
			t.Errorf("a full run at the lifetime of versions.env is a record, and the output says otherwise:\n%s", errOut)
		}
	})
	for _, tc := range []struct {
		name  string
		env   []string
		files []string
		runs  int
		scans int
	}{
		{name: "a failure stops the run", env: []string{"STUB_FAIL_TESTS=TestM9OneWayPartitions"}, runs: 3, scans: 4},
		{name: "a token stops the run", files: []string{"scan-hit"}, runs: 0, scans: 1},
		{name: "an interrupt stops the run", env: []string{"STUB_INTERRUPT_TESTS=TestM9ConnectedRevocation"}, runs: 2, scans: 3},
		{name: "a failed switch", files: []string{"svid-set-fail"}, runs: 0, scans: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			for _, f := range tc.files {
				r.state(f, "")
			}
			r.write("build/gate-m9-TestM9IslandsHold.json", `{"Action":"pass","Test":"TestM9IslandsHold","Elapsed":1}`+"\n")
			out, errOut, code := r.run("gate.sh", tc.env, "m9")
			calls := r.calls()
			if code != 1 {
				t.Fatalf("exit %d, want 1 after Phase 7\nstdout %s\nstderr %s", code, out, errOut)
			}
			if r.exists("build/gate-m9-TestM9IslandsHold.json") {
				t.Error("the events file of an earlier run is still there, and it reads as a result of this run")
			}
			if n := len(goRuns(calls)); n != tc.runs {
				t.Errorf("%d test runs, want %d:\n%s", n, tc.runs, calls)
			}
			if n := strings.Count(calls, "\nscan "); n != tc.scans {
				t.Errorf("%d token scans, want %d (Phase 7 scans an interrupted run):\n%s", n, tc.scans, calls)
			}
			restore, status := callAt(calls, "svid-ttl restore"), callAt(calls, "mise run harness:status")
			if restore < 0 || status < restore {
				t.Errorf("Phase 7 did not run the restore and then harness:status:\n%s", calls)
			}
			if r.exists("build/gate/m9-svid-ttl") {
				t.Error("the marker is still there after Phase 7")
			}
		})
	}
	t.Run("a failed check stops before the switch", func(t *testing.T) {
		t.Parallel()
		r := newGateM9Rig(t)
		r.state("m9-check-fail", "")
		out, errOut, code := r.run("gate.sh", nil, "m9")
		calls := r.calls()
		if code == 0 || strings.Contains(calls, "svid-ttl") || len(goRuns(calls)) != 0 || strings.Contains(calls, "harness:status") || !strings.Contains(out+errOut, "mise run gate:m9:repair") {
			t.Fatalf("exit %d, stderr %q, calls %s; want a stop that names the repair, with no switch, no test and no Phase 7", code, errOut, calls)
		}
	})
}

// TestGateM9RunPattern: with -run, gate.sh m9 runs one invocation with that pattern, between Phase 0 and Phase 7, and the run is not a record.
func TestGateM9RunPattern(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"-run", "^TestM9IslandsHold$"}, {"-run=^TestM9IslandsHold$"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			_, errOut, code := r.run("gate.sh", nil, append([]string{"m9"}, args...)...)
			calls := r.calls()
			runs := goRuns(calls)
			if code != 0 || len(runs) != 1 {
				t.Fatalf("exit %d, runs %v\nstderr %s", code, runs, errOut)
			}
			if strings.Count(runs[0], "-run") != 1 || !strings.Contains(runs[0], "^TestM9IslandsHold$") || strings.Contains(runs[0], "TestM9Local") {
				t.Errorf("the run %q does not hold the pattern alone", runs[0])
			}
			if callAt(calls, "svid-ttl set 1h") < 0 || callAt(calls, "svid-ttl restore") < 0 {
				t.Errorf("Phase 0 or Phase 7 did not run around the pattern:\n%s", calls)
			}
			if !strings.Contains(errOut, "not a slow-tier record") {
				t.Errorf("stderr %q lacks 'not a slow-tier record'", errOut)
			}
			if !r.exists("build/gate-m9-run.json") {
				t.Error("no events file build/gate-m9-run.json")
			}
		})
	}
}

// TestGateM9NotARecord: a run counts as a slow-tier record only as a full run at GATE_M9_SVID_TTL of harness/versions.env. A run with -run, or
// at another lifetime, prints "not a slow-tier record".
func TestGateM9NotARecord(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		env    []string
		args   []string
		record bool
	}{
		{name: "a full run", record: true},
		{name: "a pattern", args: []string{"-run", "^TestM9ConnectedRevocation$"}},
		{name: "another lifetime", env: []string{"GATE_M9_SVID_TTL=2h"}},
		{name: "other go test arguments", args: []string{"-v"}, record: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			_, errOut, code := r.run("gate.sh", tc.env, append([]string{"m9"}, tc.args...)...)
			if code != 0 {
				t.Fatalf("exit %d\nstderr %s", code, errOut)
			}
			if got := !strings.Contains(errOut, "not a slow-tier record"); got != tc.record {
				t.Errorf("record %v, want %v; stderr %s", got, tc.record, errOut)
			}
		})
	}
}

// TestGateM9TtlFromEnvironment: gate.sh reads GATE_M9_SVID_TTL from the environment before it sources harness/versions.env, so a caller value
// wins over the file, and the run is not a record. A value equal to cells/dev-cp.env (1m) skips the switch and the restore. Without a caller
// value, the file value is the lifetime.
func TestGateM9TtlFromEnvironment(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, file, want string
		env              []string
		record           bool
	}{
		{name: "1m from the environment skips the switch", env: []string{"GATE_M9_SVID_TTL=1m"}},
		{name: "30m from the environment", env: []string{"GATE_M9_SVID_TTL=30m"}, want: "svid-ttl set 30m"},
		{name: "the file value", file: "2h", want: "svid-ttl set 2h", record: true},
		{name: "1m with a marker that a test writes", env: []string{"GATE_M9_SVID_TTL=1m", "STUB_WRITE_MARKER=1"}, want: "svid-ttl restore"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			if tc.file != "" {
				r.setVersion("GATE_M9_SVID_TTL", tc.file)
			}
			_, errOut, code := r.run("gate.sh", tc.env, "m9")
			calls := r.calls()
			if code != 0 || len(goRuns(calls)) != len(m9Tests) {
				t.Fatalf("exit %d, %d runs\nstderr %s", code, len(goRuns(calls)), errOut)
			}
			if tc.want == "" {
				if strings.Contains(calls, "svid-ttl") {
					t.Errorf("the lifetime of cells/dev-cp.env ran svid-ttl:\n%s", calls)
				}
			} else if callAt(calls, tc.want) < 0 || callAt(calls, "svid-ttl restore") < 0 {
				t.Errorf("calls lack %q and the restore:\n%s", tc.want, calls)
			}
			if got := !strings.Contains(errOut, "not a slow-tier record"); got != tc.record {
				t.Errorf("record %v, want %v; stderr %s", got, tc.record, errOut)
			}
		})
	}
}

// TestGateM9TimeoutAsSet: the -timeout of each invocation is GATE_M9_TEST_TIMEOUT_MINUTES as it stands, not twice the budget of the whole tier. An
// empty value or an empty budget stops the gate before the tests.
func TestGateM9TimeoutAsSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, setting, value, want string
	}{
		{name: "versions.env", want: "-timeout 270m"},
		{name: "another value", setting: "GATE_M9_TEST_TIMEOUT_MINUTES", value: "100", want: "-timeout 100m"},
		{name: "no timeout", setting: "GATE_M9_TEST_TIMEOUT_MINUTES", value: ""},
		{name: "no budget", setting: "GATE_M9_BUDGET_MINUTES", value: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			if tc.setting != "" {
				r.setVersion(tc.setting, tc.value)
			}
			_, errOut, code := r.run("gate.sh", nil, "m9")
			runs := goRuns(r.calls())
			if tc.want == "" {
				if code == 0 || len(runs) != 0 || !strings.Contains(errOut, tc.setting) {
					t.Fatalf("exit %d, %d runs, stderr %q; want a stop that names %s", code, len(runs), errOut, tc.setting)
				}
				return
			}
			if code != 0 || len(runs) != len(m9Tests) {
				t.Fatalf("exit %d, %d runs\nstderr %s", code, len(runs), errOut)
			}
			for _, run := range runs {
				if !strings.Contains(run, " "+tc.want+" ") || strings.Contains(run, "-timeout 990m") {
					t.Errorf("run %q, want %s", run, tc.want)
				}
			}
		})
	}
}

// TestGateM9BudgetCoversTier: the elapsed time of gate:m9 runs from Phase 0 to the end of Phase 7, so a slow switch or a slow restore counts
// against GATE_M9_BUDGET_MINUTES although the tests take no time.
func TestGateM9BudgetCoversTier(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		budget string
		pass   bool
	}{{budget: "30"}, {budget: "31", pass: true}} {
		t.Run("budget "+tc.budget, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			r.setVersion("GATE_M9_BUDGET_MINUTES", tc.budget)
			_, errOut, code := r.run("gate.sh", []string{"STUB_SET_SECONDS=901", "STUB_RESTORE_SECONDS=901"}, "m9")
			if tc.pass {
				if code != 0 {
					t.Fatalf("exit %d\nstderr %s", code, errOut)
				}
				return
			}
			if code == 0 || !strings.Contains(errOut, "over the budget of 30 minutes") || !strings.Contains(errOut, "1802s") {
				t.Fatalf("exit %d, stderr %q; want a failure over the budget after 1802 s", code, errOut)
			}
		})
	}
}

// TestGateM9ImageCheck: Phase 0 checks the images of the M8 list, plus the container agent-ban in spire-server-0 of dev-cp, cell-proxy of
// the mesh-view tunnel in each cell and the three cell-proxy servers of management. A missing agent-ban or a stale image stops the run before
// the switch.
func TestGateM9ImageCheck(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, stale, want string
		noBan             bool
	}{
		{name: "healthy"},
		{name: "no agent-ban", noBan: true, want: "agent-ban"},
		{name: "a stale mesh-view tunnel", stale: "mesh-view-system deployment/mesh-view dev-cell-2", want: "CELL=dev-cell-2 mise run cell:up"},
		{name: "a stale mesh hub", stale: "mesh-view-system deployment/mesh-view-hub management", want: "LINK_ONLY=mesh-view-hub"},
		{name: "a stale repo server", stale: "argocd deployment/argocd-repo-server dev-cell-1", want: "CELL=dev-cell-1 mise run cell:up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			if tc.noBan {
				r.state("no-agent-ban", "")
			}
			if tc.stale != "" {
				r.state("stale", tc.stale)
			}
			_, errOut, code := r.run("gate.sh", nil, "m9")
			calls := r.calls()
			if tc.want == "" {
				if code != 0 {
					t.Fatalf("exit %d\nstderr %s", code, errOut)
				}
				for _, want := range []string{"kind-dev-cell-1 -n mesh-view-system get deployment/mesh-view ", "kind-dev-cell-2 -n mesh-view-system get deployment/mesh-view ",
					"kind-management -n central-view-system get deployment/argocd-agent-principal", "kind-management -n observability-system get deployment/telemetry-gateway",
					"kind-management -n mesh-view-system get deployment/mesh-view-hub", "kind-dev-cp -n spire-system get statefulset/spire-server",
					"kind-dev-cp -n cell-system get statefulset/bundle-store", "kind-dev-cell-2 -n cell-identity-system get deployment/celld"} {
					if !strings.Contains(calls, want) {
						t.Errorf("the image check did not read %q", want)
					}
				}
				return
			}
			if code == 0 || !strings.Contains(errOut, tc.want) || strings.Contains(calls, "svid-ttl") {
				t.Fatalf("exit %d, stderr %q; want a stop before the switch that says %q", code, errOut, tc.want)
			}
		})
	}
}

// TestGateJqUnbuffered: gate.sh prints the test text through jq --unbuffered, so a long run shows its progress as it goes.
func TestGateJqUnbuffered(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../scripts/gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for i, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, "select(.Output != null)") {
			continue
		}
		n++
		if !strings.Contains(line, "jq --unbuffered ") {
			t.Errorf("gate.sh line %d prints the test text without jq --unbuffered: %s", i+1, strings.TrimSpace(line))
		}
	}
	if n < 2 {
		t.Errorf("gate.sh prints the test text in %d places, want the run of every milestone and the runs of m9", n)
	}
}

// m9PartitionStub stands in for scripts/partition.sh: list prints one line for each cut in stub/cuts, and heal --all empties it.
const m9PartitionStub = `#!/usr/bin/env bash
d="$STUB_DIR"
echo "partition $*" >>"$d/calls"
touch "$d/cuts"
case "$*" in
  list) while read -r node tag; do [[ -n "$node" ]] && jq -nc --arg n "$node" --arg t "$tag" '{node: $n, tool: "iptables", chain: "FORWARD", tag: $t, rule: "x"}'; done <"$d/cuts" ;;
  "heal --all") : >"$d/cuts"; echo '{"tag":"all","healed":0,"nodes":[]}' ;;
  *) exit 2 ;;
esac
`

// m9M2RepairStub stands in for scripts/gate-m2-repair.sh: it removes the test key of the node.
const m9M2RepairStub = `#!/usr/bin/env bash
echo "m2 repair $*" >>"$STUB_DIR/calls"
rm -f "$STUB_DIR/keytest"
`

// newRepairM9Rig is an m9Rig with stubs for the scripts that gate-m9-repair.sh calls: the partition tool, svid-ttl.sh and gate-m2-repair.sh.
// scripts/revoke.sh (Task 17) exists only when the test writes it.
func newRepairM9Rig(t *testing.T) *m9Rig {
	t.Helper()
	r := newM9Rig(t)
	r.write("scripts/partition.sh", m9PartitionStub)
	r.write("scripts/svid-ttl.sh", m9SvidStub)
	r.write("scripts/gate-m2-repair.sh", m9M2RepairStub)
	if err := os.Remove(r.root + "/scripts/revoke.sh"); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return r
}

// traces writes every trace that a stopped slow tier can leave: a cut, the marker with the live lifetime, a revoked test cell, a held entry for
// two reads, an input entry, an m9- namespace and the API server test key.
func (r *m9Rig) traces() {
	r.t.Helper()
	r.state("cuts", "dev-cp-control-plane gate-m9-cut-0a1b2c3d\n")
	r.marker("1h")
	r.state("live-ttl", "1h\n")
	r.write("build/gate/m9-revoked", "dev-cell-2\n")
	r.state("held", "dev-cell-2\n")
	r.state("held-reads", "2\n")
	r.state("inputs", "0123456789abcdef\n")
	r.state("ns-dev-cell-1", "namespace/m9-ab12cd\nnamespace/m8-keep\n")
	r.state("keytest", "the node holds /etc/kubernetes/pki/m2-test-sa.key\n")
}

// mutations are the call log parts of a repair that changes something.
var m9Mutations = []string{"partition heal", "delete namespace", "mgmt -- unrevoke", "svid-ttl", "mise run revoke", "m2 repair", "harness:status"}

// TestGateM9RepairOrder: gate-m9-repair.sh heals every cut, waits until connected, waits until envd holds no entry, runs revoke -- clean,
// un-revokes each recorded cell, repairs the API server when the test key exists, restores the lifetime, deletes the m9- namespaces and runs
// harness:status, in that order.
func TestGateM9RepairOrder(t *testing.T) {
	t.Parallel()
	r := newRepairM9Rig(t)
	r.traces()
	r.state("mgmt-down", "2\n")
	r.write("scripts/revoke.sh", "#!/usr/bin/env bash\nexit 0\n")
	_, errOut, code := r.run("gate-m9-repair.sh", nil)
	calls := r.calls()
	if code != 0 {
		t.Fatalf("exit %d\nstderr %s\ncalls %s", code, errOut, calls)
	}
	heal := callAt(calls, "partition heal --all")
	connected := lastCallAt(calls, "mise run mgmt -- status")
	settled := lastCallAt(calls, "get configmap cell-records")
	clean := callAt(calls, "mise run revoke -- clean")
	unrevoke := callAt(calls, "mise run mgmt -- unrevoke --cell dev-cell-2")
	m2 := callAt(calls, "m2 repair")
	restore := callAt(calls, "svid-ttl restore")
	ns := callAt(calls, "delete namespace m9-ab12cd")
	status := callAt(calls, "mise run harness:status")
	order := []int{heal, connected, settled, clean, unrevoke, m2, restore, ns, status}
	for i := range order {
		if order[i] < 0 || (i > 0 && order[i] < order[i-1]) {
			t.Fatalf("want heal, connected, settle, clean, un-revoke, API server repair, restore, namespaces, harness:status (%v):\n%s", order, calls)
		}
	}
	if n := strings.Count(calls, "mise run mgmt -- status"); n < 3 {
		t.Errorf("%d status reads, want the wait to read again until connected:\n%s", n, calls)
	}
	if strings.Contains(calls, "m8-keep") {
		t.Errorf("the repair touched a namespace of another milestone:\n%s", calls)
	}
	for _, rel := range []string{"build/gate/m9-svid-ttl", "build/gate/m9-revoked", "stub/keytest"} {
		if r.exists(rel) {
			t.Errorf("%s is still there", rel)
		}
	}
	if _, errOut, code := r.run("gate-m9-repair.sh", nil, "--check"); code != 0 {
		t.Errorf("--check after the repair: exit %d, stderr %s", code, errOut)
	}
}

// TestGateM9RepairRestores: a stopped slow tier that left only the marker gets the restore and harness:status. With no scripts/revoke.sh
// (Task 17), the clean step is skipped with a log line. A failed restore fails the repair and names it again.
func TestGateM9RepairRestores(t *testing.T) {
	t.Parallel()
	t.Run("the marker", func(t *testing.T) {
		t.Parallel()
		r := newRepairM9Rig(t)
		r.marker("1h")
		r.state("live-ttl", "1h\n")
		_, errOut, code := r.run("gate-m9-repair.sh", nil)
		calls := r.calls()
		if code != 0 || r.exists("build/gate/m9-svid-ttl") {
			t.Fatalf("exit %d, marker %v\nstderr %s\ncalls %s", code, r.exists("build/gate/m9-svid-ttl"), errOut, calls)
		}
		if restore, status := callAt(calls, "svid-ttl restore"), callAt(calls, "mise run harness:status"); restore < 0 || status < restore {
			t.Errorf("want the restore and then harness:status:\n%s", calls)
		}
		if strings.Contains(calls, "mise run revoke") || !strings.Contains(errOut, "scripts/revoke.sh") {
			t.Errorf("with no scripts/revoke.sh, want no clean call and a log line that names it; stderr %s\ncalls %s", errOut, calls)
		}
		if strings.Contains(calls, "m2 repair") || strings.Contains(calls, "unrevoke") {
			t.Errorf("the repair ran a step that nothing needs:\n%s", calls)
		}
	})
	t.Run("a failed restore", func(t *testing.T) {
		t.Parallel()
		r := newRepairM9Rig(t)
		r.marker("1h")
		r.state("svid-restore-fail", "")
		_, errOut, code := r.run("gate-m9-repair.sh", nil)
		if code == 0 || !strings.Contains(errOut, "mise run gate:m9:repair") || strings.Contains(r.calls(), "harness:status") {
			t.Fatalf("exit %d, stderr %q; want a failure that names the repair, before harness:status", code, errOut)
		}
	})
	t.Run("harness:status clears after two reads", func(t *testing.T) {
		t.Parallel()
		r := newRepairM9Rig(t)
		r.state("status-fails", "2\n")
		_, errOut, code := r.run("gate-m9-repair.sh", nil)
		if n := strings.Count(r.calls(), "mise run harness:status"); code != 0 || n != 3 {
			t.Fatalf("exit %d, %d reads of harness:status, stderr %s; want a pass at the third read", code, n, errOut)
		}
	})
	t.Run("harness:status stays bad", func(t *testing.T) {
		t.Parallel()
		r := newRepairM9Rig(t)
		r.state("status-fail", "")
		_, errOut, code := r.run("gate-m9-repair.sh", []string{"HARNESS_STATUS_WAIT=120"})
		if n := strings.Count(r.calls(), "mise run harness:status"); code == 0 || n != 3 || !strings.Contains(errOut, "harness:status reports a bad value") {
			t.Fatalf("exit %d, %d reads of harness:status, stderr %q; want a failure after the bound of 120 s", code, n, errOut)
		}
	})
	t.Run("never connected", func(t *testing.T) {
		t.Parallel()
		r := newRepairM9Rig(t)
		r.marker("1h")
		r.state("mgmt-down", "1000\n")
		_, errOut, code := r.run("gate-m9-repair.sh", []string{"GATE_M9_WAIT=60", "GATE_M9_POLL=10"})
		if code == 0 || !strings.Contains(errOut, "connected") || strings.Contains(r.calls(), "svid-ttl") {
			t.Fatalf("exit %d, stderr %q; want a failure after the bound, before the restore", code, errOut)
		}
	})
}

// TestGateM9RepairCheck: --check lists each trace with the repair command and exits 1, and changes nothing. With no trace it exits 0. An e2e
// namespace of another milestone is no trace.
func TestGateM9RepairCheck(t *testing.T) {
	t.Parallel()
	t.Run("none", func(t *testing.T) {
		t.Parallel()
		r := newRepairM9Rig(t)
		r.state("ns-dev-cp", "namespace/m8-other\n")
		_, errOut, code := r.run("gate-m9-repair.sh", nil, "--check")
		if code != 0 {
			t.Fatalf("exit %d, stderr %s", code, errOut)
		}
	})
	for _, tc := range []struct {
		name, want string
		setup      func(r *m9Rig)
	}{
		{"a cut", "gate-m9-cut-0a1b2c3d", func(r *m9Rig) { r.state("cuts", "dev-cp-control-plane gate-m9-cut-0a1b2c3d\n") }},
		{"the marker", "build/gate/m9-svid-ttl", func(r *m9Rig) { r.marker("1h"); r.state("live-ttl", "1h\n") }},
		{"a restore that did not settle", "build/gate/m9-svid-ttl.restoring", func(r *m9Rig) { r.write("build/gate/m9-svid-ttl.restoring", "") }},
		{"a live lifetime with no marker", "agent_ttl '1h'", func(r *m9Rig) { r.state("live-ttl", "1h\n") }},
		{"a revoked test cell", "dev-cell-2", func(r *m9Rig) { r.write("build/gate/m9-revoked", "dev-cell-2\n") }},
		{"a held entry", "envd holds", func(r *m9Rig) { r.state("held", "dev-cell-1\n") }},
		{"an input entry", "0123456789abcdef", func(r *m9Rig) { r.state("inputs", "0123456789abcdef\n") }},
		{"a namespace", "m9-ab12cd", func(r *m9Rig) { r.state("ns-dev-cell-2", "namespace/m9-ab12cd\n") }},
		{"the API server test key", "m2-test-sa", func(r *m9Rig) {
			r.state("keytest", "the node holds /etc/kubernetes/pki/m2-test-sa.key\n")
		}},
		{"everything", "m9-ab12cd", func(r *m9Rig) { r.traces() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRepairM9Rig(t)
			tc.setup(r)
			out, errOut, code := r.run("gate-m9-repair.sh", nil, "--check")
			if code != 1 || !strings.Contains(out+errOut, tc.want) || !strings.Contains(errOut, "Run: mise run gate:m9:repair") {
				t.Fatalf("exit %d, output %q %q; want exit 1 with %q and the repair command", code, out, errOut, tc.want)
			}
			for _, m := range m9Mutations {
				if strings.Contains(r.calls(), m) {
					t.Errorf("--check changed something (%q):\n%s", m, r.calls())
				}
			}
		})
	}
}

// TestPocGateFastOrder: poc-gate.sh fast runs gate:m1 to gate:m8, with gate:m6:provision after gate:m6, and stops at the first failure. The
// manual drills do not run. GATE_FAST_BUDGET_MINUTES bounds it when set. slow runs gate:m9, and all runs fast and then slow.
func TestPocGateFastOrder(t *testing.T) {
	t.Parallel()
	fast := []string{"gate:m1", "gate:m2", "gate:m3", "gate:m4", "gate:m5", "gate:m6", "gate:m6:provision", "gate:m7", "gate:m8"}
	gates := func(calls string) []string {
		var out []string
		for _, l := range strings.Split(calls, "\n") {
			if f := strings.Fields(l); len(f) >= 3 && f[0] == "mise" && f[1] == "run" && strings.HasPrefix(f[2], "gate:") {
				out = append(out, f[2])
			}
		}
		return out
	}
	for _, tc := range []struct {
		name, tier, budget string
		env                []string
		want               []string
		fail               string
	}{
		{name: "fast", tier: "fast", want: fast},
		{name: "fast stops at a failure", tier: "fast", env: []string{"STUB_FAIL_GATES=gate:m5"}, want: fast[:5], fail: "gate:m5"},
		{name: "fast over its budget", tier: "fast", budget: "1", env: []string{"STUB_GATE_SECONDS=10"}, want: fast, fail: "budget"},
		{name: "fast within its budget", tier: "fast", budget: "2", env: []string{"STUB_GATE_SECONDS=10"}, want: fast},
		{name: "slow", tier: "slow", want: []string{"gate:m9"}},
		{name: "all", tier: "all", want: append(append([]string{}, fast...), "gate:m9")},
		{name: "all stops after a failed fast tier", tier: "all", env: []string{"STUB_FAIL_GATES=gate:m8"}, want: fast, fail: "gate:m8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newM9Rig(t)
			if tc.budget != "" {
				r.setVersion("GATE_FAST_BUDGET_MINUTES", tc.budget)
			}
			out, errOut, code := r.run("poc-gate.sh", tc.env, tc.tier)
			if got := gates(r.calls()); strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("gates %v, want %v", got, tc.want)
			}
			if tc.fail == "" {
				if code != 0 {
					t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errOut)
				}
				return
			}
			if code == 0 || !strings.Contains(errOut, tc.fail) {
				t.Fatalf("exit %d, stderr %q; want a failure that names %q", code, errOut, tc.fail)
			}
		})
	}
	t.Run("usage", func(t *testing.T) {
		t.Parallel()
		r := newM9Rig(t)
		if _, errOut, code := r.run("poc-gate.sh", nil, "m9"); code == 0 || !strings.Contains(errOut, "fast|slow|all") || strings.Contains(r.calls(), "mise") {
			t.Errorf("exit %d, stderr %q; want the usage and no gate", code, errOut)
		}
	})
}
