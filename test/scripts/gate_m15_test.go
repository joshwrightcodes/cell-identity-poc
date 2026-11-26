package scripts

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// m15Kubectl stands in for kubectl in the repair tests of M15. It lists the e2e namespaces of stub/ns-<cluster>, and a delete removes the
// name from that file, unless stub/ns-stuck exists.
const m15Kubectl = `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_DIR/calls"
d="$STUB_DIR"
ctx="" prev=""
for a in "$@"; do
  [[ "$prev" == --context ]] && ctx="${a#kind-}"
  prev="$a"
done
case " $* " in
  *" get namespaces -l cell.poc.internal/e2e=true -o name "*) cat "$d/ns-$ctx" 2>/dev/null; exit 0 ;;
  *" delete namespace "*)
    [[ ! -e "$d/ns-stuck" ]] || exit 0
    for a in "$@"; do
      [[ "$a" == m1[0-9]-* || "$a" == m9-* ]] || continue
      grep -vx "namespace/$a" "$d/ns-$ctx" >"$d/ns-$ctx.new" || true
      mv "$d/ns-$ctx.new" "$d/ns-$ctx"
    done ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// m9CalledBare matches the log line of gate-m9-repair.sh with no argument, which is a repair and not a check.
var m9CalledBare = regexp.MustCompile(`(?m)^m9 repair $`)

// newRepairM15Rig is an m9Rig with a stub of gate-m9-repair.sh that records its arguments. stub/m9-fail makes it fail.
func newRepairM15Rig(t *testing.T) *m9Rig {
	t.Helper()
	r := newM9Rig(t)
	r.write("bin/kubectl", m15Kubectl)
	r.write("scripts/gate-m9-repair.sh", "#!/usr/bin/env bash\necho \"m9 repair $*\" >>\"$STUB_DIR/calls\"\n"+
		"[[ ! -e \"$STUB_DIR/m9-fail\" ]] || { echo 'a trace of m9. Run: mise run gate:m9:repair' >&2; exit 1; }\n")
	return r
}

// newGateM15Rig is a gate rig whose gate-m15-repair.sh is a stub that records its arguments. stub/m15-check-fail makes it fail.
func newGateM15Rig(t *testing.T) *m9Rig {
	t.Helper()
	r := newGateM9Rig(t)
	r.write("scripts/gate-m15-repair.sh", "#!/usr/bin/env bash\necho \"m15 repair $*\" >>\"$STUB_DIR/calls\"\n"+
		"[[ ! -e \"$STUB_DIR/m15-check-fail\" ]] || { echo 'a trace of m15. Run: mise run gate:m15:repair'; exit 1; }\n")
	return r
}

// TestGateM15Phases: gate.sh m15 runs the repair checks of M6 to M8 and of M15 in order, then the image check of M8, then the tests that match
// ^TestM15 with the timeout of harness/versions.env, then the token scan. A failed check, a stale image or a token stops or fails the run.
func TestGateM15Phases(t *testing.T) {
	t.Parallel()
	t.Run("order", func(t *testing.T) {
		t.Parallel()
		r := newGateM15Rig(t)
		_, errOut, code := r.run("gate.sh", nil, "m15")
		calls := r.calls()
		if code != 0 {
			t.Fatalf("exit %d\nstderr %s\ncalls %s", code, errOut, calls)
		}
		m6, m7, m8, m9 := callAt(calls, "m6 repair --check"), callAt(calls, "m7 repair --check"), callAt(calls, "m8 repair --check"), callAt(calls, "m15 repair --check")
		image := callAt(calls, "kind-dev-cp -n spire-system get statefulset/spire-server")
		run := callAt(calls, "go test", "-run ^TestM15", " -json ")
		scan := callAt(calls, "scan ")
		order := []int{m6, m7, m8, m9, image, run, scan}
		for i := range order {
			if order[i] < 0 || (i > 0 && order[i] < order[i-1]) {
				t.Fatalf("want the checks of M6 to M8, the check of M15, the image check, the tests and the token scan in this order (%v):\n%s", order, calls)
			}
		}
		runs := goRuns(calls)
		if len(runs) != 1 || !strings.Contains(runs[0], " -timeout 70m ") {
			t.Errorf("runs %v, want one run with -timeout 70m", runs)
		}
		for _, want := range []string{"kind-dev-cp -n cell-system get statefulset/bundle-store", "kind-dev-cell-2 -n argocd get deployment/argocd-repo-server",
			"kind-dev-cell-2 -n cell-identity-system get deployment/celld"} {
			if !strings.Contains(calls, want) {
				t.Errorf("the image check did not read %q", want)
			}
		}
	})
	t.Run("a failed check", func(t *testing.T) {
		t.Parallel()
		for _, m := range []string{"m6", "m7", "m8", "m15"} {
			r := newGateM15Rig(t)
			r.state(m+"-check-fail", "")
			out, errOut, code := r.run("gate.sh", nil, "m15")
			if code == 0 || len(goRuns(r.calls())) != 0 || !strings.Contains(out+errOut, "mise run gate:"+m+":repair") {
				t.Errorf("%s: exit %d, stderr %q; want a stop before the tests that names the repair", m, code, errOut)
			}
		}
	})
	t.Run("no agent-ban", func(t *testing.T) {
		t.Parallel()
		r := newGateM15Rig(t)
		r.state("no-agent-ban", "")
		_, errOut, code := r.run("gate.sh", nil, "m15")
		if code == 0 || len(goRuns(r.calls())) != 0 || !strings.Contains(errOut, "agent-ban") {
			t.Fatalf("exit %d, stderr %q; want a stop before the tests that names agent-ban", code, errOut)
		}
	})
	t.Run("a stale image", func(t *testing.T) {
		t.Parallel()
		r := newGateM15Rig(t)
		r.state("stale", "cell-system statefulset/bundle-store dev-cell-1")
		_, errOut, code := r.run("gate.sh", nil, "m15")
		if code == 0 || len(goRuns(r.calls())) != 0 || !strings.Contains(errOut, "CELL=dev-cell-1 mise run cell:up") {
			t.Fatalf("exit %d, stderr %q; want a stop before the tests", code, errOut)
		}
	})
	t.Run("a token in a log", func(t *testing.T) {
		t.Parallel()
		r := newGateM15Rig(t)
		r.state("scan-hit", "")
		_, errOut, code := r.run("gate.sh", nil, "m15")
		if code == 0 || len(goRuns(r.calls())) != 1 || !strings.Contains(errOut, "found a token") {
			t.Fatalf("exit %d, stderr %q; want a failure after the tests", code, errOut)
		}
	})
	t.Run("a failed test", func(t *testing.T) {
		t.Parallel()
		r := newGateM15Rig(t)
		_, _, code := r.run("gate.sh", []string{"STUB_FAIL_TESTS=TestM15"}, "m15")
		if code == 0 || !strings.Contains(r.calls(), "scan ") {
			t.Errorf("exit %d; want a failure, and the token scan after the tests:\n%s", code, r.calls())
		}
	})
	t.Run("the slow lifetime", func(t *testing.T) {
		t.Parallel()
		r := newGateM15Rig(t)
		r.marker("1h")
		_, errOut, code := r.run("gate.sh", nil, "m15")
		if code == 0 || len(goRuns(r.calls())) != 0 || !strings.Contains(errOut, "mise run gate:m9:repair") {
			t.Fatalf("exit %d, stderr %q; want a refusal that names gate:m9:repair", code, errOut)
		}
	})
}

// TestGateM15Budget: harness/versions.env holds the limits of M15, a budget of 35 minutes and a timeout of 70 minutes, and gate.sh m15 stops
// before every check and test when one of them is empty. A timeout skips every cleanup of a test, so the timeout follows the setting.
func TestGateM15Budget(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../harness/versions.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GATE_M15_BUDGET_MINUTES=35", "GATE_M15_TEST_TIMEOUT_MINUTES=70"} {
		if !strings.Contains(string(b), "\n"+want+"\n") {
			t.Errorf("harness/versions.env lacks the line %q", want)
		}
	}
	for _, name := range []string{"GATE_M15_BUDGET_MINUTES", "GATE_M15_TEST_TIMEOUT_MINUTES"} {
		t.Run("empty "+name, func(t *testing.T) {
			t.Parallel()
			r := newGateM15Rig(t)
			r.setVersion(name, "")
			_, errOut, code := r.run("gate.sh", nil, "m15")
			if code == 0 || !strings.Contains(errOut, name+" is empty in harness/versions.env") || strings.Contains(r.calls(), "repair --check") || len(goRuns(r.calls())) != 0 {
				t.Fatalf("exit %d, stderr %q; want a stop that names %s before every check and test", code, errOut, name)
			}
		})
	}
	t.Run("another timeout", func(t *testing.T) {
		t.Parallel()
		r := newGateM15Rig(t)
		r.setVersion("GATE_M15_TEST_TIMEOUT_MINUTES", "260")
		if _, errOut, code := r.run("gate.sh", nil, "m15"); code != 0 || !strings.Contains(strings.Join(goRuns(r.calls()), "\n"), " -timeout 260m ") {
			t.Fatalf("exit %d, stderr %q, calls %s; want -timeout 260m", code, errOut, r.calls())
		}
	})
}

// TestGateM15RepairCallsM9: gate-m15-repair.sh runs gate-m9-repair.sh, then deletes each namespace m15-<name> with the test label in every
// cluster and waits until none is left. It leaves the namespaces of other prefixes, and it stops when a namespace stays.
func TestGateM15RepairCallsM9(t *testing.T) {
	t.Parallel()
	t.Run("repair", func(t *testing.T) {
		t.Parallel()
		r := newRepairM15Rig(t)
		r.state("ns-dev-cell-1", "namespace/m15-ab12cd\nnamespace/m8-keep\nnamespace/m9-keep\n")
		r.state("ns-management", "namespace/m15-ef34ab\n")
		_, errOut, code := r.run("gate-m15-repair.sh", nil)
		calls := r.calls()
		if code != 0 {
			t.Fatalf("exit %d\nstderr %s\ncalls %s", code, errOut, calls)
		}
		m9 := callAt(calls, "m9 repair")
		d1 := callAt(calls, "kind-dev-cell-1", "delete namespace m15-ab12cd")
		d2 := callAt(calls, "kind-management", "delete namespace m15-ef34ab")
		if m9 < 0 || d1 < m9 || d2 < m9 {
			t.Fatalf("want gate-m9-repair.sh before the deletes (%d, %d, %d):\n%s", m9, d1, d2, calls)
		}
		if strings.Contains(calls, "m8-keep") || strings.Contains(calls, "m9-keep") || strings.Contains(calls, "m9 repair --check") {
			t.Errorf("the repair touched another prefix, or ran the check:\n%s", calls)
		}
		if strings.TrimSpace(r.read("stub/ns-dev-cell-1")) != "namespace/m8-keep\nnamespace/m9-keep" {
			t.Errorf("namespaces left: %q", r.read("stub/ns-dev-cell-1"))
		}
	})
	t.Run("m9 repair fails", func(t *testing.T) {
		t.Parallel()
		r := newRepairM15Rig(t)
		r.state("m9-fail", "")
		r.state("ns-dev-cell-1", "namespace/m15-ab12cd\n")
		_, errOut, code := r.run("gate-m15-repair.sh", nil)
		if code == 0 || strings.Contains(r.calls(), "delete namespace") || !strings.Contains(errOut, "mise run gate:m15:repair") {
			t.Fatalf("exit %d, stderr %q; want a stop before the deletes that names the repair", code, errOut)
		}
	})
	t.Run("a marker of the rotation", func(t *testing.T) {
		t.Parallel()
		r := newRepairM15Rig(t)
		r.write("build/gate/m15-intermediate-rotated", "2026-12-01T10:00:00Z\n")
		_, errOut, code := r.run("gate-m15-repair.sh", nil)
		calls := r.calls()
		m9, rot := callAt(calls, "m9 repair"), callAt(calls, "mise run pki:rotate-intermediate CELL=dev-cp")
		if code != 0 || m9 < 0 || rot < m9 || r.exists("build/gate/m15-intermediate-rotated") {
			t.Fatalf("exit %d, stderr %q, calls %s; want the rotation after gate-m9-repair.sh and no marker", code, errOut, calls)
		}
	})
	t.Run("a failed rotation keeps the marker", func(t *testing.T) {
		t.Parallel()
		r := newRepairM15Rig(t)
		r.write("build/gate/m15-intermediate-rotated", "x\n")
		r.state("rotate-fail", "")
		_, errOut, code := r.run("gate-m15-repair.sh", nil)
		if code == 0 || !r.exists("build/gate/m15-intermediate-rotated") || !strings.Contains(errOut, "pki:rotate-intermediate") {
			t.Fatalf("exit %d, stderr %q; want a failure that keeps the marker", code, errOut)
		}
	})
	t.Run("a namespace stays", func(t *testing.T) {
		t.Parallel()
		r := newRepairM15Rig(t)
		r.state("ns-dev-cell-1", "namespace/m15-ab12cd\n")
		r.state("ns-stuck", "")
		_, errOut, code := r.run("gate-m15-repair.sh", []string{"GATE_M15_WAIT=10", "GATE_M15_POLL=5"})
		if code == 0 || !strings.Contains(errOut, "still there after 10s") {
			t.Fatalf("exit %d, stderr %q; want a failure that names the wait", code, errOut)
		}
	})
}

// TestGateM15RepairCheck: --check runs gate-m9-repair.sh --check, lists the m15- namespaces, changes nothing, and exits 1 with the repair
// command when either finds a trace.
func TestGateM15RepairCheck(t *testing.T) {
	t.Parallel()
	t.Run("none", func(t *testing.T) {
		t.Parallel()
		r := newRepairM15Rig(t)
		r.state("ns-dev-cell-1", "namespace/m8-other\n")
		_, errOut, code := r.run("gate-m15-repair.sh", nil, "--check")
		if code != 0 || !strings.Contains(r.calls(), "m9 repair --check") {
			t.Fatalf("exit %d, stderr %q, calls %s; want exit 0 after the check of M9", code, errOut, r.calls())
		}
	})
	for _, tc := range []struct {
		name, want string
		setup      func(r *m9Rig)
	}{
		{"a namespace", "m15-ab12cd", func(r *m9Rig) { r.state("ns-dev-cell-2", "namespace/m15-ab12cd\n") }},
		{"a marker of the rotation", "m15-intermediate-rotated", func(r *m9Rig) { r.write("build/gate/m15-intermediate-rotated", "x\n") }},
		{"a trace of M9", "a trace of m9", func(r *m9Rig) { r.state("m9-fail", "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRepairM15Rig(t)
			tc.setup(r)
			out, errOut, code := r.run("gate-m15-repair.sh", nil, "--check")
			if code != 1 || !strings.Contains(out+errOut, tc.want) || !strings.Contains(errOut, "Run: mise run gate:m15:repair") {
				t.Fatalf("exit %d, output %q %q; want exit 1 with %q and the repair command", code, out, errOut, tc.want)
			}
			if strings.Contains(r.calls(), "delete namespace") || m9CalledBare.MatchString(r.calls()) {
				t.Errorf("--check changed something:\n%s", r.calls())
			}
		})
	}
	t.Run("usage", func(t *testing.T) {
		t.Parallel()
		r := newRepairM15Rig(t)
		if _, errOut, code := r.run("gate-m15-repair.sh", nil, "--fix"); code == 0 || !strings.Contains(errOut, "usage") {
			t.Errorf("exit %d, stderr %q; want the usage", code, errOut)
		}
	})
}
