package scripts

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// stubKindFlaky lists the five clusters of the harness with one write for each name, as kind does. The first STUB_KIND_FAILS calls fail
// the way kind fails when the container runtime does not answer, and the file STUB_KIND_CALLS counts the calls. With STUB_KIND_PAUSE,
// the stub pauses that many seconds after each name, so a reader that stops at the first match closes the pipe before the next write.
const stubKindFlaky = `#!/usr/bin/env bash
[[ "$*" == "get clusters" ]] || exit 2
n=$(($(cat "$STUB_KIND_CALLS" 2>/dev/null || echo 0) + 1))
echo "$n" >"$STUB_KIND_CALLS"
((n > ${STUB_KIND_FAILS:-0})) || { echo "ERROR: failed to list clusters: command \"docker ps\" failed with error: exit status 1" >&2; exit 1; }
for name in ${STUB_KIND:-dev-cell-1 dev-cp management dev-cell-2 rogue}; do
  printf '%s\n' "$name"
  [[ -z "${STUB_KIND_PAUSE:-}" ]] || sleep "$STUB_KIND_PAUSE"
done
`

// writeFlakyKind replaces the kind stub of a test root with stubKindFlaky, and returns the environment that points the stub at its
// call counter. KIND_CLUSTERS_PAUSE=0 keeps the retries of kind_clusters fast.
func writeFlakyKind(t *testing.T, bin string) []string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(bin, "kind"), []byte(stubKindFlaky), 0o755); err != nil {
		t.Fatal(err)
	}
	return []string{"STUB_KIND_CALLS=" + filepath.Join(t.TempDir(), "kind-calls"), "KIND_CLUSTERS_PAUSE=0"}
}

func kindCalls(t *testing.T, env []string) string {
	t.Helper()
	for _, e := range env {
		if f, ok := strings.CutPrefix(e, "STUB_KIND_CALLS="); ok {
			b, _ := os.ReadFile(f)
			return strings.TrimSpace(string(b))
		}
	}
	t.Fatal("no STUB_KIND_CALLS in the environment")
	return ""
}

// TestKindClusters: kind_clusters prints the clusters that kind lists. It retries a failing kind, and when kind keeps failing, it
// returns 1 with the error of kind on standard error, never an empty list.
func TestKindClusters(t *testing.T) {
	testtool.Need(t, "yq", "bash")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, env ...string) (string, string, []string, error) {
		t.Helper()
		return runLibFlaky(t, lib, "kind_clusters", env...)
	}
	const all = "dev-cell-1\ndev-cp\nmanagement\ndev-cell-2\nrogue\n"
	t.Run("kind answers", func(t *testing.T) {
		out, errOut, env, err := run(t)
		if err != nil || out != all || kindCalls(t, env) != "1" {
			t.Fatalf("err %v, stdout %q, stderr %q, calls %s; want the five clusters from one call", err, out, errOut, kindCalls(t, env))
		}
	})
	for _, tries := range []string{"0", "-1", "abc", "2x"} {
		t.Run("KIND_CLUSTERS_TRIES="+tries+" gives the default of 3 calls", func(t *testing.T) {
			out, errOut, env, err := run(t, "STUB_KIND_FAILS=99", "KIND_CLUSTERS_TRIES="+tries)
			if err == nil || out != "" || !strings.Contains(errOut, "kind get clusters failed 3 times") || kindCalls(t, env) != "3" {
				t.Fatalf("err %v, stdout %q, stderr %q, calls %s; want 3 calls and a failure that names kind", err, out, errOut, kindCalls(t, env))
			}
		})
	}
	t.Run("KIND_CLUSTERS_TRIES=1 gives one call", func(t *testing.T) {
		_, errOut, env, err := run(t, "STUB_KIND_FAILS=99", "KIND_CLUSTERS_TRIES=1")
		if err == nil || !strings.Contains(errOut, "kind get clusters failed 1 times") || kindCalls(t, env) != "1" {
			t.Fatalf("err %v, stderr %q, calls %s; want one call", err, errOut, kindCalls(t, env))
		}
	})
	t.Run("kind fails once", func(t *testing.T) {
		out, errOut, env, err := run(t, "STUB_KIND_FAILS=1")
		if err != nil || out != all || kindCalls(t, env) != "2" {
			t.Fatalf("err %v, stdout %q, stderr %q, calls %s; want the five clusters from the second call", err, out, errOut, kindCalls(t, env))
		}
	})
	t.Run("kind keeps failing", func(t *testing.T) {
		out, errOut, env, err := run(t, "STUB_KIND_FAILS=99")
		if err == nil || out != "" || !strings.Contains(errOut, "kind get clusters failed 3 times") || !strings.Contains(errOut, `command "docker ps" failed`) {
			t.Fatalf("err %v, stdout %q, stderr %q; want a failure that names kind and gives its error", err, out, errOut)
		}
		if got := kindCalls(t, env); got != "3" {
			t.Errorf("kind ran %s times, want 3", got)
		}
	})
	t.Run("no cluster", func(t *testing.T) {
		out, errOut, _, err := run(t, "STUB_KIND= ")
		if err != nil || out != "" || errOut != "" {
			t.Fatalf("err %v, stdout %q, stderr %q; want an empty list and no error", err, out, errOut)
		}
	})
}

// TestUpKindListing: up.sh reads the whole list of kind before it looks for the cluster, so a kind that SIGPIPE ends is never an
// absent cell. It retries a failing kind, and when kind keeps failing, it stops with the error of kind and not with cell_needs_step.
// The same holds for the check of HARNESS_ONLY.
func TestUpKindListing(t *testing.T) {
	t.Run("kind writes the cell first and pauses", func(t *testing.T) {
		root, logFile := upRoot(t)
		env := append(writeFlakyKind(t, filepath.Join(root, "bin")), "STUB_KIND_PAUSE=0.2")
		_, calls := runUp(t, root, logFile, env...)
		if !strings.Contains(calls, " create -f -") {
			t.Errorf("up.sh did not reach the bootstrap state:\n%s", calls)
		}
	})
	t.Run("kind fails once", func(t *testing.T) {
		root, logFile := upRoot(t)
		env := append(writeFlakyKind(t, filepath.Join(root, "bin")), "STUB_KIND_FAILS=1")
		_, calls := runUp(t, root, logFile, env...)
		if !strings.Contains(calls, " create -f -") || kindCalls(t, env) != "2" {
			t.Errorf("kind ran %s times; want 2 and a run to the bootstrap state:\n%s", kindCalls(t, env), calls)
		}
	})
	t.Run("kind keeps failing", func(t *testing.T) {
		root, logFile := upRoot(t)
		env := append(writeFlakyKind(t, filepath.Join(root, "bin")), "STUB_KIND_FAILS=99")
		out, calls, err := runUpErr(t, root, logFile, env...)
		if err == nil || strings.Contains(out, "cell_needs_step") || !strings.Contains(out, "kind get clusters failed 3 times") ||
			!strings.Contains(out, `command "docker ps" failed`) || !strings.Contains(out, "cell:up cannot tell whether the cluster dev-cell-1 exists") {
			t.Fatalf("err %v, output:\n%s\nwant a stop that names the kind failure", err, out)
		}
		if strings.Contains(calls, "hostsvc") || strings.Contains(calls, "apply") {
			t.Errorf("up.sh went on after the kind failure:\n%s", calls)
		}
	})
	t.Run("a cell that kind does not list needs a step", func(t *testing.T) {
		root, logFile := upRoot(t)
		env := append(writeFlakyKind(t, filepath.Join(root, "bin")), "STUB_KIND=management dev-cp rogue")
		out, _, err := runUpErr(t, root, logFile, env...)
		if err == nil || !strings.Contains(out, "cell_needs_step: cell dev-cell-1 has no cluster") {
			t.Fatalf("err %v, output:\n%s\nwant cell_needs_step", err, out)
		}
	})
	t.Run("HARNESS_ONLY: kind writes the cluster first and pauses", func(t *testing.T) {
		root, logFile := harnessOnlyRoot(t)
		env := append(writeFlakyKind(t, filepath.Join(root, "bin")), "HARNESS_ONLY=envd", "STUB_KIND=dev-cp management rogue", "STUB_KIND_PAUSE=0.2")
		out, log, err := runHarnessOnly(t, root, logFile, "up.sh", env...)
		if err != nil || !strings.Contains(log, "render envd") {
			t.Fatalf("err %v, output:\n%s\ncalls:\n%s", err, out, log)
		}
	})
	t.Run("HARNESS_ONLY: kind keeps failing", func(t *testing.T) {
		root, logFile := harnessOnlyRoot(t)
		env := append(writeFlakyKind(t, filepath.Join(root, "bin")), "HARNESS_ONLY=envd", "STUB_KIND_FAILS=99")
		out, log, err := runHarnessOnly(t, root, logFile, "up.sh", env...)
		if err == nil || strings.Contains(out, "does not exist") || !strings.Contains(out, "kind get clusters failed 3 times") ||
			!strings.Contains(out, "HARNESS_ONLY cannot tell whether the cluster dev-cp exists") || strings.Contains(log, "apply") {
			t.Fatalf("err %v, output:\n%s\ncalls:\n%s\nwant a stop that names the kind failure", err, out, log)
		}
	})
}

// runUpErr runs up.sh like runUp, and returns its error instead of failing the test.
func runUpErr(t *testing.T, root, logFile string, env ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "up.sh"))
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "CELL_UP_SKIP_LINK=1", "UP_WAIT=20", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + logFile,
		"STUB_CREATED=" + filepath.Join(root, "created.json"), "STUB_APPLIED=" + filepath.Join(root, "applied")}, env...)
	out, err := cmd.CombinedOutput()
	calls, _ := os.ReadFile(logFile)
	return string(out), string(calls), err
}

// runLibFlaky sources scripts/lib.sh with the live stubs and stubKindFlaky on PATH, and runs call.
func runLibFlaky(t *testing.T, lib, call string, env ...string) (string, string, []string, error) {
	t.Helper()
	bin := t.TempDir()
	writeLiveStubs(t, bin)
	env = append(writeFlakyKind(t, bin), env...)
	cmd := exec.Command("bash", "-c", `source "$1"; `+call, "_", lib)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cp",
		"POC_BUILD_ROOT=" + t.TempDir()}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return out.String(), errOut.String(), env, err
}

// TestKindCallersRetry: live_cells and existing_clusters read kind through kind_clusters, so one failed call of kind is retried, and a
// kind that keeps failing gives the error of kind and the reason of the caller.
func TestKindCallersRetry(t *testing.T) {
	testtool.Need(t, "yq", "bash")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ call, want, reason string }{
		{"live_cells", "dev-cell-1\ndev-cell-2\n", "the live cells are unknown"},
		{"existing_clusters", "management\ndev-cp\ndev-cell-1\ndev-cell-2\nrogue\n", "the existing clusters are unknown"},
	} {
		t.Run(tc.call+": kind fails once", func(t *testing.T) {
			out, errOut, env, err := runLibFlaky(t, lib, tc.call, "STUB_KIND_FAILS=1")
			if err != nil || out != tc.want || kindCalls(t, env) != "2" {
				t.Fatalf("err %v, stdout %q, stderr %q, calls %s; want %q from the second call", err, out, errOut, kindCalls(t, env), tc.want)
			}
		})
		t.Run(tc.call+": kind keeps failing", func(t *testing.T) {
			out, errOut, _, err := runLibFlaky(t, lib, tc.call, "STUB_KIND_FAILS=99")
			if err == nil || out != "" || !strings.Contains(errOut, "kind get clusters failed 3 times") || !strings.Contains(errOut, tc.reason) {
				t.Fatalf("err %v, stdout %q, stderr %q; want the error of kind and %q", err, out, errOut, tc.reason)
			}
		})
	}
}

// TestVerifyRetriesKind: cell:verify of a cell with no cluster prints the skip line and passes. One failed call of kind does not turn
// the absent cell into a run of every check.
func TestVerifyRetriesKind(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	bin := t.TempDir()
	writeLiveStubs(t, bin)
	env := writeFlakyKind(t, bin)
	for _, name := range []string{"kubectl", "mise", "curl", "oras", "helm"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/usr/bin/env bash\necho \"stub "+name+" $*\" >&2\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	verify, err := filepath.Abs("../../scripts/verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, verify)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cell-1",
		"POC_BUILD_ROOT=" + t.TempDir(), "STUB_KIND_FAILS=1", "STUB_KIND=management dev-cp dev-cell-2 rogue"}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "skipped: cell dev-cell-1 has no cluster yet") || kindCalls(t, env) != "2" {
		t.Fatalf("err %v, calls %s, output:\n%s\nwant the skip line after a second call of kind", err, kindCalls(t, env), out)
	}
}
