package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
		bin := t.TempDir()
		writeLiveStubs(t, bin)
		env = append(writeFlakyKind(t, bin), env...)
		cmd := exec.Command("bash", "-c", `source "$1"; kind_clusters`, "_", lib)
		cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cp",
			"POC_BUILD_ROOT=" + t.TempDir()}, env...)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		return out.String(), errOut.String(), env, err
	}
	const all = "dev-cell-1\ndev-cp\nmanagement\ndev-cell-2\nrogue\n"
	t.Run("kind answers", func(t *testing.T) {
		out, errOut, env, err := run(t)
		if err != nil || out != all || kindCalls(t, env) != "1" {
			t.Fatalf("err %v, stdout %q, stderr %q, calls %s; want the five clusters from one call", err, out, errOut, kindCalls(t, env))
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
