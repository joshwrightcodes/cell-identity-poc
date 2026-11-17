package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// downRoot is a harness root for scripts/down.sh. The fake mise logs each call with the cluster and whether the lock of dev-cell-1
// is held at that moment. The fake host service script logs each call: status says that the service runs unless STUB_HOST_DOWN
// is set, steps answers the journal in $STUB_STEPS (a file), and cancel succeeds.
func downRoot(t *testing.T) (root, calls string) {
	t.Helper()
	root, calls = harnessRoot(t)
	write := func(path, content string) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("bin/mise", `#!/usr/bin/env bash
lock=free; [[ -d "$POC_BUILD_ROOT/locks/dev-cell-1.lock" ]] && lock=held
echo "mise $* | CELL=${CELL:-} lock=$lock" >>"$STUB_LOG"
`)
	write("bin/hostsvc-serve", `#!/usr/bin/env bash
echo "hostsvc-serve $*" >>"$STUB_LOG"
case "$1" in
  status) [[ -z "${STUB_STATUS_FAIL:-}" ]] || exit 1
    if [[ -n "${STUB_HOST_DOWN:-}" ]]; then echo '{"running":false}'; else echo '{"running":true}'; fi ;;
  steps) [[ -z "${STUB_STEPS_FAIL:-}" ]] || exit 1
    if [[ -s "${STUB_STEPS:-/nonexistent}" ]]; then cat "$STUB_STEPS"; else echo '{"steps":[],"corrupt":false}'; fi ;;
esac
`)
	write("bin/portal", `#!/usr/bin/env bash
echo "portal $*" >>"$STUB_LOG"
case "${STUB_PORTAL:-ok}" in
  ok) echo '{"requestId":"r","revision":{"epoch":1,"counter":2}}' ;;
  no_step) echo '{"level":"ERROR","msg":"portal failed","error":"no_step","reason":"no_step"}'; exit 1 ;;
  restore_active) echo '{"level":"ERROR","msg":"portal failed","error":"restore_active","reason":"restore_active"}'; exit 1 ;;
  unreachable) echo "mise run mgmt -- portal failed: connection refused" >&2; exit 1 ;;
esac
`)
	return root, calls
}

func runDown(t *testing.T, root, calls string, env ...string) (log, errOut string, err error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "down.sh"))
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + calls,
		"HOSTSVC_SERVE=" + filepath.Join(root, "bin", "hostsvc-serve"), "PORTAL_SH=" + filepath.Join(root, "bin", "portal"), "CELL_DOWN_POLL=0.2", "CELL_DOWN_WAIT=2"}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	b, _ := os.ReadFile(calls)
	return string(b), out.String(), err
}

// TestCellDownRerenders: cell:down cancels the step of the cell at the host service, waits until no step of the cell runs a stage,
// takes the lock, deletes the cluster, releases the lock, and then renders dev-cp and links management so that their lists drop
// the node. With a stage still running after the wait, it stops and names hostsvc:serve -- cancel.
func TestCellDownRerenders(t *testing.T) {
	t.Run("order", func(t *testing.T) {
		root, calls := downRoot(t)
		if err := os.MkdirAll(filepath.Join(root, "build", "dev-cell-1"), 0o755); err != nil {
			t.Fatal(err)
		}
		log, errOut, err := runDown(t, root, calls)
		if err != nil {
			t.Fatalf("down.sh failed: %v\n%s\n%s", err, errOut, log)
		}
		var got []string
		for _, l := range strings.Split(strings.TrimSpace(log), "\n") {
			if !strings.HasPrefix(l, "hostsvc-serve steps") && !strings.HasPrefix(l, "hostsvc-serve status") {
				got = append(got, l)
			}
		}
		want := []string{
			"hostsvc-serve cancel --cell dev-cell-1",
			"mise run hostsvc -- down --only dev-cell-1 | CELL=dev-cell-1 lock=held",
			"mise run cell:up | CELL=dev-cp lock=free",
			"mise run cell:link | CELL=management lock=free",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("calls\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		if _, err := os.Stat(filepath.Join(root, "build", "dev-cell-1")); err == nil {
			t.Error("down.sh left build/dev-cell-1")
		}
		if _, err := os.Stat(filepath.Join(root, "build", "locks", "dev-cell-1.lock")); err == nil {
			t.Error("down.sh left the lock")
		}
		// The cancel comes before the first read of the steps that waits for it.
		if i, j := strings.Index(log, "cancel --cell"), strings.Index(log, "hostsvc-serve steps"); i < 0 || j < i {
			t.Errorf("the wait reads the steps before the cancel:\n%s", log)
		}
	})

	t.Run("a running stage after the wait stops it", func(t *testing.T) {
		root, calls := downRoot(t)
		steps := filepath.Join(root, "steps.json")
		doc := `{"steps":[{"id":"` + strings.Repeat("a", 32) + `","cell":"dev-cell-1","state":"admitting"},{"id":"` + strings.Repeat("b", 32) + `","cell":"dev-cell-2","state":"done"}],"corrupt":false}`
		if err := os.WriteFile(steps, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		log, errOut, err := runDown(t, root, calls, "STUB_STEPS="+steps)
		if err == nil || !strings.Contains(errOut, "hostsvc:serve -- cancel --cell dev-cell-1") || !strings.Contains(errOut, "admitting") {
			t.Fatalf("err %v, output %q; want a failure that names hostsvc:serve -- cancel", err, errOut)
		}
		if strings.Contains(log, "hostsvc -- down") || strings.Contains(log, "cell:up") || strings.Contains(log, "cell:link") {
			t.Fatalf("down.sh went on with a stage running:\n%s", log)
		}
	})

	t.Run("a stage of another cell does not hold it", func(t *testing.T) {
		root, calls := downRoot(t)
		steps := filepath.Join(root, "steps.json")
		doc := `{"steps":[{"id":"` + strings.Repeat("b", 32) + `","cell":"dev-cell-2","state":"bootstrapping"}],"corrupt":false}`
		if err := os.WriteFile(steps, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		if log, errOut, err := runDown(t, root, calls, "STUB_STEPS="+steps); err != nil || !strings.Contains(log, "hostsvc -- down --only dev-cell-1") {
			t.Fatalf("err %v\n%s\n%s", err, errOut, log)
		}
	})

	t.Run("a running host service cancels at the host and not through mgmtd", func(t *testing.T) {
		root, calls := downRoot(t)
		log, errOut, err := runDown(t, root, calls)
		if err != nil || !strings.Contains(log, "hostsvc-serve cancel --cell dev-cell-1") || strings.Contains(log, "portal ") {
			t.Fatalf("err %v, output %q, calls\n%s; want the host cancel and no portal call", err, errOut, log)
		}
	})

	t.Run("a host service that does not run cancels through mgmtd", func(t *testing.T) {
		root, calls := downRoot(t)
		log, errOut, err := runDown(t, root, calls, "STUB_HOST_DOWN=1")
		if err != nil || !strings.Contains(log, "portal cancel --cell dev-cell-1") || strings.Contains(log, "hostsvc-serve cancel") || !strings.Contains(log, "hostsvc -- down --only dev-cell-1") {
			t.Fatalf("err %v, output %q, calls\n%s; want portal -- cancel, no host cancel, and the delete", err, errOut, log)
		}
		if i, j := strings.Index(log, "portal cancel"), strings.Index(log, "hostsvc -- down"); i < 0 || j < i {
			t.Errorf("the delete comes before the cancel:\n%s", log)
		}
	})

	t.Run("a cell without an open step needs no cancel", func(t *testing.T) {
		root, calls := downRoot(t)
		log, errOut, err := runDown(t, root, calls, "STUB_HOST_DOWN=1", "STUB_PORTAL=no_step")
		if err != nil || !strings.Contains(errOut, "no open step") || !strings.Contains(log, "hostsvc -- down --only dev-cell-1") {
			t.Fatalf("err %v, output %q, calls\n%s; want the delete after a no_step answer", err, errOut, log)
		}
	})

	t.Run("a host service that does not run and an unreachable mgmtd stop the delete", func(t *testing.T) {
		root, calls := downRoot(t)
		log, errOut, err := runDown(t, root, calls, "STUB_HOST_DOWN=1", "STUB_PORTAL=unreachable")
		if err == nil || !strings.Contains(errOut, "LINK_ONLY=mgmt-api mise run cell:link") || !strings.Contains(errOut, "cell:down again") ||
			strings.Contains(log, "hostsvc -- down") || strings.Contains(log, "cell:up") {
			t.Fatalf("err %v, output %q, calls\n%s; want a refusal with a hint, before the delete", err, errOut, log)
		}
	})

	t.Run("a restore in force names the restore command", func(t *testing.T) {
		root, calls := downRoot(t)
		log, errOut, err := runDown(t, root, calls, "STUB_HOST_DOWN=1", "STUB_PORTAL=restore_active")
		if err == nil || !strings.Contains(errOut, "mise run mgmt -- restore --revision latest") || strings.Contains(errOut, "cell:link") || strings.Contains(log, "hostsvc -- down") {
			t.Fatalf("err %v, output %q, calls\n%s; want the restore hint and no delete", err, errOut, log)
		}
	})

	t.Run("an unreadable catalog and a stopped service refuse the delete", func(t *testing.T) {
		root, calls := downRoot(t)
		if err := os.WriteFile(filepath.Join(root, "bin", "yq"), []byte("#!/usr/bin/env bash\nif [[ \"$*\" == *cell-identity* ]]; then exit 1; fi\nexec \""+yqPath(t)+"\" \"$@\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		log, errOut, err := runDown(t, root, calls, "STUB_HOST_DOWN=1")
		if err == nil || !strings.Contains(errOut, "catalog") || !strings.Contains(errOut, "hostsvc:serve -- start") || strings.Contains(log, "hostsvc -- down") || strings.Contains(log, "portal ") {
			t.Fatalf("err %v, output %q, calls\n%s; want a refusal before the delete", err, errOut, log)
		}
	})

	t.Run("a host service that does not run and a cluster that is no cell skip the cancel", func(t *testing.T) {
		root, calls := downRoot(t)
		log, errOut, err := runDown(t, root, calls, "STUB_HOST_DOWN=1", "CELL=dev-cp")
		if err != nil || strings.Contains(log, "portal ") || !strings.Contains(errOut, "not a cell") || !strings.Contains(log, "hostsvc -- down --only dev-cp") {
			t.Fatalf("err %v, output %q, calls\n%s", err, errOut, log)
		}
	})

	t.Run("a failed read of the host service stops the delete", func(t *testing.T) {
		for _, env := range []string{"STUB_STATUS_FAIL=1", "STUB_STEPS_FAIL=1"} {
			root, calls := downRoot(t)
			log, errOut, err := runDown(t, root, calls, env)
			if err == nil || !strings.Contains(errOut, "mise run hostsvc:serve -- ") || strings.Contains(log, "hostsvc -- down") || strings.Contains(log, "cell:up") {
				t.Fatalf("%s: err %v, output %q, calls\n%s; want a stop that names the read, before the delete", env, err, errOut, log)
			}
		}
	})

	t.Run("an unreadable catalog after the delete prints the re-render commands and fails", func(t *testing.T) {
		root, calls := downRoot(t)
		// A topology that does not parse makes yq fail, but only after the cell name check of lib.sh, so break it after the delete started.
		if err := os.WriteFile(filepath.Join(root, "bin", "yq"), []byte("#!/usr/bin/env bash\nif [[ \"$*\" == *cell-identity* ]]; then exit 1; fi\nexec \""+yqPath(t)+"\" \"$@\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		log, errOut, err := runDown(t, root, calls)
		if err == nil || !strings.Contains(errOut, "CELL=dev-cp mise run cell:up") || !strings.Contains(errOut, "CELL=management mise run cell:link") || !strings.Contains(log, "hostsvc -- down --only dev-cell-1") {
			t.Fatalf("err %v, output %q, calls\n%s; want the delete, the two commands and exit 1", err, errOut, log)
		}
	})

	t.Run("CELL_DOWN_SKIP_RERENDER skips the two renders", func(t *testing.T) {
		root, calls := downRoot(t)
		log, errOut, err := runDown(t, root, calls, "CELL_DOWN_SKIP_RERENDER=1")
		if err != nil || strings.Contains(log, "cell:up") || strings.Contains(log, "cell:link") || !strings.Contains(log, "hostsvc -- down --only dev-cell-1") {
			t.Fatalf("err %v, output %q, calls\n%s", err, errOut, log)
		}
	})

	t.Run("a cluster that is no cell renders nothing again", func(t *testing.T) {
		root, calls := downRoot(t)
		log, _, err := runDown(t, root, calls, "CELL=dev-cp")
		if err != nil || strings.Contains(log, "cell:up") || strings.Contains(log, "cell:link") || !strings.Contains(log, "hostsvc -- down --only dev-cp") {
			t.Fatalf("err %v, calls\n%s", err, log)
		}
	})

	t.Run("a live run on the cluster refuses the delete", func(t *testing.T) {
		root, calls := downRoot(t)
		holder(t, filepath.Join(root, "build"), "dev-cell-1", "up.sh", strings.Repeat("c", 32), 60)
		log, errOut, err := runDown(t, root, calls)
		if err == nil || !strings.Contains(errOut, "cluster dev-cell-1 is locked by process") || strings.Contains(log, "hostsvc -- down") {
			t.Fatalf("err %v, output %q, calls\n%s; want a refusal before the delete", err, errOut, log)
		}
	})
}

// yqPath returns the real yq, for a stub that fails for one query only.
func yqPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("yq")
	if err != nil {
		t.Skip("yq is not installed")
	}
	return p
}
