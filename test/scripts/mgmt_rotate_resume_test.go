package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// resumeRun runs mgmt:rotate-ca in a copy of the scripts whose cell:link rewrites the sidecar bundle
// of management from the bundle of the fake server, and whose cell:up fails. The sidecar bundle
// starts with the fake root certificates at the indexes in ownRoots. It returns the output,
// the spire-server calls, the refresh log and the final content of the sidecar bundle.
func (s *rotateServer) resumeRun(t *testing.T, ownRoots ...int) (out, calls, refreshes, own string, err error) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	refreshLog := filepath.Join(s.dir, "refresh.log")
	link := `#!/usr/bin/env bash
echo "link CELL=$CELL" >>"$STUB_REFRESH_LOG"
while read -r i t; do cat "$STUB_STATE/pem/$i"; done <"$STUB_STATE/x509.bundle" >"$STUB_STATE/own.pem"
`
	up := "#!/usr/bin/env bash\necho \"up CELL=$CELL\" >>\"$STUB_REFRESH_LOG\"\nexit 1\n"
	for name, body := range map[string]string{"scripts/link.sh": link, "scripts/up.sh": up} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mise := "#!/usr/bin/env bash\n[[ \"$1 $2 $3\" == \"run pki --\" ]] || { echo \"unexpected mise call: $*\" >&2; exit 2; }\nshift 3\nexec \"$STUB_PKIGEN\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(s.dir, "mise"), []byte(mise), 0o755); err != nil {
		t.Fatal(err)
	}
	var held []byte
	for _, i := range ownRoots {
		b, err := os.ReadFile(filepath.Join(s.state, "pem", s.x509[i]))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, b...)
	}
	if err := os.WriteFile(filepath.Join(s.state, "own.pem"), held, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(root, "scripts", "mgmt-rotate-ca.sh"))
	cmd.Env = []string{"PATH=" + s.dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=management", "STUB_DIR=" + s.dir, "STUB_STATE=" + s.state, "STUB_LOG=" + filepath.Join(s.dir, "calls"),
		"MGMT_ROTATE_TAINT_WAIT=0", "MGMT_ROTATE_WAIT=5", "POC_BUILD_ROOT=" + filepath.Join(root, "build"),
		"HOSTSVC_SERVE=" + filepath.Join(s.dir, "hostsvc-serve"), "STUB_OWN_COPY=1", "STUB_PKIGEN=" + pkigen(t), "STUB_REFRESH_LOG=" + refreshLog}
	b, err := cmd.CombinedOutput()
	r, _ := os.ReadFile(refreshLog)
	c, _ := os.ReadFile(filepath.Join(s.dir, "calls"))
	o, _ := os.ReadFile(filepath.Join(s.state, "own.pem"))
	return string(b), string(c), string(r), string(o), err
}

// afterStep4 puts the fake server in the state of a rotation that stopped in step 5: the new
// authorities are active, the bundle holds only them, and the old slot is empty or lists the old
// authorities as revoked.
func (s *rotateServer) afterStep4(t *testing.T, oldSlot string) {
	t.Helper()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(s.state, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("x509.active", s.x509[1]+"\n")
	write("x509.bundle", s.x509[1]+" false\n")
	write("x509.pool", s.x509[2]+"\n")
	write("jwt.active", "j2\n")
	write("jwt.bundle", "j2 false\n")
	write("jwt.pool", "j3\n")
	write("x509.next", s.x509[0]+"\n")
	write("jwt.next", "j1\n")
	write("x509.status", oldSlot+"\n")
	write("jwt.status", oldSlot+"\n")
}

// After a stop in step 5 the old slot is empty, or lists revoked authorities, and a copy still holds
// the old root. The run then does only the refresh. It never prepares, because that starts a new
// rotation.
func TestRotateCAResumesTheRefreshAfterTheRevoke(t *testing.T) {
	t.Parallel()
	for _, oldSlot := range []string{"", "old"} {
		t.Run("old slot "+oldSlot, func(t *testing.T) {
			s := newRotateServer(t)
			s.afterStep4(t, oldSlot)
			out, calls, refreshes, own, err := s.resumeRun(t, 0, 1)
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 3 {
				t.Fatalf("the resume exited with %v, want status 3, which says that nothing rotated\n%s", err, out)
			}
			if !strings.Contains(out, "NO NEW CA") {
				t.Fatalf("the last line does not say that no rotation happened:\n%s", out)
			}
			for _, verb := range []string{"prepare", "activate", "taint", "revoke"} {
				if n := count(calls, verb); n > 0 {
					t.Fatalf("the run called %s %d times, want only the refresh:\n%s", verb, n, calls)
				}
			}
			s.rotated(t, s.x509[1], "j2")
			if got := strings.Count(refreshes, "link CELL=management"); got != 1 {
				t.Fatalf("cell:link ran %d times, want 1:\n%s", got, refreshes)
			}
			want, _ := os.ReadFile(filepath.Join(s.state, "pem", s.x509[1]))
			if own != string(want) {
				t.Fatalf("the sidecar bundle holds %d bytes, want only the new root", len(own))
			}
			if !strings.Contains(out, "finishes step 5") {
				t.Fatalf("the output does not say that the run finishes step 5:\n%s", out)
			}
		})
	}
}

// A fresh start has an empty old slot too, but each copy holds only the roots of the bundle, so the
// run prepares, as it always did.
func TestRotateCAFreshStartPrepares(t *testing.T) {
	t.Parallel()
	s := newRotateServer(t)
	out, calls, refreshes, _, err := s.resumeRun(t, 0)
	if err != nil {
		t.Fatalf("rotation failed: %v\n%s", err, out)
	}
	for verb, want := range map[string]int{"prepare": 2, "activate": 2, "taint": 2, "revoke": 2} {
		if got := count(calls, verb); got != want {
			t.Fatalf("%d %s calls, want %d:\n%s", got, verb, want, calls)
		}
	}
	if got := strings.Count(refreshes, "link CELL=management"); got != 2 {
		t.Fatalf("cell:link ran %d times, want 2:\n%s", got, refreshes)
	}
	s.rotated(t, s.x509[1], "j2")
	if strings.Contains(out, "finishes step 5") {
		t.Fatalf("a fresh start says that it finishes step 5:\n%s", out)
	}
}
