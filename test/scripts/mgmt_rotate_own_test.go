package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// copyFiles copies the files of the repository directory src into root.
func copyFiles(t *testing.T, root, src string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("../..", src, "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no files in %s: %v", src, err)
	}
	if err := os.MkdirAll(filepath.Join(root, src), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil || info.IsDir() {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, src, filepath.Base(f)), b, info.Mode()); err != nil {
			t.Fatal(err)
		}
	}
}

// The trust bundle of the principal sidecar in management is a copy of the root. A rotation must
// refresh it with cell:link, never with cell:up of management, at the prepare and after the revoke,
// so a new principal pod attests under the new root. Without a refresh the run stops before the
// activate.
func TestRotateCARefreshesTheSidecarBundle(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refresh bool
	}{{"refreshed", true}, {"stale", false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRotateServer(t)
			root := t.TempDir()
			for _, d := range []string{"scripts", "cells", "harness"} {
				copyFiles(t, root, d)
			}
			refreshLog := filepath.Join(s.dir, "refresh.log")
			// cell:link renders the sidecar bundle from the live bundle, as render.sh does.
			link := `#!/usr/bin/env bash
echo "link CELL=$CELL" >>"$STUB_REFRESH_LOG"
[[ -n "${STUB_NO_REFRESH:-}" ]] && exit 0
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
			first, err := os.ReadFile(filepath.Join(s.state, "pem", s.x509[0]))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.state, "own.pem"), first, 0o644); err != nil {
				t.Fatal(err)
			}
			env := []string{"STUB_OWN_COPY=1", "STUB_PKIGEN=" + pkigen(t), "STUB_REFRESH_LOG=" + refreshLog}
			if !tc.refresh {
				env = append(env, "STUB_NO_REFRESH=1")
			}
			cmd := exec.Command(filepath.Join(root, "scripts", "mgmt-rotate-ca.sh"))
			cmd.Env = append([]string{"PATH=" + s.dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "STUB_DIR=" + s.dir, "STUB_STATE=" + s.state, "STUB_LOG=" + filepath.Join(s.dir, "calls"),
				"MGMT_ROTATE_TAINT_WAIT=0", "MGMT_ROTATE_WAIT=5", "POC_BUILD_ROOT=" + filepath.Join(root, "build")}, env...)
			out, err := cmd.CombinedOutput()
			refreshes, _ := os.ReadFile(refreshLog)
			calls, _ := os.ReadFile(filepath.Join(s.dir, "calls"))
			if !strings.Contains(string(out), "management central-view-system spire-trust-bundle-argocd-agent-principal") {
				t.Fatalf("output does not name the sidecar copy:\n%s", out)
			}
			if strings.Contains(string(refreshes), "up ") {
				t.Fatalf("the rotation ran cell:up of management:\n%s", refreshes)
			}
			if !tc.refresh {
				if err == nil || count(string(calls), "activate") > 0 || !strings.Contains(string(out), "still differ from the bundle") {
					t.Fatalf("err %v, calls:\n%s\noutput:\n%s\nwant a stop before the activate", err, calls, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("rotation failed: %v\n%s", err, out)
			}
			if got := strings.Count(string(refreshes), "link CELL=management"); got != 2 {
				t.Fatalf("cell:link ran %d times, want 2 (prepare and revoke):\n%s", got, refreshes)
			}
			s.rotated(t, s.x509[1], "j2")
			own, _ := os.ReadFile(filepath.Join(s.state, "own.pem"))
			want, _ := os.ReadFile(filepath.Join(s.state, "pem", s.x509[1]))
			if string(own) != string(want) {
				t.Fatalf("the sidecar bundle holds %d bytes, want only the new root", len(own))
			}
		})
	}
}
