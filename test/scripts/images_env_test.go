package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// imagesRun runs scripts/images.sh in a temporary root with a stub ko that prints the reference <repo>/<name>@sha256:<STUB_DIGEST of the name, or 64 a>
// for each path that it gets. It returns the path of build/images.env.
func imagesRun(t *testing.T, root string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "images.sh"), args...)
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "KO_DOCKER_REPO=localhost:5001"}, env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("images.sh %v: %v\n%s", args, err, out)
	}
	return filepath.Join(root, "build", "images.env")
}

func imagesRoot(t *testing.T) string {
	t.Helper()
	testtool.Need(t, "bash")
	root := t.TempDir()
	copyFiles(t, root, "scripts")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	ko := `#!/usr/bin/env bash
# ko build --base-import-paths --tags latest ./cmd/<name>...: one reference for each path. STUB_DIGEST_<NAME> (upper case, - as _) sets the hex digit.
shift 4
for p in "$@"; do
  n="${p##*/}"; v="STUB_DIGEST_$(tr 'a-z-' 'A-Z_' <<<"$n")"; d="${!v:-a}"
  printf 'localhost:5001/%s@sha256:%s\n' "$n" "$(printf "%64s" "" | tr ' ' "$d")"
done
`
	if err := os.WriteFile(filepath.Join(bin, "ko"), []byte(ko), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestImagesEnvChangesOnlyWithADigest: images.env is an input of the render, and the publish refuses a build that is older than its inputs, so the
// file must keep its time when a run builds the same digests. Only the lines of images count: the note of the commit changes with every commit.
// A changed digest replaces the file.
func TestImagesEnvChangesOnlyWithADigest(t *testing.T) {
	root := imagesRoot(t)
	file := imagesRun(t, root, nil)
	first, _ := os.ReadFile(file)
	if !strings.Contains(string(first), "IMAGE_CELLD=localhost:5001/celld@sha256:"+strings.Repeat("a", 64)) {
		t.Fatalf("images.env is %q", first)
	}
	old := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	// A note from another commit, and the same digests.
	body := strings.Replace(string(first), "# commit", "# commit 0123abc and", 1)
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	imagesRun(t, root, nil)
	got, _ := os.ReadFile(file)
	info, _ := os.Stat(file)
	if string(got) != body || !info.ModTime().Equal(old) {
		t.Errorf("a run with the same digests changed the file (mtime %s, want %s)", info.ModTime(), old)
	}
	// A run of named images with the same digests keeps it too.
	imagesRun(t, root, nil, "celld")
	if info, _ = os.Stat(file); !info.ModTime().Equal(old) {
		t.Errorf("a named run with the same digest changed the file (mtime %s)", info.ModTime())
	}
	// A changed digest replaces the file, and only that line moves.
	imagesRun(t, root, []string{"STUB_DIGEST_CELLD=b"}, "celld")
	got, _ = os.ReadFile(file)
	info, _ = os.Stat(file)
	if !strings.Contains(string(got), "IMAGE_CELLD=localhost:5001/celld@sha256:"+strings.Repeat("b", 64)) || !strings.Contains(string(got), "IMAGE_MGMTD=localhost:5001/mgmtd@sha256:"+strings.Repeat("a", 64)) || !info.ModTime().After(old) {
		t.Errorf("a changed digest did not replace the file: %q (mtime %s)", got, info.ModTime())
	}
	// A full run with another digest replaces it as well.
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	imagesRun(t, root, []string{"STUB_DIGEST_MGMTD=c"})
	got, _ = os.ReadFile(file)
	if info, _ = os.Stat(file); !strings.Contains(string(got), "IMAGE_MGMTD=localhost:5001/mgmtd@sha256:"+strings.Repeat("c", 64)) || !info.ModTime().After(old) {
		t.Errorf("a full run with a changed digest left the file: %q", got)
	}
	// No temporary file stays.
	if left, _ := filepath.Glob(filepath.Join(root, "build", ".images.env.*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}
