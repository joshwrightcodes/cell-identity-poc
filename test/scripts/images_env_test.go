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

// koImageCheck runs ko_image for the image celld in the temporary root, with a stub oras that finds every reference. It returns the reference
// from standard output, the standard error, and the error.
func koImageCheck(t *testing.T, root string) (string, string, error) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "bin", "oras"), []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1/scripts/ko-image.sh"; ko_image celld`, "bash", root)
	cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// TestImagesStampClearsKoImage: ko_image compares the Go sources with a build stamp that every successful images.sh run touches, and not with
// images.env, which keeps its time when no digest changes. A Go edit that changes no digest must therefore stop ko_image until images.sh runs, and
// one run must clear it, while images.env keeps its time for the bundle freshness rule.
func TestImagesStampClearsKoImage(t *testing.T) {
	root := imagesRoot(t)
	src := filepath.Join(root, "internal", "x", "x.go")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("package x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	envFile := imagesRun(t, root, nil)
	if _, errOut, err := koImageCheck(t, root); err != nil {
		t.Fatalf("a fresh build failed: %v\n%s", err, errOut)
	}
	// The build is old, and a Go file changed after it.
	past := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	for _, f := range []string{envFile, filepath.Join(root, "build", "images.stamp")} {
		if err := os.Chtimes(f, past, past); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	edit := past.Add(time.Hour)
	if err := os.Chtimes(src, edit, edit); err != nil {
		t.Fatal(err)
	}
	if _, errOut, err := koImageCheck(t, root); err == nil || !strings.Contains(errOut, "internal/x/x.go") || !strings.Contains(errOut, "Run mise run images again") {
		t.Fatalf("a Go edit without images.sh: err %v, stderr %q; want a failure that names the file and the command", err, errOut)
	}
	// The same digests: images.env keeps its time, and the check passes.
	imagesRun(t, root, nil)
	if info, _ := os.Stat(envFile); !info.ModTime().Equal(past) {
		t.Errorf("images.env changed with the same digests (mtime %s, want %s)", info.ModTime(), past)
	}
	if out, errOut, err := koImageCheck(t, root); err != nil || !strings.HasPrefix(out, "localhost:5001/celld@sha256:") {
		t.Fatalf("after images.sh the check failed: err %v, stdout %q, stderr %q", err, out, errOut)
	}
}

// TestImagesStampOnlyAfterAFullBuild: the stamp says that every image was built from the Go sources of that time. A run of named images, and a run
// where ko fails, leave it as it is. A missing stamp stops ko_image.
func TestImagesStampOnlyAfterAFullBuild(t *testing.T) {
	// stampedRoot is a root with a full build, and a stamp that is two hours old.
	stampedRoot := func(t *testing.T) (root, stamp string, past time.Time) {
		t.Helper()
		root = imagesRoot(t)
		imagesRun(t, root, nil)
		stamp = filepath.Join(root, "build", "images.stamp")
		past = time.Now().Add(-2 * time.Hour).Truncate(time.Second)
		if err := os.Chtimes(stamp, past, past); err != nil {
			t.Fatal(err)
		}
		return root, stamp, past
	}
	unmoved := func(t *testing.T, stamp string, past time.Time) {
		t.Helper()
		if info, err := os.Stat(stamp); err != nil || !info.ModTime().Equal(past) {
			t.Errorf("the stamp moved: %v, %v; want mtime %s", info, err, past)
		}
	}
	t.Run("a named run", func(t *testing.T) {
		root, stamp, past := stampedRoot(t)
		imagesRun(t, root, []string{"STUB_DIGEST_CELLD=b"}, "celld")
		unmoved(t, stamp, past)
	})
	t.Run("a full run where ko fails", func(t *testing.T) {
		root, stamp, past := stampedRoot(t)
		if err := os.WriteFile(filepath.Join(root, "bin", "ko"), []byte("#!/usr/bin/env bash\necho ko failed >&2\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(root, "scripts", "images.sh"))
		cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "KO_DOCKER_REPO=localhost:5001"}
		if err := cmd.Run(); err == nil {
			t.Fatal("a failed ko build succeeded")
		}
		unmoved(t, stamp, past)
	})
	t.Run("a missing stamp", func(t *testing.T) {
		root, stamp, _ := stampedRoot(t)
		src := filepath.Join(root, "internal", "x", "x.go")
		if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(src, []byte("package x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-3 * time.Hour)
		if err := os.Chtimes(src, old, old); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(stamp); err != nil {
			t.Fatal(err)
		}
		if out, errOut, err := koImageCheck(t, root); err == nil || !strings.Contains(errOut, "images.stamp") {
			t.Fatalf("a missing stamp: err %v, stdout %q, stderr %q; want a refusal that names the stamp", err, out, errOut)
		}
	})
}
