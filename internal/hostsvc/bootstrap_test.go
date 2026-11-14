package hostsvc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// digestRepo makes a git repository with one tracked file under each bootstrap path.
func digestRepo(t *testing.T) string {
	t.Helper()
	testtool.Need(t, "git")
	root := t.TempDir()
	files := map[string]string{
		"bootstrap/a.yaml":    "a",
		"cells/common.env":    "c",
		"cmd/x/main.go":       "m",
		"components/c/k.yaml": "k",
		"harness/t.yaml":      "t",
		"internal/p/p.go":     "p",
		"scripts/up.sh":       "u",
		"vendor/v/v.yaml":     "v",
		"go.mod":              "mod",
		"go.sum":              "sum",
		"mise.toml":           "mise",
		"mise.lock":           "lock",
		"README.md":           "readme",
		"build/images.env":    "IMG=1\n",
	}
	for p, c := range files {
		writeRepoFile(t, root, p, c)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git("init", "-q")
	for p := range files {
		if p != "build/images.env" {
			git("add", p)
		}
	}
	git("commit", "-q", "-m", "x")
	return root
}

func writeRepoFile(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustDigest(t *testing.T, root string) (string, int) {
	t.Helper()
	sum, n, err := BootstrapDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum) != 64 || sum != strings.ToLower(sum) {
		t.Fatalf("digest %q is not 64 lowercase hex characters", sum)
	}
	return sum, n
}

func TestBootstrapDigest(t *testing.T) {
	root := digestRepo(t)
	base, n := mustDigest(t, root)
	if n != 13 {
		t.Errorf("files = %d, want 13 (12 tracked inputs and build/images.env)", n)
	}
	if again, _ := mustDigest(t, root); again != base {
		t.Fatalf("digest is not stable: %s then %s", base, again)
	}
	write := func(p, c string) func(t *testing.T, root string) {
		return func(t *testing.T, root string) { writeRepoFile(t, root, p, c) }
	}
	tests := []struct {
		name string
		do   func(t *testing.T, root string)
		same bool
	}{
		{"one_byte", write("internal/p/p.go", "q"), false},
		{"tracked_uncommitted_edit", write("scripts/up.sh", "u2"), false},
		{"vendor_file", write("vendor/v/v.yaml", "v2"), false},
		{"mise_toml", write("mise.toml", "x"), false},
		{"cmd_file", write("cmd/x/main.go", "m2"), false},
		{"bootstrap_file", write("bootstrap/a.yaml", "a2"), false},
		{"images_env", write("build/images.env", "IMG=2\n"), false},
		{"untracked_ignored", write("internal/p/new.go", "new"), true},
		{"ds_store_ignored", write("cells/.DS_Store", "junk"), true},
		{"outside_file", write("README.md", "changed"), true},
		{"deleted_tracked", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "components/c/k.yaml")); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := digestRepo(t)
			orig, _ := mustDigest(t, root)
			tc.do(t, root)
			got, _ := mustDigest(t, root)
			if tc.same && got != orig {
				t.Errorf("digest changed, want it unchanged")
			}
			if !tc.same && got == orig {
				t.Errorf("digest did not change")
			}
		})
	}
	t.Run("deleted_line", func(t *testing.T) {
		root := digestRepo(t)
		_ = os.Remove(filepath.Join(root, "components/c/k.yaml"))
		sum, _ := mustDigest(t, root)
		want := listingSum(t, root, map[string]string{"components/c/k.yaml": "deleted"})
		if sum != want {
			t.Errorf("digest = %s, want the listing with a deleted line (%s)", sum, want)
		}
	})
	t.Run("stable_order", func(t *testing.T) {
		// The listing is sorted by byte order whatever order git lists the files in.
		root := digestRepo(t)
		sum, _ := mustDigest(t, root)
		if want := listingSum(t, root, nil); sum != want {
			t.Errorf("digest = %s, want the sorted listing %s", sum, want)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := digestRepo(t)
		if err := os.Remove(filepath.Join(root, "scripts/up.sh")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../go.mod", filepath.Join(root, "scripts/up.sh")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := BootstrapDigest(root); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("error = %v, want a symbolic link error", err)
		}
	})
	t.Run("missing_images_env", func(t *testing.T) {
		root := digestRepo(t)
		if err := os.Remove(filepath.Join(root, "build/images.env")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := BootstrapDigest(root); err == nil {
			t.Error("no error for a missing build/images.env")
		}
	})
	t.Run("large_file", func(t *testing.T) {
		root := digestRepo(t)
		writeRepoFile(t, root, "internal/p/p.go", strings.Repeat("x", 4<<20+1))
		if _, _, err := BootstrapDigest(root); err == nil {
			t.Error("no error for a file above 4 MiB")
		}
		writeRepoFile(t, root, "internal/p/p.go", strings.Repeat("x", 4<<20))
		if _, _, err := BootstrapDigest(root); err != nil {
			t.Errorf("a file of exactly 4 MiB: %v", err)
		}
	})
	t.Run("not_a_repository", func(t *testing.T) {
		if _, _, err := BootstrapDigest(t.TempDir()); err == nil {
			t.Error("no error outside a git repository")
		}
	})
}

// listingSum builds the expected listing by hand. override maps a path to "deleted".
func listingSum(t *testing.T, root string, override map[string]string) string {
	t.Helper()
	paths := []string{"build/images.env", "bootstrap/a.yaml", "cells/common.env", "cmd/x/main.go", "components/c/k.yaml",
		"harness/t.yaml", "internal/p/p.go", "scripts/up.sh", "vendor/v/v.yaml", "go.mod", "go.sum", "mise.toml", "mise.lock"}
	slices.Sort(paths)
	h := sha256.New()
	for _, p := range paths {
		if override[p] == "deleted" {
			fmt.Fprintf(h, "deleted  %s\n", p)
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h, "%x  %s\n", sha256.Sum256(b), p)
	}
	return hex.EncodeToString(h.Sum(nil))
}
