package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := execute(args, &out)
	return code, out.String()
}

func TestOutThenCheckPasses(t *testing.T) {
	dir := t.TempDir()
	if code, out := run(t, "--out", dir); code != 0 || out != "" {
		t.Fatalf("--out: code %d, output %q; want 0 and no output", code, out)
	}
	for _, p := range []string{"provider.yaml", filepath.Join("alerting", "rules.json")} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("--out wrote no %s: %v", p, err)
		}
	}
	if code, out := run(t, "--check", dir); code != 0 || out != "" {
		t.Fatalf("--check: code %d, output %q; want 0 and no output", code, out)
	}
}

func TestCheckNamesEachFileThatDiffers(t *testing.T) {
	dir := t.TempDir()
	if code, _ := run(t, "--out", dir); code != 0 {
		t.Fatalf("--out: code %d", code)
	}
	if err := os.WriteFile(filepath.Join(dir, "provider.yaml"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "alerting", "rules.json")); err != nil {
		t.Fatal(err)
	}
	code, out := run(t, "--check", dir)
	if code != 1 || out != "alerting/rules.json\nprovider.yaml\n" {
		t.Fatalf("--check: code %d, output %q; want 1 and both file names", code, out)
	}
}

func TestCheckWritesNothing(t *testing.T) {
	dir := t.TempDir()
	run(t, "--check", dir)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("--check wrote %d entries", len(entries))
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"--out", "a", "--check", "b"}, {"--bogus"}, {"--out", "a", "extra"}} {
		code, out := run(t, args...)
		if code != 2 || !strings.Contains(out, "dashgen failed") {
			t.Errorf("args %v: code %d, output %q; want 2 and an error line", args, code, out)
		}
	}
}
