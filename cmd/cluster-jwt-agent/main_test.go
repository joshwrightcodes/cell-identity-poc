package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStderr(t *testing.T) func() string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = f
	t.Cleanup(func() { os.Stderr = old })
	return func() string {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

func fakeExe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plugin-binary")
	if err := os.WriteFile(p, []byte("binary bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	return func() string { return p }()
}

func TestInstallCopiesExecutable(t *testing.T) {
	src := fakeExe(t)
	dir := t.TempDir()
	stderr := captureStderr(t)
	var out bytes.Buffer
	if code := runCLI([]string{"install", dir}, &out, func() (string, error) { return src, nil }); code != 0 {
		t.Fatalf("code = %d, stdout %q", code, out.String())
	}
	dst := filepath.Join(dir, "cluster-jwt-agent")
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "binary bytes" {
		t.Fatalf("copy = %q, err %v", got, err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 != 0o111 {
		t.Fatalf("mode = %v, want executable", fi.Mode())
	}
	if out.Len() != 0 || stderr() != "" {
		t.Fatalf("stdout %q, stderr %q", out.String(), stderr())
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(left) != 1 {
		t.Fatalf("directory holds %v", left)
	}
}

func TestInstallReplacesExistingFile(t *testing.T) {
	src := fakeExe(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cluster-jwt-agent"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runCLI([]string{"install", dir}, &bytes.Buffer{}, func() (string, error) { return src, nil }); code != 0 {
		t.Fatalf("code = %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "cluster-jwt-agent"))
	if string(got) != "binary bytes" {
		t.Fatalf("copy = %q", got)
	}
}

func TestFailuresAreOneJSONLineOnStdout(t *testing.T) {
	src := fakeExe(t)
	exe := func() (string, error) { return src, nil }
	readOnly := t.TempDir()
	if err := os.Chmod(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })
	cases := map[string][]string{
		"bogus flag":    {"install", "--bogus"},
		"help":          {"install", "-h"},
		"no directory":  {"install"},
		"two arguments": {"install", "a", "b"},
		"unknown":       {"frobnicate"},
		"missing dir":   {"install", filepath.Join(t.TempDir(), "absent")},
		"read-only dir": {"install", readOnly},
	}
	if os.Geteuid() == 0 {
		delete(cases, "read-only dir")
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			stderr := captureStderr(t)
			var out bytes.Buffer
			if code := runCLI(args, &out, exe); code == 0 {
				t.Fatal("expected a non-zero exit code")
			}
			lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("want one line, got %q", out.String())
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
				t.Fatalf("stdout is not JSON: %v", err)
			}
			if m["level"] != "ERROR" || m["error"] == nil || m["error"] == "" {
				t.Fatalf("unexpected line %v", m)
			}
			if got := stderr(); got != "" {
				t.Fatalf("stderr = %q", got)
			}
		})
	}
}
