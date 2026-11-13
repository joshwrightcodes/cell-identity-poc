package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var resetNow = func() time.Time { return time.Unix(1700000000, 0) }

func TestResetStateMovesBothFilesAside(t *testing.T) {
	dir := t.TempDir()
	for n, body := range map[string]string{"state.json": `{"bad":`, "ed25519.key": "KEY"} {
		must(t, os.WriteFile(filepath.Join(dir, n), []byte(body), 0o400))
	}
	var out bytes.Buffer
	if code := resetCommand([]string{"--data-dir", dir}, &out, resetNow); code != 0 {
		t.Fatalf("code %d: %s", code, out.String())
	}
	var res struct{ Moved []movedFile }
	if strings.Count(out.String(), "\n") != 1 || json.Unmarshal(out.Bytes(), &res) != nil || len(res.Moved) != 2 {
		t.Fatalf("output %q", out.String())
	}
	for n, body := range map[string]string{"state.json": `{"bad":`, "ed25519.key": "KEY"} {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Fatalf("%s still in place: %v", n, err)
		}
		b, err := os.ReadFile(filepath.Join(dir, n+".reset-1700000000"))
		if err != nil || string(b) != body {
			t.Fatalf("%s moved content %q, err %v", n, b, err)
		}
	}
}

func TestResetStateSkipsAbsentFilesAndKeepsOthers(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "state.json"), []byte("{}"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "state.json.corrupt-1"), []byte("old"), 0o600))
	moved, err := resetState(dir, resetNow())
	if err != nil || len(moved) != 1 {
		t.Fatalf("moved %v, err %v", moved, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json.corrupt-1")); err != nil {
		t.Fatal("an earlier moved file was touched")
	}
	moved, err = resetState(dir, resetNow())
	if err != nil || len(moved) != 0 {
		t.Fatalf("a second run moved %v, err %v", moved, err)
	}
}

func TestResetStateErrorsPrintOneJSONLine(t *testing.T) {
	var out bytes.Buffer
	if code := resetCommand([]string{"--data-dir", filepath.Join(t.TempDir(), "absent")}, &out, resetNow); code != 1 {
		t.Fatalf("code %d", code)
	}
	var rec map[string]any
	if strings.Count(out.String(), "\n") != 1 || json.Unmarshal(out.Bytes(), &rec) != nil || rec["level"] != "ERROR" {
		t.Fatalf("output %q", out.String())
	}
	out.Reset()
	if code := resetCommand([]string{"--bogus"}, &out, resetNow); code != exitConfig || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("code %d, output %q", code, out.String())
	}
}

func TestResetStateRefusesAnExistingTarget(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "state.json"), []byte("{}"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "state.json.reset-1700000000"), []byte("x"), 0o600))
	if _, err := resetState(dir, resetNow()); err == nil {
		t.Fatal("an existing target was overwritten")
	}
}

// A staged key that survives a reset would become a trusted signer of the new state (B-02), so reset
// moves it aside with the stamp of the other files.
func TestResetStateMovesTheStagedKeyAside(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{"state.json": "{}", "ed25519.key": "KEY", "ed25519.next.key": "NEXT"}
	for n, body := range files {
		must(t, os.WriteFile(filepath.Join(dir, n), []byte(body), 0o400))
	}
	moved, err := resetState(dir, resetNow())
	if err != nil || len(moved) != 3 {
		t.Fatalf("moved %v, err %v", moved, err)
	}
	for n, body := range files {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Fatalf("%s still in place: %v", n, err)
		}
		if b, err := os.ReadFile(filepath.Join(dir, n+".reset-1700000000")); err != nil || string(b) != body {
			t.Fatalf("%s moved content %q, err %v", n, b, err)
		}
	}
	// With no staged key, the reset moves the other two files and finds nothing to complain about.
	dir = t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "state.json"), []byte("{}"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "ed25519.key"), []byte("KEY"), 0o400))
	if moved, err = resetState(dir, resetNow()); err != nil || len(moved) != 2 {
		t.Fatalf("moved %v, err %v", moved, err)
	}
}
