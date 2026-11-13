package mgmt

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ed25519.key")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	key, created, err := LoadOrCreateKey(path)
	if err != nil || !created {
		t.Fatalf("first call: created %v, err %v", created, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o400 {
		t.Fatalf("key file mode %o, want 0400", got)
	}

	again, created, err := LoadOrCreateKey(path)
	if err != nil || created {
		t.Fatalf("second call: created %v, err %v", created, err)
	}
	if !key.Equal(again) {
		t.Fatal("the second call returned another key")
	}

	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("directory holds %d files, want only the key", len(entries))
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("a key file with mode 0644 is accepted")
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("a key file readable by the group is accepted")
	}
}

func TestLoadOrCreateKeyRefusesJunk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(path, []byte("not a pem"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("a file that is not a key is accepted")
	}
}

func TestWriteKeyReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	first, _, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	_, second, _ := ed25519.GenerateKey(nil)
	if err := WriteKey(path, second); err != nil {
		t.Fatal(err)
	}
	got, created, err := LoadOrCreateKey(path)
	if err != nil || created || !got.Equal(second) || got.Equal(first) {
		t.Fatalf("after WriteKey: created %v, err %v, equal to new %v", created, err, got.Equal(second))
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("mode %o after replace", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("directory holds %d files after replace", len(entries))
	}
}
