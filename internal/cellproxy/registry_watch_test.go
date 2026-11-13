package cellproxy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

func atRevision(name string, epoch, counter uint64) record.Cell {
	c := cell(name, false)
	c.Epoch, c.Counter = epoch, counter
	return c
}

func TestRegistryRecordSkipsRevoked(t *testing.T) {
	pub, priv := signerKey(t)
	keys := []ed25519.PublicKey{pub}
	t.Run("highest revision wins", func(t *testing.T) {
		reg, err := LoadRegistry(writeRegistry(t, keys, priv, atRevision("dev-cell-1", 1, 3), atRevision("dev-cell-1", 2, 1), atRevision("dev-cell-1", 1, 9)))
		if err != nil {
			t.Fatal(err)
		}
		rec, ok := reg.Record("dev-cell-1")
		if !ok || rec.Epoch != 2 || rec.Counter != 1 {
			t.Fatalf("got %+v %v", rec, ok)
		}
	})
	t.Run("any revoked record hides the cell", func(t *testing.T) {
		revoked := atRevision("dev-cell-1", 1, 1)
		revoked.Revoked = true
		reg, err := LoadRegistry(writeRegistry(t, keys, priv, revoked, atRevision("dev-cell-1", 1, 5)))
		if err != nil {
			t.Fatal(err)
		}
		if rec, ok := reg.Record("dev-cell-1"); ok {
			t.Fatalf("got %+v for a cell with a revoked record", rec)
		}
	})
	t.Run("unknown cell", func(t *testing.T) {
		reg, err := LoadRegistry(writeRegistry(t, keys, priv, atRevision("dev-cell-1", 1, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := reg.Record("dev-cell-2"); ok {
			t.Fatal("a cell with no record has a record")
		}
	})
}

// watchFixture holds a registry directory, its pinned signer file and a running watcher.
type watchFixture struct {
	dir, signerFile string
	pub             ed25519.PublicKey
	priv            ed25519.PrivateKey
	w               *RegistryWatcher
	out             *syncBuffer
}

func newWatchFixture(t *testing.T, cells ...record.Cell) *watchFixture {
	t.Helper()
	f := &watchFixture{out: &syncBuffer{}}
	f.pub, f.priv = signerKey(t)
	f.dir = writeRegistry(t, []ed25519.PublicKey{f.pub}, f.priv, cells...)
	f.signerFile = filepath.Join(t.TempDir(), "signers.pub")
	copyFile(t, filepath.Join(f.dir, "signers.pub"), f.signerFile)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	w, err := WatchRegistry(ctx, f.dir, f.signerFile, 20*time.Millisecond, jsonLog(f.out))
	if err != nil {
		t.Fatal(err)
	}
	f.w = w
	return f
}

func (f *watchFixture) revision(t *testing.T, name string) (uint64, uint64) {
	t.Helper()
	rec, ok := f.w.Current().Record(name)
	if !ok {
		t.Fatalf("no record of %s", name)
	}
	return rec.Epoch, rec.Counter
}

func (f *watchFixture) waitLog(t *testing.T, msg, contains string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, l := range logLines(t, f.out) {
			e, _ := l["error"].(string)
			r, _ := l["reason"].(string)
			if l["msg"] == msg && strings.Contains(e+r, contains) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q line holding %q in:\n%s", msg, contains, f.out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *watchFixture) waitRevision(t *testing.T, name string, epoch, counter uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if rec, ok := f.w.Current().Record(name); ok && rec.Epoch == epoch && rec.Counter == counter {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the registry did not reach revision %d.%d:\n%s", epoch, counter, f.out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRegistryWatchKeepsLastGood(t *testing.T) {
	f := newWatchFixture(t, atRevision("dev-cell-1", 1, 1))
	if err := os.WriteFile(filepath.Join(f.dir, "dev-cell-1.dsse.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The error line carries no reason field, so the check reads the error text.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(f.out.String(), "registry_reload_failed") {
		if time.Now().After(deadline) {
			t.Fatalf("no registry_reload_failed line:\n%s", f.out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e, c := f.revision(t, "dev-cell-1"); e != 1 || c != 1 {
		t.Fatalf("revision %d.%d after a failed reload", e, c)
	}
	rewriteRegistry(t, f.dir, []ed25519.PublicKey{f.pub}, f.priv, atRevision("dev-cell-1", 1, 2))
	f.waitRevision(t, "dev-cell-1", 1, 2)
	if !strings.Contains(f.out.String(), `"msg":"registry reloaded"`) || !strings.Contains(f.out.String(), "content_sha256") {
		t.Fatalf("no registry reloaded line with the content hash:\n%s", f.out.String())
	}
}

func TestRegistryWatchFailsAtStart(t *testing.T) {
	pub, priv := signerKey(t)
	dir := writeRegistry(t, []ed25519.PublicKey{pub}, priv)
	signerFile := filepath.Join(t.TempDir(), "signers.pub")
	copyFile(t, filepath.Join(dir, "signers.pub"), signerFile)
	if _, err := WatchRegistry(t.Context(), dir, signerFile, time.Second, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("a registry with no record started")
	}
}

func TestRegistryWatchRefusesOtherSigner(t *testing.T) {
	f := newWatchFixture(t, atRevision("dev-cell-1", 1, 1))
	otherPub, otherPriv := signerKey(t)
	// The directory is valid under its own keys, but they are not the pinned keys.
	rewriteRegistry(t, f.dir, []ed25519.PublicKey{otherPub}, otherPriv, atRevision("dev-cell-1", 1, 2))
	f.waitLog(t, "registry_reload_failed", "signer file")
	if e, c := f.revision(t, "dev-cell-1"); e != 1 || c != 1 {
		t.Fatalf("revision %d.%d after a registry of another signer", e, c)
	}

	t.Run("at start", func(t *testing.T) {
		if _, err := WatchRegistry(t.Context(), f.dir, f.signerFile, time.Second, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "signer file") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestRegistryWatchRefusesLowerRevision(t *testing.T) {
	f := newWatchFixture(t, atRevision("dev-cell-1", 1, 5), atRevision("dev-cell-2", 1, 1))
	rewriteRegistry(t, f.dir, []ed25519.PublicKey{f.pub}, f.priv, atRevision("dev-cell-1", 1, 4), atRevision("dev-cell-2", 1, 9))
	f.waitLog(t, "registry_reload_failed", "lower revision refused")
	if e, c := f.revision(t, "dev-cell-1"); e != 1 || c != 5 {
		t.Fatalf("revision %d.%d after a lower revision", e, c)
	}
	if _, c := f.revision(t, "dev-cell-2"); c != 1 {
		t.Fatal("a refused registry was applied in part")
	}
	rewriteRegistry(t, f.dir, []ed25519.PublicKey{f.pub}, f.priv, atRevision("dev-cell-1", 2, 1), atRevision("dev-cell-2", 1, 1))
	f.waitRevision(t, "dev-cell-1", 2, 1)
}

func TestRegistryWatchResetsOnSignerChange(t *testing.T) {
	f := newWatchFixture(t, atRevision("dev-cell-1", 3, 7))
	newPub, newPriv := signerKey(t)
	rewriteRegistry(t, f.dir, []ed25519.PublicKey{newPub}, newPriv, atRevision("dev-cell-1", 1, 1))
	// The pinned file still names the old signer, so the new registry is refused.
	f.waitLog(t, "registry_reload_failed", "signer file")
	if err := os.WriteFile(f.signerFile, []byte(base64.StdEncoding.EncodeToString(newPub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.waitRevision(t, "dev-cell-1", 1, 1)
	f.waitLog(t, "state_reset", "signer")
	// The marks restart under the new signer and then hold again.
	rewriteRegistry(t, f.dir, []ed25519.PublicKey{newPub}, newPriv, atRevision("dev-cell-1", 1, 2))
	f.waitRevision(t, "dev-cell-1", 1, 2)
	rewriteRegistry(t, f.dir, []ed25519.PublicKey{newPub}, newPriv, atRevision("dev-cell-1", 1, 1))
	f.waitLog(t, "registry_reload_failed", "lower revision refused")
}
