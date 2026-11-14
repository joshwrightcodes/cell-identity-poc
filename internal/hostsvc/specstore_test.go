package hostsvc

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

func signSpecAt(t *testing.T, priv ed25519.PrivateKey, env string, epoch, counter uint64, cellCounter uint64) []byte {
	t.Helper()
	sp := spec.Spec{Env: env, Revision: spec.Revision{Epoch: epoch, Counter: counter}}
	if cellCounter > 0 {
		sp.Cells = []spec.Entry{{Name: "dev-cell-1", Revision: spec.Revision{Epoch: epoch, Counter: cellCounter}, RecordSHA256: strings.Repeat("0", 64)}}
	}
	out, err := spec.Sign(sp, priv)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func putDetail(t *testing.T, s *SpecStore, env []byte) string {
	t.Helper()
	_, err := s.Put(env)
	if err == nil {
		return ""
	}
	return detailOfCheck(t, err)
}

func TestSpecStore(t *testing.T) {
	t.Run("accepts_and_keeps_highest", func(t *testing.T) {
		e := newStepEnv(t)
		if putDetail(t, e.spec, signSpecAt(t, e.priv, "dev", 1, 5, 0)) != "" {
			t.Fatal("first spec refused")
		}
		if putDetail(t, e.spec, signSpecAt(t, e.priv, "dev", 1, 6, 0)) != "" {
			t.Fatal("higher spec refused")
		}
		if sp, ok := e.spec.Current(); !ok || sp.Revision.Counter != 6 {
			t.Fatalf("Current = %v %v, want counter 6", sp.Revision, ok)
		}
	})
	t.Run("older_spec_refused", func(t *testing.T) {
		e := newStepEnv(t)
		e.spec.Put(signSpecAt(t, e.priv, "dev", 1, 5, 0))
		if got := putDetail(t, e.spec, signSpecAt(t, e.priv, "dev", 1, 4, 0)); got != step.DetailRevisionOld {
			t.Errorf("detail = %q, want revision_old", got)
		}
		if got := putDetail(t, e.spec, signSpecAt(t, e.priv, "dev", 0+1, 1, 0)); got != step.DetailRevisionOld {
			t.Errorf("lower counter, same epoch: %q", got)
		}
		if sp, _ := e.spec.Current(); sp.Revision.Counter != 5 {
			t.Errorf("revision moved back to %v", sp.Revision)
		}
	})
	t.Run("higher_epoch_beats_counter", func(t *testing.T) {
		e := newStepEnv(t)
		e.spec.Put(signSpecAt(t, e.priv, "dev", 1, 50, 0))
		if got := putDetail(t, e.spec, signSpecAt(t, e.priv, "dev", 2, 1, 0)); got != "" {
			t.Errorf("a higher epoch with a low counter: %q", got)
		}
	})
	t.Run("other_env", func(t *testing.T) {
		e := newStepEnv(t)
		if got := putDetail(t, e.spec, signSpecAt(t, e.priv, "prod", 1, 1, 0)); got != step.DetailEnvMismatch {
			t.Errorf("detail = %q, want env_mismatch", got)
		}
		if _, ok := e.spec.Current(); ok {
			t.Error("a spec of another env was kept")
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		e := newStepEnv(t)
		_, rogue := newKey(t)
		if got := putDetail(t, e.spec, signSpecAt(t, rogue, "dev", 1, 1, 0)); got != step.DetailSignatureInvalid {
			t.Errorf("rogue key: %q, want signature_invalid", got)
		}
		if got := putDetail(t, e.spec, stripSignatures(t, signSpecAt(t, e.priv, "dev", 1, 1, 0))); got != step.DetailSignatureInvalid {
			t.Errorf("no signature: %q, want signature_invalid", got)
		}
		if got := putDetail(t, e.spec, []byte("{")); got != step.DetailPayloadInvalid {
			t.Errorf("garbage: %q, want payload_invalid", got)
		}
		if _, ok := e.spec.Current(); ok {
			t.Error("a bad spec was kept")
		}
	})
	t.Run("survives_reopen", func(t *testing.T) {
		e := newStepEnv(t)
		e.spec.Put(signSpecAt(t, e.priv, "dev", 1, 7, 0))
		s2, err := OpenSpecStore(e.dir, e.getKeys, "dev")
		if err != nil {
			t.Fatal(err)
		}
		if sp, ok := s2.Current(); !ok || sp.Revision.Counter != 7 {
			t.Fatalf("after reopen: %v %v", sp.Revision, ok)
		}
		if got := putDetail(t, s2, signSpecAt(t, e.priv, "dev", 1, 6, 0)); got != step.DetailRevisionOld {
			t.Errorf("an older spec after reopen: %q, want revision_old", got)
		}
		fi, err := os.Stat(filepath.Join(e.dir, "spec.json"))
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("spec.json: %v mode %v", err, fi)
		}
	})
	t.Run("resets_on_key_change", func(t *testing.T) {
		e := newStepEnv(t)
		e.spec.Put(signSpecAt(t, e.priv, "dev", 3, 9, 0))
		newPub, newPriv := newKey(t)
		// While the old key is still trusted, a lower revision from a second key is refused.
		e.setKeys(e.pub, newPub)
		if got := putDetail(t, e.spec, signSpecAt(t, newPriv, "dev", 1, 1, 0)); got != step.DetailRevisionOld {
			t.Errorf("old key still trusted: %q, want revision_old", got)
		}
		// After the old key leaves, a lower revision under the new key resets the mark.
		e.setKeys(newPub)
		if got := putDetail(t, e.spec, signSpecAt(t, newPriv, "dev", 1, 1, 0)); got != "" {
			t.Errorf("after the key changed: %q, want accepted", got)
		}
		if sp, _ := e.spec.Current(); sp.Revision != (spec.Revision{Epoch: 1, Counter: 1}) {
			t.Errorf("Current = %v after reset", sp.Revision)
		}
		if got := putDetail(t, e.spec, signSpecAt(t, newPriv, "dev", 1, 0+1, 0)); got != "" {
			t.Errorf("same spec again after reset: %q", got)
		}
	})
	t.Run("stored_spec_of_replaced_key_is_ignored_on_open", func(t *testing.T) {
		e := newStepEnv(t)
		e.spec.Put(signSpecAt(t, e.priv, "dev", 3, 9, 0))
		newPub, _ := newKey(t)
		e.setKeys(newPub)
		s2, err := OpenSpecStore(e.dir, e.getKeys, "dev")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s2.Current(); ok {
			t.Error("a spec that no trusted key verifies was loaded")
		}
	})
	t.Run("same_spec_again", func(t *testing.T) {
		e := newStepEnv(t)
		env := signSpecAt(t, e.priv, "dev", 1, 5, 0)
		ch := e.spec.Subscribe()
		if _, err := e.spec.Put(env); err != nil {
			t.Fatal(err)
		}
		<-ch
		path := filepath.Join(e.dir, "spec.json")
		before, _ := os.Stat(path)
		time.Sleep(20 * time.Millisecond)
		// The same revision and payload under a fresh signature is the same spec.
		again := signSpecAt(t, e.priv, "dev", 1, 5, 0)
		if _, err := e.spec.Put(again); err != nil {
			t.Fatalf("same spec again: %v", err)
		}
		after, _ := os.Stat(path)
		if !after.ModTime().Equal(before.ModTime()) {
			t.Error("spec.json was written again")
		}
		select {
		case <-ch:
			t.Error("the same spec sent a Subscribe event")
		default:
		}
	})
	t.Run("same_revision_other_bytes", func(t *testing.T) {
		e := newStepEnv(t)
		e.spec.Put(signSpecAt(t, e.priv, "dev", 1, 5, 0))
		if got := putDetail(t, e.spec, signSpecAt(t, e.priv, "dev", 1, 5, 3)); got != step.DetailRevisionOld {
			t.Errorf("detail = %q, want revision_old", got)
		}
	})
	t.Run("subscribe_latest_wins", func(t *testing.T) {
		e := newStepEnv(t)
		ch := e.spec.Subscribe()
		e.spec.Put(signSpecAt(t, e.priv, "dev", 1, 1, 0))
		e.spec.Put(signSpecAt(t, e.priv, "dev", 1, 2, 0))
		if sp := <-ch; sp.Revision.Counter != 2 {
			t.Errorf("event revision = %v, want the latest", sp.Revision)
		}
	})
}
