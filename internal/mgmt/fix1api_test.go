package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

func TestIfSeqIsCompareAndSwap(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	seq := r.status().Seq
	if seq != r.plane.snapshotSeq() {
		t.Fatalf("status seq %d, snapshot %d", seq, r.plane.snapshotSeq())
	}
	r.clk.Advance(61 * time.Second)
	if res, _ := r.plane.KeyCheck(t.Context(), cell1); res != CheckUnchanged {
		t.Fatal(res)
	}
	if r.status().Seq == seq {
		t.Fatal("a check does not move the state version")
	}
	before := r.stateBytes()
	if err := r.plane.IfSeq(seq).Restore(2); ReasonOf(err) != mgmtapi.ReasonConflict {
		t.Fatalf("restore on a stale version: %v", err)
	}
	if _, err := r.plane.IfSeq(seq).RotateKey(t.Context()); ReasonOf(err) != mgmtapi.ReasonConflict {
		t.Fatalf("rotation on a stale version: %v", err)
	}
	if string(before) != string(r.stateBytes()) {
		t.Fatal("a refused command changed the state")
	}
	if err := r.plane.IfSeq(r.status().Seq).Restore(2); err != nil {
		t.Fatal(err)
	}
}

func TestSpecReturnsACopy(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	b := r.plane.Spec()
	b.Records["dev-cell-1"] = []byte("changed")
	delete(b.Records, "dev-cell-1")
	if _, ok := r.plane.Spec().Records["dev-cell-1"]; !ok {
		t.Fatal("a caller changed what is served")
	}
	r.verifyRecord(cell1)
}

func TestConfigKeyLoadsOnce(t *testing.T) {
	r := newRig(t)
	if n := r.logs.count("signing_key_created"); n != 1 {
		t.Fatalf("%d signing_key_created lines from NewPlane", n)
	}
	dir := t.TempDir()
	key, created, err := LoadOrCreateKey(filepath.Join(dir, "k"))
	if err != nil || !created {
		t.Fatal(err)
	}
	cfg := r.config()
	cfg.KeyPath, cfg.Key = filepath.Join(dir, "unused-key-path"), key
	cfg.Store = &FileStore{Path: filepath.Join(dir, "state.json")}
	p, err := NewPlane(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !p.PublicKey().Equal(key.Public()) {
		t.Fatal("the plane ignores the key from the config")
	}
	if n := r.logs.count("signing_key_created"); n != 1 {
		t.Fatalf("NewPlane logs the creation of a key that it did not make: %d lines", n)
	}
}

func TestStateFileThatFailsValidationIsNotMovedAside(t *testing.T) {
	cases := map[string]func(st map[string]any){
		"future_version":   func(st map[string]any) { st["version"] = 2 },
		"history_mismatch": func(st map[string]any) { st["last"] = map[string]any{"epoch": 1, "counter": 9} },
		"unknown_member":   func(st map[string]any) { st["added"] = true; st["version"] = 3 },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
			var st map[string]any
			if err := json.Unmarshal(r.stateBytes(), &st); err != nil {
				t.Fatal(err)
			}
			mod(st)
			b, _ := json.Marshal(st)
			path := filepath.Join(r.dir, "state.json")
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := NewPlane(r.config())
			if !errors.Is(err, ErrStateInvalid) || !strings.Contains(err.Error(), "state_invalid") ||
				!strings.Contains(err.Error(), "Recover lost management state") || strings.Contains(err.Error(), "rotate-signing-key") {
				t.Fatalf("NewPlane: %v", err)
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, b) {
				t.Fatal("the state file moved or changed")
			}
			if m, _ := filepath.Glob(path + ".corrupt-*"); len(m) != 0 {
				t.Fatalf("moved aside: %v", m)
			}
		})
	}
}
