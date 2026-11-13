package cellproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// LoadPinnedRegistry is LoadRegistry plus a check that signers.pub in dir holds the same keys as
// signerFile. It returns the registry and the fingerprint of the pinned keys.
func LoadPinnedRegistry(dir, signerFile string) (*Registry, string, error) {
	pinned, err := readSigners(signerFile)
	if err != nil {
		return nil, "", fmt.Errorf("signer file: %w", err)
	}
	reg, err := LoadRegistry(dir)
	if err != nil {
		return nil, "", err
	}
	fp := signerFingerprint(pinned)
	if got := signerFingerprint(reg.keys); got != fp {
		return nil, "", fmt.Errorf("%s in %s holds other keys (sha256 %s) than the signer file (sha256 %s)", signersFile, dir, got, fp)
	}
	return reg, fp, nil
}

// signerFingerprint is the hex SHA-256 of the sorted public keys, so the order of the lines does not matter.
func signerFingerprint(keys []ed25519.PublicKey) string {
	sorted := slices.Clone(keys)
	slices.SortFunc(sorted, func(a, b ed25519.PublicKey) int { return bytes.Compare(a, b) })
	h := sha256.New()
	for _, k := range sorted {
		h.Write(k)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RegistryWatcher serves the last good registry of a directory and reloads it on a timer.
type RegistryWatcher struct {
	dir, signerFile string
	log             *slog.Logger
	cur             atomic.Pointer[Registry]

	mu      sync.Mutex
	signer  string
	marks   map[string]spec.Revision
	lastSig string
	lastErr string
}

// WatchRegistry loads the registry of dir as LoadRegistry does and refuses a registry whose
// signers.pub differs from signerFile. It reloads every `every` until ctx ends, and keeps the last
// good registry on any error (log registry_reload_failed). It logs "registry reloaded" with the
// content SHA-256 when the registry changes.
//
// A revision mark for each cell lives for the process and refuses a lower revision. The marks are
// keyed by the fingerprint of signerFile: when the signer changes, the marks reset and the log
// carries state_reset, because a rebuilt signer starts again at epoch 1. A restore of the
// management state serves older revisions under the same signer, so the log shows them as a
// refused lower revision.
func WatchRegistry(ctx context.Context, dir, signerFile string, every time.Duration, log *slog.Logger) (*RegistryWatcher, error) {
	reg, fp, err := LoadPinnedRegistry(dir, signerFile)
	if err != nil {
		return nil, err
	}
	return WatchLoaded(ctx, reg, fp, dir, signerFile, every, log), nil
}

// WatchLoaded is WatchRegistry for a registry that LoadPinnedRegistry has loaded already, with the
// signer fingerprint that it returned. A zero every starts no reload.
func WatchLoaded(ctx context.Context, reg *Registry, fp, dir, signerFile string, every time.Duration, log *slog.Logger) *RegistryWatcher {
	w := &RegistryWatcher{dir: dir, signerFile: signerFile, log: log, signer: fp, marks: highestRevisions(reg)}
	w.lastSig = registrySignature(reg)
	w.cur.Store(reg)
	if every > 0 {
		go w.run(ctx, every)
	}
	return w
}

// Current returns the last good registry.
func (w *RegistryWatcher) Current() *Registry { return w.cur.Load() }

func (w *RegistryWatcher) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.reload()
		}
	}
}

func (w *RegistryWatcher) reload() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.tryReload(); err != nil {
		if msg := err.Error(); msg != w.lastErr {
			w.lastErr = msg
			w.log.Warn("registry_reload_failed", "error", msg)
		}
		return
	}
	w.lastErr = ""
}

// tryReload loads the directory and adopts it only when every check passes. The caller holds w.mu.
func (w *RegistryWatcher) tryReload() error {
	reg, fp, err := LoadPinnedRegistry(w.dir, w.signerFile)
	if err != nil {
		return err
	}
	marks := w.marks
	reset := fp != w.signer
	if reset {
		marks = map[string]spec.Revision{}
	}
	next := highestRevisions(reg)
	for _, name := range slices.Sorted(maps.Keys(next)) {
		if mark, ok := marks[name]; ok && next[name].Compare(mark) < 0 {
			return fmt.Errorf("lower revision refused: cell %s is at epoch %d counter %d, below the mark epoch %d counter %d",
				name, next[name].Epoch, next[name].Counter, mark.Epoch, mark.Counter)
		}
	}
	if reset {
		w.log.Warn("state_reset", "reason", "the registry signer changed, so the revision marks restart",
			"signer_sha256", fp, "previous_signer_sha256", w.signer)
		w.signer, marks = fp, map[string]spec.Revision{}
	}
	merged := maps.Clone(marks)
	maps.Copy(merged, next)
	w.marks = merged
	w.cur.Store(reg)
	if sig := registrySignature(reg); sig != w.lastSig {
		w.lastSig = sig
		st := reg.Stats()
		w.log.Info("registry reloaded", "content_sha256", reg.ContentSHA256(), "records", st.Records, "revoked", st.Revoked, "signers", st.Signers)
	}
	return nil
}

// highestRevisions maps each cell name to the highest revision among its records.
func highestRevisions(r *Registry) map[string]spec.Revision {
	out := map[string]spec.Revision{}
	for _, c := range r.cells {
		rev := revisionOf(c)
		if cur, ok := out[c.Name]; !ok || rev.Compare(cur) > 0 {
			out[c.Name] = rev
		}
	}
	return out
}

// registrySignature changes whenever a record changes: its name, environment, revision, revocation
// or key set.
func registrySignature(r *Registry) string {
	lines := make([]string, 0, len(r.cells))
	for _, c := range r.cells {
		sum := sha256.Sum256(append([]byte(c.Issuer+"\n"), c.JWKS...))
		lines = append(lines, strings.Join([]string{c.Name, c.Env, strconv.FormatUint(c.Epoch, 10), strconv.FormatUint(c.Counter, 10),
			strconv.FormatBool(c.Revoked), hex.EncodeToString(sum[:])}, " "))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}
