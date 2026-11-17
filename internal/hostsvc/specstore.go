package hostsvc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

const (
	specFile = "spec.json"
	// maxSeenSteps is the number of step IDs that the store remembers after a spec indexed them.
	maxSeenSteps = 256
)

// IndexState tells how the newest spec indexes a step.
type IndexState int

const (
	// IndexMatch means the newest spec indexes the step ID and the digest of the envelope.
	IndexMatch IndexState = iota
	// IndexResign means the newest spec indexes the step ID with another digest: a re-signed envelope.
	IndexResign
	// IndexDropped means an earlier spec indexed the step ID and the newest one does not.
	IndexDropped
	// IndexAbsent means no spec indexed the step ID that this host has seen.
	IndexAbsent
)

type storedSpec struct {
	Envelope string `json:"envelope"`
	SignedBy string `json:"signedBy"`
}

// SpecStore keeps the newest verified spec that the management plane sent, in dir/spec.json.
type SpecStore struct {
	dir  string
	keys func() []ed25519.PublicKey
	env  string
	log  *slog.Logger

	mu     sync.Mutex
	cur    *spec.Spec
	sha    string
	signer string
	seen   []string
	subs   []chan spec.Spec
}

// OpenSpecStore loads dir/spec.json. A stored spec that no key verifies any more is ignored, and
// the next Put replaces it. keys supplies the trusted public keys at each call.
func OpenSpecStore(dir string, keys func() []ed25519.PublicKey, env string) (*SpecStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("spec directory: %w", err)
	}
	s := &SpecStore{dir: dir, keys: keys, env: env, log: slog.Default()}
	data, err := os.ReadFile(filepath.Join(dir, specFile))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	var st storedSpec
	if err := json.Unmarshal(data, &st); err != nil {
		s.log.Warn("spec_reset", "reason", "stored file does not parse")
		return s, nil
	}
	sp, payload, err := spec.Verify([]byte(st.Envelope), keys())
	if err != nil || sp.Env != env {
		s.log.Warn("spec_reset", "reason", "stored spec does not verify under the current keys")
		return s, nil
	}
	s.cur, s.sha, s.signer = &sp, step.PayloadSHA256(payload), st.SignedBy
	s.noteSeen(sp)
	return s, nil
}

// SetLogger sets the logger of the store.
func (s *SpecStore) SetLogger(l *slog.Logger) {
	s.mu.Lock()
	s.log = l
	s.mu.Unlock()
}

func keySHA(k ed25519.PublicKey) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:])
}

// Put verifies the envelope under the trusted keys and keeps it when its revision is higher than
// the stored one. The same revision with the same payload succeeds and changes nothing. A lower
// revision, or the same revision with another payload, gets revision_old, unless the signing key
// replaced the key of the stored spec in the trusted set: then the mark resets, as envd does. The
// errors carry a step detail: signature_invalid, payload_invalid, env_mismatch or revision_old.
func (s *SpecStore) Put(envelope []byte) (spec.Spec, error) {
	keys := s.keys()
	sp, payload, err := spec.Verify(envelope, keys)
	if err != nil {
		return spec.Spec{}, &step.Error{Detail: step.DetailOf(err)}
	}
	if sp.Env != s.env {
		return spec.Spec{}, &step.Error{Detail: step.DetailEnvMismatch}
	}
	signer := ""
	for _, k := range keys {
		if _, _, err := spec.Verify(envelope, []ed25519.PublicKey{k}); err == nil {
			signer = keySHA(k)
			break
		}
	}
	sha := step.PayloadSHA256(payload)

	s.mu.Lock()
	defer s.mu.Unlock()
	reset := false
	if s.cur != nil {
		switch c := sp.Revision.Compare(s.cur.Revision); {
		case c == 0 && sha == s.sha:
			s.notify(*s.cur)
			return *s.cur, nil
		case c <= 0:
			if s.signerTrusted(keys) || signer == s.signer {
				return spec.Spec{}, &step.Error{Detail: step.DetailRevisionOld}
			}
			reset = true
		}
	}
	data, err := json.Marshal(storedSpec{Envelope: string(envelope), SignedBy: signer})
	if err != nil {
		return spec.Spec{}, err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, specFile), data, 0o644); err != nil {
		return spec.Spec{}, fmt.Errorf("write spec: %w", err)
	}
	if reset {
		s.log.Warn("spec_reset", "reason", "signing key replaced the stored key", "from", s.cur.Revision, "to", sp.Revision)
	}
	s.cur, s.sha, s.signer = &sp, sha, signer
	s.noteSeen(sp)
	s.notify(sp)
	return sp, nil
}

// notify hands sp to every subscriber, in place of a spec that it has not read yet. The caller
// holds s.mu. A push that repeats the stored spec also notifies, because it shows that the
// management plane holds nothing newer.
func (s *SpecStore) notify(sp spec.Spec) {
	for _, ch := range s.subs {
		select {
		case <-ch:
		default:
		}
		ch <- sp
	}
}

// signerTrusted reports whether the key that signed the stored spec is still trusted.
func (s *SpecStore) signerTrusted(keys []ed25519.PublicKey) bool {
	return slices.ContainsFunc(keys, func(k ed25519.PublicKey) bool { return keySHA(k) == s.signer })
}

func (s *SpecStore) noteSeen(sp spec.Spec) {
	for _, e := range sp.Steps {
		if !slices.Contains(s.seen, e.StepID) {
			s.seen = append(s.seen, e.StepID)
		}
	}
	if n := len(s.seen) - maxSeenSteps; n > 0 {
		s.seen = slices.Delete(s.seen, 0, n)
	}
}

// Current returns the newest spec.
func (s *SpecStore) Current() (spec.Spec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return spec.Spec{}, false
	}
	return *s.cur, true
}

// Subscribe returns a channel that holds the newest accepted spec. A slow reader sees only the
// latest one.
func (s *SpecStore) Subscribe() <-chan spec.Spec {
	ch := make(chan spec.Spec, 1)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	return ch
}

// Index tells how the newest spec indexes the step with this ID for cell and payload digest.
func (s *SpecStore) Index(cell, id, payloadSHA string) IndexState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		for _, e := range s.cur.Steps {
			if e.StepID != id {
				continue
			}
			if e.Name == cell && e.StepSHA256 == payloadSHA {
				return IndexMatch
			}
			if e.Name == cell {
				return IndexResign
			}
		}
	}
	if slices.Contains(s.seen, id) {
		return IndexDropped
	}
	return IndexAbsent
}

// IndexedDigest returns the digest that the newest spec holds for step id, and whether it indexes
// the ID at all.
func (s *SpecStore) IndexedDigest(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		for _, e := range s.cur.Steps {
			if e.StepID == id {
				return e.StepSHA256, true
			}
		}
	}
	return "", false
}
