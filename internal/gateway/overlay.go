package gateway

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// overlay is the set of cells that a signed local revocation holds revoked. The store keeps the
// verified envelopes, and the copy in memory answers the hot checks of the stream and the claim.
type overlay struct {
	setMu sync.Mutex
	mu    sync.RWMutex
	held  revoke.Held
}

// SetRevocations verifies envelopes under keys for env and adds the entries to the overlay that
// the store holds. The store keeps the verified envelopes, so that a restart verifies them again
// when it calls SetRevocations with the keys. An entry leaves the overlay only when the stored
// records say that its cell is revoked or retired, so an empty list clears nothing. A new entry
// that names a record revision below the stored record of its cell is dropped as stale. An
// envelope that fails verification is logged and ignored.
func (s *Store) SetRevocations(ctx context.Context, envelopes []json.RawMessage, keys []ed25519.PublicKey, env string) error {
	s.ov.setMu.Lock()
	defer s.ov.setMu.Unlock()
	var next revoke.Held
	var refused []revoke.Refusal
	err := s.tx(ctx, func(tx *sql.Tx) error {
		stored, err := metaString(tx, "revocations")
		if err != nil {
			return err
		}
		var kept []json.RawMessage
		if stored != "" {
			if err := json.Unmarshal([]byte(stored), &kept); err != nil {
				return fmt.Errorf("read stored revocations: %w", err)
			}
		}
		known, _ := revoke.Load(toBytes(kept), keys, env)
		all := append(append([]json.RawMessage{}, kept...), envelopes...)
		held, refusals := revoke.Load(toBytes(all), keys, env)
		refused = refusals

		records := map[string]record.Cell{}
		retired := map[string]bool{}
		if err := scanRows(tx, `SELECT name, cell FROM records`, func(r *sql.Rows) error {
			var name string
			var body []byte
			if err := r.Scan(&name, &body); err != nil {
				return err
			}
			var c record.Cell
			if err := json.Unmarshal(body, &c); err != nil {
				return err
			}
			records[name] = c
			return nil
		}); err != nil {
			return err
		}
		if err := scanRows(tx, `SELECT name FROM marks`, func(r *sql.Rows) error {
			var name string
			if err := r.Scan(&name); err != nil {
				return err
			}
			if _, live := records[name]; !live {
				retired[name] = true
			}
			return nil
		}); err != nil {
			return err
		}
		for cell, raw := range held {
			if _, old := known[cell]; old {
				continue
			}
			e, err := revoke.Verify(raw, keys)
			if err != nil {
				delete(held, cell)
				continue
			}
			if rec, ok := records[cell]; ok && revoke.Stale(e, spec.RecordRevision(rec)) {
				delete(held, cell)
			}
		}
		next = revoke.Settle(held, records, retired)
		body, err := json.Marshal(next.Envelopes())
		if err != nil {
			return err
		}
		return setMeta(tx, "revocations", string(body))
	})
	if err != nil {
		return fmt.Errorf("set revocations: %w", err)
	}
	if len(refused) > 0 {
		s.log.WarnContext(ctx, "revocation_refused", "count", len(refused), "reason", refused[0].Reason, "detail", refused[0].Detail)
	}
	s.ov.mu.Lock()
	s.ov.held = next
	s.ov.mu.Unlock()
	return nil
}

func toBytes(in []json.RawMessage) [][]byte {
	out := make([][]byte, len(in))
	for i, r := range in {
		out[i] = r
	}
	return out
}

// Overlaid reports whether a signed local revocation holds cell revoked.
func (s *Store) Overlaid(_ context.Context, cell string) (bool, error) {
	s.ov.mu.RLock()
	defer s.ov.mu.RUnlock()
	_, ok := s.ov.held[cell]
	return ok, nil
}

// OverlayCount returns the number of cells that the overlay holds revoked.
func (s *Store) OverlayCount() int {
	s.ov.mu.RLock()
	defer s.ov.mu.RUnlock()
	return len(s.ov.held)
}
