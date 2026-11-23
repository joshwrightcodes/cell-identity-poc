package gateway

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
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
	// lastSummary is the refusal summary that the last call logged. setMu guards it.
	lastSummary string
}

// The bounds of the list that one sync passes to SetRevocations. envd holds at most revoke.MaxHeld
// entries of at most revoke.MaxCanonicalBytes each, so a small multiple of that is generous.
const (
	maxSyncEntries = 4 * revoke.MaxHeld
	maxSyncBytes   = 4 * revoke.MaxHeld * revoke.MaxCanonicalBytes
)

// capList returns the leading part of in that stays within maxSyncEntries and maxSyncBytes, and
// whether it dropped anything.
func capList(in []json.RawMessage) ([]json.RawMessage, bool) {
	total := 0
	for i, raw := range in {
		total += len(raw)
		if i >= maxSyncEntries || total > maxSyncBytes {
			return in[:i], true
		}
	}
	return in, false
}

type settled struct{ cell, id, why string }

// SetRevocations verifies envelopes under keys for env and adds the entries to the overlay that
// the store holds. The store keeps the verified envelopes, so that a restart verifies them again
// when it calls SetRevocations with the keys. The list is bounded in count and bytes before it is
// read. A new entry for a cell with no stored record is refused, as envd refuses it.
//
// An entry leaves the overlay in two cases. The stored records revoke or retire its cell. Or the
// entry is stale against the stored record of its cell and envd no longer lists it, because a newer
// verified record outranks an entry that envd let go. An entry that envd still lists stays, even
// when it is stale, and an empty list on its own clears nothing. The call logs each entry that
// leaves as revocation_settled, and one summary line when the set of refusals changes.
func (s *Store) SetRevocations(ctx context.Context, envelopes []json.RawMessage, keys []ed25519.PublicKey, env string) error {
	return s.setRevocations(ctx, envelopes, keys, env, false)
}

// RestoreRevocations verifies the stored envelopes again under keys for env. It runs at start, when
// no list of envd exists yet, so it drops no stale entry. The next sync decides that.
func (s *Store) RestoreRevocations(ctx context.Context, keys []ed25519.PublicKey, env string) error {
	return s.setRevocations(ctx, nil, keys, env, true)
}

func (s *Store) setRevocations(ctx context.Context, envelopes []json.RawMessage, keys []ed25519.PublicKey, env string, restore bool) error {
	s.ov.setMu.Lock()
	defer s.ov.setMu.Unlock()
	envelopes, capped := capList(envelopes)
	var next revoke.Held
	var left []settled
	refusals := map[string]int{}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		storedText, err := metaString(tx, "revocations")
		if err != nil {
			return err
		}
		var kept []json.RawMessage
		if storedText != "" {
			if err := json.Unmarshal([]byte(storedText), &kept); err != nil {
				s.log.ErrorContext(ctx, "revocation_store_corrupt", "error", err.Error())
				s.NoteFailure("revocations", err)
				kept = nil
			}
		}
		known, _ := revoke.Load(toBytes(kept), keys, env)
		listed, _ := revoke.Load(toBytes(envelopes), keys, env)

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
		// An entry that is stale against its stored record and that envd no longer lists leaves
		// before the cap applies, so that it holds no slot.
		for cell, raw := range known {
			e, err := revoke.Verify(raw, keys)
			if err != nil {
				delete(known, cell)
				continue
			}
			if rec, ok := records[cell]; ok && !restore && revoke.Stale(e, spec.RecordRevision(rec)) {
				if _, still := listed[cell]; !still {
					left = append(left, settled{cell, e.ID, "stale"})
					delete(known, cell)
				}
			}
		}
		all := append(known.Envelopes(), envelopes...)
		held, refused := revoke.Load(toBytes(all), keys, env)
		for _, r := range refused {
			key := r.Reason
			if r.Detail != "" {
				key += "/" + r.Detail
			}
			refusals[key]++
		}
		for cell := range held {
			if _, wasHeld := known[cell]; wasHeld {
				continue
			}
			if _, hasRec := records[cell]; !hasRec {
				refusals[revoke.ReasonUnknownCell]++
				delete(held, cell)
			}
		}
		next = revoke.Settle(held, records, retired)
		for cell := range held {
			if _, ok := next[cell]; ok {
				continue
			}
			if _, wasHeld := known[cell]; wasHeld {
				left = append(left, settled{cell, "", "revoked_or_retired"})
			}
		}
		body, err := json.Marshal(next.Envelopes())
		if err != nil {
			return err
		}
		if string(body) == storedText {
			return nil
		}
		return setMeta(tx, "revocations", string(body))
	})
	if err != nil {
		return fmt.Errorf("set revocations: %w", err)
	}
	for _, l := range left {
		s.log.InfoContext(ctx, "revocation_settled", "cell", l.cell, "id", l.id, "why", l.why)
	}
	if capped {
		refusals["input_capped"]++
	}
	s.ov.summarise(ctx, s.log, refusals)
	s.ov.mu.Lock()
	s.ov.held = next
	s.ov.mu.Unlock()
	return nil
}

// summarise logs one line when the set of refusals differs from the last one that it logged.
func (o *overlay) summarise(ctx context.Context, log *slog.Logger, refusals map[string]int) {
	keys := slices.Sorted(maps.Keys(refusals))
	parts := make([]string, len(keys))
	attrs := make([]any, 0, 2*len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, refusals[k])
		attrs = append(attrs, k, refusals[k])
	}
	sum := strings.Join(parts, ",")
	if sum == o.lastSummary {
		return
	}
	o.lastSummary = sum
	if sum != "" {
		log.WarnContext(ctx, "revocation_refused", attrs...)
	}
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
