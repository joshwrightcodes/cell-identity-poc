package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// Lease is one claimed operation. ID is the store ID of the database file and the queue row ID.
// It stays the same for the life of the row, so a result finds its row after a later claim has
// given the row a new fence, and a lease from another file never matches a row.
type Lease struct {
	ID       string
	OpID     string
	Envelope []byte
	Fence    op.Fence
	Until    time.Time
}

// Enqueue adds the envelope to the queue of cell. The ID and key epoch come from op.Peek, and the
// peeked cell must equal cell. A known (cell, ID) adds nothing. An item that is not done and has a
// lower stored key epoch takes the new bytes and keeps its lease and fence; other different bytes
// give gwapi.ErrEnvelopeConflict. added is true only for a new row. The subscribers of cell get a
// signal when the queue changes.
//
// A done row meets a re-signed envelope of a higher key epoch after a key rotation, when its result
// has not yet reached the management plane. That gives ErrEnvelopeConflict for that operation. It
// is an expected event of one operation and not a failed sync.
func (s *Store) Enqueue(ctx context.Context, cell string, envelope []byte) (id string, added bool, err error) {
	id, keyEpoch, err := peekFor(cell, envelope)
	if err != nil {
		return "", false, err
	}
	var changed bool
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		added, changed, err = enqueue(tx, cell, id, keyEpoch, envelope)
		return err
	})
	if err == nil && changed {
		s.notify(cell)
	}
	return id, added, err
}

// EnqueueReplay deletes the row of that cell for the envelope ID, then enqueues the envelope. A
// row of another cell stays.
func (s *Store) EnqueueReplay(ctx context.Context, cell string, envelope []byte) (id string, err error) {
	id, keyEpoch, err := peekFor(cell, envelope)
	if err != nil {
		return "", err
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM queue WHERE cell = ? AND op_id = ?`, cell, id); err != nil {
			return err
		}
		_, _, err := enqueue(tx, cell, id, keyEpoch, envelope)
		return err
	})
	if err == nil {
		s.notify(cell)
	}
	return id, err
}

func peekFor(cell string, envelope []byte) (id string, keyEpoch uint64, err error) {
	id, peeked, keyEpoch, err := op.Peek(envelope)
	if err != nil {
		return "", 0, fmt.Errorf("enqueue: %w", err)
	}
	if peeked != cell {
		return "", 0, fmt.Errorf("enqueue: envelope is for cell %q, not %q", peeked, cell)
	}
	return id, keyEpoch, nil
}

func enqueue(tx *sql.Tx, cell, id string, keyEpoch uint64, envelope []byte) (added, changed bool, err error) {
	var stored []byte
	var storedEpoch uint64
	var done bool
	err = tx.QueryRow(`SELECT envelope, key_epoch, done FROM queue WHERE cell = ? AND op_id = ?`, cell, id).
		Scan(&stored, &storedEpoch, &done)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.Exec(`INSERT INTO queue (cell, op_id, envelope, key_epoch) VALUES (?, ?, ?, ?)`, cell, id, envelope, keyEpoch)
		return err == nil, err == nil, err
	case err != nil:
		return false, false, err
	case bytes.Equal(stored, envelope):
		return false, false, nil
	case !done && storedEpoch < keyEpoch:
		_, err = tx.Exec(`UPDATE queue SET envelope = ?, key_epoch = ? WHERE cell = ? AND op_id = ?`, envelope, keyEpoch, cell, id)
		return false, err == nil, err
	}
	return false, false, gwapi.ErrEnvelopeConflict
}

// Claim leases the oldest item of cell that is queued or whose lease has expired, for 60 s, under
// the next global fence. It returns nil and no error when there is none.
func (s *Store) Claim(ctx context.Context, cell, holder string) (*Lease, error) {
	return s.claim(ctx, cell, holder, false)
}

// ErrCellNotLive means the record of a cell is missing or revoked.
var ErrCellNotLive = errors.New("cell has no live record")

// ClaimLive is Claim, and it also checks in the same transaction that the cell has a record that is
// not revoked. It returns ErrCellNotLive and leases nothing otherwise.
func (s *Store) ClaimLive(ctx context.Context, cell, holder string) (*Lease, error) {
	return s.claim(ctx, cell, holder, true)
}

func (s *Store) claim(ctx context.Context, cell, holder string, requireLive bool) (*Lease, error) {
	var l *Lease
	err := s.tx(ctx, func(tx *sql.Tx) error {
		l = nil
		if requireLive {
			var body []byte
			err := tx.QueryRow(`SELECT cell FROM records WHERE name = ?`, cell).Scan(&body)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrCellNotLive
			}
			if err != nil {
				return err
			}
			var rec struct {
				Revoked bool `json:"revoked"`
			}
			if err := json.Unmarshal(body, &rec); err != nil {
				return err
			}
			if rec.Revoked {
				return ErrCellNotLive
			}
		}
		now := s.now()
		var seq int64
		var opID string
		var env []byte
		err := tx.QueryRow(`SELECT seq, op_id, envelope FROM queue
			WHERE cell = ? AND done = 0 AND lease_until <= ? ORDER BY seq LIMIT 1`, cell, now.UnixNano()).Scan(&seq, &opID, &env)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := addMeta(tx, "counter", 1); err != nil {
			return err
		}
		counter, err := metaInt(tx, "counter")
		if err != nil {
			return err
		}
		epoch, err := metaInt(tx, "epoch")
		if err != nil {
			return err
		}
		f := op.Fence{Epoch: uint64(epoch), Counter: uint64(counter)}
		until := now.Add(LeaseTTL)
		if _, err := tx.Exec(`UPDATE queue SET holder = ?, lease_until = ?, fence_epoch = ?, fence_counter = ?, claims = claims + 1
			WHERE seq = ?`, holder, until.UnixNano(), f.Epoch, f.Counter, seq); err != nil {
			return err
		}
		l = &Lease{ID: s.storeID + "." + strconv.FormatInt(seq, 10), OpID: opID, Envelope: env, Fence: f, Until: until.UTC()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// CompleteWithItem appends the result item and finds the queue row by leaseID, never by it.OpID.
// It marks the row done when f is at or above the lease fence of the row. It returns
// gwapi.ErrLeaseLost, with the item still appended and its ID returned, only when a live lease
// holds a higher fence. A call only appends, and never marks a row, when leaseID is empty, does not
// parse, names another store file, names a row of another cell, or when it.OpID is not empty and
// differs from the op ID of the row.
func (s *Store) CompleteWithItem(ctx context.Context, cell, leaseID string, it gwapi.Item, f op.Fence) (gwapi.ItemID, error) {
	if it.Cell != cell {
		return "", fmt.Errorf("complete: item is for cell %q, not %q", it.Cell, cell)
	}
	var id gwapi.ItemID
	var lost bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		lost = false
		if id, err = s.appendItem(tx, it); err != nil {
			return err
		}
		if leaseID == "" {
			return nil
		}
		seq, ok := s.parseLease(cell, leaseID)
		if !ok {
			return nil
		}
		var cur op.Fence
		var until int64
		var done bool
		var rowOp string
		err = tx.QueryRow(`SELECT fence_epoch, fence_counter, lease_until, done, op_id FROM queue WHERE seq = ? AND cell = ?`, seq, cell).
			Scan(&cur.Epoch, &cur.Counter, &until, &done, &rowOp)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && done) {
			return nil
		}
		if err != nil {
			return err
		}
		if it.OpID != "" && it.OpID != rowOp {
			s.log.Warn("lease_op_mismatch", "cell", cell, "lease_op", rowOp, "item_op", it.OpID)
			return nil
		}
		if f.Compare(cur) < 0 && until > s.now().UnixNano() {
			lost = true
			return nil
		}
		_, err = tx.Exec(`UPDATE queue SET done = 1, done_at = ? WHERE seq = ?`, s.now().UnixNano(), seq)
		return err
	})
	if err != nil {
		return "", err
	}
	if lost {
		return id, gwapi.ErrLeaseLost
	}
	return id, nil
}

// ErrEpochOutOfRange means a fence epoch is too high to raise the epoch to one above it.
var ErrEpochOutOfRange = errors.New("fence epoch is out of range")

// MaxRaisableEpoch is the highest epoch that RaiseEpoch accepts as seen. The stored epoch then
// stays at or below math.MaxInt64 - 1, so one more raise never wraps or leaves the database range.
const MaxRaisableEpoch = math.MaxInt64 - 2

// RaiseEpoch lifts the epoch to one above seen.Epoch when seen.Epoch is at or above it. A hello
// reports the last fence that a cell saw. It refuses a seen.Epoch above MaxRaisableEpoch with
// ErrEpochOutOfRange and changes nothing.
func (s *Store) RaiseEpoch(ctx context.Context, seen op.Fence) error {
	if seen.Epoch > MaxRaisableEpoch {
		return fmt.Errorf("%w: %d", ErrEpochOutOfRange, seen.Epoch)
	}
	s.raiseMu.Lock()
	defer s.raiseMu.Unlock()
	var next uint64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		next = 0
		cur, err := metaInt(tx, "epoch")
		if err != nil {
			return err
		}
		if seen.Epoch < uint64(cur) {
			return nil
		}
		next = seen.Epoch + 1
		if err := setMeta(tx, "epoch", next); err != nil {
			return err
		}
		return setMeta(tx, "epoch_changed_at", s.now().UnixNano())
	})
	if err == nil && next != 0 {
		s.epoch.Store(next)
	}
	return err
}

// Depth returns the number of items of cell that are not done.
func (s *Store) Depth(ctx context.Context, cell string) (int, error) {
	var n int
	err := s.tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM queue WHERE cell = ? AND done = 0`, cell).Scan(&n)
	})
	return n, err
}

// Prune deletes done items older than 24 h and outcomes older than 10 min.
func (s *Store) Prune(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		now := s.now()
		if _, err := tx.Exec(`DELETE FROM queue WHERE done = 1 AND done_at < ?`, now.Add(-DoneRetention).UnixNano()); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM outcomes WHERE at < ?`, now.Add(-OutcomeRetention).UnixNano())
		return err
	})
}

// parseLease returns the row ID of a lease ID of this store file. It logs the other cases, which
// only append.
func (s *Store) parseLease(cell, leaseID string) (int64, bool) {
	id, rest, found := strings.Cut(leaseID, ".")
	if !found {
		s.log.Warn("lease_id_invalid", "cell", cell)
		return 0, false
	}
	seq, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		s.log.Warn("lease_id_invalid", "cell", cell)
		return 0, false
	}
	if id != s.storeID {
		s.log.Warn("lease_other_store", "cell", cell)
		return 0, false
	}
	return seq, true
}
