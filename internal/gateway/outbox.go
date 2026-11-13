package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// Append stores an item in the outbox and returns its ID. When the outbox is full, in items, bytes
// or items of that cell, the oldest status item of the same cell goes first. With none left, the
// new item gets gwapi.ErrOverloaded and nothing is dropped. A bind item also gets ErrOverloaded
// when its cell already has four pending binds.
func (s *Store) Append(ctx context.Context, it gwapi.Item) (gwapi.ItemID, error) {
	var id gwapi.ItemID
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = s.appendItem(tx, it)
		return err
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func itemSize(it gwapi.Item) int {
	return len(it.Body) + len(it.Token) + len(it.Cell) + len(it.OpID) + len(it.Kind)
}

func (s *Store) appendItem(tx *sql.Tx, it gwapi.Item) (gwapi.ItemID, error) {
	switch it.Kind {
	case gwapi.KindResult, gwapi.KindStatus, gwapi.KindBind:
	default:
		return "", fmt.Errorf("append: unknown item kind %q", it.Kind)
	}
	if it.Cell == "" {
		return "", errors.New("append: item has no cell")
	}
	size := itemSize(it)
	if it.Kind == gwapi.KindBind {
		var binds int
		if err := tx.QueryRow(`SELECT count(*) FROM outbox WHERE cell = ? AND kind = ?`, it.Cell, gwapi.KindBind).Scan(&binds); err != nil {
			return "", err
		}
		if binds >= s.maxBinds {
			return "", gwapi.ErrOverloaded
		}
	}
	dropped := 0
	for {
		var items, cellItems, bytes, cellBytes int
		if err := tx.QueryRow(`SELECT count(*), coalesce(sum(size), 0), coalesce(sum(cell = ?), 0), coalesce(sum(CASE WHEN cell = ? THEN size ELSE 0 END), 0) FROM outbox`, it.Cell, it.Cell).
			Scan(&items, &bytes, &cellItems, &cellBytes); err != nil {
			return "", err
		}
		globalOK := items < s.maxItems && bytes+size <= s.maxBytes
		cellOK := cellItems < s.perCell && cellBytes+size <= s.perCellBytes
		if globalOK && cellOK {
			break
		}
		// A cell that is over its own share gives up its own oldest status item. When only the
		// whole outbox is full, a result displaces the oldest status item of the cell that holds
		// the most bytes, so that no cell can keep another cell's result out.
		victim := it.Cell
		if cellOK && it.Kind == gwapi.KindResult {
			err := tx.QueryRow(`SELECT cell FROM outbox GROUP BY cell HAVING sum(kind = ?) > 0 ORDER BY sum(size) DESC, cell LIMIT 1`, gwapi.KindStatus).Scan(&victim)
			if errors.Is(err, sql.ErrNoRows) {
				return "", gwapi.ErrOverloaded
			}
			if err != nil {
				return "", err
			}
		}
		res, err := tx.Exec(`DELETE FROM outbox WHERE seq = (SELECT min(seq) FROM outbox WHERE cell = ? AND kind = ?)`, victim, gwapi.KindStatus)
		if err != nil {
			return "", err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return "", gwapi.ErrOverloaded
		}
		dropped++
	}
	if dropped > 0 {
		if err := addMeta(tx, "dropped", int64(dropped)); err != nil {
			return "", err
		}
		if err := setMeta(tx, "dropped_at", s.now().UnixNano()); err != nil {
			return "", err
		}
	}
	id := gwapi.NewItemID()
	_, err := tx.Exec(`INSERT INTO outbox (id, cell, kind, op_id, body, token, size, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		string(id), it.Cell, it.Kind, it.OpID, []byte(it.Body), it.Token, size, s.now().UnixNano())
	return id, err
}

// Peek returns the oldest outbox items, at most maxItems and about maxBytes of encoded items, and
// never more than 100 items and 900 KiB. It always returns one item when the outbox has one. It
// does not remove anything.
func (s *Store) Peek(ctx context.Context, maxItems, maxBytes int) ([]gwapi.OutItem, error) {
	maxItems, maxBytes = min(maxItems, MaxPeekItems), min(maxBytes, MaxPeekBytes)
	var out []gwapi.OutItem
	err := s.tx(ctx, func(tx *sql.Tx) error {
		out = nil
		total, full := 0, false
		return scanRows(tx, `SELECT id, cell, kind, op_id, body, token FROM outbox ORDER BY seq LIMIT ?`, func(r *sql.Rows) error {
			if full || len(out) >= maxItems {
				return nil
			}
			var oi gwapi.OutItem
			var body []byte
			if err := r.Scan(&oi.ID, &oi.Cell, &oi.Kind, &oi.OpID, &body, &oi.Token); err != nil {
				return err
			}
			oi.Body = json.RawMessage(body)
			enc, err := json.Marshal(oi)
			if err != nil {
				return err
			}
			if len(out) > 0 && total+len(enc) > maxBytes {
				full = true
				return nil
			}
			total += len(enc)
			out = append(out, oi)
			return nil
		}, MaxPeekItems)
	})
	return out, err
}

// Ack deletes each item that the outcomes name and stores its outcome by item ID and op ID. An ID
// that the outbox does not hold is ignored.
func (s *Store) Ack(ctx context.Context, outcomes []mgmtapi.ItemOutcome) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		at := s.now().UnixNano()
		for _, o := range outcomes {
			var seq int64
			var cell, opID string
			err := tx.QueryRow(`SELECT seq, cell, op_id FROM outbox WHERE id = ?`, o.ID).Scan(&seq, &cell, &opID)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			o.OpID = opID
			body, err := json.Marshal(o)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM outbox WHERE seq = ?`, seq); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT OR REPLACE INTO outcomes (seq, id, cell, op_id, outcome, body, at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				seq, o.ID, cell, opID, o.Outcome, body, at); err != nil {
				return err
			}
		}
		return nil
	})
}

// Outcome returns the stored outcome of an item of cell. It never returns the outcome of an item
// of another cell.
func (s *Store) Outcome(ctx context.Context, cell string, id gwapi.ItemID) (mgmtapi.ItemOutcome, bool, error) {
	var o mgmtapi.ItemOutcome
	var found bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var body []byte
		err := tx.QueryRow(`SELECT body FROM outcomes WHERE id = ? AND cell = ?`, string(id), cell).Scan(&body)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return json.Unmarshal(body, &o)
	})
	if err != nil {
		return mgmtapi.ItemOutcome{}, false, err
	}
	return o, found, nil
}

// FinalOutcomes returns the outcomes of the result items of cell with an outbox row ID above
// after, oldest first, at most 100, and the highest row ID that it returned (after when it
// returned none). The stream keeps that cursor. It deletes nothing: after the stream has written
// the frames, it calls ForgetRetries with the cursor.
//
// The cursor is the outbox row ID, which follows the order of Peek. Peek returns the oldest prefix,
// one Ack stores the outcomes of a whole batch in one transaction, and the row ID is AUTOINCREMENT,
// so a later batch has only higher IDs. An outcome below the cursor can appear only when a caller
// breaks that order, for example with a partial ack, and the resend of the cell then heals it.
func (s *Store) FinalOutcomes(ctx context.Context, cell string, after int64) ([]mgmtapi.ItemOutcome, int64, error) {
	var outs []mgmtapi.ItemOutcome
	cursor := after
	err := s.tx(ctx, func(tx *sql.Tx) error {
		outs, cursor = nil, after
		return scanRows(tx, `SELECT seq, body FROM outcomes WHERE cell = ? AND op_id != '' AND seq > ? ORDER BY seq LIMIT 100`,
			func(r *sql.Rows) error {
				var seq int64
				var body []byte
				var o mgmtapi.ItemOutcome
				if err := r.Scan(&seq, &body); err != nil {
					return err
				}
				if err := json.Unmarshal(body, &o); err != nil {
					return err
				}
				outs = append(outs, o)
				cursor = seq
				return nil
			}, cell, after)
	})
	if err != nil {
		return nil, after, err
	}
	return outs, cursor, nil
}

// ForgetRetries deletes the retry outcomes of cell with an outbox row ID up to upTo. The stream
// calls it with the cursor of FinalOutcomes after it wrote the frames, because the cell then sends
// the result again.
func (s *Store) ForgetRetries(ctx context.Context, cell string, upTo int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM outcomes WHERE cell = ? AND seq <= ? AND op_id != '' AND outcome = ?`, cell, upTo, mgmtapi.OutcomeRetry)
		return err
	})
}
