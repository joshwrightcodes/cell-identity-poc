// Package gateway keeps the state of the cell gateway in SQLite: the operation queue, the outbox
// for the management plane, and the signed records of the cells.
package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"

	_ "modernc.org/sqlite" // the database driver, registered as "sqlite"
)

// SchemaVersion is the version of the tables that Open creates and accepts.
const SchemaVersion = 1

// LeaseTTL is how long a claim holds an item.
const LeaseTTL = 60 * time.Second

// Limits of the outbox and of one Peek batch.
const (
	MaxOutboxItems   = 10_000
	MaxOutboxBytes   = 64 << 20
	MaxItemsPerCell  = 2_000
	MaxPendingBinds  = 4
	MaxPeekItems     = 100
	MaxPeekBytes     = 900 << 10
	DoneRetention    = 24 * time.Hour
	OutcomeRetention = 10 * time.Minute
)

// Store is the SQLite state of the gateway. Every method runs in one immediate transaction on the
// only connection.
type Store struct {
	db    *sql.DB
	n     *gwapi.Notifier
	now   func() time.Time
	log   *slog.Logger
	epoch atomic.Uint64

	maxItems, maxBytes, perCell, maxBinds int
}

const schema = `
CREATE TABLE meta (key TEXT PRIMARY KEY, value);
CREATE TABLE queue (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  cell TEXT NOT NULL,
  op_id TEXT NOT NULL,
  envelope BLOB NOT NULL,
  key_epoch INTEGER NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  holder TEXT NOT NULL DEFAULT '',
  lease_until INTEGER NOT NULL DEFAULT 0,
  fence_epoch INTEGER NOT NULL DEFAULT 0,
  fence_counter INTEGER NOT NULL DEFAULT 0,
  claims INTEGER NOT NULL DEFAULT 0,
  done_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE (cell, op_id)
);
CREATE TABLE outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  cell TEXT NOT NULL,
  kind TEXT NOT NULL,
  op_id TEXT NOT NULL,
  body BLOB NOT NULL,
  token TEXT NOT NULL,
  size INTEGER NOT NULL,
  at INTEGER NOT NULL
);
CREATE TABLE outcomes (
  seq INTEGER PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  cell TEXT NOT NULL,
  op_id TEXT NOT NULL,
  body BLOB NOT NULL,
  at INTEGER NOT NULL
);
CREATE TABLE records (
  name TEXT PRIMARY KEY,
  envelope BLOB NOT NULL,
  cell BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  counter INTEGER NOT NULL,
  digest TEXT NOT NULL
);
CREATE TABLE marks (name TEXT PRIMARY KEY, epoch INTEGER NOT NULL, counter INTEGER NOT NULL);
CREATE TABLE cell_info (name TEXT PRIMARY KEY, latest BLOB NOT NULL, previous BLOB);
`

// Open opens the store at path, or makes it. The database has WAL, full synchronous writes, a 5 s
// busy timeout, immediate transactions and one connection. n may be nil. It fails when the file
// holds another schema version.
func Open(ctx context.Context, path string, n *gwapi.Notifier, now func() time.Time, log *slog.Logger) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open queue: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, n: n, now: now, log: log,
		maxItems: MaxOutboxItems, maxBytes: MaxOutboxBytes, perCell: MaxItemsPerCell, maxBinds: MaxPendingBinds}
	if err := s.tx(ctx, s.initSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open queue %s: %w", path, err)
	}
	return s, nil
}

func dsn(path string) string {
	esc := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)
	return "file:" + esc + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)&_txlock=immediate"
}

func (s *Store) initSchema(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(schema); err != nil {
			return err
		}
		now := s.now()
		for k, v := range map[string]any{"schema_version": SchemaVersion, "epoch": now.Unix(), "counter": 0, "epoch_changed_at": now.UnixNano()} {
			if err := setMeta(tx, k, v); err != nil {
				return err
			}
		}
	}
	v, err := metaInt(tx, "schema_version")
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if v != SchemaVersion {
		return fmt.Errorf("schema version %d is not supported, want %d", v, SchemaVersion)
	}
	e, err := metaInt(tx, "epoch")
	if err != nil {
		return err
	}
	s.epoch.Store(uint64(e))
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Epoch returns the fence epoch of this file.
func (s *Store) Epoch() uint64 { return s.epoch.Load() }

// Healthy returns nil when the store answers one write.
func (s *Store) Healthy(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return setMeta(tx, "healthy_at", s.now().UnixNano()) })
}

// tx runs fn in one immediate transaction. It rolls back when fn fails or panics.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func setMeta(tx *sql.Tx, key string, v any) error {
	_, err := tx.Exec(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, v)
	return err
}

func metaInt(tx *sql.Tx, key string) (int64, error) {
	var v sql.NullInt64
	err := tx.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v.Int64, err
}

func metaString(tx *sql.Tx, key string) (string, error) {
	var v sql.NullString
	err := tx.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v.String, err
}

func addMeta(tx *sql.Tx, key string, d int64) error {
	v, err := metaInt(tx, key)
	if err != nil {
		return err
	}
	return setMeta(tx, key, v+d)
}

func fromNano(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

func (s *Store) notify(cell string) {
	if s.n != nil {
		s.n.Notify(cell)
	}
}

// Stats returns the gateway status that the store knows. The stream and bind handlers fill in
// Streams and LastBindRefusal.
func (s *Store) Stats(ctx context.Context) (mgmtapi.GatewayStatus, error) {
	st := mgmtapi.GatewayStatus{
		Queued: map[string]int{}, Streams: map[string]int{}, MostClaimed: map[string]mgmtapi.ClaimInfo{},
		Records: map[string]spec.Revision{}, LastBindRefusal: map[string]mgmtapi.BindRefusal{}, KeyHints: []mgmtapi.KeyHint{},
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		st.Epoch = s.Epoch()
		for key, dst := range map[string]*time.Time{"synced_at": &st.SyncedAt, "epoch_changed_at": &st.EpochChangedAt,
			"dropped_at": &st.DroppedAt, "record_old_at": &st.RecordOldAt} {
			v, err := metaInt(tx, key)
			if err != nil {
				return err
			}
			*dst = fromNano(v)
		}
		dropped, err := metaInt(tx, "dropped")
		if err != nil {
			return err
		}
		old, err := metaInt(tx, "record_old")
		if err != nil {
			return err
		}
		st.Dropped, st.RecordOld = uint64(dropped), uint64(old)
		var oldest sql.NullInt64
		if err := tx.QueryRow(`SELECT count(*), min(at) FROM outbox`).Scan(&st.OutboxItems, &oldest); err != nil {
			return err
		}
		st.OldestOutboxAt = fromNano(oldest.Int64)
		if err := scanRows(tx, `SELECT cell, count(*) FROM queue WHERE done = 0 GROUP BY cell`, func(r *sql.Rows) error {
			var cell string
			var n int
			if err := r.Scan(&cell, &n); err != nil {
				return err
			}
			st.Queued[cell] = n
			return nil
		}); err != nil {
			return err
		}
		if err := scanRows(tx, `SELECT cell, op_id, max(claims) FROM queue WHERE done = 0 AND claims > 0 GROUP BY cell`, func(r *sql.Rows) error {
			var cell string
			var ci mgmtapi.ClaimInfo
			if err := r.Scan(&cell, &ci.OpID, &ci.Count); err != nil {
				return err
			}
			st.MostClaimed[cell] = ci
			return nil
		}); err != nil {
			return err
		}
		return scanRows(tx, `SELECT name, epoch, counter FROM records`, func(r *sql.Rows) error {
			var name string
			var rev spec.Revision
			if err := r.Scan(&name, &rev.Epoch, &rev.Counter); err != nil {
				return err
			}
			st.Records[name] = rev
			return nil
		})
	})
	return st, err
}

func scanRows(tx *sql.Tx, query string, each func(*sql.Rows) error, args ...any) error {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := each(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// MarkSynced records the time of the last envd sync.
func (s *Store) MarkSynced(ctx context.Context, t time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return setMeta(tx, "synced_at", t.UnixNano()) })
}

// NoteRecordOld counts one hello that the gateway refused with record_old.
func (s *Store) NoteRecordOld(ctx context.Context) error {
	return s.tx(ctx, s.bumpRecordOld)
}

func (s *Store) bumpRecordOld(tx *sql.Tx) error {
	if err := addMeta(tx, "record_old", 1); err != nil {
		return err
	}
	return setMeta(tx, "record_old_at", s.now().UnixNano())
}
