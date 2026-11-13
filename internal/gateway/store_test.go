package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

var t0 = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: t0} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	t     *testing.T
	path  string
	clk   *clock
	n     *gwapi.Notifier
	s     *Store
	logs  *strings.Builder
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	count int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, path: filepath.Join(t.TempDir(), "queue.db"), clk: newClock(), n: gwapi.NewNotifier(),
		logs: &strings.Builder{}, priv: priv, pub: pub}
	f.s = f.open()
	return f
}

func (f *fixture) open() *Store {
	f.t.Helper()
	log := slog.New(slog.NewJSONHandler(f.logs, nil))
	s, err := Open(context.Background(), f.path, f.n, f.clk.Now, log)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = s.Close() })
	return s
}

func (f *fixture) reopen() {
	f.t.Helper()
	if err := f.s.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.s = f.open()
}

// opEnv signs an operation with a distinct ID for cell at keyEpoch.
func (f *fixture) opEnv(id, cell string, keyEpoch uint64) []byte {
	f.t.Helper()
	f.count++
	o := op.Operation{ID: id, Env: "dev", Cell: cell, Kind: op.KindDemoAppend, Version: 1, KeyEpoch: keyEpoch,
		IssuedAt: f.clk.Now(), ExpiresAt: f.clk.Now().Add(10 * time.Minute), Args: json.RawMessage(fmt.Sprintf(`{"line":"n%d"}`, f.count))}
	env, err := op.Sign(o, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	return env
}

func opID(n int) string { return fmt.Sprintf("%032x", n) }

func (f *fixture) enqueue(n int, cell string) string {
	f.t.Helper()
	id, _, err := f.s.Enqueue(context.Background(), cell, f.opEnv(opID(n), cell, 1))
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func resultItem(cell, opID string) gwapi.Item {
	return gwapi.Item{Kind: gwapi.KindResult, Cell: cell, OpID: opID, Body: json.RawMessage(`{"outcome":"applied"}`), Token: "tok"}
}

func TestStorePragmas(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for pragma, want := range map[string]string{"journal_mode": "wal", "synchronous": "2", "busy_timeout": "5000"} {
		var got string
		if err := f.s.db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil || got != want {
			t.Errorf("PRAGMA %s = %q, %v; want %q", pragma, got, err, want)
		}
	}
	if n := f.s.db.Stats().MaxOpenConnections; n != 1 {
		t.Errorf("max open connections %d, want 1", n)
	}
	other := openOther(t, f.path)
	tx, err := f.s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE meta SET value = value WHERE key = 'counter'`); err != nil {
		t.Fatal(err)
	}
	if _, err := other.ExecContext(ctx, "BEGIN IMMEDIATE"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "busy") {
		t.Fatalf("a second connection during a transaction: %v, want busy", err)
	}
}

// openOther opens a second connection with a short busy timeout and no transaction mode.
func openOther(t *testing.T, path string) *sql.Conn {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(50)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	c, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestStoreDSNImmediate checks the DSN of Open against the opened database: a transaction takes the
// write lock at BEGIN, before its first statement, which only _txlock=immediate does.
func TestStoreDSNImmediate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	other := openOther(t, f.path)
	tx, err := f.s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ExecContext(ctx, "BEGIN IMMEDIATE"); err == nil {
		t.Fatal("a second writer began while a transaction with no statement was open: the transaction is deferred")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := other.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("a second writer after the rollback: %v", err)
	}
	if _, err := other.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if got := dsn(filepath.Join("a?b#c", "q.db")); !strings.Contains(got, "a%3fb%23c") {
		t.Errorf("dsn does not escape the path: %s", got)
	}
}

func TestStoreErrorReleasesConnection(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := f.enqueue(1, "dev-cell-1")
	if _, _, err := f.s.Enqueue(ctx, "dev-cell-1", f.opEnv(id, "dev-cell-1", 1)); err == nil {
		t.Fatal("same ID, same key epoch, other bytes: want a conflict")
	}
	for _, call := range []func() error{
		func() error { return f.s.tx(ctx, func(*sql.Tx) error { return fmt.Errorf("boom") }) },
		func() error {
			return f.s.tx(ctx, func(tx *sql.Tx) error { _, err := tx.Exec("INSERT INTO nope VALUES (1)"); return err })
		},
	} {
		if err := call(); err == nil {
			t.Fatal("want an error")
		}
		done := make(chan error, 1)
		go func() { done <- f.s.Healthy(ctx) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("the next call did not run within 1 s: the connection is held")
		}
	}
}

func TestStoreSchemaVersion(t *testing.T) {
	f := newFixture(t)
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+f.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE meta SET value = 2 WHERE key = 'schema_version'`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := Open(context.Background(), f.path, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "schema version 2") {
		t.Fatalf("Open of an unknown schema version: %v", err)
	}
}

func TestEpochFixedPerFile(t *testing.T) {
	f := newFixture(t)
	if got := f.s.Epoch(); got != uint64(t0.Unix()) {
		t.Fatalf("epoch %d, want the Unix seconds of the first open %d", got, t0.Unix())
	}
	f.clk.Advance(time.Hour)
	f.reopen()
	if got := f.s.Epoch(); got != uint64(t0.Unix()) {
		t.Fatalf("epoch after reopen %d, want %d", got, t0.Unix())
	}
}

func TestQueueFreshFileNewerEpoch(t *testing.T) {
	a := newFixture(t)
	clk := newClock()
	clk.Advance(time.Minute)
	b, err := Open(context.Background(), filepath.Join(t.TempDir(), "queue.db"), nil, clk.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Epoch() <= a.s.Epoch() {
		t.Fatalf("a file made later has epoch %d, want above %d", b.Epoch(), a.s.Epoch())
	}
}

func TestStoreHealthy(t *testing.T) {
	f := newFixture(t)
	if err := f.s.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Healthy(context.Background()); err == nil {
		t.Fatal("Healthy on a closed store: want an error")
	}
}
