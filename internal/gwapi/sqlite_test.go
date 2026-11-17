package gwapi

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestQueueDSNPragmas checks that the driver version that go.mod pins reads the DSN of the
// gateway queue: WAL, full synchronous, a 5 s busy timeout and one open connection.
func TestQueueDSNPragmas(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "queue.db") +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	for pragma, want := range map[string]string{"journal_mode": "wal", "synchronous": "2", "busy_timeout": "5000"} {
		var got string
		if err := db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil || got != want {
			t.Errorf("PRAGMA %s = %q, %v; want %q", pragma, got, err, want)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n := db.Stats().OpenConnections; n != 1 {
		t.Fatalf("%d open connections, want 1", n)
	}
}
