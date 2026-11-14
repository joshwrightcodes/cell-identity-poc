package hostsvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

func testEntry(id, cell, state string, issued time.Time) JournalEntry {
	return JournalEntry{
		Status:         mgmtapi.StepStatus{ID: id, Cell: cell, State: state, UpdatedAt: issued},
		EnvelopeSHA256: sha256Hex([]byte(id)), KeyEpoch: 1, Envelope: "{}", IssuedAt: issued,
		IndexedIn: spec.Revision{Epoch: 1, Counter: 2},
	}
}

func idN(n int) string { return fmt.Sprintf("%032x", n) }

func TestJournalRoundTripAndAtomic(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock()
	// A stale temporary file of a write that never finished is deleted on open.
	stale := filepath.Join(dir, "journal.json.123.tmp")
	if err := os.WriteFile(stale, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale tmp file: %v, want it deleted", err)
	}
	e := testEntry(idN(1), "dev-cell-1", mgmtapi.StepQueued, clock.Now())
	e.StageRuns = map[string]int{"creating": 2}
	e.Pgid, e.LeaderStart = 4242, "1.000001"
	if err := j.Put(e); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(left) != 0 {
		t.Errorf("tmp files after a write: %v", left)
	}
	fi, err := os.Stat(filepath.Join(dir, "journal.json"))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("journal.json: %v %v", err, fi)
	}
	j2, err := OpenJournal(dir, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := j2.Get(idN(1))
	if !ok || got.Pgid != 4242 || got.LeaderStart != "1.000001" || got.StageRuns["creating"] != 2 || got.Status.Cell != "dev-cell-1" {
		t.Errorf("after reopen: %+v %v", got, ok)
	}
	// Update changes one entry and keeps the others.
	if err := j2.Put(testEntry(idN(2), "dev-cell-2", mgmtapi.StepQueued, clock.Now().Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := j2.Update(idN(1), func(e *JournalEntry) { e.Status.State = mgmtapi.StepDone }); err != nil || !ok {
		t.Fatalf("Update: %v %v", ok, err)
	}
	list := j2.List()
	if len(list) != 2 || list[0].Status.ID != idN(1) || list[0].Status.State != mgmtapi.StepDone {
		t.Errorf("List = %+v", list)
	}
	// A write that cannot rename leaves the old file and no entry change in memory.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	if os.Geteuid() != 0 {
		if err := j2.Put(testEntry(idN(3), "dev-cell-1", mgmtapi.StepQueued, clock.Now())); err == nil {
			t.Error("Put succeeded in a read-only directory")
		}
		if _, ok := j2.Get(idN(3)); ok {
			t.Error("a failed write left the entry in memory")
		}
	}
}

func TestJournalCorruptFailsClosed(t *testing.T) {
	for name, content := range map[string]string{
		"not_json":       "{",
		"unknown_field":  `{"entries":[],"extra":1}`,
		"bad_status":     `{"entries":[{"status":{"id":"zz","cell":"x","state":"queued"}}]}`,
		"duplicate_id":   fmt.Sprintf(`{"entries":[{"status":{"id":%q,"cell":"a","state":"queued"}},{"status":{"id":%q,"cell":"a","state":"queued"}}]}`, idN(1), idN(1)),
		"trailing_value": `{"entries":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "journal.json"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			j, err := OpenJournal(dir, nil)
			if !errors.Is(err, ErrJournalCorrupt) || j == nil || !j.Corrupt() {
				t.Fatalf("OpenJournal = %v %v, want ErrJournalCorrupt and a corrupt journal", j, err)
			}
			if err := j.Put(testEntry(idN(1), "dev-cell-1", mgmtapi.StepQueued, time.Now())); !errors.Is(err, ErrJournalCorrupt) {
				t.Errorf("Put on a corrupt journal = %v", err)
			}
			if err := j.Reset(); err != nil {
				t.Fatal(err)
			}
			if j.Corrupt() {
				t.Error("Reset did not clear the corrupt mark")
			}
			if err := j.Put(testEntry(idN(1), "dev-cell-1", mgmtapi.StepQueued, time.Now())); err != nil {
				t.Errorf("Put after Reset: %v", err)
			}
		})
	}
}

func TestJournalResetRefusesWhileRunning(t *testing.T) {
	j, _ := OpenJournal(t.TempDir(), nil)
	_ = j.Put(testEntry(idN(1), "dev-cell-1", mgmtapi.StepAdmitting, time.Now()))
	if err := j.Reset(); err == nil {
		t.Fatal("Reset succeeded while a stage runs")
	}
	if _, ok := j.Get(idN(1)); !ok {
		t.Fatal("the running entry is gone")
	}
}

func TestJournalEviction(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock()
	j, err := OpenJournal(dir, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	j.SetLogger(discardLog())
	base := clock.Now()
	// 1: failed (not final), 2: done but indexed, 3 to 66: done. 67 entries in all.
	states := map[int]string{1: mgmtapi.StepFailed}
	for n := 1; n <= 67; n++ {
		st := mgmtapi.StepDone
		if s, ok := states[n]; ok {
			st = s
		}
		if err := j.Put(testEntry(idN(n), "dev-cell-1", st, base.Add(time.Duration(n)*time.Second))); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(j.LogPath(idN(n)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := (FileCreateRecords{Dir: dir}).Record(idN(n), "dev-cell-1"); err != nil {
			t.Fatal(err)
		}
	}
	j.Evict(func(id string) bool { return id == idN(2) })
	list := j.List()
	if len(list) != MaxJournalEntries {
		t.Fatalf("entries after eviction = %d, want %d", len(list), MaxJournalEntries)
	}
	for _, kept := range []int{1, 2} {
		if _, ok := j.Get(idN(kept)); !ok {
			t.Errorf("entry %d was evicted: it is %s", kept, map[int]string{1: "failed, not final", 2: "indexed by the newest spec"}[kept])
		}
	}
	for _, gone := range []int{3, 4, 5} {
		if _, ok := j.Get(idN(gone)); ok {
			t.Errorf("oldest final entry %d is still there", gone)
		}
		if _, err := os.Stat(j.LogPath(idN(gone))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("log of evicted entry %d: %v, want deleted", gone, err)
		}
	}
	if _, err := os.Stat(j.LogPath(idN(1))); err != nil {
		t.Errorf("log of a kept entry was deleted: %v", err)
	}
	for _, gone := range []int{3, 4, 5} {
		if _, err := os.Stat(filepath.Join(dir, idN(gone)+".create")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("create record of evicted entry %d: %v, want deleted", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, idN(1)+".create")); err != nil {
		t.Errorf("create record of a kept entry was deleted: %v", err)
	}
	// Only non-final entries: nothing may go.
	j2, _ := OpenJournal(t.TempDir(), clock.Now)
	for n := 1; n <= 70; n++ {
		_ = j2.Put(testEntry(idN(n), "dev-cell-1", mgmtapi.StepQueued, base))
	}
	j2.Evict(nil)
	if got := len(j2.List()); got != 70 {
		t.Errorf("queued entries after eviction = %d, want 70", got)
	}
}

func TestJournalInterruptedNotAnAttempt(t *testing.T) {
	clock := newFakeClock()
	j, _ := OpenJournal(t.TempDir(), clock.Now)
	e := testEntry(idN(1), "dev-cell-1", mgmtapi.StepBootstrapping, clock.Now())
	e.Status.Stage, e.Status.Attempts = mgmtapi.StageBootstrapping, 1
	e.Pgid, e.LeaderStart = 999999, "1.000000"
	_ = j.Put(e)
	_ = j.Put(testEntry(idN(2), "dev-cell-2", mgmtapi.StepQueued, clock.Now()))
	j.Reap(func(int, string) error { return nil })
	got, _ := j.Get(idN(1))
	if got.Status.State != mgmtapi.StepFailed || got.Status.Detail != step.DetailInterrupted || got.Status.Attempts != 1 ||
		got.Pgid != 0 || got.Status.Stage != mgmtapi.StageBootstrapping {
		t.Errorf("reaped entry = %+v", got.Status)
	}
	if !mgmtapi.ValidStepStatus(got.Status) {
		t.Errorf("reaped status is not valid: %+v", got.Status)
	}
	if q, _ := j.Get(idN(2)); q.Status.State != mgmtapi.StepQueued {
		t.Errorf("a queued entry changed: %v", q.Status.State)
	}
}

func TestCreateCommandNeedsStep(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Put(testEntry(idN(1), "dev-cell-1", mgmtapi.StepCreating, time.Now()))
	_ = j.Put(testEntry(idN(2), "dev-cell-1", mgmtapi.StepAdmitting, time.Now()))
	// A write of the host service that is in flight: its temporary file must stay.
	tmp := filepath.Join(dir, "journal.json.4711.tmp")
	if err := os.WriteFile(tmp, []byte("half"), 0o644); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name     string
		id, cell string
		ok       bool
	}{
		{"creating_entry", idN(1), "dev-cell-1", true},
		{"no_step_id", "", "dev-cell-1", false},
		{"other_cell", idN(1), "dev-cell-2", false},
		{"not_creating", idN(2), "dev-cell-1", false},
		{"not_in_journal", idN(9), "dev-cell-1", false},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckCreateStep(dir, tc.id, tc.cell)
			if (err == nil) != tc.ok {
				t.Errorf("CheckCreateStep = %v, want ok %v", err, tc.ok)
			}
		})
	}
	t.Run("keeps_tmp_file", func(t *testing.T) {
		_ = CheckCreateStep(dir, idN(1), "dev-cell-1")
		if b, err := os.ReadFile(tmp); err != nil || string(b) != "half" {
			t.Errorf("the temporary file of the host service did not survive: %v", err)
		}
	})
	t.Run("no_journal", func(t *testing.T) {
		if err := CheckCreateStep(t.TempDir(), idN(1), "dev-cell-1"); err == nil {
			t.Error("no error without a journal")
		}
	})
	t.Run("corrupt_journal", func(t *testing.T) {
		d := t.TempDir()
		_ = os.WriteFile(filepath.Join(d, "journal.json"), []byte("{"), 0o644)
		if err := CheckCreateStep(d, idN(1), "dev-cell-1"); !errors.Is(err, ErrJournalCorrupt) {
			t.Errorf("CheckCreateStep = %v, want ErrJournalCorrupt", err)
		}
	})
}
