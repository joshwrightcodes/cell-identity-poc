package hostsvc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

// ErrJournalCorrupt means journal.json exists but does not parse. The host service then refuses
// every step until an operator runs `hostsvc ctl reset-journal`.
var ErrJournalCorrupt = errors.New("step journal is corrupt")

// MaxJournalEntries is the number of entries above which the journal evicts old final entries.
const MaxJournalEntries = 64

const journalFile = "journal.json"

// JournalEntry is the journal record of one step.
type JournalEntry struct {
	Status         mgmtapi.StepStatus `json:"status"`
	EnvelopeSHA256 string             `json:"envelopeSHA256"`
	KeyEpoch       uint64             `json:"keyEpoch"`
	Envelope       string             `json:"envelope"`
	IssuedAt       time.Time          `json:"issuedAt"`
	// IndexedIn is the revision of the newest spec that indexed the step.
	IndexedIn spec.Revision `json:"indexedIn"`
	// ClosedIn is the revision of the spec that closed the step, or zero.
	ClosedIn    spec.Revision `json:"closedIn"`
	Pgid        int           `json:"pgid,omitempty"`
	LeaderStart string        `json:"leaderStart,omitempty"`
	HeartbeatAt time.Time     `json:"heartbeatAt,omitzero"`
	// StageRuns counts every start of each stage.
	StageRuns map[string]int `json:"stageRuns,omitempty"`
	// ResignSince is when the actor began to wait for a re-signed envelope.
	ResignSince time.Time `json:"resignSince,omitzero"`
}

// Closed reports whether a newer spec closed the step.
func (e JournalEntry) Closed() bool { return e.ClosedIn != (spec.Revision{}) }

// Final reports whether the step is in a state that never changes again.
func (e JournalEntry) Final() bool { return finalState(e.Status.State) }

// Running reports whether a stage of the step is running.
func (e JournalEntry) Running() bool { return runningState(e.Status.State) }

func finalState(s string) bool {
	switch s {
	case mgmtapi.StepDone, mgmtapi.StepFailedFinal, mgmtapi.StepCancelled, mgmtapi.StepRefused:
		return true
	}
	return false
}

func runningState(s string) bool {
	switch s {
	case mgmtapi.StepCreating, mgmtapi.StepAdmitting, mgmtapi.StepBootstrapping:
		return true
	}
	return false
}

type journalDoc struct {
	Entries []JournalEntry `json:"entries"`
}

// Journal keeps the step entries in memory and in journal.json. Each change is written with a
// temporary file, a sync, a rename and a sync of the directory.
type Journal struct {
	dir string
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*JournalEntry
	corrupt bool
	log     *slog.Logger
}

// OpenJournal reads dir/journal.json and deletes stale *.tmp files. A file that does not parse
// gives ErrJournalCorrupt together with a usable Journal that refuses to hold entries: Corrupt
// reports true until Reset.
func OpenJournal(dir string, now func() time.Time) (*Journal, error) {
	if now == nil {
		now = time.Now
	}
	j := &Journal{dir: dir, now: now, entries: map[string]*JournalEntry{}, log: slog.Default()}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("journal directory: %w", err)
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	for _, t := range tmps {
		_ = os.Remove(t)
	}
	data, err := os.ReadFile(filepath.Join(dir, journalFile))
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read journal: %w", err)
	}
	var doc journalDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err = dec.Decode(&doc)
	if err == nil && dec.More() {
		err = errors.New("data after the document")
	}
	if err != nil {
		j.corrupt = true
		return j, fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
	}
	for i := range doc.Entries {
		e := doc.Entries[i]
		if !mgmtapi.ValidStepStatus(e.Status) || slices.ContainsFunc(doc.Entries[:i], func(o JournalEntry) bool { return o.Status.ID == e.Status.ID }) {
			j.corrupt = true
			j.entries = map[string]*JournalEntry{}
			return j, fmt.Errorf("%w: entry %d is not valid", ErrJournalCorrupt, i+1)
		}
		j.entries[e.Status.ID] = &e
	}
	return j, nil
}

// SetLogger sets the logger of Reap and eviction.
func (j *Journal) SetLogger(l *slog.Logger) {
	j.mu.Lock()
	j.log = l
	j.mu.Unlock()
}

// Corrupt reports whether journal.json did not parse.
func (j *Journal) Corrupt() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.corrupt
}

// Dir returns the directory of the journal and the step logs.
func (j *Journal) Dir() string { return j.dir }

// LogPath returns the path of the log of step id.
func (j *Journal) LogPath(id string) string { return filepath.Join(j.dir, id+".log") }

func (j *Journal) saveLocked() error {
	doc := journalDoc{Entries: make([]JournalEntry, 0, len(j.entries))}
	for _, e := range j.sortedLocked() {
		doc.Entries = append(doc.Entries, e)
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(j.dir, journalFile), data, 0o644)
}

func (j *Journal) sortedLocked() []JournalEntry {
	out := make([]JournalEntry, 0, len(j.entries))
	for _, e := range j.entries {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b JournalEntry) int {
		if c := a.IssuedAt.Compare(b.IssuedAt); c != 0 {
			return c
		}
		return strings.Compare(a.Status.Cell+"/"+a.Status.ID, b.Status.Cell+"/"+b.Status.ID)
	})
	return out
}

// Get returns a copy of the entry of step id.
func (j *Journal) Get(id string) (JournalEntry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.entries[id]
	if !ok {
		return JournalEntry{}, false
	}
	return cloneEntry(*e), true
}

// List returns a copy of every entry in (issuedAt, cell) order.
func (j *Journal) List() []JournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := j.sortedLocked()
	for i := range out {
		out[i] = cloneEntry(out[i])
	}
	return out
}

func cloneEntry(e JournalEntry) JournalEntry {
	e.StageRuns = maps0(e.StageRuns)
	return e
}

func maps0(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Put stores e, replacing an entry with the same ID, and writes the journal. When the write fails,
// the previous entry stays in memory and Put returns the error.
func (j *Journal) Put(e JournalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.corrupt {
		return ErrJournalCorrupt
	}
	old, had := j.entries[e.Status.ID]
	c := cloneEntry(e)
	j.entries[e.Status.ID] = &c
	if err := j.saveLocked(); err != nil {
		if had {
			j.entries[e.Status.ID] = old
		} else {
			delete(j.entries, e.Status.ID)
		}
		return fmt.Errorf("write journal: %w", err)
	}
	return nil
}

// Update applies f to a copy of the entry of step id and stores the result. It returns the new
// entry, and false when the step is not in the journal.
func (j *Journal) Update(id string, f func(*JournalEntry)) (JournalEntry, bool, error) {
	cur, ok := j.Get(id)
	if !ok {
		return JournalEntry{}, false, nil
	}
	f(&cur)
	if err := j.Put(cur); err != nil {
		return JournalEntry{}, true, err
	}
	return cur, true, nil
}

// Evict removes the oldest final entries, with their logs, while the journal holds more than
// MaxJournalEntries. An entry that indexed reports true stays.
func (j *Journal) Evict(indexed func(id string) bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.corrupt {
		return
	}
	changed := false
	for _, e := range j.sortedLocked() {
		if len(j.entries) <= MaxJournalEntries {
			break
		}
		if !e.Final() || (indexed != nil && indexed(e.Status.ID)) {
			continue
		}
		delete(j.entries, e.Status.ID)
		_ = os.Remove(j.LogPath(e.Status.ID))
		changed = true
		j.log.Info("journal_evicted", "step", e.Status.ID, "cell", e.Status.Cell, "state", e.Status.State)
	}
	if changed {
		if err := j.saveLocked(); err != nil {
			j.log.Error("journal_write_failed", "error", err.Error())
		}
	}
}

// ErrLeaderChanged is what a kill function of Reap returns when the process group of an entry now
// belongs to another process.
var ErrLeaderChanged = errors.New("process group has another leader")

// Reap ends the stages that a stopped host service left running. For each entry in a running state,
// it calls kill with the recorded group and leader start time, logs orphan_reaped when kill
// succeeds, and marks the entry failed with detail interrupted, which is not an attempt.
func (j *Journal) Reap(kill func(pgid int, leaderStart string) error) {
	for _, e := range j.List() {
		if !e.Running() {
			continue
		}
		if e.Pgid != 0 {
			switch err := kill(e.Pgid, e.LeaderStart); {
			case err == nil:
				j.log.Warn("orphan_reaped", "step", e.Status.ID, "cell", e.Status.Cell, "stage", e.Status.Stage, "pgid", e.Pgid)
			case errors.Is(err, ErrLeaderChanged):
				j.log.Warn("orphan_not_ours", "step", e.Status.ID, "cell", e.Status.Cell, "pgid", e.Pgid)
			default:
				j.log.Error("orphan_kill_failed", "step", e.Status.ID, "cell", e.Status.Cell, "pgid", e.Pgid, "error", err.Error())
			}
		}
		now := j.now()
		_, _, err := j.Update(e.Status.ID, func(e *JournalEntry) {
			e.Pgid, e.LeaderStart = 0, ""
			e.Status.State = mgmtapi.StepFailed
			e.Status.Reason = step.Code
			e.Status.Detail = step.DetailInterrupted
			e.Status.UpdatedAt = now
			e.Status.RetryAt = now
		})
		if err != nil {
			j.log.Error("journal_write_failed", "error", err.Error())
		}
	}
}

// Reset deletes every entry and clears the corrupt mark. It refuses while a stage runs, unless the
// journal is corrupt. The step logs stay.
func (j *Journal) Reset() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.corrupt {
		for _, e := range j.entries {
			if e.Running() {
				return fmt.Errorf("step %s runs: cancel it first", e.Status.ID)
			}
		}
	}
	if err := os.Remove(filepath.Join(j.dir, journalFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove journal: %w", err)
	}
	j.entries = map[string]*JournalEntry{}
	j.corrupt = false
	return nil
}

// writeFileAtomic writes data to a temporary file in the directory of path, syncs it, renames it
// over path and syncs the directory.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// CheckCreateStep tells whether `hostsvc create` for cell may run: id must be the ID of a journal
// entry for cell that is in the creating state. It reads journal.json and nothing else. It never
// calls OpenJournal, because OpenJournal deletes stale *.tmp files and the host service may be
// writing one.
func CheckCreateStep(dir, id, cell string) error {
	if id == "" {
		return errors.New("create runs only for a step: POC_STEP_ID is not set")
	}
	data, err := os.ReadFile(filepath.Join(dir, journalFile))
	if err != nil {
		return fmt.Errorf("read journal: %w", err)
	}
	var doc journalDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
	}
	for _, e := range doc.Entries {
		if e.Status.ID != id {
			continue
		}
		if e.Status.Cell != cell {
			return fmt.Errorf("step %s is for cell %s, not %s", id, e.Status.Cell, cell)
		}
		if e.Status.State != mgmtapi.StepCreating {
			return fmt.Errorf("step %s is %s, not creating", id, e.Status.State)
		}
		return nil
	}
	return fmt.Errorf("step %s is not in the journal", id)
}
