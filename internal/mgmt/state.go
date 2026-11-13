package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const stateVersion = 1

// CellState is what the plane knows about one bound cell. Subjects holds the subjects that the
// current record carries.
type CellState struct {
	Issuer        string           `json:"issuer"`
	JWKS          json.RawMessage  `json:"jwks"`
	Subjects      []record.Subject `json:"subjects"`
	Record        spec.Revision    `json:"record"`
	BoundAt       time.Time        `json:"boundAt"`
	CheckedAt     time.Time        `json:"checkedAt"`
	KeysUpdatedAt time.Time        `json:"keysUpdatedAt"`
	LastCheck     string           `json:"lastCheck"`
}

// Signed is one served revision: the spec and the records.
type Signed struct {
	Revision spec.Revision      `json:"revision"`
	Bundle   mgmtapi.SpecBundle `json:"bundle"`
}

// State is the persistent state of the plane. Seq is the compare-and-swap version and rises at every
// saved change. DropRevision is the revision that released the last drop; the queue in PendingDrops
// releases its next drop only after envd reports a revision at or above it. Served is the counter of a restored revision, and 0 means the latest.
type State struct {
	Version      uint64                   `json:"version"`
	Seq          uint64                   `json:"seq"`
	KeySHA256    string                   `json:"keySHA256"`
	Last         spec.Revision            `json:"last"`
	Cells        map[string]*CellState    `json:"cells"`
	Retired      map[string]spec.Revision `json:"retired"`
	PendingDrops []string                 `json:"pendingDrops"`
	DropRevision spec.Revision            `json:"dropRevision"`
	History      []Signed                 `json:"history"`
	Served       uint64                   `json:"served"`
}

func newState(keySHA string) *State {
	return &State{Version: stateVersion, KeySHA256: keySHA, Cells: map[string]*CellState{}, Retired: map[string]spec.Revision{}}
}

// clone copies the parts that a change mutates. Byte slices and bundles are never mutated in place,
// so the copy shares them.
func (s *State) clone() *State {
	c := *s
	c.Cells = make(map[string]*CellState, len(s.Cells))
	for k, v := range s.Cells {
		cs := *v
		c.Cells[k] = &cs
	}
	c.Retired = maps.Clone(s.Retired)
	if c.Retired == nil {
		c.Retired = map[string]spec.Revision{}
	}
	c.PendingDrops = slices.Clone(s.PendingDrops)
	c.History = slices.Clone(s.History)
	return &c
}

// latest returns the newest signed revision, or nil for a state that signed nothing.
func (s *State) latest() *Signed {
	if len(s.History) == 0 {
		return nil
	}
	return &s.History[len(s.History)-1]
}

// served returns the bundle that the plane serves.
func (s *State) served() *Signed {
	if s.Served != 0 {
		for i := range s.History {
			if h := &s.History[i]; h.Revision.Epoch == s.Last.Epoch && h.Revision.Counter == s.Served {
				return h
			}
		}
	}
	return s.latest()
}

func (s *State) validate() error {
	if s.Version != stateVersion {
		return fmt.Errorf("state version %d is not %d", s.Version, stateVersion)
	}
	if s.Cells == nil {
		s.Cells = map[string]*CellState{}
	}
	if s.Retired == nil {
		s.Retired = map[string]spec.Revision{}
	}
	for name, c := range s.Cells {
		if c == nil {
			return fmt.Errorf("cell %q has no state", name)
		}
	}
	if l := s.latest(); l == nil || l.Revision != s.Last {
		return errors.New("history does not end at the last revision")
	}
	return nil
}

// Store persists the state.
type Store interface {
	// Load returns nil, nil when no state exists.
	Load() (*State, error)
	Save(*State) error
}

// FileStore keeps the state in one file. Log and Now are optional.
type FileStore struct {
	Path string
	Log  *slog.Logger
	Now  func() time.Time
}

// ErrStateInvalid means the state file parses but fails validation, for example a version that this
// binary does not know. Load never moves such a file aside.
var ErrStateInvalid = errors.New("state_invalid")

// Load reads the state. A file that does not parse moves to Path.corrupt-<unix time>, and Load
// then answers as for an absent file. A file that parses but fails validation is an error that
// wraps ErrStateInvalid, and it stays in place.
func (f *FileStore) Load() (*State, error) {
	data, err := os.ReadFile(f.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read state: %w", err)
	}
	st, perr := parseState(data)
	if perr == nil {
		if err := st.validate(); err != nil {
			return nil, fmt.Errorf("%w: %v; the file stays in place at %s; follow the README runbook section \"Recover lost management state\"", ErrStateInvalid, err, f.Path)
		}
		return st, nil
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	dest := f.Path + ".corrupt-" + strconv.FormatInt(now().Unix(), 10)
	if err := os.Rename(f.Path, dest); err != nil {
		return nil, fmt.Errorf("state does not parse (%v) and cannot move aside: %w", perr, err)
	}
	f.logger().Error("state_corrupt", "moved_to", dest, "error", perr.Error())
	return nil, nil
}

func (f *FileStore) logger() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, nil))
}

func parseState(data []byte) (*State, error) {
	var st State
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&st); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the state")
	}
	return &st, nil
}

// Save writes the state through a temporary file, a sync, a rename and a directory sync.
func (f *FileStore) Save(st *State) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	if err := writeFileAtomic(f.Path, data, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}
