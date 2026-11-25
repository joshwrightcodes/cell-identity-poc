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
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
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
	// Revoked marks a cell that the plane revoked. Every record that the plane signs for the cell
	// carries it, until an un-revoke clears it.
	Revoked bool `json:"revoked,omitempty"`
}

// Signed is one served revision: the spec and the records.
type Signed struct {
	Revision spec.Revision      `json:"revision"`
	Bundle   mgmtapi.SpecBundle `json:"bundle"`
}

// OpState is one operation that the plane signed. Envelopes holds the SHA-256 of every envelope
// signed for the operation, and Envelope is the current one. KeyEpoch is State.Last.Epoch at the
// time of that signing. Final is the outcome of the final result, or abandoned.
type OpState struct {
	Cell      string     `json:"cell"`
	Envelopes []string   `json:"envelopes"`
	Envelope  []byte     `json:"envelope"`
	KeyEpoch  uint64     `json:"keyEpoch"`
	IssuedAt  time.Time  `json:"issuedAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	ExpiredAt time.Time  `json:"expiredAt,omitzero"`
	Served    bool       `json:"served"`
	Result    *op.Result `json:"result,omitempty"`
	ResultAt  time.Time  `json:"resultAt,omitzero"`
	Final     string     `json:"final,omitempty"`
}

// Request is one portal request for a cell. Step is the signed step of the request, nil after a
// cancel. A step with DoneAt set is closed and no longer indexed in the spec.
type Request struct {
	RequestID   string     `json:"requestId"`
	RequestedAt time.Time  `json:"requestedAt"`
	Step        *StepState `json:"step,omitempty"`
}

// StepState is one step that the plane signed. KeysAtIssue holds the sorted key identities of the
// cell when the step was signed; the close rule compares them with the keys that a bind proves.
type StepState struct {
	ID            string    `json:"id"`
	Envelope      []byte    `json:"envelope"`
	PayloadSHA256 string    `json:"payloadSHA256"`
	KeyEpoch      uint64    `json:"keyEpoch"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	DoneAt        time.Time `json:"doneAt,omitzero"`
	KeysAtIssue   []string  `json:"keysAtIssue"`
}

// open reports whether the step is signed and not closed.
func (s *StepState) open() bool { return s != nil && s.DoneAt.IsZero() }

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
	// Ops holds the operations by ID and OpOrder their IDs, oldest first. StagedKeySHA256 is the
	// fingerprint of the staged signing key; the plane trusts the staged key file only while it names it.
	Ops             map[string]*OpState `json:"ops,omitempty"`
	OpOrder         []string            `json:"opOrder,omitempty"`
	StagedKeySHA256 string              `json:"stagedKeySHA256,omitempty"`
	// Requests holds the portal requests by cell. The field is never omitted: a state without it
	// predates the portal, and NewPlane turns each bound cell of that state into a request once.
	Requests map[string]*Request `json:"requests"`
	// Bundles holds the bundle state of each target, by target name.
	Bundles map[string]*BundleState `json:"bundles,omitempty"`
	// Revocations is the mirror: one event for each revoke and un-revoke that the plane signed,
	// oldest first. LastRevocation is the revision of the newest signed revoke, and no restore goes
	// below it in the same epoch. PendingRevokes holds the revokes that wait for their revision,
	// oldest first: one revoke commits for each revision that envd reports as applied.
	Revocations    []mgmtapi.RevocationEvent `json:"revocations,omitempty"`
	LastRevocation spec.Revision             `json:"lastRevocation,omitzero"`
	PendingRevokes []PendingRevoke           `json:"pendingRevokes,omitempty"`
}

// PendingRevoke is a revoke that waits for its revision. Source is mgmtapi.RevocationSourceAdmin or
// mgmtapi.RevocationSourceOperator. EntryID and OperatorKeySHA256 name the local revocation entry
// and the operator key of an adopted entry.
type PendingRevoke struct {
	Cell              string    `json:"cell"`
	Source            string    `json:"source"`
	EntryID           string    `json:"entryId,omitempty"`
	OperatorKeySHA256 string    `json:"operatorKeySHA256,omitempty"`
	QueuedAt          time.Time `json:"queuedAt"`
}

func newState(keySHA string) *State {
	return &State{Version: stateVersion, KeySHA256: keySHA, Cells: map[string]*CellState{}, Retired: map[string]spec.Revision{}, Ops: map[string]*OpState{}, Requests: map[string]*Request{}}
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
	c.Revocations = slices.Clone(s.Revocations)
	c.PendingRevokes = slices.Clone(s.PendingRevokes)
	c.History = slices.Clone(s.History)
	c.Ops = make(map[string]*OpState, len(s.Ops))
	for k, v := range s.Ops {
		o := *v
		o.Envelopes = slices.Clone(v.Envelopes)
		c.Ops[k] = &o
	}
	c.OpOrder = slices.Clone(s.OpOrder)
	if s.Bundles != nil {
		c.Bundles = make(map[string]*BundleState, len(s.Bundles))
		for k, v := range s.Bundles {
			b := *v
			c.Bundles[k] = &b
		}
	}
	if s.Requests != nil {
		c.Requests = make(map[string]*Request, len(s.Requests))
		for k, v := range s.Requests {
			r := *v
			if v.Step != nil {
				st := *v.Step
				st.KeysAtIssue = slices.Clone(v.Step.KeysAtIssue)
				r.Step = &st
			}
			c.Requests[k] = &r
		}
	}
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
	if s.Ops == nil {
		s.Ops = map[string]*OpState{}
	}
	for id, o := range s.Ops {
		if o == nil {
			return fmt.Errorf("operation %q has no state", id)
		}
	}
	for name, r := range s.Requests {
		if r == nil {
			return fmt.Errorf("request for %q is empty", name)
		}
	}
	if len(s.OpOrder) != len(s.Ops) {
		return errors.New("operation order does not match the operations")
	}
	for _, id := range s.OpOrder {
		if s.Ops[id] == nil {
			return fmt.Errorf("operation order names unknown operation %q", id)
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
