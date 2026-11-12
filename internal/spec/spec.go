// Package spec defines the signed environment spec: an index of the cell records that the
// management plane serves, plus the cells that left the spec.
package spec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// PayloadType is the DSSE payload type of a spec.
const PayloadType = "application/vnd.poc.env-spec+json"

// MaxNameLength is the longest cell name that a spec accepts.
const MaxNameLength = 59

var (
	labelRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Revision orders the specs and records of one environment. The epoch rises at each signing key
// rotation, and the counter rises at each signed change.
type Revision struct {
	Epoch   uint64 `json:"epoch"`
	Counter uint64 `json:"counter"`
}

// Compare returns -1, 0 or 1 when r is below, equal to or above o. It compares the epoch first.
func (r Revision) Compare(o Revision) int {
	switch {
	case r.Epoch != o.Epoch:
		return cmp(r.Epoch, o.Epoch)
	default:
		return cmp(r.Counter, o.Counter)
	}
}

func cmp(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Entry indexes one record: the cell, the revision of the record and the digest of its payload.
type Entry struct {
	Name         string   `json:"name"`
	Revision     Revision `json:"revision"`
	RecordSHA256 string   `json:"recordSHA256"`
}

// Retired marks a cell that left the spec, with the revision of its last record.
type Retired struct {
	Name     string   `json:"name"`
	Revision Revision `json:"revision"`
}

// Spec is the signed payload. Cells and Retired hold names in strictly ascending order.
type Spec struct {
	Env      string    `json:"env"`
	Revision Revision  `json:"revision"`
	Cells    []Entry   `json:"cells"`
	Retired  []Retired `json:"retired"`
}

// Sign returns a DSSE envelope that holds the spec signed with key. It runs Validate first, so it
// never signs a spec that Verify refuses.
func Sign(s Spec, key ed25519.PrivateKey) ([]byte, error) {
	if s.Cells == nil {
		s.Cells = []Entry{}
	}
	if s.Retired == nil {
		s.Retired = []Retired{}
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("refusing to sign: %w", err)
	}
	body, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encode spec: %w", err)
	}
	return record.SignEnvelope(PayloadType, body, key)
}

// Verify checks the envelope against the trusted keys, decodes the spec strictly and validates its
// index. It returns the spec and the raw signed payload. The decode refuses unknown, duplicate and
// case-folded members, trailing data, and a missing or null list. The error wraps
// record.ErrPayloadType, record.ErrSignature or record.ErrDecode, and every index error wraps
// record.ErrDecode.
func Verify(envelope []byte, keys []ed25519.PublicKey) (Spec, []byte, error) {
	body, err := record.VerifyEnvelope(envelope, PayloadType, keys)
	if err != nil {
		return Spec{}, nil, err
	}
	var s Spec
	if err := record.DecodeStrict(body, &s); err != nil {
		return Spec{}, nil, fmt.Errorf("spec: %w", err)
	}
	if s.Cells == nil || s.Retired == nil {
		return Spec{}, nil, fmt.Errorf("%w spec: cells and retired must be lists", record.ErrDecode)
	}
	if err := s.Validate(); err != nil {
		return Spec{}, nil, fmt.Errorf("%w spec: %v", record.ErrDecode, err)
	}
	return s, body, nil
}

// The errors of CheckRecord.
var (
	// ErrUnindexed means the spec has no entry for the record name.
	ErrUnindexed = errors.New("spec has no entry for the record")
	// ErrMismatch means a record differs from its entry in the spec.
	ErrMismatch = errors.New("record differs from its spec entry")
)

// CheckRecord checks that the record c, whose signed payload is payload, is the record that the spec
// indexes under name: the same name, the spec env, the entry revision and the entry digest.
func (s Spec) CheckRecord(name string, c record.Cell, payload []byte) error {
	var entry *Entry
	for i := range s.Cells {
		if s.Cells[i].Name == name {
			entry = &s.Cells[i]
			break
		}
	}
	switch {
	case entry == nil:
		return fmt.Errorf("%w: %q", ErrUnindexed, name)
	case c.Name != name:
		return fmt.Errorf("%w: record names cell %q, entry is %q", ErrMismatch, c.Name, name)
	case c.Env != s.Env:
		return fmt.Errorf("%w: record env %q, spec env %q", ErrMismatch, c.Env, s.Env)
	case RecordRevision(c) != entry.Revision:
		return fmt.Errorf("%w: record revision %v, entry revision %v", ErrMismatch, RecordRevision(c), entry.Revision)
	case RecordDigest(payload) != entry.RecordSHA256:
		return fmt.Errorf("%w: record digest differs for %q", ErrMismatch, name)
	}
	return nil
}

// RecordDigest returns the lowercase hex SHA-256 of a record payload.
func RecordDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// RecordRevision returns the revision that a record carries.
func RecordRevision(c record.Cell) Revision {
	return Revision{Epoch: c.Epoch, Counter: c.Counter}
}

func (r Revision) valid() bool { return r.Epoch >= 1 && r.Counter >= 1 }

// ValidName reports whether n is a cell name that a spec accepts: a DNS label of at most
// MaxNameLength characters.
func ValidName(n string) bool { return len(n) <= MaxNameLength && labelRE.MatchString(n) }

// Validate checks the rules that Verify applies to the index: a DNS label env, revisions of at
// least 1, valid names in strictly ascending order in each list, no name in both lists, digests of
// 64 lowercase hex characters, and no revision above the spec revision.
func (s Spec) Validate() error {
	if len(s.Env) > 63 || !labelRE.MatchString(s.Env) {
		return errors.New("env is not a DNS label")
	}
	if !s.Revision.valid() {
		return errors.New("spec revision needs an epoch and a counter of at least 1")
	}
	cells := make(map[string]bool, len(s.Cells))
	prev := ""
	for i, e := range s.Cells {
		if !ValidName(e.Name) {
			return fmt.Errorf("cell %d has an invalid name", i)
		}
		if i > 0 && e.Name <= prev {
			return fmt.Errorf("cell %q is not in strictly ascending order", e.Name)
		}
		prev = e.Name
		cells[e.Name] = true
		if !digestRE.MatchString(e.RecordSHA256) {
			return fmt.Errorf("cell %q has an invalid record digest", e.Name)
		}
		if !e.Revision.valid() || e.Revision.Compare(s.Revision) > 0 {
			return fmt.Errorf("cell %q has a revision outside 1 to the spec revision", e.Name)
		}
	}
	prev = ""
	for i, r := range s.Retired {
		if !ValidName(r.Name) {
			return fmt.Errorf("retired cell %d has an invalid name", i)
		}
		if i > 0 && r.Name <= prev {
			return fmt.Errorf("retired cell %q is not in strictly ascending order", r.Name)
		}
		prev = r.Name
		if cells[r.Name] {
			return fmt.Errorf("cell %q is in both lists", r.Name)
		}
		if !r.Revision.valid() || r.Revision.Compare(s.Revision) > 0 {
			return fmt.Errorf("retired cell %q has a revision outside 1 to the spec revision", r.Name)
		}
	}
	return nil
}
