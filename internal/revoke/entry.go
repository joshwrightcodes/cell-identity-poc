// Package revoke defines the signed local revocation entry: an operator key revokes a cell while
// the cell or its environment is cut off from the management plane. It also holds the operator
// seed and key formats, and the admit and settle rules of the overlay that envd holds.
package revoke

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	// PayloadType is the DSSE payload type of a local revocation entry.
	PayloadType = "application/vnd.poc.local-revocation+json"
	// MaxEntryBytes is the largest envelope of an entry.
	MaxEntryBytes = 4 << 10
	// MaxHeld is the most entries that the overlay holds.
	MaxHeld = 16
)

// maxEnvLength is the longest env that a spec accepts.
const maxEnvLength = 63

var (
	idRE    = regexp.MustCompile(`^[0-9a-f]{16}$`)
	labelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// Entry revokes one cell of one environment. Record is the revision of the cell record that envd
// held when the operator signed the entry.
type Entry struct {
	ID       string        `json:"id"`
	Env      string        `json:"env"`
	Cell     string        `json:"cell"`
	Record   spec.Revision `json:"record"`
	IssuedAt time.Time     `json:"issuedAt"`
}

func (e Entry) validate() error {
	switch {
	case !idRE.MatchString(e.ID):
		return errors.New("id is not 16 lowercase hex characters")
	case len(e.Env) > maxEnvLength || !labelRE.MatchString(e.Env):
		return errors.New("env is not a DNS label")
	case !spec.ValidName(e.Cell):
		return errors.New("cell is not a valid cell name")
	case e.Record.Epoch < 1 || e.Record.Counter < 1:
		return errors.New("record revision is below 1.1")
	case e.IssuedAt.IsZero():
		return errors.New("issuedAt is zero")
	}
	return nil
}

// Sign returns a DSSE envelope that holds e signed with key. It runs the rules of Verify first, so
// it never signs an entry that Verify refuses. The error wraps record.ErrDecode for a refused entry.
func Sign(e Entry, key ed25519.PrivateKey) ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, fmt.Errorf("refusing to sign: %w entry: %v", record.ErrDecode, err)
	}
	body, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode entry: %w", err)
	}
	env, err := record.SignEnvelope(PayloadType, body, key)
	if err != nil {
		return nil, err
	}
	if len(env) > MaxEntryBytes {
		return nil, fmt.Errorf("%w entry: envelope of %d bytes is above %d", record.ErrDecode, len(env), MaxEntryBytes)
	}
	return env, nil
}

// Verify checks the envelope against the trusted keys, decodes the entry strictly and checks its
// shape. It does not check the env, the cell records or the clock: Admit does. The error wraps
// record.ErrPayloadType, record.ErrSignature or record.ErrDecode.
func Verify(envelope []byte, keys []ed25519.PublicKey) (Entry, error) {
	if len(envelope) > MaxEntryBytes {
		return Entry{}, fmt.Errorf("%w entry: envelope of %d bytes is above %d", record.ErrDecode, len(envelope), MaxEntryBytes)
	}
	body, err := record.VerifyEnvelope(envelope, PayloadType, keys)
	if err != nil {
		return Entry{}, err
	}
	var e Entry
	if err := record.DecodeStrict(body, &e); err != nil {
		return Entry{}, fmt.Errorf("entry: %w", err)
	}
	if err := e.validate(); err != nil {
		return Entry{}, fmt.Errorf("%w entry: %v", record.ErrDecode, err)
	}
	return e, nil
}
