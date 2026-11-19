// Package revoke defines the signed local revocation entry: an operator key revokes a cell while
// the cell or its environment is cut off from the management plane. It also holds the operator
// seed and key formats, and the admit and settle rules of the overlay that envd holds.
package revoke

import (
	"crypto/ed25519"
	"encoding/base64"
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
	// MaxEntryBytes is the largest envelope of an entry that Verify reads, whitespace included.
	MaxEntryBytes = 4 << 10
	// MaxCanonicalBytes bounds the envelope that Sign writes for the longest env and cell and the
	// highest revision. The overlay holds envelopes in this form, so a body that carries MaxHeld
	// entries needs at most MaxHeld times this size for them.
	MaxCanonicalBytes = 1 << 10
	// MaxHeld is the most entries that the overlay holds.
	MaxHeld = 16
)

// maxEnvLength is the longest env that a spec accepts.
const maxEnvLength = 63

// ErrTooLarge means an envelope is longer than MaxEntryBytes. Verify checks it before any parse,
// and the error also wraps record.ErrDecode.
var ErrTooLarge = errors.New("entry envelope is too large")

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

// Sign returns a DSSE envelope that holds e signed with key, in the one form that Verify accepts. It
// runs the rules of Verify first, so it never signs an entry that Verify refuses. The error wraps
// record.ErrDecode for a refused entry.
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
	if len(env) > MaxCanonicalBytes {
		return nil, fmt.Errorf("%w entry: %w: %d bytes, limit %d", record.ErrDecode, ErrTooLarge, len(env), MaxCanonicalBytes)
	}
	return env, nil
}

// canonical is the one envelope form that Sign writes: the payload type, the standard base64 of the
// payload, and one signature with no key ID. The field order is the order of record.SignEnvelope.
type canonical struct {
	PayloadType string         `json:"payloadType"`
	Payload     string         `json:"payload"`
	Signatures  []canonicalSig `json:"signatures"`
}

type canonicalSig struct {
	Sig string `json:"sig"`
}

// Verify checks the envelope against the trusted keys, decodes the entry strictly and checks its
// shape. It accepts only the form that Sign writes, with any JSON whitespace and member order:
// at most MaxEntryBytes, checked before any parse, no member besides payloadType, payload and
// signatures, exactly one signature with no keyid, and the canonical standard base64 of the payload
// and of the signature. It does not check the env, the cell records or the clock: Admit does. The
// error wraps record.ErrPayloadType, record.ErrSignature or record.ErrDecode, and ErrTooLarge for an
// envelope above the limit.
func Verify(envelope []byte, keys []ed25519.PublicKey) (Entry, error) {
	e, _, err := verify(envelope, keys)
	return e, err
}

// verify is Verify that also returns the envelope in the compact form that Sign writes.
func verify(envelope []byte, keys []ed25519.PublicKey) (Entry, []byte, error) {
	if len(envelope) > MaxEntryBytes {
		return Entry{}, nil, fmt.Errorf("%w entry: %w: %d bytes, limit %d", record.ErrDecode, ErrTooLarge, len(envelope), MaxEntryBytes)
	}
	var env canonical
	if err := record.DecodeStrict(envelope, &env); err != nil {
		return Entry{}, nil, fmt.Errorf("entry envelope: %w", err)
	}
	if env.PayloadType != PayloadType {
		return Entry{}, nil, fmt.Errorf("%w %q", record.ErrPayloadType, env.PayloadType)
	}
	switch {
	case len(env.Signatures) == 0:
		return Entry{}, nil, fmt.Errorf("%w: entry envelope has no signature", record.ErrSignature)
	case len(env.Signatures) > 1:
		return Entry{}, nil, fmt.Errorf("%w entry envelope: %d signatures, want 1", record.ErrDecode, len(env.Signatures))
	case !canonicalBase64(env.Payload):
		return Entry{}, nil, fmt.Errorf("%w entry envelope: payload is not canonical standard base64", record.ErrDecode)
	case !canonicalBase64(env.Signatures[0].Sig):
		return Entry{}, nil, fmt.Errorf("%w entry envelope: signature is not canonical standard base64", record.ErrDecode)
	}
	form, err := json.Marshal(env)
	if err != nil {
		return Entry{}, nil, fmt.Errorf("encode entry envelope: %w", err)
	}
	body, err := record.VerifyEnvelope(form, PayloadType, keys)
	if err != nil {
		return Entry{}, nil, err
	}
	var e Entry
	if err := record.DecodeStrict(body, &e); err != nil {
		return Entry{}, nil, fmt.Errorf("entry: %w", err)
	}
	if err := e.validate(); err != nil {
		return Entry{}, nil, fmt.Errorf("%w entry: %v", record.ErrDecode, err)
	}
	return e, form, nil
}

// canonicalBase64 reports whether s is the standard base64 encoding of the bytes it decodes to.
func canonicalBase64(s string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && base64.StdEncoding.EncodeToString(raw) == s
}

// Stale reports whether e names a record revision below current, the revision of the signed
// record of its cell. envd refuses a stale entry, and so must every other reader that adopts one.
func Stale(e Entry, current spec.Revision) bool {
	return e.Record.Compare(current) < 0
}
