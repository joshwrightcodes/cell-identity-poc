// Package op defines the signed operation that the management plane sends to a cell, and the
// results and status that the cell sends back.
package op

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// PayloadType is the DSSE payload type of an operation.
const PayloadType = "application/vnd.poc.operation+json"

// Limits of an operation.
const (
	// MaxTTL is the longest time between IssuedAt and ExpiresAt.
	MaxTTL = time.Hour
	// MinTTL is the shortest time between IssuedAt and ExpiresAt.
	MinTTL = time.Second
	// MaxSkew is how far IssuedAt may lie in the future of the verifier clock.
	MaxSkew = 60 * time.Second
	// RecordRetention is how long a cell keeps the record of an operation after it is reported.
	RecordRetention = 24 * time.Hour

	maxLabel = 59
)

// KindDemoAppend appends one line to the demo log of a cell.
const KindDemoAppend = "demo.append"

var (
	idRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	labelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// Operation is the signed body of an operation envelope.
type Operation struct {
	ID        string          `json:"id"`
	Env       string          `json:"env"`
	Cell      string          `json:"cell"`
	Kind      string          `json:"kind"`
	Version   int             `json:"version"`
	KeyEpoch  uint64          `json:"keyEpoch"`
	IssuedAt  time.Time       `json:"issuedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
	Args      json.RawMessage `json:"args"`
}

// NewID returns a random operation ID: 128 bits as 32 lowercase hex characters.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("op: no randomness: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Sign returns a DSSE envelope that holds the operation signed with key.
func Sign(o Operation, key ed25519.PrivateKey) ([]byte, error) {
	body, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("encode operation: %w", err)
	}
	return record.SignEnvelope(PayloadType, body, key)
}

// Verify checks the envelope against the trusted keys, decodes the operation strictly and checks
// its shape. It returns the operation and the raw signed payload. The error wraps
// record.ErrPayloadType, record.ErrSignature or record.ErrDecode. It does not check the kind, the
// target or the clock.
func Verify(envelope []byte, keys []ed25519.PublicKey) (Operation, []byte, error) {
	body, err := record.VerifyEnvelope(envelope, PayloadType, keys)
	if err != nil {
		return Operation{}, nil, err
	}
	var o Operation
	if err := record.DecodeStrict(body, &o); err != nil {
		return Operation{}, nil, fmt.Errorf("operation: %w", err)
	}
	if err := o.validate(); err != nil {
		return Operation{}, nil, fmt.Errorf("%w operation: %v", record.ErrDecode, err)
	}
	return o, body, nil
}

func validLabel(s string) bool { return len(s) <= maxLabel && labelRE.MatchString(s) }

func (o Operation) validate() error {
	switch {
	case !idRE.MatchString(o.ID):
		return errors.New("id is not 32 lowercase hex characters")
	case o.Version != 1:
		return fmt.Errorf("version %d is not 1", o.Version)
	case o.KeyEpoch == 0:
		return errors.New("keyEpoch is 0")
	case !validLabel(o.Env):
		return errors.New("env is not a DNS label of at most 59 characters")
	case !validLabel(o.Cell):
		return errors.New("cell is not a DNS label of at most 59 characters")
	case !o.ExpiresAt.After(o.IssuedAt):
		return errors.New("expiresAt is not after issuedAt")
	}
	if ttl := o.ExpiresAt.Sub(o.IssuedAt); ttl < MinTTL || ttl > MaxTTL {
		return fmt.Errorf("lifetime %s is outside %s to %s", ttl, MinTTL, MaxTTL)
	}
	return nil
}

// Peek reads the ID, cell and key epoch of an operation envelope without checking any signature.
// Use it only for routing and logs. It refuses an ID or cell that has the wrong shape, so a forged
// envelope cannot put free text in a log line. The error wraps record.ErrPayloadType or
// record.ErrDecode.
func Peek(envelope []byte) (id, cell string, keyEpoch uint64, err error) {
	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return "", "", 0, fmt.Errorf("%w envelope: %v", record.ErrDecode, err)
	}
	if env.PayloadType != PayloadType {
		return "", "", 0, fmt.Errorf("%w %q", record.ErrPayloadType, env.PayloadType)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", "", 0, fmt.Errorf("%w payload: %v", record.ErrDecode, err)
	}
	var head struct {
		ID       string `json:"id"`
		Cell     string `json:"cell"`
		KeyEpoch uint64 `json:"keyEpoch"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return "", "", 0, fmt.Errorf("%w operation: %v", record.ErrDecode, err)
	}
	if !idRE.MatchString(head.ID) || !validLabel(head.Cell) {
		return "", "", 0, fmt.Errorf("%w operation: id or cell has the wrong shape", record.ErrDecode)
	}
	return head.ID, head.Cell, head.KeyEpoch, nil
}

// EnvelopeSHA256 returns the lowercase hex SHA-256 of the envelope bytes.
func EnvelopeSHA256(envelope []byte) string {
	sum := sha256.Sum256(envelope)
	return hex.EncodeToString(sum[:])
}

// MaxLine is the longest line of a demo.append operation.
const MaxLine = 200

// DemoAppend is the args of a demo.append operation.
type DemoAppend struct {
	Line string `json:"line"`
}

// ParseDemoAppend decodes the args of a demo.append operation. The line holds 1 to 200 printable
// ASCII characters.
func ParseDemoAppend(args json.RawMessage) (DemoAppend, error) {
	var d DemoAppend
	if err := record.DecodeStrict(args, &d); err != nil {
		return DemoAppend{}, err
	}
	if len(d.Line) < 1 || len(d.Line) > MaxLine {
		return DemoAppend{}, fmt.Errorf("%w demo.append: line length is outside 1 to %d", record.ErrDecode, MaxLine)
	}
	for i := 0; i < len(d.Line); i++ {
		if c := d.Line[i]; c < 0x20 || c > 0x7e {
			return DemoAppend{}, fmt.Errorf("%w demo.append: line has a character that is not printable ASCII", record.ErrDecode)
		}
	}
	return d, nil
}

// Fence orders the work that a gateway hands out: the epoch first, then the counter.
type Fence struct {
	Epoch   uint64 `json:"epoch"`
	Counter uint64 `json:"counter"`
}

// Compare returns -1, 0 or 1 when f is below, equal to or above o.
func (f Fence) Compare(o Fence) int {
	switch {
	case f.Epoch != o.Epoch:
		if f.Epoch < o.Epoch {
			return -1
		}
		return 1
	case f.Counter < o.Counter:
		return -1
	case f.Counter > o.Counter:
		return 1
	}
	return 0
}

// The outcomes of an operation. The first four are final and go up to the management plane. The
// last two are local to a cell.
const (
	OutcomeApplied        = "applied"
	OutcomeAlreadyApplied = "already_applied"
	OutcomeExpired        = "expired"
	OutcomeRefused        = "refused"
	OutcomeLeaseLost      = "lease_lost"
	OutcomeStoreFull      = "store_full"
)

// The reasons of celld for a refused operation, and the two local reasons.
const (
	ReasonSignatureInvalid = "signature_invalid"
	ReasonPayloadInvalid   = "payload_invalid"
	ReasonWrongTarget      = "wrong_target"
	ReasonEnvMismatch      = "env_mismatch"
	ReasonKindUnknown      = "kind_unknown"
	ReasonStoreFull        = "store_full"
	ReasonLeaseLost        = "lease_lost"
)

// IsFinal reports whether outcome ends an operation: applied, already_applied, expired or refused.
func IsFinal(outcome string) bool {
	switch outcome {
	case OutcomeApplied, OutcomeAlreadyApplied, OutcomeExpired, OutcomeRefused:
		return true
	}
	return false
}

// Result is what celld reports for one envelope. A refusal before the signature passes has an empty
// OpID and the peeked ID in PeekedID. EnvelopeSHA256 is the digest of the bytes that celld received.
type Result struct {
	OpID           string    `json:"opId,omitempty"`
	PeekedID       string    `json:"peekedId,omitempty"`
	Cell           string    `json:"cell"`
	Pod            string    `json:"pod,omitempty"`
	Outcome        string    `json:"outcome"`
	Reason         string    `json:"reason,omitempty"`
	Fence          Fence     `json:"fence"`
	At             time.Time `json:"at"`
	EnvelopeSHA256 string    `json:"envelopeSHA256"`
}

// Status is the periodic report of one celld pod.
type Status struct {
	Cell               string    `json:"cell"`
	Pod                string    `json:"pod"`
	PodUID             string    `json:"podUID"`
	Seq                uint64    `json:"seq"`
	At                 time.Time `json:"at"`
	SVIDExpiresAt      time.Time `json:"svidExpiresAt"`
	OldestUnreportedAt time.Time `json:"oldestUnreportedAt"`
	Applied            uint64    `json:"applied"`
	Refused            uint64    `json:"refused"`
	ForgedSeen         uint64    `json:"forgedSeen"`
	Unreported         uint64    `json:"unreported"`
	Records            uint64    `json:"records"`
	Version            string    `json:"version"`
}
