// Package step defines the signed provisioning step: the order, signed with the management key,
// that tells the host service to create one cell cluster and bring it up.
package step

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// PayloadType is the DSSE payload type of a step.
const PayloadType = "application/vnd.poc.provision-step+json"

// KindCellCreate creates one cell cluster and brings it up. It is the only kind of step.
const KindCellCreate = "cell.create"

// Limits of a step.
const (
	// DefaultTTL is the lifetime of a step when the signer is not told another.
	DefaultTTL = 6 * time.Hour
	// MinTTL is the shortest time between IssuedAt and ExpiresAt.
	MinTTL = 10 * time.Minute
	// MaxTTL is the longest time between IssuedAt and ExpiresAt.
	MaxTTL = 24 * time.Hour
	// MaxSkew is how far IssuedAt may lie in the future of the verifier clock.
	MaxSkew = 60 * time.Second

	maxLabel = 59
)

// TestDigest is the lowercase hex SHA-256 of the string "other". A step that carries it as its
// bootstrap digest is a test step, which no host service accepts for a real bootstrap.
const TestDigest = "d9298a10d1b0735837dc4bd85dac641b0f3cef27a47e5d53a54f2f3f5b2fcffa"

var (
	idRE     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	labelRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ClusterRef describes the cluster that the step creates: its two subnets and its service account
// issuer.
type ClusterRef struct {
	PodSubnet     string `json:"podSubnet"`
	ServiceSubnet string `json:"serviceSubnet"`
	Issuer        string `json:"issuer"`
}

// Step is the signed body of a step envelope.
type Step struct {
	ID              string     `json:"id"`
	Env             string     `json:"env"`
	Cell            string     `json:"cell"`
	Kind            string     `json:"kind"`
	Version         int        `json:"version"`
	KeyEpoch        uint64     `json:"keyEpoch"`
	IssuedAt        time.Time  `json:"issuedAt"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	Cluster         ClusterRef `json:"cluster"`
	BootstrapSHA256 string     `json:"bootstrapSHA256"`
}

// NewID returns a random step ID: 128 bits as 32 lowercase hex characters.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("step: no randomness: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Sign returns a DSSE envelope that holds the step signed with key. It runs the field rules of
// Verify first, so it never signs a step that Verify refuses. The error wraps record.ErrDecode.
func Sign(s Step, key ed25519.PrivateKey) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("refusing to sign: %w step: %v", record.ErrDecode, err)
	}
	body, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encode step: %w", err)
	}
	return record.SignEnvelope(PayloadType, body, key)
}

// Verify checks the envelope against the trusted keys, decodes the step strictly and checks its
// shape. It returns the step and the raw signed payload. The error wraps record.ErrPayloadType,
// record.ErrSignature or record.ErrDecode. It does not check the target or the clock: use Check.
func Verify(envelope []byte, keys []ed25519.PublicKey) (Step, []byte, error) {
	body, err := record.VerifyEnvelope(envelope, PayloadType, keys)
	if err != nil {
		return Step{}, nil, err
	}
	var s Step
	if err := record.DecodeStrict(body, &s); err != nil {
		return Step{}, nil, fmt.Errorf("step: %w", err)
	}
	if err := s.validate(); err != nil {
		return Step{}, nil, fmt.Errorf("%w step: %v", record.ErrDecode, err)
	}
	return s, body, nil
}

func validLabel(s string) bool { return len(s) <= maxLabel && labelRE.MatchString(s) }

func validSubnet(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is4() && p.Masked() == p && p.String() == s
}

func validIssuer(s string) bool {
	if strings.ContainsAny(s, "?#") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil &&
		u.Opaque == "" && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && u.Fragment == ""
}

func (s Step) validate() error {
	switch {
	case !idRE.MatchString(s.ID):
		return errors.New("id is not 32 lowercase hex characters")
	case s.Version != 1:
		return fmt.Errorf("version %d is not 1", s.Version)
	case s.KeyEpoch == 0:
		return errors.New("keyEpoch is 0")
	case s.Kind != KindCellCreate:
		return fmt.Errorf("kind %q is not %s", s.Kind, KindCellCreate)
	case !validLabel(s.Env):
		return errors.New("env is not a DNS label of at most 59 characters")
	case !validLabel(s.Cell):
		return errors.New("cell is not a DNS label of at most 59 characters")
	case !validSubnet(s.Cluster.PodSubnet):
		return errors.New("podSubnet is not a canonical IPv4 prefix")
	case !validSubnet(s.Cluster.ServiceSubnet):
		return errors.New("serviceSubnet is not a canonical IPv4 prefix")
	case !validIssuer(s.Cluster.Issuer):
		return errors.New("issuer is not an https URL with a host and no path, query or fragment")
	case !digestRE.MatchString(s.BootstrapSHA256):
		return errors.New("bootstrapSHA256 is not 64 lowercase hex characters")
	case !s.ExpiresAt.After(s.IssuedAt):
		return errors.New("expiresAt is not after issuedAt")
	}
	if ttl := s.ExpiresAt.Sub(s.IssuedAt); ttl < MinTTL || ttl > MaxTTL {
		return fmt.Errorf("lifetime %s is outside %s to %s", ttl, MinTTL, MaxTTL)
	}
	return nil
}

// Code is the reason code of every refused step. The detail says why.
const Code = "step_invalid"

// The details of a refused or failed step. The first twelve are the details of every checker. The
// rest belong to the host service.
const (
	DetailSignatureInvalid  = "signature_invalid"
	DetailPayloadInvalid    = "payload_invalid"
	DetailEnvMismatch       = "env_mismatch"
	DetailCellUnknown       = "cell_unknown"
	DetailClusterMismatch   = "cluster_mismatch"
	DetailExpired           = "expired"
	DetailNotYetValid       = "not_yet_valid"
	DetailBootstrapMismatch = "bootstrap_mismatch"
	DetailStepConflict      = "step_conflict"
	DetailStepUnindexed     = "step_unindexed"
	DetailStepMissing       = "step_missing"
	DetailRevisionOld       = "revision_old"

	DetailPeerNotAllowed = "peer_not_allowed"
	DetailRateLimited    = "rate_limited"
	DetailQueueFull      = "queue_full"
	DetailSpecBehind     = "spec_behind"
	DetailJournalCorrupt = "journal_corrupt"
	DetailCancelled      = "cancelled"
	// DetailTimeout means a stage ran past its limit.
	DetailTimeout = "timeout"
	// DetailInterrupted means the host service stopped while a stage ran.
	DetailInterrupted = "interrupted"
	// DetailStageFailed means a stage exited with a non-zero status.
	DetailStageFailed = "stage_failed"
)

// Details returns every detail string.
func Details() []string {
	return []string{
		DetailSignatureInvalid, DetailPayloadInvalid, DetailEnvMismatch, DetailCellUnknown, DetailClusterMismatch,
		DetailExpired, DetailNotYetValid, DetailBootstrapMismatch, DetailStepConflict, DetailStepUnindexed,
		DetailStepMissing, DetailRevisionOld, DetailPeerNotAllowed, DetailRateLimited, DetailQueueFull,
		DetailSpecBehind, DetailJournalCorrupt, DetailCancelled, DetailTimeout, DetailInterrupted, DetailStageFailed,
	}
}

// Error is a refusal of a step with one of the details above.
type Error struct{ Detail string }

func (e *Error) Error() string { return "step refused: " + e.Detail }

// DetailOf maps an error of Verify or Check to a detail: an *Error gives its detail, a signature
// error gives signature_invalid, and every other error gives payload_invalid.
func DetailOf(err error) string {
	var e *Error
	switch {
	case errors.As(err, &e):
		return e.Detail
	case errors.Is(err, record.ErrSignature):
		return DetailSignatureInvalid
	}
	return DetailPayloadInvalid
}

// Check tests a verified step against the environment and the clock. It returns an *Error with
// env_mismatch, expired (at ExpiresAt exactly and after) or not_yet_valid (IssuedAt more than
// MaxSkew after now).
func Check(s Step, env string, now time.Time) error {
	switch {
	case s.Env != env:
		return &Error{Detail: DetailEnvMismatch}
	case !now.Before(s.ExpiresAt):
		return &Error{Detail: DetailExpired}
	case s.IssuedAt.After(now.Add(MaxSkew)):
		return &Error{Detail: DetailNotYetValid}
	}
	return nil
}

// Peek reads the ID, cell and key epoch of a step envelope without checking any signature. Use it
// only for routing and logs. It refuses an ID or cell that has the wrong shape, so a forged
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
		return "", "", 0, fmt.Errorf("%w step: %v", record.ErrDecode, err)
	}
	if !idRE.MatchString(head.ID) || !validLabel(head.Cell) {
		return "", "", 0, fmt.Errorf("%w step: id or cell has the wrong shape", record.ErrDecode)
	}
	return head.ID, head.Cell, head.KeyEpoch, nil
}

// PayloadSHA256 returns the lowercase hex SHA-256 of a step payload. The spec index holds this
// digest.
func PayloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// SameExceptEpoch reports whether a and b are the same step signed under two key epochs: every
// field matches except KeyEpoch, which the comparison leaves out.
func SameExceptEpoch(a, b Step) bool {
	return a.ID == b.ID && a.Env == b.Env && a.Cell == b.Cell && a.Kind == b.Kind && a.Version == b.Version &&
		a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt) && a.Cluster == b.Cluster &&
		a.BootstrapSHA256 == b.BootstrapSHA256
}
