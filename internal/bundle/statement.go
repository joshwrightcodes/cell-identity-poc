package bundle

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// The fixed strings of an attestation, and its size limit.
const (
	StatementType     = "https://in-toto.io/Statement/v1"
	PredicateType     = "https://cell.poc.internal/bundle-set/v1"
	PayloadType       = "application/vnd.in-toto+json"
	MaxStatementBytes = 16 << 10

	maxTargetLabel = 59
)

// ErrSubjects marks a statement whose subjects are not the root and each component once.
var ErrSubjects = errors.New("subjects do not match the set")

// subjectsError is a subject fault. Its text names the fault, and errors.Is matches ErrSubjects.
type subjectsError string

func (e subjectsError) Error() string        { return string(e) }
func (e subjectsError) Is(target error) bool { return target == ErrSubjects }

func subjectsErr(format string, a ...any) error { return subjectsError(fmt.Sprintf(format, a...)) }

// SubjectDigest holds the digest of a subject. The strict decoder refuses any other algorithm.
type SubjectDigest struct {
	SHA256 string `json:"sha256"`
}

// Subject names one bundle of a target and gives its manifest digest, as 64 lowercase hex characters.
type Subject struct {
	Name   string        `json:"name"`
	Digest SubjectDigest `json:"digest"`
}

// PredicateComponent is a component without its digest. The digest is the subject of the same name.
type PredicateComponent struct {
	Name              string          `json:"name"`
	Wave              int             `json:"wave"`
	Namespace         string          `json:"namespace"`
	IgnoreDifferences json.RawMessage `json:"ignoreDifferences,omitempty"`
}

// Predicate states that this content at this version is approved for Target in Env.
type Predicate struct {
	Env        string               `json:"env"`
	Target     string               `json:"target"`
	Version    Version              `json:"version"`
	Components []PredicateComponent `json:"components"`
}

// Statement is an in-toto Statement v1 for a bundle set.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// RootDigest returns the digest of the root subject, as sha256:<hex>, or "" when there is none.
func (st Statement) RootDigest() string {
	want := "bundles/" + st.Predicate.Target + "/root"
	for _, s := range st.Subject {
		if s.Name == want {
			return "sha256:" + s.Digest.SHA256
		}
	}
	return ""
}

func hexOf(digest string) string { return strings.TrimPrefix(digest, "sha256:") }

// NewStatement builds the statement for set s on target in env. The root subject comes first and
// holds rootDigest, the digest of the root manifest, as sha256:<hex>. A component subject follows
// for each component, in the order of the set.
func NewStatement(env, target string, s Set, rootDigest string) Statement {
	st := Statement{
		Type:          StatementType,
		PredicateType: PredicateType,
		Predicate:     Predicate{Env: env, Target: target, Version: s.Version},
		Subject:       []Subject{{Name: "bundles/" + target + "/root", Digest: SubjectDigest{SHA256: hexOf(rootDigest)}}},
	}
	for _, c := range s.Components {
		st.Subject = append(st.Subject, Subject{Name: "bundles/" + target + "/" + c.Name, Digest: SubjectDigest{SHA256: hexOf(c.Digest)}})
		st.Predicate.Components = append(st.Predicate.Components, PredicateComponent{
			Name: c.Name, Wave: c.Wave, Namespace: c.Namespace, IgnoreDifferences: c.IgnoreDifferences,
		})
	}
	return st
}

// SignAttestation returns a DSSE envelope with payload type PayloadType that holds st, signed with
// key through record.SignEnvelope. key must be an Ed25519 private key. It refuses a statement that
// ParseAttestation would refuse, and a statement of more than MaxStatementBytes.
func SignAttestation(st Statement, key crypto.Signer) ([]byte, error) {
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("attestation key is not an Ed25519 private key")
	}
	if _, err := st.set(); err != nil {
		return nil, fmt.Errorf("%w statement: %v", record.ErrDecode, err)
	}
	body, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("encode statement: %w", err)
	}
	if len(body) > MaxStatementBytes {
		return nil, fmt.Errorf("statement of %d bytes is above %d", len(body), MaxStatementBytes)
	}
	return record.SignEnvelope(PayloadType, body, priv)
}

// ParseAttestation checks the envelope against the trusted keys and decodes the statement
// strictly. It checks the types, the shape of every field, the size, and that the subjects are the
// root and each component once, with no other. It returns the statement and the set, whose
// component digests come from the subjects. The error wraps record.ErrPayloadType,
// record.ErrSignature or record.ErrDecode. It does not check the target, the env or the clock.
func ParseAttestation(envelope []byte, keys []crypto.PublicKey) (Statement, Set, error) {
	var pubs []ed25519.PublicKey
	for _, k := range keys {
		if pub, ok := k.(ed25519.PublicKey); ok {
			pubs = append(pubs, pub)
		}
	}
	body, err := record.VerifyEnvelope(envelope, PayloadType, pubs)
	if err != nil {
		return Statement{}, Set{}, err
	}
	if len(body) > MaxStatementBytes {
		return Statement{}, Set{}, fmt.Errorf("%w statement: %d bytes are above %d", record.ErrDecode, len(body), MaxStatementBytes)
	}
	var st Statement
	if err := record.DecodeStrict(body, &st); err != nil {
		return Statement{}, Set{}, fmt.Errorf("statement: %w", err)
	}
	set, err := st.set()
	if err != nil {
		return Statement{}, Set{}, fmt.Errorf("%w statement: %w", record.ErrDecode, err)
	}
	return st, set, nil
}

func (st Statement) set() (Set, error) {
	p := st.Predicate
	switch {
	case st.Type != StatementType:
		return Set{}, fmt.Errorf("_type is %q", st.Type)
	case st.PredicateType != PredicateType:
		return Set{}, fmt.Errorf("predicateType is %q", st.PredicateType)
	case len(p.Env) > maxTargetLabel || !labelRE.MatchString(p.Env):
		return Set{}, errors.New("env is not a DNS label of at most 59 characters")
	case len(p.Target) > maxTargetLabel || !labelRE.MatchString(p.Target):
		return Set{}, errors.New("target is not a DNS label of at most 59 characters")
	case p.Version.Epoch == 0:
		return Set{}, errors.New("version epoch is 0")
	}
	digests := make(map[string]string, len(st.Subject))
	for _, s := range st.Subject {
		if _, dup := digests[s.Name]; dup {
			return Set{}, subjectsErr("subject %q appears twice", s.Name)
		}
		if !digestRE.MatchString("sha256:" + s.Digest.SHA256) {
			return Set{}, subjectsErr("subject %q has no sha256 digest of 64 lowercase hex characters", s.Name)
		}
		digests[s.Name] = s.Digest.SHA256
	}
	prefix := "bundles/" + p.Target + "/"
	set := Set{Version: p.Version, Components: make([]Component, 0, len(p.Components))}
	for _, c := range p.Components {
		d, ok := digests[prefix+c.Name]
		if !ok {
			return Set{}, subjectsErr("component %q has no subject", c.Name)
		}
		set.Components = append(set.Components, Component{
			Name: c.Name, Wave: c.Wave, Namespace: c.Namespace, Digest: "sha256:" + d, IgnoreDifferences: c.IgnoreDifferences,
		})
	}
	if err := validateComponents(set.Components); err != nil {
		return Set{}, err
	}
	if _, ok := digests[prefix+"root"]; !ok {
		return Set{}, subjectsErr("no root subject")
	}
	if len(st.Subject) != len(set.Components)+1 {
		return Set{}, subjectsErr("%d subjects for %d components", len(st.Subject), len(set.Components))
	}
	return set, nil
}
