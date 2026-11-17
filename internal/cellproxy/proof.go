package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
)

// ProofFunc runs on a client connection after the handshake and before the first payload byte. It
// writes the proof frame of the stream.
type ProofFunc func(ctx context.Context, conn *tls.Conn) error

// NewProofWriter returns a ProofFunc that asks tokens for a token whose audience binds the stream
// of cell and role to the TLS session of conn, and writes it as one proof frame.
func NewProofWriter(tokens satoken.TokenFunc, cell, role string) ProofFunc {
	return func(ctx context.Context, conn *tls.Conn) error {
		binding, err := proof.Binding(conn.ConnectionState())
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, proof.FrameTimeout)
		defer cancel()
		token, err := tokens(ctx, proof.StreamAudience(cell, role, binding))
		if err != nil {
			return fmt.Errorf("proof token: %w", err)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(proof.FrameTimeout))
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
		return proof.WriteFrame(conn, token)
	}
}

// ProofCheck makes a server require a proof from each cell source before its backend runs.
// Registry gives the live records, and Subjects maps a role to the service account that may send
// the proof of that role. Now defaults to time.Now and Timeout to proof.FrameTimeout.
type ProofCheck struct {
	Registry RegistrySource
	Subjects map[string]record.Subject
	Now      func() time.Time
	Timeout  time.Duration
}

// check reads one proof frame from conn and verifies it for src. The error is a *PeerError.
func (p *ProofCheck) check(conn *tls.Conn, src Source, id string) error {
	refuse := func(reason Reason, err error) error { return &PeerError{Reason: reason, ID: id, Err: err} }
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = proof.FrameTimeout
	}
	binding, err := proof.Binding(conn.ConnectionState())
	if err != nil {
		return refuse(ProofInvalid, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	token, err := proof.ReadFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return refuse(proofReason(err, ProofMissing), err)
	}
	subject, ok := p.Subjects[src.Role]
	if !ok {
		return refuse(ProofInvalid, errors.New("no_subject: no proof subject for role "+src.Role))
	}
	rec, ok := p.Registry.Current().recordFor(src.Cell, src.Env)
	if !ok {
		return refuse(ProofInvalid, errors.New("no_record: the registry has no usable record of cell "+src.Cell))
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	if _, err := proof.Verify(rec, token, proof.StreamAudience(src.Cell, src.Role, binding), subject, now()); err != nil {
		return refuse(proofReason(err, ProofInvalid), err)
	}
	return nil
}

// proofReason maps a *proof.Error to its reason, and any other error to def.
func proofReason(err error, def Reason) Reason {
	var pe *proof.Error
	if errors.As(err, &pe) {
		if pe.Reason == proof.ReasonMissing {
			return ProofMissing
		}
		return ProofInvalid
	}
	return def
}
