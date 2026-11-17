// Package proof carries and checks the pod-bound token that a cell sends with each report, hello
// and stream. The token audience binds the proof to one connection or one body.
package proof

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// Limits and labels of the proof.
const (
	// ExporterLabel is the TLS exporter label of the connection binding.
	ExporterLabel = "EXPORTER-poc-cell-proof"
	// MaxFrame is the longest token that a frame may carry.
	MaxFrame = 8 << 10
	// FrameTimeout is how long a peer has to send its proof frame after the handshake.
	FrameTimeout = 5 * time.Second

	// ReasonMissing means the peer sent no proof.
	ReasonMissing = "proof_missing"
	// ReasonInvalid means the proof failed a check. Error.Detail says which.
	ReasonInvalid = "proof_invalid"

	bindingBytes = 16
	frameHeader  = 4
)

// Binding returns the binding of a TLS 1.3 connection: 16 bytes from the TLS exporter, as 22
// base64url characters without padding. Both ends of one connection get the same value, and two
// connections get different values.
func Binding(cs tls.ConnectionState) (string, error) {
	if !cs.HandshakeComplete {
		return "", errors.New("proof: the TLS handshake is not complete")
	}
	if cs.Version != tls.VersionTLS13 {
		return "", errors.New("proof: the connection is not TLS 1.3")
	}
	b, err := cs.ExportKeyingMaterial(ExporterLabel, nil, bindingBytes)
	if err != nil {
		return "", fmt.Errorf("proof: export binding: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// StreamAudience is the audience of a stream proof for cell and role on a connection with binding.
func StreamAudience(cell, role, binding string) string {
	return "mgmt-stream/" + cell + "/" + role + "/" + binding
}

// HelloAudience is the audience of a gateway hello proof for cell on a connection with binding.
func HelloAudience(cell, binding string) string {
	return "env-stream/" + cell + "/" + binding
}

// ReportAudience is the audience of a report item of the given kind. It holds the SHA-256 of the
// exact body bytes, so the proof covers that body and no other.
func ReportAudience(cell, kind string, body []byte) string {
	sum := sha256.Sum256(body)
	return "mgmt-report/" + cell + "/" + kind + "/" + hex.EncodeToString(sum[:])
}

// WriteFrame writes the 4-byte big-endian length of token, then token, in one write. An empty
// token writes a frame that means no proof.
func WriteFrame(w io.Writer, token string) error {
	if len(token) > MaxFrame {
		return fmt.Errorf("proof: token of %d bytes is above the %d byte limit", len(token), MaxFrame)
	}
	buf := make([]byte, frameHeader+len(token))
	binary.BigEndian.PutUint32(buf, uint32(len(token)))
	copy(buf[frameHeader:], token)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads exactly one frame and never reads ahead. A length of 0 returns an *Error with
// ReasonMissing, and a length above MaxFrame returns an *Error with ReasonInvalid and detail
// too_large, both before it reads the token. A short read returns the read error.
func ReadFrame(r io.Reader) (string, error) {
	var head [frameHeader]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(head[:])
	switch {
	case n == 0:
		return "", &Error{Reason: ReasonMissing}
	case n > MaxFrame:
		return "", &Error{Reason: ReasonInvalid, Detail: "too_large"}
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return "", err
	}
	return string(buf), nil
}

// Error is a refused proof. Reason is ReasonMissing or ReasonInvalid. Detail is the clusterjwt
// reason, token_expired, subject_mismatch or too_large.
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "proof refused: " + e.Reason
	}
	return "proof refused: " + e.Reason + ": " + e.Detail
}

// Transient reports whether a fresh token or a key refresh can fix the proof: the token expired,
// or its key ID is not in the record yet.
func (e *Error) Transient() bool {
	return e.Detail == detailExpired || e.Detail == string(clusterjwt.UnknownKID)
}

const (
	detailExpired         = "token_expired"
	detailSubjectMismatch = "subject_mismatch"
)

// Verify checks token against the record of the cell: the signature, the claims, a single audience
// equal to audience, and a service account equal to subject. The error is an *Error.
func Verify(rec record.Cell, token, audience string, subject record.Subject, now time.Time) (clusterjwt.Claims, error) {
	if token == "" {
		return clusterjwt.Claims{}, &Error{Reason: ReasonMissing}
	}
	claims, err := clusterjwt.ValidateFor(rec, token, audience, now)
	if err != nil {
		detail := string(clusterjwt.ReasonOf(err))
		switch clusterjwt.ReasonOf(err) {
		case clusterjwt.Expired, clusterjwt.StaleIAT, clusterjwt.IATInFuture:
			detail = detailExpired
		case "":
			detail = string(clusterjwt.Malformed)
		}
		return clusterjwt.Claims{}, &Error{Reason: ReasonInvalid, Detail: detail}
	}
	if claims.Namespace != subject.Namespace || claims.ServiceAccount != subject.ServiceAccount {
		return clusterjwt.Claims{}, &Error{Reason: ReasonInvalid, Detail: detailSubjectMismatch}
	}
	return claims, nil
}
