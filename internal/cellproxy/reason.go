package cellproxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
)

// Reason says why the proxy refused a peer or a request. Logs carry the reason. Clients get only
// "denied" and a request ID.
type Reason string

const (
	// PeerUntrusted: the peer certificate does not chain to the peer bundle.
	PeerUntrusted Reason = "peer_untrusted"
	// PeerNotAllowed: the peer ID is not the expected ID, or fails the pattern or the registry.
	PeerNotAllowed Reason = "peer_not_allowed"
	// SubjectMismatch: the token of a request does not name the agent of the connection.
	SubjectMismatch Reason = "subject_mismatch"
	// RequestNotAllowed: the request is not one that the backend serves.
	RequestNotAllowed Reason = "request_not_allowed"
	// UpstreamUnavailable: the backend cannot reach its upstream.
	UpstreamUnavailable Reason = "upstream_unavailable"
	// Overloaded: the server holds its maximum number of connections.
	Overloaded Reason = "overloaded"
	// NoClientCert: the client sent no certificate, as a probe does. Logs carry it at Debug.
	NoClientCert Reason = "no_client_cert"
	// ProtocolNotH2: the handshake did not agree on ALPN h2.
	ProtocolNotH2 Reason = "protocol_not_h2"
	// HandshakeFailed: the handshake failed for another reason, for example a timeout.
	HandshakeFailed Reason = "handshake_failed"
	// PingTimeout: a ping on a tunnel got no answer, so the tunnel ends.
	PingTimeout Reason = "ping_timeout"
	// LeafExpiring: the leaf of the cell has less than two minimum backoffs of life left, so the cell skips the tunnel.
	LeafExpiring Reason = "leaf_expiring"
	// ProofMissing: a cell source sent no proof, or the proof frame did not arrive in time.
	ProofMissing Reason = "proof_missing"
	// ProofInvalid: the proof of a cell source failed a check. The log line carries the detail.
	ProofInvalid Reason = "proof_invalid"
	// ProofFailed: a client could not make or write its proof, so it ends the connection.
	ProofFailed Reason = "proof_failed"
	// LibraryLog: a line that a library wrote to its logger.
	LibraryLog Reason = "library_log"
)

// GRPCCode is the status for a refused request. A peer reason ends the handshake, so no status
// carries it.
func (r Reason) GRPCCode() codes.Code {
	switch r {
	case UpstreamUnavailable, Overloaded:
		return codes.Unavailable
	}
	return codes.PermissionDenied
}

// HTTPStatus is the HTTP status for a refused request.
func (r Reason) HTTPStatus() int {
	switch r {
	case UpstreamUnavailable, Overloaded:
		return http.StatusServiceUnavailable
	}
	return http.StatusForbidden
}

// PeerError is a refused TLS peer. ID is the unverified ID of the peer leaf, for logs only.
type PeerError struct {
	Reason Reason
	ID     string
	Err    error
}

func (e *PeerError) Error() string { return string(e.Reason) + ": " + e.Err.Error() }

func (e *PeerError) Unwrap() error { return e.Err }

// ReasonOf returns the reason of a refused peer in err, or "" for any other error.
func ReasonOf(err error) Reason {
	var pe *PeerError
	if errors.As(err, &pe) {
		return pe.Reason
	}
	return ""
}

// TLSReason names why a client TLS dial failed. It returns the reason of a refused peer, which the
// config of ClientTLS and ProbeTLS raises, handshake_failed for any other TLS failure, and "" for
// an error that is not a TLS failure, such as a refused connection, a context end or a timeout
// before any TLS byte.
//
// crypto/tls returns an alert over TCP as a net.OpError with the Op "remote error" or "local
// error". A peer that answers a TLS dial with plain HTTP gives a tls.RecordHeaderError, or
// http.ErrSchemeMismatch through an http.Client. Any other error that crypto/tls creates has
// the text prefix "tls: ". An alert has the prefix "remote error: " or "local error: ", so the OpError case
// must name it.
func TLSReason(err error) Reason {
	if r := ReasonOf(err); r != "" {
		return r
	}
	var op *net.OpError
	var hdr tls.RecordHeaderError
	var alert tls.AlertError
	switch {
	case errors.As(err, &op) && (op.Op == "remote error" || op.Op == "local error"):
		return HandshakeFailed
	case errors.As(err, &hdr), errors.As(err, &alert), errors.Is(err, http.ErrSchemeMismatch):
		return HandshakeFailed
	}
	// crypto/tls returns some failures as plain errors that start with "tls: ". A caller wraps them, so each error in the chain counts.
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.HasPrefix(e.Error(), "tls: ") {
			return HandshakeFailed
		}
	}
	return ""
}

// HandshakeReason is TLSReason for a caller that knows the error came from the TLS handshake. An
// end of stream there, which a relay that closes the connection causes, is also handshake_failed.
func HandshakeReason(err error) Reason {
	if r := TLSReason(err); r != "" {
		return r
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return HandshakeFailed
	}
	return ""
}

// ReasonAttrs returns the log attributes of the TLS reason of err: "reason" and its name, or none
// when err is not a TLS failure, so that a log query for a reason never matches an empty value.
func ReasonAttrs(err error) []any {
	if r := TLSReason(err); r != "" {
		return []any{"reason", string(r)}
	}
	return nil
}
