package cellproxy

import (
	"crypto/tls"
	"errors"
	"net/http"

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
// an error that is not a TLS failure, such as a refused connection.
func TLSReason(err error) Reason {
	if r := ReasonOf(err); r != "" {
		return r
	}
	var alert tls.AlertError
	var hdr tls.RecordHeaderError
	var verify *tls.CertificateVerificationError
	if errors.As(err, &alert) || errors.As(err, &hdr) || errors.As(err, &verify) {
		return HandshakeFailed
	}
	return ""
}
