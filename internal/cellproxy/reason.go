package cellproxy

import (
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
