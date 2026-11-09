// Package clusterjwt validates the service account tokens that cells present for attestation.
package clusterjwt

import "errors"

// Reason names why a token was refused. Errors carry only a Reason, never token contents.
type Reason string

// The reasons that Validate returns.
const (
	Revoked           Reason = "revoked"
	Malformed         Reason = "malformed"
	AlgNotAllowed     Reason = "alg_not_allowed"
	UnknownKID        Reason = "unknown_kid"
	BadSignature      Reason = "bad_signature"
	IssuerMismatch    Reason = "issuer_mismatch"
	SubjectNotAllowed Reason = "subject_not_allowed"
	NotPodBound       Reason = "not_pod_bound"
	LifetimeTooLong   Reason = "lifetime_too_long"
	StaleIAT          Reason = "stale_iat"
	IATInFuture       Reason = "iat_in_future"
	Expired           Reason = "expired"
	WrongAudience     Reason = "wrong_audience"
)

// Error is the error type of Validate.
type Error struct {
	Reason Reason
}

func (e *Error) Error() string {
	return "token refused: " + string(e.Reason)
}

func fail(r Reason) error {
	return &Error{Reason: r}
}

// ReasonOf returns the reason in err, or the empty Reason when err is nil or not an Error.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}
