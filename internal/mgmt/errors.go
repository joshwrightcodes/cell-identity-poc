package mgmt

import (
	"errors"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// Error is a refusal with one of the mgmtapi reasons. Detail is for logs and tests.
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

func refuse(reason, detail string) error { return &Error{Reason: reason, Detail: detail} }

// ReasonOf returns the reason of err when it is an *Error, and an empty string otherwise.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func tokenError(err error) error {
	return refuse(mgmtapi.ReasonTokenInvalid, string(clusterjwt.ReasonOf(err)))
}

func keySourceError(err error) error {
	var ke *mgmtapi.KeyError
	if errors.As(err, &ke) && ke.Reason == mgmtapi.ReasonIssuerUntrusted {
		return refuse(mgmtapi.ReasonIssuerUntrusted, "key_source")
	}
	return refuse(mgmtapi.ReasonIssuerUnavailable, "key_source")
}

// ErrRevisionUnknown means that a restore named a counter that the plane does not hold.
var ErrRevisionUnknown = errors.New("no stored revision")

// ErrRestorePastRevocation means that a restore named a revision below the last signed revoke of
// the epoch. Such a restore would serve a cell as not revoked again. ReasonOf gives
// restore_past_revocation.
var ErrRestorePastRevocation error = &Error{Reason: mgmtapi.ReasonRestorePastRevocation}
