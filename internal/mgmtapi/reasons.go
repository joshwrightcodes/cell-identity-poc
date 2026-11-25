package mgmtapi

import "github.com/joshwrightcodes/cell-identity-poc/internal/revoke"

// Detail reasons of envd. A refused spec is reported outward as ReasonSpecInvalid.
const (
	ReasonSignatureInvalid   = "signature_invalid"
	ReasonPayloadInvalid     = "payload_invalid"
	ReasonEnvMismatch        = "env_mismatch"
	ReasonRevisionOld        = "revision_old"
	ReasonRevisionConflict   = "revision_conflict"
	ReasonRecordInvalid      = "record_invalid"
	ReasonRecordUnindexed    = "record_unindexed"
	ReasonRecordOld          = "record_old"
	ReasonRecordConflict     = "record_conflict"
	ReasonTooManyInvalidated = "too_many_invalidated"

	// ReasonStoreFailed and ReasonStateUnverifiable are status values, not refusals of a spec.
	ReasonStoreFailed       = "store_failed"
	ReasonStateUnverifiable = "state_unverifiable"

	ReasonSpecInvalid = "spec_invalid"
)

// Detail reasons of the management plane.
const (
	ReasonCellUnknown       = "cell_unknown"
	ReasonNonceInvalid      = "nonce_invalid"
	ReasonTokenInvalid      = "token_invalid"
	ReasonIssuerUntrusted   = "issuer_untrusted"
	ReasonIssuerUnavailable = "issuer_unavailable"
	ReasonKeysUntrusted     = "keys_untrusted"
	ReasonRateLimited       = "rate_limited"
	ReasonRestoreActive     = "restore_active"
	ReasonNotBound          = "not_bound"
	ReasonConflict          = "conflict"
	ReasonProofMissing      = "proof_missing"
	ReasonProofInvalid      = "proof_invalid"
	ReasonStale             = "stale"
	ReasonStore             = "store"
	ReasonInternal          = "internal"
	// ReasonBundleOpen means a served bundle.apply of the target has no final result yet.
	ReasonBundleOpen = "bundle_open"
)

// The values of ItemOutcome.Outcome. The reason of an item outcome reuses the detail reasons above.
const (
	OutcomeAccepted   = "accepted"
	OutcomeDuplicate  = "duplicate"
	OutcomeUnknownOp  = "unknown_op"
	OutcomeForgedSeen = "forged_seen"
	OutcomeRefused    = "refused"
	OutcomeRetry      = "retry"
)

// KeyError is the error of a cluster key read. Reason is ReasonIssuerUntrusted or
// ReasonIssuerUnavailable.
type KeyError struct {
	Reason string
	Err    error
}

func (e *KeyError) Error() string {
	if e.Err == nil {
		return "cluster keys: " + e.Reason
	}
	return "cluster keys: " + e.Reason + ": " + e.Err.Error()
}

func (e *KeyError) Unwrap() error { return e.Err }

// Reasons about steps. ReasonStepInvalid and ReasonStepUnindexed are detail reasons of envd. The
// portal reasons also reuse ReasonCellUnknown. ReasonNotRequested is a portal reason and a valid
// reason.
const (
	ReasonStepInvalid   = "step_invalid"
	ReasonStepUnindexed = "step_unindexed"

	ReasonAlreadyRequested = "already_requested"
	ReasonNotRequested     = "not_requested"
	ReasonBootstrapInvalid = "bootstrap_invalid"
	ReasonStepOpen         = "step_open"
	ReasonNoStep           = "no_step"
	ReasonTooManyCells     = "too_many_cells"
	ReasonTestDigestOnly   = "test_digest_only"
)

// Reasons that a cell controller gives for a failed host service call.
const (
	ReasonHostsvcUntrusted   = "hostsvc_untrusted"
	ReasonHostsvcUnavailable = "hostsvc_unavailable"
	ReasonHostsvcDenied      = "hostsvc_denied"
	ReasonHostsvcBusy        = "hostsvc_busy"
)

// The reasons that a cell is not valid, besides ReasonNotRequested and ReasonNotBound.
const (
	ReasonRecordNotApplied = "record_not_applied"
	ReasonNoStatus         = "no_status"
	ReasonStatusStale      = "status_stale"
	// ReasonStatusInFuture is the reason of a cell whose last proven status lies more than 60 s
	// ahead of the clock.
	ReasonStatusInFuture = "status_in_future"
	ReasonKeysFailed     = "keys_failed"
)

// Reasons of envd for a local revocation entry that it refuses. The detail of
// ReasonRevocationInvalid is revoke.DetailSignature, revoke.DetailDecode or revoke.DetailEnv.
const (
	ReasonRevocationInvalid     = revoke.ReasonInvalid
	ReasonRevocationStale       = revoke.ReasonStale
	ReasonRevocationUnknownCell = revoke.ReasonUnknownCell
	ReasonRevocationOverflow    = revoke.ReasonOverflow
)

// Reasons of the revoke, un-revoke and restore commands of the management plane, besides
// ReasonNotBound.
const (
	ReasonNotConnected          = "not_connected"
	ReasonNotRevoked            = "not_revoked"
	ReasonOverlayHeld           = "overlay_held"
	ReasonRestorePastRevocation = "restore_past_revocation"
)
