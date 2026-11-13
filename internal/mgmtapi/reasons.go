package mgmtapi

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
