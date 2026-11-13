package mgmtapi

import (
	"encoding/json"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// CellInfo is what envd learns about one cell from the management plane: a fresh bind nonce, and
// whether the cell has a record.
type CellInfo struct {
	Name           string    `json:"name"`
	Nonce          string    `json:"nonce"`
	NonceExpiresAt time.Time `json:"nonceExpiresAt"`
	Bound          bool      `json:"bound"`
}

// OpsBundle is the answer to an ops pull: the signed envelopes of the open operations and the cell
// nonces.
type OpsBundle struct {
	Ops   []json.RawMessage `json:"ops"`
	Cells []CellInfo        `json:"cells"`
}

// ReportItem is one item that a cell sent up. Body holds the exact bytes that the proof audience
// covers, and every hop keeps them unchanged.
type ReportItem struct {
	ID    string          `json:"id"`
	Cell  string          `json:"cell"`
	Kind  string          `json:"kind"`
	OpID  string          `json:"opId,omitempty"`
	Body  json.RawMessage `json:"body"`
	Token string          `json:"token"`
}

// ReportBatch is the body of a report post.
type ReportBatch struct {
	Items []ReportItem `json:"items"`
}

// ItemOutcome is the verdict of the management plane on one report item. Outcome is one of the
// Outcome constants, and Reason and Detail explain a refusal or a retry. Bind carries the bind
// response of an accepted bind item.
type ItemOutcome struct {
	ID        string        `json:"id"`
	OpID      string        `json:"opId,omitempty"`
	Outcome   string        `json:"outcome"`
	Reason    string        `json:"reason,omitempty"`
	Detail    string        `json:"detail,omitempty"`
	RequestID string        `json:"requestId,omitempty"`
	Bind      *BindResponse `json:"bind,omitempty"`
}

// ReportResult is the answer to a report post: one outcome for each item, in order.
type ReportResult struct {
	Outcomes []ItemOutcome `json:"outcomes"`
}

// KeyHint tells the management plane that the keys of a cell may have changed.
type KeyHint struct {
	Cell string    `json:"cell"`
	At   time.Time `json:"at"`
}

// ClaimInfo names the operation that one cell has claimed most often, and how often.
type ClaimInfo struct {
	OpID  string `json:"opId"`
	Count int    `json:"count"`
}

// BindRefusal is the last bind that the gateway refused for a cell.
type BindRefusal struct {
	Reason    string    `json:"reason"`
	RequestID string    `json:"requestId"`
	At        time.Time `json:"at"`
}

// GatewayStatus is what the gateway reports about itself through envd. RecordOldAt is the time
// that RecordOld last rose. Records holds the record revision that the gateway has for each cell,
// and KeyHints holds the hints from the hellos that it refused.
type GatewayStatus struct {
	Epoch           uint64                   `json:"epoch"`
	SyncedAt        time.Time                `json:"syncedAt"`
	OldestOutboxAt  time.Time                `json:"oldestOutboxAt"`
	EpochChangedAt  time.Time                `json:"epochChangedAt"`
	DroppedAt       time.Time                `json:"droppedAt"`
	RecordOldAt     time.Time                `json:"recordOldAt"`
	OutboxItems     int                      `json:"outboxItems"`
	Dropped         uint64                   `json:"dropped"`
	RecordOld       uint64                   `json:"recordOld"`
	Queued          map[string]int           `json:"queued"`
	Streams         map[string]int           `json:"streams"`
	MostClaimed     map[string]ClaimInfo     `json:"mostClaimed"`
	Records         map[string]spec.Revision `json:"records"`
	LastBindRefusal map[string]BindRefusal   `json:"lastBindRefusal"`
	KeyHints        []KeyHint                `json:"keyHints"`
	StoreError      string                   `json:"storeError"`
}
