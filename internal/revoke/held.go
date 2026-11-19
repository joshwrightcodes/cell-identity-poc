package revoke

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"maps"
	"slices"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// The reasons of a refused entry. mgmtapi gives them under the same strings.
const (
	ReasonInvalid     = "revocation_invalid"
	ReasonStale       = "revocation_stale"
	ReasonUnknownCell = "revocation_unknown_cell"
	ReasonOverflow    = "revocation_overflow"
)

// The details of ReasonInvalid.
const (
	DetailSignature = "signature"
	DetailDecode    = "decode"
	DetailEnv       = "env"
)

// Held is the overlay: the envelope of one verified entry for each revoked cell, by cell name.
type Held map[string][]byte

// Refusal is an entry that Admit refused. Cell and ID are empty when the entry did not verify.
type Refusal struct {
	Cell   string
	ID     string
	Reason string
	Detail string
}

// Admit returns h with the entries of in that pass the admit rules, and one refusal for each
// entry that fails. It leaves h unchanged. An entry must verify under keys (ReasonInvalid with
// DetailSignature or DetailDecode), name env (DetailEnv), name a cell of records
// (ReasonUnknownCell), and name a record revision at or above the revision of that record
// (ReasonStale). The overlay holds at most MaxHeld entries (ReasonOverflow). An entry for a cell
// that the overlay already holds changes nothing and is not refused, so the first entry stays.
// The overlay keeps the compact form of each envelope.
func Admit(h Held, in [][]byte, keys []ed25519.PublicKey, env string, records map[string]record.Cell) (Held, []Refusal) {
	out := make(Held, len(h)+len(in))
	for cell, raw := range h {
		out[cell] = raw
	}
	var refusals []Refusal
	for _, raw := range in {
		e, err := Verify(raw, keys)
		if err != nil {
			detail := DetailDecode
			if errors.Is(err, record.ErrSignature) {
				detail = DetailSignature
			}
			refusals = append(refusals, Refusal{Reason: ReasonInvalid, Detail: detail})
			continue
		}
		refuse := func(reason, detail string) {
			refusals = append(refusals, Refusal{Cell: e.Cell, ID: e.ID, Reason: reason, Detail: detail})
		}
		if e.Env != env {
			refuse(ReasonInvalid, DetailEnv)
			continue
		}
		if _, held := out[e.Cell]; held {
			continue
		}
		rec, ok := records[e.Cell]
		switch {
		case !ok:
			refuse(ReasonUnknownCell, "")
			continue
		case e.Record.Compare(spec.RecordRevision(rec)) < 0:
			refuse(ReasonStale, "")
			continue
		case len(out) >= MaxHeld:
			refuse(ReasonOverflow, "")
			continue
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			refuse(ReasonInvalid, DetailDecode)
			continue
		}
		out[e.Cell] = compact.Bytes()
	}
	return out, refusals
}

// Settle returns h without the entries whose cell an accepted spec holds revoked in its record, or
// retires. A newer record that is not revoked keeps the entry, and so does a cell with no record.
// It leaves h unchanged.
func Settle(h Held, records map[string]record.Cell, retired map[string]bool) Held {
	out := make(Held, len(h))
	for cell, raw := range h {
		if retired[cell] {
			continue
		}
		if rec, ok := records[cell]; ok && rec.Revoked {
			continue
		}
		out[cell] = raw
	}
	return out
}

// Envelopes returns the held envelopes sorted by cell name. It returns an empty, non-nil slice
// for an empty overlay, so the list encodes as a JSON array.
func (h Held) Envelopes() []json.RawMessage {
	out := make([]json.RawMessage, 0, len(h))
	for _, cell := range slices.Sorted(maps.Keys(h)) {
		out = append(out, json.RawMessage(h[cell]))
	}
	return out
}
