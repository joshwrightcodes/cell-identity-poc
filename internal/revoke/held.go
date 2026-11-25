package revoke

import (
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
// entry that fails. It leaves h unchanged. The rules run in this order. An entry must verify under
// keys (ReasonInvalid with DetailSignature or DetailDecode) and name env (DetailEnv). An entry for a
// cell that the overlay already holds changes nothing and is not refused, so the first entry stays.
// The entry must name a cell of records (ReasonUnknownCell). An entry for a cell whose record is
// already revoked adds nothing, so it is skipped with no refusal. The entry must not be Stale
// against the revision of that record (ReasonStale). The overlay holds at most MaxHeld entries
// (ReasonOverflow). The overlay keeps each envelope in the form that Sign writes.
//
// The result depends on the order of in: the first entry for a cell wins, and the cap refuses the
// last ones. A caller that reads an unordered source, such as the keys of a ConfigMap, sorts it first.
func Admit(h Held, in [][]byte, keys []ed25519.PublicKey, env string, records map[string]record.Cell) (Held, []Refusal) {
	out := make(Held, len(h)+len(in))
	for cell, raw := range h {
		out[cell] = raw
	}
	var refusals []Refusal
	for _, raw := range in {
		e, form, refusal, ok := check(raw, keys, env)
		if !ok {
			refusals = append(refusals, refusal)
			continue
		}
		if _, held := out[e.Cell]; held {
			continue
		}
		refuse := func(reason string) {
			refusals = append(refusals, Refusal{Cell: e.Cell, ID: e.ID, Reason: reason})
		}
		rec, known := records[e.Cell]
		switch {
		case !known:
			refuse(ReasonUnknownCell)
		case rec.Revoked:
		case Stale(e, spec.RecordRevision(rec)):
			refuse(ReasonStale)
		case len(out) >= MaxHeld:
			refuse(ReasonOverflow)
		default:
			out[e.Cell] = form
		}
	}
	return out, refusals
}

// Load rebuilds the overlay from stored envelopes, for example after a restart. Each envelope must
// verify under keys and name env, as in Admit, and the overlay keys each entry by its verified cell.
// Load applies no stale rule and no unknown cell rule, because a held entry stays until Settle drops
// it. The first entry for a cell wins, and the entries after the first MaxHeld cells are refused
// with ReasonOverflow. Like Admit, the result depends on the order of envelopes.
func Load(envelopes [][]byte, keys []ed25519.PublicKey, env string) (Held, []Refusal) {
	out := make(Held, min(len(envelopes), MaxHeld))
	var refusals []Refusal
	for _, raw := range envelopes {
		e, form, refusal, ok := check(raw, keys, env)
		switch {
		case !ok:
			refusals = append(refusals, refusal)
		case out[e.Cell] != nil:
		case len(out) >= MaxHeld:
			refusals = append(refusals, Refusal{Cell: e.Cell, ID: e.ID, Reason: ReasonOverflow})
		default:
			out[e.Cell] = form
		}
	}
	return out, refusals
}

// check verifies raw and its env. It returns the entry and its envelope in the form that Sign
// writes, or the refusal and false.
func check(raw []byte, keys []ed25519.PublicKey, env string) (Entry, []byte, Refusal, bool) {
	e, form, err := verify(raw, keys)
	if err != nil {
		detail := DetailDecode
		if errors.Is(err, record.ErrSignature) {
			detail = DetailSignature
		}
		return Entry{}, nil, Refusal{Reason: ReasonInvalid, Detail: detail}, false
	}
	if e.Env != env {
		return Entry{}, nil, Refusal{Cell: e.Cell, ID: e.ID, Reason: ReasonInvalid, Detail: DetailEnv}, false
	}
	return e, form, Refusal{}, true
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
