package mgmt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// connectedWithin is how recent the last status report of envd must be for the plane to count
// as connected.
const connectedWithin = 2 * time.Minute

// reasonEntryUnrevoked is the reason of a refused adoption whose entry ID the mirror holds with a
// later un-revoke of its cell.
const reasonEntryUnrevoked = "entry_unrevoked"

// RevokeResult is the answer of a revoke or an un-revoke. Revision is the revision of the signed
// record: the new one, or for Already the one that holds the revoke. Queued means that the revoke
// waits for envd to apply the signed revision, and Revision is then zero.
type RevokeResult struct {
	Cell     string        `json:"cell"`
	Revision spec.Revision `json:"revision"`
	Queued   bool          `json:"queued"`
	Already  bool          `json:"already"`
}

// Revoke signs a record of the bound cell with revoked set. envd refuses a spec that makes more
// than one cell invalid at once, so one revoke commits for each revision that envd applied: the
// revoke commits now only when envd reported the signed revision as applied and no revoke waits.
// Else it waits in State.PendingRevokes, and revokeNext signs it. A cell that is revoked or waits
// already gives Already. A revoke fails with restore_active while a restore is active.
func (p *Plane) Revoke(ctx context.Context, cell string) (RevokeResult, error) {
	if err := ctx.Err(); err != nil {
		return RevokeResult{}, err
	}
	return p.queueRevoke(ctx, PendingRevoke{Cell: cell, Source: mgmtapi.RevocationSourceAdmin, QueuedAt: p.cfg.Now()}, nil)
}

// queueRevoke is Revoke for either source. gate, when set, runs under the mutex for a bound cell
// that is neither revoked nor queued, and a reason that it returns refuses the revoke with no
// change. An adopted entry waits in the queue during a restore.
func (p *Plane) queueRevoke(ctx context.Context, pr PendingRevoke, gate func(*State, *CellState) string) (RevokeResult, error) {
	res := RevokeResult{Cell: pr.Cell}
	err := p.commit(func(t *txn) error {
		cs := t.st.Cells[pr.Cell]
		switch {
		case cs == nil:
			return refuse(mgmtapi.ReasonNotBound, "")
		case cs.Revoked:
			res.Revision, res.Already = cs.Record, true
			return nil
		case pendingFor(t.st, pr.Cell):
			res.Queued, res.Already = true, true
			return nil
		}
		if gate != nil {
			if reason := gate(t.st, cs); reason != "" {
				return refuse(reason, "")
			}
		}
		if t.st.Served != 0 && pr.Source == mgmtapi.RevocationSourceAdmin {
			return refuse(mgmtapi.ReasonRestoreActive, "")
		}
		if len(t.st.PendingRevokes) == 0 && t.st.Served == 0 && p.appliedIs(t.st.Last) {
			if err := t.signRevoke(pr); err != nil {
				return err
			}
			res.Revision = t.rev
			return nil
		}
		t.st.PendingRevokes = append(t.st.PendingRevokes, pr)
		t.dirty, res.Queued = true, true
		return nil
	})
	if err != nil {
		return RevokeResult{}, err
	}
	switch {
	case res.Already:
	case res.Queued:
		p.cfg.Log.InfoContext(ctx, "revoke_queued", "cell", pr.Cell, "source", pr.Source, "entry_id", pr.EntryID)
	default:
		p.logRevoke(ctx, pr, res.Revision)
	}
	return res, nil
}

func pendingFor(st *State, cell string) bool {
	return slices.ContainsFunc(st.PendingRevokes, func(q PendingRevoke) bool { return q.Cell == cell })
}

// appliedIs reports whether the last status report of envd named rev as applied.
func (p *Plane) appliedIs(rev spec.Revision) bool {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	return !p.rep.lastReportAt.IsZero() && p.rep.applied == rev
}

// signRevoke signs the revoked record of a bound cell in a new revision, and adds the event to
// the mirror.
func (t *txn) signRevoke(pr PendingRevoke) error {
	if err := t.revise(); err != nil {
		return err
	}
	t.st.Cells[pr.Cell].Revoked = true
	if err := t.signCell(pr.Cell); err != nil {
		return err
	}
	t.st.LastRevocation = t.rev
	t.st.Revocations = append(t.st.Revocations, mgmtapi.RevocationEvent{
		Cell: pr.Cell, Revision: t.rev, Kind: mgmtapi.RevocationRevoke, Source: pr.Source,
		EntryID: pr.EntryID, OperatorKeySHA256: pr.OperatorKeySHA256, At: t.now,
	})
	return nil
}

func (p *Plane) logRevoke(ctx context.Context, pr PendingRevoke, rev spec.Revision) {
	p.cfg.Log.InfoContext(ctx, "cell_revoked", "cell", pr.Cell, "source", pr.Source, "entry_id", pr.EntryID,
		"operator_key_sha256", pr.OperatorKeySHA256, "record_epoch", rev.Epoch, "record_counter", rev.Counter)
}

// revokeNext signs the first pending revoke, in one revision. Like dropNext, it runs only while the
// signed revision is the one that envd reported as applied, checked under the mutex, so two reports
// of one revision release one revoke. A pending cell that is no longer bound, or that is revoked
// already, leaves the queue.
func (p *Plane) revokeNext(applied spec.Revision) error {
	var signed PendingRevoke
	var rev spec.Revision
	err := p.commit(func(t *txn) error {
		if t.st.Last != applied || applied.Compare(t.st.LastRevocation) < 0 {
			return nil
		}
		for len(t.st.PendingRevokes) > 0 {
			pr := t.st.PendingRevokes[0]
			t.st.PendingRevokes = t.st.PendingRevokes[1:]
			t.dirty = true
			if cs := t.st.Cells[pr.Cell]; cs == nil || cs.Revoked {
				continue
			}
			if err := t.signRevoke(pr); err != nil {
				return err
			}
			signed, rev = pr, t.rev
			return nil
		}
		return nil
	})
	if err == nil && signed.Cell != "" {
		p.logRevoke(context.Background(), signed, rev)
	}
	return err
}

// Unrevoke signs a record of the cell with revoked cleared. It runs only while connected, so that
// envd applied every signed revision, and only while envd holds no local revocation entry for the
// cell, because envd would keep the entry against a record that is not revoked. A revoke that
// waits in the queue is not revoked yet, so it gives not_revoked.
func (p *Plane) Unrevoke(ctx context.Context, cell string) (RevokeResult, error) {
	if err := ctx.Err(); err != nil {
		return RevokeResult{}, err
	}
	res := RevokeResult{Cell: cell}
	err := p.commit(func(t *txn) error {
		cs := t.st.Cells[cell]
		switch {
		case cs == nil:
			return refuse(mgmtapi.ReasonNotBound, "")
		case !cs.Revoked:
			return refuse(mgmtapi.ReasonNotRevoked, "")
		}
		connected, held := p.overlayView(t.st.Last, t.now)
		switch {
		case !connected:
			return refuse(mgmtapi.ReasonNotConnected, "")
		case held[cell]:
			return refuse(mgmtapi.ReasonOverlayHeld, "")
		}
		if err := t.revise(); err != nil {
			return err
		}
		cs.Revoked = false
		if err := t.signCell(cell); err != nil {
			return err
		}
		t.st.Revocations = append(t.st.Revocations, mgmtapi.RevocationEvent{
			Cell: cell, Revision: t.rev, Kind: mgmtapi.RevocationUnrevoke, Source: mgmtapi.RevocationSourceAdmin, At: t.now,
		})
		res.Revision = t.rev
		return nil
	})
	if err != nil {
		return RevokeResult{}, err
	}
	p.cfg.Log.InfoContext(ctx, "cell_unrevoked", "cell", cell, "record_epoch", res.Revision.Epoch, "record_counter", res.Revision.Counter)
	return res, nil
}

// overlayView reports whether the plane is connected at the signed revision last: envd reported
// within connectedWithin, and its applied revision is last. It also returns the cells of the
// entries that the last report holds.
func (p *Plane) overlayView(last spec.Revision, now time.Time) (bool, map[string]bool) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	connected := !p.rep.lastReportAt.IsZero() && now.Sub(p.rep.lastReportAt) <= connectedWithin && p.rep.applied == last
	return connected, p.rep.overlay
}

// overlayCells returns the cells that the envelopes name. It reads each payload with no signature
// check, because envd holds each entry that it reports, whether or not the plane pins its key.
func overlayCells(envelopes []json.RawMessage) map[string]bool {
	out := map[string]bool{}
	for _, raw := range envelopes {
		if e, ok := claimedEntry(raw); ok {
			out[e.Cell] = true
		}
	}
	return out
}

// claimedEntry decodes the entry of an envelope with no signature check.
func claimedEntry(raw []byte) (revoke.Entry, bool) {
	if len(raw) > revoke.MaxEntryBytes {
		return revoke.Entry{}, false
	}
	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if json.Unmarshal(raw, &env) != nil || env.PayloadType != revoke.PayloadType {
		return revoke.Entry{}, false
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return revoke.Entry{}, false
	}
	var e revoke.Entry
	if json.Unmarshal(body, &e) != nil || e.Cell == "" {
		return revoke.Entry{}, false
	}
	return e, true
}

// adopt verifies each local revocation entry that envd reports against Config.OperatorKeys, and
// queues a revoke with source operator for each entry that passes. An entry passes when a pinned
// key verifies it, it names this environment and a bound cell, the mirror holds no un-revoke of
// its ID (mgmtapi.EntryUnrevoked), and it is not stale against the current record of its cell
// (revoke.Stale). A refused entry logs adoption_refused, rate limited, and is never queued. An
// entry for a cell that is revoked or queued already changes nothing. With no pinned key, adopt
// logs operator_keys_absent once and adopts nothing. It reads at most revoke.MaxHeld envelopes.
func (p *Plane) adopt(ctx context.Context, envelopes []json.RawMessage, now time.Time) {
	if len(envelopes) == 0 {
		return
	}
	if len(p.cfg.OperatorKeys) == 0 {
		if p.keysAbsentLogged.CompareAndSwap(false, true) {
			p.cfg.Log.WarnContext(ctx, "operator_keys_absent", "entries", len(envelopes))
		}
		return
	}
	envelopes = envelopes[:min(len(envelopes), revoke.MaxHeld)]
	for i, raw := range envelopes {
		if slices.ContainsFunc(envelopes[:i], func(prev json.RawMessage) bool { return bytes.Equal(prev, raw) }) {
			continue
		}
		e, keySHA, refusal := p.checkEntry(raw)
		if refusal.Reason != "" {
			p.refuseAdoption(ctx, refusal)
			continue
		}
		// The steady state: envd keeps reporting an entry until a spec settles it.
		st := p.snap.Load().st
		if cs := st.Cells[e.Cell]; cs != nil && (cs.Revoked || pendingFor(st, e.Cell)) {
			continue
		}
		pr := PendingRevoke{Cell: e.Cell, Source: mgmtapi.RevocationSourceOperator, EntryID: e.ID, OperatorKeySHA256: keySHA, QueuedAt: now}
		_, err := p.queueRevoke(ctx, pr, func(st *State, cs *CellState) string {
			switch {
			case mgmtapi.EntryUnrevoked(st.Revocations, e.Cell, e.ID):
				return reasonEntryUnrevoked
			case revoke.Stale(e, cs.Record):
				return revoke.ReasonStale
			}
			return ""
		})
		switch reason := ReasonOf(err); {
		case err == nil:
		case reason == mgmtapi.ReasonNotBound:
			p.refuseAdoption(ctx, revoke.Refusal{Cell: e.Cell, ID: e.ID, Reason: revoke.ReasonUnknownCell})
		case reason == reasonEntryUnrevoked || reason == revoke.ReasonStale:
			p.refuseAdoption(ctx, revoke.Refusal{Cell: e.Cell, ID: e.ID, Reason: reason})
		default:
			p.logLimited(ctx, slog.LevelError, "adoption_failed/"+e.Cell, "adoption_failed", "cell", e.Cell, "entry_id", e.ID, "error", err.Error())
		}
	}
}

// checkEntry verifies raw under each pinned key in turn, and returns the entry and the SHA-256 of
// the key that verifies it, or the refusal. The refusal of an entry that does not verify carries
// the ID and the cell that the entry claims, for the log only.
func (p *Plane) checkEntry(raw []byte) (revoke.Entry, string, revoke.Refusal) {
	var lastErr error
	for _, k := range p.cfg.OperatorKeys {
		e, err := revoke.Verify(raw, []ed25519.PublicKey{k})
		if err != nil {
			lastErr = err
			continue
		}
		if e.Env != p.cfg.Intent.Env {
			return revoke.Entry{}, "", revoke.Refusal{Cell: e.Cell, ID: e.ID, Reason: revoke.ReasonInvalid, Detail: revoke.DetailEnv}
		}
		return e, revoke.KeySHA256(k), revoke.Refusal{}
	}
	detail := revoke.DetailDecode
	if errors.Is(lastErr, record.ErrSignature) {
		detail = revoke.DetailSignature
	}
	claimed, _ := claimedEntry(raw)
	return revoke.Entry{}, "", revoke.Refusal{Cell: claimed.Cell, ID: claimed.ID, Reason: revoke.ReasonInvalid, Detail: detail}
}

// refuseAdoption logs a refused entry. A verified entry has a limiter key of its own. The entries
// that do not verify share one key for each detail, so that invented IDs cannot fill the limiter.
func (p *Plane) refuseAdoption(ctx context.Context, r revoke.Refusal) {
	key := "adoption_refused/" + r.Reason + "/" + r.Detail
	if r.Reason != revoke.ReasonInvalid || r.Detail == revoke.DetailEnv {
		key += "/" + r.Cell + "/" + r.ID
	}
	p.logLimited(ctx, slog.LevelWarn, key, "adoption_refused", "entry_id", r.ID, "cell", r.Cell, "reason", r.Reason, "detail", r.Detail)
}
