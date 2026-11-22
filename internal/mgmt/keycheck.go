package mgmt

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// CheckResult is the outcome of a key check.
type CheckResult string

// The sources of a key check. A manual check always asks the key source. A periodic, hint or bind
// check reads the key cache while its last fetch is under KeyCacheTTL old.
const (
	ViaManual   = "manual"
	ViaPeriodic = "periodic"
	ViaHint     = "hint"
)

// KeyCheck is KeyCheckVia with the source manual.
func (p *Plane) KeyCheck(ctx context.Context, cell string) (CheckResult, error) {
	return p.KeyCheckVia(ctx, cell, ViaManual)
}

// KeyCheckVia compares the keys that the issuer publishes with the keys of the record. via is
// ViaManual, ViaPeriodic or ViaHint. An error means the check could not run; a refusal is a result.
func (p *Plane) KeyCheckVia(ctx context.Context, cell, via string) (CheckResult, error) {
	return p.keyCheck(ctx, cell, via, nil)
}

// KeyCheck is Plane.KeyCheck, guarded by the state version.
func (g SeqGuard) KeyCheck(ctx context.Context, cell string) (CheckResult, error) {
	return g.p.keyCheck(ctx, cell, ViaManual, &g.seq)
}

func (p *Plane) keyCheck(ctx context.Context, cell, via string, expect *uint64) (res CheckResult, err error) {
	mode := fetchCached
	switch via {
	case ViaManual:
		mode = fetchFresh
	case ViaPeriodic, ViaHint:
	default:
		return "", fmt.Errorf("unknown key check source %q", via)
	}
	defer func() {
		if err == nil {
			p.checkResults.Add(ctx, 1, metric.WithAttributes(attribute.String("result", string(res)), attribute.String("via", via)))
		}
	}()
	if _, ok := p.cellIn(p.snap.Load().st, cell); !ok {
		return "", refuse(mgmtapi.ReasonCellUnknown, "")
	}
	if expect != nil && p.snapshotSeq() != *expect {
		return "", refuse(mgmtapi.ReasonConflict, "state version changed")
	}
	if p.snap.Load().st.Cells[cell] == nil {
		return CheckNotBound, nil
	}
	keys, at, _, ferr := p.cachedKeys(ctx, cell, mode)
	if ferr != nil {
		res = CheckIssuerUnavailable
		if ReasonOf(ferr) == mgmtapi.ReasonIssuerUntrusted {
			res = CheckIssuerUntrusted
		}
		if err := p.noteCheck(ctx, cell, res, ferr); err != nil {
			return res, err
		}
		return res, nil
	}
	err = p.commit(func(t *txn) error {
		if err := t.expectSeq(expect); err != nil {
			return err
		}
		if _, ok := p.cellIn(t.st, cell); !ok {
			return refuse(mgmtapi.ReasonCellUnknown, "")
		}
		cs := t.st.Cells[cell]
		if cs == nil {
			res = CheckNotBound
			return nil
		}
		var err error
		res, err = p.judge(t, cell, cs, keys, at)
		return err
	})
	if err != nil {
		return "", err
	}
	if res != CheckRateLimited && res != CheckNotBound {
		if via != ViaHint {
			p.rmu.Lock()
			if c := p.rt.cell(cell); c.lastHintDoneAt.Before(at) {
				c.lastHintCheck = ""
			}
			p.rmu.Unlock()
		}
		p.cfg.Log.InfoContext(ctx, "key_check", "cell", cell, "result", string(res), "via", via)
	}
	return res, nil
}

func (p *Plane) judge(t *txn, cell string, cs *CellState, keys mgmtapi.ClusterKeys, fetchedAt time.Time) (CheckResult, error) {
	settle := func(res CheckResult) (CheckResult, error) {
		if !cs.CheckedAt.Equal(fetchedAt) || cs.LastCheck != string(res) {
			cs.CheckedAt, cs.LastCheck = fetchedAt, string(res)
			t.dirty = true
		}
		return res, nil
	}
	if keys.Issuer != cs.Issuer {
		return settle(CheckIssuerUntrusted)
	}
	fresh := parseKeys(keys.JWKS)
	d := diffKeys(parseKeys(cs.JWKS), fresh)
	switch {
	case len(fresh) == 0 || len(fresh) > maxKeys || d.common == 0 || d.added > maxNewKeys:
		return settle(CheckKeysUntrusted)
	case d.added == 0 && d.removed == 0:
		return settle(CheckUnchanged)
	}
	jwks, err := encodeKeys(fresh)
	if err != nil {
		return settle(CheckKeysUntrusted)
	}
	if p.gapActive(cs, t.now) {
		return CheckRateLimited, nil
	}
	if err := t.revise(); err != nil {
		return "", err
	}
	old := *cs
	cs.JWKS, cs.KeysUpdatedAt = jwks, t.now
	if _, err := settle(CheckKeysUpdated); err != nil {
		return "", err
	}
	if err := t.signCell(cell); err != nil {
		if ReasonOf(err) != mgmtapi.ReasonKeysUntrusted {
			return "", err
		}
		// The new set does not fit a record. The cell keeps its last good record and no revision is signed.
		*cs = old
		t.revised, t.rev = false, spec.Revision{}
		return settle(CheckKeysUntrusted)
	}
	return CheckKeysUpdated, nil
}

// noteCheck records a check that learned nothing about the keys, so that status shows it. It does
// not start the update gap. It logs a line when the outcome of the cell changes, so a host service
// that stays down gives one line, and not one for each check.
func (p *Plane) noteCheck(ctx context.Context, cell string, res CheckResult, cause error) error {
	changed := false
	err := p.commit(func(t *txn) error {
		if cs := t.st.Cells[cell]; cs != nil && cs.LastCheck != string(res) {
			cs.LastCheck = string(res)
			t.dirty = true
			changed = true
		}
		return nil
	})
	if err == nil && changed {
		p.cfg.Log.WarnContext(ctx, "key_check_"+string(res), "cell", cell, "result", string(res), "error", cause.Error())
	}
	return err
}

// RunChecks checks each bound cell whose last check is older than CheckEvery. It runs on a tick every
// minute until ctx ends.
func (p *Plane) RunChecks(ctx context.Context) error {
	var ticks <-chan time.Time
	if p.cfg.Ticks != nil {
		ticks = p.cfg.Ticks(time.Minute)
	} else {
		tk := time.NewTicker(time.Minute)
		defer tk.Stop()
		ticks = tk.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
		}
		st := p.snap.Load().st
		for _, name := range sortedKeys(st.Cells) {
			if _, ok := p.cellIn(st, name); !ok || p.cfg.Now().Sub(st.Cells[name].CheckedAt) < p.cfg.CheckEvery {
				continue
			}
			if _, err := p.KeyCheckVia(ctx, name, ViaPeriodic); err != nil {
				p.logLimited(ctx, slog.LevelWarn, "key_check_failed/"+name, "key_check_failed", "cell", name, "error", err.Error())
			}
		}
	}
}

// PreviewKeys reads the keys of a cell without a cache and changes no state.
func (p *Plane) PreviewKeys(ctx context.Context, cell string) (mgmtapi.ClusterKeys, error) {
	if _, ok := p.cellIn(p.snap.Load().st, cell); !ok {
		return mgmtapi.ClusterKeys{}, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	keys, err := p.cfg.Keys.Keys(ctx, cell)
	if err != nil {
		return mgmtapi.ClusterKeys{}, keySourceError(err)
	}
	return keys, nil
}

// The results of KeyCheck.
const (
	CheckUnchanged         CheckResult = "unchanged"
	CheckKeysUpdated       CheckResult = "keys_updated"
	CheckKeysUntrusted     CheckResult = "keys_untrusted"
	CheckIssuerUntrusted   CheckResult = "issuer_untrusted"
	CheckIssuerUnavailable CheckResult = "issuer_unavailable"
	CheckNotBound          CheckResult = "not_bound"
	CheckRateLimited       CheckResult = "rate_limited"
)
