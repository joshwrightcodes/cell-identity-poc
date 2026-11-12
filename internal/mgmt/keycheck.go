package mgmt

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// CheckResult is the outcome of a key check.
type CheckResult string

// KeyCheck compares the keys that the issuer publishes with the keys of the record. An error means
// the check could not run; a refusal is a result.
func (p *Plane) KeyCheck(ctx context.Context, cell string) (res CheckResult, err error) {
	defer func() {
		if err == nil {
			p.checkResults.Add(ctx, 1, metric.WithAttributes(attribute.String("result", string(res))))
		}
	}()
	if _, ok := p.intent[cell]; !ok {
		return "", refuse(mgmtapi.ReasonCellUnknown, "")
	}
	pre := p.snap.Load().st.Cells[cell]
	switch {
	case pre == nil:
		return CheckNotBound, nil
	case p.gapActive(pre, p.cfg.Now()):
		return CheckRateLimited, nil
	}
	keys, at, _, ferr := p.cachedKeys(ctx, cell, fetchFresh)
	if ferr != nil {
		res = CheckIssuerUnavailable
		if ReasonOf(ferr) == mgmtapi.ReasonIssuerUntrusted {
			res = CheckIssuerUntrusted
		}
		if err := p.noteCheck(cell, res); err != nil {
			return res, err
		}
		return res, nil
	}
	err = p.commit(func(t *txn) error {
		cs := t.st.Cells[cell]
		switch {
		case cs == nil:
			res = CheckNotBound
			return nil
		case p.gapActive(cs, t.now):
			res = CheckRateLimited
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
		p.cfg.Log.InfoContext(ctx, "key_check", "cell", cell, "result", string(res))
	}
	return res, nil
}

func (p *Plane) judge(t *txn, cell string, cs *CellState, keys mgmtapi.ClusterKeys, fetchedAt time.Time) (CheckResult, error) {
	settle := func(res CheckResult) (CheckResult, error) {
		cs.CheckedAt, cs.LastCheck = fetchedAt, string(res)
		t.dirty = true
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
		// The new set does not fit a record. The cell keeps its last good record.
		*cs = old
		return settle(CheckKeysUntrusted)
	}
	return CheckKeysUpdated, nil
}

// noteCheck records a check that learned nothing about the keys, so that status shows it. It does
// not start the update gap.
func (p *Plane) noteCheck(cell string, res CheckResult) error {
	return p.commit(func(t *txn) error {
		if cs := t.st.Cells[cell]; cs != nil && cs.LastCheck != string(res) {
			cs.LastCheck = string(res)
			t.dirty = true
		}
		return nil
	})
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
			if _, ok := p.intent[name]; !ok || p.cfg.Now().Sub(st.Cells[name].CheckedAt) < p.cfg.CheckEvery {
				continue
			}
			if _, err := p.KeyCheck(ctx, name); err != nil {
				p.logLimited(ctx, slog.LevelWarn, "key_check_failed/"+name, "key_check_failed", "cell", name, "error", err.Error())
			}
		}
	}
}

// PreviewKeys reads the keys of a cell without a cache and changes no state.
func (p *Plane) PreviewKeys(ctx context.Context, cell string) (mgmtapi.ClusterKeys, error) {
	if _, ok := p.intent[cell]; !ok {
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
