package mgmt

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// ReasonStatusInFuture is the valid reason of a cell whose last proven status lies more than
// MaxValidSkew ahead of the clock.
const ReasonStatusInFuture = "status_in_future"

const (
	// MaxValidAge is the oldest proven status that a valid cell may have.
	MaxValidAge = 2 * time.Minute
	// MaxValidSkew is how far a proven status of a valid cell may lie in the future.
	MaxValidSkew = 60 * time.Second
)

// ValidInput holds the facts that decide whether a cell is valid. KeysUpdatedAt is the time that the
// current keys of the cell took effect; a status older than that proves nothing about them.
type ValidInput struct {
	Requested, Bound bool
	Record, Applied  spec.Revision
	LastStatusAt     time.Time
	KeysUpdatedAt    time.Time
	LastCheck        string
}

// ValidOf reports whether a cell is valid at now. The reason names the first rule that fails, and is
// empty for a valid cell. Step status from the host never enters the rule.
func ValidOf(in ValidInput, now time.Time) (bool, string) {
	switch {
	case !in.Requested:
		return false, mgmtapi.ReasonNotRequested
	case !in.Bound:
		return false, mgmtapi.ReasonNotBound
	case in.Record.Compare(in.Applied) > 0:
		return false, mgmtapi.ReasonRecordNotApplied
	case in.LastStatusAt.IsZero() || in.LastStatusAt.Before(in.KeysUpdatedAt):
		return false, mgmtapi.ReasonNoStatus
	case now.Sub(in.LastStatusAt) > MaxValidAge:
		return false, mgmtapi.ReasonStatusStale
	case in.LastStatusAt.Sub(now) > MaxValidSkew:
		return false, ReasonStatusInFuture
	}
	switch CheckResult(in.LastCheck) {
	case CheckKeysUntrusted, CheckIssuerUntrusted, CheckIssuerUnavailable:
		return false, mgmtapi.ReasonKeysFailed
	}
	return true, ""
}

// validOf evaluates one catalog or state cell against the snapshot st and the live data. The caller
// holds rmu.
func (p *Plane) validOf(st *State, name string, live cellRuntime, applied spec.Revision, now time.Time) (bool, string) {
	in := ValidInput{Applied: applied, LastStatusAt: live.lastStatusAt}
	_, in.Requested = p.cellIn(st, name)
	if c := st.Cells[name]; c != nil {
		in.Bound, in.Record, in.KeysUpdatedAt, in.LastCheck = true, c.Record, c.KeysUpdatedAt, c.LastCheck
	}
	return ValidOf(in, now)
}

// observeValid reports the count of valid cells.
func (p *Plane) observeValid(_ context.Context, o metric.Int64Observer) error {
	st := p.snap.Load().st
	now := p.cfg.Now()
	p.rmu.Lock()
	defer p.rmu.Unlock()
	var n int64
	for _, name := range p.intentNames(st) {
		var live cellRuntime
		if c := p.rt.cells[name]; c != nil {
			live = *c
		}
		if ok, _ := p.validOf(st, name, live, p.rep.applied, now); ok {
			n++
		}
	}
	o.Observe(n)
	return nil
}

// noteValid keeps the time that a cell was first seen invalid, and returns it. A valid cell has none.
func (p *Plane) noteValid(name string, valid bool, now time.Time) time.Time {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	c := p.rt.cell(name)
	switch {
	case valid:
		c.invalidSince = time.Time{}
	case c.invalidSince.IsZero():
		c.invalidSince = now
	}
	return c.invalidSince
}
