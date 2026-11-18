package mgmt

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// logWindow is how long a repeated log line stays quiet.
const logWindow = 5 * time.Minute

// Status is what `ctl status` shows.
type Status struct {
	Env                string           `json:"env"`
	Seq                uint64           `json:"seq"`
	Signed             spec.Revision    `json:"signed"`
	Served             spec.Revision    `json:"served"`
	RestoreActive      bool             `json:"restoreActive"`
	Applied            spec.Revision    `json:"applied"`
	AppliedAt          time.Time        `json:"appliedAt,omitzero"`
	LagSince           time.Time        `json:"lagSince,omitzero"`
	LastReportAt       time.Time        `json:"lastReportAt,omitzero"`
	LastRefusal        *mgmtapi.Refusal `json:"lastRefusal,omitempty"`
	StoreError         string           `json:"storeError,omitempty"`
	PendingDrops       []string         `json:"pendingDrops"`
	StateBehindApplied bool             `json:"stateBehindApplied"`
	Cells              []CellStatus     `json:"cells"`

	// Gateway is the last gateway status that envd reported. DroppedAt is the time that the dropped
	// count last rose, and EpochChangedAt the time that the queue epoch last changed. StagedKey is
	// the fingerprint of the staged signing key.
	Gateway        *mgmtapi.GatewayStatus `json:"gateway,omitempty"`
	GatewayAt      time.Time              `json:"gatewayAt,omitzero"`
	DroppedAt      time.Time              `json:"droppedAt,omitzero"`
	EpochChangedAt time.Time              `json:"epochChangedAt,omitzero"`
	StagedKey      string                 `json:"stagedKey,omitempty"`

	// PlaneBundle is the last served set of the control plane, and PlaneBundleStatus the bundle state
	// that envd reported for it.
	PlaneBundle       *mgmtapi.TargetBundle `json:"planeBundle,omitempty"`
	PlaneBundleStatus *op.BundleStatus      `json:"planeBundleStatus,omitempty"`

	// HostSpecPushedAt and HostSpecPushError describe the last spec push to the host service, from
	// Config.SpecPushState.
	HostSpecPushedAt  time.Time `json:"hostSpecPushedAt,omitzero"`
	HostSpecPushError string    `json:"hostSpecPushError,omitempty"`
}

// StepView is the step of a cell as the status shows it. Host is the last status that the host
// service reported for the step, kept in memory only.
type StepView struct {
	ID        string              `json:"id"`
	IssuedAt  time.Time           `json:"issuedAt"`
	ExpiresAt time.Time           `json:"expiresAt"`
	DoneAt    time.Time           `json:"doneAt,omitzero"`
	Host      *mgmtapi.StepStatus `json:"host,omitempty"`
}

// CellStatus is the status of one intent cell.
type CellStatus struct {
	Name      string        `json:"name"`
	Bound     bool          `json:"bound"`
	Issuer    string        `json:"issuer"`
	Kids      []string      `json:"kids"`
	Record    spec.Revision `json:"record"`
	CheckedAt time.Time     `json:"checkedAt,omitzero"`
	LastCheck string        `json:"lastCheck"`

	LastStatusAt       time.Time    `json:"lastStatusAt,omitzero"`
	LastStatusPod      string       `json:"lastStatusPod,omitempty"`
	Unreported         uint64       `json:"unreported"`
	OldestUnreportedAt time.Time    `json:"oldestUnreportedAt,omitzero"`
	Records            uint64       `json:"records"`
	OpenOps            int          `json:"openOps"`
	ExpiredOps         int          `json:"expiredOps"`
	LastResultAt       time.Time    `json:"lastResultAt,omitzero"`
	LastRefusal        *ItemRefusal `json:"lastRefusal,omitempty"`
	ForgedSeen         int          `json:"forgedSeen"`
	HintAt             time.Time    `json:"hintAt,omitzero"`
	LastHintCheck      string       `json:"lastHintCheck,omitempty"`

	// Bundle is the last signed set of the cell, and BundleStatus the state that its applier reported.
	Bundle       *mgmtapi.TargetBundle `json:"bundle,omitempty"`
	BundleStatus *op.BundleStatus      `json:"bundleStatus,omitempty"`

	Requested    bool      `json:"requested"`
	RequestedAt  time.Time `json:"requestedAt,omitzero"`
	RequestID    string    `json:"requestId,omitempty"`
	Step         *StepView `json:"step,omitempty"`
	Valid        bool      `json:"valid"`
	ValidReason  string    `json:"validReason,omitempty"`
	InvalidSince time.Time `json:"invalidSince,omitzero"`
}

type reports struct {
	applied      spec.Revision
	appliedAt    time.Time
	lastReportAt time.Time
	lagSince     time.Time
	refusal      *mgmtapi.Refusal
	storeError   string
	behindLogged bool

	planeBundle *op.BundleStatus

	gateway        *mgmtapi.GatewayStatus
	gatewayAt      time.Time
	droppedAt      time.Time
	epochChangedAt time.Time

	// stepHost is the last host status of each open step, by step ID. It lives in memory, so a
	// report never raises the state version.
	stepHost map[string]mgmtapi.StepStatus
}

// maxStepStatuses is the most step statuses that one report stores.
const maxStepStatuses = 32

func servedRevision(st *State) spec.Revision {
	if s := st.served(); s != nil {
		return s.Revision
	}
	return st.Last
}

// noteGateway keeps the gateway status, and the times that its dropped count last rose and its
// epoch last changed. A time that the gateway reports wins when it is later. Without one, a rise
// since the last report counts from now. The caller holds rmu.
func (p *Plane) noteGateway(g *mgmtapi.GatewayStatus, now time.Time) {
	prev := p.rep.gateway
	cp := *g
	cp.KeyHints = slices.Clone(g.KeyHints)
	p.rep.gateway, p.rep.gatewayAt = &cp, now
	if g.DroppedAt.After(p.rep.droppedAt) {
		p.rep.droppedAt = g.DroppedAt
	} else if prev != nil && g.Dropped > prev.Dropped {
		p.rep.droppedAt = now
	}
	if g.EpochChangedAt.After(p.rep.epochChangedAt) {
		p.rep.epochChangedAt = g.EpochChangedAt
	} else if prev != nil && g.Epoch != prev.Epoch {
		p.rep.epochChangedAt = now
	}
}

// Report stores what envd reported. A report of the signed revision releases the next pending drop.
// Each key hint, from the report or from the gateway, queues at most one background hint check for
// its cell in 60 s, so Report returns at once.
func (p *Plane) Report(r mgmtapi.StatusReport) {
	now := p.cfg.Now()
	p.rmu.Lock()
	st := p.snap.Load().st
	behind := r.Applied.Compare(st.Last) > 0
	if r.Applied != p.rep.applied || p.rep.appliedAt.IsZero() {
		p.rep.appliedAt = now
	}
	p.rep.applied, p.rep.lastReportAt, p.rep.storeError = r.Applied, now, r.StoreError
	p.rep.refusal = nil
	if r.LastRefusal != nil {
		cp := *r.LastRefusal
		p.rep.refusal = &cp
	}
	hints := slices.Clone(r.KeyHints)
	if r.Gateway != nil {
		p.noteGateway(r.Gateway, now)
		hints = append(hints, r.Gateway.KeyHints...)
	}
	p.rep.planeBundle = nil
	if r.PlaneBundleStatus != nil {
		b := *r.PlaneBundleStatus
		p.rep.planeBundle = &b
	}
	p.noteSteps(st, r.Steps)
	p.lagLocked(st, now)
	logBehind := behind && !p.rep.behindLogged
	p.rep.behindLogged = behind
	p.rmu.Unlock()
	if logBehind {
		p.cfg.Log.Error("state_behind_applied", "applied_epoch", r.Applied.Epoch, "applied_counter", r.Applied.Counter,
			"signed_epoch", st.Last.Epoch, "signed_counter", st.Last.Counter)
	}
	for _, h := range hints {
		p.queueHint(h.Cell)
	}
	p.planeResult(r.PlaneBundle)
	if len(st.PendingDrops) > 0 && r.Applied == st.Last {
		if err := p.dropNext(r.Applied); err != nil && ReasonOf(err) != mgmtapi.ReasonRestoreActive {
			p.logLimited(context.Background(), slog.LevelError, "drop_failed", "drop_failed", "error", err.Error())
		}
	}
}

// noteSteps keeps the host status of each open step that the report names, and forgets the status
// of every step that is no longer open. An entry that fails ValidStepStatus, names an unknown step
// or another cell than its step is dropped. The caller holds rmu.
func (p *Plane) noteSteps(st *State, steps []mgmtapi.StepStatus) {
	open := map[string]string{}
	for name, r := range st.Requests {
		if _, in := p.cellIn(st, name); in && r.Step.open() {
			open[r.Step.ID] = name
		}
	}
	for id := range p.rep.stepHost {
		if _, ok := open[id]; !ok {
			delete(p.rep.stepHost, id)
		}
	}
	if len(steps) > maxStepStatuses {
		steps = steps[:maxStepStatuses]
	}
	for _, s := range steps {
		if cell, ok := open[s.ID]; !ok || cell != s.Cell || !mgmtapi.ValidStepStatus(s) {
			continue
		}
		if p.rep.stepHost == nil {
			p.rep.stepHost = map[string]mgmtapi.StepStatus{}
		}
		p.rep.stepHost[s.ID] = s
	}
}

func (p *Plane) lagLocked(st *State, now time.Time) {
	if p.rep.applied.Compare(servedRevision(st)) >= 0 {
		p.rep.lagSince = time.Time{}
	} else if p.rep.lagSince.IsZero() {
		p.rep.lagSince = now
	}
}

func (p *Plane) noteLag() {
	st := p.snap.Load().st
	now := p.cfg.Now()
	p.rmu.Lock()
	p.lagLocked(st, now)
	p.rmu.Unlock()
}

func (p *Plane) observeLag(_ context.Context, o metric.Int64Observer) error {
	served := servedRevision(p.snap.Load().st)
	p.rmu.Lock()
	applied := p.rep.applied
	p.rmu.Unlock()
	var lag int64
	switch {
	case applied.Compare(served) >= 0:
	case applied.Epoch == served.Epoch:
		lag = int64(served.Counter - applied.Counter)
	default:
		lag = int64(served.Counter)
	}
	o.Observe(lag)
	return nil
}

// Status returns the status from the current snapshot and the last report.
func (p *Plane) Status() Status {
	st := p.snap.Load().st
	p.rmu.Lock()
	rep := p.rep
	if rep.gateway != nil {
		cp := *rep.gateway
		rep.gateway = &cp
	}
	live := p.rt.snapshot()
	hosts := maps.Clone(p.rep.stepHost)
	p.rmu.Unlock()
	now := p.cfg.Now()
	s := Status{
		Env: p.cfg.Intent.Env, Seq: st.Seq, Signed: st.Last, Served: servedRevision(st), RestoreActive: st.Served != 0,
		Applied: rep.applied, AppliedAt: rep.appliedAt, LagSince: rep.lagSince, LastReportAt: rep.lastReportAt,
		LastRefusal: rep.refusal, StoreError: rep.storeError,
		PendingDrops:       append([]string{}, st.PendingDrops...),
		StateBehindApplied: rep.applied.Compare(st.Last) > 0,
		Cells:              []CellStatus{},
		Gateway:            rep.gateway, GatewayAt: rep.gatewayAt, DroppedAt: rep.droppedAt, EpochChangedAt: rep.epochChangedAt,
		StagedKey: st.StagedKeySHA256,
	}
	if tb, ok := st.Bundles[p.cfg.Intent.ControlPlaneName()].shown(); ok {
		s.PlaneBundle = &tb
	}
	s.PlaneBundleStatus = rep.planeBundle
	if p.cfg.SpecPushState != nil {
		s.HostSpecPushedAt, s.HostSpecPushError = p.cfg.SpecPushState()
	}
	seen := map[string]bool{}
	var names []string
	for _, set := range [][]string{sortedKeys(p.catalog), sortedKeys(st.Cells)} {
		for _, name := range set {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	for _, name := range names {
		cs := CellStatus{Name: name, Kids: []string{}}
		if c := st.Cells[name]; c != nil {
			cs.Bound, cs.Issuer, cs.Kids, cs.Record = true, c.Issuer, kidsOf(c.JWKS), c.Record
			cs.CheckedAt, cs.LastCheck = c.CheckedAt, c.LastCheck
		}
		cs.fill(live[name], st, now)
		if _, in := p.cellIn(st, name); in {
			r := st.Requests[name]
			cs.Requested, cs.RequestedAt, cs.RequestID = true, r.RequestedAt, r.RequestID
			if r.Step != nil {
				cs.Step = &StepView{ID: r.Step.ID, IssuedAt: r.Step.IssuedAt, ExpiresAt: r.Step.ExpiresAt, DoneAt: r.Step.DoneAt}
				if h, ok := hosts[r.Step.ID]; ok && r.Step.open() {
					cs.Step.Host = &h
				}
			}
		}
		cs.Valid, cs.ValidReason = p.validOf(st, name, live[name], rep.applied, now)
		cs.InvalidSince = p.noteValid(name, cs.Valid, now)
		s.Cells = append(s.Cells, cs)
	}
	return s
}

// logLimited logs a line that can repeat. It lets one line through for each key and window, and
// adds the count of the lines that it held back.
func (p *Plane) logLimited(ctx context.Context, level slog.Level, key, msg string, args ...any) {
	_, ok, suppressed, held := p.logs.Allow(key)
	for _, h := range held {
		p.cfg.Log.Warn("log_suppressed", "key", h.Key, "suppressed", h.Suppressed)
	}
	if !ok {
		return
	}
	if suppressed > 0 {
		args = append(args, "suppressed", suppressed)
	}
	p.cfg.Log.Log(ctx, level, msg, args...)
}
