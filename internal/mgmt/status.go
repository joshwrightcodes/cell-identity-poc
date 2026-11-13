package mgmt

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
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
}

type reports struct {
	applied      spec.Revision
	appliedAt    time.Time
	lastReportAt time.Time
	lagSince     time.Time
	refusal      *mgmtapi.Refusal
	storeError   string
	behindLogged bool

	gateway        *mgmtapi.GatewayStatus
	gatewayAt      time.Time
	droppedAt      time.Time
	epochChangedAt time.Time
}

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
	if len(st.PendingDrops) > 0 && r.Applied == st.Last {
		if err := p.dropNext(r.Applied); err != nil && ReasonOf(err) != mgmtapi.ReasonRestoreActive {
			p.logLimited(context.Background(), slog.LevelError, "drop_failed", "drop_failed", "error", err.Error())
		}
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
	names := sortedKeys(p.intent)
	for name := range st.Cells {
		if _, ok := p.intent[name]; !ok {
			names = append(names, name)
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
