package envd

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// statusTimeout bounds the read of the bundle state for a status report.
const statusTimeout = 5 * time.Second

// detailTarget is the detail that the engine gives to a set that names another target.
const detailTarget = "target"

// BundleApplier is the part of bundleapply.Applier that the plane path uses.
type BundleApplier interface {
	Apply(ctx context.Context, opID, opTarget string, attestation []byte) (bundleapply.Outcome, error)
	Status(ctx context.Context) (*op.BundleStatus, error)
}

// PlaneConfig holds what a Plane needs. Keys returns the keys that sign operations, read again for
// each envelope. A nil Now uses the real clock and a nil Log uses the default logger.
type PlaneConfig struct {
	Env, Cluster string
	Keys         func() []crypto.PublicKey
	Applier      BundleApplier
	Now          func() time.Time
	Log          *slog.Logger
}

// Plane applies the signed bundle set for the cluster of envd. The management plane hands the open
// envelope to each ops pull, and the plane applies it once, in its own goroutine, and keeps the
// final result for the status report until the envelope leaves the ops pull.
type Plane struct {
	cfg PlaneConfig
	wg  sync.WaitGroup

	logs *lograte.Limiter

	mu  sync.Mutex
	cur *planeEntry
}

// planeEntry is the envelope that the plane has taken. res is nil while the apply runs. recheck is
// true when res can change without a new envelope: a signature or payload refusal (the keys can
// change) and an operation that is not yet valid (the clock moves).
type planeEntry struct {
	sha     string
	res     *op.Result
	recheck bool
}

// logWindow is how long an equal engine fault stays silent in the log.
const logWindow = time.Minute

// NewPlane returns a Plane for cfg. It fails when Keys or Applier is nil.
func NewPlane(cfg PlaneConfig) (*Plane, error) {
	if cfg.Keys == nil || cfg.Applier == nil {
		return nil, errors.New("a plane needs Keys and an Applier")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Plane{cfg: cfg, logs: lograte.New(logWindow, 16, cfg.Now)}, nil
}

// Offer hands the open plane envelope of the ops pull to the plane, or nil when the pull holds none.
// It never blocks on the engine. An envelope that the plane already holds changes nothing, and so
// does a different envelope while an apply runs, except that a held refusal that the keys or the
// clock can undo is checked again. An empty offer drops the held result, unless an apply is still
// running. The plane runs only after envd accepts a spec and only when a gateway is set, because the
// ops pull belongs to the relay legs.
func (p *Plane) Offer(ctx context.Context, envelope []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(envelope) == 0 {
		if p.cur != nil && p.cur.res != nil {
			p.cur = nil
		}
		return
	}
	sha := op.EnvelopeSHA256(envelope)
	if p.cur != nil && (p.cur.res == nil || p.cur.sha == sha && !p.cur.recheck) {
		return
	}
	o, res, recheck := p.check(envelope, sha)
	if res != nil {
		p.cur = &planeEntry{sha: sha, res: res, recheck: recheck}
		return
	}
	p.cur = &planeEntry{sha: sha}
	p.wg.Go(func() { p.apply(ctx, o, sha) })
}

// check runs every rule that needs no engine and returns the operation, or the refusal result and
// whether a later check can undo it.
func (p *Plane) check(envelope []byte, sha string) (op.Operation, *op.Result, bool) {
	o, _, err := op.Verify(envelope, p.keys())
	if err != nil {
		reason := op.ReasonPayloadInvalid
		if errors.Is(err, record.ErrSignature) {
			reason = op.ReasonSignatureInvalid
		}
		res := p.result("", op.OutcomeRefused, reason, "", sha)
		if id, _, _, perr := op.Peek(envelope); perr == nil {
			res.PeekedID = id
		}
		return op.Operation{}, res, true
	}
	refuse := func(outcome, reason string) (op.Operation, *op.Result, bool) {
		return op.Operation{}, p.result(o.ID, outcome, reason, "", sha), false
	}
	now := p.cfg.Now()
	switch {
	case o.Kind != op.KindBundleApply:
		return refuse(op.OutcomeRefused, op.ReasonKindUnknown)
	case o.Env != p.cfg.Env:
		return refuse(op.OutcomeRefused, op.ReasonEnvMismatch)
	case o.Cell != p.cfg.Cluster:
		return refuse(op.OutcomeRefused, op.ReasonWrongTarget)
	case o.IssuedAt.After(now.Add(op.MaxSkew)):
		// The clock of envd runs behind the signer. The result is not final, so the operation stays
		// open until the clock passes the issue time.
		res := p.result(o.ID, op.OutcomeLeaseLost, op.ReasonLeaseLost, "clock", sha)
		return op.Operation{}, res, true
	case !now.Before(o.ExpiresAt):
		return refuse(op.OutcomeExpired, "")
	case len(o.Args) > op.MaxBundleArgsBytes:
		return refuse(op.OutcomeRefused, op.ReasonPayloadInvalid)
	}
	return o, nil, false
}

func (p *Plane) keys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, k := range p.cfg.Keys() {
		if ed, ok := k.(ed25519.PublicKey); ok {
			keys = append(keys, ed)
		}
	}
	return keys
}

func (p *Plane) result(opID, outcome, reason, detail, sha string) *op.Result {
	return &op.Result{OpID: opID, Cell: p.cfg.Cluster, Outcome: outcome, Reason: reason, Detail: detail,
		At: p.cfg.Now().UTC(), EnvelopeSHA256: sha}
}

// apply runs the engine and records the final result. A fault that a repeat can resume leaves no
// result, so the next offer of the same envelope runs the engine again.
func (p *Plane) apply(ctx context.Context, o op.Operation, sha string) {
	out, err := p.cfg.Applier.Apply(ctx, o.ID, o.Cell, o.Args)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur == nil || p.cur.sha != sha {
		return
	}
	if err != nil {
		p.cur = nil
		msg := clip(err.Error())
		if _, ok, suppressed, _ := p.logs.Allow(msg); ok {
			p.cfg.Log.WarnContext(ctx, "plane bundle apply did not finish", "op", o.ID, "error", msg, "suppressed", suppressed)
		}
		return
	}
	if out.Outcome == op.OutcomeRefused && out.Reason == op.ReasonPayloadInvalid && out.Detail == detailTarget {
		out.Reason = op.ReasonWrongTarget
	}
	detail := out.Detail
	if detail != "" && !op.ValidDetail(detail) {
		detail = ""
	}
	p.cur.res = p.result(o.ID, out.Outcome, out.Reason, detail, sha)
	p.cfg.Log.InfoContext(ctx, "plane bundle applied", "op", o.ID, "outcome", out.Outcome, "reason", out.Reason)
}

// Report returns the final result that the status report carries, and the bundle state of the
// cluster. Either is nil when there is none.
func (p *Plane) Report() (*op.Result, *op.BundleStatus) {
	p.mu.Lock()
	var res *op.Result
	if p.cur != nil && p.cur.res != nil {
		cp := *p.cur.res
		res = &cp
	}
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), statusTimeout)
	defer cancel()
	st, err := p.cfg.Applier.Status(ctx)
	if err != nil {
		p.cfg.Log.Warn("plane bundle status not read", "error", clip(err.Error()))
		st = nil
	}
	return res, st
}

// wait blocks until every running apply ends. Tests use it.
func (p *Plane) wait() { p.wg.Wait() }
