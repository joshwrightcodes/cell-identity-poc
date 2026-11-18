// Package executor is the part of celld that verifies a signed operation, records it with a lease
// and applies it at most once for each operation ID.
package executor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	// DefaultNamespace holds the operation records and the demo log.
	DefaultNamespace = "cell-ops-system"

	leaseTerm  = 60 * time.Second
	renewEvery = 20 * time.Second
	// effectMargin is how long before the lease end the context of an effect ends.
	effectMargin = 5 * time.Second
	maxRecords   = 1000

	// ReasonStoreError is the reason of a local lease_lost that follows a failed API call. A cell
	// never sends it up.
	ReasonStoreError = "store_error"
	// ReasonFenceRange is the reason of a local lease_lost for a lease whose fence epoch is too far
	// above the clock of the cell. A cell never sends it up.
	ReasonFenceRange = "fence_range"
	// ReasonEffectFailed is the reason of a local lease_lost that follows a failed effect. A cell
	// never sends it up.
	ReasonEffectFailed = "effect_failed"
)

// Config holds what an Executor needs.
type Config struct {
	Cell, Env, Pod, PodUID, Namespace string
	Keys                              []ed25519.PublicKey
	Kinds                             map[string]Effect
	Client                            kubernetes.Interface
	Now                               func() time.Time
	Log                               *slog.Logger
	Meter                             metric.Meter
	// Bundle, when set, adds the kind bundle.apply to Kinds.
	Bundle *bundleapply.Applier
}

// Executor applies signed operations to one cell.
type Executor struct {
	cfg     Config
	bundle  bundleApplier
	results metric.Int64Counter

	applied, refused, forged atomic.Uint64

	renewEvery time.Duration
	// margin is how long before the lease end the context of an effect ends.
	margin     time.Duration
	afterClaim func()
	// beforeTakeover runs between the read and the update of a takeover.
	beforeTakeover func()
}

// New returns an Executor. A zero Namespace, Kinds, Now, Log or Meter takes its default.
func New(cfg Config) *Executor {
	if cfg.Namespace == "" {
		cfg.Namespace = DefaultNamespace
	}
	if cfg.Kinds == nil {
		cfg.Kinds = DefaultKinds()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.Meter == nil {
		cfg.Meter = metricnoop.NewMeterProvider().Meter("celld")
	}
	e := &Executor{cfg: cfg, renewEvery: renewEvery, margin: effectMargin}
	if cfg.Bundle != nil {
		e.bundle = cfg.Bundle
		e.cfg.Kinds = withBundle(cfg.Kinds, cfg.Bundle)
	}
	e.results, _ = cfg.Meter.Int64Counter("celld.ops.results")
	return e
}

func (e *Executor) result(opID, outcome, reason string, f op.Fence, sha string) op.Result {
	return op.Result{
		OpID: opID, Cell: e.cfg.Cell, Pod: e.cfg.Pod, Outcome: outcome, Reason: reason,
		Fence: f, At: e.cfg.Now(), EnvelopeSHA256: sha,
	}
}

// finishFinal records the final outcome of an effect, and returns it as the result.
func (e *Executor) finishFinal(ctx context.Context, id string, f op.Fence, sha string, fin *Final) op.Result {
	res := e.result(id, fin.Outcome, fin.Reason, f, sha)
	if fin.Detail == "" || op.ValidDetail(fin.Detail) {
		res.Detail = fin.Detail
	}
	if !e.finish(ctx, id, f, res) {
		return e.result(id, op.OutcomeLeaseLost, op.ReasonLeaseLost, f, sha)
	}
	return res
}

// Execute verifies the envelope, claims its operation, runs the effect and records the result. It
// never returns an error: every failure is a result.
func (e *Executor) Execute(ctx context.Context, envelope []byte, f op.Fence) op.Result {
	res := e.execute(ctx, envelope, f)
	e.count(res)
	e.results.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", res.Outcome), attribute.String("reason", res.Reason)))
	e.cfg.Log.LogAttrs(ctx, slog.LevelInfo, "operation result",
		slog.String("op_id", res.OpID), slog.String("peeked_id", res.PeekedID),
		slog.String("outcome", res.Outcome), slog.String("reason", res.Reason))
	return res
}

func (e *Executor) execute(ctx context.Context, envelope []byte, f op.Fence) op.Result {
	sha := op.EnvelopeSHA256(envelope)
	if f.Epoch > uint64(e.cfg.Now().Unix())+op.MaxFenceAhead {
		// The gateway refuses a hello with an epoch above this bound, so a record with such a fence
		// would lock the cell out of the stream.
		e.cfg.Log.LogAttrs(ctx, slog.LevelWarn, "lease refused: fence epoch is too high",
			slog.Uint64("epoch", f.Epoch), slog.Uint64("counter", f.Counter))
		return e.result("", op.OutcomeLeaseLost, ReasonFenceRange, f, sha)
	}
	o, refusal := e.check(ctx, envelope, f, sha)
	if refusal != nil {
		return *refusal
	}
	if res := e.claim(ctx, o, f, sha); res != nil {
		return *res
	}
	if e.afterClaim != nil {
		e.afterClaim()
	}
	until, err := e.renew(ctx, o.ID, f)
	if err != nil {
		reason := ReasonStoreError
		if errors.Is(err, errNotHeld) {
			reason = op.ReasonLeaseLost
		}
		return e.result(o.ID, op.OutcomeLeaseLost, reason, f, sha)
	}
	effectCtx, stop := e.renewLease(ctx, o.ID, f, until)
	err = e.cfg.Kinds[o.Kind](effectCtx, e, o)
	stop()
	var final *Final
	if errors.As(err, &final) {
		return e.finishFinal(ctx, o.ID, f, sha, final)
	}
	if err != nil {
		e.cfg.Log.LogAttrs(ctx, slog.LevelWarn, "effect failed",
			slog.String("op_id", o.ID), slog.String("error", err.Error()))
		return e.result(o.ID, op.OutcomeLeaseLost, ReasonEffectFailed, f, sha)
	}
	res := e.result(o.ID, op.OutcomeApplied, "", f, sha)
	if !e.finish(ctx, o.ID, f, res) {
		return e.result(o.ID, op.OutcomeLeaseLost, op.ReasonLeaseLost, f, sha)
	}
	return res
}

// Counts holds how many results of each kind the executor has returned. ForgedSeen counts the
// refusals for a bad signature or a wrong target (environment or cell).
type Counts struct {
	Applied, Refused, ForgedSeen uint64
}

// Counts returns the running totals.
func (e *Executor) Counts() Counts {
	return Counts{Applied: e.applied.Load(), Refused: e.refused.Load(), ForgedSeen: e.forged.Load()}
}

func (e *Executor) count(res op.Result) {
	switch res.Outcome {
	case op.OutcomeApplied:
		e.applied.Add(1)
	case op.OutcomeRefused:
		e.refused.Add(1)
		switch res.Reason {
		case op.ReasonSignatureInvalid, op.ReasonWrongTarget, op.ReasonEnvMismatch:
			e.forged.Add(1)
		}
	}
}
