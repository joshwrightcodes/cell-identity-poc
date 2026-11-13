// Package executor is the part of celld that verifies a signed operation, records it with a lease
// and applies it at most once for each operation ID.
package executor

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	// DefaultNamespace holds the operation records and the demo log.
	DefaultNamespace = "cell-ops-system"

	leaseTerm    = 60 * time.Second
	renewEvery   = 20 * time.Second
	maxRecords   = 1000
	reasonStore  = "store_error"
	reasonEffect = "effect_failed"
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
}

// Executor applies signed operations to one cell.
type Executor struct {
	cfg     Config
	results metric.Int64Counter

	renewEvery time.Duration
	afterClaim func()
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
	e := &Executor{cfg: cfg, renewEvery: renewEvery}
	e.results, _ = cfg.Meter.Int64Counter("celld.ops.results")
	return e
}

func (e *Executor) result(opID, outcome, reason string, f op.Fence, sha string) op.Result {
	return op.Result{
		OpID: opID, Cell: e.cfg.Cell, Pod: e.cfg.Pod, Outcome: outcome, Reason: reason,
		Fence: f, At: e.cfg.Now(), EnvelopeSHA256: sha,
	}
}

// Execute verifies the envelope, claims its operation, runs the effect and records the result. It
// never returns an error: every failure is a result.
func (e *Executor) Execute(ctx context.Context, envelope []byte, f op.Fence) op.Result {
	res := e.execute(ctx, envelope, f)
	e.results.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", res.Outcome), attribute.String("reason", res.Reason)))
	e.cfg.Log.LogAttrs(ctx, slog.LevelInfo, "operation result",
		slog.String("op_id", res.OpID), slog.String("peeked_id", res.PeekedID),
		slog.String("outcome", res.Outcome), slog.String("reason", res.Reason))
	return res
}

func (e *Executor) execute(ctx context.Context, envelope []byte, f op.Fence) op.Result {
	sha := op.EnvelopeSHA256(envelope)
	o, refusal := e.check(envelope, f, sha)
	if refusal != nil {
		return *refusal
	}
	if res := e.claim(ctx, o, f, sha); res != nil {
		return *res
	}
	if e.afterClaim != nil {
		e.afterClaim()
	}
	if _, ok := e.holds(ctx, o.ID, f); !ok {
		return e.result(o.ID, op.OutcomeLeaseLost, op.ReasonLeaseLost, f, sha)
	}
	stop := e.renewLease(ctx, o.ID, f)
	err := e.cfg.Kinds[o.Kind](ctx, e, o)
	stop()
	if err != nil {
		e.cfg.Log.LogAttrs(ctx, slog.LevelWarn, "effect failed",
			slog.String("op_id", o.ID), slog.String("error", err.Error()))
		return e.result(o.ID, op.OutcomeLeaseLost, reasonEffect, f, sha)
	}
	res := e.result(o.ID, op.OutcomeApplied, "", f, sha)
	if !e.finish(ctx, o.ID, f, res) {
		return e.result(o.ID, op.OutcomeLeaseLost, op.ReasonLeaseLost, f, sha)
	}
	return res
}
