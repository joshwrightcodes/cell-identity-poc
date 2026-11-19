package executor

import (
	"context"
	"fmt"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// bundleApplier is the part of bundleapply.Applier that the executor uses.
type bundleApplier interface {
	Apply(ctx context.Context, opID, opTarget string, attestation []byte) (bundleapply.Outcome, error)
	Recorded(ctx context.Context, opID string) (bundleapply.Outcome, bool, error)
	Status(ctx context.Context) (*op.BundleStatus, error)
}

// applyBundle returns the effect of bundle.apply. A final outcome other than applied comes back as a
// *Final, so that the executor records it. An error from the engine is a fault that a repeat of the
// operation can resume: the executor records no result for it.
func applyBundle(a bundleApplier) Effect {
	return func(ctx context.Context, _ *Executor, o op.Operation) error {
		if o.Kind != op.KindBundleApply {
			return fmt.Errorf("kind %q is not %s", o.Kind, op.KindBundleApply)
		}
		out, err := a.Apply(ctx, o.ID, o.Cell, o.Args)
		if err != nil {
			return fmt.Errorf("apply bundle set: %w", err)
		}
		return finalOf(out)
	}
}

// finalOf maps an engine outcome to the error of an effect. The engine reports a set that names
// another target as payload_invalid with detail target. The cell reports it as wrong_target, the
// reason that it gives to an operation for another cell.
func finalOf(out bundleapply.Outcome) error {
	switch {
	case out.Outcome == op.OutcomeApplied:
		return nil
	case out.Outcome == op.OutcomeRefused && out.Reason == op.ReasonPayloadInvalid && out.Detail == bundleapply.DetailTarget:
		return &Final{Outcome: op.OutcomeRefused, Reason: op.ReasonWrongTarget, Detail: out.Detail}
	}
	return &Final{Outcome: out.Outcome, Reason: out.Reason, Detail: out.Detail}
}
