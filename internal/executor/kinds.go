package executor

import (
	"context"
	"maps"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// Effect applies one operation to the cell. It must carry the operation ID into whatever it writes,
// and it must write by compare-and-swap, so that a second run after a crash changes nothing.
type Effect func(ctx context.Context, e *Executor, o op.Operation) error

// DefaultKinds returns the kinds that a production celld accepts: only demo.append.
func DefaultKinds() map[string]Effect {
	return map[string]Effect{op.KindDemoAppend: applyDemoAppend}
}

// withBundle returns a copy of kinds with the kind bundle.apply added.
func withBundle(kinds map[string]Effect, a bundleApplier) map[string]Effect {
	out := maps.Clone(kinds)
	out[op.KindBundleApply] = applyBundle(a)
	return out
}
