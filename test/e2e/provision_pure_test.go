package e2e

import (
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
)

// stageSection is one stage of a step log: its header fields and its lines.
type stageSection struct {
	stage, cluster string
	at             time.Time
	lines          []string
}

// lastAttempts keeps the last section of each stage, in the order in which the stages first appear. A retry of the host service appends
// another section for the stage that it runs again, and only the last attempt shows how the step ended.
func lastAttempts(secs []stageSection) []stageSection {
	var order []string
	last := map[string]stageSection{}
	for _, s := range secs {
		if _, ok := last[s.stage]; !ok {
			order = append(order, s.stage)
		}
		last[s.stage] = s
	}
	out := make([]stageSection, 0, len(order))
	for _, name := range order {
		out = append(out, last[name])
	}
	return out
}

// freshRefusal reports whether r is the refusal of the item that a case injected at injected: it has the kind and reason, and it is
// newer than both the start of the window and prev, the refusal that ended the case before. ItemRefusal has no item ID, so a second
// case with the same reason would otherwise pass on the refusal of the first.
func freshRefusal(r *mgmt.ItemRefusal, kind, reason string, injected, prev time.Time) bool {
	return r != nil && r.Kind == kind && r.Reason == reason && r.At.After(injected) && r.At.After(prev)
}
