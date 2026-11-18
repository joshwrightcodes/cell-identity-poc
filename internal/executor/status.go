package executor

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const statusReadTimeout = 10 * time.Second

// NewStatus returns a function that makes the status of one celld pod. Seq rises with each call,
// so the management plane can drop a stale report. The counts and the record figures come from e.
func NewStatus(cell, pod, podUID, version string, svidExpiry func() time.Time, e *Executor) func() op.Status {
	var seq atomic.Uint64
	return func() op.Status {
		ctx, cancel := context.WithTimeout(context.Background(), statusReadTimeout)
		defer cancel()
		c := e.Counts()
		s := op.Status{
			Cell: cell, Pod: pod, PodUID: podUID, Version: version,
			Seq: seq.Add(1), At: e.cfg.Now(), SVIDExpiresAt: svidExpiry(),
			Applied: c.Applied, Refused: c.Refused, ForgedSeen: c.ForgedSeen,
		}
		if n, err := e.Count(ctx); err == nil {
			s.Records = uint64(n)
		}
		if pending, err := e.Pending(ctx); err == nil {
			s.Unreported = uint64(len(pending))
			if len(pending) > 0 {
				s.OldestUnreportedAt = pending[0].At
			}
		}
		if e.bundle != nil {
			if b, err := e.bundle.Status(ctx); err == nil {
				s.Bundle = b
			}
		}
		return s
	}
}
