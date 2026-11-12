package envd

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

func reflectEqual(a, b any) bool { return reflect.DeepEqual(a, b) }

// clock is a fake clock whose Sleep advances time at once and stops a Run after a number of sleeps.
type clock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
	stop   int
	cancel context.CancelFunc
}

func newClock(stopAfter int) *clock {
	return &clock{now: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC), stop: stopAfter}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	done := c.stop > 0 && len(c.sleeps) >= c.stop
	cancel := c.cancel
	c.mu.Unlock()
	if done && cancel != nil {
		cancel()
	}
	return ctx.Err()
}

func (c *clock) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sleeps)
}

func (c *clock) slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

// firstBundle is a bundle of cells a and b, both at revision r.
func firstBundle(f *fx, r spec.Revision) mgmtapi.SpecBundle {
	return f.bundle(r, []item{f.item(f.cell("a", r, false)), f.item(f.cell("b", r, false))}, nil)
}
