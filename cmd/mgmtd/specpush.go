package main

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// Back-off of a failed spec push: it starts at specBackoffMin and doubles up to specBackoffMax.
const (
	specBackoffMin = time.Second
	specBackoffMax = 30 * time.Second
	// specRepushEvery is how often the pusher sends the latest spec again, so that a host service
	// that restarted and lost its copy gets it back.
	specRepushEvery = 60 * time.Second
)

// SpecPusher sends the newest signed spec to the host service. Offer never blocks and keeps only
// the latest envelope, so a slow or absent host service cannot delay a commit. Run pushes the
// latest envelope after each Offer, again after a failure with a back-off, and again after every
// interval while it has one.
type SpecPusher struct {
	c interface {
		PutSpec(context.Context, []byte) error
	}
	every time.Duration
	log   *slog.Logger
	wake  chan struct{}
	limit *lograte.Limiter

	// Tests replace these before Run.
	backoffMin, backoffMax time.Duration
	now                    func() time.Time
	started                time.Time

	mu       sync.Mutex
	latest   []byte
	gen      uint64
	pushedAt time.Time
	lastErr  string
}

// NewSpecPusher returns a pusher that sends to c and repeats its latest push every interval.
func NewSpecPusher(c interface {
	PutSpec(context.Context, []byte) error
}, every time.Duration, log *slog.Logger) *SpecPusher {
	p := &SpecPusher{
		c: c, every: every, log: log, wake: make(chan struct{}, 1),
		limit:      lograte.New(time.Minute, 4, time.Now),
		backoffMin: specBackoffMin, backoffMax: specBackoffMax, now: time.Now,
	}
	p.started = p.now()
	return p
}

// Offer makes envelope the latest spec to push. It copies the bytes, replaces an envelope that was
// not pushed yet, and returns at once.
func (p *SpecPusher) Offer(envelope []byte) {
	p.mu.Lock()
	p.latest = append([]byte(nil), envelope...)
	p.gen++
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// State returns the time of the last successful push, and the reason of the last failure. The reason
// is empty after a success.
func (p *SpecPusher) State() (time.Time, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pushedAt, p.lastErr
}

// Observe registers the gauge mgmtd.hostsvc.spec_push_age: the seconds since the last successful
// push, or since the pusher was made while none has succeeded.
func (p *SpecPusher) Observe(m metric.Meter) error {
	_, err := m.Int64ObservableGauge("mgmtd.hostsvc.spec_push_age", metric.WithUnit("s"),
		metric.WithDescription("Seconds since the last successful push of the signed spec to the host service."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			since, _ := p.State()
			if since.IsZero() {
				since = p.started
			}
			o.Observe(int64(p.now().Sub(since) / time.Second))
			return nil
		}))
	return err
}

// Run pushes until ctx ends.
func (p *SpecPusher) Run(ctx context.Context) {
	var attemptedGen uint64
	wait := p.backoffMin
	announce := true
	var timer <-chan time.Time
	for {
		p.mu.Lock()
		env, gen := p.latest, p.gen
		p.mu.Unlock()
		if env != nil {
			attemptedGen = gen
			err := p.c.PutSpec(ctx, env)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				reason := mgmtapi.ReasonHostsvcUnavailable
				var he *mgmtapi.HostError
				if errors.As(err, &he) {
					reason = he.Reason
				}
				p.mu.Lock()
				p.lastErr = reason
				p.mu.Unlock()
				if _, ok, suppressed, _ := p.limit.Allow("spec_push_failed"); ok {
					p.log.Warn("spec_push_failed", "reason", reason, "retry_in", wait.String(), "suppressed", suppressed)
				}
				announce = true
				timer = time.After(wait + time.Duration(rand.Int64N(int64(wait)/4+1)))
				if wait *= 2; wait > p.backoffMax {
					wait = p.backoffMax
				}
			} else {
				p.mu.Lock()
				p.pushedAt, p.lastErr = p.now(), ""
				p.mu.Unlock()
				if announce {
					p.log.Info("spec_pushed")
				}
				announce, wait = false, p.backoffMin
				timer = time.After(p.every)
			}
		}
		for again := false; !again; {
			select {
			case <-ctx.Done():
				return
			case <-p.wake:
				p.mu.Lock()
				again = p.latest != nil && p.gen != attemptedGen
				p.mu.Unlock()
			case <-timer:
				again = true
			}
		}
	}
}
