package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

type putCall struct {
	env []byte
	at  time.Time
	// pushedAt and failure are the state of the pusher when the call arrived.
	pushedAt time.Time
	failure  string
}

// fakeHost records each PutSpec call. A call waits on gate when gate is set, and answers with the
// next element of errs (nil after errs runs out).
type fakeHost struct {
	mu      sync.Mutex
	calls   []putCall
	errs    []error
	gate    chan struct{}
	entered chan struct{}
	state   func() (time.Time, string)
}

func (h *fakeHost) PutSpec(ctx context.Context, env []byte) error {
	h.mu.Lock()
	c := putCall{env: append([]byte(nil), env...), at: time.Now()}
	if h.state != nil {
		c.pushedAt, c.failure = h.state()
	}
	h.calls = append(h.calls, c)
	var err error
	if len(h.errs) > 0 {
		err, h.errs = h.errs[0], h.errs[1:]
	}
	gate, entered := h.gate, h.entered
	h.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (h *fakeHost) got() []putCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]putCall(nil), h.calls...)
}

func discardLog() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func startPusher(t *testing.T, h *fakeHost, every time.Duration) *SpecPusher {
	t.Helper()
	p := NewSpecPusher(h, every, discardLog())
	p.backoffMin, p.backoffMax = 5*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the pusher did not stop")
		}
	})
	return p
}

func TestSpecPusherLatestOnly(t *testing.T) {
	h := &fakeHost{gate: make(chan struct{}), entered: make(chan struct{}, 8)}
	p := startPusher(t, h, time.Hour)
	p.Offer([]byte("one"))
	<-h.entered // the first push is now blocked at the host

	returned := make(chan struct{})
	go func() {
		p.Offer([]byte("two"))
		p.Offer([]byte("three"))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Offer blocked while a push was running")
	}
	close(h.gate)
	waitFor(t, "the second push", func() bool { return len(h.got()) >= 2 })
	// No stale wake-up may cause a third push.
	time.Sleep(50 * time.Millisecond)
	calls := h.got()
	if len(calls) != 2 || string(calls[0].env) != "one" || string(calls[1].env) != "three" {
		var seen []string
		for _, c := range calls {
			seen = append(seen, string(c.env))
		}
		t.Fatalf("pushed %v, want [one three]", seen)
	}
	if at, msg := p.State(); at.IsZero() || msg != "" {
		t.Fatalf("state after a success: %v %q", at, msg)
	}
}

func TestSpecPusherCopiesTheEnvelope(t *testing.T) {
	h := &fakeHost{}
	p := startPusher(t, h, time.Hour)
	buf := []byte("abc")
	p.Offer(buf)
	buf[0] = 'X'
	waitFor(t, "the push", func() bool { return len(h.got()) >= 1 })
	if got := string(h.got()[0].env); got != "abc" {
		t.Fatalf("pushed %q after the caller changed its buffer", got)
	}
}

func TestSpecPusherRetriesAndRepushes(t *testing.T) {
	busy := &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcBusy, Status: 503}
	h := &fakeHost{errs: []error{busy, errors.New("connection refused"), busy, busy}}
	p := NewSpecPusher(h, 40*time.Millisecond, discardLog())
	p.backoffMin, p.backoffMax = 5*time.Millisecond, 20*time.Millisecond
	h.state = p.State
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go p.Run(ctx)
	p.Offer([]byte("spec"))
	waitFor(t, "six calls", func() bool { return len(h.got()) >= 6 })
	calls := h.got()
	// Each call sees the failure that the call before it ended with, and the first success is the fifth call.
	for i, want := range []string{"", mgmtapi.ReasonHostsvcBusy, mgmtapi.ReasonHostsvcUnavailable, mgmtapi.ReasonHostsvcBusy, mgmtapi.ReasonHostsvcBusy, ""} {
		if calls[i].failure != want || calls[i].pushedAt.IsZero() != (i < 5) {
			t.Errorf("call %d saw failure %q pushedAt %v, want failure %q and pushedAt set only from call 6", i+1, calls[i].failure, calls[i].pushedAt, want)
		}
	}
	// The gaps after a failure are at least 5, 10, 20 and 20 ms: the back-off doubles up to its maximum.
	for i, min := range []time.Duration{5, 10, 20, 20} {
		if gap := calls[i+1].at.Sub(calls[i].at); gap < min*time.Millisecond {
			t.Errorf("gap after failure %d is %v, want at least %v", i+1, gap, min*time.Millisecond)
		}
	}
	// A success clears the error, sets the time, and the same spec goes out again on the repeat timer.
	for i, c := range calls[:6] {
		if string(c.env) != "spec" {
			t.Fatalf("call %d pushed %q", i, c.env)
		}
	}
	if at, msg := p.State(); at.IsZero() || msg != "" {
		t.Fatalf("state after the success: %v %q", at, msg)
	}
	if gap := calls[5].at.Sub(calls[4].at); gap < 40*time.Millisecond {
		t.Errorf("repeat after a success came after %v, want at least the 40ms interval", gap)
	}
}

func TestSpecPusherNewOfferDuringBackoffPushesAtOnce(t *testing.T) {
	h := &fakeHost{errs: []error{&mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}}}
	p := NewSpecPusher(h, time.Hour, discardLog())
	p.backoffMin, p.backoffMax = time.Hour, time.Hour
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go p.Run(ctx)
	p.Offer([]byte("old"))
	waitFor(t, "the failure", func() bool { _, msg := p.State(); return msg != "" })
	p.Offer([]byte("new"))
	waitFor(t, "the push of the new spec", func() bool { return len(h.got()) >= 2 })
	if string(h.got()[1].env) != "new" {
		t.Fatalf("pushed %q", h.got()[1].env)
	}
}

func TestSpecPusherPushesNothingBeforeAnOffer(t *testing.T) {
	h := &fakeHost{}
	startPusher(t, h, 5*time.Millisecond)
	time.Sleep(40 * time.Millisecond)
	if n := len(h.got()); n != 0 {
		t.Fatalf("%d pushes with nothing offered", n)
	}
}

func TestSpecPusherAgeGauge(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	var meter metric.Meter = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	h := &fakeHost{}
	base := time.Now()
	var offset atomic.Int64
	clock := func() time.Time { return base.Add(time.Duration(offset.Load())) }
	p := NewSpecPusher(h, time.Hour, discardLog())
	p.now = clock
	p.started = clock()
	if err := p.Observe(meter); err != nil {
		t.Fatal(err)
	}
	age := func() (int64, bool) {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if g, ok := m.Data.(metricdata.Gauge[int64]); ok && m.Name == "mgmtd.hostsvc.spec_push_age" && len(g.DataPoints) == 1 {
					return g.DataPoints[0].Value, true
				}
			}
		}
		return 0, false
	}
	offset.Store(int64(90 * time.Second))
	if v, ok := age(); !ok || v != 90 {
		t.Fatalf("age before any push: %d %v, want 90 (time since start)", v, ok)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go p.Run(ctx)
	p.Offer([]byte("x"))
	waitFor(t, "the push", func() bool { at, _ := p.State(); return !at.IsZero() })
	offset.Add(int64(7 * time.Second))
	if v, ok := age(); !ok || v < 7 || v > 8 {
		t.Fatalf("age after a push: %d %v, want about 7", v, ok)
	}
}
