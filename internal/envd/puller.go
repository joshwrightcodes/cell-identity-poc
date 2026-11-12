package envd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/net/http2"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	// MaxBodyBytes is the largest spec bundle that the puller reads.
	MaxBodyBytes = 1 << 20
	// RefusalLogWindow is how long an unchanged refusal stays silent in the log.
	RefusalLogWindow = 5 * time.Minute

	defaultInterval     = 10 * time.Second
	defaultMinBackoff   = time.Second
	defaultMaxBackoff   = 30 * time.Second
	defaultRoundTimeout = 15 * time.Second
	readIdleTimeout     = 15 * time.Second
	pingTimeout         = 10 * time.Second
	maxLogKeys          = 64
)

// NewClient returns an HTTP/2 client that dials with tlsCfg. The transport pings an idle connection
// after 15 s and drops it when the peer does not answer within 10 s.
func NewClient(tlsCfg *tls.Config) *http.Client {
	return &http.Client{Transport: &http2.Transport{
		TLSClientConfig: tlsCfg,
		ReadIdleTimeout: readIdleTimeout,
		PingTimeout:     pingTimeout,
	}}
}

// PullerConfig holds what a Puller needs. Zero durations take the defaults of the envd timers, a nil
// Meter or Tracer records nothing, and a nil Now or Sleep uses the real clock.
type PullerConfig struct {
	Client       *http.Client
	BaseURL, Env string
	Keys         []ed25519.PublicKey
	Store        Store
	Interval     time.Duration
	MinBackoff   time.Duration
	MaxBackoff   time.Duration
	RoundTimeout time.Duration
	Log          *slog.Logger
	Meter        metric.Meter
	Tracer       trace.Tracer
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
}

// Puller pulls the bundle of one environment in rounds, accepts it, saves it and reports.
type Puller struct {
	cfg      PullerConfig
	ready    atomic.Bool
	state    *State
	applied  spec.Revision
	refusal  *mgmtapi.Refusal
	lastPair string
	pairGen  int
	storeErr string
	logs     *lograte.Limiter
	counter  metric.Int64Gauge
	refusals metric.Int64Counter
}

// NewPuller returns a Puller for cfg.
func NewPuller(cfg PullerConfig) *Puller {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = defaultMinBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.RoundTimeout <= 0 {
		cfg.RoundTimeout = defaultRoundTimeout
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Meter == nil {
		cfg.Meter = noopmetric.NewMeterProvider().Meter("envd")
	}
	if cfg.Tracer == nil {
		cfg.Tracer = nooptrace.NewTracerProvider().Tracer("envd")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	p := &Puller{cfg: cfg, logs: lograte.New(RefusalLogWindow, maxLogKeys, cfg.Now)}
	// The instrument names are valid, so creation cannot fail. A failure leaves a no-op instrument.
	p.counter, _ = cfg.Meter.Int64Gauge("envd.spec.counter",
		metric.WithDescription("Counter of the last saved spec revision"))
	p.refusals, _ = cfg.Meter.Int64Counter("envd.spec.refusals",
		metric.WithDescription("Rounds in which envd refused the bundle"))
	return p
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Ready reports whether the puller has loaded its state. It does not depend on the management plane.
func (p *Puller) Ready() bool { return p.ready.Load() }

// HealthHandler answers 200 once p is Ready and 503 before.
func HealthHandler(p *Puller) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !p.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
}

// Run loads the state, then pulls until ctx ends. It returns ctx.Err(). While the stored state does
// not verify, Run pulls nothing, stays not Ready, and reports state_unverifiable.
func (p *Puller) Run(ctx context.Context) error {
	failures := 0
	for p.state == nil {
		lctx, cancel := context.WithTimeout(ctx, p.cfg.RoundTimeout)
		st, err := p.cfg.Store.Load(lctx)
		cancel()
		if err == nil {
			p.state = st
			p.setApplied(ctx, st.Revision)
			p.ready.Store(true)
			break
		}
		failures++
		p.logLimited(ctx, "load failed", "load", "error", clip(err.Error()))
		if errors.Is(err, ErrStateUnverifiable) {
			p.report(ctx, mgmtapi.StatusReport{StoreError: mgmtapi.ReasonStateUnverifiable})
		}
		if err := p.cfg.Sleep(ctx, p.backoff(failures)); err != nil {
			return err
		}
	}
	failures = 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := p.cfg.Interval
		if p.round(ctx) {
			failures++
			wait = p.backoff(failures)
		} else {
			failures = 0
		}
		p.cfg.Client.CloseIdleConnections()
		if err := p.cfg.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// backoff returns the wait after n consecutive failures: from MinBackoff, doubling up to MaxBackoff,
// plus jitter of up to the same amount again, never above MaxBackoff.
func (p *Puller) backoff(n int) time.Duration {
	d := p.cfg.MinBackoff
	for i := 1; i < n && d < p.cfg.MaxBackoff; i++ {
		d *= 2
	}
	d = min(d, p.cfg.MaxBackoff)
	hi := min(2*d, p.cfg.MaxBackoff)
	return d + rand.N(hi-d+1)
}

func (p *Puller) setApplied(ctx context.Context, r spec.Revision) {
	p.applied = r
	p.counter.Record(ctx, int64(r.Counter))
}

// fail marks the span of a step as failed.
func fail(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, clip(err.Error()))
}

// round runs one pull and reports whether it failed in a way that calls for a backoff.
func (p *Puller) round(ctx context.Context) (failed bool) {
	ctx, span := p.cfg.Tracer.Start(ctx, "envd.round")
	defer span.End()
	rctx, cancel := context.WithTimeout(ctx, p.cfg.RoundTimeout)
	defer cancel()
	p.storeErr = ""
	p.syncStore(rctx)

	bundle, err := p.fetch(rctx)
	if err != nil {
		fail(span, err)
		p.logLimited(ctx, "pull failed", "pull", "error", clip(err.Error()))
		return true
	}
	_, acceptSpan := p.cfg.Tracer.Start(rctx, "envd.accept")
	next, changed, err := Accept(p.state, bundle, p.cfg.Env, p.cfg.Keys)
	var refused *Refused
	switch {
	case errors.As(err, &refused):
		acceptSpan.SetAttributes(attribute.String("reason", refused.Reason))
		fail(acceptSpan, err)
		p.refuse(ctx, refused)
	case err != nil:
		fail(acceptSpan, err)
		p.logLimited(ctx, "accept failed", "accept", "error", clip(err.Error()))
		failed = true
	case changed:
		sctx, saveSpan := p.cfg.Tracer.Start(rctx, "envd.save")
		if err := p.cfg.Store.Save(sctx, next); err != nil {
			fail(saveSpan, err)
			p.storeErr = mgmtapi.ReasonStoreFailed
			p.logLimited(ctx, "save failed", "save", "error", clip(err.Error()))
		} else {
			p.state = next
			p.refusal = nil
			p.lastPair = ""
			p.setApplied(ctx, next.Revision)
			p.cfg.Log.InfoContext(ctx, "spec applied", "epoch", next.Revision.Epoch, "counter", next.Revision.Counter, "cells", len(next.Cells))
		}
		saveSpan.End()
	default:
		p.refusal = nil
		p.lastPair = ""
	}
	acceptSpan.End()
	if p.storeErr != "" {
		failed = true
	}
	p.report(ctx, mgmtapi.StatusReport{Applied: p.applied, LastRefusal: p.refusal, StoreError: p.storeErr})
	return failed
}

// sameContent reports whether two states hold the same signed spec and records.
func sameContent(a, b *State) bool {
	if a.SpecSHA256 != b.SpecSHA256 || len(a.Records) != len(b.Records) {
		return false
	}
	for k, v := range a.Records {
		if w, ok := b.Records[k]; !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

// syncStore compares the store with the accepted state. A higher verified stored revision, for
// example from a save whose answer was lost, becomes the accepted state. Any other difference,
// including extra keys and a state that does not verify, is rewritten from the accepted state.
// Applied is the revision that the store holds.
func (p *Puller) syncStore(ctx context.Context) {
	ctx, span := p.cfg.Tracer.Start(ctx, "envd.sync")
	defer span.End()
	live, clean, err := p.cfg.Store.Peek(ctx)
	switch {
	case errors.Is(err, ErrStateUnverifiable):
		live, clean = Empty(), false
	case err != nil:
		fail(span, err)
		p.storeErr = mgmtapi.ReasonStoreFailed
		p.logLimited(ctx, "store read failed", "peek", "error", clip(err.Error()))
		return
	}
	if live.Revision.Compare(p.state.Revision) > 0 {
		for k, v := range p.state.Marks {
			if v.Compare(live.Marks[k]) > 0 {
				live.Marks[k] = v
			}
		}
		p.cfg.Log.WarnContext(ctx, "state_adopted", "epoch", live.Revision.Epoch, "counter", live.Revision.Counter)
		p.state = live
	}
	if clean && sameContent(live, p.state) {
		p.setApplied(ctx, live.Revision)
		return
	}
	p.setApplied(ctx, live.Revision)
	p.cfg.Log.WarnContext(ctx, "state_drift", "stored_epoch", live.Revision.Epoch, "stored_counter", live.Revision.Counter,
		"epoch", p.state.Revision.Epoch, "counter", p.state.Revision.Counter, "clean", clean)
	if err := p.cfg.Store.Save(ctx, p.state); err != nil {
		fail(span, err)
		p.storeErr = mgmtapi.ReasonStoreFailed
		p.logLimited(ctx, "save failed", "save", "error", clip(err.Error()))
		return
	}
	p.setApplied(ctx, p.state.Revision)
}

// refuse records the refusal, counts it, and logs it when its reason or revision differs from the
// last refusal, and again once in each window for the same one.
func (p *Puller) refuse(ctx context.Context, r *Refused) {
	p.refusals.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", r.Reason)))
	p.refusal = &mgmtapi.Refusal{Reason: r.Reason, Revision: r.Revision, At: p.cfg.Now().UTC()}
	pair := fmt.Sprintf("%s/%d.%d", r.Reason, r.Revision.Epoch, r.Revision.Counter)
	if pair != p.lastPair {
		p.lastPair = pair
		p.pairGen++
	}
	_, ok, suppressed, held := p.logs.Allow(fmt.Sprintf("refusal/%d/%s", p.pairGen, pair))
	for _, h := range held {
		p.cfg.Log.WarnContext(ctx, "log lines held back", "key", h.Key, "suppressed", h.Suppressed)
	}
	if ok {
		p.cfg.Log.WarnContext(ctx, "spec refused", "reason", r.Reason, "cell", r.Cell, "epoch", r.Revision.Epoch,
			"counter", r.Revision.Counter, "detail", r.Detail, "suppressed", suppressed)
	}
}

// logLimited logs a failure once for each key in each window.
func (p *Puller) logLimited(ctx context.Context, msg, key string, args ...any) {
	_, ok, suppressed, held := p.logs.Allow(key)
	for _, h := range held {
		p.cfg.Log.WarnContext(ctx, "log lines held back", "key", h.Key, "suppressed", h.Suppressed)
	}
	if ok {
		p.cfg.Log.WarnContext(ctx, msg, append(args, "suppressed", suppressed)...)
	}
}

func (p *Puller) fetch(ctx context.Context) (mgmtapi.SpecBundle, error) {
	ctx, span := p.cfg.Tracer.Start(ctx, "envd.fetch")
	defer span.End()
	b, err := p.get(ctx)
	if err != nil {
		fail(span, err)
	}
	return b, err
}

func (p *Puller) get(ctx context.Context) (mgmtapi.SpecBundle, error) {
	var b mgmtapi.SpecBundle
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.BaseURL+mgmtapi.SpecPath(p.cfg.Env), nil)
	if err != nil {
		return b, err
	}
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		return b, fmt.Errorf("get spec: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return b, fmt.Errorf("get spec: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return b, fmt.Errorf("read spec: %w", err)
	}
	if len(body) > MaxBodyBytes {
		return b, fmt.Errorf("spec body is larger than %d bytes", MaxBodyBytes)
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return b, fmt.Errorf("decode spec bundle: %w", err)
	}
	return b, nil
}

// report tells the management plane what envd has applied. It runs under its own deadline, and a
// failure only reaches the log.
func (p *Puller) report(ctx context.Context, rep mgmtapi.StatusReport) {
	ctx, span := p.cfg.Tracer.Start(ctx, "envd.report")
	defer span.End()
	rctx, cancel := context.WithTimeout(ctx, p.cfg.RoundTimeout)
	defer cancel()
	body, err := json.Marshal(rep)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, p.cfg.BaseURL+mgmtapi.StatusPath(p.cfg.Env), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// The report ends the round. Close marks the connection for single use, so the next round dials
	// again and shakes hands with the current SVID.
	req.Close = true
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		fail(span, err)
		p.logLimited(ctx, "status report failed", "report", "error", clip(err.Error()))
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		p.logLimited(ctx, "status report refused", "report", "status", resp.StatusCode)
	}
}
