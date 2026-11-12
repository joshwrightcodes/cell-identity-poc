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
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/net/http2"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
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
// Meter records nothing, and a nil Now or Sleep uses the real clock.
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
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
}

// Puller pulls the bundle of one environment in rounds, accepts it, saves it and reports.
type Puller struct {
	cfg      PullerConfig
	ready    atomic.Bool
	state    *State
	refusal  *mgmtapi.Refusal
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
		cfg.Meter = noop.NewMeterProvider().Meter("envd")
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

// Run loads the state, then pulls until ctx ends. It returns ctx.Err().
func (p *Puller) Run(ctx context.Context) error {
	failures := 0
	for p.state == nil {
		st, err := p.cfg.Store.Load(ctx)
		if err == nil {
			p.state = st
			p.updateGauge(ctx)
			p.ready.Store(true)
			break
		}
		failures++
		p.logLimited("load failed", "load", "error", err.Error())
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

// backoff returns the wait after n consecutive failures, from MinBackoff doubling up to MaxBackoff,
// with jitter that takes off up to half.
func (p *Puller) backoff(n int) time.Duration {
	d := p.cfg.MinBackoff
	for i := 1; i < n && d < p.cfg.MaxBackoff; i++ {
		d *= 2
	}
	d = min(d, p.cfg.MaxBackoff)
	return d/2 + rand.N(d/2+1)
}

// round runs one pull and reports whether it failed in a way that calls for a backoff.
func (p *Puller) round(ctx context.Context) (failed bool) {
	rctx, cancel := context.WithTimeout(ctx, p.cfg.RoundTimeout)
	defer cancel()
	bundle, err := p.fetch(rctx)
	if err != nil {
		p.logLimited("pull failed", "pull", "error", err.Error())
		return true
	}
	next, changed, err := Accept(p.state, bundle, p.cfg.Env, p.cfg.Keys)
	var refused *Refused
	switch {
	case errors.As(err, &refused):
		p.refuse(ctx, refused)
	case err != nil:
		p.logLimited("accept failed", "accept", "error", err.Error())
		failed = true
	case changed:
		if err := p.cfg.Store.Save(rctx, next); err != nil {
			p.storeErr = mgmtapi.ReasonStoreFailed
			p.logLimited("save failed", "save", "error", err.Error())
			failed = true
		} else {
			p.state = next
			p.storeErr = ""
			p.updateGauge(ctx)
			p.cfg.Log.Info("spec applied", "epoch", next.Revision.Epoch, "counter", next.Revision.Counter, "cells", len(next.Cells))
		}
	default:
		p.storeErr = ""
	}
	p.report(ctx)
	return failed
}

func (p *Puller) updateGauge(ctx context.Context) {
	p.counter.Record(ctx, int64(p.state.Revision.Counter))
}

// refuse records the refusal, counts it, and logs it once for each revision and reason in each window.
func (p *Puller) refuse(ctx context.Context, r *Refused) {
	p.refusals.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", r.Reason)))
	p.refusal = &mgmtapi.Refusal{Reason: r.Reason, Revision: r.Revision, At: p.cfg.Now().UTC()}
	key := fmt.Sprintf("refusal/%s/%d.%d", r.Reason, r.Revision.Epoch, r.Revision.Counter)
	_, ok, suppressed, held := p.logs.Allow(key)
	for _, h := range held {
		p.cfg.Log.Warn("log lines held back", "key", h.Key, "suppressed", h.Suppressed)
	}
	if ok {
		p.cfg.Log.Warn("spec refused", "reason", r.Reason, "cell", r.Cell, "epoch", r.Revision.Epoch,
			"counter", r.Revision.Counter, "detail", r.Detail, "suppressed", suppressed)
	}
}

// logLimited logs a failure once for each key in each window.
func (p *Puller) logLimited(msg, key string, args ...any) {
	_, ok, suppressed, held := p.logs.Allow(key)
	for _, h := range held {
		p.cfg.Log.Warn("log lines held back", "key", h.Key, "suppressed", h.Suppressed)
	}
	if ok {
		p.cfg.Log.Warn(msg, append(args, "suppressed", suppressed)...)
	}
}

func (p *Puller) fetch(ctx context.Context) (mgmtapi.SpecBundle, error) {
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
func (p *Puller) report(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, p.cfg.RoundTimeout)
	defer cancel()
	body, err := json.Marshal(mgmtapi.StatusReport{Applied: p.state.Revision, LastRefusal: p.refusal, StoreError: p.storeErr})
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
		p.logLimited("status report failed", "report", "error", err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		p.logLimited("status report refused", "report", "status", resp.StatusCode)
	}
}
