package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/net/http2"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

// Defaults of StreamConfig.
const (
	DefaultMinBackoff      = time.Second
	DefaultMaxBackoff      = 30 * time.Second
	DefaultClaimEvery      = 10 * time.Second
	DefaultStatusEvery     = 30 * time.Second
	DefaultResendEvery     = 60 * time.Second
	DefaultAckTimeout      = 30 * time.Second
	DefaultPongTimeout     = 30 * time.Second
	DefaultClaimsPerSecond = 5.0

	dialTimeout     = 10 * time.Second
	welcomeTimeout  = 10 * time.Second
	readIdleTimeout = 15 * time.Second
	h2PingTimeout   = 10 * time.Second
	pingEvery       = 10 * time.Second
	forgedEvery     = 10 * time.Second
	gcEvery         = time.Hour
	statusSpread    = 0.2
	backoffSpread   = 0.5
	kubeTimeout     = 5 * time.Second
	minResendGap    = 30 * time.Second
	maxResendBurst  = 20
)

// StreamConfig holds the settings of RunStream. A zero duration, ClaimsPerSecond, Log, Tracer, Now,
// Sleep or Rand takes its default. Tracer starts the span of each stream, so the log lines of the
// stream carry trace_id.
type StreamConfig struct {
	Cell, Upstream string
	// TLS returns the client settings for a new connection, and an error while the cell holds no SVID.
	TLS func() (*tls.Config, error)
	// SVIDUpdates receives a value for each new SVID. Each value ends the stream, and a new one starts.
	SVIDUpdates <-chan struct{}
	Tokens      satoken.TokenFunc
	Exec        *Executor
	// EffectCtx is the context of each Execute call. A nil value takes the context of RunStream. A
	// caller can pass a context that ends a few seconds after the one of RunStream, so that an
	// effect that runs at shutdown has time to finish.
	EffectCtx context.Context
	Status    func() op.Status

	MinBackoff, MaxBackoff, ClaimEvery, StatusEvery, ResendEvery, AckTimeout, PongTimeout time.Duration
	ClaimsPerSecond                                                                       float64

	Log    *slog.Logger
	Tracer trace.Tracer
	Now    func() time.Time
	Sleep  func(context.Context, time.Duration) error
	Rand   func() float64

	resent *resendLog
	// status holds the next status deadline across streams. A stream ends about every half life of the SVID, which can be shorter than
	// StatusEvery, so a deadline that restarted with each stream would never fire.
	status *statusClock
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	// pingEvery is the application ping interval of a test. Zero takes the 10 s default.
	pingEvery time.Duration
}

// StreamTLS returns the TLS settings function for StreamConfig: mutual TLS 1.3 with the current SVID,
// where the server must hold the SPIFFE ID gateway and a certificate from bundle. It fails while svid
// holds no SVID.
func StreamTLS(svid x509svid.Source, bundle x509bundle.Source, gateway spiffeid.ID) func() (*tls.Config, error) {
	return func() (*tls.Config, error) {
		if _, err := svid.GetX509SVID(); err != nil {
			return nil, fmt.Errorf("no SVID: %w", err)
		}
		return cellproxy.ClientTLS(svid, bundle, gateway), nil
	}
}

func (c StreamConfig) withDefaults() (StreamConfig, error) {
	switch {
	case c.Cell == "":
		return c, errors.New("stream: Cell is required")
	case c.Upstream == "":
		return c, errors.New("stream: Upstream is required")
	case c.TLS == nil:
		return c, errors.New("stream: TLS is required")
	case c.Tokens == nil:
		return c, errors.New("stream: Tokens is required")
	case c.Exec == nil:
		return c, errors.New("stream: Exec is required")
	case c.Status == nil:
		return c, errors.New("stream: Status is required")
	}
	for _, d := range []struct {
		v   *time.Duration
		def time.Duration
	}{
		{&c.MinBackoff, DefaultMinBackoff}, {&c.MaxBackoff, DefaultMaxBackoff}, {&c.ClaimEvery, DefaultClaimEvery},
		{&c.StatusEvery, DefaultStatusEvery}, {&c.ResendEvery, DefaultResendEvery}, {&c.AckTimeout, DefaultAckTimeout},
		{&c.PongTimeout, DefaultPongTimeout}, {&c.pingEvery, pingEvery},
	} {
		if *d.v <= 0 {
			*d.v = d.def
		}
	}
	if c.MaxBackoff < c.MinBackoff {
		c.MaxBackoff = c.MinBackoff
	}
	if c.ClaimsPerSecond <= 0 {
		c.ClaimsPerSecond = DefaultClaimsPerSecond
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.Tracer == nil {
		c.Tracer = noop.NewTracerProvider().Tracer("celld")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = sleepTimer
	}
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
	if c.status == nil {
		c.status = &statusClock{}
	}
	if c.resent == nil {
		c.resent = &resendLog{last: map[string]time.Time{}}
	}
	if c.dial == nil {
		c.dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	return c, nil
}

func sleepTimer(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var errSVIDUpdate = errors.New("a new SVID arrived")

// RunStream keeps one stream to the cell gateway open, claims work on it, runs each lease through the
// executor and reports the results. A failed stream is opened again after a jittered backoff, and a
// new SVID opens a new stream at once. It returns only when ctx ends, or at once when cfg is invalid.
func RunStream(ctx context.Context, cfg StreamConfig) error {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return err
	}
	gcCtx, stopGC := context.WithCancel(ctx)
	var gc sync.WaitGroup
	gc.Add(1)
	go func() { defer gc.Done(); cfg.runGC(gcCtx) }()
	defer func() { stopGC(); gc.Wait() }()

	for failures := 0; ; {
		drain(cfg.SVIDUpdates)
		start := cfg.Now()
		err := cfg.runOne(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, errSVIDUpdate) {
			cfg.Log.InfoContext(ctx, "stream restarts for a new SVID")
			failures = 0
			continue
		}
		if cfg.Now().Sub(start) >= cfg.MaxBackoff {
			failures = 0
		}
		wait := cfg.backoff(failures)
		failures++
		cfg.Log.WarnContext(ctx, "stream ended", "cell", cfg.Cell, "error", err.Error(), "reason", string(cellproxy.TLSReason(err)), "retry_in", wait.String())
		if err := cfg.wait(ctx, wait); err != nil {
			return err
		}
	}
}

func drain(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// wait sleeps for d. A new SVID ends the wait early.
func (c StreamConfig) wait(ctx context.Context, d time.Duration) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var updated atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-c.SVIDUpdates:
			updated.Store(true)
			cancel()
		case <-wctx.Done():
		}
	}()
	err := c.Sleep(wctx, d)
	cancel()
	<-done
	if updated.Load() && ctx.Err() == nil {
		return nil
	}
	return err
}

// backoff returns MinBackoff doubled for each earlier failure up to MaxBackoff, with jitter. Below
// the cap the wait lies between d and 1.5 d. At the cap it lies between two thirds of MaxBackoff and
// MaxBackoff, so a long outage keeps its jitter.
func (c StreamConfig) backoff(failures int) time.Duration {
	d := c.MinBackoff
	for i := 0; i < failures && d < c.MaxBackoff; i++ {
		d *= 2
	}
	d = min(d, c.MaxBackoff)
	high := min(time.Duration(float64(d)*(1+backoffSpread)), c.MaxBackoff)
	low := min(d, high*2/3)
	return low + time.Duration(c.Rand()*float64(high-low))
}

func (c StreamConfig) runGC(ctx context.Context) {
	t := time.NewTicker(gcEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Exec.GC(ctx); err != nil && ctx.Err() == nil {
				c.Log.WarnContext(ctx, "record cleanup failed", "error", err.Error())
			}
		}
	}
}

// lastFence returns the highest fence in the operation records. It skips a fence whose epoch is above
// the bound of the gateway, because the gateway refuses a hello that reports one.
func (e *Executor) lastFence(ctx context.Context) (op.Fence, error) {
	items, err := e.list(ctx)
	if err != nil {
		return op.Fence{}, err
	}
	limit := uint64(e.cfg.Now().Unix()) + op.MaxFenceAhead
	var last op.Fence
	for i := range items {
		rec, err := decodeRecord(&items[i])
		if err == nil && rec.Fence.Epoch <= limit && rec.Fence.Compare(last) > 0 {
			last = rec.Fence
		}
	}
	return last, nil
}

// runOne opens one stream and serves it until it ends.
func (c StreamConfig) runOne(ctx context.Context) (err error) {
	tlsCfg, err := c.TLS()
	if err != nil {
		return fmt.Errorf("TLS settings: %w", err)
	}
	ctx, span := c.Tracer.Start(ctx, "celld.stream")
	defer func() {
		if err != nil && !errors.Is(err, errSVIDUpdate) {
			span.RecordError(err)
			span.SetStatus(codes.Error, "stream ended")
		}
		span.End()
	}()

	dctx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	raw, err := c.dial(dctx, "tcp", c.Upstream)
	if err != nil {
		cancelDial()
		return fmt.Errorf("dial: %w", err)
	}
	conn := tls.Client(raw, tlsCfg)
	err = conn.HandshakeContext(dctx)
	cancelDial()
	if err != nil {
		_ = raw.Close()
		return fmt.Errorf("TLS handshake: %w", err)
	}
	defer func() { _ = conn.Close() }()

	binding, err := proof.Binding(conn.ConnectionState())
	if err != nil {
		return err
	}
	token, err := c.Tokens(ctx, proof.HelloAudience(c.Cell, binding))
	if err != nil {
		return fmt.Errorf("mint the hello token: %w", err)
	}
	kctx, kcancel := context.WithTimeout(ctx, kubeTimeout)
	last, err := c.Exec.lastFence(kctx)
	kcancel()
	if err != nil {
		return fmt.Errorf("read the records: %w", err)
	}

	cc, err := (&http2.Transport{ReadIdleTimeout: readIdleTimeout, PingTimeout: h2PingTimeout}).NewClientConn(conn)
	if err != nil {
		return fmt.Errorf("HTTP/2 connection: %w", err)
	}
	defer func() { _ = cc.Close() }()

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close(); _ = pr.Close() }()
	req, err := http.NewRequestWithContext(sctx, http.MethodPost, "https://"+c.Upstream+gwapi.StreamPath(c.Cell), pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	welcomeTimer := time.AfterFunc(welcomeTimeout, cancel)
	defer welcomeTimer.Stop()
	go func() {
		if err := gwapi.Encode(pw, gwapi.Frame{Type: gwapi.TypeHello, Token: token, LastFence: last}); err != nil {
			_ = pw.CloseWithError(err)
		}
	}()
	resp, err := telemetry.Transport(cc).RoundTrip(req)
	if err != nil {
		return fmt.Errorf("open the stream: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the gateway answered HTTP %d", resp.StatusCode)
	}
	dec := gwapi.NewDecoder(resp.Body)
	welcome, err := dec.Decode()
	if err != nil {
		return fmt.Errorf("wait for the welcome: %w", err)
	}
	switch welcome.Type {
	case gwapi.TypeWelcome:
	case gwapi.TypeRefused:
		return fmt.Errorf("the gateway refused the stream: %s", welcome.Reason)
	default:
		return fmt.Errorf("the gateway sent %q, want welcome", welcome.Type)
	}
	welcomeTimer.Stop()
	c.Log.InfoContext(ctx, "stream open", "cell", c.Cell, "pod", welcome.Pod, "cap", welcome.Cap)

	l := newLoop(c, sctx, pw, dec)
	err = l.run(ctx)
	cancel()
	_ = pw.Close()
	_ = resp.Body.Close()
	l.finish()
	return err
}

// resendLog keeps when each result went up again, so that no op goes more than once in minResendGap,
// whatever opens or retries the streams.
type resendLog struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (r *resendLog) allow(opID string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.last[opID]; ok && now.Sub(t) < minResendGap {
		return false
	}
	r.last[opID] = now
	return true
}

func (r *resendLog) forget(opID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.last, opID)
}

// statusClock keeps the time of the next status for all streams of one StreamConfig.
type statusClock struct {
	mu   sync.Mutex
	next time.Time
}

// get returns the next deadline, or the zero time before the first status.
func (s *statusClock) get() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

func (s *statusClock) set(t time.Time) {
	s.mu.Lock()
	s.next = t
	s.mu.Unlock()
}
