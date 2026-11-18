package cellctl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// The defaults of Config.
const (
	DefaultInterval   = 10 * time.Second
	DefaultPollEvery  = 10 * time.Second
	DefaultHeartbeat  = 30 * time.Second
	DefaultMinBackoff = time.Second
	DefaultMaxBackoff = 30 * time.Second

	// minWake is the shortest sleep of Run, so that a due item that cannot run yet never spins.
	minWake = 50 * time.Millisecond
	// maxAttemptsAtHost is the attempt limit of the host service. A failed step at the limit is final.
	maxAttemptsAtHost = 3
)

// HostClient is the part of the host service that the controller uses. The errors are
// *mgmtapi.HostError.
type HostClient interface {
	Put(ctx context.Context, id string, envelope []byte) (mgmtapi.StepStatus, error)
	Get(ctx context.Context, id string) (mgmtapi.StepStatus, error)
}

// Config configures a Controller. Zero timers take the defaults of this package.
type Config struct {
	Env        string
	Namespace  string
	StepsName  string
	StatusName string
	Client     kubernetes.Interface
	// Keys returns the trusted spec keys. It is called at each read.
	Keys func() []ed25519.PublicKey
	Host HostClient

	// Interval is the time between reads of the steps ConfigMap. PollEvery is the time between
	// polls of one started step. Heartbeat is the longest time between two writes of the status.
	Interval, PollEvery, Heartbeat time.Duration
	// MinBackoff and MaxBackoff bound the wait after a failed call of the host service.
	MinBackoff, MaxBackoff time.Duration

	Now   func() time.Time
	Sleep func(context.Context, time.Duration) error
	// Rand returns a number in [0, 1) for the jitter.
	Rand  func() float64
	Log   *slog.Logger
	Meter metric.Meter
}

// Controller loads the signed steps, sends them to the host service one call at a time and reports
// their progress.
type Controller struct {
	cfg    Config
	store  *statusStore
	ready  atomic.Bool
	steps  metric.Int64Counter
	refuse metric.Int64Counter

	// The revision mark and the last index live in memory only. After a restart the host service,
	// with its own spec mark and index checks, is the backstop.
	entries   map[string]*entry
	mark      spec.Revision
	lastIndex map[string]string // step ID to cell, from the last spec that verified
	specLog   string            // digest of the last refused spec that was logged
	logged    map[string]bool

	nextRead     time.Time
	blockedUntil time.Time // no host call at all: the host service is unavailable or untrusted
	// putBlockedUntil holds back Puts only, after a busy answer. Polls go on.
	putBlockedUntil time.Time
	failures        int
	lastWrite       time.Time
	lastWritten     []byte
	writeRetry      time.Time
}

// entry is what the controller knows about one step ID.
type entry struct {
	id, cell string
	issuedAt time.Time
	firstAt  time.Time

	cur     *Verified           // the step as verified at the last read, nil when it left the spec
	refusal *mgmtapi.StepStatus // the refusal of the last read
	status  *mgmtapi.StepStatus // the last status from the host service
	putEnv  []byte              // the envelope of the last accepted Put
	denied  *denial             // set while the host service denies the step
	ended   bool                // the poll of a dropped step has ended
	lastErr *mgmtapi.HostErrorInfo
	polled  time.Time
	state   string // the last state that was counted
}

type denial struct {
	envelope  []byte
	requestID string
}

// New checks cfg and returns a Controller.
func New(cfg Config) (*Controller, error) {
	switch {
	case cfg.Env == "" || cfg.Namespace == "" || cfg.StepsName == "" || cfg.StatusName == "":
		return nil, errors.New("cell controller needs env, namespace and the two ConfigMap names")
	case cfg.Client == nil || cfg.Keys == nil || cfg.Host == nil:
		return nil, errors.New("cell controller needs a Kubernetes client, a key source and a host client")
	}
	setDefault := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	setDefault(&cfg.Interval, DefaultInterval)
	setDefault(&cfg.PollEvery, DefaultPollEvery)
	setDefault(&cfg.Heartbeat, DefaultHeartbeat)
	setDefault(&cfg.MinBackoff, DefaultMinBackoff)
	setDefault(&cfg.MaxBackoff, DefaultMaxBackoff)
	if cfg.MaxBackoff < cfg.MinBackoff {
		return nil, errors.New("cell controller: MaxBackoff is below MinBackoff")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Meter == nil {
		cfg.Meter = noop.NewMeterProvider().Meter("cellctl")
	}
	steps, err := cfg.Meter.Int64Counter("cellctl.steps", metric.WithDescription("step state changes seen by the cell controller"))
	if err != nil {
		return nil, fmt.Errorf("counter cellctl.steps: %w", err)
	}
	refuse, err := cfg.Meter.Int64Counter("cellctl.refusals", metric.WithDescription("refusals of steps and specs"))
	if err != nil {
		return nil, fmt.Errorf("counter cellctl.refusals: %w", err)
	}
	return &Controller{
		cfg: cfg, store: &statusStore{c: cfg.Client, namespace: cfg.Namespace, name: cfg.StatusName},
		steps: steps, refuse: refuse, entries: map[string]*entry{}, lastIndex: map[string]string{}, logged: map[string]bool{},
	}, nil
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

// Ready reports whether the controller has read the steps ConfigMap once. It does not depend on
// the host service.
func (c *Controller) Ready() bool { return c.ready.Load() }

// Run works until ctx ends and returns ctx.Err() or the error of Sleep.
func (c *Controller) Run(ctx context.Context) error {
	for {
		c.round(ctx)
		if err := c.cfg.Sleep(ctx, c.wait()); err != nil {
			return err
		}
	}
}

func (c *Controller) round(ctx context.Context) {
	c.prune()
	if now := c.cfg.Now(); !now.Before(c.nextRead) {
		c.read(ctx, now)
		c.nextRead = now.Add(c.cfg.Interval)
	}
	c.hostWork(ctx)
	c.report(ctx)
}

// prune forgets the steps whose work is over. A step that left the spec goes when its poll ended,
// the host service denied it, or it never reached the host service. A final step that left the
// spec stays in the report until the report is full, and then the oldest goes first.
func (c *Controller) prune() {
	for id, e := range c.entries {
		if e.cur != nil {
			continue
		}
		if e.denied != nil || e.ended || e.status == nil && e.refusal == nil {
			delete(c.entries, id)
		}
	}
	for len(c.entries) > MaxStatuses {
		var oldest *entry
		for _, e := range c.entries {
			if e.cur == nil && e.final() && (oldest == nil || e.issuedAt.Before(oldest.issuedAt)) {
				oldest = e
			}
		}
		if oldest == nil {
			return
		}
		delete(c.entries, oldest.id)
	}
}

func (e *entry) final() bool {
	if e.status == nil {
		return false
	}
	switch e.status.State {
	case mgmtapi.StepDone, mgmtapi.StepFailedFinal, mgmtapi.StepCancelled:
		return true
	}
	return false
}

// needsPut reports whether the step must go to the host service now: it is in the spec, nothing
// stops it, and the host service has no answer for these envelope bytes, or the step failed and
// its RetryAt has passed.
func (e *entry) needsPut(now time.Time) bool {
	if e.cur == nil || e.refusal != nil || e.final() {
		return false
	}
	if e.denied != nil {
		return false
	}
	if e.status == nil || !bytes.Equal(e.putEnv, e.cur.Envelope) {
		return true
	}
	return e.status.State == mgmtapi.StepFailed && e.status.Attempts < maxAttemptsAtHost && !now.Before(e.status.RetryAt)
}

// pollDue returns the time of the next poll, and false when the step needs none.
func (e *entry) pollDue(every time.Duration) (time.Time, bool) {
	if e.status == nil || e.final() || e.ended || e.denied != nil {
		return time.Time{}, false
	}
	return e.polled.Add(every), true
}

func (c *Controller) ordered() []*entry {
	out := make([]*entry, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.issuedAt.Equal(b.issuedAt) {
			return a.issuedAt.Before(b.issuedAt)
		}
		if a.cell != b.cell {
			return a.cell < b.cell
		}
		return a.id < b.id
	})
	return out
}

func (c *Controller) entry(id, cell string, now time.Time) *entry {
	e, ok := c.entries[id]
	if !ok {
		e = &entry{id: id, cell: cell, firstAt: now}
		c.entries[id] = e
	}
	return e
}

// read loads the steps ConfigMap and applies the result.
func (c *Controller) read(ctx context.Context, now time.Time) {
	cm, err := c.cfg.Client.CoreV1().ConfigMaps(c.cfg.Namespace).Get(ctx, c.cfg.StepsName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		c.ready.Store(true)
		c.accept(now, nil, c.mark, nil)
		return
	case err != nil:
		c.logOnce("read", "steps configmap not read", "error", err.Error())
		return
	}
	c.ready.Store(true)
	delete(c.logged, "read")
	verified, rev, refused := Load(cm.Data, c.cfg.Env, c.cfg.Keys(), c.mark, now)
	for _, r := range refused {
		if r.ID == "" {
			c.specRefused(now, cm.Data[SpecKey], r.Detail)
			return
		}
	}
	c.specLog = ""
	c.accept(now, verified, rev, refused)
}

// specRefused records the refusal of the spec. The step IDs of the last accepted index show it.
func (c *Controller) specRefused(now time.Time, envelope, detail string) {
	sum := sha256.Sum256([]byte(envelope + "\x00" + detail))
	digest := hex.EncodeToString(sum[:])
	if c.specLog != digest {
		c.specLog = digest
		c.cfg.Log.Warn("spec refused", "detail", detail, "spec_sha256", digest)
		c.refuse.Add(context.Background(), 1, metric.WithAttributes(attribute.String("detail", detail)))
	}
	for _, e := range c.entries {
		e.refusal = nil
	}
	for id, cell := range c.lastIndex {
		r := refusal(id, cell, detail)
		c.entry(id, cell, now).refusal = &r
	}
}

// accept applies a verified read.
func (c *Controller) accept(now time.Time, verified []Verified, rev spec.Revision, refused []mgmtapi.StepStatus) {
	if rev.Compare(c.mark) > 0 {
		c.mark = rev
	}
	c.lastIndex = map[string]string{}
	for _, e := range c.entries {
		e.cur, e.refusal = nil, nil
	}
	for i := range verified {
		v := verified[i]
		e := c.entry(v.Step.ID, v.Step.Cell, now)
		e.cur, e.issuedAt = &v, v.Step.IssuedAt
		c.lastIndex[v.Step.ID] = v.Step.Cell
		if e.denied != nil && !bytes.Equal(e.denied.envelope, v.Envelope) {
			e.denied = nil
		}
	}
	seen := map[string]bool{}
	for i := range refused {
		r := refused[i]
		e := c.entry(r.ID, r.Cell, now)
		e.refusal = &r
		c.lastIndex[r.ID] = r.Cell
		key := "refused:" + r.ID + ":" + r.Detail
		seen[key] = true
		if !c.logged[key] {
			c.logged[key] = true
			c.cfg.Log.Warn("step refused", "step", r.ID, "cell", r.Cell, "detail", r.Detail)
			c.refuse.Add(context.Background(), 1, metric.WithAttributes(attribute.String("detail", r.Detail)))
		}
	}
	for key := range c.logged {
		if len(key) > 8 && key[:8] == "refused:" && !seen[key] {
			delete(c.logged, key)
		}
	}
}

func (c *Controller) logOnce(key, msg string, args ...any) {
	if c.logged[key] {
		return
	}
	c.logged[key] = true
	c.cfg.Log.Warn(msg, args...)
}

// hostWork makes the calls that are due, one at a time and in the order of the steps. A busy or
// unavailable host service ends the work of the round.
func (c *Controller) hostWork(ctx context.Context) {
	for _, e := range c.ordered() {
		if ctx.Err() != nil {
			return
		}
		now := c.cfg.Now()
		if now.Before(c.blockedUntil) {
			return
		}
		if e.needsPut(now) && !now.Before(c.putBlockedUntil) && c.mayPut(e) {
			c.put(ctx, e)
			continue
		}
		if due, ok := e.pollDue(c.cfg.PollEvery); ok && !now.Before(due) {
			c.poll(ctx, e)
		}
	}
}

// mayPut holds a step that the host service has not seen while another step is open at the host
// service, so that the oldest step goes first and one step runs. A step that the host service
// knows, and a step that waits for its RetryAt, never hold anything back.
func (c *Controller) mayPut(e *entry) bool {
	if e.status != nil || e.putEnv != nil {
		return true
	}
	for _, x := range c.entries {
		if x != e && x.open() {
			return false
		}
	}
	return true
}

// open reports whether the host service holds the step in a state that queues or runs it.
func (e *entry) open() bool {
	if e.status == nil || e.ended || e.denied != nil {
		return false
	}
	switch e.status.State {
	case mgmtapi.StepQueued, mgmtapi.StepCreating, mgmtapi.StepAdmitting, mgmtapi.StepBootstrapping:
		return true
	}
	return false
}

// hostOK ends an outage: the failure count and every lastHostError go.
func (c *Controller) hostOK() {
	c.failures = 0
	for _, x := range c.entries {
		x.lastErr = nil
	}
}

func (c *Controller) put(ctx context.Context, e *entry) {
	env := e.cur.Envelope
	st, err := c.cfg.Host.Put(ctx, e.id, env)
	if err == nil && (st.ID != e.id || st.Cell != e.cell) {
		err = &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}
	}
	if err != nil {
		c.failed(e, "put", env, err)
		return
	}
	c.hostOK()
	e.denied, e.ended = nil, false
	e.putEnv = append([]byte(nil), env...)
	c.setStatus(e, st)
}

func (c *Controller) poll(ctx context.Context, e *entry) {
	st, err := c.cfg.Host.Get(ctx, e.id)
	if err == nil && (st.ID != e.id || st.Cell != e.cell) {
		err = &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}
	}
	if err != nil {
		c.failed(e, "get", nil, err)
		return
	}
	c.hostOK()
	c.setStatus(e, st)
}

func (c *Controller) setStatus(e *entry, st mgmtapi.StepStatus) {
	now := c.cfg.Now()
	st.LastHostError = nil
	e.status, e.polled = &st, now
	if e.state != st.State {
		c.cfg.Log.Info("step state", "step", e.id, "cell", e.cell, "state", st.State, "stage", st.Stage, "detail", st.Detail)
		c.steps.Add(context.Background(), 1, metric.WithAttributes(attribute.String("state", st.State)))
		e.state = st.State
	}
}

// failed applies a failed host call. Env is the envelope of a Put.
func (c *Controller) failed(e *entry, op string, env []byte, err error) {
	now := c.cfg.Now()
	var he *mgmtapi.HostError
	if !errors.As(err, &he) {
		he = &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}
	}
	mark := func(x *entry) {
		if x.lastErr == nil {
			x.lastErr = &mgmtapi.HostErrorInfo{Reason: he.Reason, At: now}
		} else {
			x.lastErr.Reason = he.Reason
		}
	}
	c.cfg.Log.Warn("host call failed", "op", op, "step", e.id, "reason", he.Reason, "status", he.Status, "request_id", he.RequestID)

	switch {
	case he.Reason == mgmtapi.ReasonHostsvcDenied && op == "get" && he.Status == 404:
		// The host service does not know the step.
		c.hostOK()
		if e.cur == nil {
			e.ended = true
			return
		}
		e.status, e.putEnv = nil, nil
		return
	case he.Reason == mgmtapi.ReasonHostsvcDenied:
		c.hostOK()
		mark(e)
		if env == nil && e.cur != nil {
			env = e.cur.Envelope
		}
		e.denied = &denial{envelope: append([]byte(nil), env...), requestID: he.RequestID}
		e.polled = now
		c.refuse.Add(context.Background(), 1, metric.WithAttributes(attribute.String("detail", mgmtapi.ReasonHostsvcDenied)))
		c.steps.Add(context.Background(), 1, metric.WithAttributes(attribute.String("state", mgmtapi.StepRefused)))
		return
	}
	for _, x := range c.entries {
		if !x.final() && x.denied == nil && (x.cur != nil || x.status != nil) {
			mark(x)
		}
	}
	if he.Reason == mgmtapi.ReasonHostsvcBusy {
		wait := he.RetryAfter
		if wait <= 0 {
			wait = c.cfg.MinBackoff
		}
		c.putBlockedUntil = now.Add(wait)
		e.polled = now
		return
	}
	c.blockedUntil = now.Add(c.backoff())
}

// backoff returns the wait after a failed call and counts the failure. It doubles from MinBackoff
// to MaxBackoff, and the jitter takes a random share of the upper half.
func (c *Controller) backoff() time.Duration {
	base := c.cfg.MinBackoff
	for range c.failures {
		base *= 2
		if base >= c.cfg.MaxBackoff {
			base = c.cfg.MaxBackoff
			break
		}
	}
	c.failures++
	d := base/2 + time.Duration(c.cfg.Rand()*float64(base/2))
	return min(max(d, c.cfg.MinBackoff), c.cfg.MaxBackoff)
}

// statuses returns the report: one entry for each known step, at most MaxStatuses. When there are
// more, final entries go first, then entries that only a refusal holds, then the oldest.
func (c *Controller) statuses() []mgmtapi.StepStatus {
	type item struct {
		e  *entry
		st mgmtapi.StepStatus
	}
	var items []item
	for _, e := range c.ordered() {
		if st, ok := e.report(); ok {
			items = append(items, item{e, st})
		}
	}
	final := func(it item) bool {
		return it.st.State == mgmtapi.StepDone || it.st.State == mgmtapi.StepFailedFinal || it.st.State == mgmtapi.StepCancelled
	}
	for len(items) > MaxStatuses {
		drop := slices.IndexFunc(items, final)
		if drop < 0 {
			drop = slices.IndexFunc(items, func(it item) bool { return it.e.cur == nil && it.e.status == nil })
		}
		if drop < 0 {
			drop = 0
		}
		items = slices.Delete(items, drop, drop+1)
	}
	out := make([]mgmtapi.StepStatus, 0, len(items))
	for _, it := range items {
		out = append(out, it.st)
	}
	return out
}

// report gives the status of one entry: a denial, a refusal (which wins over the host status, while
// the controller still polls the step), the status of the host service, or queued for a step that
// the host service has not accepted yet.
func (e *entry) report() (mgmtapi.StepStatus, bool) {
	var st mgmtapi.StepStatus
	switch {
	case e.denied != nil:
		st = mgmtapi.StepStatus{ID: e.id, Cell: e.cell, State: mgmtapi.StepRefused, Reason: mgmtapi.ReasonHostsvcDenied,
			RequestID: e.denied.requestID, UpdatedAt: e.firstAt}
	case e.refusal != nil:
		st = *e.refusal
		st.ID, st.Cell, st.UpdatedAt = e.id, e.cell, e.firstAt
	case e.status != nil:
		st = *e.status
	case e.cur != nil:
		st = mgmtapi.StepStatus{ID: e.id, Cell: e.cell, State: mgmtapi.StepQueued, UpdatedAt: e.firstAt}
	default:
		return st, false
	}
	if e.lastErr != nil {
		info := *e.lastErr
		st.LastHostError = &info
	}
	return st, true
}

// report writes the status when it changed, and at least every Heartbeat.
func (c *Controller) report(ctx context.Context) {
	now := c.cfg.Now()
	steps := c.statuses()
	body, err := encodeSteps(steps)
	if err != nil {
		c.cfg.Log.Error("status not encoded", "error", err.Error())
		return
	}
	changed := !sameSteps(body, c.lastWritten)
	if !changed && now.Sub(c.lastWrite) < c.cfg.Heartbeat {
		return
	}
	if now.Before(c.writeRetry) {
		return
	}
	if err := c.store.write(ctx, now, steps); err != nil {
		c.writeRetry = now.Add(c.cfg.MinBackoff)
		c.logOnce("write", "status not written", "error", err.Error())
		return
	}
	delete(c.logged, "write")
	c.lastWrite, c.lastWritten, c.writeRetry = now, body, time.Time{}
}

// wait returns the time to the next work: a read, a call that is due, a retry or a heartbeat.
func (c *Controller) wait() time.Duration {
	now := c.cfg.Now()
	next := c.nextRead
	consider := func(t time.Time) {
		if t.Before(next) {
			next = t
		}
	}
	consider(c.lastWrite.Add(c.cfg.Heartbeat))
	if !c.writeRetry.IsZero() {
		consider(c.writeRetry)
	}
	hostDue := func(t time.Time) {
		if t.Before(c.blockedUntil) {
			t = c.blockedUntil
		}
		consider(t)
	}
	for _, e := range c.entries {
		if e.needsPut(now) && c.mayPut(e) {
			hostDue(maxTime(now, c.putBlockedUntil))
		}
		if due, ok := e.pollDue(c.cfg.PollEvery); ok {
			if e.cur != nil && e.status != nil && e.status.State == mgmtapi.StepFailed && e.status.RetryAt.Before(due) {
				due = e.status.RetryAt
			}
			hostDue(due)
		}
	}
	return max(next.Sub(now), minWake)
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
