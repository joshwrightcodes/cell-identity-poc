package bundleapply

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

// The telemetry names of the applier. Every span of an apply is a child of spanApply.
const (
	spanApply    = "bundle.apply"
	spanFetch    = "fetch"
	spanCheck    = "check"
	spanPush     = "push"
	spanTag      = "tag"
	spanWait     = "wait"
	spanRollback = "rollback"

	metricOutcomes          = "bundle.apply.outcomes"
	metricDuration          = "bundle.apply.duration"
	metricTerminateFailures = "bundle.rollback.terminate.failures"
	metricRefills           = "bundle.store.refills"
	metricSetApplied        = "bundle.set.applied"
	metricSyncDelay         = "bundle.sync.delay"

	// rootDigestChars is the number of hex digits of the root digest in the root.digest attribute.
	rootDigestChars = 12
	// detailTimeout starts the detail of a health wait that ended at its deadline.
	detailTimeout = "timeout:"
)

// The values of the result attribute of bundle.sync.delay.
const (
	syncSynced    = "synced"
	syncUnhealthy = "unhealthy"
	syncTimeout   = "timeout"
)

// setSnapshot is the set that the applier last read or wrote, for bundle.set.applied. The state
// stores a time only in Good[].At. So the time of a set that is not the first good set is the time
// of the first read of that root in that state, which a restart resets.
type setSnapshot struct {
	mu      sync.Mutex
	known   bool
	version bundle.Version
	root    string
	state   string
	at      time.Time
	// writes counts the observed writes, so that a read that a write overtook is dropped.
	writes uint64
}

// generation returns the count of writes. A reader takes it before it reads the store.
func (n *setSnapshot) generation() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.writes
}

// observeWrite refreshes the snapshot from st, the state that the applier just wrote.
func (n *setSnapshot) observeWrite(st State, now time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.writes++
	n.set(st, now)
}

// observeRead refreshes the snapshot from st, which a read made after it took generation gen. A
// write since then makes st stale, so the read changes nothing.
func (n *setSnapshot) observeRead(st State, now time.Time, gen uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.writes == gen {
		n.set(st, now)
	}
}

// set keeps the full digest and the version as the identity of the set. The caller holds mu.
func (n *setSnapshot) set(st State, now time.Time) {
	if st.State == "" {
		return
	}
	at := now
	switch {
	case st.State == stateHealthy && len(st.Good) > 0 && st.Good[0].Root.Digest == st.Root.Digest:
		at = st.Good[0].At
	case n.known && n.root == st.Root.Digest && n.version == st.Version && n.state == st.State:
		at = n.at
	}
	n.known, n.root, n.version, n.state, n.at = true, st.Root.Digest, st.Version, st.State, at
}

// attrs returns the attributes of the series. Only the attribute shortens the digest.
func (n *setSnapshot) attrs(role string) metric.MeasurementOption {
	root := strings.TrimPrefix(n.root, "sha256:")
	root = root[:min(len(root), rootDigestChars)]
	return metric.WithAttributes(attribute.String("role", role),
		attribute.String("version", fmt.Sprintf("%d.%d", n.version.Epoch, n.version.Counter)),
		attribute.String("root.digest", root), attribute.String("state", n.state))
}

func syncResult(detail string) string {
	switch {
	case detail == "":
		return syncSynced
	case strings.HasPrefix(detail, detailTimeout):
		return syncTimeout
	}
	return syncUnhealthy
}

type telemetry struct {
	tracer            trace.Tracer
	outcomes          metric.Int64Counter
	duration          metric.Float64Histogram
	terminateFailures metric.Int64Counter
	refills           metric.Int64Counter
	syncDelay         metric.Float64Histogram
	role              string
	snap              *setSnapshot
}

func newTelemetry(role string, tr trace.Tracer, m metric.Meter) (telemetry, error) {
	if tr == nil {
		tr = tracenoop.NewTracerProvider().Tracer("")
	}
	if m == nil {
		m = metricnoop.NewMeterProvider().Meter("")
	}
	outcomes, err := m.Int64Counter(metricOutcomes, metric.WithDescription("Bundle sets that the applier finished, by outcome and reason."))
	if err != nil {
		return telemetry{}, err
	}
	duration, err := m.Float64Histogram(metricDuration, metric.WithUnit("s"), metric.WithDescription("Time that the applier took for one bundle set."))
	if err != nil {
		return telemetry{}, err
	}
	terminateFailures, err := m.Int64Counter(metricTerminateFailures,
		metric.WithDescription("Running sync operations that a rollback could not terminate, by role and Application."))
	if err != nil {
		return telemetry{}, err
	}
	refills, err := m.Int64Counter(metricRefills, metric.WithDescription("Refills of the in-cluster bundle store, by outcome."))
	if err != nil {
		return telemetry{}, err
	}
	syncDelay, err := m.Float64Histogram(metricSyncDelay, metric.WithUnit("s"),
		metric.WithDescription("Time from the tag move of a set to the end of its health wait."))
	if err != nil {
		return telemetry{}, err
	}
	snap := &setSnapshot{}
	_, err = m.Int64ObservableGauge(metricSetApplied, metric.WithUnit("s"),
		metric.WithDescription("Unix time at which the current signed set reached its state."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			snap.mu.Lock()
			defer snap.mu.Unlock()
			if snap.known {
				o.Observe(snap.at.Unix(), snap.attrs(role))
			}
			return nil
		}))
	if err != nil {
		return telemetry{}, err
	}
	return telemetry{tracer: tr, outcomes: outcomes, duration: duration, terminateFailures: terminateFailures, refills: refills,
		syncDelay: syncDelay, role: role, snap: snap}, nil
}

// step starts a child span and returns the function that ends it. The function records err on the span.
func (t telemetry) step(ctx context.Context, name string) (context.Context, func(error)) {
	ctx, span := t.tracer.Start(ctx, name)
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}
}

// record counts one finished apply and times it. It does not depend on the cancellation of ctx.
func (t telemetry) record(ctx context.Context, role, outcome, reason string, took time.Duration) {
	ctx = context.WithoutCancel(ctx)
	t.outcomes.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome), attribute.String("reason", reason), attribute.String("role", role)))
	t.duration.Record(ctx, took.Seconds())
}

// recordSync records the time from the tag move to the end of the health wait.
func (t telemetry) recordSync(ctx context.Context, detail string, took time.Duration) {
	t.syncDelay.Record(context.WithoutCancel(ctx), took.Seconds(), metric.WithAttributes(
		attribute.String("role", t.role), attribute.String("result", syncResult(detail))))
}
