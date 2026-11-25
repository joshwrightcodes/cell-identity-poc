package bundleapply

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

type telemetryEnv struct {
	*env
	spans  *tracetest.SpanRecorder
	reader *sdkmetric.ManualReader
	meter  metric.Meter
}

func newTelemetryEnv(t *testing.T) *telemetryEnv {
	t.Helper()
	e := newEnv(t)
	te := &telemetryEnv{env: e, spans: tracetest.NewSpanRecorder(), reader: sdkmetric.NewManualReader()}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(te.spans))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(te.reader))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()); _ = mp.Shutdown(t.Context()) })
	cfg := e.cfg
	cfg.Tracer = tp.Tracer("test")
	te.meter = mp.Meter("test")
	cfg.Meter = te.meter
	e.a = e.applier(cfg)
	return te
}

// counter returns the value of bundle.apply.outcomes for the attributes.
func (te *telemetryEnv) counter(t *testing.T, want attribute.Set) int64 {
	t.Helper()
	return te.sum(t, "bundle.apply.outcomes", want)
}

// sum returns the value of the counter name for the attributes.
func (te *telemetryEnv) sum(t *testing.T, name string, want attribute.Set) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := te.reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T", name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				if dp.Attributes.Equals(&want) {
					return dp.Value
				}
			}
		}
	}
	return 0
}

func (te *telemetryEnv) durations(t *testing.T) (count uint64, sum float64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := te.reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "bundle.apply.duration" {
				continue
			}
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("duration is %T", m.Data)
			}
			if m.Unit != "s" {
				t.Errorf("duration unit = %q", m.Unit)
			}
			for _, dp := range h.DataPoints {
				count += dp.Count
				sum += dp.Sum
			}
		}
	}
	return count, sum
}

func attrs(outcome, reason string) attribute.Set {
	return attribute.NewSet(attribute.String("outcome", outcome), attribute.String("reason", reason), attribute.String("role", "cell"))
}

func TestApplyTelemetry(t *testing.T) {
	t.Run("rolled back", func(t *testing.T) {
		te := newTelemetryEnv(t)
		a := te.set(1, std("a"))
		wantOutcome(t, te.apply("opA", a), op.OutcomeApplied, "", "")
		b := te.set(2, std("b"))
		te.health = func(root, app string) (string, string) {
			if root == b.root.Digest && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
		wantOutcome(t, te.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")

		var tops []sdktrace.ReadOnlySpan
		for _, s := range te.spans.Ended() {
			if s.Name() == "bundle.apply" {
				tops = append(tops, s)
			}
		}
		if len(tops) != 2 {
			t.Fatalf("%d bundle.apply spans, want 2", len(tops))
		}
		top := tops[1]
		if top.Parent().IsValid() {
			t.Fatal("bundle.apply has a parent")
		}
		children := map[string]int{}
		for _, s := range te.spans.Ended() {
			if s.Parent().SpanID() == top.SpanContext().SpanID() {
				children[s.Name()]++
			}
		}
		for _, name := range []string{"fetch", "check", "push", "tag", "wait", "rollback"} {
			if children[name] == 0 {
				t.Errorf("no %s span under bundle.apply: %v", name, children)
			}
		}
		if n := te.counter(t, attrs("rolled_back", "unhealthy")); n != 1 {
			t.Fatalf("outcomes rolled_back/unhealthy = %d, want 1", n)
		}
		if n := te.counter(t, attrs("applied", "")); n != 1 {
			t.Fatalf("outcomes applied = %d, want 1", n)
		}
		if count, sum := te.durations(t); count != 2 || sum <= 0 {
			t.Fatalf("duration count %d sum %v", count, sum)
		}
	})
	t.Run("refused", func(t *testing.T) {
		te := newTelemetryEnv(t)
		wantOutcome(t, te.apply("op1", te.set(5, std("a"))), op.OutcomeApplied, "", "")
		b := te.build(tTarget, bundle.Version{Epoch: 1, Counter: 2}, std("b"))
		b.att = te.sign(b, tEnv, tTarget, b.root.Digest, te.priv)
		wantOutcome(t, te.apply("op2", b), op.OutcomeRefused, op.ReasonVersionOld, "")
		if n := te.counter(t, attrs("refused", "version_old")); n != 1 {
			t.Fatalf("outcomes refused/version_old = %d", n)
		}
	})
	t.Run("rollback ends with an error", func(t *testing.T) {
		te := newTelemetryEnv(t)
		a := te.set(1, std("a"))
		wantOutcome(t, te.apply("opA", a), op.OutcomeApplied, "", "")
		b := te.set(2, std("b"))
		te.health = func(root, app string) (string, string) {
			if app == "apps-sample" {
				return "Synced", "Progressing"
			}
			return "Synced", "Healthy"
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		te.hook = func(int) {
			if te.currentRoot() == a.root.Digest {
				cancel()
			}
		}
		if _, err := te.a.Apply(ctx, "opB", tTarget, b.att); err == nil {
			t.Fatal("a rollback with a canceled context succeeded")
		}
		var found bool
		for _, s := range te.spans.Ended() {
			if s.Name() != "rollback" {
				continue
			}
			found = true
			if s.Status().Code != codes.Error {
				t.Fatalf("rollback span status = %v, want Error", s.Status())
			}
		}
		if !found {
			t.Fatal("no rollback span")
		}
	})
	t.Run("lock held", func(t *testing.T) {
		te := newTelemetryEnv(t)
		st := te.state()
		st.Holder, st.Until = "pod-z", te.clk.Now().Add(time.Hour)
		te.mustWriteState(st)
		if _, err := te.a.Apply(t.Context(), "op1", tTarget, te.set(1, std("a")).att); err == nil {
			t.Fatal("lock not held")
		}
		if n := te.counter(t, attrs("error", "lock_held")); n != 1 {
			t.Fatalf("outcomes error/lock_held = %d", n)
		}
	})
}

// TestTelemetryTerminateFailures checks that each Application whose running sync the rollback could not
// terminate counts in bundle.rollback.terminate.failures, by role and Application: a Role that lacks the
// patch right brings back a rollback that waits behind the retries of Argo CD, and the result does not
// show it.
func TestTelemetryTerminateFailures(t *testing.T) {
	te := newTelemetryEnv(t)
	a := te.set(1, std("a"))
	wantOutcome(t, te.apply("opA", a), op.OutcomeApplied, "", "")
	b := te.set(2, std("b"))
	te.sync = syncOf("apps-sample", b.digests()["apps-sample"], func(now time.Time) (string, time.Time) { return "Running", now })
	te.conflicts = 5
	wantOutcome(t, te.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "rollback_unhealthy")
	want := attribute.NewSet(attribute.String("role", "cell"), attribute.String("app", "apps-sample"))
	if got := te.sum(t, "bundle.rollback.terminate.failures", want); got != 1 {
		t.Fatalf("bundle.rollback.terminate.failures for apps-sample = %d, want 1", got)
	}
}

// syncDelays returns the count and sum of bundle.sync.delay for a result.
func (te *telemetryEnv) syncDelays(t *testing.T, result string) (count uint64, sum float64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := te.reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	want := attribute.NewSet(attribute.String("role", "cell"), attribute.String("result", result))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "bundle.sync.delay" {
				continue
			}
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("sync delay is %T", m.Data)
			}
			if m.Unit != "s" {
				t.Errorf("sync delay unit = %q", m.Unit)
			}
			for _, dp := range h.DataPoints {
				if dp.Attributes.Equals(&want) {
					count += dp.Count
					sum += dp.Sum
				}
			}
		}
	}
	return count, sum
}

type appliedSeries struct {
	attrs attribute.Set
	value int64
}

// applied returns the series of bundle.set.applied.
func (te *telemetryEnv) applied(t *testing.T) []appliedSeries {
	t.Helper()
	return appliedFrom(t, te.reader)
}

func appliedFrom(t *testing.T, reader *sdkmetric.ManualReader) []appliedSeries {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	var out []appliedSeries
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "bundle.set.applied" {
				continue
			}
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatalf("set applied is %T", m.Data)
			}
			if m.Unit != "s" {
				t.Errorf("set applied unit = %q", m.Unit)
			}
			for _, dp := range g.DataPoints {
				out = append(out, appliedSeries{dp.Attributes, dp.Value})
			}
		}
	}
	return out
}

func wantSeries(t *testing.T, got []appliedSeries, version, root, state string, at time.Time) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("%d series of bundle.set.applied, want 1: %v", len(got), got)
	}
	want := attribute.NewSet(attribute.String("role", "cell"), attribute.String("version", version),
		attribute.String("root.digest", root), attribute.String("state", state))
	if !got[0].attrs.Equals(&want) {
		t.Fatalf("attributes = %v, want %v", got[0].attrs.ToSlice(), want.ToSlice())
	}
	if got[0].value != at.Unix() {
		t.Fatalf("value = %d, want %d", got[0].value, at.Unix())
	}
}

func rootChars(b built) string { return strings.TrimPrefix(b.root.Digest, "sha256:")[:12] }

func TestSyncDelayRecorded(t *testing.T) {
	te := newTelemetryEnv(t)
	cfg := te.cfg
	cfg.Poll = 7 * time.Second
	cfg.Tracer, cfg.Meter = nil, te.meter
	te.a = te.applier(cfg)
	wantOutcome(t, te.apply("opA", te.set(1, std("a"))), op.OutcomeApplied, "", "")
	count, sum := te.syncDelays(t, "synced")
	if count != 1 || sum != 7 {
		t.Fatalf("sync delay count %d sum %v, want 1 and 7", count, sum)
	}
}

func TestSyncDelayResult(t *testing.T) {
	te := newTelemetryEnv(t)
	wantOutcome(t, te.apply("opA", te.set(1, std("a"))), op.OutcomeApplied, "", "")
	if c, _ := te.syncDelays(t, "synced"); c != 1 {
		t.Fatalf("synced count = %d", c)
	}
	// A Degraded component ends the wait with an unhealthy result.
	b := te.set(2, std("b"))
	te.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app == "apps-sample" {
			return "Synced", "Degraded"
		}
		return "Synced", "Healthy"
	}
	wantOutcome(t, te.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
	if c, _ := te.syncDelays(t, "unhealthy"); c != 1 {
		t.Fatalf("unhealthy count = %d", c)
	}
	// A Progressing component holds the wait to the deadline.
	c := te.set(3, std("c"))
	te.health = func(root, app string) (string, string) {
		if root == c.root.Digest && app == "apps-sample" {
			return "Synced", "Progressing"
		}
		return "Synced", "Healthy"
	}
	out := te.apply("opC", c)
	if out.Outcome != op.OutcomeRolledBack {
		t.Fatalf("outcome = %+v", out)
	}
	if n, _ := te.syncDelays(t, "timeout"); n != 1 {
		t.Fatalf("timeout count = %d", n)
	}
}

func TestSetAppliedOneSeries(t *testing.T) {
	te := newTelemetryEnv(t)
	a := te.set(1, std("a"))
	wantOutcome(t, te.apply("opA", a), op.OutcomeApplied, "", "")
	wantSeries(t, te.applied(t), "1.1", rootChars(a), "healthy", te.clk.Now())
	te.clk.Advance(time.Minute)
	b := te.set(2, std("b"))
	wantOutcome(t, te.apply("opB", b), op.OutcomeApplied, "", "")
	got := te.applied(t)
	wantSeries(t, got, "1.2", rootChars(b), "healthy", te.state().Good[0].At)
}

func TestSetAppliedFromState(t *testing.T) {
	te := newTelemetryEnv(t)
	a := te.set(1, std("a"))
	wantOutcome(t, te.apply("opA", a), op.OutcomeApplied, "", "")
	at := te.state().Good[0].At
	te.clk.Advance(time.Hour)
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(t.Context()) })
	cfg := te.cfg
	cfg.Meter = mp.Meter("fresh")
	fresh := te.applier(cfg)
	if got := appliedFrom(t, reader); len(got) != 0 {
		t.Fatalf("series before the first read = %v", got)
	}
	if _, err := fresh.Status(t.Context()); err != nil {
		t.Fatal(err)
	}
	wantSeries(t, appliedFrom(t, reader), "1.1", rootChars(a), "healthy", at)
}

// TestSetAppliedRollingBack checks that the series reports the state rolling_back while the rollback waits.
func TestSetAppliedRollingBack(t *testing.T) {
	te := newTelemetryEnv(t)
	a := te.set(1, std("a"))
	wantOutcome(t, te.apply("opA", a), op.OutcomeApplied, "", "")
	b := te.set(2, std("b"))
	te.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app == "apps-sample" {
			return "Synced", "Degraded"
		}
		return "Synced", "Healthy"
	}
	var seen []appliedSeries
	var at time.Time
	te.hook = func(int) {
		if te.state().State == stateRollingBack && seen == nil {
			seen, at = te.applied(t), te.clk.Now()
		}
	}
	wantOutcome(t, te.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
	if seen == nil {
		t.Fatal("the rollback never waited")
	}
	// The series holds the time at which the state changed, which is before the first wait.
	if len(seen) == 1 {
		wantSeries(t, seen, "1.2", rootChars(b), "rolling_back", time.Unix(seen[0].value, 0))
		if seen[0].value > at.Unix() {
			t.Fatalf("value %d is after the first wait at %d", seen[0].value, at.Unix())
		}
	} else {
		t.Fatalf("series = %v", seen)
	}
}

// slowStore advances the clock at each write, so the tag move takes time.
type slowStore struct {
	Store
	clk *clock
}

func (s slowStore) Write(ctx context.Context, st State, rv string) error {
	s.clk.Advance(3 * time.Second)
	return s.Store.Write(ctx, st, rv)
}

// TestSyncDelayStartsAtTagMove checks that the time of the tag step counts in the delay.
func TestSyncDelayStartsAtTagMove(t *testing.T) {
	te := newTelemetryEnv(t)
	cfg := te.cfg
	cfg.Poll = 7 * time.Second
	cfg.Tracer, cfg.Meter = nil, te.meter
	cfg.State = slowStore{Store: cfg.State, clk: te.clk}
	te.a = te.applier(cfg)
	wantOutcome(t, te.apply("opA", te.set(1, std("a"))), op.OutcomeApplied, "", "")
	count, sum := te.syncDelays(t, "synced")
	if count != 1 || sum < 10 || int64(sum-7)%3 != 0 {
		t.Fatalf("sync delay count %d sum %v, want 1 and 7 plus whole 3 s writes of the tag step", count, sum)
	}
}
