package bundleapply

import (
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
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
	cfg.Meter = mp.Meter("test")
	e.a = e.applier(cfg)
	return te
}

// counter returns the value of bundle.apply.outcomes for the attributes.
func (te *telemetryEnv) counter(t *testing.T, want attribute.Set) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := te.reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "bundle.apply.outcomes" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("outcomes is %T", m.Data)
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
