package bundleapply

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
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

	metricOutcomes = "bundle.apply.outcomes"
	metricDuration = "bundle.apply.duration"
)

type telemetry struct {
	tracer   trace.Tracer
	outcomes metric.Int64Counter
	duration metric.Float64Histogram
}

func newTelemetry(tr trace.Tracer, m metric.Meter) (telemetry, error) {
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
	return telemetry{tracer: tr, outcomes: outcomes, duration: duration}, nil
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
