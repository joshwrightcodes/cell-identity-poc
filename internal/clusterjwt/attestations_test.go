package clusterjwt

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type attestKey struct{ cell, result, reason string }

func meterFixture(t *testing.T, f *fixture) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	if err := f.plugin.SetMeter(mp.Meter("test")); err != nil {
		t.Fatal(err)
	}
	return reader
}

// attestCounts reads the counter into a map and checks name, unit and kind.
func attestCounts(t *testing.T, r *sdkmetric.ManualReader) map[attestKey]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[attestKey]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "cluster_jwt.attestations" {
				continue
			}
			if m.Unit != "{attestation}" {
				t.Errorf("unit = %q", m.Unit)
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || !sum.IsMonotonic {
				t.Fatalf("data = %T, want a monotonic int64 sum", m.Data)
			}
			for _, dp := range sum.DataPoints {
				get := func(k string) string { v, _ := dp.Attributes.Value(attribute.Key(k)); return v.AsString() }
				if dp.Attributes.Len() != 3 {
					t.Errorf("attributes = %v, want cell, result and reason only", dp.Attributes)
				}
				out[attestKey{get("cell"), get("result"), get("reason")}] += dp.Value
			}
		}
	}
	return out
}

// waitCounts polls until the counter reaches want, because Attest counts after the client sees the reply.
func waitCounts(t *testing.T, r *sdkmetric.ManualReader, want map[attestKey]int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := attestCounts(t, r)
		if len(got) == len(want) {
			same := true
			for k, v := range want {
				same = same && got[k] == v
			}
			if same {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("counts = %v, want %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *fixture) sendPayload(cell string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(Payload{Cell: cell})
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}}); err != nil {
		return err
	}
	_, err = stream.Recv()
	return err
}

func TestAttestationsCounted(t *testing.T) {
	f := newFixture(t, fixtureOptions{
		revoked:  map[string]bool{"dev-cell-2": true},
		extraHCL: `challenge_timeout = "300ms"` + "\n" + `per_cell_rate = 0.001` + "\n" + `per_cell_burst = 1`,
	})
	r := meterFixture(t, f)

	if _, err := f.attest("dev-cell-1", f.goodToken); err != nil {
		t.Fatal(err)
	}
	_, err := f.attest("dev-cell-1", f.goodToken)
	wantDenied(t, err, RateLimited)
	_, err = f.attest("dev-cell-1", func(string) string { return f.goodToken("an-earlier-challenge") })
	wantDenied(t, err, WrongAudience)
	wantDenied(t, f.sendPayload("dev-cell-2"), Revoked)
	wantDenied(t, f.sendPayload("nope"), UnknownCell)

	// A silent client times out the challenge.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(Payload{Cell: "dev-cell-1"})
	_ = stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}})
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	wantDenied(t, err, ChallengeTimeout)

	waitCounts(t, r, map[attestKey]int64{
		{"dev-cell-1", "accepted", "none"}:             1,
		{"dev-cell-1", "refused", "rate_limited"}:      1,
		{"dev-cell-1", "refused", "wrong_audience"}:    1,
		{"dev-cell-1", "refused", "challenge_timeout"}: 1,
		{"dev-cell-2", "refused", "revoked"}:           1,
		{"unknown", "refused", "unknown_cell"}:         1,
	})
}

func TestAttestationsCellLabelBounded(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	r := meterFixture(t, f)
	for _, cell := range []string{"nope", "other", "x.y", "dev-cell-1-extra"} {
		wantDenied(t, f.sendPayload(cell), UnknownCell)
	}
	wantDenied(t, f.sendMalformed(), Malformed)
	waitCounts(t, r, map[attestKey]int64{
		{"unknown", "refused", "unknown_cell"}: 4,
		{"unknown", "refused", "malformed"}:    1,
	})
}

func (f *fixture) sendMalformed() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: []byte(`not json`)}}); err != nil {
		return err
	}
	_, err = stream.Recv()
	return err
}

// blockingExporter never returns from Export until release closes.
type blockingExporter struct {
	release chan struct{}
	entered chan struct{}
}

func (e *blockingExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}
func (e *blockingExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}
func (e *blockingExporter) Export(context.Context, *metricdata.ResourceMetrics) error {
	select {
	case e.entered <- struct{}{}:
	default:
	}
	<-e.release
	return nil
}
func (e *blockingExporter) ForceFlush(context.Context) error { return nil }
func (e *blockingExporter) Shutdown(context.Context) error   { return nil }

// The test guards against a future exporter that runs inside Attest. The SDK exports on its own goroutine today.
func TestAttestDoesNotWaitOnExport(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	exp := &blockingExporter{release: make(chan struct{}), entered: make(chan struct{}, 1)}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(10*time.Millisecond))))
	t.Cleanup(func() {
		close(exp.release)
		_ = mp.Shutdown(context.Background())
	})
	if err := f.plugin.SetMeter(mp.Meter("test")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.attest("dev-cell-1", f.goodToken); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exp.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the exporter never started")
	}
	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := f.attest("dev-cell-2", f.goodToken); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("three attestations took %v while the exporter blocked", d)
	}
}
