package agentban

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
)

var gaugeNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

// stubAPI lists a fixed set of agents, or fails.
type stubAPI struct {
	agents  []Agent
	listErr error
	banned  []string
}

func (s *stubAPI) List(context.Context) ([]Agent, error) { return s.agents, s.listErr }

func (s *stubAPI) Ban(_ context.Context, id string) error {
	s.banned = append(s.banned, id)
	return nil
}

type gaugeRig struct {
	api    *stubAPI
	cfg    Config
	reader *metric.ManualReader
	set    clusterjwt.RevokedSet
	rerr   error
}

func newGaugeRig(t *testing.T) *gaugeRig {
	t.Helper()
	r := &gaugeRig{api: &stubAPI{}, reader: metric.NewManualReader(), set: revoked()}
	mp := metric.NewMeterProvider(metric.WithReader(r.reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	r.cfg = Config{
		TrustDomain: testDomain,
		Read:        func() (clusterjwt.RevokedSet, error) { return r.set, r.rerr },
		API:         r.api,
		Log:         slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)),
		Meter:       mp.Meter("test"),
		Now:         func() time.Time { return gaugeNow },
	}
	return r
}

// counts runs one pass on the instruments of a run and returns the gauge by cell.
func (r *gaugeRig) counts(t *testing.T, o *observer) map[string]int64 {
	t.Helper()
	_, _ = o.once(context.Background(), r.cfg)
	var rm metricdata.ResourceMetrics
	if err := r.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "agentban.agents" {
				continue
			}
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatalf("agentban.agents is %T, want an int64 gauge", m.Data)
			}
			if m.Unit != "{agent}" {
				t.Fatalf("unit %q, want {agent}", m.Unit)
			}
			for _, dp := range g.DataPoints {
				cell, _ := dp.Attributes.Value("cell")
				out[cell.AsString()] = dp.Value
			}
		}
	}
	return out
}

func live(cell, uid string) Agent {
	return Agent{ID: agentID(cell, uid), ExpiresAt: gaugeNow.Add(time.Hour)}
}

func rigObserver(t *testing.T, r *gaugeRig) *observer {
	t.Helper()
	o, err := newObserver(r.cfg.Meter)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestAgentsPerCell(t *testing.T) {
	r := newGaugeRig(t)
	o := rigObserver(t, r)
	r.api.agents = []Agent{
		live("dev-cell-1", "u1"), live("dev-cell-1", "u2"), live("dev-cell-2", "u3"),
		{ID: agentID("dev-cell-2", "u4"), ExpiresAt: gaugeNow.Add(-time.Second)},
		{ID: agentID("dev-cell-2", "u5")},
	}
	got := r.counts(t, o)
	if len(got) != 2 || got["dev-cell-1"] != 2 || got["dev-cell-2"] != 1 {
		t.Fatalf("counts %v, want dev-cell-1=2 dev-cell-2=1", got)
	}
}

func TestAgentsGaugeDropsGoneCell(t *testing.T) {
	r := newGaugeRig(t)
	o := rigObserver(t, r)
	r.api.agents = []Agent{live("dev-cell-1", "u1"), live("dev-cell-2", "u2")}
	if got := r.counts(t, o); len(got) != 2 {
		t.Fatalf("first round %v, want two cells", got)
	}
	r.api.agents = []Agent{live("dev-cell-1", "u1")}
	got := r.counts(t, o)
	if _, ok := got["dev-cell-2"]; ok || got["dev-cell-1"] != 1 {
		t.Fatalf("second round %v, want only dev-cell-1=1", got)
	}
}

func TestAgentsCellFromIDPath(t *testing.T) {
	r := newGaugeRig(t)
	o := rigObserver(t, r)
	exp := gaugeNow.Add(time.Hour)
	r.api.agents = []Agent{
		{ID: "spiffe://other.test/spire/agent/cluster_jwt/dev-cell-1/u1/h1", ExpiresAt: exp},
		{ID: "spiffe://" + testDomain + "/spire/agent/k8s_psat/dev-cell-1/u1/h1", ExpiresAt: exp},
		{ID: "spiffe://" + testDomain + "/spire/agent/cluster_jwt/dev-cell-1/u1", ExpiresAt: exp},
	}
	if got := r.counts(t, o); len(got) != 0 {
		t.Fatalf("counts %v, want none", got)
	}
}

func TestAgentsLeavesOutAgentsBannedInTheRound(t *testing.T) {
	r := newGaugeRig(t)
	o := rigObserver(t, r)
	r.set = revoked("dev-cell-2")
	r.api.agents = []Agent{live("dev-cell-1", "u1"), live("dev-cell-2", "u2"), live("dev-cell-2", "u3")}
	got := r.counts(t, o)
	if len(got) != 1 || got["dev-cell-1"] != 1 {
		t.Fatalf("counts %v, want only dev-cell-1=1", got)
	}
	if len(r.api.banned) != 2 {
		t.Fatalf("banned %v, want two", r.api.banned)
	}
}

func TestAgentsClearOnListError(t *testing.T) {
	r := newGaugeRig(t)
	o := rigObserver(t, r)
	r.api.agents = []Agent{live("dev-cell-1", "u1")}
	if got := r.counts(t, o); got["dev-cell-1"] != 1 {
		t.Fatalf("first round %v", got)
	}
	r.api.listErr = errors.New("socket closed")
	if got := r.counts(t, o); len(got) != 0 {
		t.Fatalf("after a failed list %v, want none", got)
	}
}

func TestAgentsClearOnReadError(t *testing.T) {
	r := newGaugeRig(t)
	o := rigObserver(t, r)
	r.api.agents = []Agent{live("dev-cell-1", "u1")}
	if got := r.counts(t, o); got["dev-cell-1"] != 1 {
		t.Fatalf("first round %v", got)
	}
	r.rerr = errors.New("no verified spec loaded")
	if got := r.counts(t, o); len(got) != 0 {
		t.Fatalf("after a failed read %v, want none", got)
	}
}
