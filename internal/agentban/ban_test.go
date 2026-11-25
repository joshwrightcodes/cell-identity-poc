package agentban

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/metric/noop"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
)

type harness struct {
	fake *spireFake
	cfg  Config
	logs *bytes.Buffer
}

func newHarness(t *testing.T, set clusterjwt.RevokedSet, readErr error) *harness {
	t.Helper()
	fake, sock := newSpireFake(t)
	api, closeAPI, err := NewAgentAPI(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeAPI() })
	logs := &bytes.Buffer{}
	return &harness{fake: fake, logs: logs, cfg: Config{
		TrustDomain: testDomain,
		Read:        func() (clusterjwt.RevokedSet, error) { return set, readErr },
		API:         api,
		Log:         slog.New(slog.NewJSONHandler(logs, nil)),
		Meter:       noop.NewMeterProvider().Meter("test"),
	}}
}

func revoked(cells ...string) clusterjwt.RevokedSet {
	s := clusterjwt.RevokedSet{Cells: map[string]string{}}
	for _, c := range cells {
		s.Cells[c] = clusterjwt.SourceRecord
	}
	return s
}

func TestBanOnlyListedCells(t *testing.T) {
	h := newHarness(t, revoked("dev-cell-2"), nil)
	h.fake.add("cluster_jwt", agentID("dev-cell-1", "u1"))
	h.fake.add("cluster_jwt", agentID("dev-cell-2", "u2"))
	h.fake.add("cluster_jwt", agentID("dev-cell-2", "u3"))
	n, err := Once(context.Background(), h.cfg)
	if err != nil || n != 2 {
		t.Fatalf("Once = %d, %v; want 2, nil", n, err)
	}
	want := []string{agentID("dev-cell-2", "u2"), agentID("dev-cell-2", "u3")}
	if got := h.fake.banned(); !slices.Equal(got, want) {
		t.Fatalf("banned %v, want %v", got, want)
	}
	if !strings.Contains(h.logs.String(), `"msg":"agent_banned"`) || !strings.Contains(h.logs.String(), `"source":"record"`) ||
		!strings.Contains(h.logs.String(), `"cell":"dev-cell-2"`) || !strings.Contains(h.logs.String(), agentID("dev-cell-2", "u2")) {
		t.Fatalf("log lacks the agent_banned fields: %s", h.logs)
	}
}

func TestBanNothingWithoutSpec(t *testing.T) {
	h := newHarness(t, clusterjwt.RevokedSet{}, errors.New("no verified spec loaded"))
	h.fake.add("cluster_jwt", agentID("dev-cell-2", "u2"))
	n, err := Once(context.Background(), h.cfg)
	if err == nil || n != 0 {
		t.Fatalf("Once = %d, %v; want 0 and an error", n, err)
	}
	if len(h.fake.banned()) != 0 || h.fake.banCalls() != 0 {
		t.Fatal("an agent was banned without a spec")
	}
}

func TestBanIdempotent(t *testing.T) {
	h := newHarness(t, revoked("dev-cell-2"), nil)
	h.fake.add("cluster_jwt", agentID("dev-cell-2", "u2"))
	if n, err := Once(context.Background(), h.cfg); err != nil || n != 1 {
		t.Fatalf("first Once = %d, %v", n, err)
	}
	if n, err := Once(context.Background(), h.cfg); err != nil || n != 0 {
		t.Fatalf("second Once = %d, %v; want 0, nil", n, err)
	}
	if c := h.fake.banCalls(); c != 1 {
		t.Fatalf("%d BanAgent calls, want 1", c)
	}
}

func TestBanRetiredCell(t *testing.T) {
	set := clusterjwt.RevokedSet{Cells: map[string]string{"dev-cell-3": clusterjwt.SourceRetired}}
	h := newHarness(t, set, nil)
	h.fake.add("cluster_jwt", agentID("dev-cell-3", "u1"))
	if n, err := Once(context.Background(), h.cfg); err != nil || n != 1 {
		t.Fatalf("Once = %d, %v", n, err)
	}
	if !strings.Contains(h.logs.String(), `"source":"retired"`) {
		t.Fatalf("log lacks the retired source: %s", h.logs)
	}
}

func TestBanPrefixExact(t *testing.T) {
	h := newHarness(t, revoked("dev-cell-1"), nil)
	h.fake.add("cluster_jwt", agentID("dev-cell-10", "u1"))
	h.fake.add("cluster_jwt", agentID("dev-cell-1", "u2"))
	h.fake.add("cluster_jwt", agentID("dev-cell-1x", "u3"))
	if _, err := Once(context.Background(), h.cfg); err != nil {
		t.Fatal(err)
	}
	if got, want := h.fake.banned(), []string{agentID("dev-cell-1", "u2")}; !slices.Equal(got, want) {
		t.Fatalf("banned %v, want %v", got, want)
	}
}

func TestBanSkipsPsatAgents(t *testing.T) {
	h := newHarness(t, revoked("dev-cell-2"), nil)
	psat := "spiffe://" + testDomain + "/spire/agent/k8s_psat/dev-cell-2/node-1"
	h.fake.add("k8s_psat", psat)
	// An ID of another attestor that merely looks like a cell path is not a cluster_jwt agent.
	h.fake.add("k8s_psat", agentID("dev-cell-2", "u9"))
	h.fake.add("cluster_jwt", "spiffe://other.test/spire/agent/cluster_jwt/dev-cell-2/u8/h1")
	if n, err := Once(context.Background(), h.cfg); err != nil || n != 0 {
		t.Fatalf("Once = %d, %v; want 0, nil", n, err)
	}
	if h.fake.banCalls() != 0 {
		t.Fatal("a non cluster_jwt agent was banned")
	}
	for _, f := range h.fake.filters {
		if f.GetByAttestationType() != "cluster_jwt" {
			t.Fatalf("list filter %v lacks the attestation type", f)
		}
	}
}

func TestBanNotFoundIsDone(t *testing.T) {
	h := newHarness(t, revoked("dev-cell-2"), nil)
	gone := agentID("dev-cell-2", "u2")
	h.fake.add("cluster_jwt", gone)
	h.fake.add("cluster_jwt", agentID("dev-cell-2", "u3"))
	h.fake.evict(gone)
	n, err := Once(context.Background(), h.cfg)
	if err != nil {
		t.Fatalf("Once: %v; NotFound must count as done", err)
	}
	if n != 1 {
		t.Fatalf("Once = %d, want 1 (an evicted agent is done and not counted)", n)
	}
	if !strings.Contains(h.logs.String(), `"msg":"agent_gone"`) || strings.Contains(h.logs.String(), `"agent_id":"`+gone+`","source"`) {
		t.Fatalf("an evicted agent must log agent_gone and not agent_banned: %s", h.logs)
	}
	if strings.Count(h.logs.String(), `"msg":"agent_banned"`) != 1 {
		t.Fatalf("want one agent_banned line: %s", h.logs)
	}
	if got, want := h.fake.banned(), []string{agentID("dev-cell-2", "u3")}; !slices.Equal(got, want) {
		t.Fatalf("banned %v, want %v", got, want)
	}
}

func TestBanPagesThroughTheList(t *testing.T) {
	h := newHarness(t, revoked("dev-cell-2"), nil)
	for _, u := range []string{"u1", "u2", "u3", "u4", "u5"} {
		h.fake.add("cluster_jwt", agentID("dev-cell-2", u))
	}
	if n, err := Once(context.Background(), h.cfg); err != nil || n != 5 {
		t.Fatalf("Once = %d, %v; want 5", n, err)
	}
}

func TestListAsksForUnbannedAgentsOnly(t *testing.T) {
	h := newHarness(t, revoked("dev-cell-2"), nil)
	h.fake.addBanned("cluster_jwt", agentID("dev-cell-2", "u1"))
	h.fake.add("cluster_jwt", agentID("dev-cell-2", "u2"))
	agents, err := h.cfg.API.List(context.Background())
	if err != nil || len(agents) != 1 || agents[0].Banned {
		t.Fatalf("List = %v, %v; want the one unbanned agent", agents, err)
	}
	for _, f := range h.fake.filters {
		if b := f.GetByBanned(); b == nil || b.GetValue() {
			t.Fatalf("list filter %v lacks by_banned=false", f)
		}
	}
}

type failingList struct{ API }

func (failingList) List(context.Context) ([]Agent, error) { return nil, errors.New("socket closed") }

func TestListRunsWithoutRevokedCells(t *testing.T) {
	h := newHarness(t, revoked(), nil)
	h.cfg.API = failingList{h.cfg.API}
	if _, err := Once(context.Background(), h.cfg); err == nil {
		t.Fatal("Once with an empty set and a failed list returned nil")
	}
}

func TestCellOfSegments(t *testing.T) {
	pre := "spiffe://" + testDomain + "/spire/agent/cluster_jwt/"
	for _, tc := range []struct {
		id   string
		cell string
		ok   bool
	}{
		{pre + "dev-cell-2/u1/h1", "dev-cell-2", true},
		{pre + "dev-cell-2", "", false},
		{pre + "dev-cell-2/u1", "", false},
		{pre + "dev-cell-2/u1/h1/x", "", false},
		{pre + "dev-cell-2//h1", "", false},
		{pre + "/u1/h1", "", false},
		{"spiffe://other.test/spire/agent/cluster_jwt/dev-cell-2/u1/h1", "", false},
	} {
		cell, ok := cellOf(testDomain, tc.id)
		if cell != tc.cell || ok != tc.ok {
			t.Errorf("cellOf(%q) = %q, %v; want %q, %v", tc.id, cell, ok, tc.cell, tc.ok)
		}
	}
}

func TestBanSkipsMalformedSegmentCounts(t *testing.T) {
	h := newHarness(t, revoked("dev-cell-2"), nil)
	pre := "spiffe://" + testDomain + "/spire/agent/cluster_jwt/"
	for _, id := range []string{pre + "dev-cell-2", pre + "dev-cell-2/u1", pre + "dev-cell-2/u1/h1/x"} {
		h.fake.add("cluster_jwt", id)
	}
	if n, err := Once(context.Background(), h.cfg); err != nil || n != 0 || h.fake.banCalls() != 0 {
		t.Fatalf("Once = %d, %v, %d ban calls; want none", n, err, h.fake.banCalls())
	}
}
