package envd

import (
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

func ageOf(t *testing.T, h *harness) time.Duration {
	t.Helper()
	g, ok := h.metric(t, "envd.upstream.age").(metricdata.Gauge[float64])
	if !ok || len(g.DataPoints) != 1 {
		t.Fatalf("envd.upstream.age is %#v, want one float64 gauge point", h.metric(t, "envd.upstream.age"))
	}
	return time.Duration(g.DataPoints[0].Value * float64(time.Second))
}

// While every pull fails, the age counts from the start of the process and rises with the clock. It
// does not read 0 before the first good pull.
func TestEnvdUpstreamAge(t *testing.T) {
	h := newHarnessWith(t, 4, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 4)), nil }, nil)
	if got := ageOf(t, h); got != 0 {
		t.Fatalf("age %v at the start", got)
	}
	h.up.failGet.Store(true)
	start := h.clk.Now()
	runRounds(t, h.p, h.clk)
	want := h.clk.Now().Sub(start)
	if want <= 0 {
		t.Fatalf("the clock did not advance: %v", want)
	}
	if got := ageOf(t, h); got != want {
		t.Fatalf("age %v after failed pulls, want %v since the start", got, want)
	}
	h.clk.mu.Lock()
	h.clk.now = h.clk.now.Add(time.Minute)
	h.clk.mu.Unlock()
	if got := ageOf(t, h); got != want+time.Minute {
		t.Fatalf("age %v, want %v: it must keep rising while pulls fail", got, want+time.Minute)
	}
}

// A good pull sets the age to the time since that pull, not since the start.
func TestEnvdUpstreamAgeResetsOnGoodPull(t *testing.T) {
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 4)), nil }, nil)
	runRounds(t, h.p, h.clk)
	sl := h.clk.slept()
	if got, want := ageOf(t, h), sl[len(sl)-1]; got != want {
		t.Fatalf("age %v after a good pull, want %v (the last wait only)", got, want)
	}
}

// A pull that returned a decodable spec counts, even when Accept refuses it, because the
// management plane answered.
func TestEnvdUpstreamAgeRefusedSpecIsReachable(t *testing.T) {
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) {
		cur, _ := f.base()
		return f.bundle(rev(1, 4), []item{f.item(f.cell("a", rev(1, 2), false))}, nil), cur
	}, func(c *PullerConfig) { c.Interval = 10 * time.Second })
	runRounds(t, h.p, h.clk)
	if h.p.refusal == nil {
		t.Fatal("the bundle was not refused")
	}
	if got := ageOf(t, h); got != 10*time.Second {
		t.Fatalf("age %v after refused pulls, want 10s (the last wait only)", got)
	}
}
