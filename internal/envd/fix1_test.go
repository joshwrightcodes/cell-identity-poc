package envd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// writeOutside replaces the data of the live ConfigMap the way an outside writer would: through the
// API, with no check of its own.
func writeOutside(t *testing.T, c *fake.Clientset, st *State, pin string) {
	t.Helper()
	cm, err := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data = map[string]string{SpecKey: string(st.SpecEnvelope)}
	for name, raw := range st.Records {
		cm.Data[name+RecordSuffix] = string(raw)
	}
	cm.Annotations[AnnotationKeySHA] = pin
	if _, err := c.CoreV1().ConfigMaps(testNS).Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// TestPullerRepairsStoreDrift: an outside writer puts back an older signed state. The next round
// restores the accepted state, and the report matches the store.
func TestPullerRepairsStoreDrift(t *testing.T) {
	f := newFx(t)
	older, _, err := Accept(Empty(), firstBundle(f, rev(1, 2)), testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset()
	store := NewConfigMapStore(client, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	up := newUpstream(t, firstBundle(f, rev(1, 4)), nil)
	clk := newClock(5)
	logs := &syncBuffer{}
	sleeps := 0
	p := NewPuller(PullerConfig{Client: up.client, BaseURL: up.url, Env: testEnv, Keys: f.keys(), Store: store,
		Log: newLog(logs), Now: clk.Now, Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps++
			if sleeps == 2 {
				writeOutside(t, client, older, KeyFingerprint(f.keys()))
			}
			return clk.Sleep(ctx, d)
		}})
	runRounds(t, p, clk)

	live, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if live.Revision != rev(1, 4) {
		t.Fatalf("the store holds %v after the outside write, want (1,4)", live.Revision)
	}
	reps := up.got()
	if len(reps) != 5 {
		t.Fatalf("reports %d", len(reps))
	}
	if reps[2].Applied == rev(1, 4) && reps[2].StoreError == "" && logs.count("state_drift") == 0 {
		t.Error("round 3 reported (1,4) with no drift seen")
	}
	if last := reps[4]; last.Applied != rev(1, 4) || last.StoreError != "" {
		t.Errorf("last report %+v", last)
	}
	if logs.count("state_drift") != 1 {
		t.Errorf("state_drift lines: %d, want 1", logs.count("state_drift"))
	}
}

// TestPullerClearsRefusalAfterRecovery: a restore to an older revision is refused, then the latest
// spec is served again. The reports after that carry no refusal.
func TestPullerClearsRefusalAfterRecovery(t *testing.T) {
	var latest mgmtapi.SpecBundle
	h := newHarnessWith(t, 5, func(f *fx) (mgmtapi.SpecBundle, *State) {
		cur, items := f.base()
		latest = f.bundle(rev(1, 5), items, []spec.Retired{{Name: "r", Revision: rev(1, 3)}})
		return f.bundle(rev(1, 4), items[:1], nil), cur
	}, nil)
	sleeps := 0
	inner := h.clk.Sleep
	h.p.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		sleeps++
		if sleeps == 2 {
			h.up.set(latest)
		}
		return inner(ctx, d)
	}
	runRounds(t, h.p, h.clk)
	reps := h.up.got()
	if len(reps) != 5 {
		t.Fatalf("reports %d", len(reps))
	}
	for i, r := range reps {
		wantRefusal := i < 2
		if (r.LastRefusal != nil) != wantRefusal {
			t.Errorf("report %d: lastRefusal %+v, want present=%v", i, r.LastRefusal, wantRefusal)
		}
	}
}

func baseNext(f *fx, cur *State, items []item) *State {
	next, _, err := Accept(cur, f.bundle(rev(1, 6), append(slices.Clone(items), f.item(f.cell("d", rev(1, 6), false))),
		[]spec.Retired{{Name: "r", Revision: rev(1, 3)}}), testEnv, f.keys())
	if err != nil {
		f.t.Fatal(err)
	}
	return next
}

func TestStoreSaveRefusesLowerRevision(t *testing.T) {
	f := newFx(t)
	cur, items := f.base()
	higher := baseNext(f, cur, items)
	c := fake.NewClientset()
	a := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	b := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	if err := b.Save(t.Context(), higher); err != nil {
		t.Fatal(err)
	}
	if err := a.Save(t.Context(), cur); !errors.Is(err, ErrStoreNewer) {
		t.Fatalf("Save of a lower revision: %v", err)
	}
	got, err := a.Load(t.Context())
	if err != nil || got.Revision != rev(1, 6) {
		t.Fatalf("stored %v, err %v", got.Revision, err)
	}
	if err := a.Save(t.Context(), higher); err != nil {
		t.Fatalf("Save of the same revision: %v", err)
	}
}

// conflictOnce makes the first update fail with Conflict after another writer changed the live
// ConfigMap with edit.
func conflictOnce(c *fake.Clientset, edit func(cm *corev1.ConfigMap)) {
	done := false
	c.PrependReactor("update", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if done {
			return false, nil, nil
		}
		done = true
		in := a.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		stored, _ := c.Tracker().Get(configMaps, in.Namespace, in.Name)
		other := stored.(*corev1.ConfigMap).DeepCopy()
		edit(other)
		other.ResourceVersion = "999"
		_ = c.Tracker().Update(configMaps, other, in.Namespace)
		return true, nil, apierrors.NewConflict(configMaps.GroupResource(), in.Name, errors.New("changed"))
	})
}

func TestStoreSaveConflictRereads(t *testing.T) {
	f := newFx(t)
	cur, items := f.base()
	higher := baseNext(f, cur, items)

	t.Run("a_higher_revision_arrives", func(t *testing.T) {
		c := fake.NewClientset()
		s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
		if err := s.Save(t.Context(), cur); err != nil {
			t.Fatal(err)
		}
		conflictOnce(c, func(cm *corev1.ConfigMap) {
			cm.Data = map[string]string{SpecKey: string(higher.SpecEnvelope)}
			for n, raw := range higher.Records {
				cm.Data[n+RecordSuffix] = string(raw)
			}
			cm.Annotations[AnnotationCounter] = "6"
		})
		if err := s.Save(t.Context(), cur); !errors.Is(err, ErrStoreNewer) {
			t.Fatalf("Save: %v", err)
		}
		got, _ := s.Load(t.Context())
		if got.Revision != rev(1, 6) {
			t.Errorf("stored %v", got.Revision)
		}
	})
	t.Run("an_unrelated_change_arrives", func(t *testing.T) {
		c := fake.NewClientset()
		s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
		if err := s.Save(t.Context(), cur); err != nil {
			t.Fatal(err)
		}
		conflictOnce(c, func(cm *corev1.ConfigMap) { cm.Labels = map[string]string{"x": "y"} })
		if err := s.Save(t.Context(), higher); err != nil {
			t.Fatalf("Save: %v", err)
		}
		got, _ := s.Load(t.Context())
		if got.Revision != rev(1, 6) {
			t.Errorf("stored %v", got.Revision)
		}
	})
}

func TestStoreSaveDropsStaleKeys(t *testing.T) {
	f := newFx(t)
	cur, items := f.base()
	dropped, _, err := Accept(cur, f.bundle(rev(1, 6), items[1:], []spec.Retired{{Name: "a", Revision: rev(1, 2)}, {Name: "r", Revision: rev(1, 3)}}), testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientset()
	s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	for _, st := range []*State{cur, dropped} {
		if err := s.Save(t.Context(), st); err != nil {
			t.Fatal(err)
		}
	}
	cm, _ := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	if _, stale := cm.Data["a"+RecordSuffix]; stale {
		t.Fatal("the record of a dropped cell stays in the ConfigMap")
	}
	if _, err := s.Load(t.Context()); err != nil {
		t.Fatalf("Load after the drop: %v", err)
	}
}

func TestStoreAnnotationAloneKeepsState(t *testing.T) {
	f := newFx(t)
	cur, _ := f.base()
	c := fake.NewClientset()
	var logs syncBuffer
	s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(&logs))
	if err := s.Save(t.Context(), cur); err != nil {
		t.Fatal(err)
	}
	cm, _ := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	cm.Annotations[AnnotationKeySHA] = "0000"
	if _, err := c.CoreV1().ConfigMaps(testNS).Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(t.Context())
	if err != nil || got.Revision != cur.Revision || len(got.Marks) != 4 {
		t.Fatalf("Load: %+v, %v", got, err)
	}
	if logs.count("state_reset") != 0 {
		t.Error("an annotation change reset the state")
	}
	if _, clean, err := s.Peek(t.Context()); err != nil || clean {
		t.Errorf("Peek clean=%v err=%v, want not clean", clean, err)
	}
}

func TestStoreStrayKeysAreNotClean(t *testing.T) {
	f := newFx(t)
	cur, _ := f.base()
	for name, edit := range map[string]func(cm *corev1.ConfigMap){
		"stray_data_key":    func(cm *corev1.ConfigMap) { cm.Data["notes.txt"] = "x" },
		"unindexed_record":  func(cm *corev1.ConfigMap) { cm.Data["zzz"+RecordSuffix] = "x" },
		"binary_data":       func(cm *corev1.ConfigMap) { cm.BinaryData = map[string][]byte{"z" + RecordSuffix: {1}} },
		"annotation_change": func(cm *corev1.ConfigMap) { cm.Annotations[AnnotationCounter] = "9" },
	} {
		t.Run(name, func(t *testing.T) {
			c := fake.NewClientset()
			s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
			if err := s.Save(t.Context(), cur); err != nil {
				t.Fatal(err)
			}
			if _, clean, err := s.Peek(t.Context()); err != nil || !clean {
				t.Fatalf("fresh Peek clean=%v err=%v", clean, err)
			}
			cm, _ := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
			edit(cm)
			if _, err := c.CoreV1().ConfigMaps(testNS).Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, clean, err := s.Peek(t.Context()); err != nil || clean {
				t.Errorf("Peek clean=%v err=%v, want not clean", clean, err)
			}
			if got, err := s.Load(t.Context()); err != nil || got.Revision != cur.Revision {
				t.Errorf("Load: %v, %v", got, err)
			}
		})
	}
}

func TestPullerRewritesStrayKeys(t *testing.T) {
	f := newFx(t)
	b := firstBundle(f, rev(1, 4))
	client := fake.NewClientset()
	store := NewConfigMapStore(client, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	up := newUpstream(t, b, nil)
	clk := newClock(4)
	sleeps := 0
	p := NewPuller(PullerConfig{Client: up.client, BaseURL: up.url, Env: testEnv, Keys: f.keys(), Store: store,
		Log: newLog(io.Discard), Now: clk.Now, Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps++
			if sleeps == 1 {
				cm, _ := client.CoreV1().ConfigMaps(testNS).Get(ctx, testName, metav1.GetOptions{})
				cm.Data["notes.txt"] = "x"
				cm.BinaryData = map[string][]byte{"q" + RecordSuffix: {1}}
				_, _ = client.CoreV1().ConfigMaps(testNS).Update(ctx, cm, metav1.UpdateOptions{})
			}
			return clk.Sleep(ctx, d)
		}})
	runRounds(t, p, clk)
	cm, _ := client.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	if _, ok := cm.Data["notes.txt"]; ok || len(cm.BinaryData) != 0 {
		t.Fatalf("stray keys stay: %v %v", cm.Data, cm.BinaryData)
	}
}

func TestPullerReportsStateUnverifiable(t *testing.T) {
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 2)), nil }, nil)
	h.store.loadErr = fmt.Errorf("%w: tampered", ErrStateUnverifiable)
	runRounds(t, h.p, h.clk)
	if h.p.Ready() {
		t.Fatal("Ready")
	}
	if h.up.hits.Load() != 0 {
		t.Error("pulled with an unverifiable state")
	}
	reps := h.up.got()
	if len(reps) != 3 {
		t.Fatalf("reports %d", len(reps))
	}
	for _, r := range reps {
		if r.StoreError != mgmtapi.ReasonStateUnverifiable {
			t.Errorf("report %+v", r)
		}
	}
}

func TestPullerLoadHasDeadline(t *testing.T) {
	store := &memStore{blockLoad: true}
	clk := newClock(2)
	p := NewPuller(PullerConfig{Client: http.DefaultClient, BaseURL: "https://127.0.0.1:1", Env: testEnv, Store: store,
		RoundTimeout: 50 * time.Millisecond, Log: newLog(io.Discard), Now: clk.Now, Sleep: clk.Sleep})
	start := time.Now()
	runRounds(t, p, clk)
	if time.Since(start) > 5*time.Second || store.loads != 2 || p.Ready() {
		t.Fatalf("loads %d, ready %v, took %v", store.loads, p.Ready(), time.Since(start))
	}
}

// A save that commits and still returns an error must not let a later, lower revision replace it.
func TestPullerAdoptsStoredStateAfterLostSaveAnswer(t *testing.T) {
	var lower mgmtapi.SpecBundle
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) {
		cur, items := f.base()
		lower = f.bundle(rev(1, 6), items, []spec.Retired{{Name: "r", Revision: rev(1, 3)}})
		next := f.bundle(rev(1, 7), append(slices.Clone(items), f.item(f.cell("d", rev(1, 7), false))), []spec.Retired{{Name: "r", Revision: rev(1, 3)}})
		return next, cur
	}, nil)
	h.store.commitThenFail = true
	inner := h.clk.Sleep
	n := 0
	h.p.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		n++
		if n == 1 {
			h.up.set(lower)
			h.store.mu.Lock()
			h.store.commitThenFail = false
			h.store.mu.Unlock()
		}
		return inner(ctx, d)
	}
	runRounds(t, h.p, h.clk)
	if got, _ := h.store.Load(t.Context()); got.Revision != rev(1, 7) {
		t.Fatalf("the store holds %v, want (1,7)", got.Revision)
	}
	reps := h.up.got()
	if last := reps[len(reps)-1]; last.Applied != rev(1, 7) || last.LastRefusal == nil || last.LastRefusal.Reason != mgmtapi.ReasonRevisionOld {
		t.Errorf("last report %+v", last)
	}
}

func refusalBundle(f *fx, kind int) mgmtapi.SpecBundle {
	_, items := f.base()
	switch kind {
	case 0:
		return f.bundle(rev(1, 4), items[:1], nil)
	case 1:
		return f.bundle(rev(1, 3), items[:1], nil)
	}
	b := f.bundle(rev(1, 6), items, []spec.Retired{{Name: "r", Revision: rev(1, 3)}})
	b.Spec = strip(f.t, b.Spec)
	return b
}

func TestPullerRefusalLogsEveryChange(t *testing.T) {
	for name, seq := range map[string][]int{
		"reason_a_b_a":        {0, 2, 0},
		"revision_changes":    {0, 1},
		"same_stays_silent":   {0, 0, 0},
		"revision_back_again": {0, 1, 0},
	} {
		want := map[string]int{"reason_a_b_a": 3, "revision_changes": 2, "same_stays_silent": 1, "revision_back_again": 3}[name]
		t.Run(name, func(t *testing.T) {
			var f *fx
			h := newHarnessWith(t, len(seq), func(x *fx) (mgmtapi.SpecBundle, *State) {
				f = x
				cur, _ := x.base()
				return refusalBundle(x, seq[0]), cur
			}, nil)
			inner := h.clk.Sleep
			n := 0
			h.p.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
				n++
				if n < len(seq) {
					h.up.set(refusalBundle(f, seq[n]))
				}
				return inner(ctx, d)
			}
			runRounds(t, h.p, h.clk)
			if got := h.logs.count("spec refused"); got != want {
				t.Errorf("refusal lines %d, want %d", got, want)
			}
		})
	}
}

func TestPullerDefaultsAndTransport(t *testing.T) {
	p := NewPuller(PullerConfig{})
	if p.cfg.Interval != 10*time.Second || p.cfg.MinBackoff != time.Second || p.cfg.MaxBackoff != 30*time.Second || p.cfg.RoundTimeout != 15*time.Second {
		t.Errorf("defaults %v %v %v %v", p.cfg.Interval, p.cfg.MinBackoff, p.cfg.MaxBackoff, p.cfg.RoundTimeout)
	}
	tr, ok := NewClient(&tls.Config{}).Transport.(*http2.Transport)
	if !ok || tr.ReadIdleTimeout != 15*time.Second || tr.PingTimeout != 10*time.Second {
		t.Fatalf("transport %+v", tr)
	}
}

func TestPullerBackoffBounds(t *testing.T) {
	p := NewPuller(PullerConfig{})
	distinct := map[time.Duration]bool{}
	for range 200 {
		d := p.backoff(1)
		if d < time.Second || d > 2*time.Second {
			t.Fatalf("first backoff %v", d)
		}
		distinct[d] = true
		if d := p.backoff(3); d < 4*time.Second || d > 8*time.Second {
			t.Fatalf("third backoff %v", d)
		}
		if d := p.backoff(40); d != 30*time.Second {
			t.Fatalf("capped backoff %v", d)
		}
	}
	if len(distinct) < 10 {
		t.Errorf("backoff has no jitter: %d distinct values", len(distinct))
	}
}

func TestPullerBackoffResetsAfterSuccess(t *testing.T) {
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 2)), nil }, nil)
	h.up.failGet.Store(true)
	inner := h.clk.Sleep
	n := 0
	h.p.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		n++
		h.up.failGet.Store(n == 2)
		return inner(ctx, d)
	}
	runRounds(t, h.p, h.clk)
	s := h.clk.slept()
	if len(s) != 3 || s[0] < time.Second || s[0] > 2*time.Second || s[1] != 10*time.Second || s[2] < time.Second || s[2] > 2*time.Second {
		t.Fatalf("waits %v", s)
	}
}

func TestPullerReportHasOwnDeadline(t *testing.T) {
	h := newHarnessWith(t, 1, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 2)), nil },
		func(c *PullerConfig) { c.RoundTimeout = 600 * time.Millisecond })
	h.up.delay.Store(int64(400 * time.Millisecond))
	runRounds(t, h.p, h.clk)
	if len(h.up.got()) != 1 {
		t.Fatalf("reports %d: the report shares the deadline of the pull", len(h.up.got()))
	}
}

// ctxHandler keeps the span context that each log record carries.
type ctxHandler struct {
	slog.Handler
	mu   *sync.Mutex
	seen map[string]trace.SpanContext
}

func (h ctxHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	h.seen[r.Message] = trace.SpanContextFromContext(ctx)
	h.mu.Unlock()
	return h.Handler.Handle(ctx, r)
}

func TestPullerEmitsSpansAndTraceContext(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	ch := ctxHandler{Handler: slog.NewJSONHandler(io.Discard, nil), mu: &sync.Mutex{}, seen: map[string]trace.SpanContext{}}
	var up *upstream
	h := newHarnessWith(t, 2, func(f *fx) (mgmtapi.SpecBundle, *State) {
		cur, _ := f.base()
		return refusalBundle(f, 0), cur
	}, func(c *PullerConfig) { c.Tracer = tp.Tracer("test"); c.Log = slog.New(ch) })
	up = h.up
	_ = up
	runRounds(t, h.p, h.clk)

	rounds := map[trace.SpanID]trace.TraceID{}
	children := map[string]int{}
	for _, s := range rec.Ended() {
		if s.Name() == "envd.round" {
			rounds[s.SpanContext().SpanID()] = s.SpanContext().TraceID()
		}
	}
	for _, s := range rec.Ended() {
		if _, ok := rounds[s.Parent().SpanID()]; ok {
			children[s.Name()]++
		}
	}
	if len(rounds) != 2 {
		t.Fatalf("round spans %d", len(rounds))
	}
	for _, name := range []string{"envd.fetch", "envd.accept", "envd.report", "envd.sync"} {
		if children[name] != 2 {
			t.Errorf("child spans %q: %d, want 2", name, children[name])
		}
	}
	ch.mu.Lock()
	sc := ch.seen["spec refused"]
	ch.mu.Unlock()
	if !sc.IsValid() || rounds[sc.SpanID()] != sc.TraceID() {
		t.Errorf("the refusal log line carries span context %v, not that of a round", sc)
	}
}
