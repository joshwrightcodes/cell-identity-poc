package envd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

var stepT0 = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

// stepItem is one step of a bundle: the signed envelope and the entry that indexes it.
type stepItem struct {
	name  string
	env   []byte
	entry spec.StepEntry
}

// stepFor signs a step for cell. mod changes the step before it is signed.
func (f *fx) stepFor(cell string, mod func(*step.Step)) stepItem {
	f.t.Helper()
	id := step.NewID()
	s := step.Step{ID: id, Env: testEnv, Cell: cell, Kind: step.KindCellCreate, Version: 1, KeyEpoch: 1,
		IssuedAt: stepT0, ExpiresAt: stepT0.Add(step.DefaultTTL),
		Cluster:         step.ClusterRef{PodSubnet: "10.20.0.0/16", ServiceSubnet: "10.21.0.0/16", Issuer: "https://" + cell + ".example:6443"},
		BootstrapSHA256: strings.Repeat("cd", 32)}
	if mod != nil {
		mod(&s)
	}
	env, err := step.Sign(s, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	_, payload, err := step.Verify(env, f.keys())
	if err != nil {
		f.t.Fatal(err)
	}
	return stepItem{name: cell, env: env, entry: spec.StepEntry{Name: cell, StepID: s.ID, StepSHA256: step.PayloadSHA256(payload)}}
}

// bundleSteps is f.bundle with a step index and the step envelopes.
func (f *fx) bundleSteps(r spec.Revision, items []item, retired []spec.Retired, steps ...stepItem) mgmtapi.SpecBundle {
	f.t.Helper()
	s := spec.Spec{Env: testEnv, Revision: r, Retired: retired}
	slices.SortFunc(items, func(a, b item) int { return compareStr(a.entry.Name, b.entry.Name) })
	for _, it := range items {
		s.Cells = append(s.Cells, it.entry)
	}
	slices.SortFunc(steps, func(a, b stepItem) int { return compareStr(a.name, b.name) })
	for _, st := range steps {
		s.Steps = append(s.Steps, st.entry)
	}
	raw, err := spec.Sign(s, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	b := mgmtapi.SpecBundle{Spec: raw, Records: map[string]json.RawMessage{}}
	for _, it := range items {
		b.Records[it.name] = it.env
	}
	if len(steps) > 0 {
		b.Steps = map[string]json.RawMessage{}
	}
	for _, st := range steps {
		b.Steps[st.name] = st.env
	}
	return b
}

func TestAcceptStepsAccepted(t *testing.T) {
	f := newFx(t)
	cur, items := f.base()
	st := f.stepFor("d", nil)
	b := f.bundleSteps(rev(1, 6), slices.Clone(items), []spec.Retired{{Name: "r", Revision: rev(1, 3)}}, st)
	got, changed, err := Accept(cur, b, testEnv, f.keys())
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !bytes.Equal(got.Steps["d"], st.env) || len(got.Steps) != 1 || !got.stepsVerified {
		t.Fatalf("steps %v verified %v", maps.Keys(got.Steps), got.stepsVerified)
	}
	if len(cur.Steps) != 0 {
		t.Fatal("Accept changed cur")
	}
}

// An unchanged spec still checks the steps of the bundle and returns them.
func TestAcceptUnchangedVerifiesSteps(t *testing.T) {
	f := newFx(t)
	_, items := f.base()
	retired := []spec.Retired{{Name: "r", Revision: rev(1, 3)}}
	st := f.stepFor("d", nil)
	b := f.bundleSteps(rev(1, 6), slices.Clone(items), retired, st)
	cur, _, err := Accept(Empty(), b, testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	// A restart leaves a state with the same spec and no steps.
	loaded := cloneState(cur)
	loaded.Steps, loaded.stepsVerified = map[string][]byte{}, false

	got, changed, err := Accept(loaded, b, testEnv, f.keys())
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !bytes.Equal(got.Steps["d"], st.env) || !got.stepsVerified {
		t.Fatalf("steps %v verified %v", maps.Keys(got.Steps), got.stepsVerified)
	}
	if len(loaded.Steps) != 0 || loaded.stepsVerified {
		t.Fatal("Accept changed cur")
	}

	other := f.stepFor("d", func(s *step.Step) { s.Cluster.Issuer = "https://other.example:6443" })
	bad := b
	bad.Steps = map[string]json.RawMessage{"d": other.env}
	var r *Refused
	_, _, err = Accept(loaded, bad, testEnv, f.keys())
	if !errors.As(err, &r) || r.Reason != mgmtapi.ReasonStepInvalid {
		t.Fatalf("tampered envelope at an unchanged spec: %v", err)
	}
}

func TestAcceptRefusesSteps(t *testing.T) {
	f := newFx(t)
	other := newFx(t)
	cur, items := f.base()
	retired := []spec.Retired{{Name: "r", Revision: rev(1, 3)}}
	next := rev(1, 6)
	bundle := func(steps ...stepItem) mgmtapi.SpecBundle {
		return f.bundleSteps(next, slices.Clone(items), retired, steps...)
	}
	for _, tc := range []struct {
		name, reason string
		bundle       func() mgmtapi.SpecBundle
	}{
		{"step_missing_envelope", mgmtapi.ReasonStepInvalid, func() mgmtapi.SpecBundle {
			b := bundle(f.stepFor("d", nil))
			b.Steps = nil
			return b
		}},
		{"step_digest", mgmtapi.ReasonStepInvalid, func() mgmtapi.SpecBundle {
			st := f.stepFor("d", nil)
			st.entry.StepSHA256 = strings.Repeat("0", 64)
			return bundle(st)
		}},
		{"step_id", mgmtapi.ReasonStepInvalid, func() mgmtapi.SpecBundle {
			st := f.stepFor("d", nil)
			st.entry.StepID = strings.Repeat("0", 32)
			return bundle(st)
		}},
		{"step_other_cell", mgmtapi.ReasonStepInvalid, func() mgmtapi.SpecBundle {
			st := f.stepFor("e", nil)
			st.name, st.entry.Name = "d", "d"
			return bundle(st)
		}},
		{"step_other_env", mgmtapi.ReasonStepInvalid, func() mgmtapi.SpecBundle {
			return bundle(f.stepFor("d", func(s *step.Step) { s.Env = "prod" }))
		}},
		{"step_unsigned", mgmtapi.ReasonStepInvalid, func() mgmtapi.SpecBundle {
			return bundle(other.stepFor("d", nil))
		}},
		{"step_too_large", mgmtapi.ReasonStepInvalid, func() mgmtapi.SpecBundle {
			st := f.stepFor("d", nil)
			st.env = append(slices.Clone(st.env), bytes.Repeat([]byte(" "), MaxStepBytes)...)
			return bundle(st)
		}},
		{"step_extra", mgmtapi.ReasonStepUnindexed, func() mgmtapi.SpecBundle {
			b := bundle(f.stepFor("d", nil))
			b.Steps["zzz"] = f.stepFor("zzz", nil).env
			return b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := cloneState(cur)
			got, changed, err := Accept(cur, tc.bundle(), testEnv, f.keys())
			var r *Refused
			if !errors.As(err, &r) || r.Reason != tc.reason {
				t.Fatalf("err = %v, want reason %q", err, tc.reason)
			}
			if got != nil || changed || !reflectEqual(cur, before) {
				t.Error("a refusal returned a state or changed cur")
			}
		})
	}
	t.Run("with_steps", func(t *testing.T) {
		if _, changed, err := Accept(cur, bundle(f.stepFor("d", nil)), testEnv, f.keys()); err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
	})
	t.Run("step_over_limit_but_size_ok", func(t *testing.T) {
		st := f.stepFor("d", nil)
		st.env = append(slices.Clone(st.env), bytes.Repeat([]byte(" "), 1024)...)
		if _, _, err := Accept(cur, bundle(st), testEnv, f.keys()); err != nil {
			t.Fatalf("padding below the limit: %v", err)
		}
	})
}

// A step envelope that the spec stops indexing leaves the state.
func TestAcceptDropsClosedSteps(t *testing.T) {
	f := newFx(t)
	_, items := f.base()
	retired := []spec.Retired{{Name: "r", Revision: rev(1, 3)}}
	cur, _, err := Accept(Empty(), f.bundleSteps(rev(1, 6), slices.Clone(items), retired, f.stepFor("d", nil)), testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	got, changed, err := Accept(cur, f.bundleSteps(rev(1, 7), slices.Clone(items), retired), testEnv, f.keys())
	if err != nil || !changed || len(got.Steps) != 0 || !got.stepsVerified {
		t.Fatalf("changed=%v err=%v steps=%d", changed, err, len(got.Steps))
	}
}

type managerLog struct{ managers []string }

func watchManagers(c *fake.Clientset) *managerLog {
	l := &managerLog{}
	c.PrependReactor("create", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		l.managers = append(l.managers, "create:"+a.(ktesting.CreateActionImpl).CreateOptions.FieldManager)
		return false, nil, nil
	})
	c.PrependReactor("update", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		l.managers = append(l.managers, "update:"+a.(ktesting.UpdateActionImpl).UpdateOptions.FieldManager)
		return false, nil, nil
	})
	return l
}

func stepsState(t *testing.T, f *fx, counter uint64, steps ...stepItem) *State {
	t.Helper()
	_, items := f.base()
	st, _, err := Accept(Empty(), f.bundleSteps(rev(1, counter), slices.Clone(items), []spec.Retired{{Name: "r", Revision: rev(1, 3)}}, steps...), testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestStepStoreRoundTrip(t *testing.T) {
	f := newFx(t)
	c := fake.NewClientset()
	mgr := watchManagers(c)
	pin := KeyFingerprint(f.keys())
	s := NewStepStore(c, "cell-controller-system", "cell-steps", pin, slog.New(slog.DiscardHandler))
	d, e := f.stepFor("d", nil), f.stepFor("e", nil)
	st := stepsState(t, f, 6, d, e)
	if err := s.Save(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	cm, err := c.CoreV1().ConfigMaps("cell-controller-system").Get(t.Context(), "cell-steps", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(cm.Data)); !slices.Equal(got, []string{"d.step.json", "e.step.json", "spec-envelope.json"}) {
		t.Fatalf("keys %v", got)
	}
	if cm.Data["d.step.json"] != string(d.env) || cm.Data["e.step.json"] != string(e.env) || cm.Data[SpecKey] != string(st.SpecEnvelope) {
		t.Fatal("data differs from the state")
	}
	if cm.Labels["poc.internal/made-by"] != "envd" || cm.Annotations[AnnotationEpoch] != "1" || cm.Annotations[AnnotationCounter] != "6" ||
		cm.Annotations[AnnotationKeySHA] != pin {
		t.Fatalf("labels %v annotations %v", cm.Labels, cm.Annotations)
	}

	// The update replaces the whole data.
	st2 := stepsState(t, f, 7, e)
	if err := s.Save(t.Context(), st2); err != nil {
		t.Fatal(err)
	}
	cm, _ = c.CoreV1().ConfigMaps("cell-controller-system").Get(t.Context(), "cell-steps", metav1.GetOptions{})
	if got := slices.Sorted(maps.Keys(cm.Data)); !slices.Equal(got, []string{"e.step.json", "spec-envelope.json"}) || cm.Annotations[AnnotationCounter] != "7" ||
		cm.Labels["poc.internal/made-by"] != "envd" {
		t.Fatalf("keys %v annotations %v labels %v", got, cm.Annotations, cm.Labels)
	}
	if !slices.Equal(mgr.managers, []string{"create:envd", "update:envd"}) {
		t.Fatalf("field managers %v", mgr.managers)
	}

	if err := s.Save(t.Context(), Empty()); err == nil {
		t.Fatal("a state with no spec was written")
	}
}

// The steps ConfigMap is a separate object from the records ConfigMap, and a spec with steps
// does not make the records store refuse its own content.
func TestStepStoreAfterRecords(t *testing.T) {
	f := newFx(t)
	c := fake.NewClientset()
	records := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	steps := NewStepStore(c, testNS, "cell-steps", KeyFingerprint(f.keys()), newLog(io.Discard))
	st := stepsState(t, f, 6, f.stepFor("d", nil))
	if err := records.Save(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	if err := steps.Save(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	cm, _ := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	for k := range cm.Data {
		if strings.HasSuffix(k, StepSuffix) {
			t.Fatalf("records ConfigMap holds %s", k)
		}
	}
	got, clean, err := records.Peek(t.Context())
	if err != nil || !clean || got.Revision != st.Revision {
		t.Fatalf("peek: %v clean=%v", err, clean)
	}
}

func TestStoreLoadsSpecWithSteps(t *testing.T) {
	f := newFx(t)
	c := fake.NewClientset()
	s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	st := stepsState(t, f, 6, f.stepFor("d", nil))
	if err := s.Save(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(t.Context())
	if err != nil || got.Revision != st.Revision || got.stepsVerified || len(got.Steps) != 0 {
		t.Fatalf("load: %v %+v", err, got)
	}
	if _, clean, err := s.Peek(t.Context()); err != nil || !clean {
		t.Fatalf("peek: %v clean=%v", err, clean)
	}
}

func statusCM(raw string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "step-status", Namespace: "cell-controller-system"},
		Data: map[string]string{StatusKey: raw}}
}

func goodStatus(id, cell string) mgmtapi.StepStatus {
	return mgmtapi.StepStatus{ID: id, Cell: cell, State: mgmtapi.StepCreating, Stage: mgmtapi.StageCreating, Attempts: 1,
		UpdatedAt: stepT0}
}

func statusBody(t *testing.T, at time.Time, steps ...mgmtapi.StepStatus) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"at": at, "steps": steps})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestStepStatusMalformedIgnored(t *testing.T) {
	id1, id2 := strings.Repeat("a1", 16), strings.Repeat("b2", 16)
	good := goodStatus(id1, "d")
	var many []mgmtapi.StepStatus
	for i := range 40 {
		many = append(many, goodStatus(strings.Repeat("c", 31)+string(rune('a'+i%6)), "d"))
	}
	t.Run("rows", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			cm      *corev1.ConfigMap
			want    int
			wantAt  bool
			wantErr bool
		}{
			{"absent", nil, 0, false, false},
			{"no_key", &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "step-status", Namespace: "cell-controller-system"}}, 0, false, false},
			{"not_json", statusCM("not json"), 0, false, false},
			{"trailing_data", statusCM(statusBody(t, stepT0, good) + "{}"), 0, false, false},
			{"unknown_field", statusCM(`{"at":"2026-11-12T09:00:00Z","steps":[],"extra":1}`), 0, false, false},
			{"unknown_entry_field", statusCM(`{"at":"2026-11-12T09:00:00Z","steps":[{"id":"` + id1 + `","cell":"d","state":"done","bogus":1}]}`), 0, false, false},
			{"bad_at", statusCM(`{"at":"yesterday","steps":[]}`), 0, false, false},
			{"bad_entry_dropped", statusCM(statusBody(t, stepT0, good, mgmtapi.StepStatus{ID: "short", Cell: "d", State: mgmtapi.StepDone},
				mgmtapi.StepStatus{ID: id2, Cell: "e", State: "nonsense"})), 1, true, false},
			{"huge_detail_dropped", statusCM(statusBody(t, stepT0, good, mgmtapi.StepStatus{ID: id2, Cell: "e", State: mgmtapi.StepFailed, Detail: strings.Repeat("x", 70<<10)})), 0, false, false},
			{"over_32", statusCM(statusBody(t, stepT0, many...)), 32, true, false},
			{"valid", statusCM(statusBody(t, stepT0, good)), 1, true, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := fake.NewClientset()
				if tc.cm != nil {
					if _, err := c.CoreV1().ConfigMaps("cell-controller-system").Create(t.Context(), tc.cm, metav1.CreateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				got, at, err := NewConfigMapStepStatus(c, "cell-controller-system", "step-status", newLog(io.Discard)).Read(t.Context())
				if err != nil || len(got) != tc.want || at.IsZero() == tc.wantAt {
					t.Fatalf("got %d entries at %v err %v, want %d (at set %v)", len(got), at, err, tc.want, tc.wantAt)
				}
			})
		}
	})
}

// memSteps records the saves of the steps store.
type memSteps struct {
	mu       sync.Mutex
	saved    []*State
	failNext int
}

func (m *memSteps) Save(_ context.Context, s *State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext > 0 {
		m.failNext--
		return errors.New("apiserver unavailable")
	}
	m.saved = append(m.saved, s)
	return nil
}

func (m *memSteps) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.saved)
}

// stepBundle is the bundle of cells a and b at revision r, plus one step for cell d.
func stepBundle(f *fx, r spec.Revision, steps ...stepItem) mgmtapi.SpecBundle {
	return f.bundleSteps(r, []item{f.item(f.cell("a", r, false)), f.item(f.cell("b", r, false))}, nil, steps...)
}

func withSteps(ms *memSteps, ss StepStatusSource) func(*PullerConfig) {
	return func(c *PullerConfig) {
		c.Steps = ms
		c.StepStatus = ss
	}
}

func TestPullerStepSaveFailure(t *testing.T) {
	ms := &memSteps{failNext: 1}
	var d stepItem
	h := newHarnessWith(t, 2, func(f *fx) (mgmtapi.SpecBundle, *State) {
		d = f.stepFor("d", nil)
		return stepBundle(f, rev(1, 4), d), nil
	}, withSteps(ms, nil))
	runRounds(t, h.p, h.clk)
	reps := h.up.got()
	if len(reps) != 2 {
		t.Fatalf("reports %d", len(reps))
	}
	if reps[0].StoreError != mgmtapi.ReasonStoreFailed {
		t.Errorf("round 1 store error %q, want %q", reps[0].StoreError, mgmtapi.ReasonStoreFailed)
	}
	if reps[1].StoreError != "" || reps[1].Applied != rev(1, 4) {
		t.Errorf("round 2 report %+v", reps[1])
	}
	if ms.count() != 1 || !bytes.Equal(ms.saved[0].Steps["d"], d.env) {
		t.Fatalf("step saves %d", ms.count())
	}
	if !h.p.Ready() {
		t.Error("not Ready after the retry")
	}
	if got := h.store.saves(); len(got) != 2 {
		t.Errorf("record saves %v: the failed round must retry from the old state", got)
	}
}

// A new process writes the steps ConfigMap once, from the first bundle, although the stored records
// already hold the revision. It does not write again for the same content.
func TestPullerWritesStepsAfterRestart(t *testing.T) {
	ms := &memSteps{}
	var d stepItem
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) {
		d = f.stepFor("d", nil)
		b := stepBundle(f, rev(1, 4), d)
		loaded, _, err := Accept(Empty(), b, testEnv, f.keys())
		if err != nil {
			t.Fatal(err)
		}
		loaded.Steps, loaded.stepsVerified = map[string][]byte{}, false
		return b, loaded
	}, withSteps(ms, nil))
	runRounds(t, h.p, h.clk)
	if got := h.store.saves(); len(got) != 0 {
		t.Fatalf("record saves %v for an unchanged spec", got)
	}
	if ms.count() != 1 || !bytes.Equal(ms.saved[0].Steps["d"], d.env) {
		t.Fatalf("step saves %d, want one with the step", ms.count())
	}

	// The same content again, and then a new step set at the same revision of the records.
	h.up.set(stepBundle(h.f, rev(1, 4), d))
	h.clk.mu.Lock()
	h.clk.sleeps, h.clk.stop = nil, 1
	h.clk.mu.Unlock()
	runRounds(t, h.p, h.clk)
	if ms.count() != 1 {
		t.Fatalf("step saves %d after the same content", ms.count())
	}
}

// A state that syncStore adopted holds no verified steps. It writes none, and it does not mark the
// revision as written, so the next pull of the same revision still writes them.
func TestPullerAdoptDoesNotBlankSteps(t *testing.T) {
	f := newFx(t)
	ms := &memSteps{}
	cur, _, err := Accept(Empty(), stepBundle(f, rev(1, 4)), testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	d := f.stepFor("d", nil)
	b := stepBundle(f, rev(1, 6), d)
	stored, _, err := Accept(cur, b, testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	stored.Steps, stored.stepsVerified = map[string][]byte{}, false
	store := &memStore{state: stored}
	p := NewPuller(PullerConfig{Env: testEnv, Keys: f.keys(), Store: store, Steps: ms, Log: newLog(io.Discard)})
	p.state = cur

	p.syncStore(t.Context())
	if p.state.Revision != rev(1, 6) || p.state.stepsVerified || ms.count() != 0 {
		t.Fatalf("adopted revision %v verified %v step saves %d", p.state.Revision, p.state.stepsVerified, ms.count())
	}
	p.accept(t.Context(), t.Context(), b)
	if ms.count() != 1 || !bytes.Equal(ms.saved[0].Steps["d"], d.env) {
		t.Fatalf("step saves %d after the pull of the adopted revision", ms.count())
	}
	p.accept(t.Context(), t.Context(), b)
	if ms.count() != 1 {
		t.Fatalf("step saves %d for the same content", ms.count())
	}
}

// A step that the spec drops, or a new step, changes the content and writes again at the same revision of cells.
func TestPullerRewritesStepsOnChange(t *testing.T) {
	f := newFx(t)
	ms := &memSteps{}
	store := &memStore{}
	p := NewPuller(PullerConfig{Env: testEnv, Keys: f.keys(), Store: store, Steps: ms, Log: newLog(io.Discard)})
	p.state = Empty()
	d, e := f.stepFor("d", nil), f.stepFor("e", nil)
	for i, b := range []mgmtapi.SpecBundle{stepBundle(f, rev(1, 4), d), stepBundle(f, rev(1, 5), d, e), stepBundle(f, rev(1, 6))} {
		p.accept(t.Context(), t.Context(), b)
		if ms.count() != i+1 {
			t.Fatalf("after bundle %d: step saves %d", i, ms.count())
		}
	}
	if len(ms.saved[2].Steps) != 0 || len(ms.saved[1].Steps) != 2 {
		t.Fatalf("steps of the saves: %d, %d", len(ms.saved[1].Steps), len(ms.saved[2].Steps))
	}
}

type fixedStatus struct {
	steps []mgmtapi.StepStatus
	at    time.Time
	err   error
}

func (s fixedStatus) Read(context.Context) ([]mgmtapi.StepStatus, time.Time, error) {
	return s.steps, s.at, s.err
}

func TestStepStatusForwarded(t *testing.T) {
	id1, id2 := strings.Repeat("a1", 16), strings.Repeat("b2", 16)
	at := stepT0.Add(time.Minute)
	run := func(src StepStatusSource) []mgmtapi.StatusReport {
		h := newHarnessWith(t, 2, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 4)), nil },
			withSteps(&memSteps{}, src))
		runRounds(t, h.p, h.clk)
		reps := h.up.got()
		if len(reps) != 2 {
			t.Fatalf("reports %d", len(reps))
		}
		return reps
	}
	t.Run("forwarded", func(t *testing.T) {
		want := []mgmtapi.StepStatus{goodStatus(id1, "d"), goodStatus(id2, "e")}
		for i, r := range run(fixedStatus{steps: want, at: at}) {
			if !reflectEqual(r.Steps, want) || !r.StepsAt.Equal(at) {
				t.Errorf("report %d: steps %+v at %v", i, r.Steps, r.StepsAt)
			}
		}
	})
	for name, src := range map[string]StepStatusSource{
		"empty":        fixedStatus{at: at},
		"read_error":   fixedStatus{err: errors.New("boom"), steps: []mgmtapi.StepStatus{goodStatus(id1, "d")}, at: at},
		"no_source":    nil,
		"nil_in_group": fixedStatus{},
	} {
		t.Run("absent_"+name, func(t *testing.T) {
			for i, r := range run(src) {
				raw, _ := json.Marshal(r)
				var m map[string]any
				_ = json.Unmarshal(raw, &m)
				if _, ok := m["steps"]; ok {
					t.Errorf("report %d has a steps key: %s", i, raw)
				}
				if _, ok := m["stepsAt"]; ok {
					t.Errorf("report %d has a stepsAt key: %s", i, raw)
				}
			}
		})
	}
}

// A status body that does not decode gives one log line in the window, however often envd reads it.
func TestStepStatusMalformedLogsOnce(t *testing.T) {
	c := fake.NewClientset()
	if _, err := c.CoreV1().ConfigMaps("cell-controller-system").Create(t.Context(), statusCM("not json"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	src := NewConfigMapStepStatus(c, "cell-controller-system", "step-status", newLog(&logs))
	for range 5 {
		if got, _, err := src.Read(t.Context()); err != nil || len(got) != 0 {
			t.Fatalf("read: %v %v", got, err)
		}
	}
	if n := logs.count("step status ignored"); n != 1 {
		t.Fatalf("log lines %d, want 1", n)
	}
}
