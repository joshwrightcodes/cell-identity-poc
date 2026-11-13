package envd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

func liveConfigMap(t *testing.T, c *fake.Clientset) *corev1.ConfigMap {
	t.Helper()
	cm, err := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return cm
}

// deadClient returns a client and URL of a management plane that is not reachable.
func deadClient() (*httptest.Server, func()) {
	srv := httptest.NewTLSServer(nil)
	return srv, srv.Close
}

// TestPullerLeavesForeignStoreUntilFirstAccept: the pin changes, so the stored state is signed by
// another key. While no spec is accepted, envd writes nothing, also across a restart. The first spec
// that verifies under the new pin replaces the store.
func TestPullerLeavesForeignStoreUntilFirstAccept(t *testing.T) {
	oldKey, newKey := newFx(t), newFx(t)
	old, _ := oldKey.base()
	client := fake.NewClientset()
	if err := NewConfigMapStore(client, testNS, testName, testEnv, oldKey.keys(), newLog(io.Discard)).Save(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	before := liveConfigMap(t, client).DeepCopy()
	store := func() Store {
		return NewConfigMapStore(client, testNS, testName, testEnv, newKey.keys(), newLog(io.Discard))
	}

	dead, closeDead := deadClient()
	hc, url := dead.Client(), dead.URL
	closeDead()
	for restart := range 2 {
		clk := newClock(3)
		p := NewPuller(PullerConfig{Client: hc, BaseURL: url, Env: testEnv, Keys: newKey.keys(), Store: store(),
			Log: newLog(io.Discard), Now: clk.Now, Sleep: clk.Sleep})
		runRounds(t, p, clk)
		if !reflect.DeepEqual(liveConfigMap(t, client).Data, before.Data) || !reflect.DeepEqual(liveConfigMap(t, client).Annotations, before.Annotations) {
			t.Fatalf("restart %d: envd wrote to the store before it accepted a spec", restart)
		}
		if _, err := store().Load(t.Context()); err != nil {
			t.Fatalf("restart %d: Load: %v", restart, err)
		}
	}

	up := newUpstream(t, firstBundle(newKey, rev(1, 2)), nil)
	clk := newClock(2)
	p := NewPuller(PullerConfig{Client: up.client, BaseURL: up.url, Env: testEnv, Keys: newKey.keys(), Store: store(),
		Log: newLog(io.Discard), Now: clk.Now, Sleep: clk.Sleep})
	runRounds(t, p, clk)
	got, err := store().Load(t.Context())
	if err != nil || got.Revision != rev(1, 2) {
		t.Fatalf("after the first accept: %v, %v", got, err)
	}
}

// TestPullerRecoversFromUnverifiableStore: the stored state carries the pin and does not verify.
// The puller still pulls, stays not Ready and reports state_unverifiable until the first accept,
// and that accept replaces the store with no manual deletion.
func TestPullerRecoversFromUnverifiableStore(t *testing.T) {
	f := newFx(t)
	cur, _ := f.base()
	client := fake.NewClientset()
	store := NewConfigMapStore(client, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	if err := store.Save(t.Context(), cur); err != nil {
		t.Fatal(err)
	}
	cm := liveConfigMap(t, client)
	cm.Data[SpecKey] = string(tamper(t, []byte(cm.Data[SpecKey]), func(p []byte) []byte { return append([]byte(" "), p...) }))
	if _, err := client.CoreV1().ConfigMaps(testNS).Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(t.Context()); err == nil {
		t.Fatal("the store should not verify")
	}

	// First a bundle that envd refuses: not Ready, state_unverifiable reported, store untouched.
	other := newFx(t)
	up := newUpstream(t, firstBundle(other, rev(1, 7)), nil)
	clk := newClock(2)
	p := NewPuller(PullerConfig{Client: up.client, BaseURL: up.url, Env: testEnv, Keys: f.keys(), Store: store,
		Log: newLog(io.Discard), Now: clk.Now, Sleep: clk.Sleep})
	runRounds(t, p, clk)
	if p.Ready() || up.hits.Load() != 2 {
		t.Fatalf("ready=%v pulls=%d", p.Ready(), up.hits.Load())
	}
	for i, r := range up.got() {
		if r.StoreError != mgmtapi.ReasonStateUnverifiable || (i > 0 && r.LastRefusal == nil) {
			t.Errorf("report %+v", r)
		}
	}

	// Then a bundle that verifies: accepted, saved, Ready.
	up.set(firstBundle(f, rev(1, 8)))
	clk = newClock(2)
	p = NewPuller(PullerConfig{Client: up.client, BaseURL: up.url, Env: testEnv, Keys: f.keys(), Store: store,
		Log: newLog(io.Discard), Now: clk.Now, Sleep: clk.Sleep})
	runRounds(t, p, clk)
	got, err := store.Load(t.Context())
	if err != nil || got.Revision != rev(1, 8) {
		t.Fatalf("after the first accept: %v, %v", got, err)
	}
	if !p.Ready() {
		t.Error("not Ready after the first accept")
	}
	reps := up.got()
	if last := reps[len(reps)-1]; last.StoreError != "" || last.Applied != rev(1, 8) || last.LastRefusal != nil {
		t.Errorf("last report %+v", last)
	}
}

// outsideScenario runs a puller on a ConfigMap store against an upstream that serves bundles[0]
// first. before runs after the first round.
type outsideScenario struct {
	f      *fx
	client *fake.Clientset
	store  Store
	up     *upstream
	logs   *syncBuffer
	p      *Puller
	clk    *clock
}

func newOutsideScenario(t *testing.T, rounds int, bundle func(f *fx) mgmtapi.SpecBundle, after func(sc *outsideScenario, round int)) *outsideScenario {
	t.Helper()
	sc := &outsideScenario{f: newFx(t), client: fake.NewClientset(), logs: &syncBuffer{}, clk: newClock(rounds)}
	sc.store = NewConfigMapStore(sc.client, testNS, testName, testEnv, sc.f.keys(), newLog(io.Discard))
	sc.up = newUpstream(t, bundle(sc.f), nil)
	n := 0
	sc.p = NewPuller(PullerConfig{Client: sc.up.client, BaseURL: sc.up.url, Env: testEnv, Keys: sc.f.keys(), Store: sc.store,
		Log: newLog(sc.logs), Now: sc.clk.Now, Sleep: func(ctx context.Context, d time.Duration) error {
			n++
			if after != nil {
				after(sc, n)
			}
			return sc.clk.Sleep(ctx, d)
		}})
	return sc
}

func (sc *outsideScenario) failUpdates(n int) {
	left := n
	sc.client.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		if left > 0 {
			left--
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
}

func olderState(t *testing.T, f *fx, r spec.Revision) *State {
	t.Helper()
	st, _, err := Accept(Empty(), firstBundle(f, r), testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestPullerReportsStoredRevisionWhenRepairFails(t *testing.T) {
	sc := newOutsideScenario(t, 2, func(f *fx) mgmtapi.SpecBundle { return firstBundle(f, rev(1, 4)) },
		func(sc *outsideScenario, round int) {
			if round == 1 {
				writeOutside(t, sc.client, olderState(t, sc.f, rev(1, 2)), KeyFingerprint(sc.f.keys()))
				sc.failUpdates(100)
			}
		})
	runRounds(t, sc.p, sc.clk)
	reps := sc.up.got()
	if len(reps) != 2 {
		t.Fatalf("reports %d", len(reps))
	}
	if r := reps[1]; r.Applied != rev(1, 2) || r.StoreError != mgmtapi.ReasonStoreFailed {
		t.Errorf("report after a failed repair: %+v, want applied (1,2) and store_failed", r)
	}
}

func TestPullerRewritesRuntimeTamper(t *testing.T) {
	sc := newOutsideScenario(t, 3, func(f *fx) mgmtapi.SpecBundle { return firstBundle(f, rev(1, 4)) },
		func(sc *outsideScenario, round int) {
			if round == 1 {
				cm := liveConfigMap(t, sc.client)
				cm.Data[SpecKey] = string(tamper(t, []byte(cm.Data[SpecKey]), func(p []byte) []byte { return append([]byte(" "), p...) }))
				if _, err := sc.client.CoreV1().ConfigMaps(testNS).Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
		})
	runRounds(t, sc.p, sc.clk)
	got, err := sc.store.Load(t.Context())
	if err != nil || got.Revision != rev(1, 4) {
		t.Fatalf("the store after a runtime tamper: %v, %v", got, err)
	}
	if last := sc.up.got(); last[len(last)-1].Applied != rev(1, 4) || last[len(last)-1].StoreError != "" {
		t.Errorf("last report %+v", last[len(last)-1])
	}
}

func TestPullerRepairsSpecEnvelopeBytes(t *testing.T) {
	sc := newOutsideScenario(t, 3, func(f *fx) mgmtapi.SpecBundle { return firstBundle(f, rev(1, 4)) },
		func(sc *outsideScenario, round int) {
			if round == 1 {
				cm := liveConfigMap(t, sc.client)
				var m map[string]any
				_ = json.Unmarshal([]byte(cm.Data[SpecKey]), &m)
				sigs := m["signatures"].([]any)
				m["signatures"] = append(sigs, map[string]any{"sig": "AAAA"})
				raw, _ := json.Marshal(m)
				cm.Data[SpecKey] = string(raw)
				if _, err := sc.client.CoreV1().ConfigMaps(testNS).Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				if _, _, err := sc.store.Peek(t.Context()); err != nil {
					t.Fatalf("the edited spec must still verify: %v", err)
				}
			}
		})
	runRounds(t, sc.p, sc.clk)
	if got := liveConfigMap(t, sc.client).Data[SpecKey]; got != string(sc.p.state.SpecEnvelope) {
		t.Fatal("the junk signature stays in the stored spec")
	}
}

func TestPullerClearsRefusalAfterSavedAccept(t *testing.T) {
	var newer mgmtapi.SpecBundle
	sc := newOutsideScenario(t, 4, func(f *fx) mgmtapi.SpecBundle {
		newer = firstBundle(f, rev(1, 6))
		return firstBundle(f, rev(1, 4))
	}, func(sc *outsideScenario, round int) {
		switch round {
		case 1:
			sc.up.set(firstBundle(sc.f, rev(1, 3)))
		case 2:
			sc.up.set(newer)
		}
	})
	runRounds(t, sc.p, sc.clk)
	reps := sc.up.got()
	if len(reps) != 4 || reps[1].LastRefusal == nil {
		t.Fatalf("reports %+v", reps)
	}
	for _, r := range reps[2:] {
		if r.LastRefusal != nil || r.Applied != rev(1, 6) {
			t.Errorf("report after the saved accept: %+v", r)
		}
	}
}

// A higher stored state that Accept refuses is not adopted. envd replaces it, and reports the refusal.
func TestPullerAdoptionRunsAccept(t *testing.T) {
	sc := newOutsideScenario(t, 3, func(f *fx) mgmtapi.SpecBundle {
		cur, _ := f.base()
		_ = cur
		return firstBundle(f, rev(1, 2))
	}, func(sc *outsideScenario, round int) {
		if round == 1 {
			// A signed spec at (1,9) that drops cells a and b, which envd holds marks for.
			f := sc.f
			bad := f.bundle(rev(1, 9), []item{f.item(f.cell("c", rev(1, 9), false))}, nil)
			st, _, err := Accept(Empty(), bad, testEnv, f.keys())
			if err != nil {
				t.Fatal(err)
			}
			writeOutside(t, sc.client, st, KeyFingerprint(f.keys()))
		}
	})
	runRounds(t, sc.p, sc.clk)
	if sc.p.state.Revision != rev(1, 2) {
		t.Fatalf("envd adopted a stored state that Accept refuses: %v", sc.p.state.Revision)
	}
	got, err := sc.store.Load(t.Context())
	if err != nil || got.Revision != rev(1, 2) {
		t.Fatalf("the store after the replace: %v, %v", got, err)
	}
	reps := sc.up.got()
	if r := reps[1]; r.LastRefusal == nil || r.LastRefusal.Reason != mgmtapi.ReasonSpecInvalid || r.LastRefusal.Revision != rev(1, 9) {
		t.Errorf("report %+v, want a spec_invalid refusal of (1,9)", r)
	}
}

// A failed repair does not keep store_failed in the report of a round whose own save succeeds.
func TestPullerClearsSyncStoreErrorAfterSave(t *testing.T) {
	var newer mgmtapi.SpecBundle
	sc := newOutsideScenario(t, 2, func(f *fx) mgmtapi.SpecBundle {
		newer = firstBundle(f, rev(1, 6))
		return firstBundle(f, rev(1, 4))
	}, func(sc *outsideScenario, round int) {
		if round == 1 {
			writeOutside(t, sc.client, olderState(t, sc.f, rev(1, 2)), KeyFingerprint(sc.f.keys()))
			sc.failUpdates(1)
			sc.up.set(newer)
		}
	})
	runRounds(t, sc.p, sc.clk)
	if r := sc.up.got()[1]; r.StoreError != "" || r.Applied != rev(1, 6) {
		t.Errorf("report %+v", r)
	}
}

func TestStoreRefusesStateWithNoSpec(t *testing.T) {
	f := newFx(t)
	c := fake.NewClientset()
	s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	if err := s.Save(t.Context(), Empty()); err == nil {
		t.Fatal("Save wrote a state with no spec")
	}
	if err := s.Replace(t.Context(), Empty()); err == nil {
		t.Fatal("Replace wrote a state with no spec")
	}
	if _, err := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{}); err == nil {
		t.Fatal("a ConfigMap exists")
	}
}
