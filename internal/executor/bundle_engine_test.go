package executor

import (
	"context"
	"crypto"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore/ocitest"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

var applications = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}

// flakyState is a bundle state store that refuses every write after the first limit writes, as a
// pod that dies mid-apply would. A limit of zero refuses nothing.
type flakyState struct {
	bundleapply.Store
	limit, writes atomic.Int32
}

func (f *flakyState) Write(ctx context.Context, st bundleapply.State, rv string) error {
	if n := f.writes.Add(1); f.limit.Load() > 0 && n > f.limit.Load() {
		return errors.New("state write refused")
	}
	return f.Store.Write(ctx, st, rv)
}

// engineRig runs the real engine of the cell cell-1 against two in-memory registries and a fake Argo
// CD, with the clock and the clients of the executor rig.
type engineRig struct {
	*rig
	mirror, store *ocitest.Registry
	dyn           *dynamicfake.FakeDynamicClient
	state         *flakyState
}

func newEngineRig(t *testing.T) *engineRig {
	t.Helper()
	r := newRig(t)
	return &engineRig{
		rig: r, mirror: ocitest.NewRegistry(t), store: ocitest.NewRegistry(t),
		dyn: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
			map[schema.GroupVersionResource]string{applications: "ApplicationList"}),
		state: &flakyState{Store: &bundleapply.ConfigMapStore{Client: r.client, Namespace: DefaultNamespace, Name: "bundle-state", MadeBy: "celld"}},
	}
}

// engine returns the engine of the pod with the name holder, as celld builds it.
func (er *engineRig) engine(holder string) *bundleapply.Applier {
	er.t.Helper()
	mirror, err := ocistore.New(ocistore.Client{Base: er.mirror.URL()})
	if err != nil {
		er.t.Fatal(err)
	}
	store, err := ocistore.New(ocistore.Client{Base: er.store.URL(), WriteOnly: true})
	if err != nil {
		er.t.Fatal(err)
	}
	return bundleapply.New(bundleapply.Config{
		Role: "cell", Env: "dev", Target: "cell-1", Holder: holder,
		Mirror: mirror, Store: store, Dynamic: er.dyn, Client: er.client, Policy: bundle.DefaultPolicy(),
		Keys:  func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{er.pub}, nil },
		State: er.state, HealthTimeout: time.Minute, RollbackTimeout: time.Minute, Now: er.clock.Now,
	})
}

// signedSet packs one ConfigMap for each component of a cell set, seeds the mirror under the
// repositories of target, and returns the set, its root and the attestation for target.
func (er *engineRig) signedSet(target string) (bundle.Set, bundle.Artifact, []byte) {
	er.t.Helper()
	set := bundle.Set{Version: bundle.Version{Epoch: 1, Counter: 1}}
	for _, c := range []struct{ name, ns string }{{"apps-sample", "apps-sample"}, {"network-policy", "cell-system"}} {
		body, err := bundle.Canonical([]map[string]any{{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": c.name, "namespace": c.ns},
			"data":     map[string]any{"v": "1"},
		}})
		if err != nil {
			er.t.Fatal(err)
		}
		art, err := bundle.Pack(map[string][]byte{bundle.ManifestsFile: body})
		if err != nil {
			er.t.Fatal(err)
		}
		repo := "bundles/" + target + "/" + c.name
		er.mirror.Seed(repo, art.Config)
		er.mirror.Seed(repo, art.Layer)
		er.mirror.SeedManifest(repo, "", bundle.MediaTypeManifest, art.Manifest)
		set.Components = append(set.Components, bundle.Component{Name: c.name, Namespace: c.ns, Digest: art.Digest})
	}
	root, err := bundle.ComposeRoot("cell", set, bundle.DefaultPolicy())
	if err != nil {
		er.t.Fatal(err)
	}
	att, err := bundle.SignAttestation(bundle.NewStatement("dev", target, set, root.Digest), er.priv)
	if err != nil {
		er.t.Fatal(err)
	}
	return set, root, att
}

// healthy makes the fake Argo CD report every Application of the set as Synced and Healthy at its
// digest, through a sync that succeeded at the digest before the engine runs, so that the health wait
// of the engine ends at its first poll.
func (er *engineRig) healthy(set bundle.Set, root bundle.Artifact) {
	er.t.Helper()
	started := er.clock.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	put := func(name, rev string) {
		u := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
			"metadata": map[string]any{"name": name, "namespace": "argocd"},
			"status": map[string]any{
				"sync":   map[string]any{"status": "Synced", "revision": rev},
				"health": map[string]any{"status": "Healthy"},
				"operationState": map[string]any{
					"phase": "Succeeded", "startedAt": started,
					"operation":  map[string]any{"sync": map[string]any{"revision": rev}},
					"syncResult": map[string]any{"revision": rev},
				},
			},
		}}
		if _, err := er.dyn.Resource(applications).Namespace("argocd").Create(context.Background(), u, metav1.CreateOptions{}); err != nil {
			er.t.Fatal(err)
		}
	}
	for _, c := range set.Components {
		put(c.Name, c.Digest)
	}
	put("root", root.Digest)
}

// TestBundleEffectRealEngineWrongTarget checks that a set signed for another target reaches the cell
// as wrong_target with detail target through the real engine, so that the detail that the engine
// gives and the one that the executor maps cannot drift apart.
func TestBundleEffectRealEngineWrongTarget(t *testing.T) {
	er := newEngineRig(t)
	_, _, att := er.signedSet("cell-2")
	e := er.executor("uid-a", func(c *Config) { c.Bundle = er.engine("celld-uid-a") })
	o := er.operation(op.KindBundleApply, string(att))
	res := e.Execute(ctx, er.sign(o), fence(1, 1))
	if res.Outcome != op.OutcomeRefused || res.Reason != op.ReasonWrongTarget || res.Detail != "target" {
		t.Fatalf("result = %+v, want refused wrong_target target", res)
	}
	if rec := er.record(o.ID); rec.State != stateApplied || rec.Result == nil || rec.Result.Reason != op.ReasonWrongTarget {
		t.Fatalf("record = %+v", rec)
	}
}

// TestBundleEffectRealEngineTakeover drives the real engine through a crash and a takeover: pod a
// claims the operation and dies after the state enters applying, with the engine lock still held.
// Pod b takes the lease with a higher fence, gets the lock fault as a retryable failure while the
// lock of pod a lasts, and then resumes the same operation ID under its own pod name.
func TestBundleEffectRealEngineTakeover(t *testing.T) {
	er := newEngineRig(t)
	set, root, att := er.signedSet("cell-1")
	// Argo CD reports the set healthy from the start, so that no engine run waits for health: the
	// wait sleeps in real time while the deadline reads the fake clock.
	er.healthy(set, root)
	o := er.operation(op.KindBundleApply, string(att))
	o.ExpiresAt = o.IssuedAt.Add(30 * time.Minute)
	env := er.sign(o)
	run := func(e *Executor, f op.Fence) op.Result {
		t.Helper()
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		return e.Execute(c, env, f)
	}

	// Pod a: the lock write and the applying write go through, the tag write is refused.
	er.state.limit.Store(2)
	a := er.executor("uid-a", func(c *Config) { c.Bundle = er.engine("celld-uid-a") })
	if res := run(a, fence(1, 1)); res.Outcome != op.OutcomeLeaseLost || res.Reason != ReasonEffectFailed {
		t.Fatalf("pod a = %+v, want a retryable effect failure", res)
	}
	er.state.limit.Store(0)
	st, _, err := er.state.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "applying" || st.Holder != "celld-uid-a" || !st.Until.After(er.clock.Now()) {
		t.Fatalf("engine state after the crash = %s holder %s until %v", st.State, st.Holder, st.Until)
	}

	// Pod b, after the lease of pod a ends: the engine lock of pod a still holds.
	er.clock.Advance(leaseTerm + time.Second)
	b := er.executor("uid-b", func(c *Config) { c.Bundle = er.engine("celld-uid-b") })
	if res := run(b, fence(1, 2)); res.Outcome != op.OutcomeLeaseLost || res.Reason != ReasonEffectFailed {
		t.Fatalf("pod b under the lock of pod a = %+v, want a retryable effect failure", res)
	}
	if rec := er.record(o.ID); rec.State != stateClaimed || rec.Result != nil {
		t.Fatalf("record = %+v, want the claim with no result", rec)
	}

	// The engine lock of pod a ends. Pod b resumes the same operation ID.
	er.clock.Advance(5 * time.Minute)
	res := run(b, fence(1, 3))
	if res.Outcome != op.OutcomeApplied || res.OpID != o.ID {
		t.Fatalf("pod b after the lock = %+v, want applied", res)
	}
	st, _, err = er.state.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "healthy" || st.Holder != "" || st.Root.Digest != root.Digest || st.Result == nil || st.Result.OpID != o.ID {
		t.Fatalf("engine state after the takeover = %s holder %q root %s result %+v", st.State, st.Holder, st.Root.Digest, st.Result)
	}
	if m, ok := er.store.Manifest("bundles/root", "current"); !ok || ocitest.Digest(m) != root.Digest {
		t.Fatal("the store tag does not hold the root of the set")
	}
}

// TestBundleEffectRealEngineExpiredInFlight checks that an operation that expires while the engine
// state still names it in applying, after pod a died, is not reported expired: the cluster may run
// its root. Pod b answers with a retryable result and does not apply the expired operation.
func TestBundleEffectRealEngineExpiredInFlight(t *testing.T) {
	er := newEngineRig(t)
	set, root, att := er.signedSet("cell-1")
	er.healthy(set, root)
	o := er.operation(op.KindBundleApply, string(att))
	env := er.sign(o)
	er.state.limit.Store(2)
	a := er.executor("uid-a", func(c *Config) { c.Bundle = er.engine("celld-uid-a") })
	if res := a.Execute(ctx, env, fence(1, 1)); res.Outcome != op.OutcomeLeaseLost || res.Reason != ReasonEffectFailed {
		t.Fatalf("pod a = %+v, want a retryable effect failure", res)
	}
	er.state.limit.Store(0)

	er.clock.Advance(o.ExpiresAt.Sub(er.clock.Now()) + time.Second)
	b := er.executor("uid-b", func(c *Config) { c.Bundle = er.engine("celld-uid-b") })
	res := b.Execute(ctx, env, fence(1, 2))
	if res.Outcome != op.OutcomeLeaseLost || res.Reason != ReasonEffectFailed || op.IsFinal(res.Outcome) {
		t.Fatalf("pod b after the expiry = %+v, want a retryable result, not expired", res)
	}
	st, _, err := er.state.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "applying" || st.OpID != o.ID || st.Holder != "celld-uid-a" {
		t.Fatalf("engine state = %s op %s holder %s, want it untouched", st.State, st.OpID, st.Holder)
	}
}
