package bundleapply

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore/ocitest"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// applied applies a signed set, publishes its root to the mirror as the attestation names it, and
// returns the set. The mirror tag current names the same root, as the real mirror does.
func (e *env) applied(counter uint64) built {
	e.t.Helper()
	b := e.set(counter, std(fmt.Sprintf("v%d", counter)))
	e.seed(e.mirrorReg, "bundles/"+tTarget+"/root", b.root)
	e.mirrorReg.SeedManifest("bundles/"+tTarget+"/root", "current", bundle.MediaTypeManifest, b.root.Manifest)
	wantOutcome(e.t, e.apply(fmt.Sprintf("op%d", counter), b), op.OutcomeApplied, "", "")
	return b
}

func (e *env) refill() RefillResult {
	e.t.Helper()
	res, err := e.a.Refill(e.t.Context())
	if err != nil {
		e.t.Fatalf("refill: %v", err)
	}
	return res
}

func writesOf(reg *ocitest.Registry, from int) []string {
	var w []string
	for _, r := range reg.Requests()[from:] {
		w = append(w, r.Method+" "+r.Path)
	}
	return w
}

func TestRefillIntact(t *testing.T) {
	e := newEnv(t)
	b := e.applied(1)
	store, mirror := len(e.storeReg.Requests()), len(e.mirrorReg.Requests())
	res := e.refill()
	if res.Outcome != RefillIntact || res.Pushed != 0 || res.Root != b.root.Digest {
		t.Fatalf("result = %+v", res)
	}
	got := writesOf(e.storeReg, store)
	if len(got) != 1 || !strings.HasPrefix(got[0], "PUT ") || !strings.HasSuffix(got[0], "/bundles/root/manifests/"+b.root.Digest) {
		t.Fatalf("store requests = %v, want one PUT of the root by digest", got)
	}
	if got := writesOf(e.mirrorReg, mirror); len(got) != 0 {
		t.Fatalf("mirror requests = %v, want none", got)
	}
}

func TestRefillAfterLoss(t *testing.T) {
	te := newTelemetryEnv(t)
	e := te.env
	b := e.applied(1)
	e.storeReg.Lose()
	actions := len(e.dyn.Actions())
	res := e.refill()
	if res.Outcome != RefillRefilled || res.Pushed != 3 || res.Root != b.root.Digest {
		t.Fatalf("result = %+v", res)
	}
	for name, art := range b.arts {
		if m, ok := e.storeReg.Manifest("bundles/"+name, art.Digest); !ok || ocitest.Digest(m) != art.Digest {
			t.Errorf("component %s manifest missing", name)
		}
		if _, ok := e.storeReg.Blob("bundles/"+name, art.LayerDigest); !ok {
			t.Errorf("component %s layer missing", name)
		}
		if _, ok := e.storeReg.Blob("bundles/"+name, art.ConfigDigest); !ok {
			t.Errorf("component %s config missing", name)
		}
	}
	if _, ok := e.storeReg.Manifest("bundles/root", b.root.Digest); !ok {
		t.Error("root manifest by digest missing")
	}
	if e.currentRoot() != b.root.Digest {
		t.Errorf("tag current = %q, want %q", e.currentRoot(), b.root.Digest)
	}
	var refreshed bool
	for _, act := range e.dyn.Actions()[actions:] {
		refreshed = refreshed || act.GetVerb() == "patch" && strings.Contains(fmt.Sprint(act), "root")
	}
	if !refreshed {
		t.Error("the root Application was not refreshed")
	}
	if n := te.sum(t, "bundle.store.refills", attribute.NewSet(attribute.String("outcome", RefillRefilled))); n != 1 {
		t.Errorf("bundle.store.refills refilled = %d, want 1", n)
	}
	if again := e.refill(); again.Outcome != RefillIntact {
		t.Errorf("second refill = %+v, want intact", again)
	}
}

func TestRefillByDigestOnly(t *testing.T) {
	e := newEnv(t)
	b := e.applied(1)
	other := e.build(tTarget, bundle.Version{Epoch: 1, Counter: 9}, std("other"))
	e.mirrorReg.SeedManifest("bundles/"+tTarget+"/root", "current", bundle.MediaTypeManifest, other.root.Manifest)
	for name := range b.arts {
		e.mirrorReg.SeedManifest("bundles/"+tTarget+"/"+name, "current", bundle.MediaTypeManifest, other.arts[name].Manifest)
	}
	e.storeReg.Lose()
	mirror := len(e.mirrorReg.Requests())
	res := e.refill()
	if res.Outcome != RefillRefilled || e.currentRoot() != b.root.Digest {
		t.Fatalf("result = %+v, current = %s", res, e.currentRoot())
	}
	for _, r := range e.mirrorReg.Requests()[mirror:] {
		if strings.Contains(r.Path, "/manifests/") && !strings.Contains(r.Path, "/manifests/sha256:") {
			t.Errorf("the mirror was read by tag: %s %s", r.Method, r.Path)
		}
	}
}

func TestRefillDigestMismatch(t *testing.T) {
	for _, what := range []string{"component", "root"} {
		t.Run(what, func(t *testing.T) {
			e := newEnv(t)
			b := e.applied(1)
			d := b.arts["apps-sample"].Digest
			if what == "root" {
				d = b.root.Digest
			}
			e.mirrorReg.Corrupt(d)
			e.storeReg.Lose()
			store := len(e.storeReg.Requests())
			res, err := e.a.Refill(t.Context())
			if res.Outcome != RefillFailed || !errors.Is(err, ocistore.ErrDigestMismatch) {
				t.Fatalf("result = %+v, error = %v", res, err)
			}
			if e.currentRoot() != "" {
				t.Errorf("tag current = %q after a failed refill", e.currentRoot())
			}
			for _, w := range writesOf(e.storeReg, store) {
				if !strings.HasPrefix(w, "PUT ") || !strings.Contains(w, "/bundles/root/manifests/sha256:") {
					t.Errorf("a failed refill wrote %s", w)
				}
			}
			for name, art := range b.arts {
				if _, ok := e.storeReg.Blob("bundles/"+name, art.LayerDigest); ok {
					t.Errorf("component %s was pushed before the checks ended", name)
				}
			}
		})
	}
}

func TestRefillLockHeld(t *testing.T) {
	t.Run("this process", func(t *testing.T) {
		e := newEnv(t)
		e.applied(1)
		e.storeReg.Lose()
		store := len(e.storeReg.Requests())
		e.a.running.Lock()
		defer e.a.running.Unlock()
		if res := e.refill(); res.Outcome != RefillSkipped {
			t.Fatalf("result = %+v", res)
		}
		if got := writesOf(e.storeReg, store); len(got) != 0 {
			t.Fatalf("store requests = %v", got)
		}
	})
	t.Run("another holder", func(t *testing.T) {
		e := newEnv(t)
		e.applied(1)
		e.storeReg.Lose()
		st := e.state()
		st.Holder, st.Until = "pod-b", e.clk.Now().Add(time.Minute)
		e.mustWriteState(st)
		store := len(e.storeReg.Requests())
		if res := e.refill(); res.Outcome != RefillSkipped {
			t.Fatalf("result = %+v", res)
		}
		if got := writesOf(e.storeReg, store); len(got) != 0 {
			t.Fatalf("store requests = %v", got)
		}
		e.clk.Advance(2 * time.Minute)
		if res := e.refill(); res.Outcome != RefillRefilled {
			t.Fatalf("after the lock expired: %+v", res)
		}
	})
}

func TestRefillBootstrapSkipped(t *testing.T) {
	e := newEnv(t)
	e.storeReg.Lose()
	store := len(e.storeReg.Requests())
	if res := e.refill(); res.Outcome != RefillSkipped || res.Pushed != 0 {
		t.Fatalf("result = %+v", res)
	}
	if got := writesOf(e.storeReg, store); len(got) != 0 {
		t.Fatalf("store requests = %v", got)
	}
}

func TestRefillUsesGoodWhileInFlight(t *testing.T) {
	e := newEnv(t)
	b := e.applied(1)
	e.storeReg.Lose()
	st := e.state()
	st.State, st.Root, st.Components = stateApplying, Root{Digest: "sha256:" + strings.Repeat("1", 64), Manifest: []byte("x")}, map[string]string{}
	e.mustWriteState(st)
	if res := e.refill(); res.Outcome != RefillRefilled || res.Root != b.root.Digest || e.currentRoot() != b.root.Digest {
		t.Fatalf("result = %+v, current = %s", res, e.currentRoot())
	}
}

func TestRefillNeverDeletes(t *testing.T) {
	e := newEnv(t)
	b := e.applied(1)
	e.storeReg.Lose()
	extra := e.storeReg.Seed("bundles/unrelated", []byte("kept"))
	e.storeReg.SeedManifest("bundles/root", "old", bundle.MediaTypeManifest, []byte(`{"schemaVersion":2}`))
	store, mirror := len(e.storeReg.Requests()), len(e.mirrorReg.Requests())
	if res := e.refill(); res.Outcome != RefillRefilled {
		t.Fatalf("result = %+v", res)
	}
	for _, w := range append(writesOf(e.storeReg, store), writesOf(e.mirrorReg, mirror)...) {
		if strings.HasPrefix(w, "DELETE") {
			t.Errorf("refill sent %s", w)
		}
	}
	if _, ok := e.storeReg.Blob("bundles/unrelated", extra); !ok {
		t.Error("an unrelated blob was removed")
	}
	if _, ok := e.storeReg.Manifest("bundles/root", "old"); !ok {
		t.Error("an unrelated tag was removed")
	}
	if e.currentRoot() != b.root.Digest {
		t.Error("tag current not set")
	}
}

func TestRunRefillStopsWithContext(t *testing.T) {
	e := newEnv(t)
	e.applied(1)
	e.storeReg.Lose()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { e.a.RunRefill(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for e.currentRoot() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RunRefill did not stop")
	}
	if e.currentRoot() == "" {
		t.Fatal("the first refill did not run at once")
	}
	e.a.RunRefill(t.Context(), 0)
}
