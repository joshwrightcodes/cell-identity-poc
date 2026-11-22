package bundleapply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
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

// hooked returns an Applier like e.a whose mirror reads go through a proxy. before runs once, ahead
// of the first read of a manifest from the mirror, as another process would act during the refill.
func (e *env) hooked(before func()) *Applier {
	e.t.Helper()
	target, err := url.Parse("http://" + e.mirrorReg.URL())
	if err != nil {
		e.t.Fatal(err)
	}
	var once sync.Once
	proxy := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			once.Do(before)
		}
		proxy.ServeHTTP(w, r)
	}))
	e.t.Cleanup(srv.Close)
	mirror, err := ocistore.New(ocistore.Client{Base: strings.TrimPrefix(srv.URL, "http://")})
	if err != nil {
		e.t.Fatal(err)
	}
	cfg := e.cfg
	cfg.Mirror = mirror
	return e.applier(cfg)
}

func TestRefillStateMovesDuringRead(t *testing.T) {
	for _, what := range []string{"lease lost", "root moved"} {
		t.Run(what, func(t *testing.T) {
			e := newEnv(t)
			old := e.applied(1)
			next := e.set(2, std("v2"))
			e.storeReg.Lose()
			a := e.hooked(func() {
				st := e.state()
				if what == "lease lost" {
					st.Holder, st.Until = "pod-b", e.clk.Now().Add(time.Minute)
				} else {
					st.Root, st.Components = Root{Digest: next.root.Digest, Manifest: next.root.Manifest}, next.digests()
				}
				e.mustWriteState(st)
				e.storeReg.SeedManifest("bundles/root", "current", bundle.MediaTypeManifest, next.root.Manifest)
			})
			res, err := a.Refill(t.Context())
			if err != nil || res.Outcome != RefillSkipped {
				t.Fatalf("result = %+v, error = %v", res, err)
			}
			if e.currentRoot() != next.root.Digest {
				t.Errorf("tag current = %q, want %q: the refill moved it back to %q", e.currentRoot(), next.root.Digest, old.root.Digest)
			}
		})
	}
}

func TestRefillHoldsLease(t *testing.T) {
	e := newEnv(t)
	b := e.applied(1)
	e.storeReg.Lose()
	var during State
	a := e.hooked(func() { during = e.state() })
	if res, err := a.Refill(t.Context()); err != nil || res.Outcome != RefillRefilled || res.Root != b.root.Digest {
		t.Fatalf("result = %+v, error = %v", res, err)
	}
	if during.Holder != "pod-a" || !during.Until.After(e.clk.Now()) {
		t.Errorf("during the read: holder %q until %v, want pod-a with a live lease", during.Holder, during.Until)
	}
	if st := e.state(); st.Holder != "" || !st.Until.IsZero() {
		t.Errorf("after the refill: holder %q until %v, want the lease released", st.Holder, st.Until)
	}
}

func TestRefillStateManifestHash(t *testing.T) {
	e := newEnv(t)
	e.applied(1)
	e.storeReg.Lose()
	st := e.state()
	st.Root.Manifest = append(bytes.Clone(st.Root.Manifest), ' ')
	e.mustWriteState(st)
	store := len(e.storeReg.Requests())
	res, err := e.a.Refill(t.Context())
	if res.Outcome != RefillFailed || err == nil {
		t.Fatalf("result = %+v, error = %v", res, err)
	}
	if got := writesOf(e.storeReg, store); len(got) != 0 || e.currentRoot() != "" {
		t.Fatalf("store requests = %v, tag current = %q", got, e.currentRoot())
	}
}

func TestRefillLogsPersistentFailureOnce(t *testing.T) {
	e := newEnv(t)
	e.applied(1)
	e.storeReg.Lose()
	e.mirrorReg.Lose()
	var buf bytes.Buffer
	cfg := e.cfg
	cfg.Log = slog.New(slog.NewTextHandler(&buf, nil))
	a := e.applier(cfg)
	for range 3 {
		if _, err := a.Refill(t.Context()); err == nil {
			t.Fatal("refill succeeded with a mirror that lost its content")
		}
	}
	if n := strings.Count(buf.String(), "store_refill_failed"); n != 1 {
		t.Fatalf("store_refill_failed logged %d times, want 1:\n%s", n, buf.String())
	}
}

// raced is a state store that runs before on its nth read.
type raced struct {
	Store
	n, at  int
	before func()
}

func (r *raced) Read(ctx context.Context) (State, string, error) {
	if r.n++; r.n == r.at {
		r.before()
	}
	return r.Store.Read(ctx)
}

func TestRefillLeaseTakenByAnotherHolder(t *testing.T) {
	e := newEnv(t)
	e.applied(1)
	e.storeReg.Lose()
	cfg := e.cfg
	cfg.State = &raced{Store: e.gate, at: 2, before: func() {
		st := e.state()
		st.Holder, st.Until = "pod-b", e.clk.Now().Add(time.Minute)
		e.mustWriteState(st)
	}}
	res, err := e.applier(cfg).Refill(t.Context())
	if err != nil || res.Outcome != RefillSkipped || res.Pushed != 0 || e.currentRoot() != "" {
		t.Fatalf("result = %+v, error = %v, current = %q", res, err, e.currentRoot())
	}
	if st := e.state(); st.Holder != "pod-b" {
		t.Errorf("holder = %q, want pod-b", st.Holder)
	}
}
