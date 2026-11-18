package bundleapply

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore/ocitest"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const (
	tTarget = "dev-cell-1"
	tEnv    = "dev"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// gate is a state store that can start to refuse writes, as a pod that dies mid-apply would.
type gate struct {
	Store
	fail atomic.Bool
}

func (g *gate) Write(ctx context.Context, st State, rv string) error {
	if g.fail.Load() {
		return errors.New("state write refused")
	}
	return g.Store.Write(ctx, st, rv)
}

type spec struct{ name, ns, body string }

type built struct {
	att  []byte
	set  bundle.Set
	root bundle.Artifact
	arts map[string]bundle.Artifact
}

func (b built) digests() map[string]string {
	m := map[string]string{}
	for _, c := range b.set.Components {
		m[c.Name] = c.Digest
	}
	return m
}

type env struct {
	t         *testing.T
	clk       *clock
	mirrorReg *ocitest.Registry
	storeReg  *ocitest.Registry
	cs        *fake.Clientset
	disc      *fakediscovery.FakeDiscovery
	dyn       *dynamicfake.FakeDynamicClient
	gate      *gate
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	cfg       Config
	a         *Applier

	boot  built
	roots map[string]map[string]string // root digest to component digests, for the Argo CD simulation
	// health returns the sync and health status that the simulated Argo CD gives an Application
	// while the root tag of the store is root. A nil function means Synced and Healthy.
	health func(root, app string) (string, string)
	// revision, when set, gives the revision that the simulated Argo CD shows in place of rev.
	revision func(root, app, rev string) string
	// hook runs after each simulated poll. A non-nil error ends the wait.
	hook  func(n int)
	polls int
	// lag is how long the simulated Argo CD keeps showing the root that it showed before the tag
	// moved. shown is the root that it shows, and seenRoot and seenAt record the last tag move.
	lag      time.Duration
	shown    string
	seenRoot string
	seenAt   time.Time

	// ops holds the last sync operation of each simulated Application, and written is the root whose
	// child Applications the simulated root wrote last. rvs holds the resource version of each
	// Application, and nextRV the next one.
	ops     map[string]*simOp
	written string
	rvs     map[string]string
	nextRV  int
	// sync, when set, decides how the simulated Argo CD syncs app to rev while the tag holds root: the
	// phase of the operation that it starts ("" for none) and its start time. A nil function starts a
	// sync that succeeds at once.
	sync func(root, app, rev string, now time.Time) (string, time.Time)
	// terminated lists the Applications whose operation the engine terminated, in order, and
	// terminateRVs the resource version that each terminate patch carried. conflicts makes that many
	// terminate patches fail with a conflict.
	terminated   []string
	terminateRVs []string
	conflicts    int
}

// simOp is a sync operation of the simulated Argo CD.
type simOp struct {
	phase, rev string
	started    time.Time
}

// canonBody returns the canonical form of body.
func canonBody(t testing.TB, body string) []byte {
	t.Helper()
	return canonicalOf(t, []byte(body))
}

func cmap(ns, name, v string) string {
	return fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n  namespace: %s\ndata:\n  v: %q\n", name, ns, v)
}

func std(v string) []spec {
	return []spec{
		{"apps-sample", "apps-demo", cmap("apps-demo", "app", v)},
		{"network-policy", "cell-system", cmap("cell-system", "np", v)},
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clk: &clock{t: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)}, roots: map[string]map[string]string{},
		ops: map[string]*simOp{}, rvs: map[string]string{}}
	e.mirrorReg = ocitest.NewRegistry(t)
	e.storeReg = ocitest.NewRegistry(t)
	mirror, err := ocistore.New(ocistore.Client{Base: e.mirrorReg.URL()})
	if err != nil {
		t.Fatal(err)
	}
	store, err := ocistore.New(ocistore.Client{Base: e.storeReg.URL(), WriteOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	e.cs = fake.NewSimpleClientset()
	versioned(e.cs)
	e.disc = e.cs.Discovery().(*fakediscovery.FakeDiscovery)
	e.dyn = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{applicationGVR: "ApplicationList"})
	e.dyn.PrependReactor("patch", "applications", e.terminateReactor)
	e.pub, e.priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e.gate = &gate{Store: &ConfigMapStore{Client: e.cs, Namespace: "cell-ops-system", Name: "bundle-state", MadeBy: "celld"}}
	e.cfg = Config{
		Role: "cell", Env: tEnv, Target: tTarget, Holder: "pod-a",
		Mirror: mirror, Store: store, Dynamic: e.dyn, Client: e.cs,
		Policy: bundle.DefaultPolicy(),
		Keys:   func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{e.pub}, nil },
		State:  e.gate, HealthTimeout: 5 * time.Minute, DegradedGrace: time.Minute, RollbackTimeout: 5 * time.Minute,
		Poll: 5 * time.Second, Now: e.clk.Now, Log: slog.New(slog.DiscardHandler),
	}
	e.a = e.applier(e.cfg)
	e.seedBootstrap()
	return e
}

// applier returns an Applier whose waits advance the fake clock and run the Argo CD simulation.
func (e *env) applier(cfg Config) *Applier {
	a := New(cfg)
	a.sleep = func(ctx context.Context, d time.Duration) error {
		e.clk.Advance(d)
		e.polls++
		e.step()
		if e.hook != nil {
			e.hook(e.polls)
		}
		return ctx.Err()
	}
	return a
}

func (e *env) build(target string, v bundle.Version, specs []spec) built {
	e.t.Helper()
	b := built{arts: map[string]bundle.Artifact{}}
	b.set.Version = v
	for _, s := range specs {
		art, err := bundle.Pack(map[string][]byte{bundle.ManifestsFile: canonBody(e.t, s.body)})
		if err != nil {
			e.t.Fatal(err)
		}
		e.seed(e.mirrorReg, "bundles/"+target+"/"+s.name, art)
		b.arts[s.name] = art
		b.set.Components = append(b.set.Components, bundle.Component{Name: s.name, Namespace: s.ns, Digest: art.Digest})
	}
	slices.SortFunc(b.set.Components, func(x, y bundle.Component) int { return strings.Compare(x.Name, y.Name) })
	// A set that the policy refuses still has a signed root. Its content is the digest of the first component.
	root, err := bundle.ComposeRoot(e.cfg.Role, b.set, e.cfg.Policy)
	if err != nil {
		root = bundle.Artifact{Digest: b.set.Components[0].Digest}
	}
	b.root = root
	e.roots[root.Digest] = b.digests()
	return b
}

func (e *env) seed(reg *ocitest.Registry, repo string, art bundle.Artifact) {
	reg.Seed(repo, art.Config)
	reg.Seed(repo, art.Layer)
	reg.SeedManifest(repo, "", bundle.MediaTypeManifest, art.Manifest)
}

func (e *env) sign(b built, env, target, rootDigest string, key ed25519.PrivateKey) []byte {
	e.t.Helper()
	att, err := bundle.SignAttestation(bundle.NewStatement(env, target, b.set, rootDigest), key)
	if err != nil {
		e.t.Fatal(err)
	}
	return att
}

// set builds and signs a set for the target of the applier.
func (e *env) set(counter uint64, specs []spec) built {
	e.t.Helper()
	b := e.build(tTarget, bundle.Version{Epoch: 1, Counter: counter}, specs)
	b.att = e.sign(b, tEnv, tTarget, b.root.Digest, e.priv)
	return b
}

func (e *env) seedBootstrap() {
	e.t.Helper()
	b := e.build(tTarget, bundle.Version{}, []spec{
		{"apps-sample", "apps-demo", cmap("apps-demo", "app", "boot")},
		{"network-policy", "cell-system", cmap("cell-system", "np", "boot")},
	})
	e.boot = b
	e.seed(e.storeReg, "bundles/root", b.root)
	e.storeReg.SeedManifest("bundles/root", "current", bundle.MediaTypeManifest, b.root.Manifest)
	e.mustWriteState(State{
		Source: "bootstrap", State: "healthy", Root: Root{Digest: b.root.Digest, Manifest: b.root.Manifest}, Components: b.digests(),
	})
	// Argo CD synced the bootstrap set an hour before the tests start.
	synced := e.clk.Now().Add(-time.Hour)
	for name, d := range b.digests() {
		e.ops[name] = &simOp{"Succeeded", d, synced}
		e.putApp(name, appState{Sync: "Synced", Health: "Healthy", Revision: d})
	}
	e.ops["root"] = &simOp{"Succeeded", b.root.Digest, synced}
	e.written = b.root.Digest
	e.putApp("root", appState{Sync: "Synced", Health: "Healthy", Revision: b.root.Digest})
}

func (e *env) mustWriteState(st State) {
	e.t.Helper()
	_, rv, err := e.gate.Store.Read(e.t.Context())
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.gate.Store.Write(e.t.Context(), st, rv); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) state() State {
	e.t.Helper()
	st, _, err := e.gate.Store.Read(e.t.Context())
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

// putApp writes the status of one simulated Application, with its last operation from e.ops, as Argo
// CD shows it: status.operationState, and the field operation while the operation runs. Each write
// gives the Application a new resource version.
func (e *env) putApp(name string, s appState) {
	e.t.Helper()
	gvr := applicationGVR.GroupVersion().WithResource("applications")
	ctx := context.Background()
	status := map[string]any{
		"sync":   map[string]any{"status": s.Sync, "revision": s.Revision},
		"health": map[string]any{"status": s.Health},
	}
	var operation map[string]any
	if o := e.ops[name]; o != nil {
		sync := map[string]any{"revision": o.rev}
		status["operationState"] = map[string]any{
			"phase": o.phase, "startedAt": o.started.UTC().Format(time.RFC3339),
			"operation": map[string]any{"sync": sync}, "syncResult": map[string]any{"revision": o.rev},
		}
		if o.phase == "Running" || o.phase == "Terminating" {
			operation = map[string]any{"sync": sync}
		}
	}
	e.nextRV++
	rv := strconv.Itoa(e.nextRV)
	e.rvs[name] = rv
	u := application(name, status)
	cur, err := e.dyn.Resource(gvr).Namespace("argocd").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		cur = u
	}
	cur.Object["status"] = status
	delete(cur.Object, "operation")
	if operation != nil {
		cur.Object["operation"] = operation
	}
	cur.SetResourceVersion(rv)
	if err != nil {
		if _, err := e.dyn.Resource(gvr).Namespace("argocd").Create(ctx, cur, metav1.CreateOptions{}); err != nil {
			e.t.Fatal(err)
		}
		return
	}
	if _, err := e.dyn.Resource(gvr).Namespace("argocd").Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
		e.t.Fatal(err)
	}
}

// terminateReactor is the API server and the controller of the simulated Argo CD for a patch that
// sets status.operationState.phase: it refuses a patch whose resource version is not current with a
// conflict, and marks the operation Terminating, which the next step ends as Failed. Other patches go
// on to the default reactor.
func (e *env) terminateReactor(action k8stesting.Action) (bool, runtime.Object, error) {
	p, ok := action.(k8stesting.PatchAction)
	if !ok {
		return false, nil, nil
	}
	var body struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Status struct {
			OperationState struct {
				Phase string `json:"phase"`
			} `json:"operationState"`
		} `json:"status"`
	}
	if err := json.Unmarshal(p.GetPatch(), &body); err != nil || body.Status.OperationState.Phase == "" {
		return false, nil, nil
	}
	name := p.GetName()
	e.terminateRVs = append(e.terminateRVs, body.Metadata.ResourceVersion)
	if p.GetPatchType() != types.MergePatchType || body.Status.OperationState.Phase != "Terminating" {
		return true, nil, fmt.Errorf("unexpected patch of %s: %s %s", name, p.GetPatchType(), p.GetPatch())
	}
	if e.conflicts > 0 || body.Metadata.ResourceVersion != e.rvs[name] {
		e.conflicts--
		return true, nil, apierrors.NewConflict(applicationGVR.GroupResource(), name, errors.New("the object has been modified"))
	}
	e.terminated = append(e.terminated, name)
	if o := e.ops[name]; o != nil && o.phase == "Running" {
		o.phase = "Terminating"
	}
	return true, nil, nil
}

// currentRoot returns the digest that the tag current has in the store.
func (e *env) currentRoot() string {
	m, ok := e.storeReg.Manifest("bundles/root", "current")
	if !ok {
		return ""
	}
	return ocitest.Digest(m)
}

// lagged makes the simulated Argo CD show each new root tag only d after the tag moved.
func (e *env) lagged(d time.Duration) {
	e.lag, e.shown, e.seenRoot, e.seenAt = d, e.currentRoot(), e.currentRoot(), e.clk.Now()
}

// step is the simulated Argo CD. The root Application reads the current root tag, or the root that it
// showed before while the lag lasts, and each child Application reads its revision from the root that
// the root Application synced last. An Application whose revision changed starts a sync (e.sync), as
// automated sync does, but not while an operation runs: an operation that the engine terminated ends
// Failed first. An Application keeps a sync that it attempted once for the same revision.
func (e *env) step() {
	cur := e.currentRoot()
	if e.lag > 0 {
		now := e.clk.Now()
		if cur != e.seenRoot {
			e.seenRoot, e.seenAt = cur, now
		}
		if now.Sub(e.seenAt) < e.lag {
			cur = e.shown
		}
		e.shown = cur
	}
	if _, ok := e.roots[cur]; !ok {
		return
	}
	now := e.clk.Now()
	advance := func(app, rev string) {
		o := e.ops[app]
		if o != nil && o.phase == "Terminating" {
			o.phase = "Failed"
		}
		if o != nil && (o.phase == "Running" || o.rev == rev) {
			return
		}
		phase, started := "Succeeded", now
		if e.sync != nil {
			phase, started = e.sync(cur, app, rev, now)
		}
		if phase != "" {
			e.ops[app] = &simOp{phase, rev, started}
		}
	}
	advance("root", cur)
	if o := e.ops["root"]; o != nil && (o.phase == "Succeeded" || o.phase == "Running") {
		e.written = o.rev
	}
	state := func(root, app, rev string) appState {
		s, h := "Synced", "Healthy"
		if e.health != nil {
			s, h = e.health(root, app)
		}
		if e.revision != nil {
			rev = e.revision(root, app, rev)
		}
		return appState{Sync: s, Health: h, Revision: rev}
	}
	for name, d := range e.roots[e.written] {
		advance(name, d)
		e.putApp(name, state(e.written, name, d))
	}
	e.putApp("root", state(cur, "root", cur))
}

func (e *env) apply(id string, b built) Outcome {
	e.t.Helper()
	out, err := e.a.Apply(e.t.Context(), id, tTarget, b.att)
	if err != nil {
		e.t.Fatalf("apply %s: %v", id, err)
	}
	return out
}

func wantOutcome(t *testing.T, got Outcome, outcome, reason, detail string) {
	t.Helper()
	if got != (Outcome{outcome, reason, detail}) {
		t.Fatalf("outcome = %+v, want {%s %s %s}", got, outcome, reason, detail)
	}
}

// storeWrites returns the requests to the in-cell store that are not reads.
func (e *env) storeWrites() []string {
	var w []string
	for _, r := range e.storeReg.Requests() {
		if r.Method != "GET" && r.Method != "HEAD" {
			w = append(w, r.Method+" "+r.Path)
		}
	}
	return w
}

func (e *env) tagWrites() int {
	n := 0
	for _, w := range e.storeWrites() {
		if strings.HasPrefix(w, "PUT") && strings.HasSuffix(w, "/bundles/root/manifests/current") {
			n++
		}
	}
	return n
}

func TestApplyHappyPath(t *testing.T) {
	e := newEnv(t)
	b := e.set(1, std("v1"))
	out := e.apply("op1", b)
	wantOutcome(t, out, op.OutcomeApplied, "", "")

	st := e.state()
	if st.State != "healthy" || st.Source != "signed" || st.Holder != "" || st.OpID != "op1" {
		t.Fatalf("state = %+v", st)
	}
	if st.Version != (bundle.Version{Epoch: 1, Counter: 1}) {
		t.Fatalf("version = %+v", st.Version)
	}
	if st.Root.Digest != b.root.Digest || string(st.Root.Manifest) != string(b.root.Manifest) {
		t.Fatalf("root = %s", st.Root.Digest)
	}
	if fmt.Sprint(st.Components) != fmt.Sprint(b.digests()) {
		t.Fatalf("components = %v", st.Components)
	}
	if len(st.Good) != 2 || st.Good[0].Root.Digest != b.root.Digest || st.Good[1].Root.Digest != e.boot.root.Digest {
		t.Fatalf("good = %+v", st.Good)
	}
	if string(st.Good[1].Root.Manifest) != string(e.boot.root.Manifest) {
		t.Fatal("the bootstrap root manifest bytes are not kept")
	}
	if st.Result == nil || st.Result.OpID != "op1" || st.Result.Outcome != op.OutcomeApplied || st.Result.Cell != tTarget {
		t.Fatalf("result = %+v", st.Result)
	}
	if e.currentRoot() != b.root.Digest {
		t.Fatalf("tag current = %s, want %s", e.currentRoot(), b.root.Digest)
	}
	for name, art := range b.arts {
		got, ok := e.storeReg.Manifest("bundles/"+name, art.Digest)
		if !ok || string(got) != string(art.Manifest) {
			t.Errorf("store has no manifest of %s", name)
		}
		if _, ok := e.storeReg.Blob("bundles/"+name, art.LayerDigest); !ok {
			t.Errorf("store has no layer of %s", name)
		}
	}
	if _, ok := e.storeReg.Manifest("bundles/root", b.root.Digest); !ok {
		t.Error("store has no root manifest by digest")
	}
	var refreshed bool
	for _, act := range e.dyn.Actions() {
		if act.GetVerb() == "patch" && strings.Contains(fmt.Sprint(act), "root") {
			refreshed = true
		}
	}
	if !refreshed {
		t.Error("the root Application was not refreshed")
	}
	if len(st.Checked) != 2 {
		t.Fatalf("checked = %v", st.Checked)
	}
	status, err := e.a.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "healthy" || status.RootDigest != b.root.Digest || status.Version != st.Version || status.AllowSHA256 != bundle.AllowSHA256() {
		t.Fatalf("status = %+v", status)
	}
}

func TestApplyVersionOld(t *testing.T) {
	cases := []struct {
		name         string
		first, again bundle.Version
		outcome      string
		reason       string
	}{
		{"lower counter", bundle.Version{Epoch: 1, Counter: 5}, bundle.Version{Epoch: 1, Counter: 4}, op.OutcomeRefused, op.ReasonVersionOld},
		{"lower epoch", bundle.Version{Epoch: 2, Counter: 1}, bundle.Version{Epoch: 1, Counter: 9}, op.OutcomeRefused, op.ReasonVersionOld},
		{"higher epoch with lower counter", bundle.Version{Epoch: 1, Counter: 9}, bundle.Version{Epoch: 2, Counter: 1}, op.OutcomeApplied, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			b1 := e.build(tTarget, tc.first, std("v1"))
			b1.att = e.sign(b1, tEnv, tTarget, b1.root.Digest, e.priv)
			wantOutcome(t, e.apply("op1", b1), op.OutcomeApplied, "", "")
			before := e.state()
			writes := len(e.storeWrites())
			b2 := e.build(tTarget, tc.again, std("v2"))
			b2.att = e.sign(b2, tEnv, tTarget, b2.root.Digest, e.priv)
			wantOutcome(t, e.apply("op2", b2), tc.outcome, tc.reason, "")
			if tc.outcome == op.OutcomeRefused {
				if len(e.storeWrites()) != writes {
					t.Fatal("a refused set wrote to the store")
				}
				if st := e.state(); st.Version != before.Version || st.Root.Digest != before.Root.Digest || st.State != "healthy" {
					t.Fatalf("a refusal moved the state: %+v", st)
				}
				if st := e.state(); st.Result.OpID != "op2" || st.Result.Reason != op.ReasonVersionOld {
					t.Fatalf("result = %+v", st.Result)
				}
			}
		})
	}
}

func TestApplySameVersion(t *testing.T) {
	e := newEnv(t)
	v := bundle.Version{Epoch: 1, Counter: 5}
	b := e.build(tTarget, v, std("v1"))
	b.att = e.sign(b, tEnv, tTarget, b.root.Digest, e.priv)
	wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
	writes := len(e.storeWrites())

	wantOutcome(t, e.apply("op2", b), op.OutcomeAlreadyApplied, "", "")
	if len(e.storeWrites()) != writes {
		t.Fatal("an applied set was written again")
	}

	c := e.build(tTarget, v, std("v2"))
	c.att = e.sign(c, tEnv, tTarget, c.root.Digest, e.priv)
	wantOutcome(t, e.apply("op3", c), op.OutcomeRefused, op.ReasonVersionOld, "version_conflict")
	if e.currentRoot() != b.root.Digest || e.state().Root.Digest != b.root.Digest {
		t.Fatal("a conflicting set moved the root")
	}
}

func TestApplyKeyResetAllowsLowerVersion(t *testing.T) {
	e := newEnv(t)
	var logs bytes.Buffer
	cfg := e.cfg
	cfg.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	e.a = e.applier(cfg)
	resets := func() int { return strings.Count(logs.String(), `"msg":"bundle_version_reset"`) }
	wantOutcome(t, e.apply("op1", e.set(9, std("v1"))), op.OutcomeApplied, "", "")
	oldKey := e.state().KeySHA256
	if oldKey == "" {
		t.Fatal("the state does not record the key")
	}
	same := e.set(1, std("v2"))
	wantOutcome(t, e.apply("op2", same), op.OutcomeRefused, op.ReasonVersionOld, "")
	if n := resets(); n != 0 {
		t.Fatalf("%d reset log lines with the same key", n)
	}

	e.pub, e.priv, _ = ed25519.GenerateKey(rand.Reader)
	low := e.set(1, std("v3"))
	wantOutcome(t, e.apply("op3", low), op.OutcomeApplied, "", "")
	if st := e.state(); st.Version.Counter != 1 || st.State != "healthy" {
		t.Fatalf("state = %+v", st)
	}
	if n := resets(); n != 1 || !strings.Contains(logs.String(), `"key":"`+oldKey+`"`) {
		t.Fatalf("%d reset log lines, want one that names the old key: %s", n, logs.String())
	}
}

func TestApplyRepeatedOpID(t *testing.T) {
	e := newEnv(t)
	b := e.set(3, std("v1"))
	wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
	writes, mirror := len(e.storeWrites()), len(e.mirrorReg.Requests())
	wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
	if len(e.storeWrites()) != writes || len(e.mirrorReg.Requests()) != mirror {
		t.Fatal("a repeated operation ID did work")
	}
	old := e.set(2, std("v0"))
	wantOutcome(t, e.apply("op2", old), op.OutcomeRefused, op.ReasonVersionOld, "")
	wantOutcome(t, e.apply("op2", old), op.OutcomeRefused, op.ReasonVersionOld, "")
	st := e.state()
	if st.Result.OpID != "op2" {
		t.Fatalf("result = %+v", st.Result)
	}
}

// brokenState is a state store whose reads fail.
type brokenState struct{ Store }

func (brokenState) Read(context.Context) (State, string, error) {
	return State{}, "", errors.New("state read refused")
}

func TestRecorded(t *testing.T) {
	e := newEnv(t)
	if _, ok, err := e.a.Recorded(t.Context(), "op1"); ok || err != nil {
		t.Fatalf("before any apply: ok %v err %v", ok, err)
	}
	wantOutcome(t, e.apply("op1", e.set(2, std("v1"))), op.OutcomeApplied, "", "")
	out, ok, err := e.a.Recorded(t.Context(), "op1")
	if err != nil || !ok || out != (Outcome{Outcome: op.OutcomeApplied}) {
		t.Fatalf("op1: %+v ok %v err %v", out, ok, err)
	}
	wantOutcome(t, e.apply("op2", e.set(1, std("v0"))), op.OutcomeRefused, op.ReasonVersionOld, "")
	out, ok, err = e.a.Recorded(t.Context(), "op2")
	if err != nil || !ok || out != (Outcome{Outcome: op.OutcomeRefused, Reason: op.ReasonVersionOld}) {
		t.Fatalf("op2: %+v ok %v err %v", out, ok, err)
	}
	// The refusal of op2 overwrote the stored result. The state still names op1 as healthy, so the
	// answer for op1 stays applied, on every repeat.
	for range 2 {
		if out, ok, err := e.a.Recorded(t.Context(), "op1"); err != nil || !ok || out != (Outcome{Outcome: op.OutcomeApplied}) {
			t.Fatalf("op1 after op2: %+v ok %v err %v, want applied", out, ok, err)
		}
	}
	wantOutcome(t, e.apply("op3", e.set(2, std("v9"))), op.OutcomeRefused, op.ReasonVersionOld, "version_conflict")
	if out, ok, err := e.a.Recorded(t.Context(), "op3"); err != nil || !ok || out.Detail != "version_conflict" {
		t.Fatalf("op3: %+v ok %v err %v", out, ok, err)
	}
	writes := len(e.storeWrites())
	_, rv, err := e.gate.Store.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.a.Recorded(t.Context(), "op4"); err != nil {
		t.Fatal(err)
	}
	if _, after, _ := e.gate.Store.Read(t.Context()); len(e.storeWrites()) != writes || after != rv {
		t.Fatal("a lookup wrote something")
	}
	cfg := e.cfg
	cfg.State = brokenState{}
	if _, ok, err := e.applier(cfg).Recorded(t.Context(), "op2"); err == nil || ok {
		t.Fatalf("a failed read gave ok %v err %v, want an error", ok, err)
	}
	for _, phase := range []string{"applying", "rolling_back"} {
		st := e.state()
		st.State, st.OpID = phase, "op5"
		e.mustWriteState(st)
		if _, ok, err := e.a.Recorded(t.Context(), "op5"); !errors.Is(err, ErrInFlight) || ok {
			t.Fatalf("%s: ok %v err %v, want ErrInFlight", phase, ok, err)
		}
		if _, ok, err := e.a.Recorded(t.Context(), "op6"); err != nil || ok {
			t.Fatalf("%s, another operation: ok %v err %v", phase, ok, err)
		}
	}
}

// TestRecordedRollbackAfterALaterRefusal checks that a rolled back operation keeps its answer when a
// later refusal overwrites the stored result.
func TestRecordedRollbackAfterALaterRefusal(t *testing.T) {
	e, _, b := twoSets(t)
	e.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app == "apps-sample" {
			return "Synced", "Degraded"
		}
		return "Synced", "Healthy"
	}
	wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
	e.health = nil
	wantOutcome(t, e.apply("opOld", e.set(1, std("old"))), op.OutcomeRefused, op.ReasonVersionOld, "")
	out, ok, err := e.a.Recorded(t.Context(), "opB")
	if err != nil || !ok || out != (Outcome{Outcome: op.OutcomeRolledBack, Reason: op.ReasonUnhealthy}) {
		t.Fatalf("opB: %+v ok %v err %v, want rolled_back unhealthy", out, ok, err)
	}
	if _, ok, err := e.a.Recorded(t.Context(), "opA"); ok || err != nil {
		t.Fatalf("opA, which the state no longer names: ok %v err %v", ok, err)
	}
}

func TestApplyTargetMismatch(t *testing.T) {
	t.Run("predicate names another target", func(t *testing.T) {
		e := newEnv(t)
		b := e.build("dev-cell-2", bundle.Version{Epoch: 1, Counter: 1}, std("v1"))
		b.att = e.sign(b, tEnv, "dev-cell-2", b.root.Digest, e.priv)
		out, err := e.a.Apply(t.Context(), "op1", tTarget, b.att)
		if err != nil {
			t.Fatal(err)
		}
		wantOutcome(t, out, op.OutcomeRefused, op.ReasonPayloadInvalid, "target")
		if len(e.storeWrites()) != 0 || e.state().Source != "bootstrap" {
			t.Fatal("a refused set changed the cluster")
		}
	})
	t.Run("predicate and operation name another target", func(t *testing.T) {
		e := newEnv(t)
		b := e.build("dev-cell-2", bundle.Version{Epoch: 1, Counter: 1}, std("v1"))
		b.att = e.sign(b, tEnv, "dev-cell-2", b.root.Digest, e.priv)
		out, err := e.a.Apply(t.Context(), "op1", "dev-cell-2", b.att)
		if err != nil {
			t.Fatal(err)
		}
		wantOutcome(t, out, op.OutcomeRefused, op.ReasonPayloadInvalid, "target")
		if len(e.storeWrites()) != 0 || e.state().Source != "bootstrap" {
			t.Fatal("a refused set changed the cluster")
		}
	})
	t.Run("operation names another target", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, std("v1"))
		out, err := e.a.Apply(t.Context(), "op1", "dev-cell-2", b.att)
		if err != nil {
			t.Fatal(err)
		}
		wantOutcome(t, out, op.OutcomeRefused, op.ReasonPayloadInvalid, "target")
		if len(e.storeWrites()) != 0 || e.state().Source != "bootstrap" {
			t.Fatal("a refused set changed the cluster")
		}
	})
}

func TestApplyAttestationInvalid(t *testing.T) {
	e := newEnv(t)
	b := e.set(1, std("v1"))
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name   string
		att    []byte
		reason string
		detail string
	}{
		{"signed by an untrusted key", e.sign(b, tEnv, tTarget, b.root.Digest, other), op.ReasonSignatureInvalid, ""},
		{"not an envelope", []byte("not json"), op.ReasonPayloadInvalid, "statement"},
		{"other environment", e.sign(b, "prod", tTarget, b.root.Digest, e.priv), op.ReasonEnvMismatch, ""},
		{"too large", append([]byte(`{"payloadType":"`), make([]byte, op.MaxBundleArgsBytes)...), op.ReasonPayloadInvalid, "statement"},
		{"subjects do not match the set", e.signRaw(t, func(st *bundle.Statement) { st.Subject = st.Subject[1:] }), op.ReasonPayloadInvalid, "subjects"},
		{"subject digest malformed", e.signRaw(t, func(st *bundle.Statement) { st.Subject[1].Digest.SHA256 = "x" }), op.ReasonPayloadInvalid, "subjects"},
		{"unknown field named like a subject", e.signBody(t, func(m map[string]any) { m["subjects"] = []any{} }), op.ReasonPayloadInvalid, "statement"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := e.a.Apply(t.Context(), "op-"+tc.name, tTarget, tc.att)
			if err != nil {
				t.Fatal(err)
			}
			wantOutcome(t, out, op.OutcomeRefused, tc.reason, tc.detail)
		})
	}
	if len(e.storeWrites()) != 0 || e.state().Source != "bootstrap" {
		t.Fatal("a refused attestation changed the cluster")
	}
}

// signRaw signs a statement of a valid set after mutate changes it, with no check of the result.
func (e *env) signRaw(t *testing.T, mutate func(*bundle.Statement)) []byte {
	t.Helper()
	b := e.build(tTarget, bundle.Version{Epoch: 1, Counter: 1}, std("raw"))
	st := bundle.NewStatement(tEnv, tTarget, b.set, b.root.Digest)
	mutate(&st)
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	env, err := record.SignEnvelope(bundle.PayloadType, body, e.priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// signBody signs the JSON form of a valid statement after mutate changes it.
func (e *env) signBody(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	b := e.build(tTarget, bundle.Version{Epoch: 1, Counter: 1}, std("raw"))
	raw, err := json.Marshal(bundle.NewStatement(tEnv, tTarget, b.set, b.root.Digest))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	env, err := record.SignEnvelope(bundle.PayloadType, body, e.priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestApplyKeysUnavailable checks that a missing key function, a failed key read and an empty key
// list give an error that the caller can retry, and no recorded refusal.
func TestApplyKeysUnavailable(t *testing.T) {
	readErr := errors.New("key directory not readable")
	cases := map[string]func(e *env) func() ([]crypto.PublicKey, error){
		"no key function": func(*env) func() ([]crypto.PublicKey, error) { return nil },
		"read fails": func(*env) func() ([]crypto.PublicKey, error) {
			return func() ([]crypto.PublicKey, error) { return nil, readErr }
		},
		"read fails with the last keys": func(e *env) func() ([]crypto.PublicKey, error) {
			return func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{e.pub}, readErr }
		},
		"no keys": func(*env) func() ([]crypto.PublicKey, error) {
			return func() ([]crypto.PublicKey, error) { return nil, nil }
		},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			b := e.set(1, std("v1"))
			cfg := e.cfg
			cfg.Keys = keys(e)
			out, err := e.applier(cfg).Apply(t.Context(), "op1", tTarget, b.att)
			if err == nil || out != (Outcome{}) {
				t.Fatalf("out %+v err %v, want an error and no outcome", out, err)
			}
			if strings.HasPrefix(name, "read fails") && !errors.Is(err, readErr) {
				t.Fatalf("err = %v, want the read error", err)
			}
			if st := e.state(); st.Result != nil || st.Holder != "" || st.Source != "bootstrap" || len(e.storeWrites()) != 0 {
				t.Fatalf("a key fault changed the state: %+v", st)
			}
			wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
		})
	}
}

func TestApplyRootSubjectMismatch(t *testing.T) {
	e := newEnv(t)
	b := e.build(tTarget, bundle.Version{Epoch: 1, Counter: 1}, std("v1"))
	b.att = e.sign(b, tEnv, tTarget, "sha256:"+strings.Repeat("a", 64), e.priv)
	wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonDigestMismatch, "root")
	if r := e.mirrorReg.Requests(); len(r) != 0 {
		t.Fatalf("the mirror was read before the root compare: %d requests", len(r))
	}
	if e.tagWrites() != 0 || e.currentRoot() != e.boot.root.Digest {
		t.Fatal("the root tag moved")
	}
	for _, w := range e.storeWrites() {
		if strings.Contains(w, "/bundles/root/") {
			t.Fatalf("the root was written: %s", w)
		}
	}
	if st := e.state(); st.State != "healthy" || st.Source != "bootstrap" || st.Holder != "" {
		t.Fatalf("state = %+v", st)
	}
}

func badApp(body string) []spec {
	return []spec{{"apps-sample", "apps-demo", body}}
}

func TestApplyComponentNotAllowed(t *testing.T) {
	role := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: evil\nrules: []\n"
	t.Run("kind", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, badApp(role))
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "kind")
		e.assertUntouched(t)
	})
	t.Run("unknown component", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, []spec{{"evil", "apps-demo", cmap("apps-demo", "x", "1")}})
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "component_unknown")
		e.assertUntouched(t)
	})
	t.Run("namespace of the component", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, []spec{{"apps-sample", "argocd", cmap("apps-demo", "x", "1")}})
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "namespace")
		e.assertUntouched(t)
	})
	for name, body := range map[string]string{
		"not canonical": cmap("apps-demo", "x", "1"),
		"json then yaml": `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":"apps-demo"}}` + "\n" +
			"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: pwn}\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			art, err := packRaw(map[string][]byte{"manifests.yaml": []byte(body)})
			if err != nil {
				t.Fatal(err)
			}
			e.seed(e.mirrorReg, "bundles/"+tTarget+"/apps-sample", art)
			b := e.set(1, std("v1"))
			set := b.set
			for i := range set.Components {
				if set.Components[i].Name == "apps-sample" {
					set.Components[i].Digest = art.Digest
				}
			}
			root, err := bundle.ComposeRoot("cell", set, e.cfg.Policy)
			if err != nil {
				t.Fatal(err)
			}
			b.set = set
			b.att = e.sign(b, tEnv, tTarget, root.Digest, e.priv)
			want := "not_canonical"
			if name == "json then yaml" {
				want = "layout"
			}
			wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, want)
			e.assertUntouched(t)
		})
	}
	t.Run("layout", func(t *testing.T) {
		e := newEnv(t)
		art, err := bundle.Pack(map[string][]byte{"manifests.yaml": canonBody(t, cmap("apps-demo", "x", "1")), "extra.yaml": []byte("a: b\n")})
		if err != nil {
			t.Fatal(err)
		}
		e.seed(e.mirrorReg, "bundles/"+tTarget+"/apps-sample", art)
		b := e.set(1, std("v1"))
		// Replace the component by the two-file artifact under its own digest.
		set := b.set
		for i := range set.Components {
			if set.Components[i].Name == "apps-sample" {
				set.Components[i].Digest = art.Digest
			}
		}
		root, err := bundle.ComposeRoot("cell", set, e.cfg.Policy)
		if err != nil {
			t.Fatal(err)
		}
		b.set = set
		b.att = e.sign(b, tEnv, tTarget, root.Digest, e.priv)
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "layout")
		e.assertUntouched(t)
	})
}

// assertUntouched checks that a refusal wrote nothing to the store, left the lock free and moved
// neither the mark nor the root.
func (e *env) assertUntouched(t *testing.T) {
	t.Helper()
	if w := e.storeWrites(); len(w) != 0 {
		t.Fatalf("store writes after a refusal: %v", w)
	}
	st := e.state()
	if st.Holder != "" || st.State != "healthy" || st.Version != (bundle.Version{}) || st.Root.Digest != e.boot.root.Digest {
		t.Fatalf("state after a refusal = %+v", st)
	}
	if st.Result == nil || st.Result.Outcome != op.OutcomeRefused {
		t.Fatalf("result = %+v", st.Result)
	}
}

func netpol(ns, name string) string {
	return fmt.Sprintf("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  podSelector: {}\n", name, ns)
}

func TestApplyHarnessPolicyNamed(t *testing.T) {
	harness := func(e *env, ns, name string) {
		_, err := e.cs.NetworkingV1().NetworkPolicies(ns).Create(t.Context(), &netv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"cell.poc.internal/harness": "x"}},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("reserved name", func(t *testing.T) {
		e := newEnv(t)
		harness(e, "argocd", "argocd-agent")
		b := e.set(1, []spec{{"argocd", "argocd", netpol("argocd", "argocd-agent")}})
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonPolicyBlocksPlanes, "argocd/argocd-agent")
		if e.state().Source != "bootstrap" || len(e.storeWrites()) != 0 {
			t.Fatal("a refused set changed the cluster")
		}
	})
	t.Run("live harness policy", func(t *testing.T) {
		e := newEnv(t)
		harness(e, "argocd", "harness-extra")
		b := e.set(1, []spec{{"argocd", "argocd", netpol("argocd", "harness-extra")}})
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonPolicyBlocksPlanes, "argocd/harness-extra")
	})
	t.Run("other policy passes", func(t *testing.T) {
		e := newEnv(t)
		harness(e, "argocd", "harness-extra")
		b := e.set(1, []spec{{"argocd", "argocd", netpol("argocd", "mine")}})
		wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
	})
}

func TestApplyDigestMismatch(t *testing.T) {
	t.Run("layer", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, std("v1"))
		e.mirrorReg.Corrupt(b.arts["apps-sample"].LayerDigest)
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonDigestMismatch, "apps-sample")
		e.assertUntouched(t)
	})
	t.Run("manifest", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, std("v1"))
		e.mirrorReg.Corrupt(b.arts["network-policy"].Digest)
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonDigestMismatch, "network-policy")
		e.assertUntouched(t)
	})
}

// TestApplySetTooLarge checks the limit on the layer bytes that one apply reads and holds.
func TestApplySetTooLarge(t *testing.T) {
	if New(Config{}).maxSetBytes != 64<<20 {
		t.Fatalf("default limit = %d, want 64 MiB", New(Config{}).maxSetBytes)
	}
	e := newEnv(t)
	b := e.set(1, std("v1"))
	total := 0
	for _, art := range b.arts {
		total += len(art.Layer)
	}
	e.a.maxSetBytes = total - 1
	wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "too_large")
	e.assertUntouched(t)
	e.a.maxSetBytes = total
	wantOutcome(t, e.apply("op2", e.set(2, std("v2"))), op.OutcomeApplied, "", "")
}

func TestApplyMirrorUnavailable(t *testing.T) {
	e := newEnv(t)
	b := e.set(1, std("v1"))
	e.mirrorReg.Missing(b.arts["apps-sample"].Digest)
	out, err := e.a.Apply(t.Context(), "op1", tTarget, b.att)
	if !errors.Is(err, ocistore.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if out != (Outcome{}) {
		t.Fatalf("outcome = %+v", out)
	}
	st := e.state()
	if st.Holder != "" || st.State != "healthy" || st.Source != "bootstrap" || len(e.storeWrites()) != 0 {
		t.Fatalf("a mirror fault changed the cluster: %+v", st)
	}
	wantOutcome(t, e.apply("op2", e.set(2, std("v2"))), op.OutcomeApplied, "", "")
}

// twoSets applies a good set A and returns it with a second set B for the rollback tests.
func twoSets(t *testing.T) (*env, built, built) {
	t.Helper()
	e := newEnv(t)
	a := e.set(1, std("a"))
	wantOutcome(t, e.apply("opA", a), op.OutcomeApplied, "", "")
	b := e.set(2, std("b"))
	return e, a, b
}

func (e *env) assertRolledBackTo(t *testing.T, a built, mark bundle.Version) {
	t.Helper()
	if got := e.currentRoot(); got != a.root.Digest {
		t.Fatalf("tag current = %s, want the last good root %s", got, a.root.Digest)
	}
	m, _ := e.storeReg.Manifest("bundles/root", "current")
	if string(m) != string(a.root.Manifest) {
		t.Fatal("the tag does not hold the manifest bytes of the last good root")
	}
	st := e.state()
	if st.State != "rolled_back" || st.Holder != "" || st.Version != mark {
		t.Fatalf("state = %+v", st)
	}
	if st.Root.Digest != a.root.Digest || fmt.Sprint(st.Components) != fmt.Sprint(a.digests()) {
		t.Fatalf("root %s components %v", st.Root.Digest, st.Components)
	}
	if len(st.Good) != 2 || st.Good[0].Root.Digest != a.root.Digest || st.Good[1].Root.Digest != e.boot.root.Digest {
		t.Fatalf("good = %+v", st.Good)
	}
	if st.Result == nil || st.Result.Outcome != op.OutcomeRolledBack {
		t.Fatalf("result = %+v", st.Result)
	}
}

func TestApplyRollbackOnDegraded(t *testing.T) {
	e, a, b := twoSets(t)
	e.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app == "apps-sample" {
			return "Synced", "Degraded"
		}
		return "Synced", "Healthy"
	}
	start := e.clk.Now()
	wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
	e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
	if el := e.clk.Now().Sub(start); el < time.Minute || el >= 3*time.Minute {
		t.Fatalf("the wait took %v, want the degraded grace of 1 minute", el)
	}
	st := e.state()
	if st.Result.Reason != op.ReasonUnhealthy || st.Result.Detail != "apps-sample:Synced/Degraded" || st.Result.OpID != "opB" {
		t.Fatalf("result = %+v", st.Result)
	}
	s, err := e.a.Status(t.Context())
	if err != nil || s.State != "rolled_back" || s.Version != (bundle.Version{Epoch: 1, Counter: 2}) || s.RootDigest != a.root.Digest {
		t.Fatalf("status = %+v, %v", s, err)
	}
}

func TestApplyRollbackOnTimeout(t *testing.T) {
	e, a, b := twoSets(t)
	e.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app == "apps-sample" {
			return "Synced", "Progressing"
		}
		return "Synced", "Healthy"
	}
	start := e.clk.Now()
	wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "timeout:apps-sample:Synced/Progressing")
	e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
	if el := e.clk.Now().Sub(start); el < 5*time.Minute {
		t.Fatalf("the wait took %v, want at least the health timeout", el)
	}
}

func TestApplyRollbackTimeoutNamesFirstChild(t *testing.T) {
	e, _, b := twoSets(t)
	e.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app != "root" {
			return "OutOfSync", "Progressing"
		}
		return "Synced", "Healthy"
	}
	wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "timeout:apps-sample:OutOfSync/Progressing")
}

func TestApplyRollbackUnhealthy(t *testing.T) {
	e, a, b := twoSets(t)
	e.health = func(root, app string) (string, string) {
		if app == "apps-sample" {
			return "Synced", "Degraded"
		}
		return "Synced", "Healthy"
	}
	wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "rollback_unhealthy")
	e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
}

func TestApplyRollbackNeverDeletes(t *testing.T) {
	e, _, b := twoSets(t)
	e.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app == "apps-sample" {
			return "Synced", "Degraded"
		}
		return "Synced", "Healthy"
	}
	wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
	for _, reg := range []*ocitest.Registry{e.storeReg, e.mirrorReg} {
		for _, r := range reg.Requests() {
			if r.Method == "DELETE" {
				t.Fatalf("registry delete: %s", r.Path)
			}
		}
	}
	for _, act := range e.dyn.Actions() {
		if strings.HasPrefix(act.GetVerb(), "delete") {
			t.Fatalf("dynamic delete: %v", act)
		}
	}
	for _, act := range e.cs.Actions() {
		if strings.HasPrefix(act.GetVerb(), "delete") {
			t.Fatalf("clientset delete: %v", act)
		}
	}
}

// TestApplyDegradedCountsOnlyTheWantedRevision checks that an Application that is Degraded at another
// revision does not end a wait early: Argo CD can need longer than the degraded grace to read a root.
func TestApplyDegradedCountsOnlyTheWantedRevision(t *testing.T) {
	t.Run("forward wait", func(t *testing.T) {
		e, a, b := twoSets(t)
		e.health = func(root, app string) (string, string) {
			if root == a.root.Digest && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
		e.step()
		e.lagged(90 * time.Second)
		wantOutcome(t, e.apply("opB", b), op.OutcomeApplied, "", "")
		if e.currentRoot() != b.root.Digest {
			t.Fatal("the set that fixes the Degraded app was rolled back")
		}
	})
	t.Run("rollback wait", func(t *testing.T) {
		e, a, b := twoSets(t)
		e.health = func(root, app string) (string, string) {
			if root == b.root.Digest && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
		e.lagged(90 * time.Second)
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
		e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
	})
	// Argo CD sets the revision when it compares, before the sync applies anything: the app shows the
	// new revision, OutOfSync, and the health of the old resources.
	t.Run("compared but not synced", func(t *testing.T) {
		e, a, b := twoSets(t)
		var t0 time.Time
		e.health = func(root, app string) (string, string) {
			switch {
			case app == "apps-sample" && root == a.root.Digest:
				return "Synced", "Degraded"
			case app == "apps-sample" && root == b.root.Digest && e.clk.Now().Sub(t0) < 90*time.Second:
				return "OutOfSync", "Degraded"
			}
			return "Synced", "Healthy"
		}
		e.step()
		t0 = e.clk.Now()
		wantOutcome(t, e.apply("opB", b), op.OutcomeApplied, "", "")
	})
	// The root takes the worst health of its children, so it stays Degraded at the new root while the
	// waves run, for example while the Argo CD controller restarts.
	t.Run("root shows the old child", func(t *testing.T) {
		e, a, b := twoSets(t)
		var t0 time.Time
		e.health = func(root, app string) (string, string) {
			slow := root == b.root.Digest && e.clk.Now().Sub(t0) < 90*time.Second
			switch {
			case root == a.root.Digest && (app == "apps-sample" || app == "root"):
				return "Synced", "Degraded"
			case app == "root" && slow:
				return "OutOfSync", "Degraded"
			case slow:
				return "OutOfSync", "Progressing"
			}
			return "Synced", "Healthy"
		}
		e.step()
		t0 = e.clk.Now()
		wantOutcome(t, e.apply("opB", b), op.OutcomeApplied, "", "")
	})
	t.Run("Degraded before the first compare", func(t *testing.T) {
		e, _, b := twoSets(t)
		var t0 time.Time
		early := func(root string) bool { return root == b.root.Digest && e.clk.Now().Sub(t0) < 90*time.Second }
		e.health = func(root, app string) (string, string) {
			if early(root) && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
		e.revision = func(root, app, rev string) string {
			if early(root) && app == "apps-sample" {
				return ""
			}
			return rev
		}
		t0 = e.clk.Now()
		wantOutcome(t, e.apply("opB", b), op.OutcomeApplied, "", "")
	})
	t.Run("synced and Degraded at the wanted revision", func(t *testing.T) {
		e, _, b := twoSets(t)
		e.health = func(root, app string) (string, string) {
			if root == b.root.Digest && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
		start := e.clk.Now()
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
		if el := e.clk.Now().Sub(start); el >= 3*time.Minute {
			t.Fatalf("the wait took %v, want the degraded grace", el)
		}
	})
}

// TestApplyRollbackStateFollowsTheTag checks that the state names the root that the tag holds when a
// rollback cannot move the tag: a corrupt last good root, or a refused tag write.
func TestApplyRollbackStateFollowsTheTag(t *testing.T) {
	degraded := func(e *env, b built) {
		e.health = func(root, app string) (string, string) {
			if root == b.root.Digest && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
	}
	check := func(t *testing.T, e *env, b built) {
		t.Helper()
		if got := e.currentRoot(); got != b.root.Digest {
			t.Fatalf("tag current = %s, want the failed root %s", got, b.root.Digest)
		}
		st := e.state()
		if st.State != "rolled_back" || st.Holder != "" || st.Root.Digest != b.root.Digest || string(st.Root.Manifest) != string(b.root.Manifest) {
			t.Fatalf("state root %s state %s, want the root that the tag holds", st.Root.Digest, st.State)
		}
		if fmt.Sprint(st.Components) != fmt.Sprint(b.digests()) {
			t.Fatalf("components = %v, want those of the root that the tag holds", st.Components)
		}
		s, err := e.a.Status(t.Context())
		if err != nil || s.RootDigest != b.root.Digest {
			t.Fatalf("status = %+v, %v", s, err)
		}
	}
	t.Run("last good root corrupt", func(t *testing.T) {
		e, _, b := twoSets(t)
		st := e.state()
		st.Good[0].Root.Manifest = append(slices.Clone(st.Good[0].Root.Manifest), ' ')
		e.mustWriteState(st)
		degraded(e, b)
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "rollback_unhealthy")
		check(t, e, b)
	})
	t.Run("rollback tag write refused", func(t *testing.T) {
		e, _, b := twoSets(t)
		degraded(e, b)
		first := e.polls + 1
		e.hook = func(n int) {
			if n == first {
				e.storeReg.Deny(http.StatusForbidden)
			}
		}
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "rollback_unhealthy")
		check(t, e, b)
	})
}

func TestApplyRollbackWithoutGoodRoot(t *testing.T) {
	e := newEnv(t)
	st := e.state()
	st.Root, st.Components, st.Good = Root{}, nil, nil
	e.mustWriteState(st)
	b := e.set(1, std("v1"))
	e.health = func(root, app string) (string, string) { return "Synced", "Degraded" }
	wantOutcome(t, e.apply("op1", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "rollback_unhealthy")
	if got := e.state(); got.State != "rolled_back" || got.Holder != "" {
		t.Fatalf("state = %+v", got)
	}
}

func TestApplyResumeAfterRestart(t *testing.T) {
	e := newEnv(t)
	b := e.set(1, std("v1"))
	e.health = func(root, app string) (string, string) { return "Synced", "Progressing" }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	e.hook = func(n int) {
		if n == 2 {
			e.gate.fail.Store(true)
			cancel()
		}
	}
	if _, err := e.a.Apply(ctx, "op1", tTarget, b.att); err == nil {
		t.Fatal("an apply with a canceled context succeeded")
	}
	e.gate.fail.Store(false)
	e.hook = nil
	st := e.state()
	if st.State != "applying" || st.Holder != "pod-a" || st.OpID != "op1" || !st.Until.After(e.clk.Now()) {
		t.Fatalf("state after the crash = %+v", st)
	}
	if e.currentRoot() != b.root.Digest {
		t.Fatal("the tag was not moved before the crash")
	}

	cfg := e.cfg
	cfg.Holder = "pod-b"
	second := e.applier(cfg)
	if _, err := second.Apply(t.Context(), "op1", tTarget, b.att); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("a live lock gave %v, want ErrLockHeld", err)
	}
	e.clk.Advance(time.Hour)
	e.health = nil
	out, err := second.Apply(t.Context(), "op1", tTarget, b.att)
	if err != nil {
		t.Fatal(err)
	}
	wantOutcome(t, out, op.OutcomeApplied, "", "")
	if st := e.state(); st.State != "healthy" || st.Holder != "" || st.Root.Digest != b.root.Digest || st.Result.OpID != "op1" {
		t.Fatalf("state after the resume = %+v", st)
	}
}

// TestApplyResumeRollbackAfterRestart checks that a process that takes over a rollback that a crash
// stopped resumes the rollback: it does not push the failed root again.
func TestApplyResumeRollbackAfterRestart(t *testing.T) {
	for name, again := range map[string]string{"same operation": "opB", "another operation of the same set": "opB2"} {
		t.Run(name, func(t *testing.T) {
			e, a, b := twoSets(t)
			before := e.state()
			e.health = func(root, app string) (string, string) {
				if root == b.root.Digest && app == "apps-sample" {
					return "Synced", "Degraded"
				}
				return "Synced", "Healthy"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			e.hook = func(int) {
				if e.currentRoot() == a.root.Digest {
					e.gate.fail.Store(true)
					cancel()
				}
			}
			if _, err := e.a.Apply(ctx, "opB", tTarget, b.att); err == nil {
				t.Fatal("an apply with a canceled context succeeded")
			}
			e.gate.fail.Store(false)
			e.hook = nil
			st := e.state()
			if st.State != "rolling_back" || st.Failed != "apps-sample:Synced/Degraded" || st.Holder != "pod-a" {
				t.Fatalf("state after the crash = %s failed %q holder %s", st.State, st.Failed, st.Holder)
			}

			cfg := e.cfg
			cfg.Holder = "pod-b"
			second := e.applier(cfg)
			e.clk.Advance(time.Hour)
			tags := e.tagWrites()
			var sawFailed bool
			e.hook = func(int) { sawFailed = sawFailed || e.currentRoot() == b.root.Digest }
			out, err := second.Apply(t.Context(), again, tTarget, b.att)
			if err != nil {
				t.Fatal(err)
			}
			wantOutcome(t, out, op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
			if n := e.tagWrites() - tags; n != 1 || sawFailed {
				t.Fatalf("the resume wrote the tag %d times and showed the failed root: %v; want one write of the good root", n, sawFailed)
			}
			e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
			if st := e.state(); st.Failed != "" || st.Result.OpID != again {
				t.Fatalf("failed %q result %+v", st.Failed, st.Result)
			}
			if st := e.state(); st.CheckedBy != before.CheckedBy || fmt.Sprint(st.Checked) != fmt.Sprint(before.Checked) {
				t.Fatalf("checked %v by %s, want the record of the good set %v by %s", st.Checked, st.CheckedBy, before.Checked, before.CheckedBy)
			}
		})
	}
}

// TestApplyOtherSetDuringRollingBack checks that a state in rolling_back resumes only for the set
// that failed, which the state names, and that any other set follows the version rules.
func TestApplyOtherSetDuringRollingBack(t *testing.T) {
	crash := func(t *testing.T) (*env, built, built) {
		t.Helper()
		e, a, b := twoSets(t)
		e.health = func(root, app string) (string, string) {
			if root == b.root.Digest && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		e.hook = func(int) {
			if e.currentRoot() == a.root.Digest {
				e.gate.fail.Store(true)
				cancel()
			}
		}
		if _, err := e.a.Apply(ctx, "opB", tTarget, b.att); err == nil {
			t.Fatal("an apply with a canceled context succeeded")
		}
		e.gate.fail.Store(false)
		e.hook, e.health = nil, nil
		if st := e.state(); st.State != "rolling_back" {
			t.Fatalf("state after the crash = %s", st.State)
		}
		cfg := e.cfg
		cfg.Holder = "pod-b"
		e.a = e.applier(cfg)
		e.clk.Advance(time.Hour)
		return e, a, b
	}
	t.Run("higher set", func(t *testing.T) {
		e, _, _ := crash(t)
		c := e.set(3, std("c"))
		wantOutcome(t, e.apply("opC", c), op.OutcomeApplied, "", "")
		st := e.state()
		if e.currentRoot() != c.root.Digest || st.State != "healthy" || st.Root.Digest != c.root.Digest {
			t.Fatalf("tag %s state %s root %s, want the higher set applied", e.currentRoot(), st.State, st.Root.Digest)
		}
		if st.Failed != "" {
			t.Fatalf("failed = %q after a later set", st.Failed)
		}
	})
	t.Run("same version, other content", func(t *testing.T) {
		e, _, _ := crash(t)
		other := e.set(2, std("other"))
		wantOutcome(t, e.apply("opX", other), op.OutcomeRefused, op.ReasonVersionOld, "version_conflict")
		if st := e.state(); st.State != "rolling_back" || e.currentRoot() == other.root.Digest {
			t.Fatalf("state %s tag %s", st.State, e.currentRoot())
		}
	})
}

func TestApplyLockHeld(t *testing.T) {
	t.Run("live lock", func(t *testing.T) {
		e := newEnv(t)
		st := e.state()
		st.Holder, st.Until = "pod-z", e.clk.Now().Add(10*time.Minute)
		e.mustWriteState(st)
		before := e.state()
		out, err := e.a.Apply(t.Context(), "op1", tTarget, e.set(1, std("v1")).att)
		if !errors.Is(err, ErrLockHeld) || out != (Outcome{}) {
			t.Fatalf("out %+v err %v", out, err)
		}
		if got := e.state(); fmt.Sprint(got) != fmt.Sprint(before) {
			t.Fatalf("the state changed: %+v", got)
		}
		if len(e.storeWrites()) != 0 || len(e.mirrorReg.Requests()) != 0 {
			t.Fatal("work started under a held lock")
		}
	})
	t.Run("same holder", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, std("v1"))
		next := e.set(2, std("v2"))
		type answer struct {
			out Outcome
			err error
		}
		var second []answer
		e.health = func(root, app string) (string, string) { return "Synced", "Progressing" }
		e.hook = func(n int) {
			if n != 1 {
				return
			}
			// A second call of the same process, while the first waits for health: an effect retry
			// or the next ops pull of envd.
			ch := make(chan answer, 2)
			for _, id := range []string{"op1", "op2"} {
				att := b.att
				if id == "op2" {
					att = next.att
				}
				go func() {
					out, err := e.a.Apply(t.Context(), id, tTarget, att)
					ch <- answer{out, err}
				}()
			}
			second = append(second, <-ch, <-ch)
			e.health = nil
		}
		wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
		if len(second) != 2 {
			t.Fatalf("%d second calls ran", len(second))
		}
		for _, a := range second {
			if !errors.Is(a.err, ErrLockHeld) || a.out != (Outcome{}) {
				t.Fatalf("a second call of the same holder gave %+v, %v; want ErrLockHeld", a.out, a.err)
			}
		}
		if st := e.state(); st.State != "healthy" || st.Holder != "" || st.Version.Counter != 1 || st.Result.OpID != "op1" {
			t.Fatalf("state = %+v", st)
		}
	})
	t.Run("expired lock", func(t *testing.T) {
		e := newEnv(t)
		st := e.state()
		st.Holder, st.Until = "pod-z", e.clk.Now().Add(-time.Second)
		e.mustWriteState(st)
		wantOutcome(t, e.apply("op1", e.set(1, std("v1"))), op.OutcomeApplied, "", "")
		if e.state().Holder != "" {
			t.Fatal("the lock was not released")
		}
	})
}

func TestApplyFirstSetChecksBootstrap(t *testing.T) {
	role := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: evil\nrules: []\n"
	t.Run("bootstrap digest is not trusted", func(t *testing.T) {
		e := newEnv(t)
		bad := e.build(tTarget, bundle.Version{}, badApp(role))
		st := e.state()
		st.Components = map[string]string{"apps-sample": bad.set.Components[0].Digest, "network-policy": e.boot.digests()["network-policy"]}
		e.mustWriteState(st)
		b := e.build(tTarget, bundle.Version{Epoch: 1, Counter: 1}, std("v1"))
		set := b.set
		for i := range set.Components {
			if set.Components[i].Name == "apps-sample" {
				set.Components[i].Digest = bad.set.Components[0].Digest
			}
		}
		b.set = set
		root, err := bundle.ComposeRoot("cell", set, e.cfg.Policy)
		if err != nil {
			t.Fatal(err)
		}
		b.att = e.sign(b, tEnv, tTarget, root.Digest, e.priv)
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "kind")
	})
	t.Run("a checked digest is not fetched again", func(t *testing.T) {
		e := newEnv(t)
		first := e.set(1, std("v1"))
		wantOutcome(t, e.apply("op1", first), op.OutcomeApplied, "", "")
		seen := len(e.mirrorReg.Requests())
		next := e.set(2, []spec{std("v1")[0], {"network-policy", "cell-system", cmap("cell-system", "np", "v2")}})
		if next.digests()["apps-sample"] != first.digests()["apps-sample"] {
			t.Fatal("test setup: the digest changed")
		}
		wantOutcome(t, e.apply("op2", next), op.OutcomeApplied, "", "")
		hex := strings.TrimPrefix(first.digests()["apps-sample"], "sha256:")
		for _, r := range e.mirrorReg.Requests()[seen:] {
			if strings.Contains(r.Path, hex) {
				t.Fatalf("a checked digest was fetched again: %s", r.Path)
			}
		}
	})
}

func TestApplyCheckedBounded(t *testing.T) {
	e := newEnv(t)
	var sets []built
	for i := uint64(1); i <= 3; i++ {
		b := e.set(i, std(fmt.Sprintf("v%d", i)))
		sets = append(sets, b)
		wantOutcome(t, e.apply(fmt.Sprintf("op%d", i), b), op.OutcomeApplied, "", "")
		if i == 1 {
			st := e.state()
			for name, d := range e.boot.digests() {
				if slices.Contains(st.Checked, name+"@"+d) {
					t.Fatalf("a bootstrap digest is in checked: %s", d)
				}
			}
			if len(st.Checked) != 2 {
				t.Fatalf("checked after one set = %v", st.Checked)
			}
		}
	}
	st := e.state()
	var want []string
	for _, b := range sets[1:] {
		for name, d := range b.digests() {
			want = append(want, name+"@"+d)
		}
	}
	got := slices.Clone(st.Checked)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("checked = %v\nwant      %v", got, want)
	}
	if len(st.Good) != 2 {
		t.Fatalf("good = %d entries", len(st.Good))
	}
}

// TestApplyCheckedFollowsThePolicyInputs checks that a digest that an earlier set checked is checked
// again when an input of the check has changed since: the live harness policies, the allow data, or a
// state that an older build wrote with no record of its inputs.
func TestApplyCheckedFollowsThePolicyInputs(t *testing.T) {
	harness := func(e *env, ns, name string) {
		t.Helper()
		_, err := e.cs.NetworkingV1().NetworkPolicies(ns).Create(t.Context(), &netv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"cell.poc.internal/harness": "x"}},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("new harness policy", func(t *testing.T) {
		e := newEnv(t)
		argocd := spec{"argocd", "argocd", netpol("argocd", "later")}
		wantOutcome(t, e.apply("op1", e.set(1, []spec{argocd, std("v1")[1]})), op.OutcomeApplied, "", "")
		if e.state().CheckedBy == "" {
			t.Fatal("the state does not record the inputs of the check")
		}
		harness(e, "argocd", "later")
		wantOutcome(t, e.apply("op2", e.set(2, []spec{argocd, std("v2")[1]})), op.OutcomeRefused, op.ReasonPolicyBlocksPlanes, "argocd/later")
	})
	widgets := func(ns string) spec {
		return spec{"network-policy", "cell-system", fmt.Sprintf("apiVersion: example.io/v1\nkind: Widget\nmetadata:\n  name: w\n  namespace: %s\n", ns)}
	}
	widgetCRD := func(scope string) spec {
		return spec{"argocd", "argocd", "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.io\nspec:\n  group: example.io\n  scope: " + scope + "\n  names:\n    kind: Widget\n    plural: widgets\n"}
	}
	served := func(e *env, namespaced bool) {
		e.disc.Resources = []*metav1.APIResourceList{{GroupVersion: "example.io/v1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: namespaced}}}}
	}
	t.Run("live scope changed", func(t *testing.T) {
		e := newEnv(t)
		served(e, true)
		wantOutcome(t, e.apply("op1", e.set(1, []spec{std("v1")[0], widgets("cell-system")})), op.OutcomeApplied, "", "")
		served(e, false)
		out := e.apply("op2", e.set(2, []spec{std("v2")[0], widgets("cell-system")}))
		if out.Outcome != op.OutcomeRefused || out.Reason != op.ReasonComponentNotAllowed {
			t.Fatalf("outcome = %+v, want the checked Widget component checked again and refused", out)
		}
	})
	t.Run("custom resource definition of the set disagrees with the live scope", func(t *testing.T) {
		e := newEnv(t)
		served(e, true)
		wantOutcome(t, e.apply("op1", e.set(1, []spec{widgetCRD("Namespaced"), widgets("cell-system")})), op.OutcomeApplied, "", "")
		out := e.apply("op2", e.set(2, []spec{widgetCRD("Cluster"), widgets("cell-system")}))
		if out.Outcome != op.OutcomeRefused || out.Reason != op.ReasonComponentNotAllowed {
			t.Fatalf("outcome = %+v, want the checked Widget component checked again under cluster scope", out)
		}
	})
	t.Run("custom resource definition of the set makes a kind namespaced", func(t *testing.T) {
		// The live API does not serve Widget. The first set defines it as Cluster, in a policy whose
		// platform class allows it as a cluster kind, and holds a Widget with no namespace. The next set
		// makes Widget Namespaced: the checked component must be checked again under that scope.
		e := newEnv(t)
		raw, err := json.Marshal(e.cfg.Policy)
		if err != nil {
			t.Fatal(err)
		}
		var wide bundle.Policy
		if err := json.Unmarshal(raw, &wide); err != nil {
			t.Fatal(err)
		}
		platform := wide.Classes["platform"]
		platform.ClusterKinds = append(slices.Clone(platform.ClusterKinds), "example.io/Widget")
		wide.Classes["platform"] = platform
		cfg := e.cfg
		cfg.Policy = wide
		e.a = e.applier(cfg)
		clusterWidget := spec{"network-policy", "cell-system", "apiVersion: example.io/v1\nkind: Widget\nmetadata:\n  name: w\n"}
		wantOutcome(t, e.apply("op1", e.set(1, []spec{widgetCRD("Cluster"), clusterWidget})), op.OutcomeApplied, "", "")
		out := e.apply("op2", e.set(2, []spec{widgetCRD("Namespaced"), clusterWidget}))
		if out.Outcome != op.OutcomeRefused || out.Reason != op.ReasonComponentNotAllowed {
			t.Fatalf("outcome = %+v, want the checked Widget component checked again under namespaced scope", out)
		}
	})
	t.Run("custom resource definition of the set agrees with the live scope", func(t *testing.T) {
		e := newEnv(t)
		served(e, true)
		first := e.set(1, []spec{widgetCRD("Namespaced"), widgets("cell-system")})
		wantOutcome(t, e.apply("op1", first), op.OutcomeApplied, "", "")
		seen := len(e.mirrorReg.Requests())
		crd := widgetCRD("Namespaced")
		crd.body += "  versions: []\n"
		wantOutcome(t, e.apply("op2", e.set(2, []spec{crd, widgets("cell-system")})), op.OutcomeApplied, "", "")
		hex := strings.TrimPrefix(first.digests()["network-policy"], "sha256:")
		for _, r := range e.mirrorReg.Requests()[seen:] {
			if strings.Contains(r.Path, hex) {
				t.Fatalf("a checked component was fetched again: %s", r.Path)
			}
		}
	})
	t.Run("harness policy renamed", func(t *testing.T) {
		e := newEnv(t)
		harness(e, "argocd", "first")
		later := spec{"argocd", "argocd", netpol("argocd", "later")}
		wantOutcome(t, e.apply("op1", e.set(1, []spec{later, std("v1")[1]})), op.OutcomeApplied, "", "")
		if err := e.cs.NetworkingV1().NetworkPolicies("argocd").Delete(t.Context(), "first", metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		harness(e, "argocd", "later")
		wantOutcome(t, e.apply("op2", e.set(2, []spec{later, std("v2")[1]})), op.OutcomeRefused, op.ReasonPolicyBlocksPlanes, "argocd/later")
	})
	t.Run("entry of an older good root", func(t *testing.T) {
		e := newEnv(t)
		later := spec{"argocd", "argocd", netpol("argocd", "later")}
		wantOutcome(t, e.apply("op1", e.set(1, []spec{later, std("v1")[1]})), op.OutcomeApplied, "", "")
		harness(e, "argocd", "later")
		other := spec{"argocd", "argocd", netpol("argocd", "other")}
		wantOutcome(t, e.apply("op2", e.set(2, []spec{other, std("v2")[1]})), op.OutcomeApplied, "", "")
		// good[1] still names the argocd digest that the first set checked before the harness policy.
		wantOutcome(t, e.apply("op3", e.set(3, []spec{later, std("v3")[1]})), op.OutcomeRefused, op.ReasonPolicyBlocksPlanes, "argocd/later")
	})
	t.Run("allow data changed", func(t *testing.T) {
		e := newEnv(t)
		wantOutcome(t, e.apply("op1", e.set(1, std("v1"))), op.OutcomeApplied, "", "")
		raw, err := json.Marshal(e.cfg.Policy)
		if err != nil {
			t.Fatal(err)
		}
		var narrow bundle.Policy
		if err := json.Unmarshal(raw, &narrow); err != nil {
			t.Fatal(err)
		}
		app := narrow.Classes["app"]
		app.NamespacedKinds = slices.DeleteFunc(slices.Clone(app.NamespacedKinds), func(k string) bool { return k == "ConfigMap" })
		narrow.Classes["app"] = app
		cfg := e.cfg
		cfg.Policy = narrow
		e.a = e.applier(cfg)
		next := e.set(2, []spec{std("v1")[0], std("v2")[1]})
		wantOutcome(t, e.apply("op2", next), op.OutcomeRefused, op.ReasonComponentNotAllowed, "kind")
	})
	t.Run("state of an older build", func(t *testing.T) {
		e := newEnv(t)
		role := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: evil\nrules: []\n"
		bad := e.build(tTarget, bundle.Version{}, badApp(role))
		d := bad.set.Components[0].Digest
		st := e.state()
		st.Checked = []string{d, "apps-sample@" + d}
		st.Components = map[string]string{"apps-sample": d, "network-policy": e.boot.digests()["network-policy"]}
		e.mustWriteState(st)
		b := e.build(tTarget, bundle.Version{Epoch: 1, Counter: 1}, std("v1"))
		set := b.set
		for i := range set.Components {
			if set.Components[i].Name == "apps-sample" {
				set.Components[i].Digest = d
			}
		}
		b.set = set
		root, err := bundle.ComposeRoot("cell", set, e.cfg.Policy)
		if err != nil {
			t.Fatal(err)
		}
		b.att = e.sign(b, tEnv, tTarget, root.Digest, e.priv)
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "kind")
	})
}

func TestCheckInputsCoverEveryInput(t *testing.T) {
	p := bundle.DefaultPolicy()
	base := func() checkIn {
		return checkIn{
			role: "cell", policy: p, module: policySource,
			harness:    HarnessRefs{NetworkPolicies: []ObjectRef{{Namespace: "argocd", Name: "argocd-agent"}}},
			cluster:    []string{"example.io/Gadget"},
			namespaced: []string{"example.io/Widget"},
			opa:        "1.0.0",
		}
	}
	want, err := checkInputs(base())
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := checkInputs(base()); again != want {
		t.Fatal("the fingerprint is not stable")
	}
	reordered := base()
	reordered.cluster = []string{"example.io/Gadget", "example.io/Bolt"}
	sorted := base()
	sorted.cluster = []string{"example.io/Bolt", "example.io/Gadget"}
	if x, _ := checkInputs(reordered); x != func() string { y, _ := checkInputs(sorted); return y }() {
		t.Fatal("the order of the live scopes changes the fingerprint")
	}
	narrow := bundle.Policy{Version: p.Version, Classes: p.Classes, Roles: map[string]bundle.Role{"cell": p.Roles["cell"]}}
	for name, mod := range map[string]func(*checkIn){
		"role":         func(in *checkIn) { in.role = "cp" },
		"allow":        func(in *checkIn) { in.policy = narrow },
		"rego":         func(in *checkIn) { in.module += "\n" },
		"harness":      func(in *checkIn) { in.harness = HarnessRefs{} },
		"harness name": func(in *checkIn) { in.harness.NetworkPolicies = []ObjectRef{{Namespace: "argocd", Name: "other"}} },
		"cluster scope": func(in *checkIn) {
			in.cluster, in.namespaced = []string{"example.io/Gadget", "example.io/Widget"}, nil
		},
		"namespaced scope": func(in *checkIn) { in.namespaced = append(in.namespaced, "example.io/Sprocket") },
		"opa version":      func(in *checkIn) { in.opa = "1.0.1" },
	} {
		in := base()
		mod(&in)
		fp, err := checkInputs(in)
		if err != nil || fp == want {
			t.Errorf("a change of the %s gives the same fingerprint (%v)", name, err)
		}
	}
}

// TestApplyCheckedKeyedByComponent checks that a digest checked for one component is checked again
// when another component names it, under the class of that component, and pushed to its repository.
func TestApplyCheckedKeyedByComponent(t *testing.T) {
	e := newEnv(t)
	first := e.set(1, std("v1"))
	wantOutcome(t, e.apply("op1", first), op.OutcomeApplied, "", "")
	np := first.arts["network-policy"]
	e.seed(e.mirrorReg, "bundles/"+tTarget+"/apps-sample", np)
	b := e.set(2, std("v2"))
	set := b.set
	for i := range set.Components {
		if set.Components[i].Name == "apps-sample" {
			set.Components[i].Digest = np.Digest
		}
	}
	b.set = set
	root, err := bundle.ComposeRoot("cell", set, e.cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	b.att = e.sign(b, tEnv, tTarget, root.Digest, e.priv)
	out := e.apply("op2", b)
	if out.Outcome != op.OutcomeRefused || out.Reason != op.ReasonComponentNotAllowed {
		t.Fatalf("outcome = %+v, want a component_not_allowed refusal from the class app", out)
	}
	for _, c := range e.state().Checked {
		if !strings.Contains(c, "@sha256:") {
			t.Fatalf("checked entry %q does not name its component", c)
		}
	}
}

func TestApplyScopesFromDiscoveryAndSet(t *testing.T) {
	widget := "apiVersion: example.io/v1\nkind: Widget\nmetadata:\n  name: w\n  namespace: cell-system\n"
	crd := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.io\nspec:\n  group: example.io\n  scope: Namespaced\n  names:\n    kind: Widget\n    plural: widgets\n"
	t.Run("unknown kind", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, []spec{{"network-policy", "cell-system", widget}})
		wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "kind_unknown_scope")
	})
	t.Run("live discovery", func(t *testing.T) {
		e := newEnv(t)
		e.disc.Resources = []*metav1.APIResourceList{{GroupVersion: "example.io/v1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: true}}}}
		b := e.set(1, []spec{{"network-policy", "cell-system", widget}})
		wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
	})
	t.Run("custom resource definition in another component", func(t *testing.T) {
		e := newEnv(t)
		b := e.set(1, []spec{{"argocd", "argocd", crd}, {"network-policy", "cell-system", widget}})
		wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
	})
}

func TestApplyLiveScopeWinsOverBundleCRD(t *testing.T) {
	e := newEnv(t)
	crd := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.io\nspec:\n  group: example.io\n  scope: Namespaced\n  names:\n    kind: Widget\n    plural: widgets\n"
	widget := "apiVersion: example.io/v1\nkind: Widget\nmetadata:\n  name: w\n  namespace: cell-system\n"
	e.disc.Resources = []*metav1.APIResourceList{{GroupVersion: "example.io/v1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: false}}}}
	b := e.set(1, []spec{{"argocd", "argocd", crd}, {"network-policy", "cell-system", widget}})
	wantOutcome(t, e.apply("op1", b), op.OutcomeRefused, op.ReasonComponentNotAllowed, "kind")
	e.assertUntouched(t)
}

func TestApplyFreshCheckerPerApply(t *testing.T) {
	e := newEnv(t)
	widget := func(v string) []spec {
		return []spec{{"network-policy", "cell-system", fmt.Sprintf("apiVersion: example.io/v1\nkind: Widget\nmetadata:\n  name: w%s\n  namespace: cell-system\n", v)}}
	}
	e.disc.Resources = []*metav1.APIResourceList{{GroupVersion: "example.io/v1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: true}}}}
	wantOutcome(t, e.apply("op1", e.set(1, widget("1"))), op.OutcomeApplied, "", "")
	e.disc.Resources = nil
	wantOutcome(t, e.apply("op2", e.set(2, widget("2"))), op.OutcomeRefused, op.ReasonComponentNotAllowed, "kind_unknown_scope")
}

func projectYAML(t *testing.T, name string, mutate func(spec map[string]any)) string {
	t.Helper()
	spec, err := ExpectedAppProjectSpec("cell", name, bundle.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(spec)
	}
	body, err := yaml.Marshal(map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "AppProject",
		"metadata": map[string]any{"name": name, "namespace": "argocd"},
		"spec":     spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestApplyAppProjectSpec(t *testing.T) {
	t.Run("expected projects", func(t *testing.T) {
		e := newEnv(t)
		body := projectYAML(t, "cell", nil) + "---\n" + projectYAML(t, "cell-app", nil)
		wantOutcome(t, e.apply("op1", e.set(1, []spec{{"argocd", "argocd", body}})), op.OutcomeApplied, "", "")
	})
	t.Run("locked default project", func(t *testing.T) {
		e := newEnv(t)
		raw, err := os.ReadFile("../../components/argocd/default-project.yaml")
		if err != nil {
			t.Fatal(err)
		}
		// kustomize gives every object of the argocd component the namespace argocd.
		locked := strings.Replace(string(raw), "  name: default\n", "  name: default\n  namespace: argocd\n", 1)
		body := projectYAML(t, "cell", nil) + "---\n" + locked
		wantOutcome(t, e.apply("op1", e.set(1, []spec{{"argocd", "argocd", body}})), op.OutcomeApplied, "", "")
	})
	t.Run("widened default project", func(t *testing.T) {
		e := newEnv(t)
		body := "apiVersion: argoproj.io/v1alpha1\nkind: AppProject\nmetadata:\n  name: default\n  namespace: argocd\nspec:\n  sourceRepos: ['*']\n  destinations: []\n  clusterResourceWhitelist: []\n  namespaceResourceWhitelist: []\n  description: Allows nothing. Applications use the project cell\n"
		wantOutcome(t, e.apply("op1", e.set(1, []spec{{"argocd", "argocd", body}})), op.OutcomeRefused, op.ReasonComponentNotAllowed, "appproject_spec")
		e.assertUntouched(t)
	})
	t.Run("widened destinations", func(t *testing.T) {
		e := newEnv(t)
		body := projectYAML(t, "cell-app", func(s map[string]any) {
			s["destinations"] = append(s["destinations"].([]any), map[string]any{"server": "https://kubernetes.default.svc", "namespace": "argocd"})
		})
		wantOutcome(t, e.apply("op1", e.set(1, []spec{{"argocd", "argocd", body}})), op.OutcomeRefused, op.ReasonComponentNotAllowed, "appproject_spec")
		e.assertUntouched(t)
	})
}

// packRaw builds a bundle artifact like bundle.Pack, without the canonical check of manifests.yaml,
// for tests of a layer that the applier must refuse.
func packRaw(files map[string][]byte) (bundle.Artifact, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(files[n])), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return bundle.Artifact{}, err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return bundle.Artifact{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return bundle.Artifact{}, err
	}
	dg := func(b []byte) string { sum := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(sum[:]) }
	a := bundle.Artifact{Layer: buf.Bytes(), Config: []byte("{}")}
	a.LayerDigest, a.ConfigDigest = dg(a.Layer), dg(a.Config)
	type desc struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	m, err := json.Marshal(struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Config        desc   `json:"config"`
		Layers        []desc `json:"layers"`
	}{2, bundle.MediaTypeManifest, desc{bundle.MediaTypeConfig, a.ConfigDigest, len(a.Config)},
		[]desc{{bundle.MediaTypeLayer, a.LayerDigest, len(a.Layer)}}})
	if err != nil {
		return bundle.Artifact{}, err
	}
	a.Manifest, a.Digest = m, dg(m)
	return a, nil
}

func TestPackRawMatchesPack(t *testing.T) {
	files := map[string][]byte{bundle.ManifestsFile: canonBody(t, cmap("apps-demo", "x", "1"))}
	a, err := bundle.Pack(files)
	if err != nil {
		t.Fatal(err)
	}
	b, err := packRaw(files)
	if err != nil || a.Digest != b.Digest || a.LayerDigest != b.LayerDigest {
		t.Fatalf("packRaw differs from Pack: %v", err)
	}
}
