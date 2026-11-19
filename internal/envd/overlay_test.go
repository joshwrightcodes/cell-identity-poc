package envd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// memSource is a RevocationSource that a test changes between rounds.
type memSource struct {
	mu  sync.Mutex
	in  [][]byte
	err error
}

func (s *memSource) Read(context.Context) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return slices.Clone(s.in), nil
}

func (s *memSource) set(err error, in ...[]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.in, s.err = in, err
}

// last returns the newest sync request that the gateway received.
func (g *memGateway) last(t *testing.T) gwapi.SyncRequest {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.syncs) == 0 {
		t.Fatal("the gateway received no sync")
	}
	return g.syncs[len(g.syncs)-1]
}

// ovRig runs pullers on a ConfigMap store with an overlay, against a management plane and a gateway.
type ovRig struct {
	t      *testing.T
	f      *fx
	opPub  ed25519.PublicKey
	opPriv ed25519.PrivateKey
	client *fake.Clientset
	up     *upstream
	gw     *memGateway
	src    *memSource
	logs   *syncBuffer
	read   *sdkmetric.ManualReader
}

// newOvRig saves the base state of f in the store, and the management plane serves the same spec.
func newOvRig(t *testing.T) *ovRig {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := &ovRig{t: t, f: newFx(t), opPub: pub, opPriv: priv, client: fake.NewClientset(), gw: &memGateway{},
		src: &memSource{}, logs: &syncBuffer{}, read: sdkmetric.NewManualReader()}
	cur, _ := r.f.base()
	if err := r.store().Save(t.Context(), cur); err != nil {
		t.Fatal(err)
	}
	r.up = newUpstream(t, r.spec(rev(1, 5), r.f.cell("a", rev(1, 2), false)), nil)
	return r
}

func (r *ovRig) operatorKeys() []ed25519.PublicKey { return []ed25519.PublicKey{r.opPub} }

func (r *ovRig) store() Store {
	return NewConfigMapStore(r.client, testNS, testName, testEnv, r.f.keys(), newLog(io.Discard), WithOperatorKeys(r.operatorKeys))
}

// spec returns a bundle at revision rv that holds cell, cells b at (1,3) and c at (1,4) of the base
// state, and the retired cell r. A cell of the empty name is left out, so the bundle retires a.
func (r *ovRig) spec(rv spec.Revision, a record.Cell) mgmtapi.SpecBundle {
	items := []item{r.f.item(r.f.cell("b", rev(1, 3), false)), r.f.item(r.f.cell("c", rev(1, 4), false))}
	retired := []spec.Retired{{Name: "r", Revision: rev(1, 3)}}
	if a.Name != "" {
		items = append(items, r.f.item(a))
	} else {
		retired = append([]spec.Retired{{Name: "a", Revision: rv}}, retired...)
	}
	return r.f.bundle(rv, items, retired)
}

// entry returns an entry for cell at record revision rec, signed with the operator key.
func (r *ovRig) entry(cell string, rec spec.Revision) []byte {
	r.t.Helper()
	return signEntry(r.t, r.opPriv, testEnv, cell, rec)
}

var entryIDs struct {
	sync.Mutex
	n int
}

func signEntry(t *testing.T, priv ed25519.PrivateKey, env, cell string, rec spec.Revision) []byte {
	t.Helper()
	entryIDs.Lock()
	entryIDs.n++
	id := fmt.Sprintf("%016x", entryIDs.n)
	entryIDs.Unlock()
	raw, err := revoke.Sign(revoke.Entry{ID: id, Env: env, Cell: cell, Record: rec,
		IssuedAt: time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// run runs a new puller for rounds rounds. after runs after each round, with the round number.
func (r *ovRig) run(rounds int, after func(round int)) *Puller {
	r.t.Helper()
	clk := newClock(rounds)
	n := 0
	p := NewPuller(PullerConfig{Client: r.up.client, BaseURL: r.up.url, Env: testEnv, Keys: r.f.keys(), Store: r.store(),
		Gateway: r.gw, OperatorKeys: r.operatorKeys, Revocations: r.src,
		Log: newLog(r.logs), Meter: sdkmetric.NewMeterProvider(sdkmetric.WithReader(r.read)).Meter("test"),
		Now: clk.Now, Sleep: func(ctx context.Context, d time.Duration) error {
			n++
			if after != nil {
				after(n)
			}
			return clk.Sleep(ctx, d)
		}})
	runRounds(r.t, p, clk)
	return p
}

// stored returns the overlay key of the records ConfigMap and whether it is present.
func (r *ovRig) stored() (string, bool) {
	r.t.Helper()
	v, ok := liveConfigMap(r.t, r.client).Data[RevocationsKey]
	return v, ok
}

// editStored changes the records ConfigMap the way an outside writer would.
func (r *ovRig) editStored(edit func(cm *corev1.ConfigMap)) {
	r.t.Helper()
	cm := liveConfigMap(r.t, r.client)
	edit(cm)
	if _, err := r.client.CoreV1().ConfigMaps(testNS).Update(r.t.Context(), cm, metav1.UpdateOptions{}); err != nil {
		r.t.Fatal(err)
	}
}

// updates counts the updates of the records ConfigMap so far.
func (r *ovRig) updates() int {
	n := 0
	for _, a := range r.client.Actions() {
		if a.GetVerb() == "update" && a.GetResource().Resource == "configmaps" {
			n++
		}
	}
	return n
}

func (r *ovRig) metric(name string) metricdata.Aggregation {
	r.t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.read.Collect(r.t.Context(), &rm); err != nil {
		r.t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m.Data
			}
		}
	}
	return nil
}

func (r *ovRig) heldGauge() int64 {
	r.t.Helper()
	g, ok := r.metric("envd.revocations.held").(metricdata.Gauge[int64])
	if !ok || len(g.DataPoints) != 1 {
		r.t.Fatalf("envd.revocations.held: %+v", r.metric("envd.revocations.held"))
	}
	return g.DataPoints[0].Value
}

func (r *ovRig) refusedCount(reason string) int64 {
	r.t.Helper()
	s, ok := r.metric("envd.revocations.refused").(metricdata.Sum[int64])
	if !ok {
		return 0
	}
	var n int64
	for _, dp := range s.DataPoints {
		if v, _ := dp.Attributes.Value("reason"); v.AsString() == reason {
			n += dp.Value
		}
	}
	return n
}

// lines returns the log lines with msg.
func (r *ovRig) lines(msg string) []map[string]any {
	var out []map[string]any
	for _, l := range r.logs.lines() {
		if l["msg"] == msg {
			out = append(out, l)
		}
	}
	return out
}

func list(envs ...[]byte) string {
	raw, err := json.Marshal(rawList(envs...))
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func rawList(envs ...[]byte) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(envs))
	for _, e := range envs {
		out = append(out, json.RawMessage(e))
	}
	return out
}

func sameList(got []json.RawMessage, want ...[]byte) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}

// TestOverlayHeldWithManagementDown: the spec pull fails, and envd still holds a signed entry from
// the input. It saves the entry in the records ConfigMap, sends it to the gateway and reports it.
func TestOverlayHeldWithManagementDown(t *testing.T) {
	r := newOvRig(t)
	r.up.failGet.Store(true)
	e := r.entry("a", rev(1, 2))
	r.src.set(nil, e)
	p := r.run(1, nil)

	if got, ok := r.stored(); !ok || got != list(e) {
		t.Errorf("stored overlay %q (present %v), want %q", got, ok, list(e))
	}
	if !bytes.Equal(p.state.Revocations["a"], e) || len(p.state.Revocations) != 1 {
		t.Errorf("held %v", p.state.Revocations)
	}
	if s := r.gw.last(t); !sameList(s.Revocations, e) {
		t.Errorf("gateway revocations %s", s.Revocations)
	}
	reps := r.up.got()
	if len(reps) != 1 || !sameList(reps[0].LocalRevocations, e) {
		t.Fatalf("reports %+v", reps)
	}
	held := r.lines("revocation_held")
	if len(held) != 1 || held[0]["cell"] != "a" || held[0]["id"] == "" {
		t.Errorf("revocation_held lines %v", held)
	}
	if n := r.heldGauge(); n != 1 {
		t.Errorf("held gauge %d", n)
	}
}

// TestOverlayRefusedUnsigned: entries that do not verify, name another env or name an unknown cell
// are never held. Each refusal is counted, and the log lines are limited.
func TestOverlayRefusedUnsigned(t *testing.T) {
	r := newOvRig(t)
	signed := r.entry("a", rev(1, 2))
	var env map[string]any
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	env["signatures"] = []any{}
	unsigned, _ := json.Marshal(env)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	in := [][]byte{
		unsigned,
		signEntry(t, otherKey, testEnv, "a", rev(1, 2)),
		[]byte("not an envelope"),
		signEntry(t, r.opPriv, "prod", "a", rev(1, 2)),
		r.entry("zz", rev(1, 2)),
	}
	r.src.set(nil, in...)
	const rounds = 3
	p := r.run(rounds, nil)

	if len(p.state.Revocations) != 0 {
		t.Errorf("held %v", p.state.Revocations)
	}
	if v, ok := r.stored(); ok {
		t.Errorf("stored overlay %q", v)
	}
	if s := r.gw.last(t); len(s.Revocations) != 0 {
		t.Errorf("gateway revocations %s", s.Revocations)
	}
	for _, rep := range r.up.got() {
		if len(rep.LocalRevocations) != 0 {
			t.Errorf("report %+v", rep)
		}
	}
	if n := r.refusedCount(revoke.ReasonInvalid); n != 4*rounds {
		t.Errorf("refused invalid %d, want %d", n, 4*rounds)
	}
	if n := r.refusedCount(revoke.ReasonUnknownCell); n != rounds {
		t.Errorf("refused unknown cell %d, want %d", n, rounds)
	}
	lines := r.lines("revocation_refused")
	seen := map[string]bool{}
	for _, l := range lines {
		seen[fmt.Sprint(l["reason"], "/", l["detail"])] = true
	}
	for _, want := range []string{"revocation_invalid/signature", "revocation_invalid/decode", "revocation_invalid/env", "revocation_unknown_cell/"} {
		if !seen[want] {
			t.Errorf("no revocation_refused line for %s in %v", want, lines)
		}
	}
	if len(lines) > 4 {
		t.Errorf("%d revocation_refused lines in %d rounds, want the limit of one for each kind", len(lines), rounds)
	}
	if n := r.heldGauge(); n != 0 {
		t.Errorf("held gauge %d", n)
	}
}

// TestOverlayHeldAcrossUnrelatedRevision: a newer record of the held cell that is not revoked keeps
// the entry, also while the input still holds it.
func TestOverlayHeldAcrossUnrelatedRevision(t *testing.T) {
	r := newOvRig(t)
	e := r.entry("a", rev(1, 2))
	r.src.set(nil, e)
	p := r.run(3, func(round int) {
		if round == 1 {
			r.up.set(r.spec(rev(1, 6), r.f.cell("a", rev(1, 6), false)))
		}
	})
	if p.state.Revision != rev(1, 6) {
		t.Fatalf("the newer spec was not applied: %v", p.state.Revision)
	}
	if !bytes.Equal(p.state.Revocations["a"], e) {
		t.Errorf("held %v", p.state.Revocations)
	}
	if got, _ := r.stored(); got != list(e) {
		t.Errorf("stored overlay %q", got)
	}
	if s := r.gw.last(t); !sameList(s.Revocations, e) {
		t.Errorf("gateway revocations %s", s.Revocations)
	}
	reps := r.up.got()
	if len(reps) != 3 || !sameList(reps[2].LocalRevocations, e) {
		t.Errorf("last report %+v", reps[len(reps)-1])
	}
	if l := r.lines("revocation_settled"); len(l) != 0 {
		t.Errorf("settled %v", l)
	}
	if l := r.lines("revocation_refused"); len(l) != 0 {
		t.Errorf("refused %v", l)
	}
}

// TestOverlaySettledByRevokedRecord: an accepted spec that revokes or retires the cell drops the
// entry. The input entry that stays behind then adds no store write and no refusal for a revoked
// cell.
func TestOverlaySettledByRevokedRecord(t *testing.T) {
	for name, tc := range map[string]struct {
		cause  string
		refuse string
	}{
		"revoked": {cause: "revoked"},
		"retired": {cause: "retired", refuse: revoke.ReasonUnknownCell},
	} {
		t.Run(name, func(t *testing.T) {
			r := newOvRig(t)
			e := r.entry("a", rev(1, 2))
			r.src.set(nil, e)
			next := r.spec(rev(1, 6), record.Cell{})
			if name == "revoked" {
				next = r.spec(rev(1, 6), r.f.cell("a", rev(1, 6), true))
			}
			var updates int
			p := r.run(4, func(round int) {
				switch round {
				case 1:
					if got, _ := r.stored(); got != list(e) {
						t.Errorf("round 1: stored overlay %q", got)
					}
					r.up.set(next)
				case 2:
					updates = r.updates()
				}
			})
			if len(p.state.Revocations) != 0 {
				t.Errorf("held %v", p.state.Revocations)
			}
			if v, ok := r.stored(); ok {
				t.Errorf("stored overlay %q", v)
			}
			if s := r.gw.last(t); len(s.Revocations) != 0 {
				t.Errorf("gateway revocations %s", s.Revocations)
			}
			reps := r.up.got()
			if last := reps[len(reps)-1]; len(last.LocalRevocations) != 0 {
				t.Errorf("last report %+v", last)
			}
			settled := r.lines("revocation_settled")
			if len(settled) != 1 || settled[0]["cell"] != "a" || settled[0]["cause"] != tc.cause {
				t.Errorf("settled lines %v", settled)
			}
			if n := r.updates(); n != updates {
				t.Errorf("rounds 3 and 4 wrote the store %d times", n-updates)
			}
			refused := r.lines("revocation_refused")
			switch tc.refuse {
			case "":
				if len(refused) != 0 || r.refusedCount(revoke.ReasonStale) != 0 {
					t.Errorf("the entry of a revoked cell was refused: %v", refused)
				}
			default:
				if len(refused) != 1 || refused[0]["reason"] != tc.refuse {
					t.Errorf("refused lines %v, want one %s", refused, tc.refuse)
				}
			}
			if n := r.heldGauge(); n != 0 {
				t.Errorf("held gauge %d", n)
			}
		})
	}
}

// TestOverlayReplayAfterUnrevokeRefused: an entry settles when its cell is revoked. After an
// un-revoke, the same entry in the input names a record below the current one and is refused.
func TestOverlayReplayAfterUnrevokeRefused(t *testing.T) {
	r := newOvRig(t)
	e := r.entry("a", rev(1, 2))
	r.src.set(nil, e)
	p := r.run(4, func(round int) {
		switch round {
		case 1:
			r.up.set(r.spec(rev(1, 6), r.f.cell("a", rev(1, 6), true)))
		case 2:
			r.up.set(r.spec(rev(1, 7), r.f.cell("a", rev(1, 7), false)))
		}
	})
	if p.state.Revision != rev(1, 7) || p.state.Cells["a"].Revoked {
		t.Fatalf("the un-revoke was not applied: %v", p.state.Revision)
	}
	if len(p.state.Revocations) != 0 {
		t.Errorf("held %v", p.state.Revocations)
	}
	if v, ok := r.stored(); ok {
		t.Errorf("stored overlay %q", v)
	}
	if s := r.gw.last(t); len(s.Revocations) != 0 {
		t.Errorf("gateway revocations %s", s.Revocations)
	}
	refused := r.lines("revocation_refused")
	if len(refused) != 1 || refused[0]["reason"] != revoke.ReasonStale || refused[0]["cell"] != "a" {
		t.Errorf("refused lines %v", refused)
	}
	if n := r.refusedCount(revoke.ReasonStale); n != 2 {
		t.Errorf("refused stale %d, want one in each of rounds 3 and 4", n)
	}
}

// TestOverlaySurvivesRestart: a new puller loads the held entry from the store and keeps it while
// the management plane is down and the input is empty.
func TestOverlaySurvivesRestart(t *testing.T) {
	r := newOvRig(t)
	e := r.entry("a", rev(1, 2))
	r.src.set(nil, e)
	r.run(1, nil)

	r.src.set(nil)
	r.up.failGet.Store(true)
	before := len(r.up.got())
	p := r.run(2, nil)
	if !bytes.Equal(p.state.Revocations["a"], e) || len(p.state.Revocations) != 1 {
		t.Errorf("held after restart %v", p.state.Revocations)
	}
	if got, _ := r.stored(); got != list(e) {
		t.Errorf("stored overlay %q", got)
	}
	if s := r.gw.last(t); !sameList(s.Revocations, e) {
		t.Errorf("gateway revocations %s", s.Revocations)
	}
	reps := r.up.got()[before:]
	if len(reps) != 2 || !sameList(reps[0].LocalRevocations, e) {
		t.Errorf("reports after restart %+v", reps)
	}
	if l := r.lines("revocation_settled"); len(l) != 0 {
		t.Errorf("settled %v", l)
	}
}

// TestOverlayStaleAfterRestartDropped: a stored entry that a new puller loads is checked once,
// against the record of its cell in the spec of the same store. A stale one settles. Afterwards the
// loaded entry follows the settle rule, so a pulled newer record that is not revoked keeps it.
func TestOverlayStaleAfterRestartDropped(t *testing.T) {
	plant := func(r *ovRig, e []byte) {
		r.editStored(func(cm *corev1.ConfigMap) { cm.Data[RevocationsKey] = list(e) })
	}
	newer := func(r *ovRig) mgmtapi.SpecBundle { return r.spec(rev(1, 6), r.f.cell("a", rev(1, 6), false)) }

	t.Run("stored_spec", func(t *testing.T) {
		r := newOvRig(t)
		st, _, err := Accept(Empty(), newer(r), testEnv, r.f.keys())
		if err != nil {
			t.Fatal(err)
		}
		if err := r.store().Save(t.Context(), st); err != nil {
			t.Fatal(err)
		}
		plant(r, r.entry("a", rev(1, 2)))
		r.up.failGet.Store(true)
		p := r.run(1, nil)
		if len(p.state.Revocations) != 0 {
			t.Errorf("held %v", p.state.Revocations)
		}
		if v, ok := r.stored(); ok {
			t.Errorf("stored overlay %q", v)
		}
		if s := r.gw.last(t); len(s.Revocations) != 0 {
			t.Errorf("gateway revocations %s", s.Revocations)
		}
		if reps := r.up.got(); len(reps) != 1 || len(reps[0].LocalRevocations) != 0 {
			t.Errorf("reports %+v", reps)
		}
		settled := r.lines("revocation_settled")
		if len(settled) != 1 || settled[0]["cell"] != "a" || settled[0]["cause"] != "stale" {
			t.Errorf("settled lines %v", settled)
		}
	})

	t.Run("first_pull", func(t *testing.T) {
		r := newOvRig(t)
		e := r.entry("a", rev(1, 2))
		plant(r, e)
		r.up.set(newer(r))
		r.up.failGet.Store(true)
		var held1 []json.RawMessage
		p := r.run(2, func(round int) {
			if round == 1 {
				held1 = r.gw.last(t).Revocations
				r.up.failGet.Store(false)
			}
		})
		if !sameList(held1, e) {
			t.Errorf("round 1 with the stored spec: gateway revocations %s", held1)
		}
		if p.state.Revision != rev(1, 6) || !bytes.Equal(p.state.Revocations["a"], e) {
			t.Errorf("after the first pull: revision %v, held %v", p.state.Revision, p.state.Revocations)
		}
		if got, _ := r.stored(); got != list(e) {
			t.Errorf("stored overlay %q", got)
		}
		if l := r.lines("revocation_settled"); len(l) != 0 {
			t.Errorf("settled %v", l)
		}
	})

	// rollback_residual: a writer of the records ConfigMap puts back an older signed spec with an
	// old entry. The marks come from the stored spec itself, so the restart accepts the older spec,
	// the entry is not stale against it, and the first pull keeps it. This is the T4 residual.
	t.Run("rollback_residual", func(t *testing.T) {
		r := newOvRig(t)
		st, _, err := Accept(Empty(), newer(r), testEnv, r.f.keys())
		if err != nil {
			t.Fatal(err)
		}
		if err := r.store().Save(t.Context(), st); err != nil {
			t.Fatal(err)
		}
		older, _ := r.f.base()
		writeOutside(t, r.client, older, KeyFingerprint(r.f.keys()))
		e := r.entry("a", rev(1, 2))
		plant(r, e)
		r.up.set(newer(r))
		p := r.run(2, nil)
		if p.state.Revision != rev(1, 6) || !bytes.Equal(p.state.Revocations["a"], e) {
			t.Errorf("revision %v, held %v", p.state.Revision, p.state.Revocations)
		}
	})

	t.Run("confirmed_by_pull", func(t *testing.T) {
		r := newOvRig(t)
		e := r.entry("a", rev(1, 2))
		plant(r, e)
		p := r.run(3, func(round int) {
			if round == 1 {
				r.up.set(newer(r))
			}
		})
		if p.state.Revision != rev(1, 6) || !bytes.Equal(p.state.Revocations["a"], e) {
			t.Errorf("revision %v, held %v", p.state.Revision, p.state.Revocations)
		}
		if l := r.lines("revocation_settled"); len(l) != 0 {
			t.Errorf("settled %v", l)
		}
	})
}

// TestOverlayRestartKeepsEntryAcrossUnrelatedRecord: envd holds an entry, restarts during an island
// and then pulls a newer record of the cell that is not revoked. The entry stays held.
func TestOverlayRestartKeepsEntryAcrossUnrelatedRecord(t *testing.T) {
	r := newOvRig(t)
	e := r.entry("a", rev(1, 2))
	r.src.set(nil, e)
	r.run(1, nil)
	if got, _ := r.stored(); got != list(e) {
		t.Fatalf("before the restart: stored overlay %q", got)
	}

	r.up.failGet.Store(true)
	before := len(r.up.got())
	p := r.run(3, func(round int) {
		if round == 1 {
			r.up.set(r.spec(rev(1, 6), r.f.cell("a", rev(1, 6), false)))
			r.up.failGet.Store(false)
		}
	})
	if p.state.Revision != rev(1, 6) {
		t.Fatalf("the newer spec was not applied: %v", p.state.Revision)
	}
	if !bytes.Equal(p.state.Revocations["a"], e) || len(p.state.Revocations) != 1 {
		t.Errorf("held %v", p.state.Revocations)
	}
	if got, _ := r.stored(); got != list(e) {
		t.Errorf("stored overlay %q", got)
	}
	if s := r.gw.last(t); !sameList(s.Revocations, e) {
		t.Errorf("gateway revocations %s", s.Revocations)
	}
	reps := r.up.got()[before:]
	if len(reps) != 3 || !sameList(reps[2].LocalRevocations, e) {
		t.Errorf("reports after the restart %+v", reps)
	}
	if l := r.lines("revocation_settled"); len(l) != 0 {
		t.Errorf("settled %v", l)
	}
	if l := r.lines("revocation_refused"); len(l) != 0 {
		t.Errorf("refused %v", l)
	}
}

// TestOverlayStoreCanonical: the overlay key is part of the canonical form of the store. A stripped,
// reformatted, extended or broken key is written back from the held overlay.
func TestOverlayStoreCanonical(t *testing.T) {
	// clean is what Peek says after the edit: a stored overlay in the canonical form of its own
	// content is clean, and the puller still writes back the overlay that it holds.
	for name, tc := range map[string]struct {
		edit  func(r *ovRig, cm *corev1.ConfigMap)
		clean bool
	}{
		"stripped": {edit: func(_ *ovRig, cm *corev1.ConfigMap) { delete(cm.Data, RevocationsKey) }, clean: true},
		"spaced": {edit: func(_ *ovRig, cm *corev1.ConfigMap) {
			var v []json.RawMessage
			if err := json.Unmarshal([]byte(cm.Data[RevocationsKey]), &v); err != nil {
				panic(err)
			}
			raw, _ := json.MarshalIndent(v, "", "  ")
			cm.Data[RevocationsKey] = string(raw)
		}},
		"planted": {edit: func(r *ovRig, cm *corev1.ConfigMap) {
			cm.Data[RevocationsKey] = strings.TrimSuffix(cm.Data[RevocationsKey], "]") + "," + string(r.entry("b", rev(1, 3))) + "]"
		}, clean: true},
		"junk":  {edit: func(_ *ovRig, cm *corev1.ConfigMap) { cm.Data[RevocationsKey] = "not json" }},
		"empty": {edit: func(_ *ovRig, cm *corev1.ConfigMap) { cm.Data[RevocationsKey] = "[]" }},
	} {
		t.Run(name, func(t *testing.T) {
			r := newOvRig(t)
			e := r.entry("a", rev(1, 2))
			r.src.set(nil, e)
			var edited string
			p := r.run(2, func(round int) {
				if round == 1 {
					if _, clean, err := r.store().Peek(t.Context()); err != nil || !clean {
						t.Errorf("after the save: clean %v, err %v", clean, err)
					}
					r.editStored(func(cm *corev1.ConfigMap) { tc.edit(r, cm) })
					edited = liveConfigMap(t, r.client).Data[RevocationsKey]
					if _, clean, err := r.store().Peek(t.Context()); err != nil || clean != tc.clean {
						t.Errorf("after the edit: clean %v, err %v, want clean %v", clean, err, tc.clean)
					}
				}
			})
			if got, ok := r.stored(); !ok || got != list(e) {
				t.Errorf("stored overlay %q after the edit %q, want %q", got, edited, list(e))
			}
			if len(p.state.Revocations) != 1 || !bytes.Equal(p.state.Revocations["a"], e) {
				t.Errorf("held %v", p.state.Revocations)
			}
			if _, clean, err := r.store().Peek(t.Context()); err != nil || !clean {
				t.Errorf("after the repair: clean %v, err %v", clean, err)
			}
		})
	}
}

// TestOverlayInputReadError: a failed read of the input keeps the held overlay.
func TestOverlayInputReadError(t *testing.T) {
	r := newOvRig(t)
	e := r.entry("a", rev(1, 2))
	r.src.set(nil, e)
	p := r.run(3, func(round int) {
		if round == 1 {
			r.src.set(errors.New("apiserver unavailable"))
		}
	})
	if !bytes.Equal(p.state.Revocations["a"], e) {
		t.Errorf("held %v", p.state.Revocations)
	}
	if got, _ := r.stored(); got != list(e) {
		t.Errorf("stored overlay %q", got)
	}
	if s := r.gw.last(t); !sameList(s.Revocations, e) {
		t.Errorf("gateway revocations %s", s.Revocations)
	}
	reps := r.up.got()
	if last := reps[len(reps)-1]; !sameList(last.LocalRevocations, e) {
		t.Errorf("last report %+v", last)
	}
	if n := len(r.lines("revocation input read failed")); n != 1 {
		t.Errorf("%d read failure lines in 2 rounds, want 1", n)
	}
	if l := r.lines("revocation_settled"); len(l) != 0 {
		t.Errorf("settled %v", l)
	}
}

// TestConfigMapRevocationsRead: the input ConfigMap gives its values in key order, an absent
// ConfigMap gives no entries, and an API error is an error.
func TestConfigMapRevocationsRead(t *testing.T) {
	c := fake.NewClientset()
	src := ConfigMapRevocations{Client: c, Namespace: "envd-system", Name: "local-revocations"}
	if in, err := src.Read(t.Context()); err != nil || len(in) != 0 {
		t.Fatalf("absent: %q %v", in, err)
	}
	if _, err := c.CoreV1().ConfigMaps("envd-system").Create(t.Context(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "local-revocations", Namespace: "envd-system"},
		Data:       map[string]string{"00000000000000b2.json": "two", "00000000000000a1.json": "one"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	in, err := src.Read(t.Context())
	if err != nil || len(in) != 2 || string(in[0]) != "one" || string(in[1]) != "two" {
		t.Fatalf("read %q %v", in, err)
	}
	c.PrependReactor("get", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	if _, err := src.Read(t.Context()); err == nil {
		t.Fatal("an API error gave no error")
	}
}

// junkArray returns a JSON array of n items "1".
func junkArray(n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat("1,", n), ",") + "]"
}

// TestOverlayHostileInput: an input or a stored overlay above its bound is refused before any
// parse. A refused input keeps the held overlay, and a refused stored overlay is written back.
func TestOverlayHostileInput(t *testing.T) {
	junk := func(n, size int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = bytes.Repeat([]byte("x"), size)
		}
		return out
	}
	for name, in := range map[string][][]byte{
		"too_many_entries": junk(MaxRevocationInputs+1, 1),
		"too_many_bytes":   junk(MaxRevocationInputBytes/revoke.MaxEntryBytes+1, revoke.MaxEntryBytes),
	} {
		t.Run("input_"+name, func(t *testing.T) {
			r := newOvRig(t)
			e := r.entry("a", rev(1, 2))
			r.src.set(nil, e)
			p := r.run(3, func(round int) {
				if round == 1 {
					r.src.set(nil, append(in, r.entry("b", rev(1, 3)))...)
				}
			})
			if len(p.state.Revocations) != 1 || !bytes.Equal(p.state.Revocations["a"], e) {
				t.Errorf("held %v", p.state.Revocations)
			}
			if n := r.refusedCount(revoke.ReasonInvalid); n != 0 {
				t.Errorf("%d entries of a refused input were checked one by one", n)
			}
			lines := r.lines("revocation input read failed")
			if len(lines) != 1 || !strings.Contains(fmt.Sprint(lines[0]["error"]), "too large") {
				t.Errorf("read failure lines %v", lines)
			}
		})
	}

	t.Run("configmap_too_many_keys", func(t *testing.T) {
		c := fake.NewClientset()
		data := map[string]string{}
		for i := range 10 * MaxRevocationInputs {
			data[fmt.Sprintf("%016x.json", i)] = "1"
		}
		if _, err := c.CoreV1().ConfigMaps("envd-system").Create(t.Context(), &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "local-revocations", Namespace: "envd-system"}, Data: data}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		in, err := ConfigMapRevocations{Client: c, Namespace: "envd-system", Name: "local-revocations"}.Read(t.Context())
		if !errors.Is(err, ErrRevocationInputTooLarge) || in != nil {
			t.Fatalf("read %d entries, err %v", len(in), err)
		}
	})

	// store_many_items holds one signed entry more than revoke.MaxHeld, each for a cell of its own,
	// so only the item cap keeps revoke.Load from holding the first revoke.MaxHeld of them.
	for name, stored := range map[string]func(r *ovRig) string{
		"store_junk_array": func(*ovRig) string { return junkArray(512 << 10) },
		"store_many_items": func(r *ovRig) string {
			var envs [][]byte
			for i := range revoke.MaxHeld + 1 {
				envs = append(envs, r.entry(fmt.Sprintf("x%02d", i), rev(1, 2)))
			}
			return list(envs...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newOvRig(t)
			e := r.entry("a", rev(1, 2))
			r.src.set(nil, e)
			r.run(1, nil)
			value := stored(r)
			r.editStored(func(cm *corev1.ConfigMap) { cm.Data[RevocationsKey] = value })

			var before, after goruntime.MemStats
			goruntime.GC()
			goruntime.ReadMemStats(&before)
			live, clean, err := r.store().Peek(t.Context())
			goruntime.ReadMemStats(&after)
			if err != nil || clean || len(live.Revocations) != 0 {
				t.Fatalf("Peek: clean %v, held %v, err %v", clean, live.Revocations, err)
			}
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 16<<20 {
				t.Errorf("Peek of a stored overlay of %d bytes allocated %d bytes", len(value), grew)
			}
			r.run(1, nil)
			if got, _ := r.stored(); got != list(e) {
				t.Errorf("stored overlay %.80q, want it written back", got)
			}
		})
	}
}
