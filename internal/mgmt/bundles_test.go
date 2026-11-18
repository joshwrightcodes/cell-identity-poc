package mgmt

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const cpTarget = "dev-cp"

func digestOf(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func cellComps() []bundle.Component {
	return []bundle.Component{
		{Name: "apps-sample", Wave: 10, Namespace: "apps-demo", Digest: digestOf('b')},
		{Name: "argocd", Wave: -5, Namespace: "argocd", Digest: digestOf('a')},
		{Name: "namespaces", Wave: -10, Namespace: "default", Digest: digestOf('c')},
	}
}

func cpComps() []bundle.Component {
	return []bundle.Component{
		{Name: "argocd", Wave: -5, Namespace: "argocd", Digest: digestOf('a')},
		{Name: "namespaces", Wave: -10, Namespace: "default", Digest: digestOf('c')},
		{Name: "spire-server", Wave: 5, Namespace: "spire-system", Digest: digestOf('d'), IgnoreDifferences: json.RawMessage(`[{"kind":"ConfigMap","name":"x","jsonPointers":["/data"]}]`)},
	}
}

func (r *rig) signBundle(target string, comps []bundle.Component, serve bool) mgmtapi.BundleSignResult {
	r.t.Helper()
	res, err := r.plane.SignBundle(r.t.Context(), target, comps, 0, serve)
	if err != nil {
		r.t.Fatalf("SignBundle(%s): %v", target, err)
	}
	return res
}

func (r *rig) bundleOf(target string) *BundleState {
	r.t.Helper()
	return r.plane.snap.Load().st.Bundles[target]
}

// bundleResult builds the final result that the applier of the target reports for the operation.
func (r *rig) bundleResult(opID, outcome string) op.Result {
	r.t.Helper()
	v, err := r.plane.OpView(opID)
	if err != nil {
		r.t.Fatal(err)
	}
	return op.Result{
		OpID: opID, Cell: v.Cell, Pod: "celld-0", Outcome: outcome, Fence: op.Fence{Epoch: 1, Counter: 1},
		At: r.clk.Now(), EnvelopeSHA256: op.EnvelopeSHA256(v.Envelope),
	}
}

func (r *rig) planeOpen() bool { return len(r.plane.OpenOps().PlaneBundle) > 0 }

func (r *rig) reportPlane(res *op.Result) {
	r.plane.Report(mgmtapi.StatusReport{PlaneBundle: res})
}

func TestSignBundleVersionRises(t *testing.T) {
	r, _ := boundRig(t)
	var last bundle.Version
	for i := uint64(1); i <= 3; i++ {
		res := r.signBundle(cell1, cellComps(), false)
		if res.Version != (bundle.Version{Epoch: 1, Counter: i}) {
			t.Fatalf("set %d has version %+v", i, res.Version)
		}
		last = res.Version
	}
	// Each target has its own counter.
	if res := r.signBundle(cpTarget, cpComps(), false); res.Version != (bundle.Version{Epoch: 1, Counter: 1}) {
		t.Fatalf("the control plane took the counter of a cell: %+v", res.Version)
	}
	// A refused request does not move the counter.
	if _, err := r.plane.SignBundle(t.Context(), cell1, nil, 0, false); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Fatalf("empty set: %v", err)
	}
	// The counter survives a restart and the epoch of a rotation comes first.
	r.restart(nil)
	if res := r.signBundle(cell1, cellComps(), false); res.Version.Compare(last) <= 0 || res.Version.Counter != 4 {
		t.Fatalf("after a restart %+v, last %+v", res.Version, last)
	}
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	if res := r.signBundle(cell1, cellComps(), false); res.Version != (bundle.Version{Epoch: 2, Counter: 5}) {
		t.Fatalf("after a rotation %+v", res.Version)
	}
	if got := r.bundleOf(cell1).Last.Version; got != (bundle.Version{Epoch: 2, Counter: 5}) {
		t.Fatalf("state holds %+v", got)
	}
}

func TestSignBundleStatement(t *testing.T) {
	for _, c := range []struct {
		target, role string
		comps        []bundle.Component
	}{
		{cell1, "cell", cellComps()},
		{cpTarget, "cp", cpComps()},
	} {
		t.Run(c.target, func(t *testing.T) {
			r, _ := boundRig(t)
			res := r.signBundle(c.target, c.comps, true)
			st, set, err := bundle.ParseAttestation(res.Envelope, []crypto.PublicKey{r.plane.PublicKey()})
			if err != nil {
				t.Fatalf("the attestation does not verify under the signing key: %v", err)
			}
			if st.Predicate.Target != c.target || st.Predicate.Env != "dev" || st.Predicate.Version != res.Version {
				t.Fatalf("predicate %+v", st.Predicate)
			}
			if len(st.Subject) != len(c.comps)+1 || st.Subject[0].Name != "bundles/"+c.target+"/root" {
				t.Fatalf("subjects %+v", st.Subject)
			}
			for i, comp := range c.comps {
				s := st.Subject[i+1]
				if s.Name != "bundles/"+c.target+"/"+comp.Name || "sha256:"+s.Digest.SHA256 != comp.Digest {
					t.Fatalf("subject %d is %+v", i+1, s)
				}
			}
			want := bundle.Set{Version: res.Version, Components: c.comps}
			art, err := bundle.ComposeRoot(c.role, want, bundle.DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if st.RootDigest() != art.Digest || res.RootDigest != art.Digest {
				t.Fatalf("root subject %s, result %s, ComposeRoot %s", st.RootDigest(), res.RootDigest, art.Digest)
			}
			if res.ContentSHA256 != bundle.ContentSHA256(want) {
				t.Fatalf("content %s", res.ContentSHA256)
			}
			if !reflect.DeepEqual(set.Components, c.comps) {
				t.Fatalf("set %+v", set.Components)
			}
			// The operation carries the envelope as its args, for the target and no other.
			v, err := r.plane.OpView(res.OpID)
			if err != nil || v.Kind != op.KindBundleApply || v.Cell != c.target || !v.Served {
				t.Fatalf("op view %+v, %v", v, err)
			}
			o, err := decodeOpUnverified(v.Envelope)
			if err != nil || o.Cell != c.target || !bytes.Equal(o.Args, res.Envelope) || o.Env != "dev" {
				t.Fatalf("operation %+v, %v", o, err)
			}
			if got := o.ExpiresAt.Sub(o.IssuedAt); got != DefaultBundleTTL {
				t.Fatalf("ttl %v", got)
			}
			if _, _, err := op.Verify(v.Envelope, []ed25519.PublicKey{r.plane.PublicKey()}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(res.SigstoreBundle), `"hint":"`+fingerprint(r.plane.PublicKey())+`"`) {
				t.Fatalf("cosign bundle %s", res.SigstoreBundle)
			}
			b := r.bundleOf(c.target)
			if b == nil || b.Last.OpID != res.OpID || b.Last.RootDigest != art.Digest || !b.Last.Served || b.Last.Result != nil || len(b.Last.Components) != len(c.comps) {
				t.Fatalf("bundle state %+v", b)
			}
		})
	}
}

// A set for one target reaches that target only.
func TestSignBundleDeliveredToItsTarget(t *testing.T) {
	r, _ := boundRig(t, cell1, cell2)
	res := r.signBundle(cell2, cellComps(), true)
	if r.isOpen(res.OpID) != true {
		t.Fatal("the set is not offered")
	}
	b := r.plane.OpenOps()
	if len(b.Ops) != 1 {
		t.Fatalf("%d ops", len(b.Ops))
	}
	o, _ := decodeOpUnverified(b.Ops[0])
	st, _, err := bundle.ParseAttestation(o.Args, []crypto.PublicKey{r.plane.PublicKey()})
	if err != nil || o.Cell != cell2 || st.Predicate.Target != cell2 {
		t.Fatalf("op for %s holds a set for %s (%v)", o.Cell, st.Predicate.Target, err)
	}
	if c := cellStatus(r.status(), cell1); c.OpenOps != 0 || c.Bundle != nil {
		t.Fatalf("cell 1 shows %+v", c)
	}
	if c := cellStatus(r.status(), cell2); c.OpenOps != 1 || c.Bundle == nil || c.Bundle.OpID != res.OpID {
		t.Fatalf("cell 2 shows %+v", c)
	}
}

func TestSignBundleOneOpen(t *testing.T) {
	r, _ := boundRig(t, cell1, cell2)
	// A set that is not served never blocks, and never counts as open.
	r.signBundle(cell1, cellComps(), false)
	r.signBundle(cell1, cellComps(), false)
	first := r.signBundle(cell1, cellComps(), true)
	if _, err := r.plane.SignBundle(t.Context(), cell1, cellComps(), 0, true); ReasonOf(err) != mgmtapi.ReasonBundleOpen {
		t.Fatalf("second served set: %v", err)
	}
	// A set that is not served still signs while one is open.
	r.signBundle(cell1, cellComps(), false)
	// Another target is not blocked.
	r.signBundle(cell2, cellComps(), true)
	r.signBundle(cpTarget, cpComps(), true)
	if _, err := r.plane.SignBundle(t.Context(), cpTarget, cpComps(), 0, true); ReasonOf(err) != mgmtapi.ReasonBundleOpen {
		t.Fatalf("second served set for the control plane: %v", err)
	}
	// A final result frees the target.
	want(t, r.one(r.resultItem(r.bundleResult(first.OpID, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	r.signBundle(cell1, cellComps(), true)
	// An operation past its expiry and grace time frees it too.
	r.clk.Advance(DefaultBundleTTL + opGrace + time.Second)
	r.signBundle(cell1, cellComps(), true)
}

func TestSignBundleRefusesGivenVersion(t *testing.T) {
	r, _ := boundRig(t)
	h := NewAdminHandler(r.plane, nil)
	body, _ := json.Marshal(cellComps())
	rec := adminDo(h, "POST", "/bundles?target="+cell1+"&version=7", string(body))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"reason":"payload_invalid"`) || !strings.Contains(rec.Body.String(), "version_given") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(r.plane.snap.Load().st.Ops) != 0 || r.bundleOf(cell1) != nil {
		t.Fatal("a refused request left state")
	}
}

func TestSignBundleUnbound(t *testing.T) {
	r := newRig(t)
	_, err := r.plane.SignBundle(t.Context(), cell1, cellComps(), 0, true)
	if ReasonOf(err) != mgmtapi.ReasonNotBound {
		t.Fatalf("unbound cell: %v", err)
	}
	if len(r.plane.snap.Load().st.Ops) != 0 || r.bundleOf(cell1) != nil {
		t.Fatal("a refused request left state")
	}
	// The control plane has no bind.
	r.signBundle(cpTarget, cpComps(), true)
}

func TestSignBundleTarget(t *testing.T) {
	r, _ := boundRig(t)
	for _, target := range []string{"", "dev-cell-9", "management", "cp", "dev-cell-1/x"} {
		if _, err := r.plane.SignBundle(t.Context(), target, cellComps(), 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
			t.Errorf("target %q: %v", target, err)
		} else if _, d := reasonDetail(err); d != "target" {
			t.Errorf("target %q: detail %q", target, d)
		}
	}
	// A catalog cell that no request holds is not a target.
	r2 := newBareRig(t)
	if _, err := r2.plane.SignBundle(t.Context(), cell1, cellComps(), 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Errorf("cell with no request: %v", err)
	}
	// The role of the target decides the components.
	spire := cpComps()
	if _, err := r.plane.SignBundle(t.Context(), cell1, spire, 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Errorf("a cell set with spire-server: %v", err)
	} else if _, d := reasonDetail(err); d != "set" {
		t.Errorf("detail %q", d)
	}
	if _, err := r.plane.SignBundle(t.Context(), cpTarget, cellComps(), 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Errorf("a control plane set with apps-sample: %v", err)
	}
	// A namespace that the class refuses.
	bad := cellComps()
	bad[1].Namespace = "kube-system"
	if _, err := r.plane.SignBundle(t.Context(), cell1, bad, 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Errorf("namespace: %v", err)
	}
	// A set that breaks a rule of the set.
	for name, comps := range map[string][]bundle.Component{
		"unsorted": {cellComps()[1], cellComps()[0]},
		"digest":   {{Name: "argocd", Namespace: "argocd", Digest: "sha256:zz"}},
		"none":     nil,
	} {
		if _, err := r.plane.SignBundle(t.Context(), cell1, comps, 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
			t.Errorf("%s: %v", name, err)
		} else if _, d := reasonDetail(err); d != "set" {
			t.Errorf("%s: detail %q", name, d)
		}
	}
	for _, ttl := range []time.Duration{-time.Second, time.Hour + time.Second} {
		if _, err := r.plane.SignBundle(t.Context(), cell1, cellComps(), ttl, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
			t.Errorf("ttl %v: %v", ttl, err)
		}
	}
	if len(r.plane.snap.Load().st.Ops) != 0 {
		t.Fatalf("%d ops, want none", len(r.plane.snap.Load().st.Ops))
	}
	r.signBundle(cpTarget, spire, true)
}

// bigPolicy is the default policy with 32 components of role cell, each with a name of 40 characters.
func bigPolicy(t *testing.T) (bundle.Policy, []bundle.Component) {
	t.Helper()
	p := bundle.DefaultPolicy()
	roles := map[string]bundle.Role{}
	for k, v := range p.Roles {
		roles[k] = v
	}
	cell := roles["cell"]
	cell.Components = map[string]string{}
	var comps []bundle.Component
	for i := 0; i < bundle.MaxComponents; i++ {
		name := fmt.Sprintf("component-with-a-long-name-%013d", i)
		if len(name) != bundle.MaxNameLen {
			t.Fatalf("name %q has %d characters", name, len(name))
		}
		cell.Components[name] = "platform"
		comps = append(comps, bundle.Component{Name: name, Wave: i%30 - 10, Namespace: "apps-demo", Digest: digestOf(byte('a' + i%6))})
	}
	roles["cell"] = cell
	p.Roles = roles
	return p, comps
}

func TestSignBundleOpSize(t *testing.T) {
	policy, comps := bigPolicy(t)
	r := newRig(t)
	r.mod = func(c *Config) { c.Policy = policy }
	r.restart(nil)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	// Grow the predicate until the statement is close to its limit.
	entry := `{"jqPathExpressions":[".spec.template.metadata.annotations.alpha",".spec.template.metadata.annotations.beta"],"jsonPointers":["/spec/replicas","/spec/template/spec/containers/0/image"],"kind":"Deployment","name":"example"}`
	ignore := json.RawMessage("[" + strings.TrimSuffix(strings.Repeat(entry+",", 8), ",") + "]")
	var res mgmtapi.BundleSignResult
	grown := 0
	for ; grown < len(comps); grown++ {
		comps[grown].IgnoreDifferences = ignore
		var err error
		res, err = r.plane.SignBundle(t.Context(), cell1, comps, 0, false)
		if ReasonOf(err) == mgmtapi.ReasonPayloadInvalid {
			if _, d := reasonDetail(err); d != "too_large" {
				t.Fatalf("detail %q", d)
			}
			comps[grown].IgnoreDifferences = nil
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if grown == 0 || grown == len(comps) {
		t.Fatalf("the statement limit was never reached (%d entries)", grown)
	}
	// The last set that signed holds the largest statement: 32 components under 24 KiB of args.
	res, err := r.plane.SignBundle(t.Context(), cell1, comps, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	st, _, err := bundle.ParseAttestation(res.Envelope, []crypto.PublicKey{r.plane.PublicKey()})
	if err != nil || len(st.Predicate.Components) != bundle.MaxComponents {
		t.Fatalf("%v %d", err, len(st.Predicate.Components))
	}
	t.Logf("32 components with %d ignoreDifferences lists: envelope of %d bytes", grown, len(res.Envelope))
	if len(res.Envelope) > op.MaxBundleArgsBytes || len(res.Envelope) < 18<<10 {
		t.Fatalf("envelope of %d bytes against %d", len(res.Envelope), op.MaxBundleArgsBytes)
	}
	v, err := r.plane.OpView(res.OpID)
	if err != nil {
		t.Fatal(err)
	}
	o, err := decodeOpUnverified(v.Envelope)
	if err != nil || len(o.Args) > op.MaxBundleArgsBytes {
		t.Fatalf("args of %d bytes: %v", len(o.Args), err)
	}
}

func TestCreateOpRefusesBundleKind(t *testing.T) {
	r, _ := boundRig(t)
	res := r.signBundle(cell1, cellComps(), false)
	if _, _, err := r.plane.CreateOp(t.Context(), cell1, op.KindBundleApply, res.Envelope, 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Fatalf("CreateOp: %v", err)
	} else if _, d := reasonDetail(err); d != "kind_unknown" {
		t.Fatalf("detail %q", d)
	}
	h := NewAdminHandler(r.plane, nil)
	body := `{"cell":"` + cell1 + `","kind":"bundle.apply","args":` + string(res.Envelope) + `}`
	if rec := adminDo(h, "POST", "/ops", body); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /ops: %d %s", rec.Code, rec.Body)
	}
	if n := len(r.plane.snap.Load().st.Ops); n != 1 {
		t.Fatalf("%d ops", n)
	}
}

func TestOpsPullSplitsPlaneBundle(t *testing.T) {
	r, _ := boundRig(t)
	plane := r.signBundle(cpTarget, cpComps(), true)
	b := r.plane.OpenOps()
	if len(b.Ops) != 0 {
		t.Fatalf("the plane set is in Ops: %d", len(b.Ops))
	}
	v, _ := r.plane.OpView(plane.OpID)
	if !bytes.Equal(b.PlaneBundle, v.Envelope) {
		t.Fatalf("PlaneBundle is not the envelope of the operation")
	}
	cellSet := r.signBundle(cell1, cellComps(), true)
	b = r.plane.OpenOps()
	if len(b.Ops) != 1 || !bytes.Equal(b.PlaneBundle, v.Envelope) {
		t.Fatalf("ops %d", len(b.Ops))
	}
	if o, _ := decodeOpUnverified(b.Ops[0]); o.ID != cellSet.OpID {
		t.Fatal("the cell set is not in Ops")
	}
	// A set that is not served is never offered.
	r2, _ := boundRig(t)
	r2.signBundle(cpTarget, cpComps(), false)
	if b := r2.plane.OpenOps(); len(b.PlaneBundle) != 0 || len(b.Ops) != 0 {
		t.Fatalf("an unserved set is offered: %+v", b)
	}
	// The wire form carries the key only when a set is open.
	raw, _ := json.Marshal(mgmtapi.OpsBundle{Ops: []json.RawMessage{}, Cells: []mgmtapi.CellInfo{}})
	if strings.Contains(string(raw), "planeBundle") {
		t.Fatal("planeBundle is not omitted")
	}
}

func TestPlaneResultClosesOp(t *testing.T) {
	for _, outcome := range []string{op.OutcomeApplied, op.OutcomeAlreadyApplied, op.OutcomeRefused, op.OutcomeRolledBack, op.OutcomeExpired} {
		t.Run(outcome, func(t *testing.T) {
			r, _ := boundRig(t)
			set := r.signBundle(cpTarget, cpComps(), true)
			res := r.bundleResult(set.OpID, outcome)
			res.Reason, res.Detail = "unhealthy", "timeout:argocd:OutOfSync/Healthy"
			r.reportPlane(&res)
			st := r.opState(set.OpID)
			if st.Final != outcome || st.Result == nil || st.Result.Detail != res.Detail || st.ResultAt.IsZero() {
				t.Fatalf("op state %+v", st)
			}
			if r.planeOpen() {
				t.Fatal("the plane set is still offered")
			}
			if got := r.bundleOf(cpTarget).Last.Result; got == nil || got.Outcome != outcome {
				t.Fatalf("recorded %+v", got)
			}
			// A new set is allowed once the last one is final.
			r.signBundle(cpTarget, cpComps(), true)
		})
	}
}

func TestPlaneResultOtherOpIgnored(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cpTarget, cpComps(), true)
	demo, demoEnv := r.newOp(cell1)
	cellSet := r.signBundle(cell1, cellComps(), true)
	good := r.bundleResult(set.OpID, op.OutcomeApplied)
	mod := func(f func(*op.Result)) *op.Result {
		c := good
		f(&c)
		return &c
	}
	for name, res := range map[string]*op.Result{
		"demo op":        ptr(resultFor(demo, demoEnv, op.OutcomeApplied)),
		"cell set":       ptr(r.bundleResult(cellSet.OpID, op.OutcomeApplied)),
		"unknown op":     mod(func(c *op.Result) { c.OpID = strings.Repeat("0", 32) }),
		"other envelope": mod(func(c *op.Result) { c.EnvelopeSHA256 = strings.Repeat("1", 64) }),
		"other cell":     mod(func(c *op.Result) { c.Cell = cell1 }),
		"no op ID":       mod(func(c *op.Result) { c.OpID, c.PeekedID = "", set.OpID }),
		"peeked id only": mod(func(c *op.Result) {
			c.OpID, c.PeekedID, c.Outcome, c.Reason = "", set.OpID, op.OutcomeRefused, op.ReasonSignatureInvalid
		}),
		"payload refusal": mod(func(c *op.Result) {
			c.OpID, c.PeekedID, c.Outcome, c.Reason = "", set.OpID, op.OutcomeRefused, op.ReasonPayloadInvalid
		}),
		"bad op ID": mod(func(c *op.Result) { c.OpID = "XYZ" }),
	} {
		r.reportPlane(res)
		if st := r.opState(set.OpID); st.Final != "" || st.Result != nil {
			t.Fatalf("%s closed the plane op: %+v", name, st)
		}
		if !r.planeOpen() {
			t.Fatalf("%s: the plane set is no longer offered", name)
		}
	}
	if st := r.opState(demo.ID); st.Final != "" {
		t.Fatal("a plane report closed a cell op")
	}
	if st := r.opState(cellSet.OpID); st.Final != "" {
		t.Fatal("a plane report closed a cell set")
	}
	// The matching result still closes it.
	r.reportPlane(&good)
	if r.opState(set.OpID).Final != op.OutcomeApplied {
		t.Fatal("the matching result did not close the op")
	}
}

func ptr[T any](v T) *T { return &v }

// A result that is not final, as envd reports a set whose time has not come, keeps the op open.
func TestPlaneResultNonFinalKeepsOpen(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cpTarget, cpComps(), true)
	res := r.bundleResult(set.OpID, op.OutcomeLeaseLost)
	res.Reason, res.Detail = op.ReasonLeaseLost, "clock"
	if op.IsFinal(res.Outcome) {
		t.Fatal("the test needs a non-final outcome")
	}
	before := r.plane.snap.Load().st.Seq
	r.reportPlane(&res)
	if st := r.opState(set.OpID); st.Final != "" || st.Result != nil {
		t.Fatalf("a non-final result closed the op: %+v", st)
	}
	if !r.planeOpen() || r.bundleOf(cpTarget).Last.Result != nil {
		t.Fatal("the op is no longer offered, or the set shows a result")
	}
	if r.plane.snap.Load().st.Seq != before {
		t.Fatal("a non-final result changed the state")
	}
	// The same op closes later on a final result.
	done := r.bundleResult(set.OpID, op.OutcomeApplied)
	r.reportPlane(&done)
	if r.opState(set.OpID).Final != op.OutcomeApplied {
		t.Fatal("the final result did not close the op")
	}
	// A repeat of the final result changes nothing.
	seq := r.plane.snap.Load().st.Seq
	r.reportPlane(&done)
	other := r.bundleResult(set.OpID, op.OutcomeRefused)
	r.reportPlane(&other)
	if r.plane.snap.Load().st.Seq != seq || r.opState(set.OpID).Final != op.OutcomeApplied {
		t.Fatal("a later result changed a closed op")
	}
}

func TestBundleFinalRecorded(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cell1, cellComps(), true)
	if c := cellStatus(r.status(), cell1); c.Bundle == nil || c.Bundle.Result != nil || c.Bundle.OpID != set.OpID {
		t.Fatalf("status before the result: %+v", c.Bundle)
	}
	res := r.bundleResult(set.OpID, op.OutcomeRolledBack)
	res.Reason, res.Detail = op.ReasonUnhealthy, "timeout:apps-sample:Synced/Progressing"
	want(t, r.one(r.resultItem(res, r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	got := r.bundleOf(cell1).Last.Result
	if got == nil || got.Outcome != op.OutcomeRolledBack || got.Detail != res.Detail {
		t.Fatalf("recorded %+v", got)
	}
	if c := cellStatus(r.status(), cell1); c.Bundle == nil || c.Bundle.Result == nil || c.Bundle.Result.Reason != op.ReasonUnhealthy {
		t.Fatalf("status %+v", c.Bundle)
	}
	// The record survives the trim of the operation history and a restart.
	r.restart(nil)
	if got := r.bundleOf(cell1).Last.Result; got == nil || got.Outcome != op.OutcomeRolledBack {
		t.Fatalf("after a restart %+v", got)
	}
	// A result for an older set does not replace the record of a newer one.
	newer := r.signBundle(cell1, cellComps(), false)
	if r.bundleOf(cell1).Last.OpID != newer.OpID || r.bundleOf(cell1).Last.Result != nil {
		t.Fatalf("newer set %+v", r.bundleOf(cell1).Last)
	}
}

func TestResultRolledBackOnlyForBundleApply(t *testing.T) {
	r, _ := boundRig(t)
	demo, demoEnv := r.newOp(cell1)
	rb := resultFor(demo, demoEnv, op.OutcomeRolledBack)
	rb.Reason = op.ReasonUnhealthy
	got := r.one(r.resultItem(rb, r.signers[cell1]))
	want(t, got, mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, "outcome")
	if st := r.opState(demo.ID); st.Final != "" || st.Result != nil {
		t.Fatalf("rolled_back closed a demo.append op: %+v", st)
	}
	want(t, r.one(r.resultItem(resultFor(demo, demoEnv, op.OutcomeApplied), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")

	set := r.signBundle(cell1, cellComps(), true)
	want(t, r.one(r.resultItem(r.bundleResult(set.OpID, op.OutcomeRolledBack), r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	if r.opState(set.OpID).Final != op.OutcomeRolledBack {
		t.Fatal("rolled_back did not close a bundle.apply op")
	}
}

// A refusal that carries no op ID never closes an op, on the cell path as on the plane path.
func TestRefusalWithoutOpIDNeverCloses(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cell1, cellComps(), true)
	res := r.bundleResult(set.OpID, op.OutcomeRefused)
	res.Reason, res.PeekedID, res.OpID = op.ReasonSignatureInvalid, set.OpID, ""
	got := r.one(r.resultItem(res, r.signers[cell1]))
	want(t, got, mgmtapi.OutcomeForgedSeen, "", "")
	if st := r.opState(set.OpID); st.Final != "" || st.Result != nil {
		t.Fatalf("the op closed: %+v", st)
	}
	if !r.isOpen(set.OpID) {
		t.Fatal("the op is no longer offered")
	}
}

func TestStateWithoutBundlesLoads(t *testing.T) {
	r, _ := boundRig(t)
	r.signBundle(cell1, cellComps(), false)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(r.stateBytes(), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["bundles"]; !ok {
		t.Fatal("the state has no bundles")
	}
	delete(m, "bundles")
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(r.dir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := r.store.Load()
	if err != nil || st == nil || len(st.Bundles) != 0 {
		t.Fatalf("load: %+v, %v", st, err)
	}
	r.restart(nil)
	if res := r.signBundle(cell1, cellComps(), false); res.Version.Counter != 1 {
		t.Fatalf("version %+v", res.Version)
	}
}

func TestIntentControlPlane(t *testing.T) {
	in := testIntent(cell1)
	if in.ControlPlaneName() != "dev-cp" {
		t.Fatalf("default %q", in.ControlPlaneName())
	}
	in.ControlPlane = "env-cp"
	if err := in.validate(); err != nil || in.ControlPlaneName() != "env-cp" {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{"Bad_Name", cell1, strings.Repeat("a", 60)} {
		in.ControlPlane = bad
		if err := in.validate(); err == nil {
			t.Errorf("control plane %q validates", bad)
		}
	}
	r := newRig(t)
	r.intent.ControlPlane = "env-cp"
	r.restart(nil)
	r.signBundle("env-cp", cpComps(), true)
	if _, err := r.plane.SignBundle(t.Context(), cpTarget, cpComps(), 0, true); ReasonOf(err) != mgmtapi.ReasonPayloadInvalid {
		t.Fatalf("the default name is not a target when the intent renames it: %v", err)
	}
}

func TestAdminBundleRoutes(t *testing.T) {
	r, _ := boundRig(t)
	h := NewAdminHandler(r.plane, nil)
	body, _ := json.Marshal(cellComps())
	rec := adminDo(h, "POST", "/bundles?target="+cell1+"&ttl=5m", string(body))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	m := decodeMap(t, rec)
	if m["opId"] == nil || m["envelope"] == nil || m["sigstoreBundle"] == nil || m["rootDigest"] == nil {
		t.Fatalf("answer %v", m)
	}
	opID := m["opId"].(string)
	v, _ := r.plane.OpView(opID)
	if o, _ := decodeOpUnverified(v.Envelope); o.ExpiresAt.Sub(o.IssuedAt) != 5*time.Minute || !v.Served {
		t.Fatalf("ttl or serve: %+v", o)
	}
	rec = adminDo(h, "GET", "/bundles?target="+cell1, "")
	if rec.Code != 200 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	g := decodeMap(t, rec)
	if g["opId"] != opID || g["served"] != true || g["components"] == nil {
		t.Fatalf("get %v", g)
	}
	// serve=0 signs without offering.
	rec = adminDo(h, "POST", "/bundles?target="+cpTarget+"&serve=0", string(mustJSON(cpComps())))
	if rec.Code != 200 || r.planeOpen() {
		t.Fatalf("serve=0: %d, open %v", rec.Code, r.planeOpen())
	}
	for name, c := range map[string]struct {
		method, target, body string
		code                 int
	}{
		"no target":    {"POST", "/bundles", string(body), 422},
		"bad serve":    {"POST", "/bundles?target=" + cell1 + "&serve=2", string(body), 400},
		"bad ttl":      {"POST", "/bundles?target=" + cell1 + "&ttl=soon", string(body), 400},
		"bad body":     {"POST", "/bundles?target=" + cell1, `{"x":1}`, 400},
		"open":         {"POST", "/bundles?target=" + cell1, string(body), 409},
		"unknown get":  {"GET", "/bundles?target=dev-cell-9", "", 404},
		"no set":       {"GET", "/bundles?target=" + cell2, "", 404},
		"get no param": {"GET", "/bundles", "", 404},
	} {
		if rec := adminDo(h, c.method, c.target, c.body); rec.Code != c.code {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestRotateKeyResignsBundleAttestation(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cell1, cellComps(), true)
	old := r.plane.PublicKey()
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	fresh := r.plane.PublicKey()
	v, _ := r.plane.OpView(set.OpID)
	o, err := decodeOpUnverified(v.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bundle.ParseAttestation(o.Args, []crypto.PublicKey{fresh}); err != nil {
		t.Fatalf("the attestation of an open op does not verify under the new key: %v", err)
	}
	if _, _, err := bundle.ParseAttestation(o.Args, []crypto.PublicKey{old}); err == nil {
		t.Fatal("the attestation still verifies under the old key")
	}
	st, _, _ := bundle.ParseAttestation(o.Args, []crypto.PublicKey{fresh})
	if st.Predicate.Version != set.Version || st.RootDigest() != set.RootDigest {
		t.Fatalf("the re-signed statement changed: %+v", st.Predicate)
	}
}

func TestStatusShowsPlaneBundle(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cpTarget, cpComps(), true)
	s := r.status()
	if s.PlaneBundle == nil || s.PlaneBundle.OpID != set.OpID || s.PlaneBundle.Result != nil {
		t.Fatalf("status %+v", s.PlaneBundle)
	}
	bs := &op.BundleStatus{Version: set.Version, RootDigest: set.RootDigest, State: "healthy", AllowSHA256: strings.Repeat("e", 64)}
	r.plane.Report(mgmtapi.StatusReport{PlaneBundleStatus: bs})
	if got := r.status().PlaneBundleStatus; got == nil || *got != *bs {
		t.Fatalf("plane bundle status %+v", got)
	}
	// A status report that omits it clears it.
	r.plane.Report(mgmtapi.StatusReport{})
	if r.status().PlaneBundleStatus != nil {
		t.Fatal("a stale bundle status stays")
	}
}

func TestStatusShowsCellBundleStatus(t *testing.T) {
	r, _ := boundRig(t)
	bs := &op.BundleStatus{Version: bundle.Version{Epoch: 1, Counter: 2}, RootDigest: digestOf('f'), State: "applying", AllowSHA256: strings.Repeat("e", 64)}
	st := op.Status{Cell: cell1, Pod: "celld-0", PodUID: "pod-uid", Seq: 1, At: r.clk.Now(), Bundle: bs}
	it := r.item(cell1, "status", st, r.signers[cell1], nil)
	want(t, r.one(it), mgmtapi.OutcomeAccepted, "", "")
	if got := cellStatus(r.status(), cell1).BundleStatus; got == nil || *got != *bs {
		t.Fatalf("bundle status %+v", got)
	}
}
