package mgmt

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
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
		{Name: "apps-sample", Wave: 10, Namespace: "apps-sample", Digest: digestOf('b')},
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
	if tb, _ := r.bundleOf(cell1).shown(); tb.Version != (bundle.Version{Epoch: 2, Counter: 5}) {
		t.Fatalf("state holds %+v", tb.Version)
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
	r.mod = func(c *Config) { c.bundlePolicy = policy }
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
		"demo op":  ptr(resultFor(demo, demoEnv, op.OutcomeApplied)),
		"cell set": ptr(r.bundleResult(cellSet.OpID, op.OutcomeApplied)),
		"cell set claimed as plane": mod(func(c *op.Result) {
			*c = r.bundleResult(cellSet.OpID, op.OutcomeApplied)
			c.Cell = cpTarget
		}),
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
	if st := r.opState(cellSet.OpID); st.Final != "" || st.Result != nil {
		t.Fatal("a plane report closed a cell set")
	}
	if r.bundleOf(cell1).Last.Result != nil {
		t.Fatal("a plane report recorded a result on a cell set")
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
}

// A set that is signed and not served never hides the outcome of the last served set.
func TestNoServeSetKeepsLastServed(t *testing.T) {
	r, _ := boundRig(t)
	// A target with no served set shows the set that was signed and not served.
	only := r.signBundle(cell1, cellComps(), false)
	if got, err := r.plane.BundleView(cell1); err != nil || got.OpID != only.OpID || got.Served {
		t.Fatalf("view %+v, %v", got, err)
	}
	served := r.signBundle(cell1, cellComps(), true)
	res := r.bundleResult(served.OpID, op.OutcomeRolledBack)
	res.Reason, res.Detail = op.ReasonUnhealthy, "rollback_unhealthy"
	want(t, r.one(r.resultItem(res, r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
	injected := r.signBundle(cell1, cellComps(), false)
	got, err := r.plane.BundleView(cell1)
	if err != nil || got.OpID != served.OpID || got.Result == nil || got.Result.Outcome != op.OutcomeRolledBack {
		t.Fatalf("bundle get shows %+v, %v", got, err)
	}
	if c := cellStatus(r.status(), cell1); c.Bundle == nil || c.Bundle.OpID != served.OpID || c.Bundle.Result == nil {
		t.Fatalf("status shows %+v", c.Bundle)
	}
	// The next version still counts the injected set.
	if next := r.signBundle(cell1, cellComps(), false); next.Version.Counter != injected.Version.Counter+1 {
		t.Fatalf("version %+v after %+v", next.Version, injected.Version)
	}
	r.restart(nil)
	if got, _ := r.plane.BundleView(cell1); got.OpID != served.OpID {
		t.Fatalf("after a restart %+v", got)
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

// payloadOf returns the payload bytes of a DSSE envelope.
func payloadOf(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func ignoringComps() []bundle.Component {
	c := cellComps()
	c[0].IgnoreDifferences = json.RawMessage(`[{"group":"apps","kind":"Deployment","jsonPointers":["/spec/replicas"],"jqPathExpressions":[".spec.template<x>&y"]}]`)
	return c
}

func TestRotateKeyResignsBundleAttestation(t *testing.T) {
	for _, c := range []struct {
		name, target string
		comps        []bundle.Component
	}{
		{"cell with ignoreDifferences", cell1, ignoringComps()},
		{"plane op", cpTarget, cpComps()},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, _ := boundRig(t)
			set := r.signBundle(c.target, c.comps, true)
			before := r.bundleResult(set.OpID, op.OutcomeApplied)
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
			if !bytes.Equal(payloadOf(t, o.Args), payloadOf(t, set.Envelope)) {
				t.Fatalf("the signed payload changed:\n%s\n%s", payloadOf(t, o.Args), payloadOf(t, set.Envelope))
			}
			if c.target == cpTarget {
				if got := r.plane.OpenOps().PlaneBundle; !bytes.Equal(got, v.Envelope) {
					t.Fatal("the plane op that is served is not the re-signed one")
				}
			}
			// A result for the envelope that was current before the rotation still closes the op.
			if c.target == cpTarget {
				r.reportPlane(&before)
			} else {
				want(t, r.one(r.resultItem(before, r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")
			}
			if r.opState(set.OpID).Final != op.OutcomeApplied {
				t.Fatal("a result for the old envelope did not close the op")
			}
		})
	}
}

// A set that is not served is not signed again: a new-key attestation at an old version would be
// valid input for an applier after its mark reset.
func TestRotateKeyLeavesUnservedBundleOps(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cell1, cellComps(), false)
	old := r.plane.PublicKey()
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	v, _ := r.plane.OpView(set.OpID)
	o, _ := decodeOpUnverified(v.Envelope)
	if _, _, err := bundle.ParseAttestation(o.Args, []crypto.PublicKey{r.plane.PublicKey()}); err == nil {
		t.Fatal("an unserved set verifies under the new key")
	}
	if _, _, err := bundle.ParseAttestation(o.Args, []crypto.PublicKey{old}); err != nil {
		t.Fatalf("the unserved set changed: %v", err)
	}
	if len(v.Envelopes) != 1 {
		t.Fatalf("envelopes %v", v.Envelopes)
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

func TestAdminBundleRequiresWave(t *testing.T) {
	r, _ := boundRig(t)
	h := NewAdminHandler(r.plane, nil)
	noWave := `[{"name":"argocd","namespace":"argocd","digest":"` + digestOf('a') + `"}]`
	rec := adminDo(h, "POST", "/bundles?target="+cell1+"&serve=0", noWave)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"reason":"payload_invalid"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(r.plane.snap.Load().st.Ops) != 0 || r.bundleOf(cell1) != nil {
		t.Fatal("a refused request left state")
	}
	// The same component with a wave signs.
	withWave := strings.Replace(noWave, `"name"`, `"wave":0,"name"`, 1)
	if rec := adminDo(h, "POST", "/bundles?target="+cell1+"&serve=0", withWave); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestAdminBundleGetRefusesUnknownQuery(t *testing.T) {
	r, _ := boundRig(t)
	r.signBundle(cell1, cellComps(), true)
	h := NewAdminHandler(r.plane, nil)
	for _, q := range []string{"?target=" + cell1 + "&x=1", "?target=" + cell1 + "&target=" + cell1, "?target=" + cell1 + "&serve=0"} {
		for _, path := range []string{"/bundles", "/bundles/cosign"} {
			if rec := adminDo(h, "GET", path+q, ""); rec.Code != 400 || !strings.Contains(rec.Body.String(), `"reason":"query_invalid"`) {
				t.Errorf("%s%s: %d %s", path, q, rec.Code, rec.Body)
			}
		}
	}
}

func TestBundleCosignFollowsRotation(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cell1, cellComps(), true)
	h := NewAdminHandler(r.plane, nil)
	get := func() map[string]any {
		rec := adminDo(h, "GET", "/bundles/cosign?target="+cell1, "")
		if rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		return decodeMap(t, rec)
	}
	hint := func(m map[string]any) string {
		raw, _ := json.Marshal(m["sigstoreBundle"])
		var b struct {
			VM struct {
				PK struct {
					Hint string `json:"hint"`
				} `json:"publicKey"`
			} `json:"verificationMaterial"`
		}
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		return b.VM.PK.Hint
	}
	first := get()
	if first["opId"] != set.OpID || hint(first) != fingerprint(r.plane.PublicKey()) {
		t.Fatalf("before a rotation %v", first)
	}
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	after := get()
	if hint(after) != fingerprint(r.plane.PublicKey()) || hint(after) == hint(first) {
		t.Fatalf("after a rotation the hint is %s", hint(after))
	}
	sb, err := r.plane.BundleCosign(cell1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bundle.ParseAttestation(sb.Envelope, []crypto.PublicKey{r.plane.PublicKey()}); err != nil {
		t.Fatalf("the envelope does not verify under the current key: %v", err)
	}
	if !bytes.Contains(sb.SigstoreBundle, []byte(`"dsseEnvelope":`+string(sb.Envelope)+`}`)) {
		t.Fatal("the cosign bundle does not wrap the current envelope unchanged")
	}
	// A set that is not served stays under its own key, so no bundle exists for the current one.
	r2, _ := boundRig(t)
	r2.signBundle(cell1, cellComps(), false)
	if _, err := r2.plane.BundleCosign(cell1); err != nil {
		t.Fatalf("before a rotation: %v", err)
	}
	if _, err := r2.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	h2 := NewAdminHandler(r2.plane, nil)
	if rec := adminDo(h2, "GET", "/bundles/cosign?target="+cell1, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "bundle_key_retired") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := adminDo(h2, "GET", "/bundles/cosign?target="+cell2, ""); rec.Code != 404 {
		t.Fatalf("%d", rec.Code)
	}
}

// A result whose reason or detail breaks the shape never reaches the state.
func TestResultReasonAndDetailAreValidated(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cell1, cellComps(), true)
	for field, bad := range map[string]func(*op.Result){
		"reason": func(c *op.Result) { c.Reason = "bad reason!" },
		"detail": func(c *op.Result) { c.Detail = strings.Repeat("a", 97) },
	} {
		res := r.bundleResult(set.OpID, op.OutcomeRefused)
		bad(&res)
		want(t, r.one(r.resultItem(res, r.signers[cell1])), mgmtapi.OutcomeRefused, mgmtapi.ReasonPayloadInvalid, field)
		if st := r.opState(set.OpID); st.Final != "" || st.Result != nil {
			t.Fatalf("a result with a bad %s closed the op", field)
		}
	}
	good := r.bundleResult(set.OpID, op.OutcomeRolledBack)
	good.Reason, good.Detail = op.ReasonUnhealthy, "timeout:apps-sample:Synced/Progressing"
	want(t, r.one(r.resultItem(good, r.signers[cell1])), mgmtapi.OutcomeAccepted, "", "")

	// The plane path ignores such a result.
	cp := r.signBundle(cpTarget, cpComps(), true)
	for _, bad := range []func(*op.Result){
		func(c *op.Result) { c.Reason = "bad reason!" },
		func(c *op.Result) { c.Detail = "has space" },
	} {
		res := r.bundleResult(cp.OpID, op.OutcomeRefused)
		bad(&res)
		r.reportPlane(&res)
		if st := r.opState(cp.OpID); st.Final != "" || st.Result != nil {
			t.Fatal("a plane result with a bad reason or detail closed the op")
		}
	}
}

// A plane result that is dropped leaves one warning with the op ID and the reason class, and no
// forged-seen record.
func TestPlaneResultDroppedIsLogged(t *testing.T) {
	r, _ := boundRig(t)
	set := r.signBundle(cpTarget, cpComps(), true)
	bad := r.bundleResult(set.OpID, op.OutcomeApplied)
	bad.EnvelopeSHA256 = strings.Repeat("1", 64)
	for i := 0; i < 3; i++ {
		r.reportPlane(&bad)
	}
	if n := r.logs.count("plane_result_ignored"); n != 1 {
		t.Fatalf("%d lines for a repeated result, want 1", n)
	}
	line := ""
	for _, l := range strings.Split(r.logs.buf.String(), "\n") {
		if strings.Contains(l, `"msg":"plane_result_ignored"`) {
			line = l
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	if m["level"] != "WARN" || m["op_id"] != set.OpID || m["reason"] != "envelope" {
		t.Fatalf("log line %s", line)
	}
	if got := r.plane.ForgedSeen(cpTarget); len(got) != 0 || r.plane.Status().Cells[0].ForgedSeen != 0 {
		t.Fatalf("a forged_seen record %v", got)
	}
	// A result with no ID and a result that is not final each give their own line.
	noID := r.bundleResult(set.OpID, op.OutcomeRefused)
	noID.OpID, noID.PeekedID = "", set.OpID
	r.reportPlane(&noID)
	late := r.bundleResult(set.OpID, op.OutcomeLeaseLost)
	r.reportPlane(&late)
	if n := r.logs.count("plane_result_ignored"); n != 3 {
		t.Fatalf("%d lines, want 3", n)
	}
	// A repeat after the op closed is not a drop.
	done := r.bundleResult(set.OpID, op.OutcomeApplied)
	r.reportPlane(&done)
	r.reportPlane(&done)
	if n := r.logs.count("plane_result_ignored"); n != 3 {
		t.Fatalf("%d lines after a close, want 3", n)
	}
}
