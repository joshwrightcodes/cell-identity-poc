package mgmt

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// DefaultBundleTTL is the lifetime of a bundle.apply operation when the caller gives none.
const DefaultBundleTTL = 30 * time.Minute

// The roles of the bundle policy: a cell and the environment control plane.
const (
	roleCell = "cell"
	roleCP   = "cp"
)

// ErrBundleUnknown means the target is unknown, or has no signed set.
var ErrBundleUnknown = errors.New("bundle_unknown")

// ErrBundleRetired means the attestation of the set is signed with a key that is no longer the
// signing key, so no cosign bundle exists for the current key.
var ErrBundleRetired = errors.New("bundle_key_retired")

// BundleState is what the plane keeps for one target: the counter of the last signed set, the last
// set that was served, and the last set that was signed and not served. Last holds the final result
// of its operation once the plane has it. A set that is not served never replaces Last, so the
// outcome of the last served set stays visible.
type BundleState struct {
	Counter  uint64                `json:"counter"`
	Last     mgmtapi.TargetBundle  `json:"last"`
	Unserved *mgmtapi.TargetBundle `json:"unserved,omitempty"`
}

// shown returns the set that status and bundle get show: the last served set, or the last set that
// was not served when the target has no served set.
func (b *BundleState) shown() (mgmtapi.TargetBundle, bool) {
	switch {
	case b == nil:
		return mgmtapi.TargetBundle{}, false
	case b.Last.OpID != "":
		return b.Last, true
	case b.Unserved != nil:
		return *b.Unserved, true
	}
	return mgmtapi.TargetBundle{}, false
}

func (p *Plane) policy() bundle.Policy {
	if len(p.cfg.bundlePolicy.Roles) > 0 {
		return p.cfg.bundlePolicy
	}
	return bundle.DefaultPolicy()
}

// bundleRole returns the policy role of a target in st: cp for the control plane and cell for an
// intent cell. Any other name is not a target.
func (p *Plane) bundleRole(st *State, target string) (string, error) {
	if target == p.cfg.Intent.ControlPlaneName() {
		return roleCP, nil
	}
	if _, ok := p.cellIn(st, target); ok {
		return roleCell, nil
	}
	return "", refuse(mgmtapi.ReasonPayloadInvalid, "target")
}

// opKind returns the kind of the operation, or an empty string when its envelope does not decode.
func opKind(o *OpState) string {
	cur, err := decodeOpUnverified(o.Envelope)
	if err != nil {
		return ""
	}
	return cur.Kind
}

// bundleOpen reports whether a served bundle.apply operation of the target has no final result and
// is not past its grace time. A set that is not served never counts.
func (t *txn) bundleOpen(target string) bool {
	return slices.ContainsFunc(t.st.OpOrder, func(id string) bool {
		o := t.st.Ops[id]
		return o.Cell == target && o.Served && o.open(t.now) && opKind(o) == op.KindBundleApply
	})
}

// SignBundle signs the bundle set comps for target, wraps the attestation in one bundle.apply
// operation and builds the cosign bundle. The plane sets the version: the key epoch of the state
// and a counter that rises by one for each set of the target. It composes the root with the role of
// the target. A zero ttl takes DefaultBundleTTL. With serve false the operation is recorded and never
// offered, and it never blocks a later set.
func (p *Plane) SignBundle(ctx context.Context, target string, comps []bundle.Component, ttl time.Duration, serve bool) (mgmtapi.BundleSignResult, error) {
	if err := ctx.Err(); err != nil {
		return mgmtapi.BundleSignResult{}, err
	}
	if ttl == 0 {
		ttl = DefaultBundleTTL
	}
	if ttl < op.MinTTL || ttl > op.MaxTTL {
		return mgmtapi.BundleSignResult{}, refuse(mgmtapi.ReasonPayloadInvalid, "ttl")
	}
	if _, err := p.bundleRole(p.snap.Load().st, target); err != nil {
		return mgmtapi.BundleSignResult{}, err
	}
	raw, err := json.Marshal(comps)
	if err != nil {
		return mgmtapi.BundleSignResult{}, refuse(mgmtapi.ReasonPayloadInvalid, "set")
	}
	checked, err := bundle.ParseComponents(raw)
	if err != nil {
		return mgmtapi.BundleSignResult{}, refuse(mgmtapi.ReasonPayloadInvalid, "set")
	}
	var res mgmtapi.BundleSignResult
	err = p.commit(func(t *txn) error {
		role, err := p.bundleRole(t.st, target)
		if err != nil {
			return err
		}
		if role == roleCell && t.st.Cells[target] == nil {
			return refuse(mgmtapi.ReasonNotBound, "")
		}
		if serve && t.bundleOpen(target) {
			return refuse(mgmtapi.ReasonBundleOpen, "")
		}
		if t.st.Bundles == nil {
			t.st.Bundles = map[string]*BundleState{}
		}
		bs := t.st.Bundles[target]
		if bs == nil {
			bs = &BundleState{}
			t.st.Bundles[target] = bs
		}
		bs.Counter++
		set := bundle.Set{Version: bundle.Version{Epoch: t.st.Last.Epoch, Counter: bs.Counter}, Components: checked}
		art, err := bundle.ComposeRoot(role, set, p.policy())
		if err != nil {
			return refuse(mgmtapi.ReasonPayloadInvalid, "set")
		}
		stmt := bundle.NewStatement(p.cfg.Intent.Env, target, set, art.Digest)
		if body, err := json.Marshal(stmt); err != nil || len(body) > bundle.MaxStatementBytes {
			return refuse(mgmtapi.ReasonPayloadInvalid, "too_large")
		}
		envelope, err := bundle.SignAttestation(stmt, t.key)
		if err != nil {
			return refuse(mgmtapi.ReasonPayloadInvalid, "set")
		}
		if len(envelope) > op.MaxBundleArgsBytes {
			return refuse(mgmtapi.ReasonPayloadInvalid, "too_large")
		}
		sig, err := sigstoreBundle(envelope, fingerprint(t.key.Public().(ed25519.PublicKey)))
		if err != nil {
			return err
		}
		o, _, err := t.addOp(target, op.KindBundleApply, envelope, ttl, serve)
		if err != nil {
			return err
		}
		content := bundle.ContentSHA256(set)
		tb := mgmtapi.TargetBundle{
			OpID: o.ID, Version: set.Version, ContentSHA256: content, RootDigest: art.Digest,
			Components: slices.Clone(checked), IssuedAt: o.IssuedAt, ExpiresAt: o.ExpiresAt, Served: serve,
		}
		if serve {
			bs.Last = tb
		} else {
			bs.Unserved = &tb
		}
		res = mgmtapi.BundleSignResult{
			OpID: o.ID, Version: set.Version, ContentSHA256: content, RootDigest: art.Digest,
			Envelope: slices.Clone(envelope), SigstoreBundle: sig,
		}
		t.dirty = true
		return nil
	})
	if err != nil {
		return mgmtapi.BundleSignResult{}, err
	}
	return res, nil
}

// BundleView returns the last signed set of the target. The error is ErrBundleUnknown for a name
// that is no target and for a target with no set.
func (p *Plane) BundleView(target string) (mgmtapi.TargetBundle, error) {
	st := p.snap.Load().st
	if _, err := p.bundleRole(st, target); err != nil {
		return mgmtapi.TargetBundle{}, ErrBundleUnknown
	}
	tb, ok := st.Bundles[target].shown()
	if !ok {
		return mgmtapi.TargetBundle{}, ErrBundleUnknown
	}
	return tb, nil
}

// BundleCosign returns the attestation and the cosign bundle that the plane holds now for the set
// that BundleView shows. After a rotation of the signing key, a set that is served and open holds
// an attestation under the new key, and the cosign bundle names that key. A set whose attestation
// the current key does not verify gives ErrBundleRetired.
func (p *Plane) BundleCosign(target string) (mgmtapi.BundleSignResult, error) {
	snap := p.snap.Load()
	if _, err := p.bundleRole(snap.st, target); err != nil {
		return mgmtapi.BundleSignResult{}, ErrBundleUnknown
	}
	tb, ok := snap.st.Bundles[target].shown()
	if !ok || snap.st.Ops[tb.OpID] == nil {
		return mgmtapi.BundleSignResult{}, ErrBundleUnknown
	}
	cur, err := decodeOpUnverified(snap.st.Ops[tb.OpID].Envelope)
	if err != nil {
		return mgmtapi.BundleSignResult{}, ErrBundleUnknown
	}
	if _, _, err := bundle.ParseAttestation(cur.Args, []crypto.PublicKey{snap.pub}); err != nil {
		return mgmtapi.BundleSignResult{}, ErrBundleRetired
	}
	sig, err := sigstoreBundle(cur.Args, fingerprint(snap.pub))
	if err != nil {
		return mgmtapi.BundleSignResult{}, err
	}
	return mgmtapi.BundleSignResult{
		OpID: tb.OpID, Version: tb.Version, ContentSHA256: tb.ContentSHA256, RootDigest: tb.RootDigest,
		Envelope: slices.Clone(cur.Args), SigstoreBundle: sig,
	}, nil
}

// finishOp records a final result on an operation, and on the last set of its target when that set
// belongs to the operation.
func (t *txn) finishOp(id string, x *OpState, res op.Result) {
	x.Result, x.ResultAt, x.Final = &res, t.now, res.Outcome
	if b := t.st.Bundles[x.Cell]; b != nil {
		switch {
		case b.Last.OpID == id:
			b.Last.Result = &res
		case b.Unserved != nil && b.Unserved.OpID == id:
			u := *b.Unserved
			u.Result = &res
			b.Unserved = &u
		}
	}
	t.dirty = true
}

// planeResult closes the bundle.apply operation for the control plane that envd reports. Only a
// final result that carries the ID of an open operation of the control plane, the control plane as
// its cell, a well formed reason and detail, and the digest of one of the envelopes of the
// operation closes it. Any other result changes nothing and leaves one warning, except a repeat
// for an operation that is already closed.
func (p *Plane) planeResult(res *op.Result) {
	if res == nil {
		return
	}
	cp := p.cfg.Intent.ControlPlaneName()
	clean := func(id string) string {
		if opIDRE.MatchString(id) {
			return id
		}
		return ""
	}
	drop := func(class string) {
		p.logLimited(context.Background(), slog.LevelWarn, "plane_result_ignored/"+class+"/"+clean(res.OpID)+clean(res.PeekedID), "plane_result_ignored",
			"op_id", clean(res.OpID), "peeked_id", clean(res.PeekedID), "reason", class)
	}
	if res.OpID == "" || !opIDRE.MatchString(res.OpID) {
		drop("no_id")
		return
	}
	x := p.snap.Load().st.Ops[res.OpID]
	switch {
	case x != nil && x.Final != "":
		return
	case !op.IsFinal(res.Outcome):
		drop("not_final")
		return
	case res.Reason != "" && !op.ValidDetail(res.Reason), res.Detail != "" && !op.ValidDetail(res.Detail):
		drop("detail")
		return
	case x == nil:
		drop("unknown_op")
		return
	case x.Cell != cp || res.Cell != cp || opKind(x) != op.KindBundleApply:
		drop("other_target")
		return
	case !slices.Contains(x.Envelopes, res.EnvelopeSHA256):
		drop("envelope")
		return
	}
	err := p.commit(func(t *txn) error {
		if x := t.st.Ops[res.OpID]; x != nil && x.Cell == cp && x.Final == "" {
			t.finishOp(res.OpID, x, *res)
		}
		return nil
	})
	if err != nil {
		p.logLimited(context.Background(), slog.LevelError, "plane_result_failed", "plane_result_failed", "error", err.Error())
	}
}

// resignAttestation signs the payload of the attestation envelope again with key. The payload bytes
// stay exactly as they are, so the new envelope approves the same statement. The result must
// verify under key as an attestation.
func resignAttestation(envelope json.RawMessage, key ed25519.PrivateKey) (json.RawMessage, error) {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, err
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	out, err := record.SignEnvelope(bundle.PayloadType, body, key)
	if err != nil {
		return nil, err
	}
	if _, _, err := bundle.ParseAttestation(out, []crypto.PublicKey{key.Public()}); err != nil {
		return nil, err
	}
	return out, nil
}
