package bundleapply

import (
	"cmp"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	opaversion "github.com/open-policy-agent/opa/v1/version"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// The values of State.State and State.Source.
const (
	stateApplying    = "applying"
	stateRollingBack = "rolling_back"
	stateHealthy     = "healthy"
	stateRolledBack  = "rolled_back"
	sourceSigned     = "signed"
	repoRoot         = "bundles/root"
	tagCurrent       = "current"
	harnessLabel     = "cell.poc.internal/harness"
	maxGood          = 2
	lockSlack        = 2 * time.Minute
	maxStateAttempts = 8
	detailRollback   = "rollback_unhealthy"
	// maxSetLayerBytes limits the layer bytes that one apply reads and holds until the push: eight
	// layers of the largest size, a quarter of the most that 32 components could hold.
	maxSetLayerBytes = 8 * bundle.MaxLayerBytes
)

// DetailTarget is the detail of a payload_invalid refusal for a set whose predicate names another
// target than the applier or the operation. A cell reports it as wrong_target.
const DetailTarget = "target"

// ErrLockHeld means that another holder, or another Apply of this process, has the apply lock. The
// caller retries later.
var ErrLockHeld = errors.New("bundle apply lock is held")

// ErrInFlight means that the state names the operation in applying or rolling_back: the engine has
// started it and holds no final result for it yet.
var ErrInFlight = errors.New("bundle operation is in flight")

var (
	errLockLost = errors.New("bundle apply lock was lost")
	errNoWrite  = errors.New("no state write needed")
)

// Config holds what an Applier needs.
type Config struct {
	// Role is cell, cp or open. Env and Target name the environment and the cluster that this
	// applier serves, and Holder names this process in the apply lock.
	Role, Env, Target, Holder string
	// Mirror reads bundles from the shared registry. Store writes them to the in-cluster store with
	// a write-only client.
	Mirror, Store *ocistore.Store
	Dynamic       dynamic.Interface
	Client        kubernetes.Interface
	Policy        bundle.Policy
	// Keys returns the keys that sign attestations, read again for each apply. An error or an empty
	// list makes Apply return an error, so the caller tries the operation again.
	Keys                                                func() ([]crypto.PublicKey, error)
	State                                               Store
	HealthTimeout, DegradedGrace, RollbackTimeout, Poll time.Duration
	Now                                                 func() time.Time
	Log                                                 *slog.Logger
	Tracer                                              trace.Tracer
	Meter                                               metric.Meter
}

// Outcome is the final result of one Apply.
type Outcome struct{ Outcome, Reason, Detail string }

// Applier applies signed bundle sets.
type Applier struct {
	cfg   Config
	tel   telemetry
	log   *slog.Logger
	sleep func(ctx context.Context, d time.Duration) error
	// running is held while one Apply of this process works under the lock. The state lock names
	// the holder only, so it cannot tell two runs of one process apart.
	running sync.Mutex
	// maxSetBytes limits the layer bytes that one apply reads from the mirror and holds.
	maxSetBytes int
}

// New returns an Applier for cfg. Zero timers take the plan values: a poll of 5 s, a health
// deadline of 5 min, a degraded grace of 60 s and a rollback wait of 5 min. Nil telemetry and a nil
// logger discard their output.
func New(cfg Config) *Applier {
	if cfg.Poll <= 0 {
		cfg.Poll = 5 * time.Second
	}
	if cfg.HealthTimeout <= 0 {
		cfg.HealthTimeout = 5 * time.Minute
	}
	if cfg.DegradedGrace <= 0 {
		cfg.DegradedGrace = time.Minute
	}
	if cfg.RollbackTimeout <= 0 {
		cfg.RollbackTimeout = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	tel, err := newTelemetry(cfg.Tracer, cfg.Meter)
	if err != nil {
		log.Error("bundle telemetry", "error", err)
		tel, _ = newTelemetry(nil, nil)
	}
	return &Applier{cfg: cfg, tel: tel, log: log, sleep: realSleep, maxSetBytes: maxSetLayerBytes}
}

func realSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (a *Applier) lockTTL() time.Duration {
	return a.cfg.HealthTimeout + a.cfg.RollbackTimeout + lockSlack
}

// Apply verifies the attestation and applies the set that it signs. A final result, including a
// refusal and a rollback, comes back as the Outcome with a nil error and is stored in the state. An
// error means that the apply did not finish, and the caller can try again with the same operation ID:
// the lock is held by another process (ErrLockHeld), the keys could not be read, the mirror or the
// store failed, or ctx ended.
func (a *Applier) Apply(ctx context.Context, opID, opTarget string, attestation []byte) (Outcome, error) {
	start := a.cfg.Now()
	ctx, span := a.tel.tracer.Start(ctx, spanApply, trace.WithAttributes(
		attribute.String("op.id", opID), attribute.String("target", a.cfg.Target), attribute.String("role", a.cfg.Role)))
	defer span.End()
	out, err := a.apply(ctx, opID, opTarget, attestation)
	outcome, reason := out.Outcome, out.Reason
	if err != nil {
		outcome, reason = "error", "failed"
		switch {
		case errors.Is(err, ErrLockHeld):
			reason = "lock_held"
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			reason = "canceled"
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.SetAttributes(attribute.String("outcome", outcome), attribute.String("reason", reason))
	a.tel.record(ctx, a.cfg.Role, outcome, reason, a.cfg.Now().Sub(start))
	return out, err
}

// Status reports the state of the applier.
func (a *Applier) Status(ctx context.Context) (*op.BundleStatus, error) {
	st, _, err := a.cfg.State.Read(ctx)
	if err != nil {
		return nil, err
	}
	return &op.BundleStatus{Version: st.Version, RootDigest: st.Root.Digest, State: st.State, AllowSHA256: bundle.AllowSHA256()}, nil
}

// Recorded returns the final result that the state holds for the operation opID. The state keeps the
// result of the last operation only, so an older operation gives false. It reads the state and writes
// nothing. ErrInFlight means that the engine started the operation and has no final result for it
// yet, and any other error means that the answer is not known.
func (a *Applier) Recorded(ctx context.Context, opID string) (Outcome, bool, error) {
	st, _, err := a.cfg.State.Read(ctx)
	if err != nil {
		return Outcome{}, false, err
	}
	if st.Result != nil && st.Result.OpID == opID {
		return Outcome{st.Result.Outcome, st.Result.Reason, st.Result.Detail}, true, nil
	}
	if st.OpID == opID && (st.State == stateApplying || st.State == stateRollingBack) {
		return Outcome{}, false, ErrInFlight
	}
	return Outcome{}, false, nil
}

func refused(reason, detail string) Outcome {
	return Outcome{Outcome: op.OutcomeRefused, Reason: reason, Detail: detail}
}

func keySHA(k crypto.PublicKey) string {
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// signer returns the SHA-256 of the key that signed the attestation.
func signer(att []byte, keys []crypto.PublicKey) string {
	for _, k := range keys {
		if _, _, err := bundle.ParseAttestation(att, []crypto.PublicKey{k}); err == nil {
			return keySHA(k)
		}
	}
	return ""
}

// keys returns the trusted keys. A missing key function, a failed read and an empty list are errors,
// so that the caller tries again and no signature refusal is recorded for a key fault.
func (a *Applier) keys() ([]crypto.PublicKey, error) {
	if a.cfg.Keys == nil {
		return nil, errors.New("bundle applier has no key function")
	}
	keys, err := a.cfg.Keys()
	if err != nil {
		return nil, fmt.Errorf("read the attestation keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, errors.New("no attestation keys")
	}
	return keys, nil
}

// run is one apply under the lock.
type run struct {
	opID    string
	set     bundle.Set
	st      bundle.Statement
	content string
	keySHA  string
	snap    State
	// fetched lists the components that this apply read from the mirror and checked.
	fetched []fetched
	// harness lists the live harness objects, liveCluster and liveNamespaced the scopes that the API
	// server serves, and checkedBy is the fingerprint of the check inputs.
	harness                     HarnessRefs
	liveCluster, liveNamespaced []string
	checkedBy                   string
	// fetchedBytes counts the layer bytes that the fetch holds.
	fetchedBytes int
	root         bundle.Artifact
	// held is true while this process holds the lock and has not written a final state.
	held bool
	// rollingBack is true when the run resumes a rollback that another run started, and failed is
	// the detail of the health wait that failed.
	rollingBack bool
	failed      string
}

type fetched struct {
	comp bundle.Component
	art  bundle.Artifact
	objs []Object
}

func (a *Applier) apply(ctx context.Context, opID, opTarget string, att []byte) (Outcome, error) {
	cfg := a.cfg
	if len(att) > op.MaxBundleArgsBytes {
		return refused(op.ReasonPayloadInvalid, "statement"), nil
	}
	keys, err := a.keys()
	if err != nil {
		return Outcome{}, err
	}
	st, set, err := bundle.ParseAttestation(att, keys)
	switch {
	case errors.Is(err, record.ErrSignature):
		return refused(op.ReasonSignatureInvalid, ""), nil
	case errors.Is(err, bundle.ErrSubjects):
		return refused(op.ReasonPayloadInvalid, "subjects"), nil
	case err != nil:
		return refused(op.ReasonPayloadInvalid, "statement"), nil
	case st.Predicate.Target != cfg.Target || st.Predicate.Target != opTarget:
		return refused(op.ReasonPayloadInvalid, DetailTarget), nil
	case st.Predicate.Env != cfg.Env:
		return refused(op.ReasonEnvMismatch, ""), nil
	}
	r := &run{opID: opID, set: set, st: st, content: bundle.ContentSHA256(set), keySHA: signer(att, keys)}
	trusted := map[string]bool{}
	for _, k := range keys {
		trusted[keySHA(k)] = true
	}

	if !a.running.TryLock() {
		return Outcome{}, ErrLockHeld
	}
	defer a.running.Unlock()
	out, proceed, err := a.admit(ctx, r, trusted)
	if err != nil || !proceed {
		return out, err
	}
	r.held = true
	defer a.release(r)
	if r.rollingBack {
		return a.rollback(ctx, r, r.failed)
	}

	out, err = a.prepare(ctx, r)
	if err != nil || out != (Outcome{}) {
		if err == nil {
			err = a.finish(ctx, r, out, nil)
		}
		return out, err
	}
	return a.deploy(ctx, r)
}

// admit takes the lock and decides from the state whether the set goes on: a repeated operation ID
// gets its stored result, and the version rules refuse or accept the set. The mark moves later,
// when the state enters applying. A set that the state holds in applying or rolling_back resumes
// from that phase, under any operation ID, so that a new operation for the same set can finish it.
func (a *Applier) admit(ctx context.Context, r *run, trusted map[string]bool) (Outcome, bool, error) {
	var out Outcome
	var proceed, reset bool
	err := a.update(ctx, func(s *State) error {
		out, proceed, reset = Outcome{}, false, false
		r.rollingBack, r.failed = false, ""
		now := a.cfg.Now()
		if s.Holder != "" && s.Holder != a.cfg.Holder && now.Before(s.Until) {
			return ErrLockHeld
		}
		if s.Result != nil && s.Result.OpID == r.opID {
			out = Outcome{s.Result.Outcome, s.Result.Reason, s.Result.Detail}
			return errNoWrite
		}
		mark := s.Version
		if s.KeySHA256 != "" && !trusted[s.KeySHA256] {
			mark, reset = bundle.Version{}, true
		}
		same := !reset && s.Version == r.set.Version && s.ContentSHA256 == r.content
		resume := same && (s.State == stateApplying || s.State == stateRollingBack)
		if resume && s.State == stateRollingBack {
			r.rollingBack, r.failed = true, s.Failed
		}
		if !resume {
			switch cmp := r.set.Version.Compare(mark); {
			case cmp < 0:
				out = refused(op.ReasonVersionOld, "")
			case cmp == 0 && s.ContentSHA256 != r.content:
				out = refused(op.ReasonVersionOld, "version_conflict")
			case cmp == 0 && s.State == stateRolledBack:
				out = refused(op.ReasonVersionOld, "")
			case cmp == 0:
				out = Outcome{Outcome: op.OutcomeAlreadyApplied}
			}
		}
		if out != (Outcome{}) {
			s.Result = a.result(r.opID, out)
			return nil
		}
		proceed = true
		s.Holder, s.Until = a.cfg.Holder, now.Add(a.lockTTL())
		r.snap = *s
		return nil
	})
	if err != nil {
		return Outcome{}, false, err
	}
	if proceed && reset {
		a.log.Warn("bundle_version_reset", "target", a.cfg.Target, "key", r.snap.KeySHA256)
	}
	return out, proceed, nil
}

func (a *Applier) result(opID string, out Outcome) *op.Result {
	return &op.Result{OpID: opID, Cell: a.cfg.Target, Outcome: out.Outcome, Reason: out.Reason, Detail: out.Detail, At: a.cfg.Now()}
}

// update reads the state, applies fn and writes it, and tries again when another writer won. fn
// may return errNoWrite to skip the write.
func (a *Applier) update(ctx context.Context, fn func(*State) error) error {
	for range maxStateAttempts {
		st, rv, err := a.cfg.State.Read(ctx)
		if err != nil {
			return err
		}
		if err := fn(&st); err != nil {
			if errors.Is(err, errNoWrite) {
				return nil
			}
			return err
		}
		err = a.cfg.State.Write(ctx, st, rv)
		if errors.Is(err, ErrConflict) {
			continue
		}
		return err
	}
	return fmt.Errorf("bundle state changed %d times while it was written", maxStateAttempts)
}

// mine checks that this process still holds the lock.
func (a *Applier) mine(s *State) error {
	if s.Holder != a.cfg.Holder {
		return errLockLost
	}
	return nil
}

// release frees the lock of a run that ended with no final state, as a best effort.
func (a *Applier) release(r *run) {
	if !r.held {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := a.update(ctx, func(s *State) error {
		if s.Holder != a.cfg.Holder {
			return errNoWrite
		}
		s.Holder, s.Until = "", time.Time{}
		return nil
	})
	if err != nil {
		a.log.Warn("bundle lock not released", "error", err)
	}
}

// finish writes the final state of a run: the result, the lock freed, and the change that mutate makes.
func (a *Applier) finish(ctx context.Context, r *run, out Outcome, mutate func(*State)) error {
	err := a.update(ctx, func(s *State) error {
		if err := a.mine(s); err != nil {
			return err
		}
		if mutate != nil {
			mutate(s)
		}
		s.Result = a.result(r.opID, out)
		s.Holder, s.Until = "", time.Time{}
		return nil
	})
	if err == nil {
		r.held = false
	}
	return err
}

func asRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

func (r *Refusal) outcome() Outcome { return refused(r.Reason, r.Detail) }

// fetchRefusal maps the errors of a bundle read that come from the bytes, not from the transport.
func fetchRefusal(name string, err error) *Refusal {
	switch {
	case errors.Is(err, ocistore.ErrDigestMismatch):
		return &Refusal{Reason: op.ReasonDigestMismatch, Detail: name}
	case errors.Is(err, ocistore.ErrTooLarge), errors.Is(err, bundle.ErrTooLarge):
		return &Refusal{Reason: op.ReasonComponentNotAllowed, Detail: "too_large", Object: name}
	case errors.Is(err, ocistore.ErrLayout), errors.Is(err, bundle.ErrLayout), errors.Is(err, bundle.ErrMediaType):
		return &Refusal{Reason: op.ReasonComponentNotAllowed, Detail: "layout", Object: name}
	}
	return nil
}

// prepare composes the root and compares it with the signed subject, then reads and checks every
// component that the state has not checked. It writes nothing. It returns a refusal as an Outcome.
func (a *Applier) prepare(ctx context.Context, r *run) (Outcome, error) {
	cfg := a.cfg
	root, err := bundle.ComposeRoot(cfg.Role, r.set, cfg.Policy)
	var na *bundle.NotAllowed
	switch {
	case errors.As(err, &na):
		return refused(op.ReasonComponentNotAllowed, na.Detail), nil
	case err != nil:
		return refused(op.ReasonPayloadInvalid, "statement"), nil
	}
	r.root = root
	if root.Digest != r.st.RootDigest() {
		return refused(op.ReasonDigestMismatch, "root"), nil
	}

	if r.harness, err = a.harnessRefs(ctx); err != nil {
		return Outcome{}, err
	}
	r.liveCluster, r.liveNamespaced = a.liveScopes()
	r.checkedBy, err = checkInputs(checkIn{
		role: cfg.Role, policy: cfg.Policy, module: policySource, harness: r.harness,
		cluster: r.liveCluster, namespaced: r.liveNamespaced, opa: opaversion.Version,
	})
	if err != nil {
		return Outcome{}, err
	}
	checked := map[string]bool{}
	if r.snap.CheckedBy == r.checkedBy {
		for _, c := range r.snap.Checked {
			checked[c] = true
		}
	}
	fctx, end := a.tel.step(ctx, spanFetch)
	out, err := a.fetch(fctx, r, checked)
	if err == nil && out == (Outcome{}) && len(checked) > 0 && a.setScopesDiffer(r) {
		// A custom resource definition of the set gives a kind another scope than the live API, so
		// the components that an earlier set checked are checked again under the scopes of this set.
		done := map[string]bool{}
		for _, f := range r.fetched {
			done[checkedKey(f.comp.Name, f.comp.Digest)] = true
		}
		out, err = a.fetch(fctx, r, done)
	}
	end(err)
	if err != nil || out != (Outcome{}) {
		return out, err
	}
	cctx, end := a.tel.step(ctx, spanCheck)
	out, err = a.check(cctx, r)
	end(err)
	return out, err
}

// fetch reads and decodes each component of the set whose key skip does not hold.
func (a *Applier) fetch(ctx context.Context, r *run, skip map[string]bool) (Outcome, error) {
	for _, c := range r.set.Components {
		if skip[checkedKey(c.Name, c.Digest)] {
			continue
		}
		art, err := ocistore.Fetch(ctx, a.cfg.Mirror, "bundles/"+a.cfg.Target+"/"+c.Name, c.Digest)
		if err != nil {
			if ref := fetchRefusal(c.Name, err); ref != nil {
				a.log.Warn("bundle refused", "component", c.Name, "reason", ref.Reason, "detail", ref.Detail, "error", err)
				return ref.outcome(), nil
			}
			return Outcome{}, fmt.Errorf("read component %s from the mirror: %w", c.Name, err)
		}
		if art.Digest != c.Digest {
			return refused(op.ReasonDigestMismatch, c.Name), nil
		}
		if r.fetchedBytes += len(art.Layer); r.fetchedBytes > a.maxSetBytes {
			a.log.Warn("bundle refused", "component", c.Name, "reason", op.ReasonComponentNotAllowed, "detail", "too_large", "set_bytes", r.fetchedBytes)
			return refused(op.ReasonComponentNotAllowed, "too_large"), nil
		}
		body, err := bundle.UnpackComponent(art.Layer, bundle.MaxUnpackedBytes)
		if err != nil {
			if ref := fetchRefusal(c.Name, err); ref != nil {
				return ref.outcome(), nil
			}
			return refused(op.ReasonComponentNotAllowed, "layout"), nil
		}
		objs, err := DecodeCanonical(body, bundle.MaxObjects)
		if err != nil {
			if ref, ok := asRefusal(err); ok {
				a.log.Warn("bundle refused", "component", c.Name, "reason", ref.Reason, "detail", ref.Detail)
				return ref.outcome(), nil
			}
			return Outcome{}, err
		}
		r.fetched = append(r.fetched, fetched{comp: c, art: art, objs: objs})
	}
	return Outcome{}, nil
}

// harnessRefs lists the harness NetworkPolicies of the live cluster, in name order.
func (a *Applier) harnessRefs(ctx context.Context) (HarnessRefs, error) {
	nps, err := a.cfg.Client.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: harnessLabel})
	if err != nil {
		return HarnessRefs{}, fmt.Errorf("list harness network policies: %w", err)
	}
	var refs HarnessRefs
	for _, np := range nps.Items {
		refs.NetworkPolicies = append(refs.NetworkPolicies, ObjectRef{Namespace: np.Namespace, Name: np.Name})
	}
	slices.SortFunc(refs.NetworkPolicies, func(x, y ObjectRef) int {
		return cmp.Or(strings.Compare(x.Namespace, y.Namespace), strings.Compare(x.Name, y.Name))
	})
	return refs, nil
}

// checkRevision names the rules of the Go checks: the decoder of internal/bundle
// (bundle.DecodeManifests, bundle.DecodeCanonical) and the checks of this package outside Rego. Raise
// it when one of them changes, so that the components that an older build checked are checked again.
const checkRevision = 1

// checkIn holds every input of the check that is not the component itself.
type checkIn struct {
	role                string
	policy              bundle.Policy
	module              string
	harness             HarnessRefs
	cluster, namespaced []string
	opa                 string
}

// checkInputs returns the fingerprint of the check inputs: the check revision, the role, the allow
// data, the Rego module, the live harness policies, the scopes that the live API serves and the OPA
// version. A component in State.Checked skips the check only while the state holds the same
// fingerprint. The custom resource definitions of the set are not known before the fetch, so prepare
// checks every component again when one of them gives a kind another scope than the live API.
func checkInputs(in checkIn) (string, error) {
	sorted := func(v []string) []string { return slices.Sorted(slices.Values(v)) }
	body, err := json.Marshal(struct {
		Revision            int
		Role                string
		Allow               bundle.Policy
		Rego                string
		Harness             []ObjectRef
		Cluster, Namespaced []string
		OPA                 string
	}{checkRevision, in.role, in.policy, in.module, in.harness.NetworkPolicies, sorted(in.cluster), sorted(in.namespaced), in.opa})
	if err != nil {
		return "", fmt.Errorf("encode the check inputs: %w", err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// checkedKey is the entry of State.Checked for a component: its name and digest. The class of a
// component comes from its name, so a digest that one component passed says nothing of another.
func checkedKey(name, digest string) string { return name + "@" + digest }

// check runs the policy over each component that the fetch read. It builds a new Checker for
// the set, with the harness policies of the live cluster and the scopes of the live API, then the
// CRD scopes of every component of the set. Cluster scope wins in the policy when two sources
// disagree.
func (a *Applier) check(ctx context.Context, r *run) (Outcome, error) {
	cfg := a.cfg
	checker, err := NewChecker(cfg.Role, cfg.Policy, r.harness)
	if err != nil {
		return Outcome{}, err
	}
	crdCluster, crdNamespaced := crdKinds(r.fetchedObjects())
	checker.AddScopes(append(slices.Clone(r.liveCluster), crdCluster...), append(slices.Clone(r.liveNamespaced), crdNamespaced...))
	for _, f := range r.fetched {
		err := checker.Check(ctx, f.comp.Name, f.objs)
		if err == nil {
			if ref := checkAppProjects(cfg.Role, cfg.Policy, f.objs); ref != nil {
				err = ref
			}
		}
		if err == nil {
			continue
		}
		if ref, ok := asRefusal(err); ok {
			a.log.Warn("bundle refused", "component", f.comp.Name, "reason", ref.Reason, "detail", ref.Detail, "object", ref.Object)
			return ref.outcome(), nil
		}
		return Outcome{}, err
	}
	return Outcome{}, nil
}

func (r *run) fetchedObjects() []Object {
	var all []Object
	for _, f := range r.fetched {
		all = append(all, f.objs...)
	}
	return all
}

// setScopesDiffer reports whether a custom resource definition that the fetch read gives a kind a
// scope that the live API does not serve it with.
func (a *Applier) setScopesDiffer(r *run) bool {
	crdCluster, crdNamespaced := crdKinds(r.fetchedObjects())
	for _, k := range crdCluster {
		if !slices.Contains(r.liveCluster, k) {
			return true
		}
	}
	for _, k := range crdNamespaced {
		if !slices.Contains(r.liveNamespaced, k) {
			return true
		}
	}
	return false
}

// liveScopes lists the group/Kind of every resource that the API server serves, by scope. An error
// of discovery leaves the lists short, and the policy then refuses a kind of unknown scope.
func (a *Applier) liveScopes() (cluster, namespaced []string) {
	_, lists, err := a.cfg.Client.Discovery().ServerGroupsAndResources()
	if err != nil {
		a.log.Warn("bundle discovery incomplete", "error", err)
	}
	for _, l := range lists {
		group, _, _ := strings.Cut(l.GroupVersion, "/")
		if !strings.Contains(l.GroupVersion, "/") {
			group = ""
		}
		for _, res := range l.APIResources {
			if strings.Contains(res.Name, "/") || res.Kind == "" {
				continue
			}
			key := res.Kind
			if group != "" {
				key = group + "/" + res.Kind
			}
			if res.Namespaced {
				namespaced = append(namespaced, key)
			} else {
				cluster = append(cluster, key)
			}
		}
	}
	return cluster, namespaced
}

// deploy runs a set that passed every check: it moves the state to applying, pushes the bundles and
// the root, moves the tag, waits for health and rolls back when the wait fails.
func (a *Applier) deploy(ctx context.Context, r *run) (Outcome, error) {
	cfg := a.cfg
	err := a.update(ctx, func(s *State) error {
		if err := a.mine(s); err != nil {
			return err
		}
		a.ensureGood(s)
		s.Source, s.Version, s.ContentSHA256, s.KeySHA256 = sourceSigned, r.set.Version, r.content, r.keySHA
		s.OpID, s.State, s.Failed = r.opID, stateApplying, ""
		s.Until = cfg.Now().Add(a.lockTTL())
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}

	pctx, end := a.tel.step(ctx, spanPush)
	err = a.push(pctx, r)
	end(err)
	if err != nil {
		return Outcome{}, err
	}

	comps := map[string]string{}
	for _, c := range r.set.Components {
		comps[c.Name] = c.Digest
	}
	tctx, end := a.tel.step(ctx, spanTag)
	err = a.tag(tctx, r, comps)
	end(err)
	if err != nil {
		return Outcome{}, err
	}

	wctx, end := a.tel.step(ctx, spanWait)
	detail, err := a.wait(wctx, r.set, r.root.Digest, comps, cfg.HealthTimeout)
	end(err)
	if err != nil {
		return Outcome{}, err
	}
	if detail == "" {
		out := Outcome{Outcome: op.OutcomeApplied}
		err = a.finish(ctx, r, out, func(s *State) {
			s.State = stateHealthy
			g := Good{Version: r.set.Version, ContentSHA256: r.content, Root: s.Root, Components: maps.Clone(s.Components), At: cfg.Now()}
			s.Good = slices.DeleteFunc(s.Good, func(o Good) bool { return o.Root.Digest == g.Root.Digest })
			s.Good = append([]Good{g}, s.Good...)
			if len(s.Good) > maxGood {
				s.Good = s.Good[:maxGood]
			}
			s.Checked, s.CheckedBy = a.boundChecked(s, r.checkedBy, r.fetched), r.checkedBy
		})
		return out, err
	}
	return a.rollback(ctx, r, detail)
}

// ensureGood records the current root as the first good root when the state holds a healthy root
// that no signed set made, such as the bootstrap root.
func (a *Applier) ensureGood(s *State) {
	if s.State == stateHealthy && len(s.Good) == 0 && s.Root.Digest != "" {
		s.Good = []Good{{Root: s.Root, Components: maps.Clone(s.Components), At: a.cfg.Now()}}
	}
}

// boundChecked returns the entries that stay in checked: those that the state checked before with
// the same check inputs, plus those that this run checked, kept only while a component or a good
// root names them.
func (a *Applier) boundChecked(s *State, by string, added []fetched) []string {
	live := map[string]bool{}
	for name, d := range s.Components {
		live[checkedKey(name, d)] = true
	}
	for _, g := range s.Good {
		for name, d := range g.Components {
			live[checkedKey(name, d)] = true
		}
	}
	have := map[string]bool{}
	if s.CheckedBy == by {
		for _, c := range s.Checked {
			have[c] = true
		}
	}
	for _, f := range added {
		have[checkedKey(f.comp.Name, f.comp.Digest)] = true
	}
	var out []string
	for d := range have {
		if live[d] {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out
}

func (a *Applier) push(ctx context.Context, r *run) error {
	st := a.cfg.Store
	one := func(repo string, art bundle.Artifact) error {
		if err := st.PushBlob(ctx, repo, art.ConfigDigest, art.Config); err != nil {
			return err
		}
		if err := st.PushBlob(ctx, repo, art.LayerDigest, art.Layer); err != nil {
			return err
		}
		if _, err := st.PushManifest(ctx, repo, "", bundle.MediaTypeManifest, art.Manifest); err != nil {
			return err
		}
		return nil
	}
	for _, f := range r.fetched {
		if err := one("bundles/"+f.comp.Name, f.art); err != nil {
			return fmt.Errorf("push component %s: %w", f.comp.Name, err)
		}
	}
	if err := one(repoRoot, r.root); err != nil {
		return fmt.Errorf("push root: %w", err)
	}
	return nil
}

func (a *Applier) tag(ctx context.Context, r *run, comps map[string]string) error {
	err := a.update(ctx, func(s *State) error {
		if err := a.mine(s); err != nil {
			return err
		}
		s.Root = Root{Digest: r.root.Digest, Manifest: r.root.Manifest}
		s.Components = comps
		s.Until = a.cfg.Now().Add(a.lockTTL())
		return nil
	})
	if err != nil {
		return err
	}
	if _, err := a.cfg.Store.PushManifest(ctx, repoRoot, tagCurrent, bundle.MediaTypeManifest, r.root.Manifest); err != nil {
		return fmt.Errorf("move the tag %s: %w", tagCurrent, err)
	}
	a.refresh(ctx)
	return nil
}

// refresh asks Argo CD for a hard refresh of root. A failure is not final, because Argo CD
// polls the tag by itself.
func (a *Applier) refresh(ctx context.Context) {
	if err := refreshApp(ctx, a.cfg.Dynamic, "root"); err != nil {
		a.log.Warn("bundle root refresh failed", "error", err)
	}
}

// wait polls the Applications until the root and every component are Synced at their digest and
// Healthy. It returns "" when they are. It returns <app>:<sync>/<health> for an Application that stays
// Synced and Degraded at its digest for the grace period, and timeout:<app>:<sync>/<health> for the
// first Application that is not healthy at the deadline. Argo CD sets the revision when it compares,
// before the sync applies anything, so an Application that is Degraded while OutOfSync, or at another
// revision, still shows the old resources, and only the deadline ends the wait for it. An error means
// that ctx ended.
func (a *Applier) wait(ctx context.Context, set bundle.Set, rootDigest string, comps map[string]string, timeout time.Duration) (string, error) {
	type want struct{ name, digest string }
	var wants []want
	for _, c := range set.Components {
		if d, ok := comps[c.Name]; ok {
			wants = append(wants, want{c.Name, d})
		}
	}
	wants = append(wants, want{"root", rootDigest})
	return a.waitFor(ctx, func(yield func(string, string)) {
		for _, w := range wants {
			yield(w.name, w.digest)
		}
	}, timeout)
}

func (a *Applier) waitFor(ctx context.Context, wants func(yield func(name, digest string)), timeout time.Duration) (string, error) {
	cfg := a.cfg
	deadline := cfg.Now().Add(timeout)
	degraded := map[string]time.Time{}
	for {
		apps, err := listApps(ctx, cfg.Dynamic)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			a.log.Warn("bundle health read failed", "error", err)
		}
		now := cfg.Now()
		var first, early string
		wants(func(name, digest string) {
			s, ok := apps[name]
			if !ok {
				s = appState{Sync: unknownStatus, Health: unknownStatus}
			}
			if s.Health == statusDegraded && s.Sync == statusSynced && s.Revision == digest {
				since, seen := degraded[name]
				if !seen {
					degraded[name] = now
				} else if now.Sub(since) >= cfg.DegradedGrace && early == "" {
					early = name + ":" + s.String()
				}
			} else {
				delete(degraded, name)
			}
			if first == "" && !(s.Sync == statusSynced && s.Revision == digest && s.Health == statusHealthy) {
				first = name + ":" + s.String()
			}
		})
		switch {
		case early != "":
			return early, nil
		case first == "":
			return "", nil
		case !now.Before(deadline):
			return "timeout:" + first, nil
		}
		if err := a.sleep(ctx, cfg.Poll); err != nil {
			return "", err
		}
	}
}

// rollback points the tag back at the last good root, with the manifest bytes that the state holds,
// and waits for that root to become healthy. It creates no version and deletes nothing. It first
// writes the state rolling_back with the failed detail, so that a run that takes over after a crash
// resumes the rollback and does not push the failed root again. The state names the good root only
// when the tag holds it.
func (a *Applier) rollback(ctx context.Context, r *run, failed string) (_ Outcome, err error) {
	cfg := a.cfg
	rctx, end := a.tel.step(ctx, spanRollback)
	defer func() { end(err) }()
	var good *Good
	// moved is true once the tag holds the good root again.
	var moved bool
	var st State
	err = a.update(rctx, func(s *State) error {
		if err := a.mine(s); err != nil {
			return err
		}
		s.State, s.Failed = stateRollingBack, failed
		s.Until = cfg.Now().Add(a.lockTTL())
		st = *s
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}
	if len(st.Good) > 0 {
		good = &st.Good[0]
	}
	detail := failed
	switch {
	case good == nil || sha256Digest(good.Root.Manifest) != good.Root.Digest:
		detail = detailRollback
	default:
		if _, err := cfg.Store.PushManifest(rctx, repoRoot, tagCurrent, bundle.MediaTypeManifest, good.Root.Manifest); err != nil {
			a.log.Error("bundle rollback tag failed", "error", err)
			detail = detailRollback
			break
		}
		moved = true
		a.refresh(rctx)
		left, err := a.waitFor(rctx, func(yield func(name, digest string)) {
			for _, name := range slices.Sorted(maps.Keys(good.Components)) {
				yield(name, good.Components[name])
			}
			yield("root", good.Root.Digest)
		}, cfg.RollbackTimeout)
		if err != nil {
			return Outcome{}, err
		}
		if left != "" {
			detail = detailRollback
		}
	}
	out := Outcome{Outcome: op.OutcomeRolledBack, Reason: op.ReasonUnhealthy, Detail: detail}
	err = a.finish(rctx, r, out, func(s *State) {
		s.State, s.Failed = stateRolledBack, ""
		if moved {
			s.Root, s.Components = good.Root, maps.Clone(good.Components)
		}
		by := r.checkedBy
		if r.rollingBack {
			by = s.CheckedBy
		}
		s.Checked, s.CheckedBy = a.boundChecked(s, by, nil), by
	})
	return out, err
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
