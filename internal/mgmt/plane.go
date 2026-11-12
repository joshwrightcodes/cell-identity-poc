package mgmt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// maxNewKeys is the most keys that one update may add to a cell.
const maxNewKeys = 2

// KeySource returns the issuer and public keys of a cluster. Task 4's key client implements it.
type KeySource interface {
	Keys(ctx context.Context, cluster string) (mgmtapi.ClusterKeys, error)
}

// Config configures a Plane. Zero durations take the defaults: NonceTTL 120 s, CheckEvery 15 min,
// KeyUpdateGap 60 s, KeyCacheTTL 60 s, NonceKeyEvery 24 h and HistoryLen 50.
type Config struct {
	Intent  Intent
	KeyPath string
	Store   Store
	Keys    KeySource
	Now     func() time.Time
	// Ticks returns a channel that delivers a tick every d. The default uses a time.Ticker.
	Ticks func(d time.Duration) <-chan time.Time
	Log   *slog.Logger
	Meter metric.Meter

	NonceTTL, CheckEvery, KeyUpdateGap, KeyCacheTTL, NonceKeyEvery time.Duration
	HistoryLen                                                     int
}

func (c *Config) defaults() {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Meter == nil {
		c.Meter = noop.NewMeterProvider().Meter("mgmtd")
	}
	for _, d := range []struct {
		v *time.Duration
		d time.Duration
	}{
		{&c.NonceTTL, 120 * time.Second}, {&c.CheckEvery, 15 * time.Minute}, {&c.KeyUpdateGap, 60 * time.Second},
		{&c.KeyCacheTTL, 60 * time.Second}, {&c.NonceKeyEvery, 24 * time.Hour},
	} {
		if *d.v <= 0 {
			*d.v = d.d
		}
	}
	if c.HistoryLen <= 0 {
		c.HistoryLen = 50
	}
}

// Error is a refusal with one of the mgmtapi reasons. Detail is for logs and tests.
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

func refuse(reason, detail string) error { return &Error{Reason: reason, Detail: detail} }

// ReasonOf returns the reason of err when it is an *Error, and an empty string otherwise.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func tokenError(err error) error {
	return refuse(mgmtapi.ReasonTokenInvalid, string(clusterjwt.ReasonOf(err)))
}

func keySourceError(err error) error {
	var ke *mgmtapi.KeyError
	if errors.As(err, &ke) && ke.Reason == mgmtapi.ReasonIssuerUntrusted {
		return refuse(mgmtapi.ReasonIssuerUntrusted, "key_source")
	}
	return refuse(mgmtapi.ReasonIssuerUnavailable, "key_source")
}

// CheckResult is the outcome of a key check.
type CheckResult string

// The results of KeyCheck.
const (
	CheckUnchanged         CheckResult = "unchanged"
	CheckKeysUpdated       CheckResult = "keys_updated"
	CheckKeysUntrusted     CheckResult = "keys_untrusted"
	CheckIssuerUntrusted   CheckResult = "issuer_untrusted"
	CheckIssuerUnavailable CheckResult = "issuer_unavailable"
	CheckNotBound          CheckResult = "not_bound"
	CheckRateLimited       CheckResult = "rate_limited"
)

// Status is what `ctl status` shows.
type Status struct {
	Env                string           `json:"env"`
	Signed             spec.Revision    `json:"signed"`
	Served             spec.Revision    `json:"served"`
	RestoreActive      bool             `json:"restoreActive"`
	Applied            spec.Revision    `json:"applied"`
	AppliedAt          time.Time        `json:"appliedAt,omitzero"`
	LagSince           time.Time        `json:"lagSince,omitzero"`
	LastReportAt       time.Time        `json:"lastReportAt,omitzero"`
	LastRefusal        *mgmtapi.Refusal `json:"lastRefusal,omitempty"`
	StoreError         string           `json:"storeError,omitempty"`
	PendingDrops       []string         `json:"pendingDrops"`
	StateBehindApplied bool             `json:"stateBehindApplied"`
	Cells              []CellStatus     `json:"cells"`
}

// CellStatus is the status of one intent cell.
type CellStatus struct {
	Name      string        `json:"name"`
	Bound     bool          `json:"bound"`
	Issuer    string        `json:"issuer"`
	Kids      []string      `json:"kids"`
	Record    spec.Revision `json:"record"`
	CheckedAt time.Time     `json:"checkedAt,omitzero"`
	LastCheck string        `json:"lastCheck"`
}

type snapshot struct {
	st  *State
	pub ed25519.PublicKey
}

type reports struct {
	applied      spec.Revision
	appliedAt    time.Time
	lastReportAt time.Time
	lagSince     time.Time
	refusal      *mgmtapi.Refusal
	storeError   string
	behindLogged bool
}

// Plane is the management core. One mutex serializes every change. A change fetches keys and checks
// the token before it takes the mutex, then re-reads the current state, applies, signs, saves and
// swaps an immutable snapshot that readers load without a lock.
type Plane struct {
	cfg    Config
	intent map[string]IntentCell
	nonces *Nonces
	cache  keyCache

	mu  sync.Mutex // the commit path, and key
	key ed25519.PrivateKey

	snap atomic.Pointer[snapshot]

	rmu sync.Mutex
	rep reports

	bindResults, checkResults metric.Int64Counter
}

// NewPlane loads the key and the state, signs the first spec of a fresh store, re-signs after a key
// change, and applies the intent.
func NewPlane(cfg Config) (*Plane, error) {
	cfg.defaults()
	switch {
	case cfg.Store == nil:
		return nil, errors.New("plane needs a store")
	case cfg.Keys == nil:
		return nil, errors.New("plane needs a key source")
	case cfg.KeyPath == "":
		return nil, errors.New("plane needs a key path")
	}
	if err := cfg.Intent.validate(); err != nil {
		return nil, fmt.Errorf("intent: %w", err)
	}
	key, created, err := LoadOrCreateKey(cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	nonces, err := NewNonces(cfg.Now, cfg.NonceTTL)
	if err != nil {
		return nil, err
	}
	p := &Plane{cfg: cfg, key: key, nonces: nonces.WithKeyEvery(cfg.NonceKeyEvery), intent: map[string]IntentCell{}}
	p.cache.m = map[string]*cacheEntry{}
	for _, c := range cfg.Intent.Cells {
		p.intent[c.Name] = c
	}
	p.bindResults, _ = cfg.Meter.Int64Counter("mgmtd.bind.results")
	p.checkResults, _ = cfg.Meter.Int64Counter("mgmtd.keycheck.results")
	if _, err := cfg.Meter.Int64ObservableGauge("mgmtd.spec.revision.lag", metric.WithInt64Callback(p.observeLag)); err != nil {
		return nil, err
	}

	pub := key.Public().(ed25519.PublicKey)
	fp := fingerprint(pub)
	st, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	pending := 0
	switch {
	case st == nil:
		st = newState(fp)
		p.snap.Store(&snapshot{st: st, pub: pub})
		if err := p.commit(func(t *txn) error { return t.revise() }); err != nil {
			return nil, fmt.Errorf("sign the first spec: %w", err)
		}
		if created {
			cfg.Log.Info("signing_key_created")
		}
	case st.KeySHA256 != fp:
		p.snap.Store(&snapshot{st: st, pub: pub})
		pending = len(st.PendingDrops)
		if err := p.commit(p.resignAll(fp)); err != nil {
			return nil, fmt.Errorf("re-sign after a key change: %w", err)
		}
		cfg.Log.Warn("signing_key_changed", "epoch", p.snap.Load().st.Last.Epoch)
	default:
		if err := p.checkStored(st, pub); err != nil {
			return nil, err
		}
		pending = len(st.PendingDrops)
		p.snap.Store(&snapshot{st: st, pub: pub})
	}

	if err := p.commit(p.reconcile); err != nil {
		return nil, fmt.Errorf("apply the intent: %w", err)
	}
	if pending == 0 {
		if err := p.dropNext(); err != nil && ReasonOf(err) != mgmtapi.ReasonRestoreActive {
			return nil, fmt.Errorf("drop a cell: %w", err)
		}
	}
	p.noteLag()
	return p, nil
}

// checkStored makes sure the last signed spec verifies under the key and names this environment.
func (p *Plane) checkStored(st *State, pub ed25519.PublicKey) error {
	last := st.latest()
	s, _, err := spec.Verify(last.Bundle.Spec, []ed25519.PublicKey{pub})
	if err != nil {
		return fmt.Errorf("stored spec does not verify under the signing key: %w", err)
	}
	if s.Env != p.cfg.Intent.Env {
		return fmt.Errorf("stored state is for env %q, the intent is for %q", s.Env, p.cfg.Intent.Env)
	}
	return nil
}

// --- the commit path ---

// txn is one change under the mutex. It works on a clone of the current state.
type txn struct {
	p       *Plane
	st      *State
	now     time.Time
	key     ed25519.PrivateKey
	records map[string]json.RawMessage
	rev     spec.Revision
	revised bool
	reset   bool
	dirty   bool
	after   []func()
	onFail  []func()
}

func (p *Plane) commit(fn func(*txn) error) (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.snap.Load()
	t := &txn{p: p, st: cur.st.clone(), now: p.cfg.Now(), key: p.key, records: map[string]json.RawMessage{}}
	defer func() {
		if err != nil {
			for _, f := range t.onFail {
				f()
			}
		}
	}()
	if l := cur.st.latest(); l != nil {
		maps.Copy(t.records, l.Bundle.Records)
	}
	if err = fn(t); err != nil {
		return err
	}
	switch {
	case t.revised:
		if err = t.seal(); err != nil {
			return err
		}
	case t.dirty:
	default:
		for _, f := range t.after {
			f()
		}
		return nil
	}
	t.st.Seq++
	if err = p.cfg.Store.Save(t.st); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	p.key = t.key
	p.snap.Store(&snapshot{st: t.st, pub: t.key.Public().(ed25519.PublicKey)})
	p.noteLag()
	for _, f := range t.after {
		f()
	}
	return nil
}

// revise starts a new spec revision. It refuses while a restore is active, unless the change is a
// key rotation.
func (t *txn) revise() error {
	if t.revised {
		return nil
	}
	if t.st.Served != 0 && !t.reset {
		return refuse(mgmtapi.ReasonRestoreActive, "")
	}
	switch {
	case t.st.Last.Epoch == 0:
		t.rev = spec.Revision{Epoch: 1, Counter: 1}
	case t.reset:
		t.rev = spec.Revision{Epoch: t.st.Last.Epoch + 1, Counter: 1}
	default:
		t.rev = spec.Revision{Epoch: t.st.Last.Epoch, Counter: t.st.Last.Counter + 1}
	}
	t.revised = true
	return nil
}

// signCell signs the record of a bound cell at the new revision. Subjects come from the intent
// while the cell is in it.
func (t *txn) signCell(name string) error {
	cs := t.st.Cells[name]
	if cs == nil {
		return fmt.Errorf("cell %q is not bound", name)
	}
	if ic, ok := t.p.intent[name]; ok {
		cs.Subjects = sortedSubjects(ic.Subjects)
	}
	env, err := record.Sign(record.Cell{
		Name: name, Env: t.p.cfg.Intent.Env, Issuer: cs.Issuer, JWKS: cs.JWKS, Subjects: cs.Subjects,
		Epoch: t.rev.Epoch, Counter: t.rev.Counter,
	}, t.key)
	if err != nil {
		return err
	}
	t.records[name] = env
	cs.Record = t.rev
	return nil
}

// seal signs the spec, adds the bundle to the history and trims it.
func (t *txn) seal() error {
	pubs := []ed25519.PublicKey{t.key.Public().(ed25519.PublicKey)}
	s := spec.Spec{Env: t.p.cfg.Intent.Env, Revision: t.rev, Cells: []spec.Entry{}, Retired: []spec.Retired{}}
	records := make(map[string]json.RawMessage, len(t.st.Cells))
	for _, name := range sortedKeys(t.st.Cells) {
		raw, ok := t.records[name]
		if !ok {
			return fmt.Errorf("cell %q has no signed record", name)
		}
		c, payload, err := record.VerifyWithPayload(raw, pubs)
		if err != nil {
			return fmt.Errorf("record of %q: %w", name, err)
		}
		s.Cells = append(s.Cells, spec.Entry{Name: name, Revision: spec.RecordRevision(c), RecordSHA256: spec.RecordDigest(payload)})
		records[name] = raw
	}
	for _, name := range sortedKeys(t.st.Retired) {
		s.Retired = append(s.Retired, spec.Retired{Name: name, Revision: t.st.Retired[name]})
	}
	env, err := spec.Sign(s, t.key)
	if err != nil {
		return err
	}
	t.st.Last = t.rev
	if t.reset {
		t.st.History = nil
	}
	t.st.History = append(t.st.History, Signed{Revision: t.rev, Bundle: mgmtapi.SpecBundle{Spec: env, Records: records}})
	if n := len(t.st.History); n > t.p.cfg.HistoryLen {
		t.st.History = slices.Clone(t.st.History[n-t.p.cfg.HistoryLen:])
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resignAll re-signs every record and the spec at the first revision of the next epoch.
func (p *Plane) resignAll(fp string) func(*txn) error {
	return func(t *txn) error {
		t.reset = true
		t.st.Served = 0
		t.st.KeySHA256 = fp
		if err := t.revise(); err != nil {
			return err
		}
		for _, name := range sortedKeys(t.st.Cells) {
			if err := t.signCell(name); err != nil {
				return err
			}
		}
		return nil
	}
}

// reconcile applies the intent to the state. A bound cell that left the intent becomes a pending
// drop, and a cell whose subjects changed gets a new record in one revision.
func (p *Plane) reconcile(t *txn) error {
	var gone []string
	for _, name := range sortedKeys(t.st.Cells) {
		if _, ok := p.intent[name]; !ok {
			gone = append(gone, name)
		}
	}
	if !slices.Equal(gone, t.st.PendingDrops) && (len(gone) > 0 || len(t.st.PendingDrops) > 0) {
		t.st.PendingDrops = gone
		t.dirty = true
	}
	if t.st.Served != 0 {
		return nil
	}
	for _, name := range sortedKeys(t.st.Cells) {
		ic, ok := p.intent[name]
		if !ok || slices.Equal(t.st.Cells[name].Subjects, sortedSubjects(ic.Subjects)) {
			continue
		}
		if err := t.revise(); err != nil {
			return err
		}
		if err := t.signCell(name); err != nil {
			return err
		}
	}
	return nil
}

// dropNext drops the first pending cell that is still out of the intent, in one revision.
func (p *Plane) dropNext() error {
	return p.commit(func(t *txn) error {
		for len(t.st.PendingDrops) > 0 {
			name := t.st.PendingDrops[0]
			cs := t.st.Cells[name]
			if _, in := p.intent[name]; in || cs == nil {
				t.st.PendingDrops = t.st.PendingDrops[1:]
				t.dirty = true
				continue
			}
			if err := t.revise(); err != nil {
				return err
			}
			t.st.PendingDrops = t.st.PendingDrops[1:]
			t.st.Retired[name] = cs.Record
			delete(t.st.Cells, name)
			delete(t.records, name)
			return nil
		}
		return nil
	})
}

// --- keys ---

type keyInfo struct {
	id  string
	kid string
	key jose.JSONWebKey
}

// parseKeys returns the usable public keys of a key set, in order of identity. A key is usable when
// it has a key ID and the validator accepts its algorithm. Keys compare by kid and thumbprint.
func parseKeys(jwks json.RawMessage) []keyInfo {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []keyInfo
	for _, raw := range set.Keys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(raw); err != nil || !k.Valid() || !k.IsPublic() || k.KeyID == "" {
			continue
		}
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			if pub.N.BitLen() < 2048 {
				continue
			}
		case *ecdsa.PublicKey:
			if pub.Curve != elliptic.P256() {
				continue
			}
		default:
			continue
		}
		thumb, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			continue
		}
		id := k.KeyID + ":" + base64.RawURLEncoding.EncodeToString(thumb)
		if !seen[id] {
			seen[id] = true
			out = append(out, keyInfo{id: id, kid: k.KeyID, key: k})
		}
	}
	slices.SortFunc(out, func(a, b keyInfo) int { return strings.Compare(a.id, b.id) })
	return out
}

func encodeKeys(ks []keyInfo) (json.RawMessage, error) {
	set := jose.JSONWebKeySet{}
	for _, k := range ks {
		set.Keys = append(set.Keys, k.key)
	}
	return json.Marshal(set)
}

func kidsOf(jwks json.RawMessage) []string {
	ks := parseKeys(jwks)
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, k.kid)
	}
	return out
}

type keyDiff struct{ added, removed, common int }

func diffKeys(old, fresh []keyInfo) keyDiff {
	have := map[string]bool{}
	for _, k := range old {
		have[k.id] = true
	}
	var d keyDiff
	now := map[string]bool{}
	for _, k := range fresh {
		now[k.id] = true
		if have[k.id] {
			d.common++
		} else {
			d.added++
		}
	}
	for _, k := range old {
		if !now[k.id] {
			d.removed++
		}
	}
	return d
}

type keyCache struct {
	mu sync.Mutex
	m  map[string]*cacheEntry
}

type cacheEntry struct {
	sem  chan struct{}
	keys mgmtapi.ClusterKeys
	at   time.Time
	ok   bool
}

func (c *keyCache) entry(cell string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[cell]
	if e == nil {
		e = &cacheEntry{sem: make(chan struct{}, 1)}
		c.m[cell] = e
	}
	return e
}

// cachedKeys returns the keys of a cell. A fetch within KeyCacheTTL of the last successful fetch for
// the cell comes from the cache, and one fetch per cell is in flight at a time.
func (p *Plane) cachedKeys(ctx context.Context, cell string) (mgmtapi.ClusterKeys, error) {
	e := p.cache.entry(cell)
	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		return mgmtapi.ClusterKeys{}, refuse(mgmtapi.ReasonIssuerUnavailable, "key_source")
	}
	defer func() { <-e.sem }()
	now := p.cfg.Now()
	if age := now.Sub(e.at); e.ok && age >= 0 && age < p.cfg.KeyCacheTTL {
		return e.keys, nil
	}
	keys, err := p.cfg.Keys.Keys(ctx, cell)
	if err != nil {
		return mgmtapi.ClusterKeys{}, keySourceError(err)
	}
	e.keys, e.at, e.ok = keys, now, true
	return keys, nil
}

// gapActive reports whether a key update for cs would fall inside KeyUpdateGap of the last proven
// update or key check.
func (p *Plane) gapActive(cs *CellState, now time.Time) bool {
	last := cs.KeysUpdatedAt
	if cs.CheckedAt.After(last) {
		last = cs.CheckedAt
	}
	return !last.IsZero() && now.Sub(last) < p.cfg.KeyUpdateGap
}

func (p *Plane) cellRecord(cell string, issuer string, jwks json.RawMessage) record.Cell {
	return record.Cell{
		Name: cell, Env: p.cfg.Intent.Env, Issuer: issuer, JWKS: jwks,
		Subjects: []record.Subject{p.cfg.Intent.BindSubject},
	}
}

// --- bind ---

// Nonce returns a stateless bind nonce for a cell of the intent.
func (p *Plane) Nonce(cell string) (mgmtapi.NonceResponse, error) {
	if _, ok := p.intent[cell]; !ok {
		return mgmtapi.NonceResponse{}, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	nonce, exp := p.nonces.Issue(cell)
	return mgmtapi.NonceResponse{
		Nonce: nonce, Audience: mgmtapi.BindAudience(cell, nonce), ExpiresAt: exp,
		Bound: p.snap.Load().st.Cells[cell] != nil,
	}, nil
}

// Bind checks a bind request and binds the cell, updates its keys, or answers already_bound. A
// refused bind writes no file and consumes no nonce.
func (p *Plane) Bind(ctx context.Context, cell string, req mgmtapi.BindRequest) (resp mgmtapi.BindResponse, err error) {
	defer func() { p.countBind(ctx, cell, resp, err) }()
	if _, ok := p.intent[cell]; !ok {
		return resp, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	if err := p.nonces.Check(cell, req.Nonce); err != nil {
		return resp, err
	}
	now := p.cfg.Now()
	pre := p.snap.Load().st
	cs := pre.Cells[cell]
	issuer := ""
	if cs != nil {
		issuer = cs.Issuer
	}
	aud := mgmtapi.BindAudience(cell, req.Nonce)
	if err := clusterjwt.Precheck(req.Token, issuer, aud, p.cfg.Intent.BindSubject, now); err != nil {
		return resp, tokenError(err)
	}
	if cs != nil {
		_, verr := clusterjwt.ValidateFor(p.cellRecord(cell, cs.Issuer, cs.JWKS), req.Token, aud, now)
		switch {
		case verr == nil:
			return p.alreadyBound(cell, req.Nonce, cs.Record)
		case clusterjwt.ReasonOf(verr) != clusterjwt.UnknownKID:
			return resp, tokenError(verr)
		}
	}

	keys, err := p.cachedKeys(ctx, cell)
	if err != nil {
		return resp, err
	}
	if keys.Issuer == "" || (issuer != "" && keys.Issuer != issuer) {
		return resp, refuse(mgmtapi.ReasonIssuerUntrusted, "issuer_changed")
	}
	fresh := parseKeys(keys.JWKS)
	jwks, err := encodeKeys(fresh)
	if err != nil {
		return resp, refuse(mgmtapi.ReasonKeysUntrusted, "unreadable_set")
	}
	if _, verr := clusterjwt.ValidateFor(p.cellRecord(cell, keys.Issuer, jwks), req.Token, aud, now); verr != nil {
		return resp, tokenError(verr)
	}

	err = p.commit(func(t *txn) error {
		if p.nonces.Used(req.Nonce) {
			return refuse(mgmtapi.ReasonNonceInvalid, "consumed")
		}
		cur := t.st.Cells[cell]
		if cur != nil {
			_, verr := clusterjwt.ValidateFor(p.cellRecord(cell, cur.Issuer, cur.JWKS), req.Token, aud, now)
			switch {
			case verr == nil:
				resp = mgmtapi.BindResponse{Status: mgmtapi.StatusAlreadyBound, Record: cur.Record}
				t.after = append(t.after, func() { _ = p.nonces.Consume(cell, req.Nonce) })
				return nil
			case clusterjwt.ReasonOf(verr) != clusterjwt.UnknownKID:
				return tokenError(verr)
			}
			if keys.Issuer != cur.Issuer {
				return refuse(mgmtapi.ReasonIssuerUntrusted, "issuer_changed")
			}
		}
		if len(fresh) == 0 {
			return refuse(mgmtapi.ReasonKeysUntrusted, "empty_set")
		}
		if err := t.revise(); err != nil {
			return err
		}
		status := mgmtapi.StatusBound
		if cur != nil {
			status = mgmtapi.StatusKeysUpdated
			if diffKeys(parseKeys(cur.JWKS), fresh).added > maxNewKeys {
				return refuse(mgmtapi.ReasonKeysUntrusted, "too_many_new_keys")
			}
			if p.gapActive(cur, t.now) {
				return refuse(mgmtapi.ReasonRateLimited, "key_update_gap")
			}
		} else {
			cur = &CellState{BoundAt: t.now}
			t.st.Cells[cell] = cur
			delete(t.st.Retired, cell)
		}
		cur.Issuer, cur.JWKS = keys.Issuer, jwks
		cur.KeysUpdatedAt, cur.CheckedAt, cur.LastCheck = t.now, t.now, ""
		if err := t.signCell(cell); err != nil {
			return err
		}
		resp = mgmtapi.BindResponse{Status: status, Record: t.rev}
		t.after = append(t.after, func() { _ = p.nonces.Consume(cell, req.Nonce) })
		return nil
	})
	if err != nil {
		return mgmtapi.BindResponse{}, err
	}
	return resp, nil
}

func (p *Plane) alreadyBound(cell, nonce string, rev spec.Revision) (mgmtapi.BindResponse, error) {
	if err := p.nonces.Consume(cell, nonce); err != nil {
		return mgmtapi.BindResponse{}, err
	}
	return mgmtapi.BindResponse{Status: mgmtapi.StatusAlreadyBound, Record: rev}, nil
}

func (p *Plane) countBind(ctx context.Context, cell string, resp mgmtapi.BindResponse, err error) {
	result := resp.Status
	if err != nil {
		result = ReasonOf(err)
		if result == "" {
			result = "error"
		}
		p.cfg.Log.DebugContext(ctx, "bind_refused", "cell", cell, "error", err.Error())
	} else if resp.Status != mgmtapi.StatusAlreadyBound {
		p.cfg.Log.InfoContext(ctx, "bind", "cell", cell, "result", result, "record_epoch", resp.Record.Epoch, "record_counter", resp.Record.Counter)
	}
	p.bindResults.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

// --- key checks ---

// KeyCheck compares the keys that the issuer publishes with the keys of the record. An error means
// the check could not run; a refusal is a result.
func (p *Plane) KeyCheck(ctx context.Context, cell string) (res CheckResult, err error) {
	defer func() {
		if err == nil {
			p.checkResults.Add(ctx, 1, metric.WithAttributes(attribute.String("result", string(res))))
		}
	}()
	if _, ok := p.intent[cell]; !ok {
		return "", refuse(mgmtapi.ReasonCellUnknown, "")
	}
	pre := p.snap.Load().st.Cells[cell]
	switch {
	case pre == nil:
		return CheckNotBound, nil
	case p.gapActive(pre, p.cfg.Now()):
		return CheckRateLimited, nil
	}
	keys, ferr := p.cachedKeys(ctx, cell)
	if ferr != nil {
		res = CheckIssuerUnavailable
		if ReasonOf(ferr) == mgmtapi.ReasonIssuerUntrusted {
			res = CheckIssuerUntrusted
		}
		return res, p.noteCheck(cell, res)
	}
	err = p.commit(func(t *txn) error {
		cs := t.st.Cells[cell]
		switch {
		case cs == nil:
			res = CheckNotBound
			return nil
		case p.gapActive(cs, t.now):
			res = CheckRateLimited
			return nil
		}
		var err error
		res, err = p.judge(t, cell, cs, keys)
		return err
	})
	if err != nil {
		return "", err
	}
	if res != CheckRateLimited && res != CheckNotBound {
		p.cfg.Log.InfoContext(ctx, "key_check", "cell", cell, "result", string(res))
	}
	return res, nil
}

func (p *Plane) judge(t *txn, cell string, cs *CellState, keys mgmtapi.ClusterKeys) (CheckResult, error) {
	settle := func(res CheckResult) (CheckResult, error) {
		cs.CheckedAt, cs.LastCheck = t.now, string(res)
		t.dirty = true
		return res, nil
	}
	if keys.Issuer != cs.Issuer {
		return settle(CheckIssuerUntrusted)
	}
	fresh := parseKeys(keys.JWKS)
	d := diffKeys(parseKeys(cs.JWKS), fresh)
	switch {
	case len(fresh) == 0 || d.common == 0 || d.added > maxNewKeys:
		return settle(CheckKeysUntrusted)
	case d.added == 0 && d.removed == 0:
		return settle(CheckUnchanged)
	}
	jwks, err := encodeKeys(fresh)
	if err != nil {
		return settle(CheckKeysUntrusted)
	}
	if err := t.revise(); err != nil {
		return "", err
	}
	cs.JWKS, cs.KeysUpdatedAt = jwks, t.now
	if _, err := settle(CheckKeysUpdated); err != nil {
		return "", err
	}
	return CheckKeysUpdated, t.signCell(cell)
}

// noteCheck records a check that learned nothing about the keys, so that status shows it. It does
// not start the update gap.
func (p *Plane) noteCheck(cell string, res CheckResult) error {
	return p.commit(func(t *txn) error {
		if cs := t.st.Cells[cell]; cs != nil && cs.LastCheck != string(res) {
			cs.LastCheck = string(res)
			t.dirty = true
		}
		return nil
	})
}

// RunChecks checks each bound cell whose last check is older than CheckEvery. It runs on a tick every
// minute until ctx ends.
func (p *Plane) RunChecks(ctx context.Context) error {
	var ticks <-chan time.Time
	if p.cfg.Ticks != nil {
		ticks = p.cfg.Ticks(time.Minute)
	} else {
		tk := time.NewTicker(time.Minute)
		defer tk.Stop()
		ticks = tk.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
		}
		st := p.snap.Load().st
		for _, name := range sortedKeys(st.Cells) {
			if p.cfg.Now().Sub(st.Cells[name].CheckedAt) < p.cfg.CheckEvery {
				continue
			}
			if _, err := p.KeyCheck(ctx, name); err != nil {
				p.cfg.Log.WarnContext(ctx, "key_check_failed", "cell", name, "error", err.Error())
			}
		}
	}
}

// PreviewKeys reads the keys of a cell without a cache and changes no state.
func (p *Plane) PreviewKeys(ctx context.Context, cell string) (mgmtapi.ClusterKeys, error) {
	if _, ok := p.intent[cell]; !ok {
		return mgmtapi.ClusterKeys{}, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	keys, err := p.cfg.Keys.Keys(ctx, cell)
	if err != nil {
		return mgmtapi.ClusterKeys{}, keySourceError(err)
	}
	return keys, nil
}

// --- rotation, restore, reads ---

// RotateKey makes a new signing key, writes it, and re-signs every record and the spec at the first
// revision of the next epoch. A failed save puts the old key file back.
func (p *Plane) RotateKey(ctx context.Context) (ed25519.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("make signing key: %w", err)
	}
	err = p.commit(func(t *txn) error {
		old := t.key
		if err := WriteKey(p.cfg.KeyPath, next); err != nil {
			return err
		}
		t.onFail = append(t.onFail, func() {
			if err := WriteKey(p.cfg.KeyPath, old); err != nil {
				p.cfg.Log.Error("signing_key_rollback_failed", "error", err.Error())
			}
		})
		t.key = next
		return p.resignAll(fingerprint(next.Public().(ed25519.PublicKey)))(t)
	})
	if err != nil {
		return nil, err
	}
	p.cfg.Log.Warn("signing_key_rotated", "epoch", p.snap.Load().st.Last.Epoch)
	return p.PublicKey(), nil
}

// Restore serves the stored revision with the given counter, and 0 serves the latest. While an older
// revision is served, every record change fails with restore_active.
func (p *Plane) Restore(counter uint64) error {
	return p.commit(func(t *txn) error {
		if counter == t.st.Last.Counter {
			counter = 0
		}
		if counter != 0 && !slices.ContainsFunc(t.st.History, func(h Signed) bool {
			return h.Revision.Epoch == t.st.Last.Epoch && h.Revision.Counter == counter
		}) {
			return fmt.Errorf("no stored revision with counter %d", counter)
		}
		if t.st.Served != counter {
			t.st.Served = counter
			t.dirty = true
		}
		return nil
	})
}

// CheckSeq returns conflict when seq is not the current state version.
func (p *Plane) CheckSeq(seq uint64) error {
	if cur := p.snapshotSeq(); cur != seq {
		return refuse(mgmtapi.ReasonConflict, fmt.Sprintf("state version is %d, not %d", cur, seq))
	}
	return nil
}

func (p *Plane) snapshotSeq() uint64 { return p.snap.Load().st.Seq }

// PublicKey returns the key that verifies the served specs and records.
func (p *Plane) PublicKey() ed25519.PublicKey { return slices.Clone(p.snap.Load().pub) }

// Spec returns the served bundle. The caller must not change it.
func (p *Plane) Spec() mgmtapi.SpecBundle {
	if s := p.snap.Load().st.served(); s != nil {
		return s.Bundle
	}
	return mgmtapi.SpecBundle{}
}

// Records returns the served record envelopes by cell name.
func (p *Plane) Records() map[string]json.RawMessage {
	return maps.Clone(p.Spec().Records)
}

func servedRevision(st *State) spec.Revision {
	if s := st.served(); s != nil {
		return s.Revision
	}
	return st.Last
}

// Report stores what envd reported. A report of the signed revision releases the next pending drop.
func (p *Plane) Report(r mgmtapi.StatusReport) {
	now := p.cfg.Now()
	st := p.snap.Load().st
	behind := r.Applied.Compare(st.Last) > 0
	p.rmu.Lock()
	if r.Applied != p.rep.applied || p.rep.appliedAt.IsZero() {
		p.rep.appliedAt = now
	}
	p.rep.applied, p.rep.lastReportAt, p.rep.storeError = r.Applied, now, r.StoreError
	p.rep.refusal = nil
	if r.LastRefusal != nil {
		cp := *r.LastRefusal
		p.rep.refusal = &cp
	}
	p.lagLocked(st, now)
	logBehind := behind && !p.rep.behindLogged
	p.rep.behindLogged = behind
	p.rmu.Unlock()
	if logBehind {
		p.cfg.Log.Error("state_behind_applied", "applied_epoch", r.Applied.Epoch, "applied_counter", r.Applied.Counter,
			"signed_epoch", st.Last.Epoch, "signed_counter", st.Last.Counter)
	}
	if len(st.PendingDrops) > 0 && r.Applied == st.Last {
		if err := p.dropNext(); err != nil && ReasonOf(err) != mgmtapi.ReasonRestoreActive {
			p.cfg.Log.Error("drop_failed", "error", err.Error())
		}
	}
}

func (p *Plane) lagLocked(st *State, now time.Time) {
	if p.rep.applied.Compare(servedRevision(st)) >= 0 {
		p.rep.lagSince = time.Time{}
	} else if p.rep.lagSince.IsZero() {
		p.rep.lagSince = now
	}
}

func (p *Plane) noteLag() {
	st := p.snap.Load().st
	now := p.cfg.Now()
	p.rmu.Lock()
	p.lagLocked(st, now)
	p.rmu.Unlock()
}

func (p *Plane) observeLag(_ context.Context, o metric.Int64Observer) error {
	served := servedRevision(p.snap.Load().st)
	p.rmu.Lock()
	applied := p.rep.applied
	p.rmu.Unlock()
	var lag int64
	switch {
	case applied.Compare(served) >= 0:
	case applied.Epoch == served.Epoch:
		lag = int64(served.Counter - applied.Counter)
	default:
		lag = int64(served.Counter)
	}
	o.Observe(lag)
	return nil
}

// Status returns the status from the current snapshot and the last report.
func (p *Plane) Status() Status {
	st := p.snap.Load().st
	p.rmu.Lock()
	rep := p.rep
	p.rmu.Unlock()
	s := Status{
		Env: p.cfg.Intent.Env, Signed: st.Last, Served: servedRevision(st), RestoreActive: st.Served != 0,
		Applied: rep.applied, AppliedAt: rep.appliedAt, LagSince: rep.lagSince, LastReportAt: rep.lastReportAt,
		LastRefusal: rep.refusal, StoreError: rep.storeError,
		PendingDrops:       append([]string{}, st.PendingDrops...),
		StateBehindApplied: rep.applied.Compare(st.Last) > 0,
		Cells:              []CellStatus{},
	}
	names := sortedKeys(p.intent)
	for name := range st.Cells {
		if _, ok := p.intent[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		cs := CellStatus{Name: name, Kids: []string{}}
		if c := st.Cells[name]; c != nil {
			cs.Bound, cs.Issuer, cs.Kids, cs.Record = true, c.Issuer, kidsOf(c.JWKS), c.Record
			cs.CheckedAt, cs.LastCheck = c.CheckedAt, c.LastCheck
		}
		s.Cells = append(s.Cells, cs)
	}
	return s
}
