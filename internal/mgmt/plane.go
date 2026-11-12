package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// maxBundleBytes keeps the records of one spec bundle under the body limit of envd. A variable so
// that a test can lower it.
var maxBundleBytes = 900 << 10

// maxRecordBytes keeps each signed record under the record limit of envd (64 KiB). A variable so
// that a test can lower it.
var maxRecordBytes = 48 << 10

// KeySource returns the issuer and public keys of a cluster. Task 4's key client implements it.
type KeySource interface {
	Keys(ctx context.Context, cluster string) (mgmtapi.ClusterKeys, error)
}

// Config configures a Plane. Zero durations take the defaults: NonceTTL 120 s, CheckEvery 15 min,
// KeyUpdateGap 60 s, KeyCacheTTL 60 s, NonceKeyEvery 24 h and HistoryLen 50.
type Config struct {
	Intent  Intent
	KeyPath string
	// Key is the signing key. When nil, NewPlane loads or creates the key at KeyPath.
	Key   ed25519.PrivateKey
	Store Store
	Keys  KeySource
	Now   func() time.Time
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

type snapshot struct {
	st  *State
	pub ed25519.PublicKey
}

// Plane is the management core. One mutex serializes every change. A change fetches keys and checks
// the token before it takes the mutex, then re-reads the current state, applies, signs, saves and
// swaps an immutable snapshot that readers load without a lock.
type Plane struct {
	cfg    Config
	intent map[string]IntentCell
	nonces *Nonces
	cache  keyCache
	logs   *lograte.Limiter

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
	key, created := cfg.Key, false
	if key == nil {
		var err error
		if key, created, err = LoadOrCreateKey(cfg.KeyPath); err != nil {
			return nil, err
		}
	} else if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key has the wrong size")
	}
	nonces, err := NewNonces(cfg.Now, cfg.NonceTTL)
	if err != nil {
		return nil, err
	}
	p := &Plane{cfg: cfg, key: key, logs: lograte.New(logWindow, 256, cfg.Now), nonces: nonces.WithKeyEvery(cfg.NonceKeyEvery), intent: map[string]IntentCell{}}
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
		if err := p.commit(p.resignAll(fp)); err != nil {
			return nil, fmt.Errorf("re-sign after a key change: %w", err)
		}
		cfg.Log.Warn("signing_key_changed", "epoch", p.snap.Load().st.Last.Epoch)
	default:
		if err := p.checkStored(st, pub); err != nil {
			return nil, err
		}
		p.snap.Store(&snapshot{st: st, pub: pub})
	}

	if err := p.commit(p.reconcile); err != nil {
		return nil, fmt.Errorf("apply the intent: %w", err)
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

// RotateKey makes a new signing key, writes it, and re-signs every record and the spec at the first
// revision of the next epoch. A failed change puts the old key file back.
func (p *Plane) RotateKey(ctx context.Context) (ed25519.PublicKey, error) { return p.rotate(ctx, nil) }

func (p *Plane) rotate(ctx context.Context, expect *uint64) (ed25519.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("make signing key: %w", err)
	}
	err = p.commit(func(t *txn) error {
		if err := t.expectSeq(expect); err != nil {
			return err
		}
		old := t.key
		t.onFail = append(t.onFail, func() {
			if err := WriteKey(p.cfg.KeyPath, old); err != nil {
				p.cfg.Log.Error("signing_key_rollback_failed", "error", err.Error())
			}
		})
		if err := WriteKey(p.cfg.KeyPath, next); err != nil {
			return err
		}
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
func (p *Plane) Restore(counter uint64) error { return p.restore(counter, nil) }

func (p *Plane) restore(counter uint64, expect *uint64) error {
	return p.commit(func(t *txn) error {
		if err := t.expectSeq(expect); err != nil {
			return err
		}
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

// SeqGuard runs a command only while the state version is the one that the operator saw. The check
// runs inside the commit under the mutex, so no change can land between the check and the command.
type SeqGuard struct {
	p   *Plane
	seq uint64
}

// IfSeq returns a guard for the state version seq. A stale version fails with conflict.
func (p *Plane) IfSeq(seq uint64) SeqGuard { return SeqGuard{p: p, seq: seq} }

// Restore is Plane.Restore, guarded by the state version.
func (g SeqGuard) Restore(counter uint64) error { return g.p.restore(counter, &g.seq) }

// RotateKey is Plane.RotateKey, guarded by the state version.
func (g SeqGuard) RotateKey(ctx context.Context) (ed25519.PublicKey, error) {
	return g.p.rotate(ctx, &g.seq)
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

// Spec returns a copy of the served bundle.
func (p *Plane) Spec() mgmtapi.SpecBundle {
	if s := p.snap.Load().st.served(); s != nil {
		return mgmtapi.SpecBundle{Spec: slices.Clone(s.Bundle.Spec), Records: maps.Clone(s.Bundle.Records)}
	}
	return mgmtapi.SpecBundle{}
}

// Records returns the served record envelopes by cell name.
func (p *Plane) Records() map[string]json.RawMessage {
	return maps.Clone(p.Spec().Records)
}
