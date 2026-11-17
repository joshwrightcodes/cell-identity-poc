package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
	// OnRecords is called with the served record envelopes and the signing public key after each
	// commit that changes a record, and once after NewPlane. A failed save never calls it.
	OnRecords func(records map[string]json.RawMessage, pub ed25519.PublicKey)

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
	rt  liveState

	cbmu sync.Mutex // serializes OnRecords calls
	// betweenLoads runs in notifyRecords after the snapshot load. Tests use it.
	betweenLoads func()
	ready        atomic.Bool
	bg           sync.WaitGroup // background hint checks

	bindResults, checkResults, reportItems, retryUnknownKID metric.Int64Counter
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
		if created {
			cfg.Log.Info("signing_key_created")
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
	p.reportItems, _ = cfg.Meter.Int64Counter("mgmtd.report.items")
	p.retryUnknownKID, _ = cfg.Meter.Int64Counter("mgmtd.report.retry_unknown_kid")
	p.rt.cells = map[string]*cellRuntime{}
	if _, err := cfg.Meter.Int64ObservableGauge("mgmtd.spec.revision.lag", metric.WithInt64Callback(p.observeLag)); err != nil {
		return nil, err
	}

	pub := key.Public().(ed25519.PublicKey)
	fp := fingerprint(pub)
	st, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if st == nil && !created && cfg.Key == nil {
		// A fresh state over an old key would sign revisions that the key signed before. A new key makes
		// the plugin start its marks again.
		if key, pub, fp, err = replaceKey(cfg); err != nil {
			return nil, err
		}
		p.key = key
		cfg.Log.Warn("signing_key_replaced", "reason", "no state exists for the key file")
	}
	switch {
	case st == nil:
		st = newState(fp)
		p.snap.Store(&snapshot{st: st, pub: pub})
		if err := p.commit(func(t *txn) error { return t.revise() }); err != nil {
			return nil, fmt.Errorf("sign the first spec: %w", err)
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

	if err := p.checkStaged(); err != nil {
		return nil, err
	}
	if err := p.commit(p.reconcile); err != nil {
		return nil, fmt.Errorf("apply the intent: %w", err)
	}
	p.noteLag()
	p.ready.Store(true)
	p.notifyRecords()
	return p, nil
}

// replaceKey writes a new signing key over the key file.
func replaceKey(cfg Config) (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("make signing key: %w", err)
	}
	if err := WriteKey(cfg.KeyPath, key); err != nil {
		return nil, nil, "", err
	}
	pub := key.Public().(ed25519.PublicKey)
	return key, pub, fingerprint(pub), nil
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

// RotateKey makes the staged signing key the signing key, or a new key when none is staged. It
// writes the key, and re-signs every record, the spec and every open operation at the first
// revision of the next epoch. A failed change puts the old key file back.
func (p *Plane) RotateKey(ctx context.Context) (ed25519.PublicKey, error) {
	return p.rotate(ctx, nil, rotateAuto)
}

// ErrNotStaged is the error of CommitStagedKey when no key is staged.
var ErrNotStaged = errors.New("not_staged")

// CommitStagedKey makes the staged key the signing key, and fails with ErrNotStaged, with no
// change, when no key is staged. The check and the rotation run in one locked step.
func (p *Plane) CommitStagedKey(ctx context.Context) (ed25519.PublicKey, error) {
	return p.rotate(ctx, nil, rotateCommit)
}

// RotateKeyEmergency makes a new signing key at once. A staged key lives on the same volume as the
// signing key, so a reason to rotate at once covers it too: it moves aside with a stamp and the
// stage is cleared.
func (p *Plane) RotateKeyEmergency(ctx context.Context) (ed25519.PublicKey, error) {
	return p.rotate(ctx, nil, rotateFresh)
}

// The ways that a rotation picks the next key.
const (
	rotateAuto   = iota // the staged key when one exists, else a new key
	rotateCommit        // the staged key, or ErrNotStaged
	rotateFresh         // a new key, and any staged key moves aside
)

// clearStage drops the staged key from the state in one save and then moves its file aside. It
// reports whether it changed the state.
func (p *Plane) clearStage(expect *uint64) (cleared bool, err error) {
	err = p.commit(func(t *txn) error {
		if err := t.expectSeq(expect); err != nil {
			return err
		}
		if t.st.StagedKeySHA256 == "" {
			return nil
		}
		t.st.StagedKeySHA256, t.dirty, cleared = "", true, true
		t.after = append(t.after, p.moveStagedAside)
		return nil
	})
	return cleared && err == nil, err
}

func (p *Plane) rotate(ctx context.Context, expect *uint64, mode int) (ed25519.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if mode == rotateFresh {
		// The stage is cleared in a save of its own, before the new key reaches the disk. A crash
		// between the key write and the save of the rotation then cannot leave a stage that the
		// emergency meant to discard.
		cleared, err := p.clearStage(expect)
		if err != nil {
			return nil, err
		}
		if cleared && expect != nil {
			// The clearing save raised the state version by one.
			next := *expect + 1
			expect = &next
		}
	}
	err := p.commit(func(t *txn) error {
		if err := t.expectSeq(expect); err != nil {
			return err
		}
		next, staged := p.stagedKey(t.st)
		if mode == rotateFresh {
			next, staged = nil, false
		}
		if mode == rotateCommit && !staged {
			return ErrNotStaged
		}
		if !staged {
			var err error
			if _, next, err = ed25519.GenerateKey(rand.Reader); err != nil {
				return fmt.Errorf("make signing key: %w", err)
			}
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
		if err := p.resignAll(fingerprint(next.Public().(ed25519.PublicKey)))(t); err != nil {
			return err
		}
		if staged {
			t.st.StagedKeySHA256 = ""
			t.after = append(t.after, func() {
				if err := os.Remove(p.nextKeyPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
					p.cfg.Log.Error("staged_key_remove_failed", "error", err.Error())
				}
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p.cfg.Log.Warn("signing_key_rotated", "epoch", p.snap.Load().st.Last.Epoch)
	return p.PublicKey(), nil
}

// moveStagedAside renames the staged key file to <name>.stale-<unix time>. An absent file is fine.
func (p *Plane) moveStagedAside() {
	dest := p.nextKeyPath() + ".stale-" + strconv.FormatInt(p.cfg.Now().Unix(), 10)
	if err := os.Rename(p.nextKeyPath(), dest); err != nil && !errors.Is(err, fs.ErrNotExist) {
		p.cfg.Log.Error("staged_key_move_failed", "error", err.Error())
		return
	}
	p.cfg.Log.Warn("staged_key_moved_aside", "moved_to", dest)
}

// nextKeyFile is the name of the staged signing key, next to the signing key file.
const nextKeyFile = "ed25519.next.key"

func (p *Plane) nextKeyPath() string { return filepath.Join(filepath.Dir(p.cfg.KeyPath), nextKeyFile) }

// stagedKey returns the staged key when the state names it and the file holds that key.
func (p *Plane) stagedKey(st *State) (ed25519.PrivateKey, bool) {
	if st.StagedKeySHA256 == "" {
		return nil, false
	}
	key, err := loadKey(p.nextKeyPath())
	if err != nil || fingerprint(key.Public().(ed25519.PublicKey)) != st.StagedKeySHA256 {
		return nil, false
	}
	return key, true
}

// StageKey writes the next signing key to ed25519.next.key and returns its public key. A second
// call returns the same key. RotateKey then makes it the signing key.
func (p *Plane) StageKey(ctx context.Context) (ed25519.PublicKey, error) {
	return p.stage(ctx, nil)
}

// StagedPublicKey returns the public key of the staged signing key, when the state names a staged
// key and its file holds that key.
func (p *Plane) StagedPublicKey() (ed25519.PublicKey, bool) {
	key, ok := p.stagedKey(p.snap.Load().st)
	if !ok {
		return nil, false
	}
	return slices.Clone(key.Public().(ed25519.PublicKey)), true
}

func (p *Plane) stage(ctx context.Context, expect *uint64) (ed25519.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var pub ed25519.PublicKey
	err := p.commit(func(t *txn) error {
		if err := t.expectSeq(expect); err != nil {
			return err
		}
		if key, ok := p.stagedKey(t.st); ok {
			pub = key.Public().(ed25519.PublicKey)
			return nil
		}
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("make signing key: %w", err)
		}
		if err := WriteKey(p.nextKeyPath(), key); err != nil {
			return err
		}
		t.onFail = append(t.onFail, func() { _ = os.Remove(p.nextKeyPath()) })
		pub = key.Public().(ed25519.PublicKey)
		t.st.StagedKeySHA256 = fingerprint(pub)
		t.dirty = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return slices.Clone(pub), nil
}

// checkStaged keeps the staged key file only while the state names it. Any other file moves aside,
// because it can be a key from a state that no longer exists. A name without a file is cleared.
func (p *Plane) checkStaged() error {
	st := p.snap.Load().st
	_, statErr := os.Stat(p.nextKeyPath())
	exists := statErr == nil
	_, valid := p.stagedKey(st)
	if valid && st.StagedKeySHA256 == fingerprint(p.snap.Load().pub) {
		// A rotation that crashed after it wrote the key file: the staged key is the signing key.
		valid = false
	}
	if exists && !valid {
		dest := p.nextKeyPath() + ".stale-" + strconv.FormatInt(p.cfg.Now().Unix(), 10)
		if err := os.Rename(p.nextKeyPath(), dest); err != nil {
			return fmt.Errorf("move the unnamed staged key aside: %w", err)
		}
		p.cfg.Log.Warn("staged_key_moved_aside", "moved_to", dest)
	}
	if st.StagedKeySHA256 != "" && !valid {
		return p.commit(func(t *txn) error {
			t.st.StagedKeySHA256 = ""
			t.dirty = true
			return nil
		})
	}
	return nil
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
			return fmt.Errorf("%w with counter %d", ErrRevisionUnknown, counter)
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
	return g.p.rotate(ctx, &g.seq, rotateAuto)
}

// CommitStagedKey is Plane.CommitStagedKey, guarded by the state version.
func (g SeqGuard) CommitStagedKey(ctx context.Context) (ed25519.PublicKey, error) {
	return g.p.rotate(ctx, &g.seq, rotateCommit)
}

// RotateKeyEmergency is Plane.RotateKeyEmergency, guarded by the state version.
func (g SeqGuard) RotateKeyEmergency(ctx context.Context) (ed25519.PublicKey, error) {
	return g.p.rotate(ctx, &g.seq, rotateFresh)
}

// StageKey is Plane.StageKey, guarded by the state version.
func (g SeqGuard) StageKey(ctx context.Context) (ed25519.PublicKey, error) {
	return g.p.stage(ctx, &g.seq)
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
