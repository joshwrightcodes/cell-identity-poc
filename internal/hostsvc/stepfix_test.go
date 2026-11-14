package hostsvc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

// goodDigest is the bootstrap digest that the fixture host computes.
const goodDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var fixTopo = &topology.Topology{
	NodeImage: "kindest/node:test@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
	Clusters: []topology.Cluster{
		{Name: "dev-cp", PodSubnet: "10.11.0.0/16", ServiceSubnet: "10.111.0.0/16", Issuer: "https://dev-cp.issuer.poc.internal", Components: []string{"envd"}},
		{Name: "dev-cell-1", PodSubnet: "10.20.0.0/16", ServiceSubnet: "10.120.0.0/16", Issuer: "https://dev-cell-1.issuer.poc.internal", Components: []string{"cell-identity"}},
		{Name: "dev-cell-2", PodSubnet: "10.21.0.0/16", ServiceSubnet: "10.121.0.0/16", Issuer: "https://dev-cell-2.issuer.poc.internal", Components: []string{"cell-identity"}},
		{Name: "dev-cell-3", PodSubnet: "10.22.0.0/16", ServiceSubnet: "10.122.0.0/16", Issuer: "https://dev-cell-3.issuer.poc.internal", Components: []string{"cell-identity"}},
	},
}

func discardLog() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// stepEnv is a host service with fake keys, a fake clock and a spec store in a temporary directory.
type stepEnv struct {
	t     *testing.T
	dir   string
	clock *fakeClock
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey

	mu        sync.Mutex
	keys      []ed25519.PublicKey
	digest    atomic.Value
	digests   atomic.Int32
	digestErr atomic.Bool

	spec *SpecStore
	ver  *StepVerifier
	rev  uint64
}

func newKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newStepEnv(t *testing.T) *stepEnv {
	t.Helper()
	e := &stepEnv{t: t, dir: t.TempDir(), clock: newFakeClock()}
	e.pub, e.priv = newKey(t)
	e.keys = []ed25519.PublicKey{e.pub}
	e.digest.Store(goodDigest)
	var err error
	if e.spec, err = OpenSpecStore(e.dir, e.getKeys, "dev"); err != nil {
		t.Fatal(err)
	}
	e.spec.SetLogger(discardLog())
	e.ver = &StepVerifier{Keys: e.getKeys, Env: "dev", Topo: fixTopo, Spec: e.spec, Now: e.clock.Now, Digest: func() (string, error) {
		e.digests.Add(1)
		if e.digestErr.Load() {
			return "", errors.New("git: index.lock exists")
		}
		return e.digest.Load().(string), nil
	}}
	return e
}

func (e *stepEnv) getKeys() []ed25519.PublicKey {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]ed25519.PublicKey(nil), e.keys...)
}

func (e *stepEnv) setKeys(k ...ed25519.PublicKey) {
	e.mu.Lock()
	e.keys = k
	e.mu.Unlock()
}

// newStep signs a step for cell under the fixture key. mod may change the step first.
func (e *stepEnv) newStep(cell string, mod func(*step.Step)) (step.Step, []byte) {
	return e.newStepKey(e.priv, cell, mod)
}

func (e *stepEnv) newStepKey(priv ed25519.PrivateKey, cell string, mod func(*step.Step)) (step.Step, []byte) {
	e.t.Helper()
	cl, _ := fixTopo.Cluster(cell)
	s := step.Step{
		ID: step.NewID(), Env: "dev", Cell: cell, Kind: step.KindCellCreate, Version: 1, KeyEpoch: 1,
		IssuedAt: e.clock.Now(), ExpiresAt: e.clock.Now().Add(step.DefaultTTL),
		Cluster:         step.ClusterRef{PodSubnet: cl.PodSubnet, ServiceSubnet: cl.ServiceSubnet, Issuer: cl.Issuer},
		BootstrapSHA256: goodDigest,
	}
	if mod != nil {
		mod(&s)
	}
	env, err := step.Sign(s, priv)
	if err != nil {
		e.t.Fatal(err)
	}
	return s, env
}

func payloadDigest(t testing.TB, envelope []byte) string {
	t.Helper()
	p, err := envelopePayload(string(envelope))
	if err != nil {
		t.Fatal(err)
	}
	return step.PayloadSHA256(p)
}

// indexOf returns the spec index entry of a signed step.
func (e *stepEnv) indexOf(s step.Step, envelope []byte) spec.StepEntry {
	return spec.StepEntry{Name: s.Cell, StepID: s.ID, StepSHA256: payloadDigest(e.t, envelope)}
}

// putSpec signs a spec at the next revision that indexes the given steps (sorted by cell by the
// caller) and records. cells maps a cell name to its record counter; 0 means no record.
func (e *stepEnv) putSpec(steps []spec.StepEntry, cells map[string]uint64) spec.Spec {
	e.t.Helper()
	return e.putSpecKey(e.priv, steps, cells)
}

func (e *stepEnv) putSpecKey(priv ed25519.PrivateKey, steps []spec.StepEntry, cells map[string]uint64) spec.Spec {
	e.t.Helper()
	e.rev++
	sp := spec.Spec{Env: "dev", Revision: spec.Revision{Epoch: 1, Counter: e.rev}, Steps: steps}
	for _, name := range []string{"dev-cell-1", "dev-cell-2", "dev-cell-3"} {
		if c, ok := cells[name]; ok {
			sp.Cells = append(sp.Cells, spec.Entry{Name: name, Revision: spec.Revision{Epoch: 1, Counter: c}, RecordSHA256: strings.Repeat("0", 64)})
		}
	}
	for _, c := range cells {
		if c > e.rev {
			e.rev = c
			sp.Revision.Counter = c
		}
	}
	env, err := spec.Sign(sp, priv)
	if err != nil {
		e.t.Fatal(err)
	}
	got, err := e.spec.Put(env)
	if err != nil {
		e.t.Fatalf("put spec: %v", err)
	}
	return got
}

// indexed signs a step and a spec that indexes it.
func (e *stepEnv) indexed(cell string, mod func(*step.Step)) (step.Step, []byte) {
	e.t.Helper()
	s, env := e.newStep(cell, mod)
	e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
	return s, env
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func waitUntil(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type syncBuf struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func jsonLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(w, nil)) }
