package hostsvc

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

// CellComponent is the component set that marks a topology cluster as a cell.
const CellComponent = "cell-identity"

// IsCell reports whether c is a cell: a cluster that only a signed step may create.
func IsCell(c topology.Cluster) bool { return slices.Contains(c.Components, CellComponent) }

const (
	// indexGrace is how long after issuedAt a step may wait for the spec that indexes it.
	indexGrace = 2 * time.Minute
	// digestCacheTTL is how long a cached bootstrap digest stays valid.
	digestCacheTTL = 10 * time.Second
)

// StepVerifier decides whether the host service may run a step. Check runs the rules in a fixed
// order, so the cheap ones come first and the digest runs only for a step that is signed and
// indexed.
type StepVerifier struct {
	Keys   func() []ed25519.PublicKey
	Env    string
	Topo   *topology.Topology
	Spec   *SpecStore
	Digest func() (string, error)
	Now    func() time.Time

	mu       sync.Mutex
	digest   string
	digestAt time.Time
}

// Checked is a step that passed Verify, with the digest of its signed payload.
type Checked struct {
	Step      step.Step
	PayloadSH string
}

func (v *StepVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func refuse(detail string) error { return &step.Error{Detail: detail} }

// Check verifies envelope. The order is: signature and shape, environment and clock, cell in the
// topology and a cell, cluster object, spec index, bootstrap digest. With cachedDigest the digest
// runs at most once in 10 s. The error is a *step.Error, or another error when the digest could
// not be computed.
func (v *StepVerifier) Check(envelope []byte, cachedDigest bool) (step.Step, error) {
	c, err := v.CheckFull(envelope, cachedDigest)
	return c.Step, err
}

// CheckFull is Check, and it returns the payload digest. The step is valid whenever it is not zero,
// also when a later rule refused it.
func (v *StepVerifier) CheckFull(envelope []byte, cachedDigest bool) (Checked, error) {
	s, payload, err := step.Verify(envelope, v.Keys())
	if err != nil {
		return Checked{}, refuse(step.DetailOf(err))
	}
	c := Checked{Step: s, PayloadSH: step.PayloadSHA256(payload)}
	if err := v.checkBody(s, c.PayloadSH); err != nil {
		return c, err
	}
	d, err := v.bootstrapDigest(cachedDigest)
	if err != nil {
		return c, fmt.Errorf("bootstrap digest: %w", err)
	}
	if d != s.BootstrapSHA256 {
		return c, refuse(step.DetailBootstrapMismatch)
	}
	return c, nil
}

func (v *StepVerifier) checkBody(s step.Step, payloadSHA string) error {
	if err := step.Check(s, v.Env, v.now()); err != nil {
		return err
	}
	cl, ok := v.Topo.Cluster(s.Cell)
	if !ok || !IsCell(cl) {
		return refuse(step.DetailCellUnknown)
	}
	if s.Cluster.PodSubnet != cl.PodSubnet || s.Cluster.ServiceSubnet != cl.ServiceSubnet || s.Cluster.Issuer != cl.Issuer {
		return refuse(step.DetailClusterMismatch)
	}
	return v.checkIndex(s, payloadSHA)
}

func (v *StepVerifier) checkIndex(s step.Step, payloadSHA string) error {
	switch v.Spec.Index(s.Cell, s.ID, payloadSHA) {
	case IndexMatch:
		return nil
	case IndexDropped:
		return refuse(step.DetailStepUnindexed)
	}
	if v.now().Before(s.IssuedAt.Add(indexGrace)) {
		return refuse(step.DetailSpecBehind)
	}
	return refuse(step.DetailStepUnindexed)
}

func (v *StepVerifier) bootstrapDigest(cached bool) (string, error) {
	if v.Digest == nil {
		return "", errors.New("no digest function")
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if cached && v.digest != "" && now.Sub(v.digestAt) < digestCacheTTL && !now.Before(v.digestAt) {
		return v.digest, nil
	}
	d, err := v.Digest()
	if err != nil {
		v.digest = ""
		return "", err
	}
	v.digest, v.digestAt = d, now
	return d, nil
}
