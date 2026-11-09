// Package cellproxy carries streams between the planes over SPIFFE mTLS. The client side takes
// plaintext TCP and dials one exact management plane ID. The server side ends TLS 1.3, checks an
// anchored ID pattern and the cell registry, and hands each connection to a backend.
package cellproxy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	// PlaneCell is the plane of a workload in a cell.
	PlaneCell = "cell"
	// PlaneEnvironment is the plane of a workload in the control plane of an environment.
	PlaneEnvironment = "environment"

	envTrustDomainSuffix = ".env.poc.internal"
	// maxCellName keeps the agent name <env>-<cell> within one 63-character label.
	maxCellName = 59
)

var (
	dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// reservedCells are cluster names that are never a cell. <env>-cp is reserved too.
	reservedCells = []string{"cp", "management", "rogue"}
)

// Source is the verified origin of a connection.
type Source struct {
	Env, Cluster, Plane, Cell, Role string
}

// ParseSource accepts only spiffe://<env>.env.poc.internal/cell/<cell>/<role> and
// spiffe://<env>.env.poc.internal/cp/<role>. Each segment is a DNS label.
func ParseSource(id spiffeid.ID) (Source, error) {
	td := id.TrustDomain().Name()
	env, ok := strings.CutSuffix(td, envTrustDomainSuffix)
	if !ok || !dnsLabel.MatchString(env) {
		return Source{}, fmt.Errorf("trust domain %q is not <env>%s", td, envTrustDomainSuffix)
	}
	segs := strings.Split(strings.TrimPrefix(id.Path(), "/"), "/")
	for _, s := range segs {
		if !dnsLabel.MatchString(s) {
			return Source{}, fmt.Errorf("path segment %q is not a DNS label", s)
		}
	}
	switch {
	case len(segs) == 3 && segs[0] == "cell":
		name := segs[1]
		if err := checkCellName(name, env); err != nil {
			return Source{}, err
		}
		return Source{Env: env, Cluster: name, Plane: PlaneCell, Cell: name, Role: segs[2]}, nil
	case len(segs) == 2 && segs[0] == "cp":
		return Source{Env: env, Cluster: env + "-cp", Plane: PlaneEnvironment, Role: segs[1]}, nil
	}
	return Source{}, errors.New("path is neither /cell/<cell>/<role> nor /cp/<role>")
}

// checkCellName requires that env and name are DNS labels, that name has at most 59 characters,
// and that name is not reserved.
func checkCellName(name, env string) error {
	switch {
	case !dnsLabel.MatchString(env):
		return fmt.Errorf("environment %q is not a DNS label", env)
	case !dnsLabel.MatchString(name):
		return fmt.Errorf("cell name %q is not a DNS label", name)
	case len(name) > maxCellName:
		return fmt.Errorf("cell name has more than %d characters", maxCellName)
	case slices.Contains(reservedCells, name) || name == env+"-cp":
		return fmt.Errorf("cell name %q is reserved", name)
	}
	return nil
}

// AgentName is the name of the Argo CD agent of a cell source, <env>-<cell>.
func (s Source) AgentName() string { return s.Env + "-" + s.Cell }
