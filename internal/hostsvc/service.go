package hostsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

// ErrSpecMismatch means a cluster with the requested name exists but differs from the topology.
var ErrSpecMismatch = errors.New("cluster exists with a different spec")

// Facts describes one running cluster.
type Facts struct {
	Name          string          `json:"name"`
	Issuer        string          `json:"issuer"`
	NodeName      string          `json:"nodeName"`
	NodeIP        string          `json:"nodeIP"`
	PodSubnet     string          `json:"podSubnet"`
	ServiceSubnet string          `json:"serviceSubnet"`
	APIServer     string          `json:"apiServer"`
	JWKS          json.RawMessage `json:"jwks"`
}

// Runtime is the container runtime that hosts the clusters.
type Runtime interface {
	List() ([]string, error)
	Create(cfg *v1alpha4.Cluster) error
	Delete(name string) error
	Kubeconfig(name string) (string, error)
	NodeIP(name string) (string, error)
}

// Observed is what a running cluster reports about itself.
type Observed struct {
	PodSubnet     string
	ServiceSubnet string
	Issuer        string
	APIServer     string
	JWKS          json.RawMessage
}

// Prober reads the observed state of a cluster through its kubeconfig.
type Prober interface {
	Probe(ctx context.Context, kubeconfig string) (Observed, error)
}

// ReservedFunc returns the prefixes that no cluster subnet may overlap.
type ReservedFunc func(ctx context.Context) ([]netip.Prefix, error)

// Service creates and describes the clusters of a topology.
type Service struct {
	rt       Runtime
	topo     *topology.Topology
	Prober   Prober
	Reserved ReservedFunc
	Docker   DockerFunc
}

// New returns a Service that uses the real prober and the Docker reserved prefixes.
func New(rt Runtime, t *topology.Topology) *Service {
	return &Service{rt: rt, topo: t, Prober: HTTPProber{}, Reserved: DockerReserved, Docker: RunDocker}
}

func (s *Service) lookup(name string) (topology.Cluster, error) {
	c, ok := s.topo.Cluster(name)
	if !ok {
		return topology.Cluster{}, fmt.Errorf("cluster %q is not in the topology", name)
	}
	return c, nil
}

func (s *Service) exists(name string) (bool, error) {
	names, err := s.rt.List()
	if err != nil {
		return false, fmt.Errorf("list clusters: %w", err)
	}
	return slices.Contains(names, name), nil
}

// Up creates the cluster if it is absent and returns its facts.
// It refuses to touch an existing cluster whose spec differs from the topology.
func (s *Service) Up(ctx context.Context, name string) (Facts, error) {
	c, err := s.lookup(name)
	if err != nil {
		return Facts{}, err
	}
	reserved, err := s.Reserved(ctx)
	if err != nil {
		return Facts{}, fmt.Errorf("read reserved prefixes: %w", err)
	}
	if err := s.topo.Validate(reserved); err != nil {
		return Facts{}, fmt.Errorf("validate topology: %w", err)
	}
	if err := s.EnsureRegistry(ctx); err != nil {
		return Facts{}, err
	}
	found, err := s.exists(name)
	if err != nil {
		return Facts{}, err
	}
	if found {
		f, err := s.Facts(ctx, name)
		if err != nil {
			return Facts{}, err
		}
		if f.PodSubnet != c.PodSubnet || f.ServiceSubnet != c.ServiceSubnet || f.Issuer != c.Issuer {
			return Facts{}, fmt.Errorf("%w: %s has pod subnet %s, service subnet %s and issuer %s",
				ErrSpecMismatch, name, f.PodSubnet, f.ServiceSubnet, f.Issuer)
		}
		if err := s.EnsureRegistry(ctx); err != nil {
			return Facts{}, err
		}
		if err := s.configureNode(ctx, f.NodeName); err != nil {
			return Facts{}, err
		}
		slog.Info("cluster already matches the topology", "cluster", name)
		return f, nil
	}
	slog.Info("creating cluster", "cluster", name)
	if err := s.rt.Create(KindConfig(c, s.topo.NodeImage)); err != nil {
		return Facts{}, fmt.Errorf("create cluster %s: %w", name, err)
	}
	if err := s.EnsureRegistry(ctx); err != nil {
		return Facts{}, err
	}
	if err := s.configureNode(ctx, name+"-control-plane"); err != nil {
		return Facts{}, err
	}
	return s.Facts(ctx, name)
}

// Down deletes the cluster. An absent cluster is not an error.
func (s *Service) Down(_ context.Context, name string) error {
	if _, err := s.lookup(name); err != nil {
		return err
	}
	found, err := s.exists(name)
	if err != nil {
		return err
	}
	if !found {
		slog.Info("cluster already absent", "cluster", name)
		return nil
	}
	slog.Info("deleting cluster", "cluster", name)
	if err := s.rt.Delete(name); err != nil {
		return fmt.Errorf("delete cluster %s: %w", name, err)
	}
	return nil
}

// Facts describes a running topology cluster.
func (s *Service) Facts(ctx context.Context, name string) (Facts, error) {
	if _, err := s.lookup(name); err != nil {
		return Facts{}, err
	}
	found, err := s.exists(name)
	if err != nil {
		return Facts{}, err
	}
	if !found {
		return Facts{}, fmt.Errorf("cluster %q does not exist", name)
	}
	kc, err := s.rt.Kubeconfig(name)
	if err != nil {
		return Facts{}, fmt.Errorf("read kubeconfig of %s: %w", name, err)
	}
	obs, err := s.Prober.Probe(ctx, kc)
	if err != nil {
		return Facts{}, fmt.Errorf("probe cluster %s: %w", name, err)
	}
	ip, err := s.rt.NodeIP(name)
	if err != nil {
		return Facts{}, fmt.Errorf("read node address of %s: %w", name, err)
	}
	return Facts{
		Name:          name,
		Issuer:        obs.Issuer,
		NodeName:      name + "-control-plane",
		NodeIP:        ip,
		PodSubnet:     obs.PodSubnet,
		ServiceSubnet: obs.ServiceSubnet,
		APIServer:     obs.APIServer,
		JWKS:          obs.JWKS,
	}, nil
}
