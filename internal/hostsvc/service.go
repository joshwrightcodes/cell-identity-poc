package hostsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
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
	Marker   Marker

	// lookups holds one token for each Facts call whose runtime calls have not returned.
	lookups chan struct{}
}

// MaxFactsInFlight is the number of Facts calls that may run their runtime calls at once.
const MaxFactsInFlight = 2

// ErrLookupBusy means that MaxFactsInFlight lookups are still running, so Facts did not start one.
var ErrLookupBusy = errors.New("too many cluster lookups in flight")

// New returns a Service that uses the real prober and the Docker reserved prefixes.
func New(rt Runtime, t *topology.Topology) *Service {
	return &Service{rt: rt, topo: t, Prober: HTTPProber{}, Reserved: DockerReserved, Docker: RunDocker, Marker: KubeMarker{}, lookups: make(chan struct{}, MaxFactsInFlight)}
}

func (s *Service) lookup(name string) (topology.Cluster, error) {
	c, ok := s.topo.Cluster(name)
	if !ok {
		return topology.Cluster{}, fmt.Errorf("cluster %q is not in the topology", name)
	}
	return c, nil
}

// existsCtx is exists, but returns at once when ctx ends. The kind library takes no context, so an
// abandoned call finishes in the background.
func (s *Service) existsCtx(ctx context.Context, name string) (bool, error) {
	type result struct {
		found bool
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		found, err := s.exists(name)
		ch <- result{found, err}
	}()
	select {
	case r := <-ch:
		return r.found, r.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (s *Service) exists(name string) (bool, error) {
	names, err := s.rt.List()
	if err != nil {
		return false, fmt.Errorf("list clusters: %w", err)
	}
	return slices.Contains(names, name), nil
}

// ErrCellNeedsStep means a cell cluster is absent. Only a signed step creates a cell, through
// the Create method that the step actor runs.
var ErrCellNeedsStep = errors.New("cell does not exist and only a signed step creates it")

// Marker is the ConfigMap kube-system/poc-provisioned that Create writes into a cluster that it
// made, so that a retry can tell a finished cluster from a half-built one.
type Marker interface {
	// Has reports whether the marker exists. A cluster that does not answer is an error.
	Has(ctx context.Context, kubeconfig string) (bool, error)
	// Write creates the marker with the label poc.internal/made-by=hostsvc.
	Write(ctx context.Context, kubeconfig string) error
}

// Up creates the cluster if it is absent and returns its facts. A cell that is absent is not
// created: the error wraps ErrCellNeedsStep. It refuses to touch an existing cluster whose spec
// differs from the topology.
func (s *Service) Up(ctx context.Context, name string) (Facts, error) {
	c, err := s.lookup(name)
	if err != nil {
		return Facts{}, err
	}
	found, err := s.existsCtx(ctx, name)
	if err != nil {
		return Facts{}, err
	}
	if !found && IsCell(c) {
		return Facts{}, fmt.Errorf("%w: %s", ErrCellNeedsStep, name)
	}
	return s.bringUp(ctx, c, found)
}

// UpAll runs Up for every cluster of the topology. An absent cell is skipped with a cell_needs_step
// log line, and it is not an error.
func (s *Service) UpAll(ctx context.Context) error {
	for _, c := range s.topo.Clusters {
		if _, err := s.Up(ctx, c.Name); err != nil {
			if errors.Is(err, ErrCellNeedsStep) {
				slog.Warn("cell_needs_step", "cluster", c.Name)
				continue
			}
			return err
		}
	}
	return nil
}

// Create makes the cluster of a cell and writes the marker ConfigMap after its facts are read. With
// retryOfCreate, an existing cluster without the marker is a half-built cluster of an earlier
// run, and Create deletes it first. Without it, an existing cluster is kept and checked as Up does.
func (s *Service) Create(ctx context.Context, name string, retryOfCreate bool) (Facts, error) {
	c, err := s.lookup(name)
	if err != nil {
		return Facts{}, err
	}
	found, err := s.existsCtx(ctx, name)
	if err != nil {
		return Facts{}, err
	}
	if found && retryOfCreate {
		kc, err := s.rt.Kubeconfig(name)
		if err != nil {
			return Facts{}, fmt.Errorf("read kubeconfig of %s: %w", name, err)
		}
		has, err := s.Marker.Has(ctx, kc)
		if err != nil {
			slog.Warn("marker unreadable, treating the cluster as half built", "cluster", name, "error", err.Error())
		}
		if !has {
			slog.Warn("deleting half-built cluster", "cluster", name)
			if err := s.rt.Delete(name); err != nil {
				return Facts{}, fmt.Errorf("delete half-built cluster %s: %w", name, err)
			}
			found = false
		}
	}
	f, err := s.bringUp(ctx, c, found)
	if err != nil || found {
		return f, err
	}
	kc, err := s.rt.Kubeconfig(name)
	if err != nil {
		return Facts{}, fmt.Errorf("read kubeconfig of %s: %w", name, err)
	}
	if err := s.Marker.Write(ctx, kc); err != nil {
		return Facts{}, fmt.Errorf("write marker in %s: %w", name, err)
	}
	return f, nil
}

func (s *Service) bringUp(ctx context.Context, c topology.Cluster, found bool) (Facts, error) {
	name := c.Name
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
func (s *Service) Down(ctx context.Context, name string) error {
	if _, err := s.lookup(name); err != nil {
		return err
	}
	found, err := s.existsCtx(ctx, name)
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

// Facts describes a running topology cluster. It returns when the lookup is done or ctx ends. The
// runtime calls (the kind library runs docker without a context) cannot be cancelled, so the lookup
// keeps its token until they really return. When MaxFactsInFlight lookups hold a token, Facts fails
// at once with ErrLookupBusy, and a hung docker cannot pile up processes.
func (s *Service) Facts(ctx context.Context, name string) (Facts, error) {
	if _, err := s.lookup(name); err != nil {
		return Facts{}, err
	}
	select {
	case s.lookups <- struct{}{}:
	default:
		return Facts{}, ErrLookupBusy
	}
	type result struct {
		f   Facts
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-s.lookups }()
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("lookup of %s panicked: %v", name, r)}
			}
		}()
		f, err := s.facts(ctx, name)
		done <- result{f, err}
	}()
	select {
	case r := <-done:
		return r.f, r.err
	case <-ctx.Done():
		return Facts{}, ctx.Err()
	}
}

func (s *Service) facts(ctx context.Context, name string) (Facts, error) {
	found, err := s.exists(name)
	if err != nil {
		return Facts{}, err
	}
	if !found {
		return Facts{}, fmt.Errorf("cluster %q does not exist", name)
	}
	if err := ctx.Err(); err != nil {
		return Facts{}, err
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

// Marker object that Create writes into a cluster that it made.
const (
	MarkerNamespace = "kube-system"
	MarkerName      = "poc-provisioned"
)

// KubeMarker is the Marker that talks to the cluster through its kubeconfig. A test sets Client to
// a fake clientset.
type KubeMarker struct {
	Client func(kubeconfig string) (kubernetes.Interface, error)
}

func (m KubeMarker) client(kubeconfig string) (kubernetes.Interface, error) {
	if m.Client != nil {
		return m.Client(kubeconfig)
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// Has reports whether the marker ConfigMap exists.
func (m KubeMarker) Has(ctx context.Context, kubeconfig string) (bool, error) {
	c, err := m.client(kubeconfig)
	if err != nil {
		return false, err
	}
	_, err = c.CoreV1().ConfigMaps(MarkerNamespace).Get(ctx, MarkerName, metav1.GetOptions{})
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	}
	return false, err
}

// Write creates the marker ConfigMap with the label poc.internal/made-by=hostsvc.
func (m KubeMarker) Write(ctx context.Context, kubeconfig string) error {
	c, err := m.client(kubeconfig)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: MarkerName, Namespace: MarkerNamespace, Labels: map[string]string{"poc.internal/made-by": "hostsvc"},
	}}
	_, err = c.CoreV1().ConfigMaps(MarkerNamespace).Create(ctx, cm, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}
