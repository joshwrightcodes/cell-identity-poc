package hostsvc

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

type fakeRuntime struct {
	clusters map[string]bool
	created  []*v1alpha4.Cluster
	deleted  []string
}

func (f *fakeRuntime) List() ([]string, error) {
	var out []string
	for n := range f.clusters {
		out = append(out, n)
	}
	return out, nil
}

func (f *fakeRuntime) Create(cfg *v1alpha4.Cluster) error {
	f.created = append(f.created, cfg)
	f.clusters[cfg.Name] = true
	return nil
}

func (f *fakeRuntime) Delete(name string) error {
	f.deleted = append(f.deleted, name)
	delete(f.clusters, name)
	return nil
}

func (f *fakeRuntime) Kubeconfig(string) (string, error) { return "kubeconfig", nil }
func (f *fakeRuntime) NodeIP(string) (string, error)     { return "172.18.0.5", nil }

type fakeProber struct{ obs Observed }

func (f fakeProber) Probe(context.Context, string) (Observed, error) { return f.obs, nil }

var testCluster = topology.Cluster{
	Name:          "rogue",
	PodSubnet:     "10.30.0.0/16",
	ServiceSubnet: "10.130.0.0/16",
	Issuer:        "https://rogue.issuer.poc.internal",
}

func newTestService(rt *fakeRuntime, obs Observed) *Service {
	topo := &topology.Topology{NodeImage: "kindest/node:test", Clusters: []topology.Cluster{testCluster}}
	s := New(rt, topo)
	s.Prober = fakeProber{obs: obs}
	s.Reserved = func(context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.5.0/24")}, nil
	}
	return s
}

func matchingObs() Observed {
	return Observed{
		PodSubnet:     testCluster.PodSubnet,
		ServiceSubnet: testCluster.ServiceSubnet,
		Issuer:        testCluster.Issuer,
		APIServer:     "https://127.0.0.1:40000",
		JWKS:          json.RawMessage(`{"keys":[{"kid":"k"}]}`),
	}
}

func TestKindConfigSetsSubnetsIssuerAndImage(t *testing.T) {
	cfg := KindConfig(testCluster, "kindest/node:test")
	if cfg.Name != "rogue" {
		t.Errorf("name = %q", cfg.Name)
	}
	if cfg.Networking.PodSubnet != "10.30.0.0/16" || cfg.Networking.ServiceSubnet != "10.130.0.0/16" {
		t.Errorf("networking = %+v", cfg.Networking)
	}
	if len(cfg.Nodes) != 1 || cfg.Nodes[0].Image != "kindest/node:test" {
		t.Errorf("nodes = %+v", cfg.Nodes)
	}
	if len(cfg.KubeadmConfigPatches) != 1 {
		t.Fatalf("patches = %d", len(cfg.KubeadmConfigPatches))
	}
	var patch struct {
		APIServer struct {
			ExtraArgs []struct{ Name, Value string } `json:"extraArgs"`
		} `json:"apiServer"`
	}
	if err := yaml.Unmarshal([]byte(cfg.KubeadmConfigPatches[0]), &patch); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range patch.APIServer.ExtraArgs {
		got[a.Name] = a.Value
	}
	want := map[string]string{
		"service-account-issuer":                  "https://rogue.issuer.poc.internal",
		"service-account-max-token-expiration":    "1h",
		"service-account-extend-token-expiration": "false",
	}
	if len(got) != len(want) {
		t.Fatalf("args = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("arg %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestUpCreatesAbsentCluster(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s := newTestService(rt, matchingObs())
	f, err := s.Up(context.Background(), "rogue")
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.created) != 1 || rt.created[0].Name != "rogue" {
		t.Fatalf("created = %v", rt.created)
	}
	if f.NodeName != "rogue-control-plane" || f.NodeIP != "172.18.0.5" || f.Issuer != testCluster.Issuer {
		t.Errorf("facts = %+v", f)
	}
}

func TestUpIsIdempotent(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s := newTestService(rt, matchingObs())
	for i := 0; i < 2; i++ {
		if _, err := s.Up(context.Background(), "rogue"); err != nil {
			t.Fatal(err)
		}
	}
	if len(rt.created) != 1 {
		t.Fatalf("Create called %d times", len(rt.created))
	}
}

func TestUpRefusesSpecMismatch(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{"rogue": true}}
	obs := matchingObs()
	obs.PodSubnet = "10.244.0.0/16"
	s := newTestService(rt, obs)
	_, err := s.Up(context.Background(), "rogue")
	if !errors.Is(err, ErrSpecMismatch) {
		t.Fatalf("err = %v", err)
	}
	if len(rt.created) != 0 || len(rt.deleted) != 0 {
		t.Error("mismatch must not change the cluster")
	}
}

func TestUpRefusesUnknownCluster(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s := newTestService(rt, matchingObs())
	if _, err := s.Up(context.Background(), "cell-a-1"); err == nil {
		t.Fatal("want error")
	}
	if len(rt.created) != 0 {
		t.Error("Create must not be called")
	}
}

func TestUpValidatesBeforeCreate(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s := newTestService(rt, matchingObs())
	s.Reserved = func(context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}, nil
	}
	if _, err := s.Up(context.Background(), "rogue"); err == nil {
		t.Fatal("want overlap error")
	}
	if len(rt.created) != 0 {
		t.Error("Create must not be called")
	}
}

func TestDownIgnoresAbsentCluster(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s := newTestService(rt, matchingObs())
	if err := s.Down(context.Background(), "rogue"); err != nil {
		t.Fatal(err)
	}
	if len(rt.deleted) != 0 {
		t.Error("Delete must not be called")
	}
}

func TestDownDeletesAndRefusesUnknown(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{"rogue": true, "cell-a-1": true}}
	s := newTestService(rt, matchingObs())
	if err := s.Down(context.Background(), "cell-a-1"); err == nil {
		t.Fatal("want error for cluster outside the topology")
	}
	if err := s.Down(context.Background(), "rogue"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rt.deleted, []string{"rogue"}) {
		t.Errorf("deleted = %v", rt.deleted)
	}
}
