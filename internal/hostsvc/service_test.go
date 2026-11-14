package hostsvc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
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
	topo := &topology.Topology{NodeImage: "kindest/node:test@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5", Clusters: []topology.Cluster{testCluster}}
	s := New(rt, topo)
	s.Docker = (&fakeDocker{}).run
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

var testCell = topology.Cluster{
	Name:          "dev-cell-1",
	PodSubnet:     "10.20.0.0/16",
	ServiceSubnet: "10.120.0.0/16",
	Issuer:        "https://dev-cell-1.issuer.poc.internal",
	Components:    []string{"cell-identity"},
}

func cellObs() Observed {
	return Observed{
		PodSubnet: testCell.PodSubnet, ServiceSubnet: testCell.ServiceSubnet, Issuer: testCell.Issuer,
		APIServer: "https://127.0.0.1:40001", JWKS: json.RawMessage(`{"keys":[{"kid":"k"}]}`),
	}
}

type fakeMarker struct {
	has     bool
	hasErr  error
	written int
	order   *[]string
}

func (m *fakeMarker) Has(context.Context, string) (bool, error) { return m.has, m.hasErr }
func (m *fakeMarker) Write(context.Context, string) error {
	m.written++
	m.has = true
	if m.order != nil {
		*m.order = append(*m.order, "marker")
	}
	return nil
}

// newCellService is a service whose topology holds the cell dev-cell-1 and the cluster rogue.
func newCellService(rt *fakeRuntime) (*Service, *fakeMarker, *fakeDocker) {
	topo := &topology.Topology{
		NodeImage: "kindest/node:test@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
		Clusters:  []topology.Cluster{testCluster, testCell},
	}
	s := New(rt, topo)
	d := &fakeDocker{}
	s.Docker = d.run
	s.Prober = fakeProber{obs: cellObs()}
	s.Reserved = func(context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.5.0/24")}, nil
	}
	m := &fakeMarker{}
	s.Marker = m
	return s, m, d
}

func TestIsCell(t *testing.T) {
	if !IsCell(testCell) || IsCell(testCluster) || IsCell(topology.Cluster{Components: []string{"envd"}}) {
		t.Error("IsCell must be true only for a cluster with the cell-identity component")
	}
}

func TestUpRefusesAbsentCell(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s, m, d := newCellService(rt)
	_, err := s.Up(context.Background(), "dev-cell-1")
	if !errors.Is(err, ErrCellNeedsStep) {
		t.Fatalf("Up = %v, want ErrCellNeedsStep", err)
	}
	if len(rt.created) != 0 || len(rt.deleted) != 0 || m.written != 0 || len(d.calls) != 0 {
		t.Errorf("an absent cell was touched: created %v, deleted %v, marker %d, docker %v", rt.created, rt.deleted, m.written, d.calls)
	}
}

func TestUpAllSkipsAbsentCells(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s, _, _ := newCellService(rt)
	if err := s.UpAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rt.created) != 1 || rt.created[0].Name != "rogue" {
		t.Errorf("created = %v, want the rogue cluster only", rt.created)
	}
}

func TestUpAllReportsEachSkippedCell(t *testing.T) {
	var buf syncBuf
	old := slog.Default()
	slog.SetDefault(jsonLogger(&buf))
	t.Cleanup(func() { slog.SetDefault(old) })
	s, _, _ := newCellService(&fakeRuntime{clusters: map[string]bool{}})
	if err := s.UpAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"msg":"cell_needs_step"`) || !strings.Contains(buf.String(), `"cluster":"dev-cell-1"`) {
		t.Errorf("log = %q, want cell_needs_step for dev-cell-1", buf.String())
	}
}

func TestUpAllStopsOnRealError(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{"dev-cell-1": true}}
	s, _, _ := newCellService(rt)
	obs := cellObs()
	obs.PodSubnet = "10.244.0.0/16"
	s.Prober = fakeProber{obs: obs}
	if err := s.UpAll(context.Background()); !errors.Is(err, ErrSpecMismatch) {
		t.Errorf("UpAll = %v, want ErrSpecMismatch", err)
	}
}

func TestUpExistingCellReapplies(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{"dev-cell-1": true}}
	s, m, d := newCellService(rt)
	f, err := s.Up(context.Background(), "dev-cell-1")
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != "dev-cell-1" || len(rt.created) != 0 || len(rt.deleted) != 0 || m.written != 0 {
		t.Errorf("facts %+v, created %v, deleted %v, marker %d", f, rt.created, rt.deleted, m.written)
	}
	if !slices.ContainsFunc(d.calls, func(c string) bool { return strings.Contains(c, "config dump") }) {
		t.Errorf("the registry mirror setting was not reapplied: %v", d.calls)
	}
}

func TestCreateWritesMarkerAfterFacts(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s, m, _ := newCellService(rt)
	var order []string
	m.order = &order
	s.Prober = orderedProber{inner: fakeProber{obs: cellObs()}, order: &order}
	f, err := s.Create(context.Background(), "dev-cell-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.created) != 1 || m.written != 1 || f.Name != "dev-cell-1" {
		t.Fatalf("created %v, marker %d, facts %+v", rt.created, m.written, f)
	}
	if want := "probe,marker"; strings.Join(order, ",") != want {
		t.Errorf("order = %v, want the probe of Facts, then the marker", order)
	}
	// Registry and node settings are applied to the new cluster.
}

type orderedProber struct {
	inner fakeProber
	order *[]string
}

func (p orderedProber) Probe(ctx context.Context, kc string) (Observed, error) {
	*p.order = append(*p.order, "probe")
	return p.inner.Probe(ctx, kc)
}

func TestCreateWithoutMarkerWhenFactsFail(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{}}
	s, m, _ := newCellService(rt)
	s.Prober = errProber{}
	if _, err := s.Create(context.Background(), "dev-cell-1", false); err == nil {
		t.Fatal("Create succeeded with a failing probe")
	}
	if m.written != 0 {
		t.Error("the marker was written although Facts failed")
	}
}

type errProber struct{}

func (errProber) Probe(context.Context, string) (Observed, error) {
	return Observed{}, errors.New("api down")
}

func TestRetryDeletesHalfBuiltCluster(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{"dev-cell-1": true}}
	s, m, d := newCellService(rt)
	if _, err := s.Create(context.Background(), "dev-cell-1", true); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rt.deleted, []string{"dev-cell-1"}) || len(rt.created) != 1 || m.written != 1 {
		t.Errorf("deleted %v, created %d, marker %d: want a delete, one create and a marker", rt.deleted, len(rt.created), m.written)
	}
	if !slices.ContainsFunc(d.calls, func(c string) bool { return strings.Contains(c, "config dump") }) {
		t.Errorf("the new cluster has no registry mirror setting: %v", d.calls)
	}
}

func TestRetryKeepsClusterWithMarker(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{"dev-cell-1": true}}
	s, m, _ := newCellService(rt)
	m.has = true
	if _, err := s.Create(context.Background(), "dev-cell-1", true); err != nil {
		t.Fatal(err)
	}
	if len(rt.deleted) != 0 || len(rt.created) != 0 || m.written != 0 {
		t.Errorf("a finished cluster was touched: deleted %v, created %d, marker %d", rt.deleted, len(rt.created), m.written)
	}
}

func TestFirstAttemptKeepsExistingCluster(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{"dev-cell-1": true}}
	s, m, d := newCellService(rt)
	if _, err := s.Create(context.Background(), "dev-cell-1", false); err != nil {
		t.Fatal(err)
	}
	if len(rt.deleted) != 0 || len(rt.created) != 0 || m.written != 0 {
		t.Errorf("deleted %v, created %d, marker %d: the first attempt keeps an existing cluster", rt.deleted, len(rt.created), m.written)
	}
	if !slices.ContainsFunc(d.calls, func(c string) bool { return strings.Contains(c, "config dump") }) {
		t.Errorf("the existing path did not reapply the registry settings: %v", d.calls)
	}
	// The existing path checks the spec.
	obs := cellObs()
	obs.Issuer = "https://other.example"
	s.Prober = fakeProber{obs: obs}
	if _, err := s.Create(context.Background(), "dev-cell-1", false); !errors.Is(err, ErrSpecMismatch) {
		t.Errorf("Create on a cluster with another spec = %v, want ErrSpecMismatch", err)
	}
}

func TestCreateRefusesUnknownCluster(t *testing.T) {
	s, _, _ := newCellService(&fakeRuntime{clusters: map[string]bool{}})
	if _, err := s.Create(context.Background(), "nowhere", false); err == nil {
		t.Error("Create accepted a cluster outside the topology")
	}
}

func TestKubeMarker(t *testing.T) {
	cs := fake.NewClientset()
	m := KubeMarker{Client: func(string) (kubernetes.Interface, error) { return cs, nil }}
	if has, err := m.Has(context.Background(), "kc"); err != nil || has {
		t.Fatalf("Has before Write = %v %v", has, err)
	}
	if err := m.Write(context.Background(), "kc"); err != nil {
		t.Fatal(err)
	}
	cm, err := cs.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "poc-provisioned", metav1.GetOptions{})
	if err != nil || cm.Labels["poc.internal/made-by"] != "hostsvc" {
		t.Fatalf("marker = %+v %v", cm, err)
	}
	if has, err := m.Has(context.Background(), "kc"); err != nil || !has {
		t.Errorf("Has after Write = %v %v", has, err)
	}
	if err := m.Write(context.Background(), "kc"); err != nil {
		t.Errorf("a second Write: %v", err)
	}
	bad := KubeMarker{}
	if _, err := bad.Has(context.Background(), "not a kubeconfig"); err == nil {
		t.Error("Has accepted a bad kubeconfig")
	}
}
