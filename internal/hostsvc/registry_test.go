package hostsvc

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeDocker struct {
	calls    []string
	missing  bool
	noNet    bool
	stale    bool
	rootUser bool
}

func (f *fakeDocker) run(_ context.Context, args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	f.calls = append(f.calls, line)
	switch {
	case strings.HasPrefix(line, "container inspect") && f.missing:
		return []byte("Error: No such container"), errors.New("exit 1")
	case strings.HasPrefix(line, "container inspect") && f.rootUser:
		return []byte("true "), nil
	case strings.HasPrefix(line, "container inspect"):
		return []byte("true 65534:65534"), nil
	case strings.HasPrefix(line, "network inspect") && f.noNet:
		return []byte("Error: No such network"), errors.New("exit 1")
	case strings.HasPrefix(line, "network inspect"):
		return []byte(""), nil
	case strings.HasPrefix(line, "exec") && strings.Contains(line, "config dump") && f.stale:
		return []byte("[plugins.'io.containerd.cri.v1.images'.registry]\n  config_path = ''\n"), nil
	case strings.HasPrefix(line, "exec") && strings.Contains(line, "config dump"):
		return []byte("time=x level=warning msg=migrated\n    config_path = '" + certsDir + "'\n"), nil
	}
	return nil, nil
}

func (f *fakeDocker) has(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestHostsTOMLPointsAtRegistry(t *testing.T) {
	got := HostsTOML()
	if !strings.Contains(got, `server = "http://kiln-registry:5000"`) {
		t.Errorf("no server line:\n%s", got)
	}
	if !strings.Contains(got, `[host."http://kiln-registry:5000"]`) {
		t.Errorf("no host table:\n%s", got)
	}
	if HostsDir != "/etc/containerd/certs.d/localhost:5001" {
		t.Errorf("HostsDir = %q", HostsDir)
	}
}

func TestKindConfigEnablesCertsDir(t *testing.T) {
	cfg := KindConfig(testCluster, "kindest/node:test")
	if len(cfg.ContainerdConfigPatches) != 1 || !strings.Contains(cfg.ContainerdConfigPatches[0], `config_path = "/etc/containerd/certs.d"`) {
		t.Errorf("patches = %v", cfg.ContainerdConfigPatches)
	}
}

func TestEnsureRegistryStartsAbsentContainer(t *testing.T) {
	d := &fakeDocker{missing: true}
	s := newTestService(&fakeRuntime{clusters: map[string]bool{}}, matchingObs())
	s.Docker = d.run
	if err := s.EnsureRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "run -d --restart=always --name kiln-registry --user 65534:65534 " +
		"-v kiln-registry-data:/var/lib/registry -e REGISTRY_HTTP_DEBUG_ADDR= -p 127.0.0.1:5001:5000 " + RegistryImage
	if !d.has(want) {
		t.Errorf("calls = %q", d.calls)
	}
	if !d.has("network connect kind kiln-registry") {
		t.Errorf("calls = %q", d.calls)
	}
}

func TestEnsureRegistryIsIdempotent(t *testing.T) {
	d := &fakeDocker{}
	s := newTestService(&fakeRuntime{clusters: map[string]bool{}}, matchingObs())
	s.Docker = d.run
	if err := s.EnsureRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.has("run ") {
		t.Errorf("must not start a running container: %q", d.calls)
	}
}

func TestEnsureRegistrySkipsConnectWithoutNetwork(t *testing.T) {
	d := &fakeDocker{missing: true, noNet: true}
	s := newTestService(&fakeRuntime{clusters: map[string]bool{}}, matchingObs())
	s.Docker = d.run
	if err := s.EnsureRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.has("network connect") {
		t.Errorf("calls = %q", d.calls)
	}
}

func TestUpConfiguresExistingNode(t *testing.T) {
	d := &fakeDocker{}
	rt := &fakeRuntime{clusters: map[string]bool{"rogue": true}}
	s := newTestService(rt, matchingObs())
	s.Docker = d.run
	if _, err := s.Up(context.Background(), "rogue"); err != nil {
		t.Fatal(err)
	}
	if len(rt.created) != 0 {
		t.Error("must not recreate")
	}
	if !d.has("exec rogue-control-plane sh -c") || !d.has("container inspect") {
		t.Errorf("calls = %q", d.calls)
	}
	// The registry comes first.
	if !strings.HasPrefix(d.calls[0], "container inspect") {
		t.Errorf("first call = %q", d.calls[0])
	}
}

func TestUpRejectsNodeWithoutCertsDir(t *testing.T) {
	d := &fakeDocker{stale: true}
	rt := &fakeRuntime{clusters: map[string]bool{"rogue": true}}
	s := newTestService(rt, matchingObs())
	s.Docker = d.run
	if _, err := s.Up(context.Background(), "rogue"); !errors.Is(err, ErrNodeStale) {
		t.Fatalf("err = %v", err)
	}
}

func TestCertsDirSet(t *testing.T) {
	for _, tc := range []struct {
		name, dump string
		want       bool
	}{
		{"single quotes", "  config_path = '/etc/containerd/certs.d'\n", true},
		{"double quotes", "config_path = \"/etc/containerd/certs.d\"\n", true},
		{"empty single", "config_path = ''\n", false},
		{"empty double", "config_path = \"\"\n", false},
		{"other directory", "config_path = '/etc/other'\n", false},
		{"one set among empty", "config_path = ''\n  config_path = '/etc/containerd/certs.d'\n", true},
		{"absent", "plugin_config_path = '/etc/nri/conf.d'\n", false},
	} {
		if got := certsDirSet(tc.dump); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

func TestEnsureRegistryPreparesVolumeForUnprivilegedUser(t *testing.T) {
	d := &fakeDocker{missing: true}
	s := newTestService(&fakeRuntime{clusters: map[string]bool{}}, matchingObs())
	s.Docker = d.run
	if err := s.EnsureRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !d.has("run --rm --user 0 --entrypoint chown -v kiln-registry-data:/var/lib/registry " + RegistryImage + " 65534:65534 /var/lib/registry") {
		t.Errorf("calls = %q", d.calls)
	}
}

func TestEnsureRegistryReplacesRootContainer(t *testing.T) {
	d := &fakeDocker{rootUser: true}
	s := newTestService(&fakeRuntime{clusters: map[string]bool{}}, matchingObs())
	s.Docker = d.run
	if err := s.EnsureRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !d.has("rm -f kiln-registry") || !d.has("run -d ") {
		t.Errorf("calls = %q", d.calls)
	}
}
