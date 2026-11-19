package hostsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type fakeDocker struct {
	calls    []string
	missing  bool
	noNet    bool
	stale    bool
	rootUser bool
	// env replaces the JSON environment that inspect reports. Empty means the expected environment.
	env string
	// ranEnv holds the -e values of the last "run -d". With echoRun, inspect reports them as the environment.
	ranEnv  []string
	echoRun bool
}

const goodEnv = `["PATH=/bin","REGISTRY_HTTP_DEBUG_ADDR=","REGISTRY_STORAGE_DELETE_ENABLED=false"]`

func (f *fakeDocker) inspect(user string) []byte {
	env := f.env
	if f.echoRun {
		b, _ := json.Marshal(append([]string{"PATH=/bin"}, f.ranEnv...))
		env = string(b)
	}
	if env == "" {
		env = goodEnv
	}
	return []byte("true|" + user + "|" + env)
}

func (f *fakeDocker) run(_ context.Context, args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if strings.HasPrefix(line, "run -d ") {
		f.ranEnv = nil
		for i, a := range args {
			if a == "-e" && i+1 < len(args) {
				f.ranEnv = append(f.ranEnv, args[i+1])
			}
		}
	}
	switch {
	case strings.HasPrefix(line, "container inspect") && f.missing:
		return []byte("Error: No such container"), errors.New("exit 1")
	case strings.HasPrefix(line, "container inspect") && f.rootUser:
		return f.inspect(""), nil
	case strings.HasPrefix(line, "container inspect"):
		return f.inspect("65534:65534"), nil
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
	if !strings.Contains(got, `server = "http://registry-mirror:5000"`) {
		t.Errorf("no server line:\n%s", got)
	}
	if !strings.Contains(got, `[host."http://registry-mirror:5000"]`) {
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
	want := "run -d --restart=always --name registry-mirror --user 65534:65534 " +
		"-v registry-mirror-data:/var/lib/registry -e REGISTRY_HTTP_DEBUG_ADDR= -e REGISTRY_STORAGE_DELETE_ENABLED=false -p 127.0.0.1:5001:5000 " + RegistryImage
	if !d.has(want) {
		t.Errorf("calls = %q", d.calls)
	}
	if !d.has("network connect kind registry-mirror") {
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
	if !d.has("run --rm --user 0 --entrypoint chown -v registry-mirror-data:/var/lib/registry " + RegistryImage + " 65534:65534 /var/lib/registry") {
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
	if !d.has("rm -f registry-mirror") || !d.has("run -d ") {
		t.Errorf("calls = %q", d.calls)
	}
}

func TestEnsureRegistryReplacesOnEnv(t *testing.T) {
	for name, env := range map[string]string{
		"delete setting absent":   `["PATH=/bin","REGISTRY_HTTP_DEBUG_ADDR="]`,
		"deletes enabled":         `["REGISTRY_HTTP_DEBUG_ADDR=","REGISTRY_STORAGE_DELETE_ENABLED=true"]`,
		"debug address not empty": `["REGISTRY_HTTP_DEBUG_ADDR=:5001","REGISTRY_STORAGE_DELETE_ENABLED=false"]`,
		"no environment":          `null`,
	} {
		t.Run(name, func(t *testing.T) {
			d := &fakeDocker{env: env}
			s := newTestService(&fakeRuntime{clusters: map[string]bool{}}, matchingObs())
			s.Docker = d.run
			if err := s.EnsureRegistry(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !d.has("rm -f registry-mirror") || !d.has("run -d ") {
				t.Errorf("calls = %q", d.calls)
			}
			if !d.has("run -d --restart=always --name registry-mirror --user 65534:65534 -v registry-mirror-data:/var/lib/registry ") {
				t.Errorf("the replacement must keep the volume: %q", d.calls)
			}
			if d.has("volume rm") {
				t.Errorf("the volume must stay: %q", d.calls)
			}
		})
	}
}

func TestEnsureRegistryLogsReplacedField(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	d := &fakeDocker{env: `["REGISTRY_HTTP_DEBUG_ADDR="]`}
	s := newTestService(&fakeRuntime{clusters: map[string]bool{}}, matchingObs())
	s.Docker = d.run
	if err := s.EnsureRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	var line struct {
		Msg   string `json:"msg"`
		Field string `json:"field"`
	}
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if json.Unmarshal([]byte(l), &line) == nil && line.Msg == "registry_replaced" {
			if line.Field != "env:REGISTRY_STORAGE_DELETE_ENABLED=false" {
				t.Errorf("field = %q", line.Field)
			}
			return
		}
	}
	t.Errorf("no registry_replaced line in %s", buf.String())
}

// A container that EnsureRegistry started has the environment that EnsureRegistry checks, so a second call keeps it.
func TestEnsureRegistryKeepsContainerItStarted(t *testing.T) {
	d := &fakeDocker{missing: true, echoRun: true}
	s := newTestService(&fakeRuntime{clusters: map[string]bool{}}, matchingObs())
	s.Docker = d.run
	if err := s.EnsureRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.missing, d.calls = false, nil
	if err := s.EnsureRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.has("rm -f") || d.has("run ") {
		t.Errorf("a second call replaced the container: %q", d.calls)
	}
	if len(d.ranEnv) != len(registryEnv) {
		t.Errorf("run -e values %v, want %v", d.ranEnv, registryEnv)
	}
}

func facts(out string, err error) DockerFunc {
	return func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) < 3 || args[0] != "container" || args[1] != "inspect" {
			return nil, errors.New("unexpected call " + strings.Join(args, " "))
		}
		return []byte(out), err
	}
}

func TestRegistryFacts(t *testing.T) {
	f, err := RegistryFactsOf(context.Background(), facts("172.18.0.7\n", nil))
	if err != nil {
		t.Fatal(err)
	}
	want := RegistryFacts{Name: "registry-mirror", Address: "172.18.0.7", Port: 5000, Host: "127.0.0.1:5001"}
	if f != want {
		t.Fatalf("facts = %+v, want %+v", f, want)
	}
	b, _ := json.Marshal(f)
	if string(b) != `{"name":"registry-mirror","address":"172.18.0.7","port":5000,"host":"127.0.0.1:5001"}` {
		t.Fatalf("json = %s", b)
	}
}

func TestRegistryFactsFailures(t *testing.T) {
	for name, d := range map[string]DockerFunc{
		"missing":      facts("Error: No such container: registry-mirror", errors.New("exit 1")),
		"not attached": facts("\n", nil),
		"not an IP":    facts("registry-mirror", nil),
		"IPv6":         facts("fe80::1", nil),
	} {
		if f, err := RegistryFactsOf(context.Background(), d); err == nil {
			t.Errorf("%s: facts = %+v, want an error", name, f)
		}
	}
}

// The fact reads the address on the kind network and nothing else.
func TestRegistryFactsInspectArguments(t *testing.T) {
	var got string
	_, _ = RegistryFactsOf(context.Background(), func(_ context.Context, args ...string) ([]byte, error) {
		got = strings.Join(args, " ")
		return []byte("172.18.0.7"), nil
	})
	if !strings.HasPrefix(got, "container inspect -f ") || !strings.HasSuffix(got, " registry-mirror") || !strings.Contains(got, `"kind"`) {
		t.Fatalf("docker call = %q", got)
	}
}
