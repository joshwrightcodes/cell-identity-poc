package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
)

// Registry settings. Nodes pull localhost:5001 images from the registry container by name.
const (
	RegistryName   = "registry-mirror"
	RegistryVolume = "registry-mirror-data"
	registryUser   = "65534:65534"
	RegistryImage  = "docker.io/library/registry:3.1.2@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c"
	// HostsDir is the containerd registry configuration directory for localhost:5001 on a node.
	HostsDir = "/etc/containerd/certs.d/localhost:5001"
	certsDir = "/etc/containerd/certs.d"
)

// ErrNodeStale means a node was created without the containerd registry configuration directory.
var ErrNodeStale = errors.New("node containerd does not read the registry configuration directory")

// DockerFunc runs the docker command line and returns its combined output.
type DockerFunc func(ctx context.Context, args ...string) ([]byte, error)

// RunDocker runs the docker command on PATH.
func RunDocker(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

// HostsTOML returns the containerd hosts.toml that maps localhost:5001 to the registry container.
func HostsTOML() string {
	return `server = "http://` + RegistryName + `:5000"

[host."http://` + RegistryName + `:5000"]
  capabilities = ["pull", "resolve"]
`
}

// EnsureRegistry starts the registry container and attaches it to the kind network.
// It is idempotent. The kind network is absent before the first cluster, so the attach is skipped then.
func (s *Service) EnsureRegistry(ctx context.Context) error {
	out, err := s.Docker(ctx, "container", "inspect", "-f", "{{.State.Running}} {{.Config.User}}", RegistryName)
	if err != nil && !strings.Contains(string(out), "No such container") {
		return fmt.Errorf("inspect %s: %w: %s", RegistryName, err, strings.TrimSpace(string(out)))
	}
	state := strings.Fields(string(out))
	switch {
	case err != nil:
		if err := s.runRegistry(ctx); err != nil {
			return err
		}
	case len(state) < 2 || state[1] != registryUser:
		slog.Info("replacing registry that does not run as the expected user", "container", RegistryName)
		if out, err := s.Docker(ctx, "rm", "-f", RegistryName); err != nil {
			return fmt.Errorf("remove %s: %w: %s", RegistryName, err, strings.TrimSpace(string(out)))
		}
		if err := s.runRegistry(ctx); err != nil {
			return err
		}
	case state[0] != "true":
		if out, err := s.Docker(ctx, "start", RegistryName); err != nil {
			return fmt.Errorf("start %s: %w: %s", RegistryName, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := s.Docker(ctx, "network", "inspect", kindNetwork); err != nil {
		if strings.Contains(string(out), "No such network") {
			return nil
		}
		return fmt.Errorf("inspect network %s: %w: %s", kindNetwork, err, strings.TrimSpace(string(out)))
	}
	out, err = s.Docker(ctx, "network", "connect", kindNetwork, RegistryName)
	if err != nil && !strings.Contains(string(out), "already exists") {
		return fmt.Errorf("connect %s to %s: %w: %s", RegistryName, kindNetwork, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runRegistry creates the registry container. The image runs as root by default, and it opens a
// Prometheus debug listener on port 5001. The container runs as an unprivileged user with a
// named volume that this user owns, and the debug address is empty so that nothing listens on it.
func (s *Service) runRegistry(ctx context.Context) error {
	slog.Info("starting registry", "container", RegistryName)
	if out, err := s.Docker(ctx, "run", "--rm", "--user", "0", "--entrypoint", "chown",
		"-v", RegistryVolume+":/var/lib/registry", RegistryImage, registryUser, "/var/lib/registry"); err != nil {
		return fmt.Errorf("prepare volume %s: %w: %s", RegistryVolume, err, strings.TrimSpace(string(out)))
	}
	if out, err := s.Docker(ctx, "run", "-d", "--restart=always", "--name", RegistryName,
		"--user", registryUser, "-v", RegistryVolume+":/var/lib/registry",
		"-e", "REGISTRY_HTTP_DEBUG_ADDR=", "-p", "127.0.0.1:5001:5000", RegistryImage); err != nil {
		return fmt.Errorf("start %s: %w: %s", RegistryName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// configureNode writes hosts.toml on the node. Containerd reads it on the next pull.
// It fails with ErrNodeStale when containerd on the node ignores the directory.
func (s *Service) configureNode(ctx context.Context, node string) error {
	script := "mkdir -p " + HostsDir + " && printf '%s' '" + HostsTOML() + "' > " + HostsDir + "/hosts.toml"
	if out, err := s.Docker(ctx, "exec", node, "sh", "-c", script); err != nil {
		return fmt.Errorf("write hosts.toml on %s: %w: %s", node, err, strings.TrimSpace(string(out)))
	}
	out, err := s.Docker(ctx, "exec", node, "containerd", "config", "dump")
	if err != nil {
		return fmt.Errorf("read containerd configuration on %s: %w: %s", node, err, strings.TrimSpace(string(out)))
	}
	if !certsDirSet(string(out)) {
		return fmt.Errorf("%w: %s; recreate it with the harness down and up tasks", ErrNodeStale, node)
	}
	return nil
}

var configPathLine = regexp.MustCompile(`(?m)^\s*config_path\s*=\s*(?:'([^']*)'|"([^"]*)")\s*$`)

// certsDirSet reports whether the effective containerd configuration sets config_path to the
// registry configuration directory, in either TOML string style.
func certsDirSet(dump string) bool {
	for _, m := range configPathLine.FindAllStringSubmatch(dump, -1) {
		if m[1] == certsDir || m[2] == certsDir {
			return true
		}
	}
	return false
}
