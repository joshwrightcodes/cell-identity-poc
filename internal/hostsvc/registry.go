package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// Registry settings. Nodes pull localhost:5001 images from the registry container by name.
const (
	RegistryName  = "kiln-registry"
	RegistryImage = "docker.io/library/registry:3.1.2@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c"
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
	out, err := s.Docker(ctx, "container", "inspect", "-f", "{{.State.Running}}", RegistryName)
	switch {
	case err != nil && !strings.Contains(string(out), "No such container"):
		return fmt.Errorf("inspect %s: %w: %s", RegistryName, err, strings.TrimSpace(string(out)))
	case err != nil:
		slog.Info("starting registry", "container", RegistryName)
		if out, err := s.Docker(ctx, "run", "-d", "--restart=always", "--name", RegistryName,
			"-p", "127.0.0.1:5001:5000", RegistryImage); err != nil {
			return fmt.Errorf("start %s: %w: %s", RegistryName, err, strings.TrimSpace(string(out)))
		}
	case strings.TrimSpace(string(out)) != "true":
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

// configureNode writes hosts.toml on the node. Containerd reads it on the next pull.
// It fails with ErrNodeStale when containerd on the node ignores the directory.
func (s *Service) configureNode(ctx context.Context, node string) error {
	script := "mkdir -p " + HostsDir + " && printf '%s' '" + HostsTOML() + "' > " + HostsDir + "/hosts.toml"
	if out, err := s.Docker(ctx, "exec", node, "sh", "-c", script); err != nil {
		return fmt.Errorf("write hosts.toml on %s: %w: %s", node, err, strings.TrimSpace(string(out)))
	}
	if _, err := s.Docker(ctx, "exec", node, "grep", "-q", `config_path = "`+certsDir+`"`, "/etc/containerd/config.toml"); err != nil {
		return fmt.Errorf("%w: %s; recreate it with the harness down and up tasks", ErrNodeStale, node)
	}
	return nil
}
