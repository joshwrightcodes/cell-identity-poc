//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
)

// registryAddress returns the address of the registry container on the kind network, from docker inspect.
func registryAddress(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect", "-f",
		`{{(index .NetworkSettings.Networks "kind").IPAddress}}`, hostsvc.RegistryName).Output()
	if err != nil {
		t.Fatalf("docker inspect %s: %v", hostsvc.RegistryName, err)
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		t.Fatalf("container %s has no address on the kind network", hostsvc.RegistryName)
	}
	return ip
}

// registryTestLabel marks the pods of TestM7RegistryRefusesDelete, so that its cleanup deletes only them.
const registryTestLabel = "cell.poc.internal/m7-registry"

// deleteLabeledPods deletes the pods of rogue/default that carry the label value when the test ends.
func deleteLabeledPods(t *testing.T, value string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = kubectl(t, "rogue", "", "-n", "default", "delete", "pod", "-l", registryTestLabel+"="+value, "--ignore-not-found", "--wait=false")
	})
}

// requireDeletesOff fails the test when the registry container runs with deletes on. The delete below would then remove the manifest that every
// later test pulls. gate:m7 checks the same before the run, and the host service recreates the container with the switch off.
func requireDeletesOff(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{json .Config.Env}}", hostsvc.RegistryName).Output()
	if err != nil {
		t.Fatalf("docker inspect %s: %v", hostsvc.RegistryName, err)
	}
	if !strings.Contains(string(out), `"REGISTRY_STORAGE_DELETE_ENABLED=false"`) {
		t.Fatalf("container %s does not run with REGISTRY_STORAGE_DELETE_ENABLED=false, so the test would delete a live image. Run: mise run hostsvc -- up", hostsvc.RegistryName)
	}
}

// registryRepository returns the repository path of an image reference: the part after the host and before the digest.
func registryRepository(ref string) (string, bool) {
	name, _, ok := strings.Cut(ref, "@")
	_, repo, hasHost := strings.Cut(name, "/")
	return repo, ok && hasHost && repo != ""
}

// TestM7RegistryRefusesDelete sends a manifest delete by digest from a pod of rogue to the registry container.
// The registry answers 405 with the error code UNSUPPORTED, and a pull of the same digest still works afterwards.
func TestM7RegistryRefusesDelete(t *testing.T) {
	needProbeImage(t)
	requireDeletesOff(t)
	repo, ok := registryRepository(probeImage)
	if !ok {
		t.Fatalf("IMAGE_NETPROBE %q has no repository and digest", probeImage)
	}
	_, digest, _ := strings.Cut(probeImage, "@")
	url := "http://" + registryAddress(t) + ":5000/v2/" + repo + "/manifests/" + digest
	value := strconv.FormatInt(time.Now().UnixNano(), 36)
	deleteLabeledPods(t, value)
	out := runPodLabeled(t, "rogue", "default", registryTestLabel+"="+value, []string{"http", "--method", "DELETE", "--url", url})
	var resp struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("netprobe http output %q: %v", out, err)
	}
	if resp.Status != http.StatusMethodNotAllowed || !strings.Contains(resp.Body, "UNSUPPORTED") {
		t.Fatalf("DELETE %s returned %d %s, want 405 with UNSUPPORTED", url, resp.Status, resp.Body)
	}
	// startPodLabeled always pulls, so a deleted manifest fails the pod. The pod ends at once.
	if err := startPodLabeled(t, "rogue", "default", registryTestLabel+"="+value, []string{"dial", "--addr", "127.0.0.1:1"}); err != nil {
		t.Fatalf("pull of %s after the delete: %v", digest, err)
	}
}
