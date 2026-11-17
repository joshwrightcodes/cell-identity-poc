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

// deleteNextPod deletes the pod that the next runPod or startPod call names, in rogue/default, when the test ends.
func deleteNextPod(t *testing.T) {
	t.Helper()
	pod := "probe-" + strconv.FormatInt(podCounter.Load()+1, 10)
	t.Cleanup(func() {
		_, _ = kubectl(t, "rogue", "", "-n", "default", "delete", "pod", pod, "--ignore-not-found", "--wait=false")
	})
}

// TestM7RegistryRefusesDelete sends a manifest delete from a pod of rogue to the registry container.
// The registry answers 405, and a pull of the same digest still works afterwards.
func TestM7RegistryRefusesDelete(t *testing.T) {
	needProbeImage(t)
	_, digest, ok := strings.Cut(probeImage, "@")
	if !ok {
		t.Fatalf("IMAGE_NETPROBE %q has no digest", probeImage)
	}
	url := "http://" + registryAddress(t) + ":5000/v2/netprobe/manifests/" + digest
	deleteNextPod(t)
	out := runPod(t, "rogue", "default", []string{"http", "--method", "DELETE", "--url", url})
	var resp struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("netprobe http output %q: %v", out, err)
	}
	if resp.Status != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE %s returned %d %s, want 405", url, resp.Status, resp.Body)
	}
	// startPod always pulls, so a deleted manifest fails the pod. The pod ends at once.
	deleteNextPod(t)
	if err := startPod(t, "rogue", "default", []string{"dial", "--addr", "127.0.0.1:1"}); err != nil {
		t.Fatalf("pull of %s after the delete: %v", digest, err)
	}
}
