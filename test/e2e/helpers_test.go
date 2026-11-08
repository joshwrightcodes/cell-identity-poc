//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

const (
	probeImage   = "localhost:5001/netprobe:latest"
	topologyPath = "../../harness/topology.yaml"
	podTimeout   = 5 * time.Minute
)

var podCounter atomic.Int64

// clusterFacts returns the host service facts of a running cluster.
func clusterFacts(t *testing.T, name string) hostsvc.Facts {
	t.Helper()
	topo, err := topology.Load(topologyPath)
	if err != nil {
		t.Fatalf("load topology: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, err := hostsvc.New(hostsvc.NewKindRuntime(), topo).Facts(ctx, name)
	if err != nil {
		t.Fatalf("facts of %s: %v", name, err)
	}
	return f
}

// kubectl runs kubectl against a cluster and returns standard output.
func kubectl(t *testing.T, cluster, stdin string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"--context", "kind-" + cluster}, args...)
	cmd := exec.Command("kubectl", full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("kubectl %s: %w: %s", strings.Join(full, " "), err, stderr.String())
	}
	return string(out), nil
}

// createNamespace makes a test namespace and deletes it when the test ends.
func createNamespace(t *testing.T, cluster, ns string) {
	t.Helper()
	if _, err := kubectl(t, cluster, "", "create", "namespace", ns); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = kubectl(t, cluster, "", "delete", "namespace", ns, "--ignore-not-found", "--wait=true", "--timeout=120s")
	})
}

type containerOverride struct {
	Name            string         `json:"name"`
	Image           string         `json:"image"`
	Args            []string       `json:"args"`
	SecurityContext map[string]any `json:"securityContext"`
}

// restrictedOverrides returns the pod overrides that satisfy Pod Security restricted.
func restrictedOverrides(name string, args []string) string {
	o := map[string]any{
		"spec": map[string]any{
			"securityContext": map[string]any{
				"runAsNonRoot":   true,
				"seccompProfile": map[string]any{"type": "RuntimeDefault"},
			},
			"containers": []containerOverride{{
				Name:  name,
				Image: probeImage,
				Args:  args,
				SecurityContext: map[string]any{
					"allowPrivilegeEscalation": false,
					"capabilities":             map[string]any{"drop": []string{"ALL"}},
				},
			}},
		},
	}
	b, _ := json.Marshal(o)
	return string(b)
}

// runPod runs the probe image with args to completion in a cluster and returns its standard output.
func runPod(t *testing.T, cluster, ns string, args []string) string {
	t.Helper()
	name := fmt.Sprintf("probe-%d", podCounter.Add(1))
	runArgs := []string{"-n", ns, "run", name, "--image", probeImage, "--restart=Never",
		"--overrides", restrictedOverrides(name, args)}
	if _, err := kubectl(t, cluster, "", runArgs...); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(podTimeout)
	for {
		phase, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", name, "-o", "jsonpath={.status.phase}")
		if err != nil {
			t.Fatal(err)
		}
		if phase == "Succeeded" || phase == "Failed" {
			logs, lerr := kubectl(t, cluster, "", "-n", ns, "logs", name)
			if phase == "Failed" {
				t.Fatalf("pod %s in %s failed: %v\nlogs: %s", name, cluster, lerr, logs)
			}
			if lerr != nil {
				t.Fatal(lerr)
			}
			return logs
		}
		if time.Now().After(deadline) {
			desc, _ := kubectl(t, cluster, "", "-n", ns, "describe", "pod", name)
			t.Fatalf("pod %s in %s stayed %s\n%s", name, cluster, phase, desc)
		}
		time.Sleep(time.Second)
	}
}
