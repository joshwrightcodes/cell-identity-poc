//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

const (
	imagesEnv    = "../../build/images.env"
	topologyPath = "../../harness/topology.yaml"
	podTimeout   = 5 * time.Minute
	// agentCellSet is the component set of each cell whose celld attests to the SPIRE server.
	agentCellSet = "cell-identity"
)

// clustersWith returns the clusters in harness/topology.yaml that have the component set, or every
// cluster with components when set is empty.
func clustersWith(t *testing.T, set string) []string {
	t.Helper()
	topo, err := topology.Load(topologyPath)
	if err != nil {
		t.Fatalf("load topology: %v", err)
	}
	names := topo.WithComponents()
	if set != "" {
		names = topo.WithComponent(set)
	}
	if len(names) == 0 {
		t.Fatalf("no cluster in %s has the component set %q", topologyPath, set)
	}
	return names
}

var podCounter atomic.Int64

// pocEnv is POC_ENV from cells/common.env: the environment in each attestation audience.
var pocEnv = func() string {
	data, err := os.ReadFile("../../cells/common.env")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "POC_ENV="); ok {
			return v
		}
	}
	return ""
}()

// probeImage and attestprobeImage are the references that `mise run images` recorded in
// build/images.env, pinned by digest. Each is empty when the file or the line is missing.
// needProbeImage and needAttestprobeImage then fail the test.
var (
	probeImage       = readImage("IMAGE_NETPROBE")
	attestprobeImage = readImage("IMAGE_ATTESTPROBE")
)

func readImage(variable string) string {
	data, err := os.ReadFile(imagesEnv)
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if ref, ok := strings.CutPrefix(line, variable+"="); ok && strings.Contains(ref, "@sha256:") {
			return ref
		}
	}
	return ""
}

func needProbeImage(t *testing.T) {
	t.Helper()
	if probeImage == "" {
		t.Fatalf("%s has no IMAGE_NETPROBE pinned by digest. Run mise run images.", imagesEnv)
	}
}

func needAttestprobeImage(t *testing.T) {
	t.Helper()
	if attestprobeImage == "" {
		t.Fatalf("%s has no IMAGE_ATTESTPROBE pinned by digest. Run mise run images.", imagesEnv)
	}
}

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

// kubectlTimeout bounds one kubectl call, so a hung call cannot hold a wait past its deadline.
// The longest call, a namespace delete, waits up to 180 seconds itself.
const kubectlTimeout = 4 * time.Minute

// kubectl runs kubectl against a cluster and returns standard output.
func kubectl(t *testing.T, cluster, stdin string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"--context", "kind-" + cluster}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), kubectlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", full...)
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

// testNamespaceLabel marks each namespace that createNamespace makes.
const (
	testNamespaceLabel = "cell.poc.internal/e2e"
	podSecurityLabel   = "pod-security.kubernetes.io/enforce"
)

// createNamespace makes a test namespace and deletes it when the test ends. It first removes a
// namespace of the same name that an earlier run left behind, and it waits until the default
// service account exists, because a pod cannot start before then. It never deletes a namespace
// without the test label, so a test name cannot remove a harness namespace. Pod Security enforces
// the restricted profile in each test namespace.
func createNamespace(t *testing.T, cluster, ns string) {
	t.Helper()
	createNamespaceAt(t, cluster, ns, "restricted")
}

// createNamespaceAt is createNamespace with the named Pod Security level.
func createNamespaceAt(t *testing.T, cluster, ns, level string) {
	t.Helper()
	deleteNamespace := func() error {
		_, err := kubectl(t, cluster, "", "delete", "namespace", ns, "--ignore-not-found", "--wait=true", "--timeout=180s")
		return err
	}
	label, err := kubectl(t, cluster, "", "get", "namespace", ns, "--ignore-not-found",
		"-o", "jsonpath={.metadata.labels.cell\\.poc\\.internal/e2e}{.metadata.name}")
	if err != nil {
		t.Fatal(err)
	}
	switch label {
	case "":
	case "true" + ns:
		if err := deleteNamespace(); err != nil {
			t.Fatalf("remove leftover namespace %s in %s: %v", ns, cluster, err)
		}
	default:
		t.Fatalf("namespace %s exists in %s without the label %s=true, so it is not a test namespace", ns, cluster, testNamespaceLabel)
	}
	manifest := fmt.Sprintf(`{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": %q, "labels": {%q: "true", %q: %q}}}`,
		ns, testNamespaceLabel, podSecurityLabel, level)
	if _, err := kubectl(t, cluster, manifest, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := deleteNamespace(); err != nil {
			t.Logf("cleanup of namespace %s in %s failed: %v", ns, cluster, err)
		}
	})
	deadline := time.Now().Add(time.Minute)
	for {
		_, err := kubectl(t, cluster, "", "-n", ns, "get", "serviceaccount", "default")
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("serviceaccount/default did not appear in namespace %s of %s within a minute: %v", ns, cluster, err)
		}
		time.Sleep(time.Second)
	}
}

type containerOverride struct {
	Name            string         `json:"name"`
	Image           string         `json:"image"`
	ImagePullPolicy string         `json:"imagePullPolicy,omitempty"`
	Args            []string       `json:"args"`
	SecurityContext map[string]any `json:"securityContext"`
}

// restrictedOverrides returns the pod overrides that satisfy Pod Security restricted.
func restrictedOverrides(name string, args []string) string {
	return restrictedOverridesWithPull(name, args, "")
}

// restrictedOverridesWithPull is restrictedOverrides with an image pull policy.
func restrictedOverridesWithPull(name string, args []string, pullPolicy string) string {
	o := map[string]any{
		"spec": map[string]any{
			"securityContext": map[string]any{
				"runAsNonRoot":   true,
				"seccompProfile": map[string]any{"type": "RuntimeDefault"},
			},
			"containers": []containerOverride{{
				Name:            name,
				Image:           probeImage,
				ImagePullPolicy: pullPolicy,
				Args:            args,
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
	needProbeImage(t)
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

// startPod starts the probe image with args in a cluster, always pulling the image, and waits until
// the pod is Running or Succeeded. It returns an error that describes the pod when the wait ends.
func startPod(t *testing.T, cluster, ns string, args []string) error {
	t.Helper()
	needProbeImage(t)
	name := fmt.Sprintf("probe-%d", podCounter.Add(1))
	runArgs := []string{"-n", ns, "run", name, "--image", probeImage, "--restart=Never",
		"--overrides", restrictedOverridesWithPull(name, args, "Always")}
	if _, err := kubectl(t, cluster, "", runArgs...); err != nil {
		return err
	}
	deadline := time.Now().Add(podTimeout)
	for {
		phase, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", name, "-o", "jsonpath={.status.phase}")
		if err != nil {
			return err
		}
		if phase == "Running" || phase == "Succeeded" {
			return nil
		}
		if phase == "Failed" || time.Now().After(deadline) {
			desc, _ := kubectl(t, cluster, "", "-n", ns, "describe", "pod", name)
			return fmt.Errorf("pod %s is %s\n%s", name, phase, desc)
		}
		time.Sleep(time.Second)
	}
}
