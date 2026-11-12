//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// statusSampleMax is the age limit of a Prometheus sample in harness:status.
const statusSampleMax = 5 * time.Minute

// runMise runs a mise task in the repository root, with CELL set when cell is not empty. It returns the
// standard output, the standard error and the exit status.
func runMise(t *testing.T, cell string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command("mise", append([]string{"run"}, args...)...)
	cmd.Dir = "../.."
	cmd.Env = append(cmd.Environ(), "CELL="+cell)
	if cell == "" {
		cmd.Env = cmd.Environ()
	}
	var out, errBuf lockedBuffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	err := cmd.Run()
	if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("mise run %s: %v", strings.Join(args, " "), err)
	}
	return out.String(), errBuf.String(), code
}

// statusObject is the part of one object of harness:status that the test reads.
type statusObject struct {
	Cluster string `json:"cluster"`
	OK      bool   `json:"ok"`
	Verify  struct {
		OK     bool     `json:"ok"`
		Failed []string `json:"failed"`
	} `json:"verify"`
	Problems []string `json:"problems"`
	Agents   *struct {
		Expected  []string `json:"expected"`
		Connected []string `json:"connected"`
		Missing   []string `json:"missing"`
	} `json:"agents"`
	Samples map[string]float64 `json:"samples"`
	Kiali   *struct {
		Ready      bool     `json:"ready"`
		Accessible []string `json:"accessible"`
		Missing    []string `json:"missing"`
	} `json:"kiali"`
}

// statusOnce runs harness:status and returns the object of each cluster by name, and the exit status.
func statusOnce(t *testing.T) (map[string]statusObject, string, int) {
	t.Helper()
	stdout, stderr, code := runMise(t, "", "harness:status")
	objs := map[string]statusObject{}
	for line := range strings.SplitSeq(strings.TrimSpace(stdout), "\n") {
		var o statusObject
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			t.Fatalf("a line of standard output is no JSON object: %q\nstderr: %s", line, stderr)
		}
		objs[o.Cluster] = o
	}
	return objs, stdout, code
}

// TestM3StatusHealthy checks that harness:status exits 0 on a healthy harness. The management object lists
// both agents, a Prometheus sample younger than 5 minutes for each registered cluster, and both cells in
// Kiali. An earlier test can leave a pod that restarts, so the test reads the status again for a short time.
func TestM3StatusHealthy(t *testing.T) {
	var objs map[string]statusObject
	var stdout string
	var code int
	for attempt := 1; attempt <= 3; attempt++ {
		objs, stdout, code = statusOnce(t)
		if code == 0 {
			break
		}
		t.Logf("attempt %d: harness:status exited %d:\n%s", attempt, code, stdout)
		time.Sleep(30 * time.Second)
	}
	if code != 0 {
		t.Fatalf("harness:status exited %d, want 0:\n%s", code, stdout)
	}
	for _, cluster := range clustersWith(t, "") {
		o, ok := objs[cluster]
		if !ok || !o.OK || !o.Verify.OK {
			t.Errorf("object of %s is %+v (present %v), want ok with a passing cell:verify", cluster, o, ok)
		}
	}
	mgmt := objs[mgmtCluster]
	if mgmt.Agents == nil || mgmt.Kiali == nil {
		t.Fatalf("the management object has no agents or kiali field:\n%s", stdout)
	}
	for _, cell := range viewCells(t) {
		if !slices.Contains(mgmt.Agents.Connected, agentName(cell)) {
			t.Errorf("agents.connected is %v, want %s", mgmt.Agents.Connected, agentName(cell))
		}
	}
	for _, cluster := range clustersWith(t, "") {
		age, ok := mgmt.Samples[cluster]
		if !ok || age >= statusSampleMax.Seconds() {
			t.Errorf("samples[%s] is %v (present %v), want an age under %s", cluster, age, ok, statusSampleMax)
		}
	}
	for _, cell := range meshCells(t) {
		if !slices.Contains(mgmt.Kiali.Accessible, cell) {
			t.Errorf("kiali.accessible is %v, want %s", mgmt.Kiali.Accessible, cell)
		}
	}
}

// TestM3VerifyDetectsPeerRootDrift changes one byte of ConfigMap mgmt-root of the mesh-view tunnel in
// dev-cell-1. cell:verify then fails the check of that ConfigMap and prints the command to repair it. The
// tunnel process reads the file once at start, so the running tunnel keeps its roots. The test restores
// the ConfigMap in t.Cleanup. It applies the change server-side with the manager of the harness apply, so
// the restore leaves the same field managers.
func TestM3VerifyDetectsPeerRootDrift(t *testing.T) {
	const cell, ns, name = "dev-cell-1", "mesh-view-system", "mgmt-root"
	out, err := kubectl(t, cell, "", "-n", ns, "get", "configmap", name, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var cm map[string]any
	if err := json.Unmarshal([]byte(out), &cm); err != nil {
		t.Fatal(err)
	}
	meta := cm["metadata"].(map[string]any)
	for _, k := range []string{"resourceVersion", "uid", "creationTimestamp", "managedFields", "selfLink"} {
		delete(meta, k)
	}
	data := cm["data"].(map[string]any)
	orig, _ := data["root.crt"].(string)
	// Change one base64 character after the first header line.
	i := strings.Index(orig, "\n") + 5
	if i < 5 || i >= len(orig) {
		t.Fatalf("ConfigMap %s/%s holds no PEM body: %q", ns, name, orig)
	}
	flipped := "A"
	if orig[i] == 'A' {
		flipped = "B"
	}
	apply := func(root string) error {
		data["root.crt"] = root
		body, err := json.Marshal(cm)
		if err != nil {
			return err
		}
		_, err = kubectl(t, cell, string(body), "apply", "--server-side", "--force-conflicts", "-f", "-")
		return err
	}
	t.Cleanup(func() {
		if err := apply(orig); err != nil {
			t.Errorf("could not restore ConfigMap %s/%s in %s: %v", ns, name, cell, err)
		}
	})
	if err := apply(orig[:i] + flipped + orig[i+1:]); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runMise(t, cell, "cell:verify")
	const check = "FAIL  The peer root ConfigMap of the mesh-view tunnel holds the live roots of management"
	if code == 0 || !strings.Contains(stdout, check) || !strings.Contains(stdout, "CELL="+cell+" mise run cell:up") {
		t.Fatalf("cell:verify exited %d, want a failure of the check %q and the command CELL=%s mise run cell:up.\nstdout:\n%s\nstderr:\n%s", code, check, cell, stdout, stderr)
	}
}
