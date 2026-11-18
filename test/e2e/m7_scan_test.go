//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// scanPorts returns the sorted open ports of a TCP scan of ports 1 to 65535 on host. run starts one netprobe pod with the arguments,
// to its end, and returns its log.
func scanPorts(t *testing.T, run func(args []string) string, host string) []int {
	t.Helper()
	out := run([]string{"scan", "--host", host, "--ports", "1-65535", "--timeout", "300ms", "--concurrency", "256"})
	var open []int
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &open); err != nil {
		t.Fatalf("decode the scan output %q: %v", out, err)
	}
	slices.Sort(open)
	return open
}

// requireScanWorked fails the test when a port that is always open on a node is missing, because the scan then proves nothing.
func requireScanWorked(t *testing.T, what string, open []int) {
	t.Helper()
	for _, p := range alwaysOpenPorts {
		if !slices.Contains(open, p) {
			t.Fatalf("%s: the scan did not work, because port %d is always open on a node and is missing from %v", what, p, open)
		}
	}
}

// extraPorts returns the ports of open that are not in allowed.
func extraPorts(open, allowed []int) []int {
	var extra []int
	for _, p := range open {
		if !slices.Contains(allowed, p) {
			extra = append(extra, p)
		}
	}
	return extra
}

// deletePodsLater deletes the probe pods that runPod makes in a namespace that outlives the test.
func deletePodsLater(t *testing.T, cluster, ns string, first int64) {
	t.Helper()
	t.Cleanup(func() {
		for i := first + 1; i <= podCounter.Load(); i++ {
			_, _ = kubectl(t, cluster, "", "-n", ns, "delete", "pod", fmt.Sprintf("probe-%d", i), "--ignore-not-found", "--wait=false")
		}
	})
}

// TestM7CellPodScansOtherCell scans every TCP port of the node of dev-cell-2 from a pod in dev-cell-1/default, which has no NetworkPolicy.
// Only the residual ports of M1 answer.
func TestM7CellPodScansOtherCell(t *testing.T) {
	needProbeImage(t)
	from, to := celldCell, "dev-cell-2"
	ip := clusterFacts(t, to).NodeIP
	deletePodsLater(t, from, "default", podCounter.Load())
	open := scanPorts(t, func(args []string) string { return runPod(t, from, "default", args) }, ip)
	t.Logf("open ports on %s (%s) from a pod in %s/default: %v", to, ip, from, open)
	requireScanWorked(t, to, open)
	if extra := extraPorts(open, residualPorts); len(extra) > 0 {
		t.Errorf("a pod in %s reaches the ports %v of the node of %s beyond the residual set %v", from, extra, to, residualPorts)
	}
}

// hostNetPod runs netprobe with args to its end in a pod on the host network, as root, in a privileged m7 namespace, and returns its log.
func hostNetPod(t *testing.T, cluster, ns string, args []string) string {
	t.Helper()
	needProbeImage(t)
	name := m7PodName("hostnet")
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name},
		"spec": map[string]any{"restartPolicy": "Never", "hostNetwork": true, "automountServiceAccountToken": false,
			"containers": []any{map[string]any{"name": name, "image": probeImage, "args": args, "securityContext": map[string]any{"runAsUser": 0}}}}}
	applyPod(t, cluster, ns, pod)
	phase, logs := podDone(t, cluster, ns, name)
	if phase != "Succeeded" {
		t.Fatalf("host network pod %s/%s in %s ended in phase %s: %s", ns, name, cluster, phase, logs)
	}
	return logs
}

// admittedPorts lists the ports of a target node that admit the node addresses of cells: the SPIRE server, the relays and the gateway
// listeners of dev-cp. management admits no cell node address.
var admittedPorts = map[string][]int{
	envCluster:  {30081, 30443, 30444, 30445, 30450, 30451},
	mgmtCluster: {},
}

// TestM7HostNetworkScan scans the nodes of dev-cp and management from host network pods in a privileged m7 namespace of rogue, and of
// dev-cell-1. The pod in rogue reaches only the residual ports. The pod in dev-cell-1 reaches also the ports that admit the node address
// of a cell. The test records them and requires that each is one of the known listeners. An unauthenticated handshake with each then
// gets no data: the mutual TLS listeners answer with a TLS alert, and the others wait for a request that never comes. Root host network
// pods pass kindnet policy, as poc-scope.md says, so the policy of the source is no control here; the policies of the targets are.
func TestM7HostNetworkScan(t *testing.T) {
	for _, from := range []string{"rogue", celldCell} {
		t.Run(from, func(t *testing.T) {
			ns := m7Namespace(t, from, true)
			run := func(args []string) string { return hostNetPod(t, from, ns, args) }
			for _, target := range []string{envCluster, mgmtCluster} {
				ip := clusterFacts(t, target).NodeIP
				open := scanPorts(t, run, ip)
				t.Logf("open ports on %s (%s) from a host network pod in %s: %v", target, ip, from, open)
				requireScanWorked(t, from+" to "+target, open)
				allowed := residualPorts
				if from != "rogue" {
					allowed = append(slices.Clone(residualPorts), admittedPorts[target]...)
				}
				if extra := extraPorts(open, allowed); len(extra) > 0 {
					t.Errorf("a host network pod in %s reaches the ports %v of the node of %s beyond %v", from, extra, target, allowed)
				}
				for _, p := range extraPorts(open, residualPorts) {
					res := lastJSONLine(t, run([]string{"tlsdial", "--addr", fmt.Sprintf("%s:%d", ip, p), "--no-verify"}))
					t.Logf("an unauthenticated handshake from %s with %s:%d gave %v", from, target, p, res)
					if res["after"] == "data" {
						t.Errorf("%s:%d sent data to a client with no certificate: %v", target, p, res)
					}
				}
			}
		})
	}
}

// TestM7PrincipalLoopbackOnly dials the pod address of the principal on port 8443 from an m7 namespace of management. The principal
// listens only on its loopback address, so the dial does not connect. A control dial to the API service connects first, so a failed dial
// cannot come from broken pod networking.
func TestM7PrincipalLoopbackOnly(t *testing.T) {
	needProbeImage(t)
	_, ip, _ := principalPod(t)
	ns := m7Namespace(t, mgmtCluster, false)
	if got := dialFrom(t, mgmtCluster, ns, apiServiceIP(t, mgmtCluster), 443, 3*time.Second); got != "connected" {
		t.Fatalf("the control dial to the API service gave %q, want connected", got)
	}
	got := dialFrom(t, mgmtCluster, ns, ip, 8443, 3*time.Second)
	if got != "refused" && got != "timeout" {
		t.Errorf("the dial to the principal pod %s:8443 gave %q, want refused or timeout", ip, got)
	}
}

// watchLine is one line of netprobe watch.
type watchLine struct {
	MS     int64  `json:"ms"`
	Result string `json:"result"`
}

func parseWatch(t *testing.T, logs string) []watchLine {
	t.Helper()
	var out []watchLine
	for l := range strings.SplitSeq(strings.TrimSpace(logs), "\n") {
		var w watchLine
		if json.Unmarshal([]byte(l), &w) == nil && w.Result != "" {
			out = append(out, w)
		}
	}
	return out
}

// policyWindow returns the time of the last dial that connected, or -1 when none did.
func policyWindow(lines []watchLine) int64 {
	last := int64(-1)
	for _, l := range lines {
		if l.Result == "connected" {
			last = l.MS
		}
	}
	return last
}

// attestProbePod returns a pod that runs attestprobe as service account celld of its namespace, with the downward API environment.
func attestProbePod(name string, args []string) map[string]any {
	vol, mount := configMapMount(trustBundleMap)
	pod := testPod(name, attestprobeImage, args, []map[string]any{vol}, []map[string]any{mount})
	spec := pod["spec"].(map[string]any)
	spec["serviceAccountName"], spec["automountServiceAccountToken"] = celldAccount, true
	spec["containers"].([]any)[0].(map[string]any)["env"] = bindEnv()
	return pod
}

// TestM7PolicyWindow starts three pods at the same time in an m7 namespace of dev-cell-1 that has a default deny egress policy, which
// the test applies before the pods. Two run netprobe watch against 1.1.1.1:443 and the SPIRE node port of dev-cp. The third runs
// attestprobe --variant other-subject against the SPIRE server. kindnet applies a policy to a new pod after a delay, so the first dials
// can connect. The test records the time of the last dial that connected, requires that no dial after 10 s connects and that the
// last dial of each watch is blocked, and requires that the probe never ends with issued.
func TestM7PolicyWindow(t *testing.T) {
	needProbeImage(t)
	needAttestprobeImage(t)
	cell := celldCell
	ns := m7Namespace(t, cell, false)
	if _, err := kubectl(t, cell, celldRBAC(ns), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	copyTrustBundle(t, cell, ns)
	deny := `{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"m7-deny-egress"},"spec":{"podSelector":{},"policyTypes":["Egress"]}}`
	if _, err := kubectl(t, cell, deny, "-n", ns, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	spireAddr := fmt.Sprintf("%s:%d", clusterFacts(t, envCluster).NodeIP, spireNodePort)
	watchArgs := func(addr string) []string {
		return []string{"watch", "--addr", addr, "--interval", "100ms", "--for", "15s", "--timeout", "300ms"}
	}
	names := []string{m7PodName("watch-public"), m7PodName("watch-spire"), m7PodName("attest")}
	items := []any{
		testPod(names[0], probeImage, watchArgs("1.1.1.1:443"), nil, nil),
		testPod(names[1], probeImage, watchArgs(spireAddr), nil, nil),
		attestProbePod(names[2], []string{"--variant", "other-subject", "--cell", cell, "--env", pocEnv, "--server", spireAddr, "--timeout", "25s"}),
	}
	list, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": items})
	if _, err := kubectl(t, cell, string(list), "-n", ns, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	for i, target := range []string{"1.1.1.1:443", spireAddr} {
		phase, logs := podDone(t, cell, ns, names[i])
		lines := parseWatch(t, logs)
		if phase != "Succeeded" || len(lines) == 0 {
			t.Fatalf("watch of %s ended in phase %s with %d dials: %s", target, phase, len(lines), logs)
		}
		window := policyWindow(lines)
		t.Logf("policy window to %s: the last dial that connected was at %d ms of %d dials (-1 means none connected)", target, window, len(lines))
		if window >= 10_000 {
			t.Errorf("a dial to %s connected at %d ms, want every dial blocked within 10 s", target, window)
		}
		if end := lines[len(lines)-1]; end.Result == "connected" {
			t.Errorf("the last dial to %s at %d ms connected, so the policy did not block it", target, end.MS)
		}
	}
	phase, logs := podDone(t, cell, ns, names[2])
	out := strings.TrimSpace(lastOutputLine(logs))
	t.Logf("attestprobe --variant other-subject ended in phase %s with %q", phase, out)
	if strings.HasPrefix(out, "issued:") {
		t.Errorf("the probe of another subject got an SVID: %s", out)
	}
}
