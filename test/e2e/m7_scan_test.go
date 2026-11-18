//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
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

// TestM7CellPodScansOtherCell scans every TCP port of the node of dev-cell-2 from a pod in an m7 namespace of dev-cell-1. The namespace
// has no NetworkPolicy, as dev-cell-1/default has, and gate:m7:repair deletes it after a run that stops early. Only the residual ports of
// M1 answer.
func TestM7CellPodScansOtherCell(t *testing.T) {
	needProbeImage(t)
	from, to := celldCell, "dev-cell-2"
	ip := clusterFacts(t, to).NodeIP
	ns := m7Namespace(t, from, false)
	open := scanPorts(t, func(args []string) string { return runPod(t, from, ns, args) }, ip)
	t.Logf("open ports on %s (%s) from a pod in %s/%s: %v", to, ip, from, ns, open)
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

// admittedPorts lists the ports of a target node that admit the node address of a cell: the SPIRE server, the relays and the gateway
// listeners of dev-cp. management admits no cell node address.
var admittedPorts = map[string][]int{
	envCluster:  {30081, 30443, 30444, 30445, 30450, 30451},
	mgmtCluster: {},
}

// mtlsPorts are the admitted ports whose server requires a client certificate. An unauthenticated handshake ends in a TLS alert, or in
// a closed connection.
var mtlsPorts = []int{30443, 30444, 30445, 30450}

// TestM7HostNetworkScan scans the nodes of dev-cp and management from root host network pods in a privileged m7 namespace of rogue, and
// of dev-cell-1. Root host network pods pass kindnet policy, as poc-scope.md says, so the policies of the targets are the control. For
// each source and target, the set of open ports must equal the expected set exactly: the residual ports for rogue, and for a cell also
// the ports that admit the node address of a cell. Each mutual TLS port then answers a handshake with no certificate with a TLS alert or
// a closed connection. Ports 30081 (SPIRE server) and 30451 (bind listener) authenticate at the application layer, so a handshake
// without a certificate passes there, and a connection from a cell node refuses at the request. TestM2Reject* proves the SPIRE refusals,
// and TestM5BindRefusalsLive the bind refusals, so this test asserts only the set of ports for them.
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
				want := slices.Clone(residualPorts)
				if from != "rogue" {
					want = append(want, admittedPorts[target]...)
				}
				slices.Sort(want)
				if !slices.Equal(open, want) {
					t.Errorf("a host network pod in %s reaches the ports %v of the node of %s, want exactly %v", from, open, target, want)
				}
				for _, p := range mtlsPorts {
					if !slices.Contains(open, p) {
						continue
					}
					res := lastJSONLine(t, run([]string{"tlsdial", "--addr", fmt.Sprintf("%s:%d", ip, p), "--no-verify"}))
					after := fmt.Sprint(res["after"])
					t.Logf("a handshake with no certificate from %s to %s:%d gave %v", from, target, p, res)
					if !strings.HasPrefix(after, "alert:") && after != "closed" {
						t.Errorf("%s:%d answered a client with no certificate with %q, want a TLS alert or a closed connection", target, p, after)
					}
				}
			}
		})
	}
}

// TestM7PrincipalLoopbackOnly (row 29) dials the principal from an ephemeral container in the principal pod, which shares its network
// namespace, so no NetworkPolicy lies between the dial and the listener. A dial to 127.0.0.1:8443 must connect, as the control that the
// listener runs. A dial to the pod address on 8443 must be refused: the principal listens on its loopback address only. A timeout fails
// the test, because it would come from a policy and not from the listener.
func TestM7PrincipalLoopbackOnly(t *testing.T) {
	needProbeImage(t)
	pod, ip, _ := principalPod(t)
	if got := ephemeralDial(t, mgmtCluster, viewNamespace, pod, "127.0.0.1:8443", 5*time.Second); got != "connected" {
		t.Fatalf("the control dial to 127.0.0.1:8443 gave %q, want connected, so the principal does not listen there", got)
	}
	if got := ephemeralDial(t, mgmtCluster, viewNamespace, pod, net.JoinHostPort(ip, "8443"), 5*time.Second); got != "refused" {
		t.Errorf("the dial to the pod address %s:8443 gave %q, want refused", ip, got)
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

// runWatch runs netprobe watch in a pod of an m7 namespace for dur and returns its dials.
func runWatch(t *testing.T, cluster, ns, addr string, dur time.Duration) []watchLine {
	t.Helper()
	name := m7PodName("watch-control")
	args := []string{"watch", "--addr", addr, "--interval", "100ms", "--for", dur.String(), "--timeout", "300ms"}
	applyPod(t, cluster, ns, testPod(name, probeImage, args, nil, nil))
	phase, logs := podDone(t, cluster, ns, name)
	lines := parseWatch(t, logs)
	if phase != "Succeeded" || len(lines) == 0 {
		t.Fatalf("watch of %s ended in phase %s with %d dials: %s", addr, phase, len(lines), logs)
	}
	return lines
}

// TestM7PolicyWindow starts three pods at the same time in an m7 namespace of dev-cell-1 that has a policy that denies all egress, which
// the test applies before the pods. Two run netprobe watch against 1.1.1.1:443 and the SPIRE node port of dev-cp. The third runs
// attestprobe --variant other-subject against the SPIRE server. kindnet applies a policy to a new pod after a delay, so the first dials
// can connect. A control comes first: the same watch from an m7 namespace with no policy must connect to both targets, or the test
// fails, because a window of -1 would then mean only that the target is down. The test records the time of the last dial that
// connected, requires that no dial after 10 s connects and that the last dial of each watch is blocked, and reads every output line of
// the probe: the pod ends, no line holds issued, and the outcome is a failure or a subject_not_allowed denial.
func TestM7PolicyWindow(t *testing.T) {
	needProbeImage(t)
	needAttestprobeImage(t)
	cell := celldCell
	spireAddr := fmt.Sprintf("%s:%d", clusterFacts(t, envCluster).NodeIP, spireNodePort)
	targets := []string{"1.1.1.1:443", spireAddr}

	open := m7Namespace(t, cell, false)
	for _, target := range targets {
		for _, l := range runWatch(t, cell, open, target, 3*time.Second) {
			if l.Result != "connected" {
				t.Fatalf("the control watch of %s from %s/%s with no policy gave %q at %d ms, so a blocked dial in the test would prove nothing",
					target, cell, open, l.Result, l.MS)
			}
		}
	}

	ns := m7Namespace(t, cell, false)
	if _, err := kubectl(t, cell, celldRBAC(ns), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	copyTrustBundle(t, cell, ns)
	deny := `{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"m7-deny-egress"},"spec":{"podSelector":{},"policyTypes":["Egress"]}}`
	if _, err := kubectl(t, cell, deny, "-n", ns, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	watchArgs := func(addr string) []string {
		return []string{"watch", "--addr", addr, "--interval", "100ms", "--for", "15s", "--timeout", "300ms"}
	}
	names := []string{m7PodName("watch-public"), m7PodName("watch-spire"), m7PodName("attest")}
	items := []any{
		testPod(names[0], probeImage, watchArgs(targets[0]), nil, nil),
		testPod(names[1], probeImage, watchArgs(targets[1]), nil, nil),
		attestProbePod(names[2], []string{"--variant", "other-subject", "--cell", cell, "--env", pocEnv, "--server", spireAddr, "--bundle", "/run/m7/" + trustBundleMap + "/bundle.crt", "--timeout", "25s"}),
	}
	list, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": items})
	if _, err := kubectl(t, cell, string(list), "-n", ns, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	for i, target := range targets {
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
	t.Logf("attestprobe --variant other-subject ended in phase %s with %q", phase, logs)
	if phase != "Succeeded" && phase != "Failed" {
		t.Fatalf("the probe pod is in phase %s, want it ended", phase)
	}
	denied, failed := false, false
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		if strings.Contains(l, "issued:") {
			t.Errorf("the probe of another subject got an SVID: %s", l)
		}
		denied = denied || (strings.HasPrefix(l, "denied:") && strings.Contains(l, "subject_not_allowed"))
		var rec map[string]any
		failed = failed || (json.Unmarshal([]byte(l), &rec) == nil && blockedDialError(fmt.Sprint(rec["error"])))
	}
	if !denied && !failed {
		t.Errorf("the probe output %q holds neither a subject_not_allowed denial nor an error line, so it did not run to an outcome", logs)
	}
}

// blockedDialError reports whether an error text is a dial that the network stopped: a timeout or a refused connection. Any other
// error, such as a failed token request, means the probe did not reach the attestation step.
func blockedDialError(s string) bool {
	for _, k := range []string{"i/o timeout", "context deadline exceeded", "DeadlineExceeded", "connection refused", "Unavailable"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}
