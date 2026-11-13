//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	mgmtCluster = "management"
	mgmtTD      = "mgmt.poc.internal"
	// spireServerAccount is the ServiceAccount of the SPIRE server in each plane.
	spireServerAccount = "system:serviceaccount:spire-system:spire-server"
)

// spireServerIn runs the spire-server binary in the server container of a cluster and returns its
// standard output.
func spireServerIn(t *testing.T, cluster string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"-n", spireNamespace, "exec", spireServerPod, "-c", "spire-server", "--", spireBinary}, args...)
	return kubectl(t, cluster, "", full...)
}

// mintSVID runs spire-server x509 mint in the server pod of a cluster. The key stays in memory: the
// command prints it on standard output, and no file holds it. Tests build a tls.Certificate with
// tls.X509KeyPair.
func mintSVID(t *testing.T, cluster, id string, ttl time.Duration) (certPEM, keyPEM []byte) {
	t.Helper()
	t.Logf("minting an X.509 SVID for %s in %s, valid for %s", id, cluster, ttl)
	out, err := spireServerIn(t, cluster, "x509", "mint", "-socketPath", spireSocket, "-spiffeID", id, "-ttl", ttl.String(), "-output", "json")
	if err != nil {
		// The output holds the key, so the failure shows only the error.
		t.Fatalf("spire-server x509 mint for %s in %s: %v", id, cluster, err)
	}
	var res struct {
		X509SVID   [][]byte `json:"x509_svid"`
		PrivateKey []byte   `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.X509SVID) == 0 || len(res.PrivateKey) == 0 {
		t.Fatalf("spire-server x509 mint for %s in %s: want JSON with a certificate chain and a key, decode error %v", id, cluster, err)
	}
	for _, der := range res.X509SVID {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: res.PrivateKey})
}

// bundleRoots returns the X.509 roots that the SPIRE server of a cluster prints with bundle show.
func bundleRoots(t *testing.T, cluster string) []*x509.Certificate {
	t.Helper()
	out, err := spireServerIn(t, cluster, "bundle", "show", "-socketPath", spireSocket, "-format", "pem")
	if err != nil {
		t.Fatalf("spire-server bundle show in %s: %v", cluster, err)
	}
	var roots []*x509.Certificate
	for rest := []byte(out); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("bundle show in %s: parse certificate: %v", cluster, err)
		}
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		t.Fatalf("bundle show in %s printed no certificate: %q", cluster, out)
	}
	return roots
}

var forwardAnyLine = regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:(\d+) -> (\d+)$`)

// portForward starts kubectl port-forward to target (for example svc/spire-server) on a free local
// port, and returns 127.0.0.1:<local port>. The forward stops when the test ends.
func portForward(t *testing.T, cluster, ns, target string, port int) string {
	t.Helper()
	cmd := exec.Command("kubectl", "--context", "kind-"+cluster, "-n", ns, "port-forward", "--address", "127.0.0.1", target, ":"+strconv.Itoa(port))
	var stderr lockedBuffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the port-forward to %s/%s in %s: %v", ns, target, cluster, err)
	}
	readDone := make(chan struct{})
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-readDone:
		case <-time.After(forwardWait):
			t.Logf("the port-forward output did not end within %s of the kill", forwardWait)
		}
		_ = cmd.Wait()
	})
	local := make(chan string, 1)
	go func() {
		defer close(readDone)
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if m := forwardAnyLine.FindStringSubmatch(s.Text()); m != nil && m[2] == strconv.Itoa(port) {
				local <- m[1]
				break
			}
		}
		for s.Scan() {
		}
	}()
	select {
	case p := <-local:
		addr := "127.0.0.1:" + p
		t.Logf("port-forward %s -> %s/%s:%d in %s", addr, ns, target, port, cluster)
		return addr
	case <-time.After(forwardWait):
		t.Fatalf("waited %s for the port-forward to %s/%s in %s, stderr: %s", forwardWait, ns, target, cluster, stderr.String())
	}
	return ""
}

// freshNamespace makes namespace m3-probe-<random> with Pod Security restricted and no
// NetworkPolicy. It goes away when the test ends.
func freshNamespace(t *testing.T, cluster string) string {
	t.Helper()
	ns := "m3-probe-" + randomHex(t, 4)
	t.Logf("made the fresh namespace %s in %s", ns, cluster)
	createNamespace(t, cluster, ns)
	return ns
}

// dialFrom dials addr:port once from a netprobe pod in ns, and returns the netprobe result:
// connected, refused, timeout or error.
func dialFrom(t *testing.T, cluster, ns, addr string, port int, timeout time.Duration) string {
	t.Helper()
	if net.ParseIP(addr) == nil {
		t.Fatalf("dial address %q is not an IP address; netprobe dial takes no name", addr)
	}
	out := runPod(t, cluster, ns, []string{"dial", "--addr", net.JoinHostPort(addr, strconv.Itoa(port)), "--timeout", timeout.String()})
	var res struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil {
		t.Fatalf("netprobe dial printed %q: %v", out, err)
	}
	t.Logf("dial from %s/%s to %s:%d: %s", cluster, ns, addr, port, res.Result)
	return res.Result
}

// apiServiceIP returns the ClusterIP of Service kubernetes in a cluster.
func apiServiceIP(t *testing.T, cluster string) string {
	t.Helper()
	ip, err := kubectl(t, cluster, "", "-n", "default", "get", "service", "kubernetes", "-o", "jsonpath={.spec.clusterIP}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(ip)
}

// probeFromFreshNamespace makes a fresh namespace, and dials addr:port once from a netprobe pod
// there. It returns nil when the dial timed out, which is what a NetworkPolicy drop gives, and an
// error with the result otherwise. First, a control dial to the API service must connect from the
// same namespace, so a timeout cannot come from broken pod networking.
func probeFromFreshNamespace(t *testing.T, cluster, addr string, port int, timeout time.Duration) error {
	t.Helper()
	ns := freshNamespace(t, cluster)
	t.Logf("probing %s:%d from %s in %s", addr, port, ns, cluster)
	if got := dialFrom(t, cluster, ns, apiServiceIP(t, cluster), 443, timeout); got != "connected" {
		return fmt.Errorf("the control dial from %s/%s to the API service gave %q, want connected, so a timeout would prove nothing", cluster, ns, got)
	}
	if got := dialFrom(t, cluster, ns, addr, port, timeout); got != "timeout" {
		return fmt.Errorf("the dial from %s/%s to %s:%d gave %q, want a timeout", cluster, ns, addr, port, got)
	}
	return nil
}

// listenAddrs returns the local addresses of the TCP listeners in the network namespace of one
// container, from ss on the node.
func listenAddrs(t *testing.T, cluster, ns, pod, container string) []string {
	t.Helper()
	jsonpath := fmt.Sprintf(`jsonpath={.status.containerStatuses[?(@.name=="%s")].containerID}`, container)
	id, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", pod, "-o", jsonpath)
	if err != nil {
		t.Fatal(err)
	}
	id = strings.TrimPrefix(strings.TrimSpace(id), "containerd://")
	if id == "" {
		t.Fatalf("pod %s/%s in %s has no container %s", ns, pod, cluster, container)
	}
	node := cluster + "-control-plane"
	pid, err := dockerExec(t, node, "", "crictl", "inspect", "--output", "go-template", "--template", "{{.info.pid}}", id)
	if err != nil {
		t.Fatalf("read the process of %s/%s/%s on %s: %v", ns, pod, container, node, err)
	}
	pid = strings.TrimSpace(pid)
	out, err := dockerExec(t, node, "", "nsenter", "-t", pid, "-n", "ss", "-ltnH")
	if err != nil {
		t.Fatalf("list the listeners of %s/%s/%s (process %s) on %s: %v", ns, pod, container, pid, node, err)
	}
	var addrs []string
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if fields := strings.Fields(line); len(fields) >= 4 {
			addrs = append(addrs, fields[3])
		}
	}
	t.Logf("%s/%s/%s in %s listens on %v", ns, pod, container, cluster, addrs)
	return addrs
}

// canI runs kubectl auth can-i as a user. An empty ns asks for every namespace.
func canI(t *testing.T, cluster, as, verb, resource, ns string) bool {
	t.Helper()
	return canISub(t, cluster, as, verb, resource, "", ns)
}

// canISub is canI for a subresource. kubectl reads "pods/portforward" as the pod named portforward, so a
// subresource needs its own flag.
func canISub(t *testing.T, cluster, as, verb, resource, subresource, ns string) bool {
	t.Helper()
	args := []string{"--context", "kind-" + cluster, "auth", "can-i", verb, resource, "--as", as}
	if subresource != "" {
		args = append(args, "--subresource="+subresource)
	}
	if ns == "" {
		args = append(args, "--all-namespaces")
	} else {
		args = append(args, "-n", ns)
	}
	ctx, cancel := context.WithTimeout(context.Background(), kubectlTimeout)
	defer cancel()
	// can-i exits with 1 when the answer is no, so the answer comes from standard output.
	out, _ := exec.CommandContext(ctx, "kubectl", args...).Output()
	answer := strings.TrimSpace(string(out))
	if answer != "yes" && answer != "no" {
		t.Fatalf("kubectl %s: want yes or no, got %q", strings.Join(args, " "), answer)
	}
	t.Logf("%s: can %s %s %s in %q: %s", cluster, as, verb, resource, ns, answer)
	return answer == "yes"
}

// statefulSetReady waits until a StatefulSet has every replica Ready at its update revision.
func statefulSetReady(t *testing.T, cluster, ns, name string) {
	t.Helper()
	waitFor(t, fmt.Sprintf("StatefulSet %s/%s in %s Ready with every replica updated", ns, name, cluster), statefulsetWait, func() (bool, string) {
		out, err := kubectl(t, cluster, "", "-n", ns, "get", "statefulset", name, "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var sts struct {
			Spec   struct{ Replicas int } `json:"spec"`
			Status struct {
				ReadyReplicas   int    `json:"readyReplicas"`
				UpdatedReplicas int    `json:"updatedReplicas"`
				CurrentRevision string `json:"currentRevision"`
				UpdateRevision  string `json:"updateRevision"`
			} `json:"status"`
		}
		if err := json.Unmarshal([]byte(out), &sts); err != nil {
			return false, fmt.Sprintf("decode StatefulSet: %v", err)
		}
		s := sts.Status
		return sts.Spec.Replicas > 0 && s.ReadyReplicas == sts.Spec.Replicas && s.UpdatedReplicas == sts.Spec.Replicas &&
				s.CurrentRevision == s.UpdateRevision,
			fmt.Sprintf("replicas %d, ready %d, updated %d, revision %s of %s", sts.Spec.Replicas, s.ReadyReplicas, s.UpdatedReplicas, s.CurrentRevision, s.UpdateRevision)
	})
}

// principalEvent is one line of the principal log about the stream of an agent.
type principalEvent struct {
	at        time.Time
	connected bool
	line      string
}

// lastPrincipalEvent returns the last line of the principal log that opens or closes the event
// stream of agent: "An agent connected to the subscription stream" or "Closing EventStream".
func lastPrincipalEvent(t *testing.T, agent string) (principalEvent, bool, error) {
	t.Helper()
	pod, _, _ := principalPod(t)
	logs, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "logs", pod, "-c", principalName)
	if err != nil {
		return principalEvent{}, false, err
	}
	var last principalEvent
	found := false
	for l := range strings.SplitSeq(logs, "\n") {
		var rec struct {
			Msg, Client, Time string
		}
		if json.Unmarshal([]byte(l), &rec) != nil || rec.Client != agent {
			continue
		}
		if rec.Msg != "An agent connected to the subscription stream" && rec.Msg != "Closing EventStream" {
			continue
		}
		at, _ := time.Parse(time.RFC3339, rec.Time)
		last, found = principalEvent{at: at, connected: rec.Msg != "Closing EventStream", line: l}, true
	}
	return last, found, nil
}

// viewConnectedSince reports whether the principal lists agent as connected, with a stream that
// opened at or after since.
func viewConnectedSince(t *testing.T, agent string, since time.Time) (bool, string) {
	t.Helper()
	ev, found, err := lastPrincipalEvent(t, agent)
	switch {
	case err != nil:
		return false, err.Error()
	case !found:
		return false, "the principal log has no stream line for " + agent
	case !ev.connected:
		return false, "the last stream line of " + agent + " closes the stream: " + ev.line
	case ev.at.Before(since.Truncate(time.Second)):
		return false, fmt.Sprintf("the stream of %s opened at %s, before %s: %s", agent, ev.at.Format(time.RFC3339), since.UTC().Format(time.RFC3339), ev.line)
	}
	return true, ev.line
}

// requireViewConnected fails at once, with the principal log line, when the principal does not
// list agent as connected.
func requireViewConnected(t *testing.T, agent string) {
	t.Helper()
	if ok, detail := viewConnectedSince(t, agent, time.Time{}); !ok {
		t.Fatalf("the principal does not list %s as connected: %s", agent, detail)
	}
}
