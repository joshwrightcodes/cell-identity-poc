//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// planeClusters run a SPIRE server with the k8s_psat plugin for their plane workloads.
var planeClusters = []string{mgmtCluster, spireCluster}

// The management CA lives 90 days. A root that still has 60 days left after the M3 work date has
// not rotated within a run.
var mgmtRootMinNotAfter = time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC).Add(60 * 24 * time.Hour)

// checkMgmtRoots checks that each root of the management server is a CA of mgmt.poc.internal that
// lives past mgmtRootMinNotAfter.
func checkMgmtRoots(t *testing.T, roots []*x509.Certificate) {
	t.Helper()
	for i, r := range roots {
		if !r.IsCA || !r.BasicConstraintsValid {
			t.Errorf("root %d of %s is not a CA", i, mgmtCluster)
		}
		if len(r.URIs) != 1 || r.URIs[0].String() != "spiffe://"+mgmtTD {
			t.Errorf("root %d of %s has URI SANs %v, want spiffe://%s", i, mgmtCluster, r.URIs, mgmtTD)
		}
		if !r.NotAfter.After(mgmtRootMinNotAfter) {
			t.Errorf("root %d of %s expires at %s, want after %s", i, mgmtCluster, r.NotAfter.UTC(), mgmtRootMinNotAfter)
		}
	}
}

// noFederatedBundles checks that the server of a cluster trusts no other trust domain.
func noFederatedBundles(t *testing.T, cluster string) {
	t.Helper()
	out, err := spireServerIn(t, cluster, "bundle", "list", "-socketPath", spireSocket, "-output", "json")
	if err != nil {
		t.Fatalf("spire-server bundle list in %s: %v", cluster, err)
	}
	var res struct {
		Bundles []struct {
			TrustDomain string `json:"trust_domain"`
		} `json:"bundles"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode bundle list of %s %q: %v", cluster, out, err)
	}
	if len(res.Bundles) != 0 {
		t.Errorf("the server in %s holds federated bundles %v, want none", cluster, res.Bundles)
	}
}

// TestM3MgmtServerHealthy checks the management SPIRE server: it is Ready and healthy, its own root
// is a 90-day CA of mgmt.poc.internal, it signs an SVID that chains to that root, it serves its
// API with the server ID, and neither plane server trusts another trust domain.
func TestM3MgmtServerHealthy(t *testing.T) {
	statefulSetReady(t, mgmtCluster, spireNamespace, "spire-server")
	out, err := spireServerIn(t, mgmtCluster, "healthcheck", "-socketPath", spireSocket)
	if err != nil || strings.TrimSpace(out) != "Server is healthy." {
		t.Fatalf("spire-server healthcheck in %s: want %q, got %q, error %v", mgmtCluster, "Server is healthy.", out, err)
	}
	roots := bundleRoots(t, mgmtCluster)
	checkMgmtRoots(t, roots)
	for _, cluster := range planeClusters {
		noFederatedBundles(t, cluster)
	}

	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	certPEM, keyPEM := mintSVID(t, mgmtCluster, "spiffe://"+mgmtTD+"/m3-test/health", time.Minute)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("minted SVID: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("the minted SVID does not chain to the management root: %v", err)
	}

	// The server API presents spiffe://mgmt.poc.internal/spire/server from a chain to the root.
	addr := portForward(t, mgmtCluster, spireNamespace, "svc/spire-server", 8081)
	var serverID string
	cfg := &tls.Config{
		InsecureSkipVerify: true, // the callback below checks the chain against the management root
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, der := range raw[1:] {
				if c, err := x509.ParseCertificate(der); err == nil {
					inter.AddCert(c)
				}
			}
			if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				return err
			}
			if len(cert.URIs) == 1 {
				serverID = cert.URIs[0].String()
			}
			return nil
		},
		NextProtos: []string{"h2"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("TLS to the management server API through %s: %v", addr, err)
	}
	_ = conn.Close()
	if serverID != "spiffe://"+mgmtTD+"/spire/server" {
		t.Fatalf("the server API presents %q, want spiffe://%s/spire/server", serverID, mgmtTD)
	}

	// The collector of Task 10 scrapes the metrics port on the pod address.
	listeners := listenAddrs(t, mgmtCluster, spireNamespace, spireServerPod, "spire-server")
	for _, want := range []string{"0.0.0.0:8081", "0.0.0.0:9988"} {
		if !slices.Contains(listeners, want) && !slices.Contains(listeners, strings.Replace(want, "0.0.0.0", "*", 1)) {
			t.Errorf("the management server listens on %v, want %s", listeners, want)
		}
	}
}

// TestM3MgmtServerClosedToOtherPods dials the server from namespaces with no policy: the API on its
// ClusterIP and on its pod address, and the metrics port. Only the local plane workloads may reach
// the API, and no pod may reach the metrics port before the collector of a later task.
func TestM3MgmtServerClosedToOtherPods(t *testing.T) {
	needProbeImage(t)
	ip, err := kubectl(t, mgmtCluster, "", "-n", spireNamespace, "get", "service", "spire-server", "-o", "jsonpath={.spec.clusterIP}")
	if err != nil {
		t.Fatal(err)
	}
	podIP, err := kubectl(t, mgmtCluster, "", "-n", spireNamespace, "get", "pod", spireServerPod, "-o", "jsonpath={.status.podIP}")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		addr string
		port int
	}{{strings.TrimSpace(ip), 8081}, {strings.TrimSpace(podIP), 8081}, {strings.TrimSpace(podIP), 9988}} {
		if err := probeFromFreshNamespace(t, mgmtCluster, target.addr, target.port, 3*time.Second); err != nil {
			t.Error(err)
		}
	}
}

// TestM3PSATServerRBAC checks that the server of each plane can review tokens and read pods and
// nodes, which k8s_psat needs, and nothing more.
func TestM3PSATServerRBAC(t *testing.T) {
	for _, cluster := range planeClusters {
		t.Run(cluster, func(t *testing.T) {
			for _, c := range []struct {
				verb, resource string
				want           bool
			}{
				{"create", "tokenreviews.authentication.k8s.io", true},
				{"get", "pods", true},
				{"get", "nodes", true},
				{"list", "pods", false},
				{"list", "secrets", false},
				{"get", "secrets", false},
				{"create", "pods", false},
				{"create", "serviceaccounts/token", false},
			} {
				if got := canI(t, cluster, spireServerAccount, c.verb, c.resource, ""); got != c.want {
					t.Errorf("%s: can %s %s %s: got %v, want %v", cluster, spireServerAccount, c.verb, c.resource, got, c.want)
				}
			}
		})
	}
}

// TestM3ManagementHasNoSecretStore checks that a compromised dev-cp finds no secret manager token in
// management: no store of either kind, no Secret in the operator namespace, no copy of the token
// anywhere, and no internet egress for the operator.
func TestM3ManagementHasNoSecretStore(t *testing.T) {
	needProbeImage(t)
	out, err := kubectl(t, mgmtCluster, "", "get", "clustersecretstores.external-secrets.io", "-A", "-o", "json")
	switch {
	case err != nil && strings.Contains(err.Error(), "the server doesn't have a resource type"):
		t.Logf("management has no ClusterSecretStore resource type")
	case err != nil:
		t.Fatal(err)
	default:
		if n := countItems(t, out); n != 0 {
			t.Errorf("management has %d ClusterSecretStore objects", n)
		}
	}
	for _, list := range [][]string{
		{"get", "secretstores.external-secrets.io", "-A", "-o", "json"},
		{"-n", "external-secrets", "get", "secrets", "-o", "json"},
		{"get", "secrets", "-A", "--field-selector", "metadata.name=poc-secrets-token", "-o", "json"},
	} {
		out, err := kubectl(t, mgmtCluster, "", list...)
		if err != nil {
			t.Fatal(err)
		}
		if n := countItems(t, out); n != 0 {
			t.Errorf("kubectl %s: %d objects, want none", strings.Join(list, " "), n)
		}
	}
	dep, err := kubectl(t, mgmtCluster, "", "-n", "external-secrets", "get", "deployment", "external-secrets", "-o", "jsonpath={.spec.template.spec.containers[0].args}")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dep, `"--namespace=observability-system"`) {
		t.Errorf("the operator args are %s, want --namespace=observability-system", dep)
	}
	policies, err := kubectl(t, mgmtCluster, "", "-n", "external-secrets", "get", "networkpolicies", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(policies, `"0.0.0.0/0"`) {
		t.Errorf("a NetworkPolicy in external-secrets admits 0.0.0.0/0")
	}

	// An ephemeral container shares the network of the operator pod, so its policy applies. The API
	// service is the control: it must connect, so a timeout to 1.1.1.1 comes from the policy.
	pod, err := kubectl(t, mgmtCluster, "", "-n", "external-secrets", "get", "pods", "-l", "app.kubernetes.io/name=external-secrets",
		"-o", "jsonpath={.items[0].metadata.name}")
	if err != nil || strings.TrimSpace(pod) == "" {
		t.Fatalf("no operator pod in %s: %v", mgmtCluster, err)
	}
	t.Cleanup(func() {
		// The pod keeps its ephemeral containers, so the cleanup replaces it.
		if _, err := kubectl(t, mgmtCluster, "", "-n", "external-secrets", "delete", "pod", pod, "--wait=true", "--timeout=120s"); err != nil {
			t.Logf("cleanup: delete the operator pod %s: %v", pod, err)
		}
		if _, err := kubectl(t, mgmtCluster, "", "-n", "external-secrets", "rollout", "status", "deployment/external-secrets", "--timeout=180s"); err != nil {
			t.Logf("cleanup: the operator did not roll out again: %v", err)
		}
	})
	apiIP, err := kubectl(t, mgmtCluster, "", "-n", "default", "get", "service", "kubernetes", "-o", "jsonpath={.spec.clusterIP}")
	if err != nil {
		t.Fatal(err)
	}
	if got := ephemeralDial(t, mgmtCluster, "external-secrets", pod, strings.TrimSpace(apiIP)+":443", 5*time.Second); got != "connected" {
		t.Fatalf("the control dial from the operator pod to the API service gave %q, want connected", got)
	}
	// A pod with no policy must reach 1.1.1.1:443, or a timeout from the operator pod proves nothing.
	if got := dialFrom(t, mgmtCluster, freshNamespace(t, mgmtCluster), "1.1.1.1", 443, 5*time.Second); got != "connected" {
		t.Fatalf("the control dial to 1.1.1.1:443 from a namespace with no policy gave %q, want connected. Check the internet route of the VM", got)
	}
	start := time.Now()
	if got := ephemeralDial(t, mgmtCluster, "external-secrets", pod, "1.1.1.1:443", 5*time.Second); got != "timeout" {
		t.Fatalf("the dial from the operator pod to 1.1.1.1:443 gave %q, want a timeout", got)
	}
	t.Logf("the dial to 1.1.1.1:443 ended after %s", time.Since(start).Round(time.Millisecond))
}

func countItems(t *testing.T, out string) int {
	t.Helper()
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("decode list %q: %v", out, err)
	}
	return len(list.Items)
}

// ephemeralDial adds an ephemeral netprobe container with the restricted profile to a pod, dials
// addr once, and returns the result of netprobe dial.
func ephemeralDial(t *testing.T, cluster, ns, pod, addr string, timeout time.Duration) string {
	t.Helper()
	name := "m3-probe-" + randomHex(t, 4)
	t.Logf("dialing %s from the ephemeral container %s in %s/%s of %s", addr, name, ns, pod, cluster)
	if _, err := kubectl(t, cluster, "", "-n", ns, "debug", pod, "--image", probeImage, "--profile=restricted", "--container", name,
		"--arguments-only", "--", "dial", "--addr", addr, "--timeout", timeout.String()); err != nil {
		t.Fatal(err)
	}
	var logs string
	jsonpath := fmt.Sprintf(`jsonpath={.status.ephemeralContainerStatuses[?(@.name=="%s")].state.terminated.exitCode}`, name)
	waitFor(t, "ephemeral container "+name+" to finish", 2*time.Minute, func() (bool, string) {
		code, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", pod, "-o", jsonpath)
		if err != nil {
			return false, err.Error()
		}
		return strings.TrimSpace(code) != "", "not terminated yet"
	})
	logs, err := kubectl(t, cluster, "", "-n", ns, "logs", pod, "-c", name)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(logs)), &res); err != nil {
		t.Fatalf("netprobe dial in %s printed %q: %v", name, logs, err)
	}
	return res.Result
}

// TestM3MgmtRootSurvivesRestart restarts the management SPIRE server with cell:restart. The CA key
// lives on the data volume, so the server keeps its root, and every peer copy of it stays valid.
func TestM3MgmtRootSurvivesRestart(t *testing.T) {
	before := bundleRoots(t, mgmtCluster)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "../../scripts/restart.sh")
	cmd.Env = append(os.Environ(), "CELL="+mgmtCluster)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	t.Logf("running CELL=%s mise run cell:restart", mgmtCluster)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) || ctx.Err() != nil {
			t.Fatalf("cell:restart of %s: %v\n%s", mgmtCluster, err, out.String())
		}
		t.Fatal(err)
	}
	t.Log(strings.TrimSpace(out.String()))
	statefulSetReady(t, mgmtCluster, spireNamespace, "spire-server")
	after := bundleRoots(t, mgmtCluster)
	checkMgmtRoots(t, after)
	if !slices.EqualFunc(before, after, func(a, b *x509.Certificate) bool { return a.Equal(b) }) {
		t.Fatalf("the management roots changed across the restart: %d before, %d after", len(before), len(after))
	}
}
