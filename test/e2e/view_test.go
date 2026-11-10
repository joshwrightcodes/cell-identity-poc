//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	viewNamespace  = "central-view-system"
	principalName  = "argocd-agent-principal"
	principalID    = "spiffe://mgmt.poc.internal/argocd/principal"
	viewListener   = "view-listener"
	viewNodePort   = 31443
	viewCellProxy  = "cell-proxy"
	envCluster     = "dev-cp"
	envTrustDomain = "dev.env.poc.internal"
)

// viewCells are the cells of VIEW_CELLS, which TestViewCellsMatchTopology ties to the clusters with
// the cell-identity set.
func viewCells(t *testing.T) []string {
	t.Helper()
	return clustersWith(t, agentCellSet)
}

// centralAPI reads path from the central argocd-server through a port-forward, with no credential.
// The anonymous user must get HTTP 200.
func centralAPI(t *testing.T, path string) []byte {
	t.Helper()
	// portForward matches the container port, and Service argocd-server maps port 80 to 8080.
	addr := portForward(t, mgmtCluster, viewNamespace, "deploy/argocd-server", 8080)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("http://" + addr + path)
	if err != nil {
		t.Fatalf("GET %s from the central argocd-server: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: HTTP %d, want 200 for the anonymous user: %s", path, resp.StatusCode, body)
	}
	return body
}

// principalPod returns the name and pod address of the Ready principal pod.
func principalPod(t *testing.T) (name, ip, uid string) {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+principalName, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var pods struct {
		Items []struct {
			Metadata struct{ Name, UID string } `json:"metadata"`
			Status   struct {
				PodIP      string `json:"podIP"`
				Conditions []struct{ Type, Status string } `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &pods); err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		for _, c := range p.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				return p.Metadata.Name, p.Status.PodIP, p.Metadata.UID
			}
		}
	}
	t.Fatalf("no Ready principal pod in %s/%s", mgmtCluster, viewNamespace)
	return "", "", ""
}

func deploymentReady(t *testing.T, ns, name string) (bool, string) {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", ns, "get", "deployment", name, "-o", "json")
	if err != nil {
		return false, err.Error()
	}
	var d struct {
		Metadata struct{ Generation int } `json:"metadata"`
		Spec     struct{ Replicas int }   `json:"spec"`
		Status   struct {
			ObservedGeneration, ReadyReplicas, UpdatedReplicas, Replicas int
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		return false, err.Error()
	}
	s := d.Status
	return s.ObservedGeneration == d.Metadata.Generation && s.ReadyReplicas == d.Spec.Replicas && s.UpdatedReplicas == d.Spec.Replicas && s.Replicas == d.Spec.Replicas,
		fmt.Sprintf("replicas %d, ready %d, updated %d", d.Spec.Replicas, s.ReadyReplicas, s.UpdatedReplicas)
}

// TestM3PrincipalUp checks that the principal is Ready, that it logs only JSON, and that each
// agent namespace exists with its default deny.
func TestM3PrincipalUp(t *testing.T) {
	waitFor(t, "Deployment "+principalName+" Ready", statefulsetWait, func() (bool, string) {
		return deploymentReady(t, viewNamespace, principalName)
	})
	pod, _, _ := principalPod(t)
	logs, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "logs", pod, "-c", principalName)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("the principal wrote no log line")
	}
	for _, l := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil || rec["level"] == nil || rec["msg"] == nil {
			t.Fatalf("principal log line is no JSON record with level and msg: %q", l)
		}
	}
	for _, cell := range viewCells(t) {
		ns := pocEnv + "-" + cell
		if _, err := kubectl(t, mgmtCluster, "", "get", "namespace", ns); err != nil {
			t.Errorf("agent namespace %s: %v", ns, err)
		}
		out, err := kubectl(t, mgmtCluster, "", "-n", ns, "get", "networkpolicy", "default-deny", "-o", "json")
		if err != nil {
			t.Errorf("agent namespace %s has no default-deny: %v", ns, err)
			continue
		}
		var np struct {
			Spec struct {
				PodSelector map[string]any `json:"podSelector"`
				PolicyTypes []string       `json:"policyTypes"`
				Ingress     []any          `json:"ingress"`
				Egress      []any          `json:"egress"`
			} `json:"spec"`
		}
		if err := json.Unmarshal([]byte(out), &np); err != nil {
			t.Fatal(err)
		}
		if len(np.Spec.PodSelector) != 0 || len(np.Spec.Ingress)+len(np.Spec.Egress) != 0 ||
			!slices.Contains(np.Spec.PolicyTypes, "Ingress") || !slices.Contains(np.Spec.PolicyTypes, "Egress") {
			t.Errorf("%s/default-deny is not a deny of all traffic: %+v", ns, np.Spec)
		}
	}
}

// TestM3PrincipalBinds checks that the gRPC port 8443 listens only on 127.0.0.1 in the principal
// pod. It logs the addresses of the other ports for the residual list.
func TestM3PrincipalBinds(t *testing.T) {
	pod, _, _ := principalPod(t)
	addrs := listenAddrs(t, mgmtCluster, viewNamespace, pod, principalName)
	var grpc []string
	for _, a := range addrs {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			t.Fatalf("listener %q: %v", a, err)
		}
		switch port {
		case "8443":
			grpc = append(grpc, host)
		case "9090", "6379", "8000", "8003", "8444":
			t.Logf("port %s listens on %s", port, host)
		}
	}
	if len(grpc) == 0 {
		t.Fatalf("nothing listens on 8443: %v", addrs)
	}
	for _, h := range grpc {
		if h != "127.0.0.1" {
			t.Errorf("port 8443 listens on %s, want 127.0.0.1 only: %v", h, addrs)
		}
	}
}

// TestM3CentralPortsFromFreshNamespace dials the ports of the view from a namespace with no
// policy. Each dial must time out: cell-proxy and the principal ports, argocd-server and argocd-redis.
func TestM3CentralPortsFromFreshNamespace(t *testing.T) {
	needProbeImage(t)
	_, principalIP, _ := principalPod(t)
	podIP := func(name string) string {
		ip, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+name,
			"-o", "jsonpath={.items[0].status.podIP}")
		if err != nil || strings.TrimSpace(ip) == "" {
			t.Fatalf("no pod address for %s: %v", name, err)
		}
		return strings.TrimSpace(ip)
	}
	targets := []struct {
		addr string
		port int
	}{
		{principalIP, 8444}, {principalIP, 9090}, {principalIP, 6379}, {principalIP, 8000}, {principalIP, 8003},
		{podIP("argocd-server"), 8080}, {podIP("argocd-redis"), 6379},
	}
	for _, target := range targets {
		if err := probeFromFreshNamespace(t, mgmtCluster, target.addr, target.port, 3*time.Second); err != nil {
			t.Error(err)
		}
	}
}

// viewDial makes one mTLS handshake to the view listener with cert, and checks the server ID. It
// then sends the HTTP/2 preface and reads once. It returns nil when the server answered, so it
// accepted the peer, and the error otherwise. TLS 1.3 finishes the client side of the handshake
// before the server checks the client, so only the read shows a refusal.
func viewDial(t *testing.T, addr string, cert tls.Certificate, roots *x509.CertPool) error {
	t.Helper()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert},
		// SPIFFE certificates carry no DNS name, so the callback checks the chain and the URI.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			var chain []*x509.Certificate
			for _, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				chain = append(chain, c)
			}
			inter := x509.NewCertPool()
			for _, c := range chain[1:] {
				inter.AddCert(c)
			}
			if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				return err
			}
			if len(chain[0].URIs) != 1 || chain[0].URIs[0].String() != principalID {
				return fmt.Errorf("server ID %v, want %s", chain[0].URIs, principalID)
			}
			return nil
		},
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		return fmt.Errorf("ALPN %q, want h2", p)
	}
	// The client preface and an empty SETTINGS frame.
	if _, err := conn.Write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0)); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 9)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	return nil
}

// selfSigned makes a self-signed certificate with the URI SAN id.
func selfSigned(t *testing.T, id string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestM3ViewListenerIdentity connects to the view listener with SVIDs from the dev-cp server. Only
// the argocd-agent ID of a registered cell gets an answer. The cell-proxy log names the reason of
// each refusal.
func TestM3ViewListenerIdentity(t *testing.T) {
	roots := x509.NewCertPool()
	for _, c := range bundleRoots(t, mgmtCluster) {
		roots.AddCert(c)
	}
	addr := portForward(t, mgmtCluster, viewNamespace, "svc/"+viewListener, 8444)
	pod, _, _ := principalPod(t)
	since := time.Now().Add(-2 * time.Second)
	svid := func(id string) tls.Certificate {
		certPEM, keyPEM := mintSVID(t, envCluster, id, 10*time.Minute)
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	good := "spiffe://" + envTrustDomain + "/cell/dev-cell-1/argocd-agent"
	if err := viewDial(t, addr, svid(good), roots); err != nil {
		t.Fatalf("%s: %v, want an answer", good, err)
	}
	refused := map[string]tls.Certificate{
		"spiffe://" + envTrustDomain + "/cell/rogue/argocd-agent": svid("spiffe://" + envTrustDomain + "/cell/rogue/argocd-agent"),
		"spiffe://" + envTrustDomain + "/cell/dev-cell-1/celld":   svid("spiffe://" + envTrustDomain + "/cell/dev-cell-1/celld"),
		"self-signed " + good: selfSigned(t, good),
	}
	for name, cert := range refused {
		if err := viewDial(t, addr, cert, roots); err == nil {
			t.Errorf("%s got an answer, want a refusal", name)
		} else {
			t.Logf("%s: refused: %v", name, err)
		}
	}
	want := map[string]string{
		"spiffe://" + envTrustDomain + "/cell/rogue/argocd-agent": "peer_not_allowed",
		"spiffe://" + envTrustDomain + "/cell/dev-cell-1/celld":   "peer_not_allowed",
		good: "peer_untrusted",
	}
	waitFor(t, "the cell-proxy refusal lines", time.Minute, func() (bool, string) {
		logs, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "logs", pod, "-c", viewCellProxy, "--since-time="+since.UTC().Format(time.RFC3339))
		if err != nil {
			return false, err.Error()
		}
		var missing []string
		for id, reason := range want {
			found := false
			for l := range strings.SplitSeq(logs, "\n") {
				var rec map[string]any
				if json.Unmarshal([]byte(l), &rec) != nil {
					continue
				}
				if rec["reason"] == reason && (rec["spiffe_id"] == id || rec["unverified_spiffe_id"] == id) {
					found = true
				}
			}
			if !found {
				missing = append(missing, reason+" for "+id)
			}
		}
		return len(missing) == 0, "missing: " + strings.Join(missing, "; ")
	})
}

// TestM3ViewNodePortAdmission dials the view node port of management from a pod in dev-cp, in
// dev-cell-1 and in rogue. Only the dev-cp node address may connect.
func TestM3ViewNodePortAdmission(t *testing.T) {
	needProbeImage(t)
	ip := clusterFacts(t, mgmtCluster).NodeIP
	if net.ParseIP(ip) == nil {
		t.Fatalf("management node address %q", ip)
	}
	for cluster, want := range map[string]string{envCluster: "connected", "dev-cell-1": "timeout", "rogue": "timeout"} {
		t.Run(cluster, func(t *testing.T) {
			ns := freshNamespace(t, cluster)
			if got := dialFrom(t, cluster, ns, ip, viewNodePort, 3*time.Second); got != want {
				t.Errorf("dial from %s to %s:%d gave %q, want %q", cluster, ip, viewNodePort, got, want)
			}
		})
	}
}

// TestM3PeerRootPinnedInManagement checks that ConfigMap peer-root holds the roots of the live
// dev-cp server, and that the principal pod carries their SHA-256.
func TestM3PeerRootPinnedInManagement(t *testing.T) {
	data, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "get", "configmap", "peer-root", "-o", "jsonpath={.data.root\\.crt}")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rest := []byte(data); ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		got = append(got, hex.EncodeToString(b.Bytes))
	}
	var want []string
	for _, c := range bundleRoots(t, envCluster) {
		want = append(want, hex.EncodeToString(c.Raw))
	}
	slices.Sort(got)
	slices.Sort(want)
	if len(got) == 0 || !slices.Equal(got, want) {
		t.Fatalf("peer-root holds %d roots, and dev-cp bundle show prints %d other roots", len(got), len(want))
	}
	sum := sha256.Sum256([]byte(strings.TrimRight(data, "\n")))
	ann, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "get", "deployment", principalName,
		"-o", `jsonpath={.spec.template.metadata.annotations.poc\.internal/peer-root-sha256}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(ann) != hex.EncodeToString(sum[:]) {
		t.Fatalf("pod annotation %q, want the SHA-256 %x of root.crt", ann, sum)
	}
}

// TestM3ArgoCDServerReadOnlyRBAC checks that argocd-server can read Secrets and ConfigMaps in its
// namespace, and change none.
func TestM3ArgoCDServerReadOnlyRBAC(t *testing.T) {
	as := "system:serviceaccount:" + viewNamespace + ":argocd-server"
	for _, resource := range []string{"secrets", "configmaps"} {
		if !canI(t, mgmtCluster, as, "get", resource, viewNamespace) {
			t.Errorf("argocd-server cannot get %s, so the check below proves nothing", resource)
		}
		for _, verb := range []string{"create", "update", "patch", "delete"} {
			if canI(t, mgmtCluster, as, verb, resource, viewNamespace) {
				t.Errorf("argocd-server can %s %s in %s", verb, resource, viewNamespace)
			}
		}
	}
}

// TestM3ViewWritesInAgentNamespaces checks the writes of the view ServiceAccounts in each agent
// namespace. argocd-server writes nothing there. The principal writes only Applications, which it
// stores for the autonomous agents (vendor/README.md lists each call in v0.10.0).
func TestM3ViewWritesInAgentNamespaces(t *testing.T) {
	server := "system:serviceaccount:" + viewNamespace + ":argocd-server"
	principal := "system:serviceaccount:" + viewNamespace + ":" + principalName
	for _, cell := range viewCells(t) {
		ns := pocEnv + "-" + cell
		if !canI(t, mgmtCluster, server, "get", "applications.argoproj.io", ns) {
			t.Errorf("argocd-server cannot read the Applications of %s, so the checks below prove nothing", ns)
		}
		for _, resource := range []string{"applications.argoproj.io", "appprojects.argoproj.io", "applicationsets.argoproj.io", "secrets"} {
			for _, verb := range []string{"create", "update", "patch", "delete"} {
				if canI(t, mgmtCluster, server, verb, resource, ns) {
					t.Errorf("argocd-server can %s %s in %s", verb, resource, ns)
				}
				want := resource == "applications.argoproj.io"
				if got := canI(t, mgmtCluster, principal, verb, resource, ns); got != want {
					t.Errorf("the principal can %s %s in %s: %v, want %v", verb, resource, ns, got, want)
				}
			}
		}
	}
}

// TestM3CentralAPIReadOnly reads the central API as the anonymous user. It may list Applications
// and may not sync one.
func TestM3CentralAPIReadOnly(t *testing.T) {
	var apps struct {
		Items []any `json:"items"`
	}
	if err := json.Unmarshal(centralAPI(t, "/api/v1/applications"), &apps); err != nil {
		t.Fatalf("applications: %v", err)
	}
	t.Logf("the central view lists %d Applications", len(apps.Items))
	for _, path := range []string{"applications/sync/*", "applications/update/*", "applications/delete/*", "applications/override/*",
		"applications/action/*/*", "exec/create/*"} {
		var can struct{ Value string }
		if err := json.Unmarshal(centralAPI(t, "/api/v1/account/can-i/"+path), &can); err != nil {
			t.Fatal(err)
		}
		if can.Value != "no" {
			t.Errorf("the anonymous user can %s: %q", path, can.Value)
		}
	}
	// The cluster Secrets hold the client keys of the resource proxy. The API must not show them.
	clusters := string(centralAPI(t, "/api/v1/clusters"))
	if strings.Contains(clusters, "keyData") || strings.Contains(clusters, "PRIVATE KEY") || strings.Contains(clusters, "LS0tLS1CRUdJTi") {
		t.Error("the anonymous cluster list holds key material")
	}
}

func secretSum(t *testing.T, name string) string {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "get", "secret", name, "-o", "jsonpath={.data}")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(out))
	return hex.EncodeToString(sum[:])
}

func podUID(t *testing.T, name string) string {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+name, "-o", "jsonpath={.items[*].metadata.uid}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// TestM3ViewKeysRotate runs view:rotate-keys. The agent JWT key and the Redis password change, and
// the principal and argocd-server are Ready with new pods.
func TestM3ViewKeysRotate(t *testing.T) {
	names := []string{"argocd-agent-jwt", "argocd-redis", "argocd-agent-ca", "argocd-agent-resource-proxy-tls", "argocd-secret"}
	for _, cell := range viewCells(t) {
		names = append(names, "cluster-"+pocEnv+"-"+cell)
	}
	before := map[string]string{}
	for _, n := range names {
		before[n] = secretSum(t, n)
	}
	principalUID, serverUID := podUID(t, principalName), podUID(t, "argocd-server")
	cmd := exec.Command("mise", "run", "view:rotate-keys")
	cmd.Dir = "../.."
	var stderr lockedBuffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("view:rotate-keys: %v\n%s", err, stderr.String())
	}
	// mise prints its own lines on standard error, so standard output is the data line alone.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var res struct{ Restarted []string }
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &res) != nil || len(res.Restarted) != 4 {
		t.Fatalf("view:rotate-keys printed %q, want one JSON line with four restarted workloads", out)
	}
	for _, n := range names {
		if secretSum(t, n) == before[n] {
			t.Errorf("Secret %s kept its content", n)
		}
	}
	for name, old := range map[string]string{principalName: principalUID, "argocd-server": serverUID} {
		waitFor(t, name+" Ready", statefulsetWait, func() (bool, string) { return deploymentReady(t, viewNamespace, name) })
		if uid := podUID(t, name); uid == old || uid == "" {
			t.Errorf("%s has the pod %q, want a new pod", name, uid)
		}
	}
}
