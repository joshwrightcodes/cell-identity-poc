//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// m7Prefix starts the name of every namespace that an M7 test makes. gate:m7:repair deletes each namespace with this prefix.
const m7Prefix = "m7-"

// impostorPortNumber is the port of netprobe tlsserve, and flipPortNumber the port of flipforward, in the pods of the M7 tests.
const (
	impostorPortNumber = 8443
	flipPortNumber     = 9443
)

var m7PodCounter atomic.Int64

// m7Namespace makes namespace m7-<random> in a cluster, with the label cell.poc.internal/e2e=true, and deletes it when the test ends.
// Pod Security is restricted, or privileged for a test that needs the host network. No test changes the label of a namespace that a bundle owns.
func m7Namespace(t *testing.T, cluster string, privileged bool) string {
	t.Helper()
	ns := m7Prefix + randomHex(t, 4)
	level := "restricted"
	if privileged {
		level = "privileged"
	}
	t.Logf("made the namespace %s in %s with Pod Security %s", ns, cluster, level)
	createNamespaceAt(t, cluster, ns, level)
	return ns
}

// m7PodName returns a pod name that no other pod of this run has.
func m7PodName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, m7PodCounter.Add(1))
}

// copyConfigMap copies ConfigMap name from one namespace to another, in the same cluster or another one, under the same name.
func copyConfigMap(t *testing.T, srcCluster, srcNS, name, dstCluster, dstNS string) {
	t.Helper()
	out, err := kubectl(t, srcCluster, "", "-n", srcNS, "get", "configmap", name, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &cm); err != nil || len(cm.Data) == 0 {
		t.Fatalf("ConfigMap %s/%s in %s holds no data: %v", srcNS, name, srcCluster, err)
	}
	copied, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": name, "namespace": dstNS}, "data": cm.Data})
	if _, err := kubectl(t, dstCluster, string(copied), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
}

// configMapMount returns the volume and the mount of ConfigMap name at /run/m7/<name>.
func configMapMount(name string) (volume, mount map[string]any) {
	return map[string]any{"name": name, "configMap": map[string]any{"name": name}},
		map[string]any{"name": name, "mountPath": "/run/m7/" + name, "readOnly": true}
}

// podIPOf returns the pod address of a pod, once it has one.
func podIPOf(t *testing.T, cluster, ns, pod string) string {
	t.Helper()
	var ip string
	waitFor(t, "pod "+ns+"/"+pod+" in "+cluster+" has an address", podTimeout, func() (bool, string) {
		out, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", pod, "-o", "jsonpath={.status.podIP}")
		ip = strings.TrimSpace(out)
		return err == nil && net.ParseIP(ip) != nil, fmt.Sprint(ip, err)
	})
	return ip
}

// withStdin makes the container of a pod from testPod keep standard input open until it ends.
func withStdin(pod map[string]any) map[string]any {
	ctr := pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	ctr["stdin"], ctr["stdinOnce"] = true, true
	return pod
}

// waitPodStarted waits until a pod is Running, or has ended.
func waitPodStarted(t *testing.T, cluster, ns, name string) {
	t.Helper()
	waitFor(t, "pod "+ns+"/"+name+" in "+cluster+" starts", podTimeout, func() (bool, string) {
		out, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", name, "-o", "jsonpath={.status.phase}")
		phase := strings.TrimSpace(out)
		return err == nil && phase != "Pending" && phase != "", fmt.Sprint(phase, err)
	})
}

// attachStdin sends data to the standard input of a pod from withStdin, and closes the input. The data reaches the pod only
// through kubectl attach: no Secret, ConfigMap or file holds it. The attach ends with the test.
func attachStdin(t *testing.T, cluster, ns, pod string, data []byte) {
	t.Helper()
	waitPodStarted(t, cluster, ns, pod)
	cmd := exec.Command("kubectl", "--context", "kind-"+cluster, "-n", ns, "attach", "-i", "-q", pod)
	cmd.Stdin = bytes.NewReader(data)
	var out lockedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("kubectl attach to %s/%s in %s: %v", ns, pod, cluster, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
}

// runM7Client runs one image to its end in a namespace, as a pod for Pod Security restricted, and returns its phase and its log. A
// non-nil stdin goes to the pod through attachStdin. Each volume has its mount at the same index.
func runM7Client(t *testing.T, cluster, ns, image string, args []string, volumes, mounts []map[string]any, stdin []byte) (phase, logs string) {
	t.Helper()
	if image == "" {
		t.Fatalf("the image of the client is not in %s. Run mise run images", imagesEnv)
	}
	name := m7PodName("client")
	pod := testPod(name, image, args, volumes, mounts)
	if stdin != nil {
		pod = withStdin(pod)
	}
	applyPod(t, cluster, ns, pod)
	if stdin != nil {
		attachStdin(t, cluster, ns, name, stdin)
	}
	return podDone(t, cluster, ns, name)
}

// lastJSONLine decodes the last line of logs that is a JSON object.
func lastJSONLine(t *testing.T, logs string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var m map[string]any
		if json.Unmarshal([]byte(lines[i]), &m) == nil {
			return m
		}
	}
	t.Fatalf("no JSON line in %q", logs)
	return nil
}

// selfMadeChain returns a PEM certificate and a PEM key for a leaf with the URI SAN id, under a new CA that no bundle holds. The leaf
// serves TLS. The CA stays in memory and is not part of the chain.
func selfMadeChain(t *testing.T, id string) (chainPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "m7 self-made ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// startImpostor runs netprobe tlsserve in namespace ns of a cluster, with a certificate chain and a key on standard input, and returns
// its address in the cluster. The key reaches the pod only through kubectl attach. closed returns one value for each connection that
// ended: bytes_after_handshake of a connection that completed its handshake, and 0 for a connection whose handshake failed, because
// no application byte then reached the impostor.
func startImpostor(t *testing.T, cluster, ns string, chainPEM, keyPEM []byte) (addr string, closed func() []int64) {
	t.Helper()
	needProbeImage(t)
	name := m7PodName("impostor")
	pod := withStdin(testPod(name, probeImage, []string{"tlsserve", "--addr", fmt.Sprintf(":%d", impostorPortNumber)}, nil, nil))
	applyPod(t, cluster, ns, pod)
	attachStdin(t, cluster, ns, name, append(append([]byte{}, chainPEM...), keyPEM...))
	waitFor(t, "tlsserve in "+ns+"/"+name+" of "+cluster+" serves the chain", podTimeout, func() (bool, string) {
		logs, _ := kubectl(t, cluster, "", "-n", ns, "logs", name)
		return strings.Contains(logs, `"msg":"serving tls"`), "log: " + lastLines(logs, 2)
	})
	addr = net.JoinHostPort(podIPOf(t, cluster, ns, name), fmt.Sprint(impostorPortNumber))
	closed = func() []int64 {
		logs, err := kubectl(t, cluster, "", "-n", ns, "logs", name)
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "handshake failed" || l.str("msg") == "connection closed" }) {
			if l.str("msg") == "handshake failed" {
				out = append(out, 0)
				continue
			}
			n, _ := l["bytes_after_handshake"].(float64)
			out = append(out, int64(n))
		}
		return out
	}
	return addr, closed
}

// requireImpostorSilent waits until the impostor has logged at least one ended connection, and then fails the test for every connection
// that carried a byte after the handshake. A client that refuses the certificate sends no byte.
func requireImpostorSilent(t *testing.T, what string, closed func() []int64) {
	t.Helper()
	var got []int64
	waitFor(t, "the impostor of "+what+" logs an ended connection", time.Minute, func() (bool, string) {
		got = closed()
		return len(got) > 0, "no connection logged yet"
	})
	for i, n := range got {
		if n != 0 {
			t.Errorf("%s: connection %d of the impostor carried %d bytes after the handshake, want 0", what, i, n)
		}
	}
	t.Logf("%s: the impostor logged %d ended connections, bytes after the handshake %v", what, len(got), got)
}

// flipConn is one connection that flipforward logged when it closed.
type flipConn struct {
	ID        int64
	BytesUp   int64
	BytesDown int64
	Flipped   bool
	MaxRunUp  int64
}

// startFlipForward runs netprobe flipforward in namespace ns of a cluster, between a local port-forward and upstream. It flips the byte
// at offset flipAt of direction dir, or none when flipAt is -1. It returns the local address of the port-forward and a function that
// returns the connections that flipforward has logged as closed. The source address of the upstream connection is the node of the cluster.
func startFlipForward(t *testing.T, cluster, ns, upstream string, flipAt int64, dir string) (addr string, conns func() []flipConn) {
	t.Helper()
	needProbeImage(t)
	name := m7PodName("flip")
	args := []string{"flipforward", "--listen", fmt.Sprintf(":%d", flipPortNumber), "--upstream", upstream, "--flip-at", fmt.Sprint(flipAt), "--dir", dir}
	applyPod(t, cluster, ns, testPod(name, probeImage, args, nil, nil))
	waitFor(t, "flipforward in "+ns+"/"+name+" of "+cluster+" forwards", podTimeout, func() (bool, string) {
		logs, _ := kubectl(t, cluster, "", "-n", ns, "logs", name)
		return strings.Contains(logs, `"msg":"forwarding"`), "log: " + lastLines(logs, 2)
	})
	addr = portForward(t, cluster, ns, "pod/"+name, flipPortNumber)
	conns = func() []flipConn {
		logs, err := kubectl(t, cluster, "", "-n", ns, "logs", name)
		if err != nil {
			t.Fatal(err)
		}
		var out []flipConn
		for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "connection closed" }) {
			num := func(k string) int64 { n, _ := l[k].(float64); return int64(n) }
			flipped, _ := l["flipped"].(bool)
			out = append(out, flipConn{ID: num("conn"), BytesUp: num("bytes_up"), BytesDown: num("bytes_down"), Flipped: flipped, MaxRunUp: num("max_printable_run_up")})
		}
		return out
	}
	return addr, conns
}

// waitConns waits until flipforward has logged n closed connections, and returns them.
func waitConns(t *testing.T, what string, conns func() []flipConn, n int) []flipConn {
	t.Helper()
	var got []flipConn
	waitFor(t, fmt.Sprintf("flipforward logs %d closed connections for %s", n, what), time.Minute, func() (bool, string) {
		got = conns()
		return len(got) >= n, fmt.Sprintf("%d closed connections", len(got))
	})
	return got
}
