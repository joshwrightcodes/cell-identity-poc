//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// hostsvcPinPEM returns the certificate in ConfigMap mgmt-system/hostsvc-pin.
func hostsvcPinPEM(t *testing.T) []byte {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "get", "configmap", "hostsvc-pin", "-o", `jsonpath={.data.hostsvc\.crt}`)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(out)
}

func hostsvcServe(t *testing.T, verb string) {
	t.Helper()
	out, err := command("", "mise", "run", "hostsvc:serve", "--", verb)
	if err != nil {
		t.Fatalf("mise run hostsvc:serve -- %s: %v\n%s", verb, err, out)
	}
}

// sameJSON reports whether two JSON documents are equal as values.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("decode %s: %v", a, err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return reflect.DeepEqual(x, y)
}

// TestM4HostServiceServesPinnedKeys reads the keys of each cell through hostsvc.KeyClient with the pin of the
// ConfigMap and the SVID of mgmtd. They equal the keys that the cluster reports. A client with another pin fails
// with issuer_untrusted.
func TestM4HostServiceServesPinnedKeys(t *testing.T) {
	src, _ := svidFor(t, mgmtCluster, mgmtAPIID)
	pin, err := hostsvc.PinFromPEM(hostsvcPinPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	client, err := hostsvc.NewKeyClient(hostsvc.KeyClientConfig{Addr: hostsvcAddr, ServerName: hostsvc.KeyServerHost, Pin: pin, SVIDs: src})
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range clustersWith(t, agentCellSet) {
		got, err := client.Keys(context.Background(), cell)
		if err != nil {
			t.Fatalf("keys of %s: %v", cell, err)
		}
		want := clusterFacts(t, cell)
		if got.Issuer != want.Issuer || !sameJSON(t, got.JWKS, want.JWKS) {
			t.Errorf("keys of %s: issuer %s and keys %s, want %s and %s", cell, got.Issuer, got.JWKS, want.Issuer, want.JWKS)
		}
	}
	roots := bundleRoots(t, mgmtCluster)
	wrong, err := hostsvc.PinFromPEM([]byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(roots[0].Raw) + "\n-----END CERTIFICATE-----\n"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := hostsvc.NewKeyClient(hostsvc.KeyClientConfig{Addr: hostsvcAddr, ServerName: hostsvc.KeyServerHost, Pin: wrong, SVIDs: src})
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.Keys(context.Background(), clustersWith(t, agentCellSet)[0])
	var ke *mgmtapi.KeyError
	if !errors.As(err, &ke) || ke.Reason != mgmtapi.ReasonIssuerUntrusted {
		t.Fatalf("a client with another pin got %v, want issuer_untrusted", err)
	}
}

// foreignCert makes a client certificate in this process, under a fresh self-signed CA that carries the URI SAN
// spiffe://<caDomain>. The host service never saw that CA. The leaf has the URI SAN leafID.
func foreignCert(t *testing.T, caDomain, leafID string) tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caURI, _ := url.Parse("spiffe://" + caDomain)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "foreign ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, URIs: []*url.URL{caURI}}
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
	leafURI, _ := url.Parse(leafID)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{leafURI}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshakeRefused makes one TLS 1.3 handshake with the host service and reads once. TLS 1.3 reports a refused
// client certificate on the first read, as an alert from the server. It returns an error unless the server
// answered with a TLS alert.
func handshakeRefused(cert *tls.Certificate) error {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: hostsvc.KeyServerHost, InsecureSkipVerify: true}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", hostsvcAddr, cfg)
	if err != nil {
		return refusedByAlert(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return refusedByAlert(err)
	}
	return fmt.Errorf("the server answered a client that it must refuse")
}

// refusedByAlert returns nil for an alert that the server sent, and the error otherwise, so a dial failure or a
// stopped service does not pass as a refusal.
func refusedByAlert(err error) error {
	if strings.Contains(err.Error(), "remote error: tls:") {
		return nil
	}
	return fmt.Errorf("want a TLS alert from the server, got: %w", err)
}

// TestM4HostServiceRefusesOthers: with a positive control (the real SVID of mgmtd and the pin get the keys), each
// of these clients fails with a TLS alert from the server: no client certificate; the exact ID of mgmtd under a CA
// that the host service never saw; an ID of another trust domain under a foreign CA; and the real SVID of the
// telemetry gateway of management. The test runs on the Mac, so it tests the authentication of the server. The
// reach from a pod of rogue is the residual in docs/design/poc-scope.md.
func TestM4HostServiceRefusesOthers(t *testing.T) {
	src, _ := svidFor(t, mgmtCluster, mgmtAPIID)
	pin, err := hostsvc.PinFromPEM(hostsvcPinPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	client, err := hostsvc.NewKeyClient(hostsvc.KeyClientConfig{Addr: hostsvcAddr, ServerName: hostsvc.KeyServerHost, Pin: pin, SVIDs: src})
	if err != nil {
		t.Fatal(err)
	}
	cell := clustersWith(t, agentCellSet)[0]
	if _, err := client.Keys(context.Background(), cell); err != nil {
		t.Fatalf("the positive control failed, so the refusals below prove nothing: %v", err)
	}
	sameID := foreignCert(t, mgmtTD, mgmtAPIID)
	otherDomain := foreignCert(t, "rogue.poc.internal", "spiffe://rogue.poc.internal/api")
	_, telemetry := svidFor(t, mgmtCluster, "spiffe://"+mgmtTD+"/telemetry")
	for name, cert := range map[string]*tls.Certificate{"no client certificate": nil, "the ID of mgmtd under a foreign CA": &sameID,
		"an ID of another trust domain under a foreign CA": &otherDomain, "the SVID of the telemetry gateway": &telemetry} {
		if err := handshakeRefused(cert); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestM4MgmtdReachesHostService: mgmtd previews the keys of each cell, which makes it call the host service.
func TestM4MgmtdReachesHostService(t *testing.T) {
	for _, cell := range clustersWith(t, agentCellSet) {
		var got struct {
			Keys json.RawMessage `json:"keys"`
		}
		out := mgmtCtl(t, "keys", "--cell", cell)
		if err := json.Unmarshal([]byte(out), &got); err != nil || len(out) < 10 {
			t.Fatalf("keys of %s through mgmtd: %q (%v)", cell, out, err)
		}
	}
}

// TestM4HostServicePinDrift stops the host service and starts it again. A new process has a new certificate, so
// mgmtd, which holds the old pin, refuses it until the re-link. The cleanup restarts the service, which links
// mgmt-api again.
func TestM4HostServicePinDrift(t *testing.T) {
	cell := clustersWith(t, agentCellSet)[0]
	t.Cleanup(func() { hostsvcServe(t, "restart") })
	hostsvcServe(t, "stop")
	if _, err := mgmtCtlErr("keys", "--cell", cell); err == nil {
		t.Fatal("mgmtd read keys with the host service stopped")
	}
	hostsvcServe(t, "start")
	waitFor(t, "mgmtd to refuse the new certificate of the host service", time.Minute, func() (bool, string) {
		_, err := mgmtCtlErr("keys", "--cell", cell)
		return err != nil, "keys still answer"
	})
	hostsvcServe(t, "restart")
	statefulSetReady(t, mgmtCluster, mgmtNamespace, "mgmtd")
	waitFor(t, "mgmtd to read keys again", 2*time.Minute, func() (bool, string) {
		_, err := mgmtCtlErr("keys", "--cell", cell)
		return err == nil, "keys still fail"
	})
}

// TestM4SigningKeyReaders: no Secret exists in mgmt-system, and the only pod in management that mounts PVC
// state-mgmtd-0 is mgmtd-0. The key file has mode 0400 and the owner uid of the image, read through an ephemeral
// container. The test logs each ServiceAccount that can create pods, create pods/exec, update
// pods/ephemeralcontainers or create hostPath pods, for the residual.
func TestM4SigningKeyReaders(t *testing.T) {
	needProbeImage(t)
	out, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "get", "secrets", "-o", "name")
	if err != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("secrets in mgmt-system: %q (%v), want none", out, err)
	}
	pods, err := kubectl(t, mgmtCluster, "", "get", "pods", "-A", "-o", `jsonpath={range .items[?(@.spec.volumes[*].persistentVolumeClaim.claimName=="state-mgmtd-0")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(pods); got != mgmtNamespace+"/"+mgmtdPod {
		t.Fatalf("pods that mount state-mgmtd-0: %q, want only mgmt-system/mgmtd-0", got)
	}
	// The key file mode and owner, read from the node through the volume directory. The ephemeral container of
	// the probe image has no shell, so the check reads the node.
	pv, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "get", "pvc", "state-mgmtd-0", "-o", "jsonpath={.spec.volumeName}")
	if err != nil {
		t.Fatal(err)
	}
	node := mgmtCluster + "-control-plane"
	listing, err := dockerExec(t, node, "", "sh", "-c", "stat -c '%a %u' /var/local-path-provisioner/"+strings.TrimSpace(pv)+"_"+mgmtNamespace+"_state-mgmtd-0/ed25519.key")
	if err != nil || strings.TrimSpace(listing) != "400 "+mgmtdUID {
		t.Fatalf("key file mode and owner %q (%v), want 400 %s", listing, err, mgmtdUID)
	}
	sas, err := kubectl(t, mgmtCluster, "", "get", "serviceaccounts", "-A", "-o", `jsonpath={range .items[*]}{.metadata.namespace}:{.metadata.name}{"\n"}{end}`)
	if err != nil {
		t.Fatal(err)
	}
	accounts := strings.Fields(sas)
	// Readers of the key: who can start a process next to mgmtd-0. Writers of the public key: who can change mgmt-signing-pub.
	for _, verb := range []struct{ verb, resource, sub string }{{"create", "pods", ""}, {"create", "pods", "exec"}, {"update", "pods", "ephemeralcontainers"},
		{"update", "configmaps", ""}, {"patch", "configmaps", ""}} {
		for _, sa := range accounts {
			if canISub(t, mgmtCluster, "system:serviceaccount:"+sa, verb.verb, verb.resource, verb.sub, mgmtNamespace) {
				t.Logf("residual: %s can %s %s/%s in %s", sa, verb.verb, verb.resource, verb.sub, mgmtNamespace)
			}
		}
	}
	// Kubernetes RBAC cannot name a hostPath volume. A pod that mounts the local-path directory reads the key file, and
	// Pod Security stops such a pod only in a namespace that enforces restricted or baseline. So list the accounts that can
	// create pods in each namespace that enforces neither.
	nsList, err := kubectl(t, mgmtCluster, "", "get", "namespaces", "-o", `jsonpath={range .items[*]}{.metadata.name}={.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}{end}`)
	if err != nil {
		t.Fatal(err)
	}
	for entry := range strings.FieldsSeq(nsList) {
		ns, level, _ := strings.Cut(entry, "=")
		if level == "restricted" || level == "baseline" {
			continue
		}
		for _, sa := range accounts {
			if canI(t, mgmtCluster, "system:serviceaccount:"+sa, "create", "pods", ns) {
				t.Logf("residual: %s can create hostPath pods in %s, which enforces %q", sa, ns, level)
			}
		}
	}
}

// TestM4SigningKeyStable deletes pod mgmtd-0. The key survives on the volume, so the public key does not change.
func TestM4SigningKeyStable(t *testing.T) {
	before, cm := ctlPub(t), mgmtSigningPub(t)
	if before != cm {
		t.Fatalf("mgmt -- pubkey %s differs from mgmt-signing-pub %s", before, cm)
	}
	if _, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "delete", "pod", mgmtdPod, "--wait=true", "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
	statefulSetReady(t, mgmtCluster, mgmtNamespace, "mgmtd")
	if after := ctlPub(t); after != before || mgmtSigningPub(t) != before {
		t.Fatalf("the key changed after a pod restart: before %s, after %s, ConfigMap %s", before, after, mgmtSigningPub(t))
	}
}

// envdCert mints the SVID of envd, the only peer that the API of mgmtd admits.
func envdCert(t *testing.T) tls.Certificate {
	t.Helper()
	_, cert := svidFor(t, "dev-cp", envdID)
	return cert
}

// TestM4InitialSpecSigned: the first spec that envd pulls verifies under mgmt-signing-pub, names the environment
// and holds one entry for each cell of the intent.
func TestM4InitialSpecSigned(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(mgmtSigningPub(t))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("mgmt-signing-pub is not an Ed25519 key: %v", err)
	}
	bundle, err := fetchSpec(t, envdCert(t))
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := spec.Verify(bundle.Spec, []ed25519.PublicKey{raw})
	if err != nil {
		t.Fatalf("the spec does not verify under the published key: %v", err)
	}
	if s.Env != pocEnv || s.Revision.Epoch < 1 {
		t.Errorf("spec %+v, want env %s and an epoch of 1 or more", s, pocEnv)
	}
	for _, e := range s.Cells {
		if _, ok := bundle.Records[e.Name]; !ok {
			t.Errorf("the bundle has no record for the spec entry %s", e.Name)
		}
	}
}

// TestM4MgmtAPIIdentity: the API presents spiffe://mgmt.poc.internal/api and refuses a client other than envd.
func TestM4MgmtAPIIdentity(t *testing.T) {
	if _, err := fetchSpec(t, envdCert(t)); err != nil {
		t.Fatalf("envd cannot pull the spec: %v", err)
	}
	_, other := svidFor(t, "dev-cp", "spiffe://dev.env.poc.internal/cp/otel")
	if _, err := fetchSpec(t, other); err == nil {
		t.Fatal("the API admitted an SVID that is not envd")
	}
}

// TestM4MgmtListenersAdmission: the API node port admits only the dev-cp node. A pod in a fresh namespace of a
// cell cannot reach it directly, so a dial from a cell node address times out. A dev-cp subtest dials the same port
// and must connect. If the ingress of mgmtd widens to the cell nodes, the dev-cell-1 and dev-cell-2 subtests both fail.
func TestM4MgmtListenersAdmission(t *testing.T) {
	needProbeImage(t)
	node := clusterFacts(t, mgmtCluster).NodeIP
	// The positive half: the dev-cp node reaches the port. It fails when mgmtd is down, or when the rule names another address.
	t.Run("dev-cp", func(t *testing.T) {
		ns := freshNamespace(t, "dev-cp")
		for _, port := range []int{31446} {
			if got := dialFrom(t, "dev-cp", ns, node, port, 10*time.Second); got != "connected" {
				t.Errorf("a pod in dev-cp dials management %s:%d: %s, want connected", node, port, got)
			}
		}
	})
	for _, cell := range clustersWith(t, agentCellSet) {
		t.Run(cell, func(t *testing.T) {
			for _, port := range []int{31446} {
				if err := probeFromFreshNamespace(t, cell, node, port, 5*time.Second); err != nil {
					t.Errorf("a pod in %s reaches management %s:%d: %v", cell, node, port, err)
				}
			}
		})
	}
}

// TestM4MgmtdStatePersists: the state of mgmtd survives a pod restart: the sequence number and the signed revision do not fall.
func TestM4MgmtdStatePersists(t *testing.T) {
	before := mgmtStatus(t)
	if _, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "delete", "pod", mgmtdPod, "--wait=true", "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
	statefulSetReady(t, mgmtCluster, mgmtNamespace, "mgmtd")
	after := mgmtStatus(t)
	if after.Seq < before.Seq || after.Signed.Compare(before.Signed) < 0 {
		t.Fatalf("state fell: before seq %d signed %+v, after seq %d signed %+v", before.Seq, before.Signed, after.Seq, after.Signed)
	}
}

// TestM4MgmtdLogsJSON: every log line of mgmtd is one JSON object.
func TestM4MgmtdLogsJSON(t *testing.T) {
	out, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "logs", mgmtdPod, "-c", "mgmtd", "--tail=200")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("mgmtd logged nothing")
	}
	for _, l := range lines {
		var v map[string]any
		if json.Unmarshal([]byte(l), &v) != nil || v["msg"] == nil {
			t.Errorf("log line is no JSON object with a msg: %q", l)
		}
	}
}

// TestM4MgmtdPortsClosedInside: from a fresh namespace in management, the API and health ports of the mgmtd
// pod time out. From an ephemeral container in mgmtd-0, the host service port on the host address (17444) and the
// node port 30081 of the dev-cp node time out.
func TestM4MgmtdPortsClosedInside(t *testing.T) {
	needProbeImage(t)
	ip, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "get", "pod", mgmtdPod, "-o", "jsonpath={.status.podIP}")
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{8446, 8080} {
		if err := probeFromFreshNamespace(t, mgmtCluster, strings.TrimSpace(ip), port, 5*time.Second); err != nil {
			t.Errorf("port %d of the mgmtd pod: %v", port, err)
		}
	}
	hostAddr, err := command("", "docker", "exec", mgmtCluster+"-control-plane", "getent", "ahostsv4", hostsvc.KeyServerHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{strings.Fields(hostAddr)[0] + ":17444", clusterFacts(t, "dev-cp").NodeIP + ":30081"} {
		if got := ephemeralDial(t, mgmtCluster, mgmtNamespace, mgmtdPod, target, 5*time.Second); got != "timeout" {
			t.Errorf("a dial from mgmtd-0 to %s gave %q, want timeout", target, got)
		}
	}
}
