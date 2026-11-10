//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rotateHook is the MGMT_ROTATE_REFRESH command of the test. For the test copy, it records the
// authority state of the management server, then renders the copy again with peer_root_configmap
// and applies it, as a peer render does. Any other copy belongs to a real render. A copy in
// management is the trust bundle of a link component sidecar, so the hook runs cell:link, which is
// safe to run at each refresh. For a copy in another cluster the hook runs cell:up of that cluster
// once.
const rotateHook = `#!/usr/bin/env bash
set -euo pipefail
cluster="$1" ns="$2" name="$3"
if [[ "$cluster" == management ]]; then
  CELL=management "$ROTATE_ROOT/scripts/link.sh"
  exit 0
fi
if [[ "$cluster" != "$ROTATE_TEST_CLUSTER" || "$ns" != "$ROTATE_TEST_NS" ]]; then
  grep -qxF "$cluster" "$ROTATE_DONE" 2>/dev/null && exit 0
  echo "$cluster" >>"$ROTATE_DONE"
  CELL="$cluster" "$ROTATE_ROOT/scripts/up.sh"
  exit 0
fi
kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server localauthority x509 show -socketPath /run/spire/sockets/api.sock -output json >>"$ROTATE_STATES"
source "$ROTATE_ROOT/components/lib/peer-root.sh"
peer_root_configmap "$name" "$ns" management mgmt.poc.internal | kubectl --context "kind-$cluster" apply -f - >/dev/null
`

// renderPeerCopy renders and applies the copy of the management root in a dev-cp test namespace.
func renderPeerCopy(t *testing.T, root, ns string) {
	t.Helper()
	cmd := exec.Command("bash", "-c", `source "$1/components/lib/peer-root.sh" && peer_root_configmap peer-root "$2" management mgmt.poc.internal`, "_", root, ns)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("peer_root_configmap: %v", err)
	}
	if _, err := kubectl(t, spireCluster, string(out), "apply", "-f", "-"); err != nil {
		t.Fatal(err)
	}
}

// peerCopy reads the roots of the test copy in dev-cp.
func peerCopy(t *testing.T, ns string) *x509.CertPool {
	t.Helper()
	data, err := kubectl(t, spireCluster, "", "-n", ns, "get", "configmap", "peer-root", "-o", `jsonpath={.data.root\.crt}`)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(data)) {
		t.Fatalf("the copy in %s/%s holds no certificate", spireCluster, ns)
	}
	return pool
}

// verifiesAt reports whether an SVID chains to the roots of a peer copy.
func verifiesAt(t *testing.T, certPEM, keyPEM []byte, roots *x509.CertPool) bool {
	t.Helper()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// TestM3MgmtCARotation runs mgmt:rotate-ca with a peer copy of the management root in dev-cp. The
// copy must hold the new root before SPIRE activates it, a plane SVID from the new CA must verify
// at the peer, and after the rotation the peer must refuse the SVIDs of the old CA.
func TestM3MgmtCARotation(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ns := freshNamespace(t, spireCluster)
	renderPeerCopy(t, root, ns)
	plane := "spiffe://" + mgmtTD + "/telemetry"
	oldCert, oldKey := mintSVID(t, mgmtCluster, plane, 10*time.Minute)
	if !verifiesAt(t, oldCert, oldKey, peerCopy(t, ns)) {
		t.Fatal("the plane SVID of the current CA does not verify at the peer copy before the rotation")
	}
	show := func() (string, string) {
		out, err := spireServerIn(t, mgmtCluster, "localauthority", "x509", "show", "-socketPath", spireSocket, "-output", "json")
		if err != nil {
			t.Fatal(err)
		}
		jwt, err := spireServerIn(t, mgmtCluster, "localauthority", "jwt", "show", "-socketPath", spireSocket, "-output", "json")
		if err != nil {
			t.Fatal(err)
		}
		return activeAuthority(t, out), activeAuthority(t, jwt)
	}
	oldX509, oldJWT := show()

	dir := t.TempDir()
	hook := filepath.Join(dir, "refresh")
	if err := os.WriteFile(hook, []byte(rotateHook), 0o755); err != nil {
		t.Fatal(err)
	}
	states := filepath.Join(dir, "states")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts/mgmt-rotate-ca.sh"))
	cmd.Env = append(os.Environ(), "CELL="+mgmtCluster, "MGMT_ROTATE_REFRESH="+hook, "MGMT_ROTATE_TAINT_WAIT=10",
		"ROTATE_TEST_CLUSTER="+spireCluster, "ROTATE_TEST_NS="+ns, "ROTATE_STATES="+states,
		"ROTATE_DONE="+filepath.Join(dir, "done"), "ROTATE_ROOT="+root)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	t.Logf("running CELL=%s mise run mgmt:rotate-ca with the test copy %s/%s/peer-root", mgmtCluster, spireCluster, ns)
	if err := cmd.Run(); err != nil {
		t.Fatalf("mgmt:rotate-ca: %v\n%s", err, out.String())
	}
	t.Log(strings.TrimSpace(out.String()))

	// The hook ran twice. At the first refresh the old CA was still active, and a new one was
	// prepared. At the second refresh the new CA was active.
	data, err := os.ReadFile(states)
	if err != nil {
		t.Fatal(err)
	}
	var seen []map[string]map[string]string
	for dec := json.NewDecoder(bytes.NewReader(data)); dec.More(); {
		var s map[string]map[string]string
		if err := dec.Decode(&s); err != nil {
			t.Fatalf("decode the recorded authority states: %v\n%s", err, data)
		}
		seen = append(seen, s)
	}
	newX509, newJWT := show()
	if len(seen) != 2 || seen[0]["active"]["authority_id"] != oldX509 || seen[0]["prepared"]["authority_id"] != newX509 ||
		seen[1]["active"]["authority_id"] != newX509 {
		t.Fatalf("authority states at the two refreshes are %v; want %s active with %s prepared, then %s active", seen, oldX509, newX509, newX509)
	}
	if newX509 == oldX509 || newJWT == oldJWT {
		t.Fatalf("the active authorities are X.509 %s (before %s) and JWT %s (before %s); want new ones", newX509, oldX509, newJWT, oldJWT)
	}

	roots := bundleRoots(t, mgmtCluster)
	checkMgmtRoots(t, roots)
	if len(roots) != 1 {
		t.Fatalf("the bundle holds %d roots after the rotation, want only the new one", len(roots))
	}
	got, _ := kubectl(t, spireCluster, "", "-n", ns, "get", "configmap", "peer-root", "-o", `jsonpath={.data.root\.crt}`)
	if block, _ := pem.Decode([]byte(got)); block == nil || !bytes.Equal(block.Bytes, roots[0].Raw) || strings.Count(got, "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("the peer copy is %q, want only the new root", got)
	}
	newCert, newKey := mintSVID(t, mgmtCluster, plane, 10*time.Minute)
	copyRoots := peerCopy(t, ns)
	if !verifiesAt(t, newCert, newKey, copyRoots) {
		t.Fatal("a plane SVID of the new CA does not verify at the peer copy")
	}
	if verifiesAt(t, oldCert, oldKey, copyRoots) {
		t.Fatal("a plane SVID of the old CA still verifies at the peer copy")
	}
}

func activeAuthority(t *testing.T, out string) string {
	t.Helper()
	var s struct {
		Active struct {
			AuthorityID string `json:"authority_id"`
		} `json:"active"`
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil || s.Active.AuthorityID == "" {
		t.Fatalf("decode the authority state %q: %v", out, err)
	}
	return s.Active.AuthorityID
}
