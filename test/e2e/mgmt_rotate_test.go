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
	"syscall"
	"testing"
	"time"
)

// rotateHook is the MGMT_ROTATE_REFRESH command of the test. For the test copy, it records the
// authority state of the management server, then renders the copy again with peer_root_configmap
// and applies it, as a peer render does. Any other copy belongs to a real render. A copy in
// management is the trust bundle of a link component sidecar, so the hook runs cell:link, which is
// safe to run at each refresh. For each cluster the hook runs cell:up, or cell:link for management,
// once for each content of the live bundle, as the refresh of mgmt:rotate-ca does once in each pass.
const rotateHook = `#!/usr/bin/env bash
set -euo pipefail
cluster="$1" ns="$2" name="$3"
if [[ "$cluster" == management || "$cluster" != "$ROTATE_TEST_CLUSTER" || "$ns" != "$ROTATE_TEST_NS" ]]; then
  pass="$(kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem | shasum -a 256 | cut -d' ' -f1)"
  grep -qxF "$cluster $pass" "$ROTATE_DONE" 2>/dev/null && exit 0
  echo "$cluster $pass" >>"$ROTATE_DONE"
  if [[ "$cluster" == management ]]; then
    CELL=management "$ROTATE_ROOT/scripts/link.sh"
  else
    CELL="$cluster" "$ROTATE_ROOT/scripts/up.sh"
  fi
  exit 0
fi
kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server localauthority x509 show -socketPath /run/spire/sockets/api.sock -output json >>"$ROTATE_STATES"
source "$ROTATE_ROOT/components/lib/peer-root.sh"
peer_root_configmap "$name" "$ns" management mgmt.poc.internal | kubectl --context "kind-$cluster" apply -f - >/dev/null
`

// Bounds for the rotation. One refresh pass runs cell:up in each cluster with components, and
// cell:link in management. The gate:m3 run of 2026-11-23 on a slow host took 163 s for the slowest
// cell:up and 114 s for one link, so rotatePerCluster of 5 minutes gives each cluster the double of
// that. The rotation has two refresh passes. rotatePadding covers the prepare, the activate, the
// taint wait, the revoke and the two restarts of the host service.
const (
	rotatePerCluster = 5 * time.Minute
	rotatePadding    = 10 * time.Minute
	rotateWaitDelay  = 15 * time.Second
)

// rotateBudget returns the time for one rotation with passes refresh passes over n clusters.
func rotateBudget(n, passes int) time.Duration {
	return time.Duration(n*passes)*rotatePerCluster + rotatePadding
}

// killGroup makes cmd stop the process group that it leads, so a hook and the scripts below it
// end with the script, and no orphan keeps the output pipe open.
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = rotateWaitDelay
}

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
	env := append(os.Environ(), "CELL="+mgmtCluster, "MGMT_ROTATE_REFRESH="+hook, "MGMT_ROTATE_TAINT_WAIT=10",
		"ROTATE_TEST_CLUSTER="+spireCluster, "ROTATE_TEST_NS="+ns, "ROTATE_STATES="+states,
		"ROTATE_DONE="+filepath.Join(dir, "done"), "ROTATE_ROOT="+root)
	script := filepath.Join(root, "scripts/mgmt-rotate-ca.sh")
	clusters := len(clustersWith(t, ""))
	finished := false
	// A rotation that stopped after the revoke leaves the bundle with the new root only, and the
	// copies with two. It cannot roll back, so the cleanup runs the script again, which then runs
	// only the second refresh. The hook makes the pass skip the clusters that it already refreshed.
	t.Cleanup(func() {
		if finished {
			return
		}
		x509Now, _ := show()
		if x509Now == oldX509 || len(bundleRoots(t, mgmtCluster)) != 1 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), rotateBudget(clusters, 1))
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", script)
		killGroup(cmd)
		cmd.Env = append(env, "ROTATE_STATES="+filepath.Join(dir, "states-cleanup"), "ROTATE_DONE="+filepath.Join(dir, "done-cleanup"))
		out, err := cmd.CombinedOutput()
		if !rotateRefreshDone(err) {
			t.Errorf("finish the second refresh of mgmt:rotate-ca: %v\n%s", err, out)
			return
		}
		t.Logf("finished the second refresh after the rotation stopped:\n%s", rotateRefreshLog(string(out)))
	})
	ctx, cancel := context.WithTimeout(context.Background(), rotateBudget(clusters, 2))
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script)
	killGroup(cmd)
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	t.Logf("running CELL=%s mise run mgmt:rotate-ca with the test copy %s/%s/peer-root, bound %s", mgmtCluster, spireCluster, ns, rotateBudget(clusters, 2))
	if err := cmd.Run(); err != nil {
		t.Fatalf("mgmt:rotate-ca: %v\n%s", err, out.String())
	}
	finished = true
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
	// The trust bundle of the principal sidecar is a copy in management, and the hook relinked it.
	own, _ := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "get", "configmap", "spire-trust-bundle-"+principalName, "-o", `jsonpath={.data.bundle\.crt}`)
	if block, _ := pem.Decode([]byte(own)); block == nil || !bytes.Equal(block.Bytes, roots[0].Raw) || strings.Count(own, "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("the sidecar trust bundle of the principal holds %d certificates, want only the new root", strings.Count(own, "BEGIN CERTIFICATE"))
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
