//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	apiserverManifest = "/etc/kubernetes/manifests/kube-apiserver.yaml"
	// The test saves the original manifest here before its edit. scripts/gate-m2-repair.sh restores
	// it from this file. The paths match KEYTEST_* in scripts/gate-traces.sh.
	savedManifest = "/root/m2-test-kube-apiserver.yaml"
	apiserverWait = 4 * time.Minute
	// kubeadm writes these two flags into the manifest of each kind node.
	saVerifyFlag  = "    - --service-account-key-file=/etc/kubernetes/pki/sa.pub\n"
	saSigningFlag = "    - --service-account-signing-key-file=/etc/kubernetes/pki/sa.key\n"
	// The API server reads its signing key only from a file. The repair deletes both files.
	testKeyPath = "/etc/kubernetes/pki/m2-test-sa"
	repairHint  = "Run: mise run gate:m2:repair"
)

// TestM2KeyRotationDenied adds a second service account key to the API server of dev-cell-1 and
// signs new tokens with it. The cell record still holds only the first key. The running celld agent
// must renew, and a new pod must fail with unknown_kid. A key check of mgmtd runs first, so that the periodic check
// cannot update the record during the test. The cleanup restores the manifest.
func TestM2KeyRotationDenied(t *testing.T) {
	const cell = rejectCell
	// A key check first: the record of the cell then holds the keys that the API server publishes, and the next
	// periodic check of mgmtd is 15 minutes away, so it cannot update the record while the test runs.
	if res := keyCheck(t, cell); res != "unchanged" && res != "rate_limited" {
		t.Fatalf("the key check of %s answered %q, want unchanged or rate_limited. Run: mise run gate:m2:repair", cell, res)
	}
	pods := celldPods(t, cell)
	if len(pods) != 1 || pods[0].Status.Phase != "Running" {
		t.Fatalf("want one Running celld pod in %s, got %v", cell, pods)
	}
	pod := pods[0]
	agentID := agentIDOf(t, cell, pod)

	oldKID, newKID := rotateAPIKey(t, cell)
	t.Logf("the API server signs with key %s and verifies %s too", newKID, oldKID)
	since := time.Now().Add(-logMargin)

	res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
	expectRefusal(t, res, cell, "unknown_kid", []string{newKID})

	waitFor(t, "an agent rotation for "+agentID+" after the key change", renewWait, func() (bool, string) {
		logs, err := podLog(t, cell, pod.Metadata.Name, "spire-agent", since)
		if err != nil {
			return false, err.Error()
		}
		n := len(matching(logs, func(l logLine) bool { return l.str("msg") == agentRotated && l.str("spiffe_id") == agentID }))
		return n > 0, lastLines(logs, 3)
	})
	logs, err := serverLog(t, since)
	if err != nil {
		t.Fatal(err)
	}
	if again := matching(logs, func(l logLine) bool {
		return l.str("msg") == attestDone && strings.Contains(l.str("agent_id"), "/"+pod.Metadata.UID+"/")
	}); len(again) > 0 {
		t.Errorf("the server attested the running celld pod again after the key change: %v", again)
	}
}

// rotateAPIKey adds a second service account key to the API server of a cell and signs new tokens with it, then waits until
// the API server verifies both keys and signs with the new one, and until kube-controller-manager renews its lease again. A pod of
// istio-cni-node restarts first (freshCNIToken). It returns the old and the new key ID. The cleanup runs repairAPIServer.
func rotateAPIKey(t *testing.T, cell string) (oldKID, newKID string) {
	t.Helper()
	oldKID, newKID, _ = rotateAPIKeyAt(t, cell, time.Time{})
	return oldKID, newKID
}

// rotateAPIKeyAt is rotateAPIKey with two additions. It waits before the switch until the update gap of mgmtd has passed since
// gapFrom (the time of a key check), so the wait overlaps the restart of istio-cni-node and the other set-up. A zero gapFrom does not
// wait. It also returns the time of the switch, which is the moment that the bounds of the healing tests count from.
func rotateAPIKeyAt(t *testing.T, cell string, gapFrom time.Time) (oldKID, newKID string, switchedAt time.Time) {
	t.Helper()
	node := cell + "-control-plane"
	oldKIDs := apiKIDs(t, cell)
	if len(oldKIDs) != 1 {
		t.Fatalf("the API server of %s verifies keys %v, want one key before the test", cell, oldKIDs)
	}
	freshCNIToken(t, cell)
	manifest, err := dockerExec(t, node, "", "cat", apiserverManifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(manifest, testKeyPath) {
		t.Fatalf("%s on %s still names %s from an earlier run. %s", apiserverManifest, node, testKeyPath, repairHint)
	}
	edited, err := addSigningKey(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dockerExec(t, node, "", "sh", "-c", "umask 077 && test ! -e "+savedManifest+" && cp "+apiserverManifest+" "+savedManifest); err != nil {
		t.Fatalf("save %s on %s to %s, which must not exist yet: %v. %s", apiserverManifest, node, savedManifest, err, repairHint)
	}
	t.Cleanup(func() { repairAPIServer(t) })
	if _, err := dockerExec(t, node, "", "sh", "-c", "umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "+
		testKeyPath+".key 2>/dev/null && openssl pkey -in "+testKeyPath+".key -pubout -out "+testKeyPath+".pub"); err != nil {
		t.Fatalf("make the second key on %s: %v", node, err)
	}
	if !gapFrom.IsZero() {
		waitUpdateGap(t, gapFrom)
	}
	writeNodeFile(t, node, apiserverManifest, edited)
	switchedAt = time.Now()
	waitFor(t, "the API server of "+cell+" to verify two keys and sign with the new one", apiserverWait, func() (bool, string) {
		kids, err := apiKIDsOnce(t, cell)
		if err != nil {
			return false, err.Error()
		}
		signing, err := signingKID(t, cell)
		if err != nil {
			return false, err.Error()
		}
		newKID = signing
		return len(kids) == 2 && slices.Contains(kids, oldKIDs[0]) && slices.Contains(kids, signing) && signing != oldKIDs[0],
			fmt.Sprintf("keys %v, signing key %s", kids, signing)
	})
	waitControllerManager(t, cell)
	return oldKIDs[0], newKID, switchedAt
}

// addSigningKey adds the test public key as a second verification key, and makes the test private
// key the signing key.
func addSigningKey(manifest string) (string, error) {
	if strings.Count(manifest, saVerifyFlag) != 1 || strings.Count(manifest, saSigningFlag) != 1 {
		return "", errors.New("the API server manifest does not hold each service account key flag exactly once")
	}
	out := strings.Replace(manifest, saVerifyFlag, saVerifyFlag+"    - --service-account-key-file="+testKeyPath+".pub\n", 1)
	return strings.Replace(out, saSigningFlag, "    - --service-account-signing-key-file="+testKeyPath+".key\n", 1), nil
}

// repairAPIServer runs scripts/gate-m2-repair.sh, the same code as `mise run gate:m2:repair`. It
// restores the saved manifest and deletes the test key. It makes sure that kube-controller-manager,
// which keeps a token for each controller in memory, runs a new container. It deletes each pod with
// a projected token from the test key, and the controllers create those pods again.
func repairAPIServer(t *testing.T) {
	t.Helper()
	// The fixed waits of the script add up to about 20 minutes, and each replaced pod adds up to 3.
	ctx, cancel := context.WithTimeout(context.Background(), 26*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "../../scripts/gate-m2-repair.sh")
	out, err := cmd.CombinedOutput()
	t.Logf("gate-m2-repair.sh:\n%s", strings.TrimSpace(string(out)))
	if err != nil {
		t.Errorf("the repair of dev-cell-1 failed: %v. %s", err, repairHint)
		return
	}
	// The repair ran the key check, so the record lists the key that the API server publishes now.
	kids, err := apiKIDsOnce(t, rejectCell)
	if err != nil {
		t.Errorf("read the JWKS of %s after the repair: %v", rejectCell, err)
		return
	}
	var record []string
	for _, c := range mgmtStatus(t).Cells {
		if c.Name == rejectCell {
			record = c.Kids
		}
	}
	if len(record) != 1 || !slices.Equal(record, kids) {
		t.Errorf("after the repair the record of %s lists the key IDs %v, and the API server publishes %v", rejectCell, record, kids)
	}
}

// writeNodeFile replaces a file on a node through a temporary file, so kubelet never reads a part.
func writeNodeFile(t *testing.T, node, path, content string) {
	t.Helper()
	if _, err := dockerExec(t, node, content, "sh", "-c", "umask 077 && cat > /root/m2-test.tmp && mv /root/m2-test.tmp "+path); err != nil {
		t.Fatalf("write %s on %s: %v", path, node, err)
	}
}

// apiKIDs returns the key IDs that the API server publishes, and fails the test on an error.
func apiKIDs(t *testing.T, cell string) []string {
	t.Helper()
	kids, err := apiKIDsOnce(t, cell)
	if err != nil {
		t.Fatal(err)
	}
	return kids
}

func apiKIDsOnce(t *testing.T, cell string) ([]string, error) {
	t.Helper()
	out, err := kubectl(t, cell, "", "get", "--raw", "/openid/v1/jwks")
	if err != nil {
		return nil, err
	}
	return jwksKIDs([]byte(out))
}

// signingKID requests a short token for celld and returns the key ID in its header.
func signingKID(t *testing.T, cell string) (string, error) {
	t.Helper()
	// The audience m2-kid-probe makes the token useless to the API server and to every service.
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "create", "token", celldAccount, "--duration", "10m", "--audience", "m2-kid-probe")
	if err != nil {
		return "", err
	}
	kid := tokenKID(strings.TrimSpace(out))
	if kid == "" {
		return "", errors.New("the token header holds no key ID")
	}
	return kid, nil
}
