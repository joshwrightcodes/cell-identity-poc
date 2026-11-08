//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	apiserverManifest = "/etc/kubernetes/manifests/kube-apiserver.yaml"
	apiserverWait     = 4 * time.Minute
	workloadWait      = 5 * time.Minute
	// kubeadm writes these two flags into the manifest of each kind node.
	saVerifyFlag  = "    - --service-account-key-file=/etc/kubernetes/pki/sa.pub\n"
	saSigningFlag = "    - --service-account-signing-key-file=/etc/kubernetes/pki/sa.key\n"
	// The API server reads its signing key only from a file. The cleanup deletes both files.
	testKeyPath = "/etc/kubernetes/pki/m2-test-sa"
)

// TestM2KeyRotationDenied adds a second service account key to the API server of dev-cell-1 and
// signs new tokens with it. The cell record still holds only the first key. The running celld agent
// must renew, and a new pod must fail with unknown_kid. The cleanup restores the manifest.
func TestM2KeyRotationDenied(t *testing.T) {
	const cell = rejectCell
	node := cell + "-control-plane"
	oldKIDs := apiKIDs(t, cell)
	if len(oldKIDs) != 1 {
		t.Fatalf("the API server of %s verifies keys %v, want one key before the test", cell, oldKIDs)
	}
	manifest, err := dockerExec(t, node, "", "cat", apiserverManifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(manifest, testKeyPath) {
		t.Fatalf("%s on %s still names %s from an earlier run. Remove the two m2-test-sa flags, then run cell:verify", apiserverManifest, node, testKeyPath)
	}
	edited, err := addSigningKey(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pods := celldPods(t, cell)
	if len(pods) != 1 || pods[0].Status.Phase != "Running" {
		t.Fatalf("want one Running celld pod in %s, got %v", cell, pods)
	}
	pod := pods[0]
	agentID := agentIDOf(t, cell, pod)

	t.Cleanup(func() { restoreAPIServer(t, cell, node, manifest, oldKIDs) })
	if _, err := dockerExec(t, node, "", "sh", "-c", "umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "+
		testKeyPath+".key 2>/dev/null && openssl pkey -in "+testKeyPath+".key -pubout -out "+testKeyPath+".pub"); err != nil {
		t.Fatalf("make the second key on %s: %v", node, err)
	}
	writeNodeFile(t, node, apiserverManifest, edited)
	var newKID string
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
	t.Logf("the API server signs with key %s and verifies %s too", newKID, oldKIDs[0])
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

// addSigningKey adds the test public key as a second verification key, and makes the test private
// key the signing key.
func addSigningKey(manifest string) (string, error) {
	if strings.Count(manifest, saVerifyFlag) != 1 || strings.Count(manifest, saSigningFlag) != 1 {
		return "", errors.New("the API server manifest does not hold each service account key flag exactly once")
	}
	out := strings.Replace(manifest, saVerifyFlag, saVerifyFlag+"    - --service-account-key-file="+testKeyPath+".pub\n", 1)
	return strings.Replace(out, saSigningFlag, "    - --service-account-signing-key-file="+testKeyPath+".key\n", 1), nil
}

// restoreAPIServer writes the original manifest back and deletes the test key. Pods that received a
// token from the test key during the test hold a token that the API server no longer accepts, so the
// cleanup deletes them, and their controllers create them again.
func restoreAPIServer(t *testing.T, cell, node, manifest string, oldKIDs []string) {
	t.Helper()
	writeNodeFile(t, node, apiserverManifest, manifest)
	if _, err := dockerExec(t, node, "", "rm", "-f", testKeyPath+".key", testKeyPath+".pub"); err != nil {
		t.Errorf("delete the test key on %s: %v", node, err)
	}
	waitFor(t, "the API server of "+cell+" to verify and sign with the original key only", apiserverWait, func() (bool, string) {
		kids, err := apiKIDsOnce(t, cell)
		if err != nil {
			return false, err.Error()
		}
		signing, err := signingKID(t, cell)
		if err != nil {
			return false, err.Error()
		}
		return slices.Equal(kids, oldKIDs) && signing == oldKIDs[0], fmt.Sprintf("keys %v, signing key %s", kids, signing)
	})
	// The mirror pod of the static pod reports the new container a little after the API answers.
	mirror := "kube-apiserver-" + node
	waitFor(t, "pod "+mirror+" Ready", apiserverWait, func() (bool, string) {
		out, err := kubectl(t, cell, "", "-n", "kube-system", "get", "pod", mirror,
			"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
		if err != nil {
			return false, err.Error()
		}
		return out == "True", "Ready " + out
	})
	deletePodsWithOtherKeys(t, cell, node, oldKIDs)
	waitWorkloadsReady(t, cell)
}

// deletePodsWithOtherKeys deletes each pod whose projected token on the node has a key ID outside
// kids. It reads only the token header, which holds the algorithm and the key ID.
func deletePodsWithOtherKeys(t *testing.T, cell, node string, kids []string) {
	t.Helper()
	out, err := dockerExec(t, node, "", "sh", "-c",
		`for f in /var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token; do [ -f "$f" ] && printf '%s %s\n' "$f" "$(cut -d. -f1 "$f")"; done; true`)
	if err != nil {
		t.Errorf("list the projected tokens on %s: %v", node, err)
		return
	}
	stale := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		path, head, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		rest, ok := strings.CutPrefix(path, "/var/lib/kubelet/pods/")
		if !ok {
			continue
		}
		uid, _, _ := strings.Cut(rest, "/")
		if kid := tokenKID(head + "."); kid != "" && !slices.Contains(kids, kid) {
			stale[uid] = true
		}
	}
	if len(stale) == 0 {
		t.Logf("no pod on %s holds a token from the test key", node)
		return
	}
	list, err := kubectl(t, cell, "", "get", "pods", "-A", "-o", "json")
	if err != nil {
		t.Errorf("list pods in %s: %v", cell, err)
		return
	}
	var pods struct {
		Items []struct {
			Metadata struct{ Name, Namespace, UID string } `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(list), &pods); err != nil {
		t.Errorf("decode pods of %s: %v", cell, err)
		return
	}
	for _, p := range pods.Items {
		if !stale[p.Metadata.UID] {
			continue
		}
		t.Logf("deleting pod %s/%s, which holds a token from the test key", p.Metadata.Namespace, p.Metadata.Name)
		if _, err := kubectl(t, cell, "", "-n", p.Metadata.Namespace, "delete", "pod", p.Metadata.Name, "--wait=false"); err != nil {
			t.Errorf("delete pod %s/%s: %v", p.Metadata.Namespace, p.Metadata.Name, err)
		}
	}
}

// waitWorkloadsReady waits until every Deployment, StatefulSet and DaemonSet of the cluster has all
// of its replicas updated and ready.
func waitWorkloadsReady(t *testing.T, cell string) {
	t.Helper()
	waitFor(t, "every workload of "+cell+" ready", workloadWait, func() (bool, string) {
		out, err := kubectl(t, cell, "", "get", "deployments,statefulsets,daemonsets", "-A", "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var list struct {
			Items []struct {
				Kind     string                          `json:"kind"`
				Metadata struct{ Name, Namespace string } `json:"metadata"`
				Spec     struct {
					Replicas *int `json:"replicas"`
				} `json:"spec"`
				Status struct {
					Replicas, ReadyReplicas, UpdatedReplicas, AvailableReplicas int
					DesiredNumberScheduled, NumberReady, UpdatedNumberScheduled int
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			return false, err.Error()
		}
		var bad []string
		for _, w := range list.Items {
			s := w.Status
			var ready bool
			switch w.Kind {
			case "DaemonSet":
				ready = s.NumberReady == s.DesiredNumberScheduled && s.UpdatedNumberScheduled == s.DesiredNumberScheduled
			default:
				want := 1
				if w.Spec.Replicas != nil {
					want = *w.Spec.Replicas
				}
				ready = s.ReadyReplicas == want && s.UpdatedReplicas == want && s.Replicas == want
			}
			if !ready {
				bad = append(bad, w.Kind+"/"+w.Metadata.Namespace+"/"+w.Metadata.Name)
			}
		}
		return len(bad) == 0, strings.Join(bad, ", ")
	})
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
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "create", "token", celldAccount, "--duration", "10m")
	if err != nil {
		return "", err
	}
	kid := tokenKID(strings.TrimSpace(out))
	if kid == "" {
		return "", errors.New("the token header holds no key ID")
	}
	return kid, nil
}
