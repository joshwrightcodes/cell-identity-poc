//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	bindNodePort = 30447
	bindNS       = "m4-bind"
	// denialQuiet is longer than the window (10 s) of the denial log limiter of mgmtd, which allows one line for each reason.
	denialQuiet = 11 * time.Second
	bindJobWait = 4 * time.Minute
)

var (
	denialLine = regexp.MustCompile(`^denied:([0-9a-f]{16})$`)
	nonceLine  = regexp.MustCompile(`^nonce:(\S+) (\S+)$`)
)

// bindEnv is the pod environment that the mgmt-bind target of attestprobe reads.
func bindEnv() []map[string]any {
	field := func(name, path string) map[string]any {
		return map[string]any{"name": name, "valueFrom": map[string]any{"fieldRef": map[string]any{"fieldPath": path}}}
	}
	return []map[string]any{field("POD_NAME", "metadata.name"), field("POD_UID", "metadata.uid"),
		field("POD_NAMESPACE", "metadata.namespace"), field("SERVICE_ACCOUNT", "spec.serviceAccountName")}
}

// probeJob is an attestprobe Job. The pods carry the label probeLabel=run, so allowBindEgress and gate:m4:repair find them.
type probeJob struct {
	cluster, namespace, account, run string
	args                             []string
	secret                           string // Secret with the key token, mounted at /run/attestprobe
	completions, parallelism         int
	backoffLimit                     int
}

func (j probeJob) name() string { return "attestprobe-bind-" + j.run }

func (j probeJob) manifest() []byte {
	volumes := []map[string]any{{"name": "mgmt-root", "configMap": map[string]any{"name": "mgmt-root"}}}
	mounts := []map[string]any{{"name": "mgmt-root", "mountPath": "/run/mgmt-root", "readOnly": true}}
	if j.secret != "" {
		volumes = append(volumes, map[string]any{"name": "token", "secret": map[string]any{"secretName": j.secret}})
		mounts = append(mounts, map[string]any{"name": "token", "mountPath": "/run/attestprobe", "readOnly": true})
	}
	labels := map[string]string{probeLabel: j.run}
	spec := map[string]any{
		"backoffLimit": j.backoffLimit, "activeDeadlineSeconds": 600,
		"template": map[string]any{
			"metadata": map[string]any{"labels": labels, "annotations": map[string]string{"sidecar.istio.io/inject": "false"}},
			"spec": map[string]any{
				"serviceAccountName": j.account, "automountServiceAccountToken": true, "restartPolicy": "Never",
				"securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
				"containers": []map[string]any{{
					"name": "attestprobe", "image": attestprobeImage, "args": j.args, "env": bindEnv(),
					"securityContext": map[string]any{
						"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
						"capabilities": map[string]any{"drop": []string{"ALL"}},
					},
					"volumeMounts": mounts,
				}},
				"volumes": volumes,
			},
		},
	}
	if j.completions > 0 {
		spec["completions"], spec["parallelism"] = j.completions, j.parallelism
	}
	b, _ := json.Marshal(map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{"name": j.name(), "namespace": j.namespace, "labels": labels}, "spec": spec,
	})
	return b
}

// start creates the Job and deletes it when the test ends.
func (j probeJob) start(t *testing.T) {
	t.Helper()
	if _, err := kubectl(t, j.cluster, string(j.manifest()), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, j.cluster, "", "-n", j.namespace, "delete", "job", j.name(), "--cascade=foreground", "--ignore-not-found", "--wait=true", "--timeout=180s"); err != nil {
			t.Errorf("cleanup of Job %s: %v", j.name(), err)
		}
	})
}

// wait waits until the Job has succeeded or failed, and returns the counts.
func (j probeJob) wait(t *testing.T, timeout time.Duration) (succeeded, failed int, done bool) {
	t.Helper()
	waitFor(t, "Job "+j.name()+" in "+j.cluster+" to finish", timeout, func() (bool, string) {
		out, err := kubectl(t, j.cluster, "", "-n", j.namespace, "get", "job", j.name(), "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var st struct {
			Spec   struct{ Completions *int }
			Status struct {
				Succeeded  int `json:"succeeded"`
				Failed     int `json:"failed"`
				Conditions []struct{ Type, Status string }
			} `json:"status"`
		}
		if err := json.Unmarshal([]byte(out), &st); err != nil {
			return false, err.Error()
		}
		succeeded, failed = st.Status.Succeeded, st.Status.Failed
		for _, c := range st.Status.Conditions {
			if (c.Type == "Complete" || c.Type == "Failed") && c.Status == "True" {
				done = c.Type == "Complete"
				return true, ""
			}
		}
		return false, fmt.Sprintf("succeeded %d, failed %d", succeeded, failed)
	})
	return succeeded, failed, done
}

// run1 starts a one-pod Job, waits for it, and returns the lines that it printed. A failed Job fails the test.
func (j probeJob) run1(t *testing.T) []string {
	t.Helper()
	j.start(t)
	_, failed, done := j.wait(t, bindJobWait)
	logs, _ := kubectl(t, j.cluster, "", "-n", j.namespace, "logs", "job/"+j.name())
	if !done {
		t.Fatalf("Job %s failed (%d failed pods): %s", j.name(), failed, logs)
	}
	var lines []string
	for l := range strings.SplitSeq(strings.TrimSpace(logs), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	t.Logf("%s in %s/%s as %s printed %q", strings.Join(j.args[:2], " "), j.cluster, j.namespace, j.account, lines)
	return lines
}

// allowBindEgress gives the probe pods of one run the egress rules of the live celld NetworkPolicy, which include the node port
// 30447 of dev-cp, in any namespace of the cell.
func allowBindEgress(t *testing.T, cell, ns, run string) {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "get", "networkpolicy", "celld", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var live struct {
		Spec struct {
			Egress []json.RawMessage `json:"egress"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(out), &live); err != nil || len(live.Spec.Egress) == 0 {
		t.Fatalf("decode the egress rules of NetworkPolicy celld: %v", err)
	}
	if !strings.Contains(out, strconv.Itoa(bindNodePort)) {
		t.Fatalf("NetworkPolicy celld admits no port %d: %s", bindNodePort, out)
	}
	policy, _ := json.Marshal(map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
		"metadata": map[string]any{"name": "m4-attestprobe-" + run, "namespace": ns, "labels": map[string]string{probeLabel: run}},
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": map[string]string{probeLabel: run}},
			"policyTypes": []string{"Egress"}, "egress": live.Spec.Egress,
		},
	})
	if _, err := kubectl(t, cell, string(policy), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, cell, "", "-n", ns, "delete", "networkpolicy", "m4-attestprobe-"+run, "--ignore-not-found"); err != nil {
			t.Errorf("cleanup of NetworkPolicy m4-attestprobe-%s: %v", run, err)
		}
	})
}

// copyMgmtRoot copies ConfigMap mgmt-root of cell-identity-system into a namespace of the cell, with the probe label.
func copyMgmtRoot(t *testing.T, cell, ns string) {
	t.Helper()
	root, err := kubectl(t, cell, "", "-n", celldNamespace, "get", "configmap", "mgmt-root", "-o", `jsonpath={.data.root\.crt}`)
	if err != nil || strings.TrimSpace(root) == "" {
		t.Fatalf("ConfigMap mgmt-root of %s holds no root: %v", cell, err)
	}
	cm, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "mgmt-root", "namespace": ns, "labels": map[string]string{probeLabel: "mgmt-root"}}, "data": map[string]string{"root.crt": root}})
	if _, err := kubectl(t, cell, string(cm), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, cell, "", "-n", ns, "delete", "configmap", "mgmt-root", "--ignore-not-found"); err != nil {
			t.Errorf("cleanup of ConfigMap mgmt-root in %s: %v", ns, err)
		}
	})
}

// tokenSecret stores a token in a Secret of the cell, with the probe label, and deletes it when the test ends.
func tokenSecret(t *testing.T, cell, ns, token string) string {
	t.Helper()
	name := "m4-token-" + randomHex(t, 4)
	manifest, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]string{probeLabel: name}},
		"data":     map[string]string{"token": base64.StdEncoding.EncodeToString([]byte(token))}})
	if _, err := kubectl(t, cell, string(manifest), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, cell, "", "-n", ns, "delete", "secret", name, "--ignore-not-found"); err != nil {
			t.Errorf("cleanup of Secret %s: %v", name, err)
		}
	})
	return name
}

// bindProbe returns a Job that binds through the node port of dev-cp. The caller adds the arguments after the target.
func bindProbe(t *testing.T, cell, ns, account string, extra ...string) probeJob {
	t.Helper()
	needAttestprobeImage(t)
	run := randomHex(t, 4)
	allowBindEgress(t, cell, ns, run)
	args := append([]string{"--target", "mgmt-bind", "--upstream", fmt.Sprintf("%s:%d", clusterFacts(t, spireCluster).NodeIP, bindNodePort),
		"--expect-id", mgmtAPIID, "--peer-bundle", "/run/mgmt-root/root.crt", "--env", pocEnv}, extra...)
	return probeJob{cluster: cell, namespace: ns, account: account, run: run, args: args, backoffLimit: 0}
}

// mgmtdDenial waits for the mgmtd log line bind_denied with the request ID.
func mgmtdDenial(t *testing.T, id string, since time.Time) logLine {
	t.Helper()
	var found logLine
	waitFor(t, "the mgmtd log line bind_denied with the request ID "+id, time.Minute, func() (bool, string) {
		logs := mgmtdLog(t, since)
		for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "bind_denied" && l.str("request_id") == id }) {
			found = l
			return true, ""
		}
		return false, lastLines(logs, 2)
	})
	return found
}

// celldRBAC lets service account celld of a test namespace request a token for itself.
func celldRBAC(ns string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata: {name: %[1]s, namespace: %[2]s}
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: %[1]s, namespace: %[2]s}
rules:
  - {apiGroups: [""], resources: [serviceaccounts/token], resourceNames: [%[1]s], verbs: [create]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: %[1]s, namespace: %[2]s}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: %[1]s}
subjects:
  - {kind: ServiceAccount, name: %[1]s, namespace: %[2]s}
`, celldAccount, ns)
}

// recordRevisions returns the record revision of each cell in the status of mgmtd.
func recordRevisions(t *testing.T) map[string]spec.Revision {
	t.Helper()
	out := map[string]spec.Revision{}
	for _, c := range mgmtStatus(t).Cells {
		out[c.Name] = c.Record
	}
	return out
}

// rogueToken makes a token in the cluster rogue for cell-identity-system/celld with the audience, bound to a pod there.
func rogueToken(t *testing.T, audience string) string {
	t.Helper()
	needProbeImage(t)
	createNamespace(t, "rogue", celldNamespace)
	if _, err := kubectl(t, "rogue", "", "-n", celldNamespace, "create", "serviceaccount", celldAccount); err != nil {
		t.Fatal(err)
	}
	holder := fmt.Sprintf(`{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "token-holder", "namespace": %q},
  "spec": {"serviceAccountName": %q, "automountServiceAccountToken": false,
    "securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [{"name": "holder", "image": %q, "args": ["serve", "--addr", ":8080"],
      "securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}}}]}}`, celldNamespace, celldAccount, probeImage)
	if _, err := kubectl(t, "rogue", holder, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	uid, err := kubectl(t, "rogue", "", "-n", celldNamespace, "get", "pod", "token-holder", "-o", "jsonpath={.metadata.uid}")
	if err != nil || uid == "" {
		t.Fatalf("UID of the token holder pod in rogue: %q, %v", uid, err)
	}
	token, err := kubectl(t, "rogue", "", "-n", celldNamespace, "create", "token", celldAccount, "--audience", audience, "--duration", "10m",
		"--bound-object-kind", "Pod", "--bound-object-name", "token-holder", "--bound-object-uid", uid)
	if err != nil {
		t.Fatalf("TokenRequest in rogue: %v", err)
	}
	return strings.TrimSpace(token)
}

// lastLine returns the last line of a probe output, and fails the test when the output is empty.
func lastLine(t *testing.T, lines []string) string {
	t.Helper()
	if len(lines) == 0 {
		t.Fatal("the probe Job printed nothing, want a result line")
	}
	return lines[len(lines)-1]
}

// nonceFor requests a bind nonce for a cell through a Job in the namespace, and returns the nonce and its audience.
func nonceFor(t *testing.T, cell, ns, account, forCell string) (nonce, audience string) {
	t.Helper()
	lines := bindProbe(t, cell, ns, account, "--cell", forCell, "--variant", "good", "--nonce-only").run1(t)
	if len(lines) != 1 {
		t.Fatalf("the nonce request printed %q, want one line", lines)
	}
	m := nonceLine.FindStringSubmatch(lines[0])
	if m == nil {
		t.Fatalf("the nonce request printed %q, want nonce:<value> <audience>", lines[0])
	}
	return m[1], m[2]
}

// forgedToken makes a bind token with the claims of a good one for a cell and a random key and signature.
func forgedToken(t *testing.T, issuer, audience string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "forged-" + randomHex(t, 8)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ref := func(name string) map[string]string {
		return map[string]string{"name": name, "uid": "00000000-0000-4000-8000-000000000001"}
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: issuer, Subject: "system:serviceaccount:" + celldNamespace + ":" + celldAccount, Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}).Claims(map[string]any{"kubernetes.io": map[string]any{
		"namespace": celldNamespace, "serviceaccount": ref(celldAccount), "pod": ref("forged-pod"), "node": ref("forged-node"),
	}}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	// The signature is junk: replace it with random bytes of the same length.
	parts := strings.Split(raw, ".")
	junk := make([]byte, 64)
	_, _ = rand.Read(junk)
	parts[2] = base64.RawURLEncoding.EncodeToString(junk)
	return strings.Join(parts, ".")
}
