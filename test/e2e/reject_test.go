//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The rejection tests run attestprobe as a Job in a cell. Each test asserts what the probe prints and
// the reason in the SPIRE server log. The renewal tests watch the celld agent and the server log.
const (
	rejectCell   = "dev-cell-1"
	celldAccount = "celld"
	probeLabel   = "cell.poc.internal/attestprobe"
	probeJobWait = 3 * time.Minute
	// The probe gives up after 60 seconds, so the Job ends well inside probeJobWait.
	probeDeadlineSeconds = 150
	serverLogWait        = time.Minute
	// Mac and node clocks agree within a few milliseconds. The margin keeps a log line that the server
	// writes in the same second as the start of a step.
	logMargin = 2 * time.Second
	// The server plugin logs this line for each denial, with the reason, cell and kid
	// (internal/clusterjwt/server.go).
	refusedMsg = "attestation refused"
	// SPIRE v1.15.5 agent log lines (pkg/agent/attestor/node/node.go, pkg/agent/svid/rotator.go).
	agentAttested   = "Node attestation was successful"
	agentNoSVID     = "SVID is not found. Starting node attestation"
	agentLoaded     = "SVID loaded"
	agentRotated    = "Successfully rotated agent SVID"
	agentReattested = "Successfully reattested node"
	celldUpdated    = "x509 svid updated"
	// The test profile in components/spire-server/server.conf gives agent and workload SVIDs a
	// lifetime of 1 minute. The agent renews at about half of that.
	renewWait      = 3 * time.Minute
	containerWait  = 2 * time.Minute
	tokenBinding   = "celld-token"
	trustBundleMap = "spire-trust-bundle"
	otherNamespace = "m2-other-subject"
	rogueDialNS    = "m2-rogue-dial"
	spireNodePort  = 30081
	apiServerPort  = 6443
)

func TestM2AttestProbeIssued(t *testing.T) {
	t.Parallel()
	res := runAttestProbe(t, probe{cell: rejectCell, namespace: celldNamespace, account: celldAccount, variant: "good"})
	id, ok := strings.CutPrefix(res.out, "issued:")
	want := agentIDPattern(rejectCell, res.podUID)
	if !ok || !want.MatchString(id) {
		t.Fatalf("attestprobe --variant good: want issued:<an agent ID like %s>, got %q", want, res.out)
	}
	waitServerLog(t, "a line "+attestDone+" for "+id, res.start, func(l logLine) bool {
		return l.str("msg") == attestDone && l.str("agent_id") == id
	})
}

func TestM2RejectNotPodBound(t *testing.T) {
	t.Parallel()
	rejectInCell(t, "not-pod-bound", "not_pod_bound")
}

func TestM2RejectLongLifetime(t *testing.T) {
	t.Parallel()
	rejectInCell(t, "long-lifetime", "lifetime_too_long")
}

func TestM2RejectWrongAudience(t *testing.T) {
	t.Parallel()
	rejectInCell(t, "wrong-audience", "wrong_audience")
}

// TestM2RejectOtherSubject runs the probe as a service account named celld in another namespace.
// The account name matches the record, so only the namespace differs.
func TestM2RejectOtherSubject(t *testing.T) {
	t.Parallel()
	createNamespace(t, rejectCell, otherNamespace)
	rbac := fmt.Sprintf(`apiVersion: v1
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
`, celldAccount, otherNamespace)
	if _, err := kubectl(t, rejectCell, rbac, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	copyTrustBundle(t, rejectCell, otherNamespace)
	res := runAttestProbe(t, probe{cell: rejectCell, namespace: otherNamespace, account: celldAccount, variant: "other-subject"})
	expectRefusal(t, res, rejectCell, "subject_not_allowed", cellKIDs(t, rejectCell))
}

// TestM2RejectRogueKey makes a token in rogue, for a namespace and service account of the same
// names as the celld ones, bound to a pod in rogue. rogue cannot reach the SPIRE node port, so an
// attestprobe Job in dev-cell-1 presents the token with the payload cell dev-cell-1. The audience
// cannot carry the nonce of that attestation, but the server checks the key ID first.
func TestM2RejectRogueKey(t *testing.T) {
	t.Parallel()
	needProbeImage(t)
	createNamespace(t, "rogue", celldNamespace)
	if _, err := kubectl(t, "rogue", "", "-n", celldNamespace, "create", "serviceaccount", celldAccount); err != nil {
		t.Fatal(err)
	}
	holder := fmt.Sprintf(`{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "token-holder", "namespace": %q},
  "spec": {"serviceAccountName": %q, "automountServiceAccountToken": false,
    "securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [{"name": "holder", "image": %q, "args": ["serve", "--addr", ":8080"],
      "securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}}}]}}`,
		celldNamespace, celldAccount, probeImage)
	if _, err := kubectl(t, "rogue", holder, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	uid, err := kubectl(t, "rogue", "", "-n", celldNamespace, "get", "pod", "token-holder", "-o", "jsonpath={.metadata.uid}")
	if err != nil || uid == "" {
		t.Fatalf("UID of the token holder pod in rogue: %q, %v", uid, err)
	}
	token, err := kubectl(t, "rogue", "", "-n", celldNamespace, "create", "token", celldAccount,
		"--audience", "spire-dev/rogue", "--duration", "10m",
		"--bound-object-kind", "Pod", "--bound-object-name", "token-holder", "--bound-object-uid", uid)
	if err != nil {
		t.Fatalf("TokenRequest in rogue: %v", err)
	}
	token = strings.TrimSpace(token)
	kid := tokenKID(token)
	if kid == "" || slices.Contains(cellKIDs(t, rejectCell), kid) {
		t.Fatalf("the rogue token has the key ID %q, want one that %s does not use (%v)", kid, rejectCell, cellKIDs(t, rejectCell))
	}
	t.Logf("rogue token with key ID %s", kid)

	secret := "m2-rogue-token-" + randomHex(t, 4)
	manifest, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": secret, "namespace": celldNamespace, "labels": map[string]string{probeLabel: secret}},
		"data":     map[string]string{"token": base64.StdEncoding.EncodeToString([]byte(token))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kubectl(t, rejectCell, string(manifest), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, rejectCell, "", "-n", celldNamespace, "delete", "secret", secret, "--ignore-not-found"); err != nil {
			t.Errorf("cleanup of Secret %s: %v", secret, err)
		}
	})
	res := runAttestProbe(t, probe{cell: rejectCell, namespace: celldNamespace, account: celldAccount, variant: "good", tokenSecret: secret})
	expectRefusal(t, res, rejectCell, "unknown_kid", []string{kid})
}

// TestM2RogueCannotDialServer checks the network half of the rogue case: a TCP connect from rogue to
// the SPIRE node port of dev-cp times out, because the server NetworkPolicy drops it. As a control,
// the same pod reaches the API server port of that node, a residual port of the shared network, so
// the address is right and the pod has a working network.
func TestM2RogueCannotDialServer(t *testing.T) {
	t.Parallel()
	createNamespace(t, "rogue", rogueDialNS)
	ip := clusterFacts(t, spireCluster).NodeIP
	for _, tc := range []struct {
		port int
		want string
	}{{apiServerPort, "connected"}, {spireNodePort, "timeout"}} {
		addr := fmt.Sprintf("%s:%d", ip, tc.port)
		out := runPod(t, "rogue", rogueDialNS, []string{"dial", "--addr", addr, "--timeout", "3s"})
		var res struct {
			Result string `json:"result"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("decode dial output %q: %v", out, err)
		}
		if res.Result != tc.want {
			t.Fatalf("dial from rogue to %s: want %s, got %s (%s)", addr, tc.want, res.Result, res.Error)
		}
	}
}

// TestM2RenewWithoutToken removes the RoleBinding that lets the celld pod request tokens, after its
// agent has attested. The agent must still renew its SVID twice, and celld must get two newer SVIDs,
// with no attestation in between.
func TestM2RenewWithoutToken(t *testing.T) {
	t.Parallel()
	const cell = "dev-cell-2"
	pod := replaceCelldPod(t, cell)
	waitCelldSVID(t, cell, pod)
	agentID := agentIDOf(t, cell, pod)
	removeTokenBinding(t, cell)
	since := time.Now()

	want := fmt.Sprintf("spiffe://%s/cell/%s/celld", spireTD, cell)
	waitFor(t, "two agent SVID rotations and two newer celld SVIDs without the RoleBinding", renewWait, func() (bool, string) {
		alog, err := podLog(t, cell, pod.Metadata.Name, "spire-agent", since)
		if err != nil {
			return false, err.Error()
		}
		clog, err := podLog(t, cell, pod.Metadata.Name, celldContainer, since)
		if err != nil {
			return false, err.Error()
		}
		rotations := len(matching(alog, func(l logLine) bool { return l.str("msg") == agentRotated && l.str("spiffe_id") == agentID }))
		var serials []string
		for _, l := range matching(clog, func(l logLine) bool { return l.str("msg") == celldUpdated && l.str("spiffe_id") == want }) {
			if s := l.str("serial"); !slices.Contains(serials, s) {
				serials = append(serials, s)
			}
		}
		return rotations >= 2 && len(serials) >= 2,
			fmt.Sprintf("%d agent rotations, celld serials %v, agent log: %s", rotations, serials, lastLines(alog, 3))
	})

	alog, err := podLog(t, cell, pod.Metadata.Name, "spire-agent", since)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{agentAttested, agentNoSVID, agentReattested} {
		if n := len(matching(alog, func(l logLine) bool { return l.str("msg") == msg })); n > 0 {
			t.Errorf("the agent logged %q %d times after the RoleBinding was removed", msg, n)
		}
	}
	expectOneAttestation(t, pod)
	if n := containerRestarts(t, cell, pod.Metadata.Name, "spire-agent"); n != 0 {
		t.Errorf("the spire-agent container restarted %d times, want 0", n)
	}
}

// TestM2AgentRestartKeepsID stops the spire-agent container of a new celld pod on the node. The
// container that kubelet starts again loads the SVID from the pod memory volume, keeps the agent ID
// and renews, with no new attestation.
func TestM2AgentRestartKeepsID(t *testing.T) {
	t.Parallel()
	const cell = rejectCell
	pod := replaceCelldPod(t, cell)
	waitCelldSVID(t, cell, pod)
	agentID := agentIDOf(t, cell, pod)
	id, restarts := agentContainer(t, cell, pod.Metadata.Name)
	if _, err := dockerExec(t, pod.Spec.NodeName, "", "crictl", "stop", id); err != nil {
		t.Fatalf("stop the spire-agent container: %v", err)
	}
	stopped := time.Now()
	waitFor(t, "a new ready spire-agent container in "+pod.Metadata.Name, containerWait, func() (bool, string) {
		newID, n := agentContainer(t, cell, pod.Metadata.Name)
		return n == restarts+1 && newID != id && containerReady(t, cell, pod.Metadata.Name, "spire-agent"),
			fmt.Sprintf("container %s with %d restarts", newID, n)
	})
	// The SVID lasts SPIRE_SVID_TTL of cells/dev-cp.env. A restart that takes longer finds it expired,
	// and the agent then attests again as a new agent. That is a timing failure, not a lost SVID.
	if logs, err := podLog(t, cell, pod.Metadata.Name, "spire-agent", time.Time{}); err == nil {
		if expired := matching(logs, func(l logLine) bool {
			return strings.HasPrefix(l.str("msg"), "SVID key recovered, but SVID is expired")
		}); len(expired) > 0 {
			t.Fatalf("the agent SVID expired while the container was down: the restart took %s, against the SVID lifetime SPIRE_SVID_TTL of cells/dev-cp.env",
				time.Since(stopped).Round(time.Second))
		}
	}

	var logs string
	waitFor(t, "an agent rotation for "+agentID+" in the new container", renewWait, func() (bool, string) {
		var err error
		if logs, err = podLog(t, cell, pod.Metadata.Name, "spire-agent", time.Time{}); err != nil {
			return false, err.Error()
		}
		n := len(matching(logs, func(l logLine) bool { return l.str("msg") == agentRotated && l.str("spiffe_id") == agentID }))
		return n > 0, lastLines(logs, 3)
	})
	if n := len(matching(logs, func(l logLine) bool { return l.str("msg") == agentLoaded && l.str("spiffe_id") == agentID })); n != 1 {
		t.Errorf("the new container logged %q for %s %d times, want 1", agentLoaded, agentID, n)
	}
	for _, msg := range []string{agentAttested, agentNoSVID, agentReattested} {
		if n := len(matching(logs, func(l logLine) bool { return l.str("msg") == msg })); n > 0 {
			t.Errorf("the new container logged %q %d times", msg, n)
		}
	}
	expectOneAttestation(t, pod)
}

func rejectInCell(t *testing.T, variant, reason string) {
	t.Helper()
	res := runAttestProbe(t, probe{cell: rejectCell, namespace: celldNamespace, account: celldAccount, variant: variant})
	expectRefusal(t, res, rejectCell, reason, cellKIDs(t, rejectCell))
}

type probe struct {
	cell, namespace, account, variant string
	// tokenSecret names a Secret with the key token. The probe then sends that token.
	tokenSecret string
}

type probeResult struct {
	out    string
	podUID string
	start  time.Time
}

// runAttestProbe runs attestprobe as a Job and returns the line that it printed. In
// cell-identity-system the Job gets the egress of celld through its own NetworkPolicy, because the
// namespace denies all traffic by default.
func runAttestProbe(t *testing.T, p probe) probeResult {
	t.Helper()
	needAttestprobeImage(t)
	run := randomHex(t, 4)
	name := "attestprobe-" + p.variant + "-" + run
	if p.namespace == celldNamespace {
		allowProbeEgress(t, p.cell, run)
	}
	args := []string{"--variant", p.variant, "--cell", p.cell,
		"--server", fmt.Sprintf("%s:%d", clusterFacts(t, spireCluster).NodeIP, spireNodePort)}
	volumes := []map[string]any{{"name": "bundle", "configMap": map[string]any{"name": trustBundleMap}}}
	mounts := []map[string]any{{"name": "bundle", "mountPath": "/run/spire/bundle", "readOnly": true}}
	if p.tokenSecret != "" {
		args = append(args, "--token-file", "/run/attestprobe/token")
		volumes = append(volumes, map[string]any{"name": "token", "secret": map[string]any{"secretName": p.tokenSecret}})
		mounts = append(mounts, map[string]any{"name": "token", "mountPath": "/run/attestprobe", "readOnly": true})
	}
	fieldEnv := func(name, path string) map[string]any {
		return map[string]any{"name": name, "valueFrom": map[string]any{"fieldRef": map[string]any{"fieldPath": path}}}
	}
	labels := map[string]string{probeLabel: run}
	job := map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{"name": name, "namespace": p.namespace, "labels": labels},
		"spec": map[string]any{
			"backoffLimit": 0, "activeDeadlineSeconds": probeDeadlineSeconds,
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels, "annotations": map[string]string{"sidecar.istio.io/inject": "false"}},
				"spec": map[string]any{
					"serviceAccountName": p.account, "automountServiceAccountToken": true, "restartPolicy": "Never",
					"securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
					"containers": []map[string]any{{
						"name": "attestprobe", "image": attestprobeImage, "args": args,
						"env": []map[string]any{
							fieldEnv("POD_NAME", "metadata.name"), fieldEnv("POD_UID", "metadata.uid"),
							fieldEnv("POD_NAMESPACE", "metadata.namespace"), fieldEnv("SERVICE_ACCOUNT", "spec.serviceAccountName"),
						},
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
							"capabilities": map[string]any{"drop": []string{"ALL"}},
						},
						"volumeMounts": mounts,
					}},
					"volumes": volumes,
				},
			},
		},
	}
	manifest, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-logMargin)
	if _, err := kubectl(t, p.cell, string(manifest), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, p.cell, "", "-n", p.namespace, "delete", "job", name, "--cascade=foreground", "--ignore-not-found", "--wait=true", "--timeout=120s"); err != nil {
			t.Errorf("cleanup of Job %s: %v", name, err)
		}
	})

	var failed bool
	waitFor(t, "Job "+name+" in "+p.cell+" to finish", probeJobWait, func() (bool, string) {
		out, err := kubectl(t, p.cell, "", "-n", p.namespace, "get", "job", name, "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var j struct {
			Status struct {
				Succeeded int `json:"succeeded"`
				Failed    int `json:"failed"`
			} `json:"status"`
		}
		if err := json.Unmarshal([]byte(out), &j); err != nil {
			return false, err.Error()
		}
		failed = j.Status.Failed > 0
		return j.Status.Succeeded > 0 || failed, fmt.Sprintf("succeeded %d, failed %d", j.Status.Succeeded, j.Status.Failed)
	})
	uid, err := kubectl(t, p.cell, "", "-n", p.namespace, "get", "pods", "-l", probeLabel+"="+run, "-o", "jsonpath={.items[0].metadata.uid}")
	if err != nil {
		t.Fatal(err)
	}
	logs, err := kubectl(t, p.cell, "", "-n", p.namespace, "logs", "job/"+name)
	if err != nil {
		t.Fatal(err)
	}
	if failed {
		desc, _ := kubectl(t, p.cell, "", "-n", p.namespace, "describe", "job", name)
		t.Fatalf("attestprobe Job %s failed\nlogs: %s\n%s", name, logs, desc)
	}
	out := strings.TrimSpace(logs)
	t.Logf("attestprobe --variant %s in %s/%s as %s printed %q", p.variant, p.cell, p.namespace, p.account, out)
	// An issued SVID makes an agent entry on the server, whatever the test expected.
	if id, ok := strings.CutPrefix(out, "issued:"); ok && strings.HasPrefix(id, "spiffe://") {
		t.Cleanup(func() { evictAgent(t, id) })
	}
	return probeResult{out: out, podUID: uid, start: start}
}

// allowProbeEgress gives the probe pods of one run the egress rules of the live celld NetworkPolicy.
func allowProbeEgress(t *testing.T, cell, run string) {
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
	name := "m2-attestprobe-" + run
	policy, err := json.Marshal(map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
		"metadata": map[string]any{"name": name, "namespace": celldNamespace, "labels": map[string]string{probeLabel: run}},
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": map[string]string{probeLabel: run}},
			"policyTypes": []string{"Egress"}, "egress": live.Spec.Egress,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kubectl(t, cell, string(policy), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, cell, "", "-n", celldNamespace, "delete", "networkpolicy", name, "--ignore-not-found"); err != nil {
			t.Errorf("cleanup of NetworkPolicy %s: %v", name, err)
		}
	})
}

// copyTrustBundle copies ConfigMap spire-trust-bundle of cell-identity-system into a test namespace.
func copyTrustBundle(t *testing.T, cell, ns string) {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "get", "configmap", trustBundleMap, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &cm); err != nil || cm.Data["bundle.crt"] == "" {
		t.Fatalf("ConfigMap %s holds no bundle.crt: %v", trustBundleMap, err)
	}
	copied, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": trustBundleMap, "namespace": ns}, "data": cm.Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kubectl(t, cell, string(copied), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
}

// expectRefusal checks the outcome line of the probe and the refusal in the server log. The server
// log line must carry the reason, the cell and one of the key IDs.
func expectRefusal(t *testing.T, res probeResult, cell, reason string, kids []string) {
	t.Helper()
	// SPIRE returns the plugin message to the client. It replaces the prefix "cluster_jwt: " of the
	// plugin with "nodeattestor(cluster_jwt): " (pkg/common/plugin/facade.go in v1.15.5).
	if want := "denied:nodeattestor(cluster_jwt): " + reason; res.out != want {
		t.Errorf("attestprobe: want %q, got %q", want, res.out)
	}
	waitServerLog(t, fmt.Sprintf("a line %q with reason %s, cell %s and a kid in %v", refusedMsg, reason, cell, kids), res.start, func(l logLine) bool {
		return l.str("msg") == refusedMsg && l.str("reason") == reason && l.str("cell") == cell && slices.Contains(kids, l.str("kid"))
	})
}

type logLine map[string]any

func (l logLine) str(k string) string {
	s, _ := l[k].(string)
	return s
}

// matching returns the JSON log lines of logs for which keep returns true.
func matching(logs string, keep func(logLine) bool) []logLine {
	var out []logLine
	for line := range strings.SplitSeq(logs, "\n") {
		var l logLine
		if json.Unmarshal([]byte(line), &l) == nil && keep(l) {
			out = append(out, l)
		}
	}
	return out
}

func serverLog(t *testing.T, since time.Time) (string, error) {
	t.Helper()
	return kubectl(t, spireCluster, "", "-n", spireNamespace, "logs", spireServerPod, "-c", "spire-server",
		"--since-time="+since.UTC().Format(time.RFC3339))
}

func waitServerLog(t *testing.T, what string, since time.Time, keep func(logLine) bool) {
	t.Helper()
	waitFor(t, "SPIRE server log "+what, serverLogWait, func() (bool, string) {
		logs, err := serverLog(t, since)
		if err != nil {
			return false, err.Error()
		}
		if found := matching(logs, keep); len(found) > 0 {
			t.Logf("server log: %v", found[0])
			return true, ""
		}
		return false, fmt.Sprintf("no such line in %d log bytes, refusals: %v", len(logs),
			matching(logs, func(l logLine) bool { return l.str("msg") == refusedMsg }))
	})
}

// expectOneAttestation checks that the server attested the pod exactly once since the pod started.
func expectOneAttestation(t *testing.T, pod podInfo) {
	t.Helper()
	created, err := time.Parse(time.RFC3339, pod.Metadata.CreationTimestamp)
	if err != nil {
		t.Fatalf("creation time of pod %s: %v", pod.Metadata.Name, err)
	}
	logs, err := serverLog(t, created.Add(-logMargin))
	if err != nil {
		t.Fatal(err)
	}
	ids := matching(logs, func(l logLine) bool {
		return l.str("msg") == attestDone && strings.Contains(l.str("agent_id"), "/"+pod.Metadata.UID+"/")
	})
	if len(ids) != 1 {
		t.Errorf("want one %q line for pod UID %s since the pod started, got %d: %v", attestDone, pod.Metadata.UID, len(ids), ids)
	}
}

func agentIDPattern(cell, podUID string) *regexp.Regexp {
	return regexp.MustCompile(`^spiffe://` + regexp.QuoteMeta(spireTD) + `/spire/agent/cluster_jwt/` +
		regexp.QuoteMeta(cell) + `/` + regexp.QuoteMeta(podUID) + `/[0-9a-f]{32}$`)
}

// agentIDOf returns the agent ID that the current spire-agent container of a celld pod logged when
// it attested, or when it loaded the SVID after a container restart.
func agentIDOf(t *testing.T, cell string, pod podInfo) string {
	t.Helper()
	logs, err := podLog(t, cell, pod.Metadata.Name, "spire-agent", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	lines := matching(logs, func(l logLine) bool { return l.str("msg") == agentAttested || l.str("msg") == agentLoaded })
	if len(lines) != 1 || !agentIDPattern(cell, pod.Metadata.UID).MatchString(lines[0].str("spiffe_id")) {
		t.Fatalf("want one %q or %q line with an agent ID for pod UID %s, got %v", agentAttested, agentLoaded, pod.Metadata.UID, lines)
	}
	id := lines[0].str("spiffe_id")
	t.Logf("agent ID %s", id)
	return id
}

// podLog returns the log of the current container, from since on when since is not zero.
func podLog(t *testing.T, cell, pod, container string, since time.Time) (string, error) {
	t.Helper()
	args := []string{"-n", celldNamespace, "logs", pod, "-c", container}
	if !since.IsZero() {
		args = append(args, "--since-time="+since.UTC().Format(time.RFC3339))
	}
	return kubectl(t, cell, "", args...)
}

func celldPod(t *testing.T, cell, name string) podInfo {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "get", "pod", name, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var p podInfo
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("decode pod %s: %v", name, err)
	}
	return p
}

// agentContainer returns the runtime ID of the spire-agent container and its restart count.
func agentContainer(t *testing.T, cell, pod string) (string, int) {
	t.Helper()
	for _, c := range celldPod(t, cell, pod).Status.ContainerStatuses {
		if c.Name == "spire-agent" {
			return strings.TrimPrefix(c.ContainerID, "containerd://"), c.RestartCount
		}
	}
	t.Fatalf("pod %s has no spire-agent container status", pod)
	return "", 0
}

func containerReady(t *testing.T, cell, pod, name string) bool {
	t.Helper()
	for _, c := range celldPod(t, cell, pod).Status.ContainerStatuses {
		if c.Name == name {
			return c.Ready
		}
	}
	return false
}

func containerRestarts(t *testing.T, cell, pod, name string) int {
	t.Helper()
	for _, c := range celldPod(t, cell, pod).Status.ContainerStatuses {
		if c.Name == name {
			return c.RestartCount
		}
	}
	t.Fatalf("pod %s has no %s container status", pod, name)
	return 0
}

// removeTokenBinding deletes the RoleBinding that lets celld request tokens. The cleanup applies the
// RoleBinding of the harness bundle again, with the field manager kubectl, as scripts/up.sh does.
func removeTokenBinding(t *testing.T, cell string) {
	t.Helper()
	bundle := filepath.Join("../../build", cell, "bundles", "cell-identity", "manifests.yaml")
	binding := runTool(t, nil, "yq", `select(.kind == "RoleBinding" and .metadata.name == "`+tokenBinding+`")`, bundle)
	if !strings.Contains(binding, "kind: RoleBinding") {
		t.Fatalf("%s holds no RoleBinding %s", bundle, tokenBinding)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, cell, binding, "apply", "--server-side", "--force-conflicts", "-f", "-"); err != nil {
			t.Errorf("apply RoleBinding %s again in %s: %v", tokenBinding, cell, err)
			return
		}
		waitFor(t, "celld may request tokens again in "+cell, forwardWait, func() (bool, string) {
			ans := canRequestToken(t, cell)
			return ans == "yes", ans
		})
	})
	if _, err := kubectl(t, cell, "", "-n", celldNamespace, "delete", "rolebinding", tokenBinding, "--wait=true"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "celld may no longer request tokens in "+cell, forwardWait, func() (bool, string) {
		ans := canRequestToken(t, cell)
		return ans == "no", ans
	})
}

// canRequestToken asks the API server whether celld may request a token for itself.
func canRequestToken(t *testing.T, cell string) string {
	t.Helper()
	out, _ := kubectl(t, cell, "", "-n", celldNamespace, "auth", "can-i", "create", "serviceaccounts/"+celldAccount,
		"--subresource=token", "--as=system:serviceaccount:"+celldNamespace+":"+celldAccount)
	return strings.TrimSpace(out)
}

func evictAgent(t *testing.T, id string) {
	t.Helper()
	if out, err := spireServer(t, "agent", "evict", "-socketPath", spireSocket, "-spiffeID", id); err != nil {
		t.Errorf("evict the probe agent %s: %v: %s", id, err, out)
	}
}

// cellKIDs returns the key IDs in the JWKS that the host service reports for a cluster.
func cellKIDs(t *testing.T, cell string) []string {
	t.Helper()
	kids, err := jwksKIDs(clusterFacts(t, cell).JWKS)
	if err != nil || len(kids) == 0 {
		t.Fatalf("JWKS of %s: %v, %v", cell, kids, err)
	}
	return kids
}

func jwksKIDs(jwks []byte) ([]string, error) {
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil, err
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KID)
	}
	slices.Sort(kids)
	return kids, nil
}

// tokenKID returns the key ID from the header of a token. It reads only the header.
func tokenKID(token string) string {
	head, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return ""
	}
	var h struct {
		KID string `json:"kid"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.KID
}

// dockerExec runs a command in a kind node container and returns standard output.
func dockerExec(t *testing.T, node, stdin string, args ...string) (string, error) {
	t.Helper()
	full := []string{"exec"}
	if stdin != "" {
		full = append(full, "-i")
	}
	full = append(append(full, node), args...)
	ctx, cancel := context.WithTimeout(context.Background(), kubectlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("docker exec %s %s: %w: %s", node, args[0], err, stderr.String())
	}
	return string(out), nil
}
