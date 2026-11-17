//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

const (
	cellCtlNamespace  = "cell-controller-system"
	cellCtlDeployment = "cell-controller"
	cellStepsMap      = "cell-steps"
	stepStatusMap     = "step-status"
	cellCtlUID        = "65532"
	hostsvcPort       = "17443"
	// stepLogWindow is how long a step must stay out of the host service log before a test calls it absent. The cell controller sends
	// a step within one read, 10 s, and the host service logs a refusal at once.
	stepLogWindow = 30 * time.Second
)

// cellStepsConfigMap returns the data, the annotations and the labels of ConfigMap cell-controller-system/cell-steps in dev-cp.
func cellStepsConfigMap(t *testing.T) (data, annotations, labels map[string]string, err error) {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "get", "configmap", cellStepsMap, "-o", "json")
	if err != nil {
		return nil, nil, nil, err
	}
	var cm struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
			Labels      map[string]string `json:"labels"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &cm); err != nil {
		return nil, nil, nil, fmt.Errorf("decode ConfigMap %s: %w", cellStepsMap, err)
	}
	return cm.Data, cm.Metadata.Annotations, cm.Metadata.Labels, nil
}

// stepStatusEntries returns the entries of key status.json of ConfigMap step-status. It returns none when the ConfigMap is absent.
func stepStatusEntries(t *testing.T) []mgmtapi.StepStatus {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "get", "configmap", stepStatusMap, "-o", `jsonpath={.data.status\.json}`)
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}
	var doc struct {
		Steps []mgmtapi.StepStatus `json:"steps"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("status.json of ConfigMap %s is no status object: %v\n%s", stepStatusMap, err, out)
	}
	return doc.Steps
}

// stepStatusOf returns the entry of ConfigMap step-status for the step ID. It matches by step ID, never by cell, because an entry of an
// older step of the cell stays until the controller drops it.
func stepStatusOf(t *testing.T, id string) (mgmtapi.StepStatus, bool) {
	t.Helper()
	for _, s := range stepStatusEntries(t) {
		if s.ID == id {
			return s, true
		}
	}
	return mgmtapi.StepStatus{}, false
}

// hostLogForStep returns the lines of the log of the host service whose field step is the step ID, as decoded records.
func hostLogForStep(t *testing.T, id string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(hostsvcLogFile)
	if err != nil {
		t.Fatalf("read the host service log: %v", err)
	}
	var found []map[string]any
	for line := range strings.SplitSeq(string(data), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["step"] == id {
			found = append(found, rec)
		}
	}
	return found
}

// cellCtlLog returns the JSON lines of the log of the cell controller since the time, as decoded records.
func cellCtlLog(t *testing.T, since time.Time) []map[string]any {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "logs", "deploy/"+cellCtlDeployment, "-c", cellCtlDeployment, "--since-time="+since.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("read the log of the cell controller: %v", err)
	}
	var recs []map[string]any
	for line := range strings.SplitSeq(out, "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil {
			recs = append(recs, rec)
		}
	}
	return recs
}

// cellCtlPod returns the name of the running cell controller pod.
func cellCtlPod(t *testing.T) string {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+cellCtlDeployment,
		"--field-selector=status.phase=Running", "-o", "jsonpath={.items[0].metadata.name}")
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("no running pod of the cell controller in %s: %v", cellCtlNamespace, err)
	}
	return strings.TrimSpace(out)
}

// hostsvcNodeAddress returns the one address that host.docker.internal has in the node container of dev-cp. Pods reach the host
// service there.
func hostsvcNodeAddress(t *testing.T) string {
	t.Helper()
	out, err := dockerExec(t, spireCluster+"-control-plane", "", "getent", "ahostsv4", "host.docker.internal")
	if err != nil {
		t.Fatalf("resolve host.docker.internal in %s: %v", spireCluster, err)
	}
	seen := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 && net.ParseIP(f[0]) != nil {
			seen[f[0]] = true
		}
	}
	if len(seen) != 1 {
		t.Fatalf("host.docker.internal has %d addresses in %s (%v), want one", len(seen), spireCluster, seen)
	}
	for a := range seen {
		return a
	}
	return ""
}

// m6Recreate asks for a new step of the cell with step.TestDigest, which the host service refuses at its digest check, and returns
// the step ID. It never runs scripts/portal.sh, which signs the live digest and so starts a real recreate of the cell. The ID goes to
// build/gate/m6-steps, so gate:m6:repair can cancel it after an aborted run, and the cleanup cancels the step and waits until the
// spec has no steps.
func m6Recreate(t *testing.T, cell string) string {
	t.Helper()
	m6RequireNoSteps(t)
	out := mgmtCtl(t, "portal", "recreate", "--cell", cell, "--bootstrap-sha256", step.TestDigest)
	return m6Opened(t, cell, out)
}

// m6Retry replaces the open step of the cell with a new one, as m6Recreate does.
func m6Retry(t *testing.T, cell string) string {
	t.Helper()
	out := mgmtCtl(t, "portal", "retry", "--cell", cell, "--bootstrap-sha256", step.TestDigest)
	return m6Opened(t, cell, out)
}

func m6Opened(t *testing.T, cell, out string) string {
	t.Helper()
	var res mgmtapi.PortalResult
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.Steps) != 1 || res.Steps[0].Cell != cell || !isStepID(res.Steps[0].StepID) {
		t.Fatalf("the portal answered %q (%v), want one step of %s", out, err, cell)
	}
	id := res.Steps[0].StepID
	recordM6Step(t, id)
	t.Cleanup(func() { m6Cancel(t, cell) })
	t.Logf("opened step %s for %s at revision %v", id, cell, res.Revision)
	return id
}

func isStepID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// m6Cancel drops the open step of the cell, when it has one, and waits until the spec indexes no step. A cell with no open step is
// fine: the test may have cancelled it.
func m6Cancel(t *testing.T, cell string) {
	t.Helper()
	if out, err := mgmtCtlErr("portal", "cancel", "--cell", cell); err != nil && !strings.Contains(out, "no_step") {
		t.Errorf("cleanup: portal cancel --cell %s: %v\n%s", cell, err, out)
	}
	waitFor(t, "a spec with no step", 2*time.Minute, func() (bool, string) {
		steps, err := specSteps(t)
		return err == nil && len(steps) == 0, fmt.Sprintf("%v (%v)", steps, err)
	})
}

// m6RequireNoSteps fails the test when the live spec indexes a step: a gate starts with none, and a recreate would refuse with
// step_open.
func m6RequireNoSteps(t *testing.T) {
	t.Helper()
	steps, err := specSteps(t)
	if err != nil || len(steps) != 0 {
		t.Fatalf("the live spec indexes the steps %v (%v), and a test needs none. Run: mise run gate:m6:repair", steps, err)
	}
}

// specSteps returns the step index of the live spec that mgmtd serves, verified under its key.
func specSteps(t *testing.T) ([]spec.StepEntry, error) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(mgmtSigningPub(t))
	if err != nil {
		return nil, err
	}
	bundle, err := fetchSpec(t, envdCert(t))
	if err != nil {
		return nil, err
	}
	s, _, err := spec.Verify(bundle.Spec, []ed25519.PublicKey{raw})
	if err != nil {
		return nil, fmt.Errorf("the spec does not verify: %w", err)
	}
	return s.Steps, nil
}

// hostSpecRevision returns the spec revision that the host service holds, or nil.
func hostSpecRevision(t *testing.T) *spec.Revision {
	t.Helper()
	var st struct {
		SpecRevision *spec.Revision `json:"spec_revision"`
	}
	out, err := exec.Command("mise", "run", "hostsvc:serve", "--", "status").Output()
	if err != nil {
		t.Fatalf("mise run hostsvc:serve -- status: %v", err)
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &st); err != nil {
		t.Fatalf("hostsvc:serve -- status is no object: %v\n%s", err, out)
	}
	return st.SpecRevision
}

// waitHostSpecAtLeast waits until the host service holds a spec revision at or above rev.
func waitHostSpecAtLeast(t *testing.T, rev spec.Revision, timeout time.Duration) {
	t.Helper()
	waitFor(t, fmt.Sprintf("the host service to hold the spec revision %v or a later one", rev), timeout, func() (bool, string) {
		got := hostSpecRevision(t)
		return got != nil && got.Compare(rev) >= 0, fmt.Sprint(got)
	})
}

// stepEnvelopeOf waits until ConfigMap cell-steps holds the step envelope of the cell, for the step ID, and returns it.
func stepEnvelopeOf(t *testing.T, cell, id string, timeout time.Duration) []byte {
	t.Helper()
	var envelope []byte
	waitFor(t, "ConfigMap cell-steps to hold the envelope of step "+id, timeout, func() (bool, string) {
		data, _, _, err := cellStepsConfigMap(t)
		if err != nil {
			return false, err.Error()
		}
		raw, ok := data[cell+".step.json"]
		if !ok {
			return false, "no key " + cell + ".step.json"
		}
		if got, _, _, err := step.Peek([]byte(raw)); err != nil || got != id {
			return false, fmt.Sprintf("the key holds step %q (%v)", got, err)
		}
		envelope = []byte(raw)
		return true, ""
	})
	return envelope
}

// TestM6CellControllerNetwork: from an ephemeral netprobe container in the cell controller pod, the host service port connects (the
// control), and the next port of the same address and the API node port of mgmtd time out. In dev-cp, a pod in a fresh namespace connects
// to the host service port, because no policy stops it and mTLS guards the service (a handshake with no certificate fails), and it times
// out on the health port of the cell controller pod. The ephemeral container runs through the administrator kubeconfig,
// with the pinned netprobe image and the restricted profile, because the namespace enforces Pod Security restricted.
func TestM6CellControllerNetwork(t *testing.T) {
	needProbeImage(t)
	host := hostsvcNodeAddress(t)
	mgmtIP := clusterFacts(t, mgmtCluster).NodeIP
	pod := cellCtlPod(t)
	ip, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "get", "pod", pod, "-o", "jsonpath={.status.podIP}")
	if err != nil {
		t.Fatal(err)
	}
	// The ephemeral containers stay in the pod spec, so the cleanup starts a clean pod.
	t.Cleanup(func() {
		if _, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "delete", "pod", pod, "--wait=true", "--timeout=120s"); err != nil {
			t.Logf("cleanup: delete the probed cell controller pod %s: %v", pod, err)
		}
		if _, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "rollout", "status", "deployment/"+cellCtlDeployment, "--timeout=180s"); err != nil {
			t.Logf("cleanup: the cell controller did not roll out again: %v", err)
		}
	})
	if got := ephemeralDial(t, spireCluster, cellCtlNamespace, pod, net.JoinHostPort(host, hostsvcPort), 10*time.Second); got != "connected" {
		t.Fatalf("the control dial from the cell controller to %s:%s gave %q, want connected, so a timeout elsewhere would prove nothing", host, hostsvcPort, got)
	}
	for _, target := range []string{net.JoinHostPort(host, "17444"), net.JoinHostPort(mgmtIP, "31446")} {
		t.Run("timeout to "+target, func(t *testing.T) {
			if got := ephemeralDial(t, spireCluster, cellCtlNamespace, pod, target, 10*time.Second); got != "timeout" {
				t.Errorf("the dial from the cell controller to %s gave %q, want a timeout", target, got)
			}
		})
	}
	// No policy keeps a pod of another namespace from opening a connection to the host service: a fresh namespace has no egress
	// policy. The guard is mTLS and the route check. So the pod connects, and a handshake with no client certificate fails.
	t.Run("a pod of another namespace connects, and the host service refuses a handshake with no certificate", func(t *testing.T) {
		ns := freshNamespace(t, spireCluster)
		if got := dialFrom(t, spireCluster, ns, host, 17443, 10*time.Second); got != "connected" {
			t.Errorf("a pod in %s dials %s:17443 and gets %q, want connected: only mTLS guards the host service", ns, host, got)
		}
		if err := handshakeRefused(nil); err != nil {
			t.Errorf("a handshake with no certificate: %v", err)
		}
	})
	t.Run("a pod of another namespace to the cell controller", func(t *testing.T) {
		if err := probeFromFreshNamespace(t, spireCluster, strings.TrimSpace(ip), 8080, 10*time.Second); err != nil {
			t.Error(err)
		}
	})
}

// checkRefusedAtHost waits up to 120 s for each fact of a step that the host service refuses at its digest check, for the step ID, and
// checks them together. Every fact is read by step ID, never by cell:
//   - the log of the host service holds a line with the reason bootstrap_mismatch and the field step (the step is indexed, so it reaches
//     the digest check, and nothing earlier refuses it);
//   - ConfigMap step-status lists it refused with the reason hostsvc_denied and the request ID of that log line;
//   - mgmtd shows the host state refused for the same step ID;
//   - the journal of the host service has no entry for it.
//
// It then checks that dev-cell-2 stays valid, because a refused step changes nothing at the cell.
func checkRefusedAtHost(t *testing.T, cell, id string) {
	t.Helper()
	var line map[string]any
	waitFor(t, "the host service to refuse step "+id+" with bootstrap_mismatch", 120*time.Second, func() (bool, string) {
		for _, rec := range hostLogForStep(t, id) {
			if rec["reason"] == step.DetailBootstrapMismatch {
				line = rec
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d log lines for the step, none with bootstrap_mismatch", len(hostLogForStep(t, id)))
	})
	rid, _ := line["request_id"].(string)
	waitFor(t, "step-status to list step "+id+" refused with hostsvc_denied and the request ID "+rid, 120*time.Second, func() (bool, string) {
		s, ok := stepStatusOf(t, id)
		if !ok {
			return false, "no entry for the step"
		}
		return s.State == mgmtapi.StepRefused && s.Reason == mgmtapi.ReasonHostsvcDenied && s.RequestID == rid && rid != "", fmt.Sprintf("%+v", s)
	})
	waitFor(t, "mgmtd to show the host state refused for step "+id, 120*time.Second, func() (bool, string) {
		for _, c := range mgmtStatus(t).Cells {
			if c.Name == cell && c.Step != nil && c.Step.ID == id {
				return c.Step.Host != nil && c.Step.Host.State == mgmtapi.StepRefused, fmt.Sprintf("host %+v", c.Step.Host)
			}
		}
		return false, "no step with that ID in the status of " + cell
	})
	if _, ok := hostSteps(t)[id]; ok {
		t.Errorf("the journal of the host service holds step %s, which the digest check refused", id)
	}
	for _, c := range mgmtStatus(t).Cells {
		if c.Name == cell && (!c.Valid || c.ValidReason != "") {
			t.Errorf("cell %s is valid %v (%s), want valid: a refused step changes nothing at the cell", cell, c.Valid, c.ValidReason)
		}
	}
}

// TestM6StepReachesHostService: mgmtCtl portal recreate for dev-cell-2 with step.TestDigest reaches the host service through mgmtd, envd and the
// cell controller. The host service refuses it with bootstrap_mismatch, and every report of the refusal carries the step ID. A retry
// gives a new step ID that is refused the same way. The test never calls scripts/portal.sh, because that signs the live digest, and a
// step with it starts a real recreate of dev-cell-2.
func TestM6StepReachesHostService(t *testing.T) {
	first := m6Recreate(t, m6TestCell)
	checkRefusedAtHost(t, m6TestCell, first)
	// The host service logs a refusal with one reason at most once in each 10 s, so the retry waits for a window.
	time.Sleep(11 * time.Second)
	second := m6Retry(t, m6TestCell)
	if second == first {
		t.Fatalf("the retry kept the step ID %s, want a new one", first)
	}
	checkRefusedAtHost(t, m6TestCell, second)
}

// TestM6CancelReachesHostService: a step that mgmtd cancelled is unindexed at the host service. After the recreate, the host service holds a spec at or
// above the revision of the recreate. After the cancel, it holds a later one. A PUT of the envelope that the cell controller held then
// gets 403 at once, with the reason step_unindexed, not bootstrap_mismatch: the check of the index comes first. An ID that the host
// never saw indexed would get 503 spec_behind for 2 minutes, so the test waits for the spec first.
func TestM6CancelReachesHostService(t *testing.T) {
	cert := cellControllerCert(t)
	id := m6Recreate(t, m6TestCell)
	recreated := mgmtStatus(t).Signed
	envelope := stepEnvelopeOf(t, m6TestCell, id, 2*time.Minute)
	waitHostSpecAtLeast(t, recreated, 2*time.Minute)
	if out := mgmtCtl(t, "portal", "cancel", "--cell", m6TestCell); !strings.Contains(out, "requestId") {
		t.Fatalf("portal cancel answered %q", out)
	}
	cancelled := mgmtStatus(t).Signed
	if cancelled.Compare(recreated) <= 0 {
		t.Fatalf("the signed revision is %v after the cancel, and was %v before it, want a rise", cancelled, recreated)
	}
	waitHostSpecAtLeast(t, cancelled, 2*time.Minute)
	a := putStepOnce(t, cert, id, envelope)
	rid := a.denied()
	if a.Code != http.StatusForbidden || rid == "" {
		t.Fatalf("got %d %s (Retry-After %q), want 403 with the Denied body", a.Code, a.Body, a.RetryAfter)
	}
	line := hostLog(t, rid)
	if !strings.Contains(line, `"reason":"`+step.DetailStepUnindexed+`"`) || strings.Contains(line, step.DetailBootstrapMismatch) {
		t.Fatalf("the log of the host service for request %s is %q, want the reason step_unindexed and not bootstrap_mismatch", rid, line)
	}
}

// stopCellController scales the cell controller to zero, so that a test can change ConfigMap cell-steps before the controller reads it.
// The cleanup scales it back to one.
func stopCellController(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		setReplicas(t, spireCluster, cellCtlNamespace, "deployment/"+cellCtlDeployment, 1)
		deploymentRolledOut(t, spireCluster, cellCtlNamespace, cellCtlDeployment)
	})
	setReplicas(t, spireCluster, cellCtlNamespace, "deployment/"+cellCtlDeployment, 0)
	waitFor(t, "the cell controller pod to end", 2*time.Minute, func() (bool, string) {
		out, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+cellCtlDeployment, "-o", "name")
		return err == nil && strings.TrimSpace(out) == "", out
	})
}

func startCellController(t *testing.T) {
	t.Helper()
	setReplicas(t, spireCluster, cellCtlNamespace, "deployment/"+cellCtlDeployment, 1)
	deploymentRolledOut(t, spireCluster, cellCtlNamespace, cellCtlDeployment)
}

// patchStepKey merge-patches key <cell>.step.json of ConfigMap cell-steps, as a compromised dev-cp could, and removes the key in the
// cleanup. envd writes the ConfigMap again only when its own content changes, so the key stays for the test.
func patchStepKey(t *testing.T, cell string, envelope []byte) {
	t.Helper()
	key := cell + ".step.json"
	body, err := json.Marshal(map[string]any{"data": map[string]any{key: string(envelope)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		undo := `{"data":{"` + key + `":null}}`
		if _, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "patch", "configmap", cellStepsMap, "--type", "merge", "-p", undo); err != nil {
			t.Errorf("cleanup: remove key %s of ConfigMap %s: %v", key, cellStepsMap, err)
		}
	})
	if _, err := kubectl(t, spireCluster, "", "-n", cellCtlNamespace, "patch", "configmap", cellStepsMap, "--type", "merge", "-p", string(body)); err != nil {
		t.Fatal(err)
	}
}

// TestM6CellControllerRefusesUnsignedStep: a step envelope that dev-cp wrote into ConfigMap cell-steps is verified by the cell controller under its own
// pin, so a compromised dev-cp cannot make the host service run a step. Each subtest patches key dev-cell-2.step.json, with the cell controller
// stopped, then starts it. Within 60 s the log of the cell controller holds "step refused" with the detail, step-status lists the step
// refused with step_invalid and that detail, and the log of the host service holds no line for the step ID for the next 30 s.
//   - unsigned and rogue_key replace the envelope of an open step that the spec indexes, with the same payload and no signature, or a
//     signature of another key. The detail is signature_invalid.
//   - unindexed is a step that mgmtd signed, and that no spec indexes: the detail is step_unindexed, and the host service never gets the
//     PUT. Without the index check, the host service would answer spec_behind for it, and log it with its step ID.
//
// A key of a cell that the spec does not index is refused as step_unindexed without a look at its signature, so the first two
// subtests open a step.
func TestM6CellControllerRefusesUnsignedStep(t *testing.T) {
	for _, tc := range []struct {
		name, detail string
		indexed      bool
		tamper       func(t *testing.T, envelope []byte) []byte
	}{
		{"unsigned", step.DetailSignatureInvalid, true, func(t *testing.T, env []byte) []byte { return stripSignatures(t, env) }},
		{"rogue_key", step.DetailSignatureInvalid, true, func(t *testing.T, env []byte) []byte { return resignWithRogueKey(t, env) }},
		{"unindexed", step.DetailStepUnindexed, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stopCellController(t)
			var id string
			var tampered []byte
			if tc.indexed {
				id = m6Recreate(t, m6TestCell)
				tampered = tc.tamper(t, stepEnvelopeOf(t, m6TestCell, id, 2*time.Minute))
			} else {
				m6RequireNoSteps(t)
				s := testStep(t, m6TestCell)
				recordM6Step(t, s.ID)
				id, tampered = s.ID, stepSign(t, s)
			}
			patchStepKey(t, m6TestCell, tampered)
			since := time.Now().Add(-5 * time.Second)
			startCellController(t)
			waitFor(t, "the cell controller to refuse step "+id+" with "+tc.detail, 60*time.Second, func() (bool, string) {
				var logged bool
				for _, rec := range cellCtlLog(t, since) {
					if rec["msg"] == "step refused" && rec["step"] == id && rec["detail"] == tc.detail {
						logged = true
					}
				}
				s, ok := stepStatusOf(t, id)
				listed := ok && s.State == mgmtapi.StepRefused && s.Reason == step.Code && s.Detail == tc.detail
				return logged && listed, fmt.Sprintf("logged %v, status %+v (listed %v)", logged, s, ok)
			})
			time.Sleep(stepLogWindow)
			if lines := hostLogForStep(t, id); len(lines) != 0 {
				t.Fatalf("the log of the host service holds %d lines for step %s, which the cell controller refused: %v", len(lines), id, lines)
			}
		})
	}
}

// resignWithRogueKey returns the step of the envelope, signed with a key that mgmtd does not hold.
func resignWithRogueKey(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var s step.Step
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out, err := step.Sign(s, key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestM6CellControllerIdentity: the SPIRE server issues the SVID spiffe://dev.env.poc.internal/cp/cell-controller to the cell controller, and the
// log of the server shows it. The entry selects unix:uid:<ko uid>, under the node alias of its own namespace and ServiceAccount.
func TestM6CellControllerIdentity(t *testing.T) {
	const id = cellControllerID
	out, err := spireServerIn(t, spireCluster, "entry", "show", "-socketPath", spireSocket, "-spiffeID", id, "-output", "json")
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Entries []struct {
			ParentID  struct{ TrustDomain, Path string } `json:"parent_id"`
			Selectors []struct{ Type, Value string }     `json:"selectors"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode the entry: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("want one entry for %s, got %d: %s", id, len(res.Entries), out)
	}
	e := res.Entries[0]
	var selectors []string
	for _, s := range e.Selectors {
		selectors = append(selectors, s.Type+":"+s.Value)
	}
	if !slices.Equal(selectors, []string{"unix:uid:" + cellCtlUID}) {
		t.Errorf("selectors are %v, want [unix:uid:%s]", selectors, cellCtlUID)
	}
	if e.ParentID.Path != "/agents/"+cellCtlNamespace+"/"+cellCtlDeployment {
		t.Errorf("the parent is %s, want the node alias /agents/%s/%s", e.ParentID.Path, cellCtlNamespace, cellCtlDeployment)
	}
	// The SVID of the cell controller lasts SPIRE_SVID_TTL, so the server signs it again about each half minute. The line is the
	// one that says the server signed an X509 SVID, together with the ID.
	waitFor(t, "the log of the SPIRE server to show a signed X509 SVID for "+id, 3*time.Minute, func() (bool, string) {
		logs, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "logs", spireServerPod, "-c", "spire-server", "--since=5m")
		for line := range strings.SplitSeq(logs, "\n") {
			if strings.Contains(line, "Signed X509 SVID") && strings.Contains(line, id) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("no line with Signed X509 SVID and the ID (%v)", err)
	})
	var ports []string
	for _, a := range listenAddrs(t, spireCluster, cellCtlNamespace, cellCtlPod(t), cellCtlDeployment) {
		if _, port, err := net.SplitHostPort(a); err == nil {
			ports = append(ports, port)
		}
	}
	if want := []string{"8080"}; !slices.Equal(ports, want) {
		t.Errorf("the cell controller listens on %v, want %v", ports, want)
	}
}

// TestM6EnvdWritesCellSteps: envd writes ConfigMap cell-steps with the marker poc.internal/made-by=envd. Its spec counter equals the counter
// that mgmtd signed last, and with no open step it holds no step file.
func TestM6EnvdWritesCellSteps(t *testing.T) {
	m6RequireNoSteps(t)
	waitFor(t, "ConfigMap cell-steps to carry the signed spec counter", 2*time.Minute, func() (bool, string) {
		data, annotations, labels, err := cellStepsConfigMap(t)
		if err != nil {
			return false, err.Error()
		}
		signed := mgmtStatus(t).Signed
		var files []string
		for k := range data {
			if strings.HasSuffix(k, ".step.json") {
				files = append(files, k)
			}
		}
		ok := labels["poc.internal/made-by"] == "envd" &&
			annotations["poc.internal/spec-counter"] == fmt.Sprint(signed.Counter) && annotations["poc.internal/spec-epoch"] == fmt.Sprint(signed.Epoch) &&
			len(files) == 0 && data["spec-envelope.json"] != ""
		return ok, fmt.Sprintf("labels %v, annotations %v, signed %v, step files %v", labels, annotations, signed, files)
	})
}
