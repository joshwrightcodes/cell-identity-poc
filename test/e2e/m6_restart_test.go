//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cmdrun"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

// restartWait bounds `mise run hostsvc:serve -- restart`: the stop, the start, the link of mgmt-api and the render of the cell controller.
const restartWait = 30 * time.Minute

// hostsvcState is the part of `mise run hostsvc:serve -- status` that the tests of the restart and the rotation read.
type hostsvcState struct {
	PID        *int     `json:"pid"`
	CertSHA256 string   `json:"cert_sha256"`
	Keys       []string `json:"keys"`
}

func hostsvcStatus(t *testing.T) hostsvcState {
	t.Helper()
	out, err := exec.Command("mise", "run", "hostsvc:serve", "--", "status").Output()
	if err != nil {
		t.Fatalf("mise run hostsvc:serve -- status: %v", err)
	}
	var st hostsvcState
	if err := json.Unmarshal(bytes.TrimSpace(out), &st); err != nil {
		t.Fatalf("hostsvc:serve -- status is no object: %v\n%s", err, out)
	}
	return st
}

// pinCertSHA256 returns the SHA-256 of the DER certificate in key hostsvc.crt of ConfigMap hostsvc-pin in the namespace of the cluster.
func pinCertSHA256(t *testing.T, cluster, namespace string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", namespace, "get", "configmap", "hostsvc-pin", "-o", `jsonpath={.data.hostsvc\.crt}`)
	if err != nil {
		t.Fatalf("read hostsvc-pin in %s/%s: %v", cluster, namespace, err)
	}
	block, _ := pem.Decode([]byte(out))
	if block == nil {
		t.Fatalf("hostsvc-pin in %s/%s holds no PEM certificate: %q", cluster, namespace, out)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// waitStepRefusedAtHost waits until the log of the host service holds a bootstrap_mismatch line for the step ID with a time at or after
// since, and returns every reason that the log holds for the step in that window. A zero since counts the whole log. A test that wants
// proof that a new envelope reached the host passes the time before the change: an older refusal of the same step ID then does not count.
func waitStepRefusedAtHost(t *testing.T, id string, since time.Time) []string {
	t.Helper()
	var reasons []string
	waitFor(t, "the host service to refuse step "+id+" with bootstrap_mismatch", 120*time.Second, func() (bool, string) {
		reasons = reasonsSince(hostLogForStep(t, id), since)
		return slices.Contains(reasons, step.DetailBootstrapMismatch), fmt.Sprintf("reasons %v since %s", reasons, since.Format(time.RFC3339))
	})
	return reasons
}

// TestM6HostServiceRestartRepins: a restart of the host service makes a new certificate, and the restart links mgmt-api and renders the
// cell controller again, so both ConfigMaps hostsvc-pin hold the new pin. The test opens a step of dev-cell-2 with step.TestDigest and
// waits until the host service refuses it with bootstrap_mismatch. The step stays open across the restart. After the restart, the pins of
// mgmt-system and cell-controller-system equal cert_sha256 of the status, and CELL=dev-cp cell:verify passes. The cell controller then
// sends the open step to the new service, which logs a new bootstrap_mismatch for the same ID, and no step_unindexed: the new service
// holds the spec that indexes the step. Last, the test cancels the step and opens another one, which reaches the new service within
// 120 s with bootstrap_mismatch. The cleanup cancels the step.
func TestM6HostServiceRestartRepins(t *testing.T) {
	old := m6Recreate(t, m6TestCell)
	waitStepRefusedAtHost(t, old, time.Time{})

	before := hostsvcStatus(t)
	if before.PID == nil || before.CertSHA256 == "" {
		t.Fatalf("the host service does not serve: %+v", before)
	}
	for _, p := range []struct{ cluster, ns string }{{mgmtCluster, mgmtNamespace}, {spireCluster, cellCtlNamespace}} {
		if got := pinCertSHA256(t, p.cluster, p.ns); got != before.CertSHA256 {
			t.Fatalf("hostsvc-pin in %s holds %s before the restart, and the service has %s. Run: mise run hostsvc:serve -- restart", p.ns, got, before.CertSHA256)
		}
	}

	started := time.Now()
	restartAt := started
	res, err := cmdrun.Run(restartWait, "../..", nil, "mise", "run", "hostsvc:serve", "--", "restart")
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit status %d", res.Code)
	}
	t.Logf("hostsvc:serve -- restart took %s", time.Since(started).Round(time.Second))
	if err != nil {
		t.Fatalf("mise run hostsvc:serve -- restart: %v\nstdout: %s\nstderr: %s", err, res.Stdout, res.Stderr)
	}

	after := hostsvcStatus(t)
	if after.PID == nil || *after.PID == *before.PID || after.CertSHA256 == "" || after.CertSHA256 == before.CertSHA256 {
		t.Fatalf("the status is %+v after the restart, and was %+v before it; want a new process with a new certificate", after, before)
	}
	for _, p := range []struct{ cluster, ns string }{{mgmtCluster, mgmtNamespace}, {spireCluster, cellCtlNamespace}} {
		waitFor(t, "hostsvc-pin in "+p.ns+" to hold the new pin "+after.CertSHA256, 2*time.Minute, func() (bool, string) {
			got := pinCertSHA256(t, p.cluster, p.ns)
			return got == after.CertSHA256, "it holds " + got
		})
	}
	cellVerify(t, spireCluster)

	reasons := waitStepRefusedAtHost(t, old, restartAt)
	if slices.Contains(reasons, step.DetailStepUnindexed) {
		t.Errorf("the new host service logged step_unindexed for the open step %s: %v", old, reasons)
	}
	m6Cancel(t, m6TestCell)
	fresh := m6Recreate(t, m6TestCell)
	if fresh == old {
		t.Fatalf("the new step has the ID %s of the old one", old)
	}
	waitStepRefusedAtHost(t, fresh, time.Time{})
}
