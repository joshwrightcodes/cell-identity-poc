//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cmdrun"
)

// rotateWait bounds the whole command: the render of dev-cp, the link of management and two verify runs.
const rotateWait = 45 * time.Minute

var recordKeysLine = regexp.MustCompile(`(?m)^\s*record_public_keys = \[(.*)\]$`)

// serverStart returns the start time of the spire-server container in dev-cp.
func serverStart(t *testing.T) time.Time {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "pod", spireServerPod, "-o",
		`jsonpath={.status.containerStatuses[?(@.name=="spire-server")].state.running.startedAt}`)
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("the start time of spire-server is %q: %v", out, err)
	}
	return at
}

// cellVerify runs `mise run cell:verify` for a cluster.
func cellVerify(t *testing.T, cell string) {
	t.Helper()
	res, err := cmdrun.Run(10*time.Minute, "../..", []string{"CELL=" + cell}, "mise", "run", "cell:verify")
	if err != nil || res.Code != 0 {
		t.Errorf("CELL=%s mise run cell:verify: %v (exit %d)\n%s%s", cell, err, res.Code, res.Stdout, res.Stderr)
	}
}

// TestRotationSigningKey runs `mise run mgmt -- rotate-signing-key`. It prints one JSON line with the new epoch. Then
// mgmt-signing-pub, record_public_keys of the SPIRE server and mgmt-spec-key of envd hold the new key, cell-records verifies under it at
// the new epoch, a new celld pod in each cell attests, and cell:verify passes for management and dev-cp. The test logs the
// attestation gap: the time from the start of the SPIRE server container to the first log line with the records of the new
// epoch. In that time the plugin holds no records, so a new pod cannot attest. The name is outside the pattern of gate:m4.
func TestRotationSigningKey(t *testing.T) {
	before := mgmtStatus(t)
	oldPub := mgmtSigningPub(t)
	started := time.Now()

	var stdout, stderr bytes.Buffer
	res0, err := cmdrun.Run(rotateWait, "", nil, "mise", "run", "mgmt", "--", "rotate-signing-key")
	stdout.WriteString(res0.Stdout)
	stderr.WriteString(res0.Stderr)
	if err == nil && res0.Code != 0 {
		err = fmt.Errorf("exit status %d", res0.Code)
	}
	took := time.Since(started)
	t.Logf("rotate-signing-key took %s", took.Round(time.Second))
	if err != nil {
		t.Fatalf("mise run mgmt -- rotate-signing-key: %v\nstdout: %s\nstderr (the remaining commands, when the key rotated):\n%s", err, stdout.String(), stderr.String())
	}
	var res struct {
		Rotated bool   `json:"rotated"`
		Old     string `json:"old_key_sha256"`
		New     string `json:"new_key_sha256"`
		Epoch   uint64 `json:"epoch"`
	}
	if strings.Count(stdout.String(), "\n") != 1 || json.Unmarshal(stdout.Bytes(), &res) != nil {
		t.Fatalf("standard output is %q, want one JSON line. stderr:\n%s", stdout.String(), stderr.String())
	}
	if !res.Rotated || res.Epoch != before.Signed.Epoch+1 || res.Old == res.New {
		t.Fatalf("the result %+v, want rotated at the epoch %d with a new key", res, before.Signed.Epoch+1)
	}
	t.Logf("old key %s, new key %s, epoch %d", res.Old, res.New, res.Epoch)

	newPub := mgmtSigningPub(t)
	if newPub == oldPub || newPub != ctlPub(t) {
		t.Errorf("mgmt-signing-pub holds %q, mgmtd holds %q, and the old key was %q", newPub, ctlPub(t), oldPub)
	}
	conf, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "configmap", "spire-server", "-o", `jsonpath={.data.server\.conf}`)
	if err != nil {
		t.Fatal(err)
	}
	if m := recordKeysLine.FindStringSubmatch(conf); m == nil || strings.Trim(m[1], `" `) != newPub {
		t.Errorf("record_public_keys of the SPIRE server is %v, want [%q]", m, newPub)
	}
	specKey, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "get", "configmap", "mgmt-spec-key", "-o", `jsonpath={.data.spec\.pub}`)
	if err != nil || strings.TrimSpace(specKey) != newPub {
		t.Errorf("mgmt-spec-key holds %q (%v), want the new key", specKey, err)
	}
	waitFor(t, "cell-records signed under the new key at the epoch "+fmt.Sprint(res.Epoch), 3*time.Minute, func() (bool, string) {
		sp, _, err := readLiveRecords(t)
		if err != nil {
			return false, err.Error()
		}
		return sp.Revision.Epoch == res.Epoch, fmt.Sprintf("cell-records at %+v", sp.Revision)
	})

	for _, cell := range clustersWith(t, agentCellSet) {
		pod := replaceCelldPod(t, cell)
		waitCelldSVID(t, cell, pod)
	}
	cellVerify(t, mgmtCluster)
	cellVerify(t, spireCluster)

	// The attestation gap.
	start := serverStart(t)
	logs, err := serverLog(t, start.Add(-logMargin))
	if err != nil {
		t.Fatal(err)
	}
	var first time.Time
	for _, l := range matching(logs, func(l logLine) bool {
		epoch, _ := l["spec_epoch"].(float64)
		records, _ := l["records"].(float64)
		return uint64(epoch) == res.Epoch && (l.str("msg") == "records reloaded" || (l.str("msg") == "configured" && records > 0))
	}) {
		if at, err := time.Parse(time.RFC3339Nano, l.str("time")); err == nil && (first.IsZero() || at.Before(first)) {
			first = at
		}
	}
	if first.IsZero() {
		t.Errorf("the SPIRE server log holds no line with the records of the epoch %d since %s", res.Epoch, start.Format(time.RFC3339))
		return
	}
	t.Logf("ATTESTATION_GAP_SECONDS=%.0f: the SPIRE server container started at %s and held the records of the epoch %d at %s",
		first.Sub(start).Seconds(), start.Format(time.RFC3339), res.Epoch, first.Format(time.RFC3339))
}
