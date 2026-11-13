//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

const (
	gatewayNamespace = "gateway-system"
	gatewayPod       = "cell-gateway-0"
	gatewayCellOps   = "cell-ops-system"
	// m5Wait bounds a wait for the gateway or envd to settle.
	m5Wait = 2 * time.Minute
)

// gatewayStatus is the status that cellgw ctl status prints.
type gatewayStatus = mgmtapi.GatewayStatus

// opState is the state of one operation that mgmtd ctl op get prints.
type opState = mgmt.OpView

// gwCtl runs `mise run gw -- <args>`, which runs cellgw ctl in cell-gateway-0, with stdin on its standard input, and returns the one JSON
// line that it prints.
func gwCtl(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, err := gwCtlErr(stdin, args...)
	if err != nil {
		t.Fatalf("mise run gw -- %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func gwCtlErr(stdin string, args ...string) (string, error) {
	cmd := exec.Command("mise", append([]string{"run", "gw", "--"}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return strings.TrimSpace(stdout.String()), err
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		return strings.TrimSpace(stdout.String()), fmt.Errorf("mise run gw -- %s: timed out", strings.Join(args, " "))
	}
}

// gwStatus returns the status that cellgw ctl status prints.
func gwStatus(t *testing.T) gatewayStatus {
	t.Helper()
	var s gatewayStatus
	if err := json.Unmarshal([]byte(gwCtl(t, "", "status")), &s); err != nil {
		t.Fatalf("cellgw ctl status is no status object: %v", err)
	}
	return s
}

// opCreate signs an operation of kind demo.append for cell through mgmtd, which serves it to envd, and returns its ID.
func opCreate(t *testing.T, cell, line string, ttl time.Duration) string {
	t.Helper()
	args := []string{"op", "create", "--cell", cell, "--line", line}
	if ttl > 0 {
		args = append(args, "--ttl", ttl.String())
	}
	var v opState
	if err := json.Unmarshal([]byte(mgmtCtl(t, args...)), &v); err != nil || v.ID == "" {
		t.Fatalf("mgmtd ctl op create is no operation: %v", err)
	}
	return v.ID
}

// opSign signs an operation and records it without serving it, and returns its ID and its DSSE envelope.
func opSign(t *testing.T, cell, line string, ttl time.Duration) (id string, envelope []byte) {
	t.Helper()
	args := []string{"op", "sign", "--cell", cell, "--line", line}
	if ttl > 0 {
		args = append(args, "--ttl", ttl.String())
	}
	var v opState
	if err := json.Unmarshal([]byte(mgmtCtl(t, args...)), &v); err != nil || v.ID == "" || len(v.Envelope) == 0 {
		t.Fatalf("mgmtd ctl op sign gave no operation with an envelope: %v", err)
	}
	return v.ID, []byte(v.Envelope)
}

// opGet returns the state of operation id at mgmtd.
func opGet(t *testing.T, id string) opState {
	t.Helper()
	var v opState
	if err := json.Unmarshal([]byte(mgmtCtl(t, "op", "get", id)), &v); err != nil {
		t.Fatalf("mgmtd ctl op get %s is no operation: %v", id, err)
	}
	return v
}

// demoLog returns the lines of ConfigMap cell-ops-system/demo-log in cell, or none when the ConfigMap does not exist.
func demoLog(t *testing.T, cell string) []string {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", gatewayCellOps, "get", "configmap", "demo-log", "--ignore-not-found", "-o", "jsonpath={.data.log}")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for l := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// outboxIDs returns the IDs of the items in the outbox of the gateway.
func outboxIDs(t *testing.T) []string {
	t.Helper()
	var res struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(gwCtl(t, "", "outbox")), &res); err != nil {
		t.Fatalf("cellgw ctl outbox is no list: %v", err)
	}
	ids := make([]string, 0, len(res.Items))
	for _, it := range res.Items {
		ids = append(ids, it.ID)
	}
	return ids
}

// deploymentRolledOut waits until Deployment name in ns of cluster has finished its rollout.
func deploymentRolledOut(t *testing.T, cluster, ns, name string) {
	t.Helper()
	if _, err := kubectl(t, cluster, "", "-n", ns, "rollout", "status", "deployment/"+name, "--timeout=300s"); err != nil {
		t.Fatalf("deployment/%s in %s did not finish its rollout: %v", name, cluster, err)
	}
}

// statusItem returns one status item of cell for gwCtl inject. The token is empty, so mgmtd refuses the item when it arrives.
func statusItem(cell string) string {
	body, _ := json.Marshal(map[string]any{"at": time.Now().UTC().Format(time.RFC3339)})
	item, _ := json.Marshal(map[string]any{"kind": "status", "cell": cell, "body": json.RawMessage(body), "token": ""})
	return string(item)
}
