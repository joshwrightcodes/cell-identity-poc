//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	gatewayID    = "spiffe://dev.env.poc.internal/cp/gateway"
	gatewayUID   = "65532"
	gatewayProbe = 10 * time.Second
)

// gatewayPodIP returns the pod address of cell-gateway-0.
func gatewayPodIP(t *testing.T) string {
	t.Helper()
	ip, err := kubectl(t, spireCluster, "", "-n", gatewayNamespace, "get", "pod", gatewayPod, "-o", "jsonpath={.status.podIP}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(ip)
}

// TestM5GatewayIdentity: the entry of the gateway is spiffe://dev.env.poc.internal/cp/gateway with the selector unix:uid:<ko uid>, under the
// node alias of its own namespace and ServiceAccount. The cellgw container listens on 8450, 8451, 8452 and 8080 only, and the gateway
// answers its admin socket.
func TestM5GatewayIdentity(t *testing.T) {
	out, err := spireServerIn(t, spireCluster, "entry", "show", "-socketPath", spireSocket, "-spiffeID", gatewayID, "-output", "json")
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
		t.Fatalf("want one entry for %s, got %d: %s", gatewayID, len(res.Entries), out)
	}
	e := res.Entries[0]
	var selectors []string
	for _, s := range e.Selectors {
		selectors = append(selectors, s.Type+":"+s.Value)
	}
	if !slices.Equal(selectors, []string{"unix:uid:" + gatewayUID}) {
		t.Errorf("selectors are %v, want [unix:uid:%s]", selectors, gatewayUID)
	}
	if e.ParentID.Path != "/agents/"+gatewayNamespace+"/cell-gateway" {
		t.Errorf("the parent is %s, want the node alias /agents/%s/cell-gateway", e.ParentID.Path, gatewayNamespace)
	}
	var ports []string
	for _, a := range listenAddrs(t, spireCluster, gatewayNamespace, gatewayPod, "cellgw") {
		if _, port, err := net.SplitHostPort(a); err == nil {
			ports = append(ports, port)
		}
	}
	slices.Sort(ports)
	if want := []string{"8080", "8450", "8451", "8452"}; !slices.Equal(ports, want) {
		t.Errorf("cellgw listens on %v, want %v", ports, want)
	}
	if s := gwStatus(t); s.Epoch == 0 || s.StoreError != "" {
		t.Errorf("the gateway reports epoch %d and store error %q, want an epoch and no error", s.Epoch, s.StoreError)
	}
}

// TestM5GatewayListenersAdmission: a pod in each cell reaches the stream and the bind node port of dev-cp (30450, 30451). A pod in rogue and
// a pod in management time out. In dev-cp, a pod in a fresh namespace times out on the gateway pod address (8450, 8451, 8452 and 8080), on
// the node port addresses, and on the ClusterIP of Service cell-gateway (8452). Each address and port has its own subtest, so a rule that
// widens names the subtest that fails.
func TestM5GatewayListenersAdmission(t *testing.T) {
	needProbeImage(t)
	cpIP := clusterFacts(t, spireCluster).NodeIP
	for _, cell := range clustersWith(t, agentCellSet) {
		for _, port := range []int{30450, 30451} {
			t.Run(fmt.Sprintf("%s reaches %d", cell, port), func(t *testing.T) {
				ns := m5Namespace(t, cell)
				if got := dialFrom(t, cell, ns, cpIP, port, gatewayProbe); got != "connected" {
					t.Errorf("a pod in %s dials %s:%d and gets %q, want connected, because the cell node is admitted", cell, cpIP, port, got)
				}
			})
		}
	}
	for _, other := range []string{"rogue", mgmtCluster} {
		for _, port := range []int{30450, 30451} {
			t.Run(fmt.Sprintf("%s to %d", other, port), func(t *testing.T) {
				if err := probeFromM5Namespace(t, other, cpIP, port, gatewayProbe); err != nil {
					t.Errorf("%s reaches the gateway node port: %v", other, err)
				}
			})
		}
	}
	podIP := gatewayPodIP(t)
	svcIP, err := kubectl(t, spireCluster, "", "-n", gatewayNamespace, "get", "service", "cell-gateway", "-o", "jsonpath={.spec.clusterIP}")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		name, addr string
		port       int
	}{
		{"pod", podIP, 8450}, {"pod", podIP, 8451}, {"pod", podIP, 8452}, {"pod", podIP, 8080},
		{"node", cpIP, 30450}, {"node", cpIP, 30451},
		{"service cell-gateway", strings.TrimSpace(svcIP), 8452},
	} {
		t.Run(fmt.Sprintf("dev-cp fresh namespace to %s %d", target.name, target.port), func(t *testing.T) {
			if err := probeFromM5Namespace(t, spireCluster, target.addr, target.port, gatewayProbe); err != nil {
				t.Errorf("a pod of a fresh namespace in dev-cp reaches the gateway: %v", err)
			}
		})
	}
}

// TestM5EnvdSyncsGateway: within two minutes envd syncs with the gateway, and the record revision that the gateway holds for each cell
// equals the revision of the record in cell-records, which verifies under the key of mgmtd.
func TestM5EnvdSyncsGateway(t *testing.T) {
	waitFor(t, "the gateway to hold the record revision of each cell", m5Wait, func() (bool, string) {
		_, cells, err := readLiveRecords(t)
		if err != nil {
			return false, err.Error()
		}
		s := gwStatus(t)
		if time.Since(s.SyncedAt) > time.Minute {
			return false, fmt.Sprintf("envd synced at %s", s.SyncedAt)
		}
		for name, c := range cells {
			want := spec.Revision{Epoch: c.Epoch, Counter: c.Counter}
			if got, ok := s.Records[name]; !ok || got != want {
				return false, fmt.Sprintf("the gateway holds %+v for %s, cell-records holds %+v", s.Records[name], name, want)
			}
		}
		return true, ""
	})
}

// TestM5GatewayStatePersists: with envd at zero replicas, one status item sits in the outbox. After a restart of cell-gateway-0, the epoch is
// unchanged and the item is still there. envd returns to one replica at the end.
func TestM5GatewayStatePersists(t *testing.T) {
	setReplicas(t, spireCluster, envdNamespace, "deployment/"+envdDeployment, 0)
	var injected string
	t.Cleanup(func() {
		setReplicas(t, spireCluster, envdNamespace, "deployment/"+envdDeployment, 1)
		deploymentRolledOut(t, spireCluster, envdNamespace, envdDeployment)
		if injected == "" {
			return
		}
		// envd takes the item at its next round, and mgmtd refuses it, because its token is empty. The outbox is then empty again.
		waitFor(t, "envd to take the injected item out of the outbox", m5Wait, func() (bool, string) {
			out, err := gwCtlErr("", "outbox")
			return err == nil && !strings.Contains(out, injected), out
		})
	})
	waitFor(t, "envd to stop", m5Wait, func() (bool, string) {
		out, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+envdDeployment, "-o", "name")
		return err == nil && strings.TrimSpace(out) == "", out
	})
	before := gwStatus(t)
	var added struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(gwCtl(t, statusItem(rejectCell), "inject")), &added); err != nil || added.ID == "" {
		t.Fatalf("cellgw ctl inject gave no item ID: %v", err)
	}
	injected = added.ID
	if !slices.Contains(outboxIDs(t), added.ID) {
		t.Fatalf("the outbox lacks the injected item %s", added.ID)
	}
	if _, err := kubectl(t, spireCluster, "", "-n", gatewayNamespace, "delete", "pod", gatewayPod, "--wait=true", "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
	statefulSetReady(t, spireCluster, gatewayNamespace, "cell-gateway")
	waitFor(t, "the gateway to answer after its restart", m5Wait, func() (bool, string) {
		out, err := gwCtlErr("", "status")
		return err == nil && out != "", out
	})
	after := gwStatus(t)
	if after.Epoch != before.Epoch {
		t.Errorf("the epoch is %d after the restart, and was %d before", after.Epoch, before.Epoch)
	}
	if !slices.Contains(outboxIDs(t), added.ID) {
		t.Errorf("the outbox lost the item %s in the restart", added.ID)
	}
}

// TestM5MgmtBindPathGone: Service mgmt-bind, Deployment relay-bind and its Service and policy do not exist, and the policy mgmtd admits no
// 8447. A dial from a dev-cp pod to the old bind node port of management (31447) fails, while the control dial to 31446 connects. A dial
// from a cell pod to the old relay bind node port of dev-cp (30447) fails.
func TestM5MgmtBindPathGone(t *testing.T) {
	needProbeImage(t)
	gone := func(cluster, ns, kind, name string) {
		t.Helper()
		out, err := kubectl(t, cluster, "", "-n", ns, "get", kind, name, "--ignore-not-found", "-o", "name")
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(out) != "" {
			t.Errorf("%s %s/%s still exists in %s", kind, ns, name, cluster)
		}
	}
	gone(mgmtCluster, mgmtNamespace, "service", "mgmt-bind")
	gone(spireCluster, "relay-system", "deployment", "relay-bind")
	gone(spireCluster, "relay-system", "service", "relay-bind")
	gone(spireCluster, "relay-system", "networkpolicy", "relay-bind")
	policy, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "get", "networkpolicy", "mgmtd", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(policy, `"port":8447`) || strings.Contains(policy, `"port": 8447`) {
		t.Errorf("the policy mgmtd still admits 8447: %s", policy)
	}
	mgmtIP := clusterFacts(t, mgmtCluster).NodeIP
	ns := m5Namespace(t, spireCluster)
	if got := dialFrom(t, spireCluster, ns, mgmtIP, 31446, gatewayProbe); got != "connected" {
		t.Fatalf("the control dial from dev-cp to %s:31446 gave %q, want connected, so a failure on 31447 would prove nothing", mgmtIP, got)
	}
	if got := dialFrom(t, spireCluster, ns, mgmtIP, 31447, gatewayProbe); got != "refused" && got != "timeout" {
		t.Errorf("the dial from dev-cp to %s:31447 gave %q, want refused or timeout", mgmtIP, got)
	}
	cpIP := clusterFacts(t, spireCluster).NodeIP
	cell := clustersWith(t, agentCellSet)[0]
	cellNS := m5Namespace(t, cell)
	if got := dialFrom(t, cell, cellNS, cpIP, 30450, gatewayProbe); got != "connected" {
		t.Fatalf("the control dial from %s to %s:30450 gave %q, want connected, so a failure on 30447 would prove nothing", cell, cpIP, got)
	}
	if got := dialFrom(t, cell, cellNS, cpIP, 30447, gatewayProbe); got != "refused" && got != "timeout" {
		t.Errorf("the dial from %s to %s:30447 gave %q, want refused or timeout", cell, cpIP, got)
	}
}

// TestM5EnvdIslandStillSyncs: with mgmtd at zero replicas, and its pod gone, envd still syncs with the gateway within two minutes, because a failed pull never
// stops a later leg. mgmtd returns at the end, and envd reports to it again.
func TestM5EnvdIslandStillSyncs(t *testing.T) {
	const mgmtd = "statefulset/mgmtd"
	restored := false
	restore := func() {
		if !restored {
			restored = true
			setReplicas(t, mgmtCluster, mgmtNamespace, mgmtd, 1)
		}
	}
	setReplicas(t, mgmtCluster, mgmtNamespace, mgmtd, 0)
	t.Cleanup(func() {
		restore()
		statefulSetReady(t, mgmtCluster, mgmtNamespace, "mgmtd")
	})
	waitFor(t, "the pod "+mgmtdPod+" to be gone", m5Wait, func() (bool, string) {
		out, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "get", "pod", mgmtdPod, "--ignore-not-found", "-o", "name")
		return err == nil && strings.TrimSpace(out) == "", out
	})
	gone := time.Now()
	waitFor(t, "envd to sync with the gateway while mgmtd is away", m5Wait, func() (bool, string) {
		s := gwStatus(t)
		return s.SyncedAt.After(gone), fmt.Sprintf("envd synced at %s, mgmtd went away at %s", s.SyncedAt, gone)
	})
	restore()
	statefulSetReady(t, mgmtCluster, mgmtNamespace, "mgmtd")
	returned := time.Now()
	waitFor(t, "envd to report to mgmtd again", m5Wait, func() (bool, string) {
		s := mgmtStatus(t)
		return s.LastReportAt.After(returned), fmt.Sprintf("last report at %s, mgmtd returned at %s", s.LastReportAt, returned)
	})
}
