//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	meshNamespace = "mesh-view-system"
	hubName       = "mesh-view-hub"
	kialiName     = "kiali"
	tunnelName    = "mesh-view"
	hubID         = "spiffe://mgmt.poc.internal/kiali"
	meshNodePort  = 31445
	// meshCells are the cells with the mesh-view set, and meshPorts the hub port of each.
	promProxyName = "prom-readonly"
)

// meshCells returns the clusters with the mesh-view set.
func meshCells(t *testing.T) []string {
	t.Helper()
	return clustersWith(t, "mesh-view")
}

// hubPort returns the hub port of a cell from MESH_VIEW_CELLS of management.
func hubPort(t *testing.T, cell string) int {
	t.Helper()
	data, err := os.ReadFile("../../cells/management.env")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "MESH_VIEW_CELLS="); ok {
			for _, e := range strings.Fields(strings.Trim(v, `"`)) {
				if c, p, ok := strings.Cut(e, "="); ok && c == cell {
					n, err := strconv.Atoi(p)
					if err != nil {
						t.Fatalf("MESH_VIEW_CELLS port %q of %s: %v", p, cell, err)
					}
					return n
				}
			}
		}
	}
	t.Fatalf("MESH_VIEW_CELLS of management names no port for %s", cell)
	return 0
}

// ephemeralNetprobe adds an ephemeral netprobe container with the restricted profile to a pod, runs
// netprobe with args to the end, and returns its output and how long it ran. The pod keeps the
// container, so the first call of a test registers a cleanup that replaces the pod.
func ephemeralNetprobe(t *testing.T, cluster, ns, pod string, args ...string) (string, time.Duration) {
	t.Helper()
	out, took, exit := ephemeralNetprobeExit(t, cluster, ns, pod, args...)
	if exit != 0 {
		t.Fatalf("netprobe %v exited with %d: %s", args, exit, out)
	}
	return out, took
}

// ephemeralNetprobeExit is ephemeralNetprobe for a caller that accepts a failed run. It returns the
// exit code of netprobe too.
func ephemeralNetprobeExit(t *testing.T, cluster, ns, pod string, args ...string) (string, time.Duration, int) {
	t.Helper()
	name := "m3-probe-" + randomHex(t, 4)
	t.Logf("running netprobe %v in the ephemeral container %s in %s/%s of %s", args, name, ns, pod, cluster)
	full := append([]string{"-n", ns, "debug", pod, "--image", probeImage, "--profile=restricted", "--container", name, "--arguments-only", "--"}, args...)
	if _, err := kubectl(t, cluster, "", full...); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(`{.status.ephemeralContainerStatuses[?(@.name=="%s")].state.terminated}`, name)
	var term struct {
		ExitCode   int       `json:"exitCode"`
		StartedAt  time.Time `json:"startedAt"`
		FinishedAt time.Time `json:"finishedAt"`
	}
	waitFor(t, "ephemeral container "+name+" to finish", 2*time.Minute, func() (bool, string) {
		out, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", pod, "-o", "jsonpath="+path)
		if err != nil {
			return false, err.Error()
		}
		if strings.TrimSpace(out) == "" {
			return false, "not terminated yet"
		}
		return json.Unmarshal([]byte(out), &term) == nil, out
	})
	logs, err := kubectl(t, cluster, "", "-n", ns, "logs", pod, "-c", name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(logs), term.FinishedAt.Sub(term.StartedAt), term.ExitCode
}

// kialiPod returns the name of the Ready Kiali pod, and replaces it when the test ends, because the
// pod keeps each ephemeral container.
func kialiPodForProbes(t *testing.T) string {
	t.Helper()
	pod, _ := readyPod(t, meshNamespace, kialiName)
	t.Cleanup(func() {
		if _, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "delete", "pod", pod, "--wait=true", "--timeout=120s", "--ignore-not-found"); err != nil {
			t.Logf("cleanup: delete the Kiali pod %s: %v", pod, err)
		}
		if _, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "rollout", "status", "deployment/"+kialiName, "--timeout=300s"); err != nil {
			t.Logf("cleanup: Kiali did not roll out again: %v", err)
		}
	})
	return pod
}

// probeHTTP runs netprobe http from the ephemeral container in a pod and returns the status and the
// body of the answer.
func probeHTTP(t *testing.T, cluster, ns, pod, method, url string, extra ...string) (int, string, time.Duration) {
	t.Helper()
	args := append([]string{"http", "--method", method, "--url", url, "--timeout", "30s"}, extra...)
	out, took := ephemeralNetprobe(t, cluster, ns, pod, args...)
	var res struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("netprobe http printed %q: %v", out, err)
	}
	return res.Status, res.Body, took
}

// TestM3NoWorkloadCanPortForward checks, through can-i with the subresource flag, that no ServiceAccount of the
// plane namespaces may create pods/portforward, cluster-wide or in any namespace of management. A namespaced
// Role, which the Kiali chart renders, satisfies only a check in its own namespace, so the test asks each
// namespace in turn. The viewer Role of the chart grants it, and the render deletes that rule.
func TestM3NoWorkloadCanPortForward(t *testing.T) {
	nsOut, err := kubectl(t, mgmtCluster, "", "get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		t.Fatal(err)
	}
	namespaces := strings.Fields(nsOut)
	for _, ns := range []string{viewNamespace, obsNamespace, meshNamespace} {
		out, err := kubectl(t, mgmtCluster, "", "-n", ns, "get", "serviceaccounts", "-o", "jsonpath={.items[*].metadata.name}")
		if err != nil {
			t.Fatal(err)
		}
		accounts := strings.Fields(out)
		if len(accounts) == 0 {
			t.Fatalf("namespace %s holds no ServiceAccount", ns)
		}
		for _, sa := range accounts {
			as := "system:serviceaccount:" + ns + ":" + sa
			t.Run(ns+"/"+sa, func(t *testing.T) {
				t.Parallel()
				if canISub(t, mgmtCluster, as, "create", "pods", "portforward", "") {
					t.Errorf("%s can create pods/portforward in every namespace", as)
				}
				for _, target := range namespaces {
					if canISub(t, mgmtCluster, as, "create", "pods", "portforward", target) {
						t.Errorf("%s can create pods/portforward in %s", as, target)
					}
				}
			})
		}
	}
}

// TestM3PrometheusWritePathClosed sends the write paths of Prometheus to prom-readonly from the
// Kiali pod, where each gets 403. The Kiali pod cannot dial lgtm on 9090, and a read through
// prom-readonly returns Istio metrics.
func TestM3PrometheusWritePathClosed(t *testing.T) {
	needProbeImage(t)
	pod := kialiPodForProbes(t)
	base := "http://" + promProxyName + "." + obsNamespace + ".svc:9091"
	for _, p := range []string{"/api/v1/write", "/api/v1/otlp/v1/metrics"} {
		status, body, _ := probeHTTP(t, mgmtCluster, meshNamespace, pod, "POST", base+p, "--body-stdin")
		if status != 403 || !strings.Contains(body, `"error":"denied"`) {
			t.Errorf("POST %s answers %d %s, want 403 denied", p, status, body)
		}
	}
	for _, p := range []string{"/-/reload", "/api/v1/admin/tsdb/snapshot", "/api/v1/targets"} {
		method := "GET"
		if strings.Contains(p, "admin") || strings.Contains(p, "reload") {
			method = "POST"
		}
		if status, body, _ := probeHTTP(t, mgmtCluster, meshNamespace, pod, method, base+p); status != 403 {
			t.Errorf("%s %s answers %d %s, want 403", method, p, status, body)
		}
	}
	lgtmIP, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "get", "service", "lgtm", "-o", "jsonpath={.spec.clusterIP}")
	if err != nil || net.ParseIP(strings.TrimSpace(lgtmIP)) == nil {
		t.Fatalf("lgtm address %q: %v", lgtmIP, err)
	}
	proxyIP := strings.TrimSpace(func() string {
		out, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "get", "service", promProxyName, "-o", "jsonpath={.spec.clusterIP}")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}())
	// The control dial first, so a timeout to lgtm comes from the policy.
	if got := ephemeralDialResult(t, pod, proxyIP+":9091"); got != "connected" {
		t.Fatalf("the control dial from the Kiali pod to prom-readonly gave %q, want connected", got)
	}
	if got := ephemeralDialResult(t, pod, strings.TrimSpace(lgtmIP)+":9090"); got != "timeout" {
		t.Errorf("the dial from the Kiali pod to lgtm:9090 gave %q, want a timeout", got)
	}
	status, body, _ := probeHTTP(t, mgmtCluster, meshNamespace, pod, "GET", base+"/api/v1/query?query=count(istio_requests_total)")
	var res struct {
		Status string `json:"status"`
		Data   struct {
			Result []json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &res); status != 200 || err != nil || res.Status != "success" || len(res.Data.Result) == 0 {
		t.Errorf("a query for istio_requests_total through prom-readonly answers %d %s (%v), want a series", status, body, err)
	}
}

func ephemeralDialResult(t *testing.T, pod, addr string) string {
	t.Helper()
	out, _ := ephemeralNetprobe(t, mgmtCluster, meshNamespace, pod, "dial", "--addr", addr, "--timeout", "5s")
	var res struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("netprobe dial printed %q: %v", out, err)
	}
	return res.Result
}

// TestM3MeshNodePortAdmission dials the mesh node port of management from a pod in dev-cp, in a cell
// and in rogue. Only the dev-cp node address may connect.
func TestM3MeshNodePortAdmission(t *testing.T) {
	needProbeImage(t)
	ip := clusterFacts(t, mgmtCluster).NodeIP
	if net.ParseIP(ip) == nil {
		t.Fatalf("management node address %q", ip)
	}
	for cluster, want := range map[string]string{envCluster: "connected", "dev-cell-1": "timeout", "rogue": "timeout"} {
		t.Run(cluster, func(t *testing.T) {
			ns := freshNamespace(t, cluster)
			if got := dialFrom(t, cluster, ns, ip, meshNodePort, 3*time.Second); got != want {
				t.Errorf("dial from %s to %s:%d gave %q, want %q", cluster, ip, meshNodePort, got, want)
			}
		})
	}
}

// meshOwnSVID checks that cell-proxy of a mesh-view pod gets only its own ID from the Workload API.
func meshOwnSVID(t *testing.T, cluster string) {
	t.Helper()
	want := "spiffe://" + envTrustDomain + "/cell/" + cluster + "/mesh-view"
	pod, _ := readyPodIn(t, cluster, meshNamespace, tunnelName)
	out, err := kubectl(t, cluster, "", "-n", meshNamespace, "exec", pod, "-c", "cell-proxy", "--", "/ko-app/cell-proxy", "whoami")
	if err != nil {
		t.Fatalf("cell-proxy whoami in %s/%s: %v", cluster, pod, err)
	}
	var got struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil || !slices.Equal(got.IDs, []string{want}) {
		t.Errorf("cell-proxy whoami in %s/%s prints %q, want only %s", cluster, pod, out, want)
	}
}

// hubLog returns the log of the hub container.
func hubLog(t *testing.T) string {
	t.Helper()
	pod, _ := readyPod(t, meshNamespace, hubName)
	out, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "logs", pod, "-c", "cell-proxy")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// tunnelDowns returns the number of tunnel_down lines of a cell in a hub log.
func tunnelDowns(log, cell string) int {
	n := 0
	for l := range strings.SplitSeq(log, "\n") {
		var rec struct{ Msg, Cell string }
		if json.Unmarshal([]byte(l), &rec) == nil && rec.Cell == cell && rec.Msg == "tunnel_down" {
			n++
		}
	}
	return n
}

// tunnelState returns "tunnel_up" when a cell has an open tunnel in a hub log, and "tunnel_down" otherwise,
// with the number of tunnel_up lines. A tunnel is open when its conn_id has no tunnel_down line, because the
// new tunnel of a cell logs tunnel_up before the replaced one logs tunnel_down.
func tunnelState(log, cell string) (last string, ups int) {
	all, downs, _ := hubConnIDs(log, cell)
	last = "tunnel_down"
	for _, id := range all {
		if !downs[id] {
			last = "tunnel_up"
		}
	}
	return last, len(all)
}

// waitHubTunnel waits until the hub log has more than after tunnel_up lines for a cell, with the
// last one up, and returns the number of tunnel_up lines.
func waitHubTunnel(t *testing.T, cell string, after int, within time.Duration) int {
	t.Helper()
	var ups int
	waitFor(t, "the hub tunnel of "+cell+" to be up again", within, func() (bool, string) {
		last, n := tunnelState(hubLog(t), cell)
		ups = n
		return last == "tunnel_up" && n > after, fmt.Sprintf("last %q, %d tunnel_up lines, want more than %d", last, n, after)
	})
	return ups
}

// hubConnIDs returns the conn_id of each tunnel_up line of a cell in a hub log, and the conn_ids that have a
// tunnel_down line and a tunnel_expired line.
func hubConnIDs(log, cell string) (ups []int, downs, expired map[int]bool) {
	downs, expired = map[int]bool{}, map[int]bool{}
	for l := range strings.SplitSeq(log, "\n") {
		var rec struct {
			Msg, Cell string
			ConnID    int `json:"conn_id"`
		}
		if json.Unmarshal([]byte(l), &rec) != nil || rec.Cell != cell {
			continue
		}
		switch rec.Msg {
		case "tunnel_up":
			ups = append(ups, rec.ConnID)
		case "tunnel_down":
			downs[rec.ConnID] = true
		case "tunnel_expired":
			expired[rec.ConnID] = true
		}
	}
	return ups, downs, expired
}

// hubDownCause returns the cause that the hub logged in the tunnel_down line of a conn_id, or "".
func hubDownCause(log, cell string, connID int) string {
	for l := range strings.SplitSeq(log, "\n") {
		var rec struct {
			Msg, Cell, Cause string
			ConnID           int `json:"conn_id"`
		}
		if json.Unmarshal([]byte(l), &rec) == nil && rec.Msg == "tunnel_down" && rec.Cell == cell && rec.ConnID == connID {
			return rec.Cause
		}
	}
	return ""
}

// cellTunnelState reads the state that the tunnel process of a cell serves.
func cellTunnelState(t *testing.T, cell, pod string) cellproxyStatus {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", meshNamespace, "exec", pod, "-c", "cell-proxy", "--", "/ko-app/cell-proxy", "tunnel-status")
	if err != nil {
		t.Fatalf("tunnel-status in %s/%s: %v", cell, pod, err)
	}
	var st cellproxyStatus
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &st); err != nil {
		t.Fatalf("tunnel-status printed %q: %v", out, err)
	}
	return st
}

type cellproxyStatus struct {
	Side  string `json:"side"`
	Up    bool   `json:"up"`
	Cells map[string]struct {
		Up          bool       `json:"up"`
		ConnID      int        `json:"conn_id"`
		AgeSeconds  float64    `json:"age_seconds"`
		ExpiresAt   *time.Time `json:"expires_at"`
		DownSeconds float64    `json:"down_seconds"`
		LastEnd     *struct {
			Cause, Detail string
			At            time.Time
			AgeSeconds    float64 `json:"age_seconds"`
		} `json:"last_end"`
	} `json:"cells"`
}

// TestM3TunnelStatus reads the tunnel state from the tunnel processes themselves: the hub reports both cells up, and the
// tunnel pod of each cell reports its tunnel up.
func TestM3TunnelStatus(t *testing.T) {
	hub, _ := readyPod(t, meshNamespace, hubName)
	out, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "exec", hub, "-c", "cell-proxy", "--", "/ko-app/cell-proxy", "tunnel-status")
	if err != nil {
		t.Fatal(err)
	}
	var st cellproxyStatus
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &st); err != nil || st.Side != "hub" {
		t.Fatalf("hub tunnel-status printed %q: %v", out, err)
	}
	for _, cell := range meshCells(t) {
		waitFor(t, "the hub to report the tunnel of "+cell+" up", time.Minute, func() (bool, string) {
			o, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "exec", hub, "-c", "cell-proxy", "--", "/ko-app/cell-proxy", "tunnel-status")
			var s cellproxyStatus
			if err != nil || json.Unmarshal([]byte(strings.TrimSpace(o)), &s) != nil {
				return false, fmt.Sprint(err)
			}
			return s.Cells[cell].Up, o
		})
		pod, _ := readyPodIn(t, cell, meshNamespace, tunnelName)
		waitFor(t, "the tunnel pod of "+cell+" to report its tunnel up", time.Minute, func() (bool, string) {
			return cellTunnelState(t, cell, pod).Cells["self"].Up, "down"
		})
	}
}

// keepaliveBound is the time that a side needs to find a dead path: the read idle time and the ping timeout in
// components/mesh-view/tunnel.yaml and hub.yaml (10 s and 5 s).
const keepaliveBound = 15 * time.Second

// TestM3KeepaliveBlackhole drops the packets on one direction between the relay of dev-cp and the hub, as a dead path
// does, and requires that a side finds the dead tunnel by its own pings, not by the SVID expiry. Two phases:
//
//   - relay to hub dropped: the pings of the hub get no answer. The hub logs a tunnel_down with the cause local_close
//     within twice the keepalive bound. A hub with no pings fails this phase.
//   - hub to relay dropped: the pings of the cell get no answer. The state of the tunnel pod shows a tunnel that ended
//     with the cause local_close after the drop started. A cell with no pings fails this phase.
//
// The drop starts only when the SVID that remains outlives the keepalive bound by a clear margin (the bound again), so
// the expiry never races the detection. Otherwise the test waits for the next renewal. Each attempt tags its rule with a
// comment of its own, and its timer in the node deletes only that rule, so one attempt cannot remove the rule of another.
// A timer in the node removes the rule after 120 seconds even when the test dies, and gate:m3:repair removes any rule with
// the tag prefix gate-m3-blackhole-.
func TestM3KeepaliveBlackhole(t *testing.T) {
	cell := meshCells(t)[0]
	mgmtIP := clusterFacts(t, mgmtCluster).NodeIP
	if net.ParseIP(mgmtIP) == nil {
		t.Fatalf("management node address %q", mgmtIP)
	}
	node := envCluster + "-control-plane"
	var tags []string
	ruleArgs := func(tag string, rule int) []string {
		dir := []string{"-d", mgmtIP, "--dport", strconv.Itoa(meshNodePort)}
		if rule == 1 {
			dir = []string{"-s", mgmtIP, "--sport", strconv.Itoa(meshNodePort)}
		}
		return append(append([]string{"FORWARD", "-p", "tcp"}, dir...), "-m", "comment", "--comment", tag, "-j", "DROP")
	}
	remove := func(tag string, rule int) {
		r := ruleArgs(tag, rule)
		// -C checks that the rule exists, so a rule that the timer removed already is no error.
		if _, err := dockerExec(t, node, "", append([]string{"iptables", "-C"}, r...)...); err != nil {
			return
		}
		if _, err := dockerExec(t, node, "", append([]string{"iptables", "-D"}, r...)...); err != nil {
			t.Errorf("remove the rule %v from %s: %v. Run: mise run gate:m3:repair", r, node, err)
		}
	}
	removeAll := func() {
		for _, tag := range tags {
			remove(tag, 0)
			remove(tag, 1)
		}
	}
	t.Cleanup(removeAll)
	defer removeAll()

	// renewIn returns the time until the cell opens a new tunnel. The cell renews at 60% of the leaf life, which is
	// the age of the tunnel plus the time to expiry, so the renewal comes before the SVID expires.
	renewIn := func(pod string) (time.Duration, bool) {
		self := cellTunnelState(t, cell, pod).Cells["self"]
		if !self.Up || self.ExpiresAt == nil {
			return 0, false
		}
		age := time.Duration(self.AgeSeconds * float64(time.Second))
		life := age + time.Until(*self.ExpiresAt)
		return life*6/10 - age, true
	}
	// renewMargin is the time that the checks between the measurement and the rule may take. A leaf of 60 s renews 36 s
	// after the tunnel opens, so a longer margin leaves no window to catch with a poll every 2 s.
	const renewMargin = 5 * time.Second
	// headroom waits for an open tunnel of the cell whose next renewal is at least the keepalive bound and the margin
	// away, and returns its conn_id and the name of the tunnel pod.
	headroom := func() (int, string) {
		var connID int
		var pod string
		waitFor(t, "a hub tunnel of "+cell+" with headroom", 3*time.Minute, func() (bool, string) {
			ups, downs, _ := hubConnIDs(hubLog(t), cell)
			if len(ups) == 0 || downs[ups[len(ups)-1]] {
				return false, "no open tunnel"
			}
			pod, _ = readyPodIn(t, cell, meshNamespace, tunnelName)
			left, ok := renewIn(pod)
			if !ok {
				return false, "the tunnel pod reports no open tunnel"
			}
			connID = ups[len(ups)-1]
			return left >= keepaliveBound+renewMargin, fmt.Sprintf("tunnel %d renews in %s, want %s", connID, left.Round(time.Second), keepaliveBound+renewMargin)
		})
		return connID, pod
	}
	for _, phase := range []struct {
		name string
		rule int
	}{{"the hub pings", 0}, {"the cell pings", 1}} {
		found := false
		// An attempt that ends on a renewal or an expiry says nothing about keepalive, so it does not count. The
		// loop stops after 8 attempts in all.
		counted := 0
		for attempt := 1; attempt <= 8 && counted < 3 && !found; attempt++ {
			connID, cellPod := headroom()
			tag := "gate-m3-blackhole-" + randomHex(t, 4)
			tags = append(tags, tag)
			since := time.Now().UTC()
			r := ruleArgs(tag, phase.rule)
			if _, err := dockerExec(t, node, "", append([]string{"iptables", "-I"}, r...)...); err != nil {
				t.Fatalf("insert the rule %v in %s: %v", r, node, err)
			}
			// The timer deletes only the rule of this attempt, by its tag.
			if _, err := dockerExec(t, node, "", "sh", "-c", "nohup sh -c 'sleep 120; iptables -C "+strings.Join(r, " ")+" 2>/dev/null && iptables -D "+strings.Join(r, " ")+"' >/dev/null 2>&1 &"); err != nil {
				t.Logf("start the timer in %s: %v", node, err)
			}
			if left, ok := renewIn(cellPod); ok {
				t.Logf("%s, attempt %d: the tunnel renews in %s after the rule is in", phase.name, attempt, left.Round(time.Second))
			}
			var hubCause, cellCause string
			deadline := time.Now().Add(2 * keepaliveBound)
			for time.Now().Before(deadline) {
				if phase.rule == 0 {
					hubCause = hubDownCause(hubLog(t), cell, connID)
				} else if e := cellTunnelState(t, cell, cellPod).Cells["self"].LastEnd; e != nil && e.At.After(since) {
					cellCause = e.Cause
				}
				if hubCause != "" || cellCause != "" {
					break
				}
				time.Sleep(time.Second)
			}
			took := time.Since(since).Round(time.Second)
			remove(tag, phase.rule)
			t.Logf("%s, attempt %d (%s): tunnel %d, hub cause %q, cell cause %q, after %s", phase.name, attempt, tag, connID, hubCause, cellCause, took)
			found = (phase.rule == 0 && hubCause == "local_close") || (phase.rule == 1 && cellCause == "local_close")
			switch {
			case found:
				counted++
			case hubCause == "renewal" || hubCause == "expiry" || cellCause == "renewal" || cellCause == "expiry":
				t.Logf("the tunnel ended on a renewal or an expiry, so this attempt does not count")
			default:
				counted++
			}
			waitHubTunnel(t, cell, len(mustUps(hubConnIDs(hubLog(t), cell))), 3*time.Minute)
		}
		if !found {
			t.Errorf("in %d counted attempts, %s never closed the tunnel with the cause local_close: keepalive does not find the dead path", counted, phase.name)
		}
	}
}

func mustUps(ups []int, _, _ map[int]bool) []int { return ups }

// meshNamespaces are the namespaces that Kiali reads in each cell (MESH_VIEW_NAMESPACES, and its own).
var meshNamespaces = []string{"apps-demo", "istio-egress", "istio-system", "mesh-view-system"}

// kialiForward starts a port-forward to Kiali and returns its address.
func kialiForward(t *testing.T) string {
	t.Helper()
	return portForward(t, mgmtCluster, meshNamespace, "svc/"+kialiName, 20001)
}

var kialiClient = &http.Client{Timeout: 20 * time.Second}

// kialiCall sends one request to Kiali at addr. The API has no login, because Kiali is anonymous.
func kialiCall(method, addr, path, body string) (int, []byte, error) {
	req, err := http.NewRequest(method, "http://"+addr+"/kiali"+path, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json-patch+json")
	}
	resp, err := kialiClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, out, err
}

// kialiNamespaces returns the sorted namespace names that Kiali lists for each cluster.
func kialiNamespaces(addr string) (map[string][]string, error) {
	code, body, err := kialiCall("GET", addr, "/api/namespaces", "")
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("GET /api/namespaces answers %d: %.200s", code, body)
	}
	var list []struct{ Name, Cluster string }
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode the namespaces: %w", err)
	}
	out := map[string][]string{}
	for _, n := range list {
		out[n.Cluster] = append(out[n.Cluster], n.Name)
	}
	for c := range out {
		slices.Sort(out[c])
	}
	return out, nil
}

// kialiSeesCells reports whether Kiali lists the namespaces of every cell. The listing reads each cell
// live through the hub, so it fails while a tunnel is down.
func kialiSeesCells(addr string) (bool, string) {
	got, err := kialiNamespaces(addr)
	if err != nil {
		return false, err.Error()
	}
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
		if !slices.Equal(got[cell], meshNamespaces) {
			return false, fmt.Sprintf("Kiali lists %v for %s, want %v", got[cell], cell, meshNamespaces)
		}
	}
	return true, ""
}

// kialiPodState returns the UID and the restart count of the Kiali pod.
func kialiPodState(t *testing.T) (uid string, restarts int) {
	t.Helper()
	pod, uid := readyPod(t, meshNamespace, kialiName)
	out, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "get", "pod", pod, "-o", "jsonpath={.status.containerStatuses[0].restartCount}")
	if err != nil {
		t.Fatal(err)
	}
	restarts, err = strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("restart count %q: %v", out, err)
	}
	return uid, restarts
}

// waitNewKiali waits until a Ready Kiali pod with another UID than old exists, and returns its name.
func waitNewKiali(t *testing.T, old string, within time.Duration) (name string, took time.Duration) {
	t.Helper()
	start := time.Now()
	waitFor(t, "a new Ready Kiali pod", within, func() (bool, string) {
		out, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+kialiName, "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var pods struct {
			Items []struct {
				Metadata struct {
					Name, UID string
					Deleted   *string `json:"deletionTimestamp"`
				}
				Status struct {
					Conditions []struct{ Type, Status string }
				}
			}
		}
		if err := json.Unmarshal([]byte(out), &pods); err != nil {
			return false, err.Error()
		}
		for _, p := range pods.Items {
			for _, c := range p.Status.Conditions {
				if c.Type == "Ready" && c.Status == "True" && p.Metadata.UID != old && p.Metadata.Deleted == nil {
					name = p.Metadata.Name
					return true, ""
				}
			}
		}
		return false, fmt.Sprintf("%d pods, none new and Ready", len(pods.Items))
	})
	return name, time.Since(start)
}

// applyMeshView applies the rendered bundle of mesh-view in a cell again, as the harness does. It
// sets the replicas to 1, and it takes the field of the replicas back from a scale.
func applyMeshView(t *testing.T, cell string) {
	t.Helper()
	out, err := kubectl(t, cell, "", "apply", "--server-side", "--force-conflicts", "-f", "../../build/"+cell+"/bundles/mesh-view/manifests.yaml")
	if err != nil {
		t.Errorf("apply the mesh-view bundle of %s: %v\n%s. Run: CELL=%s mise run cell:up", cell, err, out, cell)
	}
}

// TestM3KialiSeesBothCells checks that Kiali lists dev-cell-1 and dev-cell-2 as accessible clusters
// that reach their API through the hub, each with the namespaces of its own cell.
func TestM3KialiSeesBothCells(t *testing.T) {
	addr := kialiForward(t)
	waitFor(t, "Kiali to list the namespaces of both cells", 3*time.Minute, func() (bool, string) { return kialiSeesCells(addr) })
	code, body, err := kialiCall("GET", addr, "/api/config", "")
	if err != nil || code != 200 {
		t.Fatalf("GET /api/config: %d %v %.200s", code, err, body)
	}
	var conf struct {
		Clusters map[string]struct {
			Accessible  bool   `json:"accessible"`
			APIEndpoint string `json:"apiEndpoint"`
			SecretName  string `json:"secretName"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(body, &conf); err != nil {
		t.Fatal(err)
	}
	for _, cell := range meshCells(t) {
		c, ok := conf.Clusters[cell]
		want := fmt.Sprintf("http://%s.%s.svc:%d", hubName, meshNamespace, hubPort(t, cell))
		if !ok || !c.Accessible || c.APIEndpoint != want || c.SecretName != "kiali-multi-cluster-secret" {
			t.Errorf("Kiali lists the cluster %s as %+v, want accessible at %s from the remote cluster Secret", cell, c, want)
		}
	}
}

// graphNode and graphEdge are the parts of the Kiali graph that the test reads.
type graphNode struct {
	Cluster, Namespace, Workload, NodeType string
}

// kialiGraph returns the nodes by ID and the edges of the workload graph of apps-demo.
func kialiGraph(addr string) (map[string]graphNode, [][2]string, error) {
	code, body, err := kialiCall("GET", addr, "/api/namespaces/graph?namespaces=apps-demo&graphType=workload&duration=10m", "")
	if err != nil {
		return nil, nil, err
	}
	if code != 200 {
		return nil, nil, fmt.Errorf("the graph answers %d: %.200s", code, body)
	}
	var g struct {
		Elements struct {
			Nodes []struct{ Data graphNode } `json:"nodes"`
			Edges []struct {
				Data struct{ Source, Target string }
			} `json:"edges"`
		} `json:"elements"`
	}
	if err := json.Unmarshal(body, &g); err != nil {
		return nil, nil, err
	}
	// The ID is not in graphNode, so read it again.
	var raw struct {
		Elements struct {
			Nodes []struct{ Data struct{ ID string } } `json:"nodes"`
		} `json:"elements"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, err
	}
	nodes := map[string]graphNode{}
	for i, n := range g.Elements.Nodes {
		nodes[raw.Elements.Nodes[i].Data.ID] = n.Data
	}
	var edges [][2]string
	for _, e := range g.Elements.Edges {
		edges = append(edges, [2]string{e.Data.Source, e.Data.Target})
	}
	return nodes, edges, nil
}

// TestM3KialiSeparateMeshes checks that Kiali shows the mesh of each cell as a separate mesh, and that
// the workload graph of apps-demo has no edge between the two cells. Both cells hold a namespace
// apps-demo, so the graph of that namespace lists the workloads of both cells, each with its cluster.
func TestM3KialiSeparateMeshes(t *testing.T) {
	cells := meshCells(t)
	for _, cell := range cells {
		echoTraffic(t, cell, 5)
	}
	addr := kialiForward(t)
	waitFor(t, "the graph of apps-demo to hold one cluster box for each cell", 5*time.Minute, func() (bool, string) { return meshBoxes(addr, cells) })
	var want []string
	for _, cell := range cells {
		want = append(want, cell+".mesh.poc.internal")
	}
	slices.Sort(want)
	waitFor(t, "the mesh graph to name the mesh of each cell", 3*time.Minute, func() (bool, string) {
		code, body, err := kialiCall("GET", addr, "/api/mesh/graph", "")
		if err != nil || code != 200 {
			return false, fmt.Sprintf("%d %v", code, err)
		}
		var g struct {
			MeshNames []string `json:"meshNames"`
		}
		if err := json.Unmarshal(body, &g); err != nil {
			return false, err.Error()
		}
		slices.Sort(g.MeshNames)
		return slices.Equal(g.MeshNames, want), fmt.Sprintf("mesh names %v, want %v", g.MeshNames, want)
	})
	waitFor(t, "the graph of apps-demo to show client to echo in each cell", 5*time.Minute, func() (bool, string) {
		nodes, edges, err := kialiGraph(addr)
		if err != nil {
			return false, err.Error()
		}
		seen := map[string]bool{}
		for _, e := range edges {
			s, d := nodes[e[0]], nodes[e[1]]
			if s.Cluster != d.Cluster {
				t.Fatalf("an edge joins the cluster %q (%s) and the cluster %q (%s)", s.Cluster, s.Workload, d.Cluster, d.Workload)
			}
			if s.Workload == "client" && d.Workload == "echo" {
				seen[s.Cluster] = true
			}
		}
		for _, n := range nodes {
			if n.NodeType == "workload" && n.Namespace == "apps-demo" && !slices.Contains(cells, n.Cluster) {
				t.Fatalf("the workload %s of apps-demo has the cluster %q, want one of %v", n.Workload, n.Cluster, cells)
			}
		}
		return len(seen) == len(cells), fmt.Sprintf("client to echo edges in %v, want %v", seen, cells)
	})
}

// podOf returns the name of the first pod with the app label in a namespace of a cluster.
func podOf(t *testing.T, cluster, ns, app string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "get", "pods", "-l", "app="+app, "-o", "jsonpath={.items[0].metadata.name}")
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("no pod with the label app=%s in %s/%s: %v", app, cluster, ns, err)
	}
	return strings.TrimSpace(out)
}

func resourceVersion(t *testing.T, cluster, ns, kind, name string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "get", kind, name, "-o", "jsonpath={.metadata.resourceVersion}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// TestM3KialiCannotChange checks that Kiali changes nothing in a cell. A delete of a pod and a patch of
// an AuthorizationPolicy through the Kiali API fail, and each object keeps its resourceVersion. Direct
// requests from the Kiali pod to the hub port of dev-cell-1 for Secrets, exec, logs and a delete get the
// 403 body of the tunnel, and a watch of pods answers 200 and stays open.
func TestM3KialiCannotChange(t *testing.T) {
	needProbeImage(t)
	cell := "dev-cell-1"
	echo := podOf(t, cell, "apps-demo", "echo")
	podRV := resourceVersion(t, cell, "apps-demo", "pod", echo)
	policyRV := resourceVersion(t, cell, "apps-demo", "authorizationpolicy.security.istio.io", "echo-allow-client")
	addr := kialiForward(t)
	waitFor(t, "Kiali to list both cells", 3*time.Minute, func() (bool, string) { return kialiSeesCells(addr) })

	t.Run("through the Kiali API", func(t *testing.T) {
		since := time.Now().UTC().Add(-2 * time.Second)
		// Each route answers one status. Kiali v2.34.0 has no route that deletes a pod, so that case pins the
		// absence of the route: a Kiali that adds one fails the test on purpose, and the case then needs a
		// real write check. A Kiali that sends the write to the cell gets the 403 of the tunnel, and answers 403 since v2.34.1 (500 before).
		for _, tc := range []struct {
			name, method, path, body string
			status                   int
			contains                 string
		}{
			{"delete pod echo (no such route)", "DELETE", "/api/namespaces/apps-demo/pods/" + echo + "?clusterName=" + cell, "", 404, "page not found"},
			{"patch AuthorizationPolicy", "PATCH", "/api/namespaces/apps-demo/istio/security.istio.io/v1/AuthorizationPolicy/echo-allow-client?clusterName=" + cell,
				`[{"op":"replace","path":"/spec/action","value":"DENY"}]`, 403, "unknown (patch authorizationpolicies"},
			{"delete AuthorizationPolicy", "DELETE", "/api/namespaces/apps-demo/istio/security.istio.io/v1/AuthorizationPolicy/echo-allow-client?clusterName=" + cell, "", 403, "unknown (delete authorizationpolicies"},
		} {
			code, body, err := kialiCall(tc.method, addr, tc.path, tc.body)
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			} else if code != tc.status || !strings.Contains(string(body), tc.contains) {
				t.Errorf("%s answers %d %.200s, want %d with %q", tc.name, code, body, tc.status, tc.contains)
			}
		}
		if got := resourceVersion(t, cell, "apps-demo", "pod", echo); got != podRV {
			t.Errorf("pod %s has the resourceVersion %s, was %s", echo, got, podRV)
		}
		if got := resourceVersion(t, cell, "apps-demo", "authorizationpolicy.security.istio.io", "echo-allow-client"); got != policyRV {
			t.Errorf("AuthorizationPolicy echo-allow-client has the resourceVersion %s, was %s", got, policyRV)
		}
		// The tunnel of the cell refused both writes: its log has a request denied line for each method.
		pod, _ := readyPodIn(t, cell, meshNamespace, tunnelName)
		out, err := kubectl(t, cell, "", "-n", meshNamespace, "logs", pod, "-c", "cell-proxy", "--since-time="+since.Format(time.RFC3339))
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{"PATCH", "DELETE"} {
			found := false
			for l := range strings.SplitSeq(out, "\n") {
				var rec struct{ Msg, Reason, Method, Path string }
				if json.Unmarshal([]byte(l), &rec) == nil && rec.Msg == "request denied" && rec.Reason == "request_not_allowed" &&
					rec.Method == method && strings.Contains(rec.Path, "authorizationpolicies") {
					found = true
				}
			}
			if !found {
				t.Errorf("the tunnel pod of %s logged no refused %s of an AuthorizationPolicy since %s", cell, method, since.Format(time.RFC3339))
			}
		}
	})

	kiali := kialiPodForProbes(t)
	hub := fmt.Sprintf("http://%s.%s.svc:%d", hubName, meshNamespace, hubPort(t, cell))
	for _, tc := range []struct{ name, method, path string }{
		{"secrets", "GET", "/api/v1/namespaces/apps-demo/secrets"},
		{"exec", "POST", "/api/v1/namespaces/apps-demo/pods/" + echo + "/exec?command=id&stdout=true"},
		{"logs", "GET", "/api/v1/namespaces/apps-demo/pods/" + echo + "/log"},
		{"delete", "DELETE", "/api/v1/namespaces/apps-demo/pods/" + echo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := probeHTTP(t, mgmtCluster, meshNamespace, kiali, tc.method, hub+tc.path)
			var res struct {
				Error     string `json:"error"`
				RequestID string `json:"request_id"`
				Kind      string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(body), &res); status != 403 || err != nil || res.Error != "denied" || res.RequestID == "" || res.Kind != "" {
				t.Errorf("%s %s answers %d %s, want 403 with the body of the tunnel (error denied and a request ID)", tc.method, tc.path, status, body)
			}
		})
	}
	t.Run("watch", func(t *testing.T) {
		// The watch starts at the current resourceVersion, so it sends no initial events and stays open
		// until the timeout. A tunnel that ends at its SVID expiry can cut a watch short, so the test
		// tries up to 3 times.
		raw, err := kubectl(t, cell, "", "get", "--raw", "/api/v1/namespaces/apps-demo/pods?limit=1")
		var list struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if err != nil || json.Unmarshal([]byte(raw), &list) != nil || list.Metadata.ResourceVersion == "" {
			t.Fatalf("resourceVersion of the pod list: %q %v", raw, err)
		}
		listRV := list.Metadata.ResourceVersion
		var status int
		var took time.Duration
		for range 3 {
			out, d, exit := ephemeralNetprobeExit(t, mgmtCluster, meshNamespace, kiali, "http", "--method", "GET", "--timeout", "30s",
				"--url", hub+"/api/v1/namespaces/apps-demo/pods?watch=true&timeoutSeconds=12&resourceVersion="+listRV)
			var res struct{ Status int }
			status, took = 0, d
			if exit == 0 && json.Unmarshal([]byte(out), &res) == nil {
				status = res.Status
			}
			if status == 200 && took >= 10*time.Second {
				break
			}
			t.Logf("the watch ended after %s with status %d and exit code %d: %.200s", d, status, exit, out)
		}
		if status != 200 || took < 10*time.Second {
			t.Errorf("a pod watch answered %d and ended after %s, want 200 and a stream that stays open for the 12 seconds that it asked for", status, took)
		}
	})
	if got := resourceVersion(t, cell, "apps-demo", "pod", echo); got != podRV {
		t.Errorf("pod %s has the resourceVersion %s, was %s", echo, got, podRV)
	}
}

// TestM3TunnelRecovers deletes the relay-view pod in dev-cp, which ends the tunnel of each cell. The test takes the
// conn_id of the current tunnel of dev-cell-1, and requires its tunnel_down with no tunnel_expired line, so an
// expiry cycle cannot pass for the delete, and then a tunnel with a higher conn_id. Kiali lists dev-cell-1 as
// accessible again within 2 minutes, and its pod neither restarts nor changes.
func TestM3TunnelRecovers(t *testing.T) {
	addr := kialiForward(t)
	waitFor(t, "Kiali to list both cells", 3*time.Minute, func() (bool, string) { return kialiSeesCells(addr) })
	uid, restarts := kialiPodState(t)
	// Start right after a new tunnel, so that its SVID expiry is far away.
	var connID int
	waitFor(t, "a new hub tunnel of dev-cell-1", 2*time.Minute, func() (bool, string) {
		ups, downs, _ := hubConnIDs(hubLog(t), "dev-cell-1")
		if len(ups) == 0 || downs[ups[len(ups)-1]] {
			return false, "no open tunnel"
		}
		connID = ups[len(ups)-1]
		for l := range strings.SplitSeq(hubLog(t), "\n") {
			var rec struct {
				Msg    string
				Time   time.Time
				ConnID int `json:"conn_id"`
			}
			if json.Unmarshal([]byte(l), &rec) == nil && rec.Msg == "tunnel_up" && rec.ConnID == connID {
				return time.Since(rec.Time) < 10*time.Second, "the tunnel is not new"
			}
		}
		return false, "no tunnel_up line"
	})
	if _, err := kubectl(t, envCluster, "", "-n", relayNamespace, "delete", "pod", "-l", "app.kubernetes.io/name=relay-view", "--wait=true"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	t.Logf("deleted the relay-view pod at %s, while tunnel %d was open", start.UTC().Format(time.RFC3339), connID)
	waitFor(t, "the hub to end tunnel "+strconv.Itoa(connID)+" and open a newer one", 2*time.Minute, func() (bool, string) {
		ups, downs, expired := hubConnIDs(hubLog(t), "dev-cell-1")
		if !downs[connID] {
			return false, "tunnel is still open"
		}
		if expired[connID] {
			t.Fatalf("tunnel %d ended by its SVID expiry, so it never saw the delete of the relay: the test started too late", connID)
		}
		// The delete of the relay ends the tunnel from the outside: the hub sees the peer close it, or its own ping fail.
		// A replacement by the early renewal of the cell would not prove the delete.
		if cause := hubDownCause(hubLog(t), "dev-cell-1", connID); cause != "peer_closed" && cause != "local_close" {
			t.Fatalf("tunnel %d ended with the cause %q, want peer_closed or local_close: the relay delete did not end it", connID, cause)
		}
		return len(ups) > 0 && ups[len(ups)-1] > connID && !downs[ups[len(ups)-1]], "no newer open tunnel"
	})
	waitFor(t, "Kiali to list both cells again", 2*time.Minute, func() (bool, string) { return kialiSeesCells(addr) })
	t.Logf("Kiali listed both cells again %s after the delete", time.Since(start).Round(time.Second))
	code, body, err := kialiCall("GET", addr, "/api/config", "")
	if err != nil || code != 200 || !strings.Contains(string(body), `"dev-cell-1"`) {
		t.Fatalf("GET /api/config: %d %v", code, err)
	}
	var conf struct {
		Clusters map[string]struct {
			Accessible bool `json:"accessible"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(body, &conf); err != nil || !conf.Clusters["dev-cell-1"].Accessible {
		t.Errorf("Kiali does not list dev-cell-1 as accessible: %v %s", err, body)
	}
	if uid2, restarts2 := kialiPodState(t); uid2 != uid || restarts2 != restarts {
		t.Errorf("the Kiali pod changed: UID %s to %s, restarts %d to %d", uid, uid2, restarts, restarts2)
	}
}

// TestM3KialiRestartsReady deletes the Kiali pod. The new pod is Ready within 3 minutes and lists both
// cells.
func TestM3KialiRestartsReady(t *testing.T) {
	uid, _ := kialiPodState(t)
	if _, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "delete", "pod", "-l", "app.kubernetes.io/name="+kialiName, "--wait=true", "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
	pod, took := waitNewKiali(t, uid, 3*time.Minute)
	t.Logf("the new Kiali pod %s was Ready %s after the delete", pod, took.Round(time.Second))
	addr := kialiForward(t)
	waitFor(t, "Kiali to list both cells", 2*time.Minute, func() (bool, string) { return kialiSeesCells(addr) })
}

// TestM3KialiBeforeTunnels stops the tunnel pods of both cells, deletes the Kiali pod, and starts the
// tunnels again within 30 seconds. Kiali is Ready within 5 minutes and lists both cells. The test logs
// the restart count and the Kiali log lines that are warnings or errors, for verify row 11.
func TestM3KialiBeforeTunnels(t *testing.T) {
	cells := meshCells(t)
	t.Cleanup(func() {
		for _, cell := range cells {
			applyMeshView(t, cell)
		}
	})
	uid, _ := kialiPodState(t)
	for _, cell := range cells {
		if _, err := kubectl(t, cell, "", "-n", meshNamespace, "scale", "deployment/"+tunnelName, "--replicas=0"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "delete", "pod", "-l", "app.kubernetes.io/name="+kialiName, "--wait=true", "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
	deleted := time.Now()
	for _, cell := range cells {
		applyMeshView(t, cell)
	}
	if took := time.Since(deleted); took > 30*time.Second {
		t.Errorf("the tunnels came back %s after the delete of the Kiali pod, want 30 seconds or less", took.Round(time.Second))
	}
	pod, took := waitNewKiali(t, uid, 5*time.Minute)
	t.Logf("the new Kiali pod %s was Ready %s after the delete", pod, took.Round(time.Second))
	out, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "get", "pod", pod, "-o", "jsonpath={.status.containerStatuses[0].restartCount}")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("restart count of the new Kiali pod: %s", strings.TrimSpace(out))
	if logs, err := kubectl(t, mgmtCluster, "", "-n", meshNamespace, "logs", pod, "-c", "kiali"); err == nil {
		for l := range strings.SplitSeq(logs, "\n") {
			if strings.Contains(l, `"level":"warn"`) || strings.Contains(l, `"level":"error"`) || strings.Contains(l, "Discovered cluster") || strings.Contains(l, "caches synced") {
				t.Logf("kiali: %.300s", l)
			}
		}
	}
	addr := kialiForward(t)
	waitFor(t, "Kiali to list both cells", 3*time.Minute, func() (bool, string) { return kialiSeesCells(addr) })
}

// TestM3MeshPortsFromFreshNamespace dials the plain HTTP ports of the mesh view from a pod that is not Kiali:
// the hub ports of each cell, the Kiali port and the prom-readonly port. Each dial must time out, after a control
// dial that connects. The hub node port 8444 admits the dev-cp node only, so a pod of management times out there
// too.
func TestM3MeshPortsFromFreshNamespace(t *testing.T) {
	needProbeImage(t)
	hub, _ := readyPod(t, meshNamespace, hubName)
	kiali, _ := readyPod(t, meshNamespace, kialiName)
	prom, _ := readyPod(t, obsNamespace, promProxyName)
	type target struct {
		name, ip string
		port     int
	}
	targets := []target{{"hub 8444", mgmtPodIP(t, meshNamespace, hub), 8444}, {"kiali 20001", mgmtPodIP(t, meshNamespace, kiali), 20001},
		{"prom-readonly 9091", mgmtPodIP(t, obsNamespace, prom), 9091}}
	for _, cell := range meshCells(t) {
		targets = append(targets, target{"hub " + cell, mgmtPodIP(t, meshNamespace, hub), hubPort(t, cell)})
	}
	for _, tg := range targets {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			if err := probeFromFreshNamespace(t, mgmtCluster, tg.ip, tg.port, 4*time.Second); err != nil {
				t.Error(err)
			}
		})
	}
}

// meshBoxes checks the graph of apps-demo with the cluster boxes that an operator uses: one box for each cell, and
// every workload of apps-demo inside the box of its own cluster.
func meshBoxes(addr string, cells []string) (bool, string) {
	code, body, err := kialiCall("GET", addr, "/api/namespaces/graph?namespaces=apps-demo&graphType=workload&duration=10m&boxBy=cluster&includeIdleEdges=true", "")
	if err != nil || code != 200 {
		return false, fmt.Sprintf("%d %v", code, err)
	}
	var g struct {
		Elements struct {
			Nodes []struct {
				Data struct {
					ID, Cluster, Namespace, Parent, NodeType, Workload string
					IsBox                                              string `json:"isBox"`
				}
			}
		}
	}
	if err := json.Unmarshal(body, &g); err != nil {
		return false, err.Error()
	}
	boxes := map[string]string{}
	for _, n := range g.Elements.Nodes {
		if n.Data.IsBox == "cluster" {
			boxes[n.Data.ID] = n.Data.Cluster
		}
	}
	var got []string
	for _, c := range boxes {
		got = append(got, c)
	}
	slices.Sort(got)
	want := slices.Clone(cells)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return false, fmt.Sprintf("cluster boxes %v, want %v", got, want)
	}
	for _, n := range g.Elements.Nodes {
		if n.Data.NodeType == "workload" && n.Data.Namespace == "apps-demo" && boxes[n.Data.Parent] != n.Data.Cluster {
			return false, fmt.Sprintf("workload %s of %s sits in the box of %q", n.Data.Workload, n.Data.Cluster, boxes[n.Data.Parent])
		}
	}
	return true, ""
}

const meshGuardPolicy = "mesh-view-read-only"

func requireMeshDenied(t *testing.T, what, message string, err error) {
	t.Helper()
	switch {
	case err == nil:
		t.Errorf("%s succeeded, want a denial by %s", what, meshGuardPolicy)
	case !strings.Contains(err.Error(), meshGuardPolicy) || !strings.Contains(err.Error(), message):
		t.Errorf("%s failed, but not with the denial %q of %s: %v", what, message, meshGuardPolicy, err)
	default:
		t.Logf("%s: denied by %s: %s", what, meshGuardPolicy, message)
	}
}

const meshGuardTestRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mesh-guard-test
  namespace: mesh-view-system
  labels: {poc.internal/test: view-guard}
rules:
  - apiGroups: [""]
    resources: [configmaps, serviceaccounts]
    verbs: [get, create, update, patch, delete]
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list]
  - apiGroups: [""]
    resources: [pods/exec]
    verbs: [create]
  - apiGroups: [""]
    resources: [serviceaccounts/token]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mesh-guard-test
  namespace: mesh-view-system
  labels: {poc.internal/test: view-guard}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: mesh-guard-test
subjects:
  - kind: Group
    name: poc:guard-test
    apiGroup: rbac.authorization.k8s.io
`

// TestM3MeshGuardDeniesWithoutRBAC proves the policy mesh-view-read-only on its own. A temporary Role gives the test
// group every write that the guard must still deny, and each request goes out as the ServiceAccount mesh-view with that
// group (kubectl --as and --as-group), as a server-side dry run. The real account never holds the grant.
func TestM3MeshGuardDeniesWithoutRBAC(t *testing.T) {
	const account = "system:serviceaccount:mesh-view-system:mesh-view"
	for _, cell := range meshCells(t) {
		t.Run(cell, func(t *testing.T) {
			t.Cleanup(func() { repairGuardObjects(t, cell) })
			if _, err := kubectl(t, cell, meshGuardTestRole, "apply", "-f", "-"); err != nil {
				t.Fatal(err)
			}
			asArgs := []string{"--as", account, "--as-group", guardTestGroup}
			waitFor(t, "RBAC allows the test group to update ConfigMaps", time.Minute, func() (bool, string) {
				out, _ := kubectl(t, cell, "", append([]string{"auth", "can-i", "update", "configmaps", "-n", meshNamespace}, asArgs...)...)
				return strings.TrimSpace(out) == "yes", strings.TrimSpace(out)
			})
			if out, _ := kubectl(t, cell, "", "auth", "can-i", "update", "configmaps", "-n", meshNamespace, "--as="+account); strings.TrimSpace(out) != "no" {
				t.Fatalf("the account alone can update ConfigMaps in %s: %q, so the test would touch the real grant", cell, strings.TrimSpace(out))
			}
			as := func(args ...string) error {
				_, err := kubectl(t, cell, "", append(append([]string{}, asArgs...), append([]string{"-n", meshNamespace}, args...)...)...)
				return err
			}
			podOut, err := kubectl(t, cell, "", "-n", meshNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+tunnelName, "-o", "jsonpath={.items[0].metadata.name} {.items[0].metadata.uid}")
			if err != nil || len(strings.Fields(podOut)) != 2 {
				t.Fatalf("pod of %s in %s: %q %v", tunnelName, cell, podOut, err)
			}
			podName, podUID := strings.Fields(podOut)[0], strings.Fields(podOut)[1]
			t.Run("update", func(t *testing.T) {
				requireMeshDenied(t, "patch a ConfigMap", "cannot update an object", as("patch", "configmap", "mgmt-root", "--type", "merge", "-p", `{"data":{"guard-test":"1"}}`, "--dry-run=server"))
			})
			t.Run("create", func(t *testing.T) {
				requireMeshDenied(t, "create a ConfigMap", "creates only the bound token", as("create", "configmap", "guard-test", "--dry-run=server"))
			})
			t.Run("delete", func(t *testing.T) {
				requireMeshDenied(t, "delete a ConfigMap", "cannot delete an object or connect", as("delete", "configmap", "mgmt-root", "--dry-run=server"))
			})
			t.Run("connect", func(t *testing.T) {
				requireMeshDenied(t, "exec in the tunnel pod", "cannot delete an object or connect", as("exec", podName, "-c", "cell-proxy", "--", "true"))
			})
			token := func(extra bool, args ...string) error {
				full := []string{"create", "token", "mesh-view"}
				if extra {
					full = append(full, "--as-user-extra=authentication.kubernetes.io/pod-name="+podName, "--as-user-extra=authentication.kubernetes.io/pod-uid="+podUID)
				}
				return as(append(full, args...)...)
			}
			bound := []string{"--bound-object-kind=Pod", "--bound-object-name=" + podName, "--bound-object-uid=" + podUID, "--duration=10m"}
			audience := func(a string) []string { return append([]string{"--audience=" + a}, bound...) }
			t.Run("token", func(t *testing.T) {
				if err := token(true, audience("spire-"+pocEnv+"/abc_DEF-123")...); err != nil {
					t.Errorf("the bound token that the SPIRE agent asks for was refused: %v", err)
				}
				const msg = "creates only the bound token"
				requireMeshDenied(t, "a token for the API server audience", msg, token(true, audience("https://kubernetes.default.svc")...))
				requireMeshDenied(t, "a token with no bound object", msg, token(true, "--audience=spire-"+pocEnv+"/abc", "--duration=10m"))
				requireMeshDenied(t, "a token with no pod extras", msg, token(false, audience("spire-"+pocEnv+"/abc")...))
				requireMeshDenied(t, "a token bound to a Secret", msg, token(true, "--audience=spire-"+pocEnv+"/abc", "--bound-object-kind=Secret", "--bound-object-name=mgmt-root", "--duration=10m"))
				requireMeshDenied(t, "a token for another account", msg, as(append([]string{"create", "token", "default",
					"--as-user-extra=authentication.kubernetes.io/pod-name=" + podName, "--as-user-extra=authentication.kubernetes.io/pod-uid=" + podUID}, audience("spire-"+pocEnv+"/abc")...)...))
			})
		})
	}
}

// TestM3MeshViewCannotReadOrEscalate asks the API server what the ServiceAccount mesh-view may do in each cell. It
// reads pods in apps-demo (the positive control), and may mint the bound token of its own SPIRE agent. Every other answer
// is no: Secrets, exec, attach, port forward, proxies, logs, writes, impersonation, escalate and bind, and the admission
// objects. The guard mesh-view-read-only sees only the requests that reach admission, so the grants of impersonate,
// escalate, bind and the writes to the admission objects are what these checks keep out of RBAC.
func TestM3MeshViewCannotReadOrEscalate(t *testing.T) {
	const account = "system:serviceaccount:mesh-view-system:mesh-view"
	type check struct {
		name, verb, resource, sub, ns string
		want                          bool
	}
	checks := []check{{"get pods in apps-demo", "get", "pods", "", "apps-demo", true}}
	for _, ns := range []string{"mesh-view-system", "istio-system", "apps-demo", "argocd"} {
		for _, verb := range []string{"get", "list", "watch"} {
			checks = append(checks, check{fmt.Sprintf("%s secrets in %s", verb, ns), verb, "secrets", "", ns, false})
		}
	}
	for _, sub := range []string{"exec", "attach", "portforward"} {
		checks = append(checks, check{"create pods/" + sub + " in apps-demo", "create", "pods", sub, "apps-demo", false})
	}
	for _, r := range []string{"pods", "services"} {
		checks = append(checks, check{"get " + r + "/proxy in apps-demo", "get", r, "proxy", "apps-demo", false})
	}
	checks = append(checks,
		check{"get pods/log in apps-demo", "get", "pods", "log", "apps-demo", false},
		check{"get nodes/proxy", "get", "nodes", "proxy", "", false},
		check{"create serviceaccounts/token for default in mesh-view-system", "create", "serviceaccounts/default", "token", "mesh-view-system", false},
		check{"create serviceaccounts/token for mesh-view in mesh-view-system", "create", "serviceaccounts/mesh-view", "token", "mesh-view-system", true},
	)
	for _, verb := range []string{"create", "update", "patch", "delete"} {
		checks = append(checks, check{verb + " deployments in apps-demo", verb, "deployments.apps", "", "apps-demo", false})
	}
	for _, r := range []string{"users", "groups", "serviceaccounts"} {
		checks = append(checks, check{"impersonate " + r, "impersonate", r, "", "", false})
	}
	for _, r := range []string{"roles", "clusterroles"} {
		for _, verb := range []string{"escalate", "bind"} {
			checks = append(checks, check{verb + " " + r, verb, r + ".rbac.authorization.k8s.io", "", "", false})
		}
	}
	for _, r := range []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"} {
		for _, verb := range []string{"create", "update", "patch", "delete"} {
			checks = append(checks, check{verb + " " + r, verb, r + ".admissionregistration.k8s.io", "", "", false})
		}
	}
	for _, cell := range meshCells(t) {
		for _, c := range checks {
			t.Run(cell+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				args := []string{"auth", "can-i", c.verb, c.resource, "--as=" + account}
				if c.sub != "" {
					args = append(args, "--subresource="+c.sub)
				}
				if c.ns != "" {
					args = append(args, "-n", c.ns)
				}
				out, _ := kubectl(t, cell, "", args...)
				if got := strings.TrimSpace(out); got != map[bool]string{true: "yes", false: "no"}[c.want] {
					t.Errorf("can-i %s: %q, want %v", strings.Join(args[2:], " "), got, c.want)
				}
			})
		}
	}
}
