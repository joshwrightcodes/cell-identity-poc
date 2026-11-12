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

// TestM3NoWorkloadCanPortForward checks, through can-i, that no ServiceAccount of the plane
// namespaces may create pods/portforward in any namespace of management. The viewer Role of the
// Kiali chart grants it, and the render deletes that rule.
func TestM3NoWorkloadCanPortForward(t *testing.T) {
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
			if canI(t, mgmtCluster, as, "create", "pods/portforward", "") {
				t.Errorf("%s can create pods/portforward in a namespace", as)
			}
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

// tunnelState returns, for a cell, the msg of the last tunnel_up or tunnel_down line in a hub log,
// and the number of tunnel_up lines.
func tunnelState(log, cell string) (last string, ups int) {
	for l := range strings.SplitSeq(log, "\n") {
		var rec struct{ Msg, Cell string }
		if json.Unmarshal([]byte(l), &rec) != nil || rec.Cell != cell {
			continue
		}
		switch rec.Msg {
		case "tunnel_up":
			last = rec.Msg
			ups++
		case "tunnel_down":
			last = rec.Msg
		}
	}
	return last, ups
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

// TestM3KeepaliveBlackhole drops the packets between the relay of dev-cp and the hub without closing
// a connection, as a dead path does. The hub and the tunnel must find the dead connection by their own
// pings, and the tunnel must be up again when the path returns. The rule on the dev-cp node goes away
// when the test ends.
func TestM3KeepaliveBlackhole(t *testing.T) {
	cell := meshCells(t)[0]
	mgmtIP := clusterFacts(t, mgmtCluster).NodeIP
	if net.ParseIP(mgmtIP) == nil {
		t.Fatalf("management node address %q", mgmtIP)
	}
	node := envCluster + "-control-plane"
	rule := []string{"FORWARD", "-p", "tcp", "-d", mgmtIP, "--dport", strconv.Itoa(meshNodePort), "-j", "DROP"}
	last, before := tunnelState(hubLog(t), cell)
	if last != "tunnel_up" {
		t.Fatalf("the hub tunnel of %s is %q before the test, want tunnel_up", cell, last)
	}
	removed := false
	remove := func() {
		if removed {
			return
		}
		removed = true
		if _, err := dockerExec(t, node, "", append([]string{"iptables", "-D"}, rule...)...); err != nil {
			t.Errorf("remove the blackhole rule from %s: %v. Run: docker exec %s iptables -D %s", node, err, node, strings.Join(rule, " "))
		}
	}
	if _, err := dockerExec(t, node, "", append([]string{"iptables", "-I"}, rule...)...); err != nil {
		t.Fatalf("insert the blackhole rule in %s: %v", node, err)
	}
	t.Cleanup(remove)
	start := time.Now()
	// The hub pings after 30 seconds of silence and waits 15 seconds for the answer.
	waitFor(t, "the hub to find the dead tunnel of "+cell, 90*time.Second, func() (bool, string) {
		last, _ := tunnelState(hubLog(t), cell)
		return last == "tunnel_down", fmt.Sprintf("last tunnel line %q", last)
	})
	t.Logf("the hub found the dead tunnel of %s after %s", cell, time.Since(start).Round(time.Second))
	cellPod, _ := readyPodIn(t, cell, meshNamespace, tunnelName)
	waitFor(t, "the tunnel pod of "+cell+" to log the end of the tunnel", 90*time.Second, func() (bool, string) {
		out, err := kubectl(t, cell, "", "-n", meshNamespace, "logs", cellPod, "-c", "cell-proxy")
		if err != nil {
			return false, err.Error()
		}
		return strings.Contains(out, `"msg":"tunnel_closed"`), "no tunnel_closed line yet"
	})
	remove()
	waitHubTunnel(t, cell, before, 3*time.Minute)
	t.Logf("the tunnel of %s was up again %s after the start", cell, time.Since(start).Round(time.Second))
}

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
		for _, tc := range []struct{ name, method, path, body string }{
			{"delete pod echo", "DELETE", "/api/namespaces/apps-demo/pods/" + echo + "?clusterName=" + cell, ""},
			{"patch AuthorizationPolicy", "PATCH", "/api/namespaces/apps-demo/istio/security.istio.io/v1/AuthorizationPolicy/echo-allow-client?clusterName=" + cell,
				`[{"op":"replace","path":"/spec/action","value":"DENY"}]`},
			{"delete AuthorizationPolicy", "DELETE", "/api/namespaces/apps-demo/istio/security.istio.io/v1/AuthorizationPolicy/echo-allow-client?clusterName=" + cell, ""},
		} {
			code, body, err := kialiCall(tc.method, addr, tc.path, tc.body)
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			} else if code < 400 {
				t.Errorf("%s answers %d %.200s, want a failure", tc.name, code, body)
			} else {
				t.Logf("%s answers %d %.120s", tc.name, code, body)
			}
		}
		if got := resourceVersion(t, cell, "apps-demo", "pod", echo); got != podRV {
			t.Errorf("pod %s has the resourceVersion %s, was %s", echo, got, podRV)
		}
		if got := resourceVersion(t, cell, "apps-demo", "authorizationpolicy.security.istio.io", "echo-allow-client"); got != policyRV {
			t.Errorf("AuthorizationPolicy echo-allow-client has the resourceVersion %s, was %s", got, policyRV)
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

// TestM3TunnelRecovers deletes the relay-view pod in dev-cp, which ends the tunnel of each cell. Kiali
// lists dev-cell-1 again within 2 minutes, and its pod neither restarts nor changes.
func TestM3TunnelRecovers(t *testing.T) {
	addr := kialiForward(t)
	waitFor(t, "Kiali to list both cells", 3*time.Minute, func() (bool, string) { return kialiSeesCells(addr) })
	uid, restarts := kialiPodState(t)
	log := hubLog(t)
	_, before := tunnelState(log, "dev-cell-1")
	downsBefore := tunnelDowns(log, "dev-cell-1")
	if _, err := kubectl(t, envCluster, "", "-n", relayNamespace, "delete", "pod", "-l", "app.kubernetes.io/name=relay-view", "--wait=true"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	t.Logf("deleted the relay-view pod at %s", start.UTC().Format(time.RFC3339))
	waitFor(t, "Kiali to list both cells again", 2*time.Minute, func() (bool, string) { return kialiSeesCells(addr) })
	t.Logf("Kiali listed both cells again %s after the delete", time.Since(start).Round(time.Second))
	waitHubTunnel(t, "dev-cell-1", before, 2*time.Minute)
	if got := tunnelDowns(hubLog(t), "dev-cell-1"); got <= downsBefore {
		t.Errorf("the hub logged %d tunnel_down lines for dev-cell-1 after the delete of the relay pod, and %d before: the tunnel never went down", got, downsBefore)
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
