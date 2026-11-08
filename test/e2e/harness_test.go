//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

var residualPorts = []int{2379, 2380, 6443, 10250, 10256}

var alwaysOpenPorts = []int{6443, 10250}

const nodePortServer = 30090

func TestM1RogueReachesOnlyResidualPorts(t *testing.T) {
	createNamespace(t, "rogue", "m1-scan")
	for _, target := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
		t.Run(target, func(t *testing.T) {
			ip := clusterFacts(t, target).NodeIP
			out := runPod(t, "rogue", "m1-scan", []string{"scan", "--host", ip, "--ports", "1-65535",
				"--timeout", "300ms", "--concurrency", "256"})
			var open []int
			if err := json.Unmarshal([]byte(out), &open); err != nil {
				t.Fatalf("decode scan output %q: %v", out, err)
			}
			t.Logf("open ports on %s (%s): %v", target, ip, open)
			for _, p := range alwaysOpenPorts {
				if !slices.Contains(open, p) {
					t.Fatalf("cluster %s: the scan did not work, because port %d is always open on a node but is missing from the result %v",
						target, p, open)
				}
			}
			var extra []string
			for _, p := range open {
				if !slices.Contains(residualPorts, p) {
					extra = append(extra, fmt.Sprint(p))
				}
			}
			if len(extra) > 0 {
				t.Errorf("cluster %s: rogue reaches extra ports %s beyond the residual set %v",
					target, strings.Join(extra, ", "), residualPorts)
			}
		})
	}
}

const serverManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: probe-server
  labels: {app: probe-server}
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile: {type: RuntimeDefault}
  containers:
  - name: server
    image: localhost:5001/netprobe:latest
    args: ["serve", "--addr", ":8080"]
    ports: [{containerPort: 8080}]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities: {drop: [ALL]}
---
apiVersion: v1
kind: Service
metadata:
  name: probe-server
spec:
  type: NodePort
  externalTrafficPolicy: Local
  selector: {app: probe-server}
  ports:
  - port: 8080
    targetPort: 8080
    nodePort: 30090
`

// TestM1NodePortAcrossClusters starts the NodePort server in dev-cp, fetches it once from
// dev-cell-1, and checks the reply in two named subtests.
func TestM1NodePortAcrossClusters(t *testing.T) {
	createNamespace(t, "dev-cp", "m1-server")
	createNamespace(t, "dev-cell-1", "m1-client")
	if _, err := kubectl(t, "dev-cp", serverManifest, "-n", "m1-server", "apply", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if _, err := kubectl(t, "dev-cp", "", "-n", "m1-server", "wait", "--for=condition=Ready",
		"pod/probe-server", "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
	server := clusterFacts(t, "dev-cp")
	client := clusterFacts(t, "dev-cell-1")
	url := fmt.Sprintf("http://%s:%d/", server.NodeIP, nodePortServer)
	body := runPod(t, "dev-cell-1", "m1-client", []string{"get", "--url", url})

	var got struct {
		Remote string `json:"remote"`
	}
	t.Run("Reachable", func(t *testing.T) {
		if err := json.Unmarshal([]byte(body), &got); err != nil || got.Remote == "" {
			t.Fatalf("unexpected body %q: %v", body, err)
		}
	})
	t.Run("TestM1SourceIsOwnNode", func(t *testing.T) {
		host, _, err := net.SplitHostPort(got.Remote)
		if err != nil {
			t.Fatalf("remote %q: %v", got.Remote, err)
		}
		if host != client.NodeIP {
			t.Fatalf("server saw source %s, want the dev-cell-1 node IP %s", host, client.NodeIP)
		}
		t.Logf("server saw source %s, the dev-cell-1 node IP", host)
	})
}

func TestM1PodsReachHostService(t *testing.T) {
	const want = "hello from the Mac"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(want))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	createNamespace(t, "dev-cell-1", "m1-host")
	got := runPod(t, "dev-cell-1", "m1-host", []string{"get", "--url", fmt.Sprintf("http://host.docker.internal:%d/", port)})
	if strings.TrimSpace(got) != want {
		t.Fatalf("body %q, want %q", got, want)
	}
}

func TestM1MirrorOnEveryCluster(t *testing.T) {
	topo, err := topology.Load(topologyPath)
	if err != nil {
		t.Fatalf("load topology: %v", err)
	}
	for _, c := range topo.Clusters {
		t.Run(c.Name, func(t *testing.T) {
			createNamespace(t, c.Name, "m1-mirror")
			err := startPod(t, c.Name, "m1-mirror", []string{"serve", "--addr", ":8080"})
			if err != nil {
				t.Fatalf("cluster %s: a pod could not run %s through the registry mirror: %v", c.Name, probeImage, err)
			}
		})
	}
}
