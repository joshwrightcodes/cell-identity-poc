//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	agentNamespace  = "argocd"
	agentDeployment = "argocd-agent"
	relayNamespace  = "relay-system"
	relayViewPort   = 30443
	relayTelPort    = 30444
	impostorPort    = 30092
	// agentWait bounds every wait for an agent stream.
	agentWait = 2 * time.Minute
)

var cellProxyImage = readImage("IMAGE_CELL_PROXY")
var relayImage = readImage("IMAGE_RELAY")

func agentName(cell string) string { return pocEnv + "-" + cell }

// agentPod returns the name of the Ready agent pod of a cell.
func agentPod(t *testing.T, cell string) string {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", agentNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+agentDeployment, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var pods struct {
		Items []struct {
			Metadata struct{ Name string } `json:"metadata"`
			Status   struct {
				Conditions []struct{ Type, Status string } `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &pods); err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		for _, c := range p.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				return p.Metadata.Name
			}
		}
	}
	t.Fatalf("no Ready agent pod in %s/%s", cell, agentNamespace)
	return ""
}

// waitAgentsConnected waits until the principal lists the agent of every view cell with a stream
// that opened at or after since.
func waitAgentsConnected(t *testing.T, since time.Time) {
	t.Helper()
	for _, cell := range viewCells(t) {
		waitFor(t, "the principal lists "+agentName(cell)+" as connected", agentWait, func() (bool, string) {
			return viewConnectedSince(t, agentName(cell), since)
		})
	}
}

// cellApplication is the name and the status of one Application.
type cellApplication struct {
	Name, Sync, Health string
}

func decodeApplications(t *testing.T, data []byte) []cellApplication {
	t.Helper()
	var list struct {
		Items []struct {
			Metadata struct{ Name, Namespace string } `json:"metadata"`
			Status   struct {
				Sync   struct{ Status string } `json:"sync"`
				Health struct{ Status string } `json:"health"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("decode Applications: %v", err)
	}
	var out []cellApplication
	for _, i := range list.Items {
		out = append(out, cellApplication{i.Metadata.Name, i.Status.Sync.Status, i.Status.Health.Status})
	}
	slices.SortFunc(out, func(a, b cellApplication) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// TestM3BothCellsInCentralView lists the Applications of each agent namespace through the central
// API. Each cell has one Application there per child Application, with the status of the cell. The
// managed resources of apps-demo hold the live Deployment echo of that cell.
func TestM3BothCellsInCentralView(t *testing.T) {
	for _, cell := range viewCells(t) {
		t.Run(cell, func(t *testing.T) {
			requireViewConnected(t, agentName(cell))
			out, err := kubectl(t, cell, "", "-n", appsNamespace, "get", "applications.argoproj.io", "-o", "json")
			if err != nil {
				t.Fatal(err)
			}
			want := decodeApplications(t, []byte(out))
			if len(want) == 0 {
				t.Fatalf("%s holds no child Application in %s", cell, appsNamespace)
			}
			waitFor(t, "the central view of "+cell+" matches the cell", agentWait, func() (bool, string) {
				got := decodeApplications(t, centralAPI(t, "/api/v1/applications?appNamespace="+agentName(cell)))
				return slices.Equal(got, want), fmt.Sprintf("central %v, cell %v", got, want)
			})
			uid, err := kubectl(t, cell, "", "-n", "apps-demo", "get", "deployment", "echo", "-o", "jsonpath={.metadata.uid}")
			if err != nil || strings.TrimSpace(uid) == "" {
				t.Fatalf("no Deployment apps-demo/echo in %s: %v", cell, err)
			}
			var res struct {
				Items []struct {
					Kind, Name, Namespace, LiveState string
				} `json:"items"`
			}
			data := centralAPI(t, "/api/v1/applications/apps-demo/managed-resources?appNamespace="+agentName(cell))
			if err := json.Unmarshal(data, &res); err != nil {
				t.Fatalf("decode managed resources: %v", err)
			}
			for _, item := range res.Items {
				if item.Kind != "Deployment" || item.Name != "echo" {
					continue
				}
				var live struct {
					Metadata struct{ UID string } `json:"metadata"`
				}
				if err := json.Unmarshal([]byte(item.LiveState), &live); err != nil {
					t.Fatalf("the live state of echo is no JSON object: %q", item.LiveState)
				}
				if live.Metadata.UID != strings.TrimSpace(uid) {
					t.Fatalf("the view shows echo with uid %q, and %s has %q", live.Metadata.UID, cell, uid)
				}
				t.Logf("%s: the view shows Deployment echo with the uid %s of the cell", cell, live.Metadata.UID)
				return
			}
			t.Fatalf("the managed resources of apps-demo in %s hold no Deployment echo: %s", agentName(cell), data)
		})
	}
}

// TestM3AgentAuthenticatedAsOwnCell checks that the principal authenticated each agent by its own
// name, and that cell-proxy accepted the stream of that agent with the SVID of its cell.
func TestM3AgentAuthenticatedAsOwnCell(t *testing.T) {
	pod, _, _ := principalPod(t)
	principalLog, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "logs", pod, "-c", principalName)
	if err != nil {
		t.Fatal(err)
	}
	proxyLog, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "logs", pod, "-c", viewCellProxy)
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range viewCells(t) {
		requireViewConnected(t, agentName(cell))
		authenticated, accepted := false, false
		for l := range strings.SplitSeq(principalLog, "\n") {
			var rec struct{ Msg, Client, Authmethod string }
			if json.Unmarshal([]byte(l), &rec) == nil && rec.Msg == "client authentication successful" && rec.Client == agentName(cell) {
				authenticated = rec.Authmethod == "header"
			}
		}
		id := "spiffe://" + envTrustDomain + "/cell/" + cell + "/argocd-agent"
		for l := range strings.SplitSeq(proxyLog, "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(l), &rec) == nil && rec["msg"] == "peer accepted" && rec["spiffe_id"] == id {
				accepted = true
			}
		}
		if !authenticated {
			t.Errorf("the principal log names no header authentication of %s", agentName(cell))
		}
		if !accepted {
			t.Errorf("the cell-proxy log names no accepted peer %s", id)
		}
	}
}

// forwarderAddr runs the relay binary in a fresh namespace of dev-cell-1 as a TCP forwarder to the
// view node port of dev-cp, and returns a local port-forward to it. Traffic to the relay of dev-cp
// leaves from the dev-cell-1 node, as the agent traffic does.
func forwarderAddr(t *testing.T) string {
	t.Helper()
	if relayImage == "" {
		t.Fatal("build/images.env has no IMAGE_RELAY. Run mise run images")
	}
	cell := "dev-cell-1"
	ns := freshNamespace(t, cell)
	envIP := clusterFacts(t, envCluster).NodeIP
	pod := testPod("forwarder", relayImage, []string{"--route", fmt.Sprintf("8443=%s:%d", envIP, relayViewPort), "--health", ":8080"}, nil, nil)
	applyPod(t, cell, ns, pod)
	waitPodReady(t, cell, ns, "forwarder")
	return portForward(t, cell, ns, "pod/forwarder", 8443)
}

// testPod returns a Pod for Pod Security restricted, as user 65532 with no token.
func testPod(name, image string, args []string, volumes, mounts []map[string]any) map[string]any {
	ctr := map[string]any{"name": name, "image": image, "args": args,
		"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}}
	if mounts != nil {
		ctr["volumeMounts"] = mounts
	}
	spec := map[string]any{"restartPolicy": "Never", "automountServiceAccountToken": false,
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"containers":      []any{ctr}}
	if volumes != nil {
		spec["volumes"] = volumes
	}
	return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "labels": map[string]any{"app": name}}, "spec": spec}
}

func applyPod(t *testing.T, cluster, ns string, pod map[string]any) {
	t.Helper()
	b, _ := json.Marshal(pod)
	if _, err := kubectl(t, cluster, string(b), "-n", ns, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
}

func waitPodReady(t *testing.T, cluster, ns, name string) {
	t.Helper()
	if _, err := kubectl(t, cluster, "", "-n", ns, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=180s"); err != nil {
		desc, _ := kubectl(t, cluster, "", "-n", ns, "describe", "pod", name)
		t.Fatalf("pod %s/%s in %s is not Ready: %v\n%s", ns, name, cluster, err, desc)
	}
}

// podDone waits until a pod ends, and returns its phase and its log.
func podDone(t *testing.T, cluster, ns, name string) (string, string) {
	t.Helper()
	var phase string
	waitFor(t, "pod "+ns+"/"+name+" ends", podTimeout, func() (bool, string) {
		out, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", name, "-o", "jsonpath={.status.phase}")
		if err != nil {
			return false, err.Error()
		}
		phase = strings.TrimSpace(out)
		return phase == "Succeeded" || phase == "Failed", "phase " + phase
	})
	logs, err := kubectl(t, cluster, "", "-n", ns, "logs", name)
	if err != nil {
		t.Fatal(err)
	}
	return phase, logs
}

// grpcConn is an HTTP/2 client for one mTLS connection to the view through the relay.
type grpcConn struct {
	cc *http2.ClientConn
}

// dialView makes one mTLS connection to addr with cert, checks that the server is the principal ID
// chained to the management roots, and opens HTTP/2 on it.
func dialView(t *testing.T, addr string, cert tls.Certificate, roots *x509.CertPool) *grpcConn {
	t.Helper()
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, r := range raw[1:] {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				inter.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				return err
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != principalID {
				return fmt.Errorf("server ID %v, want %s", leaf.URIs, principalID)
			}
			return nil
		}}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		t.Fatalf("mTLS to the view through %s: %v", addr, err)
	}
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return &grpcConn{cc: cc}
}

// call sends one unary gRPC call and returns the response message and the grpc-status.
func (g *grpcConn) call(t *testing.T, path, authorization string, msg []byte) ([]byte, string) {
	t.Helper()
	frame := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg)))
	frame = append(frame, msg...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://127.0.0.1:8443"+path, bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := g.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read: %v", path, err)
	}
	status := resp.Trailer.Get("Grpc-Status")
	if status == "" {
		status = resp.Header.Get("Grpc-Status")
	}
	if len(body) < 5 {
		return nil, status
	}
	return body[5:], status
}

// protoString appends field num as a string to b.
func protoString(b []byte, num protowire.Number, s string) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendString(b, s)
}

// authResponse reads accessToken (1) and refreshToken (2) of an AuthResponse.
func authResponse(t *testing.T, b []byte) (access, refresh string) {
	t.Helper()
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			t.Fatal("AuthResponse: bad tag")
		}
		b = b[n:]
		if typ != protowire.BytesType {
			n = protowire.ConsumeFieldValue(num, typ, b)
			b = b[n:]
			continue
		}
		v, n := protowire.ConsumeString(b)
		if n < 0 {
			t.Fatal("AuthResponse: bad string")
		}
		b = b[n:]
		switch num {
		case 1:
			access = v
		case 2:
			refresh = v
		}
	}
	return access, refresh
}

// principalAgentVersion returns the agent version that the principal accepted last, from its log.
func principalAgentVersion(t *testing.T) string {
	t.Helper()
	pod, _, _ := principalPod(t)
	logs, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "logs", pod, "-c", principalName)
	if err != nil {
		t.Fatal(err)
	}
	version := ""
	for l := range strings.SplitSeq(logs, "\n") {
		var rec struct {
			Msg          string
			AgentVersion string `json:"agent_version"`
		}
		if json.Unmarshal([]byte(l), &rec) == nil && rec.Msg == "client authentication successful" && rec.AgentVersion != "" {
			version = rec.AgentVersion
		}
	}
	if version == "" {
		t.Fatal("the principal log names no accepted agent version")
	}
	return version
}

// TestM3TokenReplayAcrossCells gets the tokens of dev-cell-1 with its SVID, and then uses them with
// the SVID of dev-cell-2. cell-proxy refuses both calls with subject_mismatch.
func TestM3TokenReplayAcrossCells(t *testing.T) {
	roots := x509.NewCertPool()
	for _, c := range bundleRoots(t, mgmtCluster) {
		roots.AddCert(c)
	}
	svid := func(cell string) tls.Certificate {
		certPEM, keyPEM := mintSVID(t, envCluster, "spiffe://"+envTrustDomain+"/cell/"+cell+"/argocd-agent", 10*time.Minute)
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	version := principalAgentVersion(t)
	addr := forwarderAddr(t)
	pod, _, _ := principalPod(t)
	since := time.Now().Add(-2 * time.Second)
	t.Cleanup(func() {
		// The Authenticate call of the test displaces the real session of dev-cell-1.
		waitAgentsConnected(t, time.Time{})
		for _, cell := range viewCells(t) {
			requireViewConnected(t, agentName(cell))
		}
	})

	var req []byte
	req = protoString(req, 1, "header")
	req = protoString(req, 3, "autonomous")
	req = protoString(req, 4, version)
	req = protoString(req, 5, appsNamespace)
	one := dialView(t, addr, svid("dev-cell-1"), roots)
	resp, status := one.call(t, "/authapi.Authentication/Authenticate", "", req)
	if status != "0" {
		t.Fatalf("Authenticate as dev-cell-1: grpc-status %q, want 0", status)
	}
	access, refresh := authResponse(t, resp)
	if strings.Count(access, ".") != 2 || strings.Count(refresh, ".") != 2 {
		t.Fatal("Authenticate returned no access token and refresh token")
	}
	t.Log("Authenticate as dev-cell-1 returned an access token and a refresh token; they stay in memory")

	two := dialView(t, addr, svid("dev-cell-2"), roots)
	if _, status := two.call(t, "/versionapi.Version/Version", access, nil); status == "0" {
		t.Error("Version with the access token of dev-cell-1 over the SVID of dev-cell-2 succeeded")
	} else {
		t.Logf("Version with the token of dev-cell-1 over dev-cell-2: grpc-status %s", status)
	}
	var refreshReq []byte
	refreshReq = protoString(refreshReq, 1, refresh)
	if _, status := two.call(t, "/authapi.Authentication/RefreshToken", "", refreshReq); status == "0" {
		t.Error("RefreshToken with the refresh token of dev-cell-1 over the SVID of dev-cell-2 succeeded")
	} else {
		t.Logf("RefreshToken with the token of dev-cell-1 over dev-cell-2: grpc-status %s", status)
	}
	waitFor(t, "two subject_mismatch lines of cell-proxy", time.Minute, func() (bool, string) {
		logs, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "logs", pod, "-c", viewCellProxy, "--since-time="+since.UTC().Format(time.RFC3339))
		if err != nil {
			return false, err.Error()
		}
		paths := map[string]bool{}
		for l := range strings.SplitSeq(logs, "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(l), &rec) == nil && rec["reason"] == "subject_mismatch" && rec["agent"] == agentName("dev-cell-2") {
				paths[fmt.Sprint(rec["path"])] = true
			}
		}
		return paths["/versionapi.Version/Version"] && paths["/authapi.Authentication/RefreshToken"], fmt.Sprintf("refused paths %v", paths)
	})
}

// startTLSServe runs netprobe tlsserve in a fresh namespace of dev-cp with a chain and key on
// standard input, behind node port 30092. The key reaches the pod only through kubectl attach.
func startTLSServe(t *testing.T, certPEM, keyPEM []byte) {
	t.Helper()
	ns := freshNamespace(t, envCluster)
	name := "impostor"
	override := map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": name}},
		"spec": map[string]any{"automountServiceAccountToken": false,
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
			"containers": []any{map[string]any{"name": name, "image": probeImage, "args": []string{"tlsserve", "--addr", ":8443"},
				"stdin": true, "stdinOnce": true,
				"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}}}}}
	b, _ := json.Marshal(override)
	cmd := exec.Command("kubectl", "--context", "kind-"+envCluster, "-n", ns, "run", name, "--image", probeImage, "--restart=Never", "-i", "--overrides", string(b))
	cmd.Stdin = bytes.NewReader(append(append([]byte{}, certPEM...), keyPEM...))
	var out lockedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	svc := fmt.Sprintf(`{"apiVersion":"v1","kind":"Service","metadata":{"name":%q},"spec":{"type":"NodePort","selector":{"app":%q},"ports":[{"port":8443,"targetPort":8443,"nodePort":%d}]}}`, name, name, impostorPort)
	if _, err := kubectl(t, envCluster, svc, "-n", ns, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tlsserve in "+envCluster+" serves the minted SVID", podTimeout, func() (bool, string) {
		logs, _ := kubectl(t, envCluster, "", "-n", ns, "logs", name)
		return strings.Contains(logs, `"msg":"serving tls"`), "log: " + logs + " kubectl: " + out.String()
	})
}

// probeFromCell runs cell-proxy probe in a fresh namespace of dev-cell-1, with a copy of mgmt-root,
// and returns its one output line.
func probeFromCell(t *testing.T, upstream string) map[string]any {
	t.Helper()
	if cellProxyImage == "" {
		t.Fatal("build/images.env has no IMAGE_CELL_PROXY. Run mise run images")
	}
	cell := "dev-cell-1"
	ns := freshNamespace(t, cell)
	root, err := kubectl(t, cell, "", "-n", agentNamespace, "get", "configmap", "mgmt-root", "-o", "jsonpath={.data.root\\.crt}")
	if err != nil {
		t.Fatal(err)
	}
	cm, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "mgmt-root"}, "data": map[string]string{"root.crt": root}})
	if _, err := kubectl(t, cell, string(cm), "-n", ns, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	pod := testPod("probe", cellProxyImage, []string{"probe", "--upstream", upstream, "--expect-id", principalID,
		"--peer-bundle", "/run/mgmt-root/root.crt", "--peer-trust-domain", mgmtTD},
		[]map[string]any{{"name": "mgmt-root", "configMap": map[string]any{"name": "mgmt-root"}}},
		[]map[string]any{{"name": "mgmt-root", "mountPath": "/run/mgmt-root", "readOnly": true}})
	applyPod(t, cell, ns, pod)
	_, logs := podDone(t, cell, ns, "probe")
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	var res map[string]any
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &res) != nil {
		t.Fatalf("cell-proxy probe printed %q, want one JSON line", logs)
	}
	t.Logf("probe %s from %s: %s", upstream, cell, lines[0])
	return res
}

// TestM3CellSVIDCannotPoseAsPrincipal serves an SVID of a cell, and then an SVID of the management
// plane with another ID, as an impostor principal in dev-cp. cell-proxy in a cell refuses both. The
// real principal through the relay passes.
func TestM3CellSVIDCannotPoseAsPrincipal(t *testing.T) {
	needProbeImage(t)
	envIP := clusterFacts(t, envCluster).NodeIP
	impostor := net.JoinHostPort(envIP, fmt.Sprint(impostorPort))
	for _, tc := range []struct{ cluster, id, reason string }{
		{envCluster, "spiffe://" + envTrustDomain + "/cell/dev-cell-2/argocd-agent", "peer_untrusted"},
		{mgmtCluster, "spiffe://" + mgmtTD + "/telemetry", "peer_not_allowed"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			certPEM, keyPEM := mintSVID(t, tc.cluster, tc.id, 10*time.Minute)
			startTLSServe(t, certPEM, keyPEM)
			res := probeFromCell(t, impostor)
			if res["reason"] != tc.reason || res["verified"] == true {
				t.Fatalf("the probe of an impostor with %s gave %v, want the reason %s", tc.id, res, tc.reason)
			}
		})
	}
	t.Run("principal through the relay", func(t *testing.T) {
		res := probeFromCell(t, net.JoinHostPort(envIP, fmt.Sprint(relayViewPort)))
		if res["verified"] != true || res["server_id"] != principalID {
			t.Fatalf("the probe of the relay gave %v, want verified %s", res, principalID)
		}
	})
}

// TestM3AgentReconnects deletes the relay-view pod. Both agents connect again within 2 minutes.
func TestM3AgentReconnects(t *testing.T) {
	for _, cell := range viewCells(t) {
		requireViewConnected(t, agentName(cell))
	}
	since := time.Now()
	if _, err := kubectl(t, envCluster, "", "-n", relayNamespace, "delete", "pod", "-l", "app.kubernetes.io/name=relay-view", "--wait=true"); err != nil {
		t.Fatal(err)
	}
	t.Logf("deleted the relay-view pod at %s", since.UTC().Format(time.RFC3339))
	waitAgentsConnected(t, since)
}

// TestM3AgentsSurviveKeyRotation runs view:rotate-keys. Both agents connect again within 2 minutes.
func TestM3AgentsSurviveKeyRotation(t *testing.T) {
	for _, cell := range viewCells(t) {
		requireViewConnected(t, agentName(cell))
	}
	since := time.Now()
	cmd := exec.Command("mise", "run", "view:rotate-keys")
	cmd.Dir = "../.."
	var stderr lockedBuffer
	cmd.Stderr = &stderr
	if _, err := cmd.Output(); err != nil {
		t.Fatalf("view:rotate-keys: %v\n%s", err, stderr.String())
	}
	waitAgentsConnected(t, since)
}

// processListenAddrs returns the local addresses of the TCP listeners of the main process of one
// container. The containers of a pod share one network namespace, so ss names the process of each.
func processListenAddrs(t *testing.T, cluster, ns, pod, container string) []string {
	t.Helper()
	jsonpath := fmt.Sprintf(`jsonpath={.status.containerStatuses[?(@.name=="%s")].containerID}`, container)
	id, err := kubectl(t, cluster, "", "-n", ns, "get", "pod", pod, "-o", jsonpath)
	if err != nil {
		t.Fatal(err)
	}
	id = strings.TrimPrefix(strings.TrimSpace(id), "containerd://")
	node := cluster + "-control-plane"
	pid, err := dockerExec(t, node, "", "crictl", "inspect", "--output", "go-template", "--template", "{{.info.pid}}", id)
	if err != nil {
		t.Fatal(err)
	}
	pid = strings.TrimSpace(pid)
	out, err := dockerExec(t, node, "", "nsenter", "-t", pid, "-n", "ss", "-ltnpH")
	if err != nil {
		t.Fatal(err)
	}
	var addrs, all []string
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		all = append(all, line)
		if strings.Contains(line, "pid="+pid+",") {
			addrs = append(addrs, fields[3])
		}
	}
	t.Logf("%s/%s in %s: process %s of %s listens on %v; the pod listens on:\n%s", ns, pod, cluster, pid, container, addrs, strings.Join(all, "\n"))
	return addrs
}

// TestM3AgentClientBinds checks that the cell-proxy process of each agent pod listens only on
// 127.0.0.1:8443.
func TestM3AgentClientBinds(t *testing.T) {
	for _, cell := range viewCells(t) {
		t.Run(cell, func(t *testing.T) {
			addrs := processListenAddrs(t, cell, agentNamespace, agentPod(t, cell), "cell-proxy")
			if !slices.Equal(addrs, []string{"127.0.0.1:8443"}) {
				t.Errorf("cell-proxy listens on %v, want only 127.0.0.1:8443", addrs)
			}
		})
	}
}

// TestM3RelayNodePortAdmission dials the relay node ports of dev-cp. A pod in each cell connects. A
// pod in rogue and one in management time out.
func TestM3RelayNodePortAdmission(t *testing.T) {
	needProbeImage(t)
	envIP := clusterFacts(t, envCluster).NodeIP
	for _, cell := range viewCells(t) {
		t.Run(cell, func(t *testing.T) {
			ns := freshNamespace(t, cell)
			for _, port := range []int{relayViewPort, relayTelPort} {
				if got := dialFrom(t, cell, ns, envIP, port, 3*time.Second); got != "connected" {
					t.Errorf("dial from %s to %s:%d gave %q, want connected", cell, envIP, port, got)
				}
			}
		})
	}
	for _, cluster := range []string{"rogue", mgmtCluster} {
		t.Run(cluster, func(t *testing.T) {
			for _, port := range []int{relayViewPort, relayTelPort} {
				if err := probeFromFreshNamespace(t, cluster, envIP, port, 3*time.Second); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// TestM3AppsProjectGuard checks, in each cluster with Argo CD, that the admission policy denies an
// Application in argocd other than the root, and an Application in argocd-apps with another project
// than cell. A dry run of an allowed Application passes.
func TestM3AppsProjectGuard(t *testing.T) {
	app := func(ns, name, project string) string {
		return fmt.Sprintf(`{"apiVersion":"argoproj.io/v1alpha1","kind":"Application","metadata":{"name":%q,"namespace":%q},
"spec":{"project":%q,"source":{"repoURL":"oci://bundle-store.cell-system.svc.cluster.local:5000/bundles/none","targetRevision":"current","path":"."},
"destination":{"server":"https://kubernetes.default.svc","namespace":"default"}}}`, name, ns, project)
	}
	for _, cluster := range clustersWith(t, "base-cell") {
		t.Run(cluster, func(t *testing.T) {
			for _, tc := range []struct {
				ns, name, project, want string
			}{
				{appsNamespace, "m3-guard-probe", "default", "uses the project cell"},
				{"argocd", "m3-guard-probe", "cell", "holds only the root Application"},
				{appsNamespace, "m3-guard-probe", "cell", ""},
			} {
				_, err := kubectl(t, cluster, app(tc.ns, tc.name, tc.project), "create", "--dry-run=server", "-f", "-")
				switch {
				case tc.want == "" && err != nil:
					t.Errorf("%s/%s with project %s: %v, want admission", tc.ns, tc.name, tc.project, err)
				case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
					t.Errorf("%s/%s with project %s: %v, want a denial that says %q", tc.ns, tc.name, tc.project, err, tc.want)
				}
			}
		})
	}
}
