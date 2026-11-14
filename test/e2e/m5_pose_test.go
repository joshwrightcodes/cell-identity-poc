//go:build e2e

package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
)

// poseStream describes one stream into a cell-proxy server of management: how to reach it, which pod and container log its
// refusals, and how a client that the server admitted shows it.
type poseStream struct {
	name, role string
	// addr opens a port-forward to the server and returns its address.
	addr func(t *testing.T) string
	// pod returns the name of the server pod, and container the cell-proxy container in it.
	pod       func(t *testing.T) string
	namespace string
	// accepted reports whether the server took the connection after the proof frame: nil when it did.
	accepted func(conn *tls.Conn) error
}

// h2Answers writes the HTTP/2 client preface and an empty SETTINGS frame, and reads one frame header. The backend of the
// view and of the telemetry gateway is an HTTP/2 server, so it answers once the proof passed.
func h2Answers(conn *tls.Conn) error {
	if _, err := conn.Write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0)); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadFull(conn, make([]byte, 9))
	return err
}

// hubTakes reads the HTTP/2 client preface that the tunnel hub writes as soon as it takes the connection as the tunnel of the
// cell. The hub is the HTTP/2 client of the tunnel.
func hubTakes(conn *tls.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len("PRI * HTTP/2.0"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "PRI * HTTP/2.0" {
		return fmt.Errorf("the hub wrote %q, want the HTTP/2 preface", buf)
	}
	return nil
}

var poseStreams = []poseStream{
	{name: "view", role: "argocd-agent", namespace: viewNamespace, accepted: h2Answers,
		addr: func(t *testing.T) string {
			return portForward(t, mgmtCluster, viewNamespace, "svc/"+viewListener, 8444)
		},
		pod: func(t *testing.T) string { n, _, _ := principalPod(t); return n }},
	{name: "telemetry", role: "otel", namespace: obsNamespace, accepted: h2Answers,
		addr: func(t *testing.T) string { return portForward(t, mgmtCluster, obsNamespace, gatewayService, 8444) },
		pod:  func(t *testing.T) string { n, _ := readyPod(t, obsNamespace, gatewayName); return n }},
	{name: "mesh_view", role: "mesh-view", namespace: meshNamespace, accepted: hubTakes,
		addr: func(t *testing.T) string {
			return portForward(t, mgmtCluster, meshNamespace, "svc/mesh-view-listener", 8444)
		},
		pod: func(t *testing.T) string { n, _ := readyPod(t, meshNamespace, hubName); return n }},
}

// cellSVID mints the SVID of the role of a cell in dev-cp. dev-cp holds the signing key of the environment trust domain, so
// it can make the ID of any cell: the SVID alone proves nothing about the pod.
func cellSVID(t *testing.T, cell, role string) tls.Certificate {
	t.Helper()
	return senderCert(t, "spiffe://"+envTrustDomain+"/cell/"+cell+"/"+role)
}

// refusalSeen waits until the log of the server holds a "proof refused" line with the reason for the ID, since a time.
func refusalSeen(t *testing.T, s poseStream, reason, id string, since time.Time) {
	t.Helper()
	pod := s.pod(t)
	waitFor(t, "a proof refused line with "+reason+" for "+id, 2*time.Minute, func() (bool, string) {
		logs, err := kubectl(t, mgmtCluster, "", "-n", s.namespace, "logs", pod, "-c", "cell-proxy", "--since-time="+since.UTC().Format(time.RFC3339))
		if err != nil {
			return false, err.Error()
		}
		var seen []string
		for l := range strings.SplitSeq(logs, "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(l), &rec) != nil || rec["msg"] != "proof refused" {
				continue
			}
			seen = append(seen, fmt.Sprintf("%v for %v", rec["reason"], rec["spiffe_id"]))
			if rec["reason"] == reason && rec["spiffe_id"] == id {
				return true, ""
			}
		}
		return false, fmt.Sprintf("proof refused lines: %v", seen)
	})
}

// rogueStreamProof makes the proofToken of a client in the cluster rogue. It makes the namespace, the ServiceAccount and a
// holder Pod of the real client of the role there, and gives each connection a token for the audience of the posed cell. The
// key of rogue is not one that the cell publishes.
func rogueStreamProof(t *testing.T, cell, role string) func(binding string) string {
	t.Helper()
	needProbeImage(t)
	a := streamAccount[role]
	createNamespace(t, "rogue", a.ns)
	if _, err := kubectl(t, "rogue", "", "-n", a.ns, "create", "serviceaccount", a.account); err != nil {
		t.Fatal(err)
	}
	holder := fmt.Sprintf(`{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "token-holder", "namespace": %q},
  "spec": {"serviceAccountName": %q, "automountServiceAccountToken": false,
    "securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [{"name": "holder", "image": %q, "args": ["serve", "--addr", ":8080"],
      "securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}}}]}}`, a.ns, a.account, probeImage)
	if _, err := kubectl(t, "rogue", holder, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	uid, err := kubectl(t, "rogue", "", "-n", a.ns, "get", "pod", "token-holder", "-o", "jsonpath={.metadata.uid}")
	if err != nil || strings.TrimSpace(uid) == "" {
		t.Fatalf("UID of the token holder pod in rogue: %q, %v", uid, err)
	}
	return func(binding string) string {
		tok, err := kubectl(t, "rogue", "", "-n", a.ns, "create", "token", a.account, "--audience", proof.StreamAudience(cell, role, binding),
			"--duration", "10m", "--bound-object-kind", "Pod", "--bound-object-name", "token-holder", "--bound-object-uid", strings.TrimSpace(uid))
		if err != nil {
			t.Fatalf("TokenRequest in rogue: %v", err)
		}
		return strings.TrimSpace(tok)
	}
}

// requireRefused fails unless the server closed the connection and gave no answer.
func requireRefused(t *testing.T, s poseStream, conn *tls.Conn) {
	t.Helper()
	if err := s.accepted(conn); err == nil {
		t.Fatalf("the %s server answered a client with no valid proof", s.name)
	} else {
		t.Logf("refused: %v", err)
	}
}

// TestM5DevCPCannotPoseOnStreams: dev-cp makes the SVID of a cell, so the SVID of a cell proves nothing. Each cell-proxy
// server of management also needs the proof of the pod: a token of the real client pod in the cell, for the audience
// mgmt-stream/<cell>/<role>/<binding of this TLS session>. A client with no proof, a proof that a rogue cluster signed,
// and a proof that the real pod made for another session are each refused, and the log of the server names the reason.
// The control, with the real proof, is answered. The cells and the reasons differ between the cases, because the server
// writes one refusal line for each reason and ID in 10 seconds.
func TestM5DevCPCannotPoseOnStreams(t *testing.T) {
	for _, s := range poseStreams {
		t.Run(s.name, func(t *testing.T) {
			addr := s.addr(t)
			id := func(cell string) string { return "spiffe://" + envTrustDomain + "/cell/" + cell + "/" + s.role }
			t.Run("no_proof", func(t *testing.T) {
				since := time.Now().Add(-2 * time.Second)
				conn := dialAsCell(t, addr, "dev-cell-1", s.role, cellSVID(t, "dev-cell-1", s.role), func(string) string { return "" })
				requireRefused(t, s, conn)
				refusalSeen(t, s, "proof_missing", id("dev-cell-1"), since)
			})
			t.Run("rogue_proof", func(t *testing.T) {
				since := time.Now().Add(-2 * time.Second)
				conn := dialAsCell(t, addr, "dev-cell-1", s.role, cellSVID(t, "dev-cell-1", s.role), rogueStreamProof(t, "dev-cell-1", s.role))
				requireRefused(t, s, conn)
				refusalSeen(t, s, "proof_invalid", id("dev-cell-1"), since)
			})
			t.Run("replayed_proof", func(t *testing.T) {
				// The real pod of dev-cell-2 makes a token for the session of a first connection. A second connection sends
				// it. The audience names the first session, so the server refuses it.
				cell := "dev-cell-2"
				first, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, streamClientConfig(t, s.role, cellSVID(t, cell, s.role)))
				if err != nil {
					t.Fatal(err)
				}
				binding, err := proof.Binding(first.ConnectionState())
				_ = first.Close()
				if err != nil {
					t.Fatal(err)
				}
				captured := streamProof(t, cell, s.role)(binding)
				since := time.Now().Add(-2 * time.Second)
				conn := dialAsCell(t, addr, cell, s.role, cellSVID(t, cell, s.role), func(string) string { return captured })
				requireRefused(t, s, conn)
				refusalSeen(t, s, "proof_invalid", id(cell), since)
			})
			t.Run("control", func(t *testing.T) {
				cell := "dev-cell-1"
				if s.name == "mesh_view" {
					// The hub keeps the newest connection of a cell as its tunnel, so the control replaces the real
					// tunnel. The cell dials again, and the cleanup waits for it.
					_, before := tunnelState(hubLog(t), cell)
					t.Cleanup(func() { waitHubTunnel(t, cell, before+1, 3*time.Minute) })
				}
				conn := dialAsCell(t, addr, cell, s.role, cellSVID(t, cell, s.role), streamProof(t, cell, s.role))
				if err := s.accepted(conn); err != nil {
					t.Fatalf("the %s server refused the real proof: %v", s.name, err)
				}
			})
		})
	}
}

// TestM5RegistryPublishedByMgmtd: each ConfigMap cell-registry carries only the label poc.internal/made-by=mgmtd and no
// annotation, holds the records that `mgmt -- records` prints (byte for byte, as compact JSON) and the key of mgmtd in
// signers.pub, and no cell-registry in any cluster carries a harness label.
func TestM5RegistryPublishedByMgmtd(t *testing.T) {
	var served map[string]json.RawMessage
	if err := json.Unmarshal([]byte(mgmtCtl(t, "records")), &served); err != nil {
		t.Fatalf("mgmtd ctl records is no object of records: %v", err)
	}
	for _, ns := range registryNamespaces {
		t.Run(ns, func(t *testing.T) {
			cm := jsonOf(t, mgmtCluster, "-n", ns, "get", "configmap", "cell-registry")
			labels, _ := json.Marshal(field(cm, "metadata", "labels"))
			if string(labels) != `{"poc.internal/made-by":"mgmtd"}` {
				t.Errorf("cell-registry in %s has the labels %s, want only poc.internal/made-by=mgmtd", ns, labels)
			}
			if ann, ok := field(cm, "metadata", "annotations").(map[string]any); ok && len(ann) > 0 {
				t.Errorf("cell-registry in %s has the annotations %v, want none", ns, ann)
			}
			data, _ := field(cm, "data").(map[string]any)
			if got := fmt.Sprint(data["signers.pub"]); strings.TrimSpace(got) != mgmtSigningPub(t) || !strings.HasSuffix(got, "\n") {
				t.Errorf("signers.pub holds %q, want the key of mgmt-signing-pub and a newline", got)
			}
			var held []string
			for key, v := range data {
				cell, ok := strings.CutSuffix(key, ".dsse.json")
				if !ok {
					continue
				}
				held = append(held, cell)
				raw, ok := served[cell]
				if !ok {
					t.Errorf("cell-registry holds a record of %s, and mgmtd serves none", cell)
					continue
				}
				if got, want := compactJSON(t, fmt.Sprint(v)), compactJSON(t, string(raw)); got != want {
					t.Errorf("the record of %s differs from the one that mgmtd serves", cell)
				}
			}
			var want []string
			for cell := range served {
				want = append(want, cell)
			}
			slices.Sort(held)
			slices.Sort(want)
			if !slices.Equal(held, want) {
				t.Errorf("cell-registry holds the records of %v, and mgmtd serves %v", held, want)
			}
		})
	}
	for _, cluster := range []string{mgmtCluster, envCluster, "dev-cell-1", "dev-cell-2"} {
		out, err := kubectl(t, cluster, "", "get", "configmap", "-A", "-l", "cell.poc.internal/harness", "--field-selector", "metadata.name=cell-registry", "-o", "name")
		if err != nil || strings.TrimSpace(out) != "" {
			t.Errorf("a cell-registry in %s carries a harness label: %q %v", cluster, out, err)
		}
	}
}

// TestM5RealStreamsStillWork: with the proof in place, the real clients still work. The principal lists each view stream, the
// store holds live telemetry of each cell, and the hub holds a tunnel from each cell.
func TestM5RealStreamsStillWork(t *testing.T) {
	t.Run("view", func(t *testing.T) {
		for _, cell := range viewCells(t) {
			waitFor(t, "the principal lists the stream of "+cell, 3*time.Minute, func() (bool, string) { return viewConnectedSince(t, agentName(cell), time.Time{}) })
		}
	})
	t.Run("telemetry", func(t *testing.T) {
		for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
			row := rowOf(cell)
			waitFor(t, "a live up series of "+cell+" in the last 3 minutes", signalWait, func() (bool, string) {
				s := promSamplesFrom(t, fmt.Sprintf(`up{%s}`, row.matcher()), "now-3m")
				return len(s) > 0, fmt.Sprintf("%d series", len(s))
			})
		}
	})
	t.Run("mesh_view", func(t *testing.T) {
		for _, cell := range meshCells(t) {
			waitFor(t, "the hub tunnel of "+cell, 3*time.Minute, func() (bool, string) {
				last, ups := tunnelState(hubLog(t), cell)
				return last == "tunnel_up", fmt.Sprintf("last %s, %d tunnel_up lines", last, ups)
			})
		}
	})
}

// TestM5GuardStillBlocksViewTokens: the guard of the agent ServiceAccount now admits a token for the audience
// mgmt-stream/<cell>/argocd-agent/<binding> for the pod of the agent. The central view must still get no token through the
// resource proxy: it forwards a POST to a subresource only for an object that an Argo CD Application manages, and the
// ServiceAccount is not one. Each request fails with 403, and the agent log names that refusal.
func TestM5GuardStillBlocksViewTokens(t *testing.T) {
	cell := "dev-cell-1"
	requireViewConnected(t, agentName(cell))
	cs, _ := viewClient(t, agentName(cell))
	podName, podUID := podFacts(t, cell, agentDeployment)
	secs := int64(600)
	binding := strings.Repeat("A", 22)
	pod := &authenticationv1.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: podName, UID: types.UID(podUID)}
	for _, tc := range []struct {
		name string
		spec authenticationv1.TokenRequestSpec
	}{
		{"the stream audience, no bound Pod", authenticationv1.TokenRequestSpec{Audiences: []string{proof.StreamAudience(cell, "argocd-agent", binding)}, ExpirationSeconds: &secs}},
		{"the stream audience bound to the agent Pod", authenticationv1.TokenRequestSpec{Audiences: []string{proof.StreamAudience(cell, "argocd-agent", binding)}, ExpirationSeconds: &secs, BoundObjectRef: pod}},
		{"the stream audience of another cell bound to the agent Pod", authenticationv1.TokenRequestSpec{Audiences: []string{proof.StreamAudience("dev-cell-2", "argocd-agent", binding)}, ExpirationSeconds: &secs, BoundObjectRef: pod}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			since := time.Now().Add(-2 * time.Second)
			ctx, cancel := ctxTimeout()
			defer cancel()
			res := cs.CoreV1().RESTClient().Post().Namespace("argocd").Resource("serviceaccounts").Name("argocd-agent").SubResource("token").
				Body(&authenticationv1.TokenRequest{Spec: tc.spec}).Do(ctx)
			var code int
			res.StatusCode(&code)
			raw, err := res.Raw()
			t.Logf("HTTP %d, body %q, error %v", code, bytes.TrimSpace(raw), err)
			if err == nil || strings.Contains(string(raw), `"token"`) {
				t.Fatalf("the token request through the resource proxy answered HTTP %d with a token", code)
			}
			if code != 403 {
				t.Errorf("the token request answered HTTP %d with the error %q, want 403", code, err)
			}
			waitFor(t, "the agent log to name the managed-object refusal", time.Minute, func() (bool, string) {
				logs, lerr := kubectl(t, cell, "", "-n", agentNamespace, "logs", "deploy/"+agentDeployment, "-c", agentDeployment, "--since-time="+since.UTC().Format(time.RFC3339))
				if lerr != nil {
					return false, lerr.Error()
				}
				for l := range strings.SplitSeq(logs, "\n") {
					if strings.Contains(l, "resource not managed by app") && strings.Contains(l, "argocd-agent") {
						return true, ""
					}
				}
				return false, "no line with 'resource not managed by app' for argocd-agent"
			})
		})
	}
}
