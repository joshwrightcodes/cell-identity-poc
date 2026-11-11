//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	collmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
)

// These tests check the telemetry of every registered cluster in the store of management. Each
// collector sets the source attributes of its cluster, and every cluster but management sends
// through an uplink: a cell through the relay of dev-cp, dev-cp straight to the gateway.

// telemetryClusters are the clusters that send telemetry to the store.
var telemetryClusters = []string{mgmtCluster, envCluster, "dev-cell-1", "dev-cell-2"}

// sourceRow is one row of the source attribute table. An empty value means that the attribute is
// absent.
type sourceRow struct{ cluster, plane, env, cell string }

func rowOf(cluster string) sourceRow {
	switch cluster {
	case mgmtCluster:
		return sourceRow{cluster: cluster, plane: "management"}
	case envCluster:
		return sourceRow{cluster: cluster, plane: "environment", env: pocEnv}
	default:
		return sourceRow{cluster: cluster, plane: "cell", env: pocEnv, cell: cluster}
	}
}

// labels returns the labels that Prometheus and Loki hold for the row. An absent attribute has the
// empty string.
func (r sourceRow) labels() map[string]string {
	return map[string]string{"k8s_cluster_name": r.cluster, "platform_plane": r.plane, "deployment_environment_name": r.env, "platform_cell": r.cell}
}

// matcher returns the label matchers of the row, with an empty matcher for each absent attribute,
// so that PromQL and LogQL select only series without it.
func (r sourceRow) matcher() string {
	var parts []string
	for _, k := range []string{"k8s_cluster_name", "platform_plane", "deployment_environment_name", "platform_cell"} {
		parts = append(parts, fmt.Sprintf("%s=%q", k, r.labels()[k]))
	}
	return strings.Join(parts, ",")
}

// traceQL returns a TraceQL selector for the row. An absent attribute must be nil.
func (r sourceRow) traceQL(extra string) string {
	attrs := map[string]string{"k8s.cluster.name": r.cluster, "platform.plane": r.plane, "deployment.environment.name": r.env, "platform.cell": r.cell}
	var parts []string
	for _, k := range []string{"k8s.cluster.name", "platform.plane", "deployment.environment.name", "platform.cell"} {
		if attrs[k] == "" {
			parts = append(parts, fmt.Sprintf("resource.%s = nil", k))
		} else {
			parts = append(parts, fmt.Sprintf("resource.%s = %q", k, attrs[k]))
		}
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return "{ " + strings.Join(parts, " && ") + " }"
}

// requireRow fails when the labels differ from the row. An absent label is the empty string.
func requireRow(t *testing.T, what string, got map[string]string, r sourceRow) {
	t.Helper()
	for k, want := range r.labels() {
		if got[k] != want {
			t.Errorf("%s has %s=%q, want %q (row of %s)", what, k, got[k], want, r.cluster)
		}
	}
}

// echoTraffic sends n requests from client to echo in a cluster. Envoy then emits traces, access
// logs and Istio metrics.
func echoTraffic(t *testing.T, cluster string, n int) {
	t.Helper()
	for range n {
		if _, err := kubectl(t, cluster, "", "-n", "apps-demo", "exec", "deploy/client", "-c", "curl", "--", "curl", "-s", "-o", "/dev/null", "--max-time", "10", "http://echo/hostname"); err != nil {
			t.Fatalf("client to echo in %s: %v", cluster, err)
		}
	}
}

// TestM3SignalsFromEveryRegisteredCluster checks that each cluster has Prometheus series, Loki lines
// from the last 15 minutes and a Tempo trace in the store. Each carries exactly the row of the source
// attribute table for its cluster, and an absent attribute is absent.
func TestM3SignalsFromEveryRegisteredCluster(t *testing.T) {
	for _, cluster := range telemetryClusters {
		t.Run(cluster, func(t *testing.T) {
			t.Parallel()
			row := rowOf(cluster)
			echoTraffic(t, cluster, 5)
			waitFor(t, "up series with the row of "+cluster, signalWait, func() (bool, string) {
				s := promSamples(t, fmt.Sprintf(`up{%s}`, row.matcher()))
				return len(s) > 0, fmt.Sprintf("%d series", len(s))
			})
			for _, s := range promSamples(t, fmt.Sprintf(`up{k8s_cluster_name=%q}`, cluster)) {
				requireRow(t, "an up series "+fmt.Sprint(s.labels), s.labels, row)
			}
			waitFor(t, "Loki lines of "+cluster+" from the last 15 minutes", signalWait, func() (bool, string) {
				echoTraffic(t, cluster, 1)
				lines := lokiLinesFrom(t, fmt.Sprintf(`{%s}`, row.matcher()), "now-15m")
				return len(lines) > 0, fmt.Sprintf("%d lines", len(lines))
			})
			for _, l := range lokiLinesFrom(t, fmt.Sprintf(`{k8s_cluster_name=%q}`, cluster), "now-15m") {
				requireRow(t, "a Loki line of "+cluster, l.labels, row)
			}
			waitFor(t, "a Tempo trace of "+cluster, signalWait, func() (bool, string) {
				echoTraffic(t, cluster, 1)
				n := tempoTraces(t, row.traceQL(""))
				return n > 0, fmt.Sprintf("%d traces", n)
			})
		})
	}
}

// TestM3CollectorSelfTelemetry checks that the collector of each cluster sends its own metrics to its
// own port 4317, so that Prometheus holds the queue size of the exporter for the cluster.
func TestM3CollectorSelfTelemetry(t *testing.T) {
	for _, cluster := range telemetryClusters {
		t.Run(cluster, func(t *testing.T) {
			t.Parallel()
			waitFor(t, "otelcol_exporter_queue_size of "+cluster, signalWait, func() (bool, string) {
				s := promSamples(t, fmt.Sprintf(`otelcol_exporter_queue_size{k8s_cluster_name=%q}`, cluster))
				return len(s) > 0, fmt.Sprintf("%d series", len(s))
			})
		})
	}
}

// TestM3NoCrossLabels checks that no series of a cell carries the cell name of another cell, and that
// no series of management or dev-cp has platform_cell.
func TestM3NoCrossLabels(t *testing.T) {
	groups := promSamples(t, `count by (platform_cell, k8s_cluster_name) ({platform_plane="cell"})`)
	if len(groups) == 0 {
		t.Fatal("Prometheus holds no series with platform_plane=cell")
	}
	seen := map[string]bool{}
	for _, g := range groups {
		seen[g.labels["k8s_cluster_name"]] = true
		if g.labels["platform_cell"] != g.labels["k8s_cluster_name"] {
			t.Errorf("series with platform_plane=cell and platform_cell=%q from %q", g.labels["platform_cell"], g.labels["k8s_cluster_name"])
		}
	}
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
		if !seen[cell] {
			t.Errorf("Prometheus holds no series of %s with platform_plane=cell", cell)
		}
	}
	if s := promSamples(t, `{k8s_cluster_name=~"management|dev-cp", platform_cell!=""}`); len(s) > 0 {
		t.Errorf("series of management or dev-cp carry platform_cell: %v", s[0].labels)
	}
	for _, l := range lokiLines(t, `{platform_plane="cell"}`) {
		if l.labels["platform_cell"] != l.labels["k8s_cluster_name"] {
			t.Errorf("Loki line with platform_cell=%q and k8s_cluster_name=%q", l.labels["platform_cell"], l.labels["k8s_cluster_name"])
		}
	}
}

// pemCerts returns the certificates in PEM text.
func pemCerts(t *testing.T, text string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for rest := []byte(text); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		out = append(out, c)
	}
}

// TestM3PeerRootPinnedInDevCP checks that ConfigMap peer-root in dev-cp/observability-system holds
// the roots that the live SPIRE server of management prints with bundle show.
func TestM3PeerRootPinnedInDevCP(t *testing.T) {
	out, err := kubectl(t, envCluster, "", "-n", obsNamespace, "get", "configmap", "peer-root", "-o", `jsonpath={.data.root\.crt}`)
	if err != nil {
		t.Fatalf("read ConfigMap peer-root in %s: %v", envCluster, err)
	}
	got := pemCerts(t, out)
	want := bundleRoots(t, mgmtCluster)
	if len(got) == 0 || len(got) != len(want) {
		t.Fatalf("peer-root holds %d roots, the server of %s has %d", len(got), mgmtCluster, len(want))
	}
	for i := range want {
		if !got[i].Equal(want[i]) {
			t.Errorf("root %d of peer-root differs from the live bundle of %s", i, mgmtCluster)
		}
	}
}

// uplinkOwnSVID checks that cell-proxy of the uplink pod of a cluster gets only its own otel ID from the
// Workload API of its sidecar. TestM3WorkloadAPIOwnSVIDOnly runs it as a subtest for each uplink.
func uplinkOwnSVID(t *testing.T, cluster string) {
	t.Helper()
	want := "spiffe://" + envTrustDomain + "/cell/" + cluster + "/otel"
	if cluster == envCluster {
		want = "spiffe://" + envTrustDomain + "/cp/otel"
	}
	pod, _ := readyPodIn(t, cluster, obsNamespace, "otel-uplink")
	out, err := kubectl(t, cluster, "", "-n", obsNamespace, "exec", pod, "-c", "cell-proxy", "--", "/ko-app/cell-proxy", "whoami")
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

// TestM3UplinkBinds checks that the uplink container of each cluster listens on port 4319 only.
func TestM3UplinkBinds(t *testing.T) {
	for _, cluster := range []string{envCluster, "dev-cell-1", "dev-cell-2"} {
		t.Run(cluster, func(t *testing.T) {
			pod, _ := readyPodIn(t, cluster, obsNamespace, "otel-uplink")
			addrs := listenAddrs(t, cluster, obsNamespace, pod, "cell-proxy")
			if len(addrs) == 0 {
				t.Fatalf("the uplink of %s listens on nothing", cluster)
			}
			for _, a := range addrs {
				if !strings.HasSuffix(a, ":4319") {
					t.Errorf("the uplink of %s listens on %s, want only port 4319", cluster, a)
				}
			}
		})
	}
}

// podIPBySelector returns the pod address of the first pod that matches a label selector.
func podIPBySelector(t *testing.T, cluster, ns, selector string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "get", "pods", "-l", selector, "--field-selector=status.phase=Running", "-o", "jsonpath={.items[0].status.podIP}")
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("no running pod with %s in %s/%s: %q, %v", selector, cluster, ns, out, err)
	}
	return strings.TrimSpace(out)
}

// collectorJobs are the scrape jobs that each cluster must show with up equal to 1.
var collectorJobs = map[string][]string{
	mgmtCluster:  {"envoy", "istiod", "argocd", "argocd-agent-principal", "spire-server"},
	envCluster:   {"envoy", "istiod", "argocd", "spire-server"},
	"dev-cell-1": {"envoy", "istiod", "argocd", "argocd-agent"},
	"dev-cell-2": {"envoy", "istiod", "argocd", "argocd-agent"},
}

// TestM3MetricsEndpointsCollectorOnly checks that only the collector reaches a metrics endpoint. A
// pod in a fresh namespace of each cluster times out on the agent (8181), istiod (15014), Envoy of
// echo (15090) and the uplink (4319) in a cell, on the SPIRE server (9988) in management and dev-cp,
// and on the principal (8000) in management. The collector scrapes each job, so up is 1.
func TestM3MetricsEndpointsCollectorOnly(t *testing.T) {
	type target struct {
		name, ns, selector string
		port               int
	}
	targets := map[string][]target{
		"dev-cell-1": {{"agent", "argocd", "app.kubernetes.io/name=argocd-agent", 8181}, {"istiod", "istio-system", "app=istiod", 15014},
			{"envoy of echo", "apps-demo", "app=echo", 15090}, {"uplink", obsNamespace, "app.kubernetes.io/name=otel-uplink", 4319}},
		envCluster: {{"SPIRE server", "spire-system", "app.kubernetes.io/name=spire-server", 9988}},
		mgmtCluster: {{"SPIRE server", "spire-system", "app.kubernetes.io/name=spire-server", 9988},
			{"principal", viewNamespace, "app.kubernetes.io/name=" + principalName, 8000}},
	}
	targets["dev-cell-2"] = targets["dev-cell-1"]
	for cluster, list := range targets {
		for _, tg := range list {
			t.Run(cluster+" "+tg.name, func(t *testing.T) {
				t.Parallel()
				ip := podIPBySelector(t, cluster, tg.ns, tg.selector)
				if err := probeFromFreshNamespace(t, cluster, ip, tg.port, 5*time.Second); err != nil {
					t.Error(err)
				}
			})
		}
	}
	for _, cluster := range telemetryClusters {
		t.Run("up "+cluster, func(t *testing.T) {
			t.Parallel()
			waitFor(t, "up equal to 1 for every job of "+cluster, signalWait, func() (bool, string) {
				jobs := map[string]bool{}
				for _, s := range promSamples(t, fmt.Sprintf(`last_over_time(up{k8s_cluster_name=%q}[3m])`, cluster)) {
					if s.last != 1 {
						return false, fmt.Sprintf("job %s instance %s has up %v", s.labels["job"], s.labels["instance"], s.last)
					}
					jobs[s.labels["job"]] = true
				}
				for _, j := range collectorJobs[cluster] {
					if !jobs[j] {
						return false, fmt.Sprintf("no job %s, jobs %v", j, jobs)
					}
				}
				return true, ""
			})
		})
	}
}

// overwriteCount returns the sum of the counters cellproxy_gateway_attribute_overwrites_total for one
// sender and one attribute, at every level. Each series is cumulative for one gateway process, so a
// restart of the gateway starts new series, and the caller compares the sums of the same series.
func overwriteCount(t *testing.T, sender, attribute string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, s := range promSamples(t, fmt.Sprintf(`cellproxy_gateway_attribute_overwrites_total{sender_cluster=%q,attribute=%q}`, sender, attribute)) {
		out[fmt.Sprint(s.labels)] = s.last
	}
	return out
}

// TestM3IstioMetricsSurviveOTLP sends 20 requests from client to echo in each cell. Prometheus must
// then hold istio_requests_total and istio_request_duration_milliseconds_bucket with the reporter,
// the workloads, and source_cluster and destination_cluster equal to the cell. The gateway must not
// count an overwrite of source_cluster for the cell during the test, so the cluster name of Istio and
// the attributes of the collector agree with the values that the gateway sets.
func TestM3IstioMetricsSurviveOTLP(t *testing.T) {
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
		t.Run(cell, func(t *testing.T) {
			t.Parallel()
			base := overwriteCount(t, cell, "source_cluster")
			echoTraffic(t, cell, 20)
			for _, metric := range []string{"istio_requests_total", "istio_request_duration_milliseconds_bucket"} {
				waitFor(t, metric+" of "+cell, signalWait, func() (bool, string) {
					reporters := map[string]bool{}
					for _, s := range promSamples(t, fmt.Sprintf(`%s{k8s_cluster_name=%q,source_workload="client",destination_workload="echo",source_cluster=%q,destination_cluster=%q}`, metric, cell, cell, cell)) {
						reporters[s.labels["reporter"]] = true
					}
					return reporters["source"] && reporters["destination"], fmt.Sprintf("reporters %v", reporters)
				})
			}
			// The gateway exports its counters every 10 seconds, so a later look would show an overwrite.
			time.Sleep(25 * time.Second)
			if rise := overwriteRise(base, overwriteCount(t, cell, "source_cluster")); rise != 0 {
				t.Errorf("the gateway overwrote source_cluster %v times for %s during the test, want 0", rise, cell)
			}
		})
	}
}

// rogueSender makes a CA that nobody trusts, and a leaf certificate for the SPIFFE ID id under it, as
// a host in rogue would make them.
func rogueSender(t *testing.T, id string) tls.Certificate {
	t.Helper()
	ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rogue CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, ca.Public(), ca)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(id)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, key.Public(), ca)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
}

// startRelayForwarder starts the relay image in a namespace of a cell, with one route from its port
// 8444 to the relay-telemetry node port of dev-cp. The pod holds the node address of the cell, which
// the relay admits. It returns the pod name.
func startRelayForwarder(t *testing.T, cell, ns, upstream string) string {
	t.Helper()
	relayImage := readImage("IMAGE_RELAY")
	if relayImage == "" {
		t.Fatalf("%s has no IMAGE_RELAY pinned by digest. Run mise run images.", imagesEnv)
	}
	const name = "relay-forwarder"
	pod := map[string]any{
		"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"automountServiceAccountToken": false,
			"securityContext":              map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
			"containers": []map[string]any{{
				"name": "relay", "image": relayImage, "args": []string{"--route", "8444=" + upstream, "--health", ":8080"},
				"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}},
				"readinessProbe":  map[string]any{"httpGet": map[string]any{"path": "/healthz", "port": 8080}},
			}},
		},
	}
	b, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kubectl(t, cell, string(b), "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay forwarder in "+cell+" Ready", 2*time.Minute, func() (bool, string) {
		out, err := kubectl(t, cell, "", "-n", ns, "get", "pod", name, "-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		return err == nil && strings.TrimSpace(out) == "True", out
	})
	return name
}

// rogueTokenInRogue makes a pod-bound token for ServiceAccount otel-uplink in rogue and returns
// it with its key ID. The key of rogue is not one of the keys that dev-cell-1 publishes.
func rogueTokenInRogue(t *testing.T, ns string) (token, kid string) {
	t.Helper()
	needProbeImage(t)
	createNamespace(t, "rogue", ns)
	if _, err := kubectl(t, "rogue", "", "-n", ns, "create", "serviceaccount", "otel-uplink"); err != nil {
		t.Fatal(err)
	}
	holder := fmt.Sprintf(`{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "token-holder", "namespace": %q},
  "spec": {"serviceAccountName": "otel-uplink", "automountServiceAccountToken": false,
    "securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [{"name": "holder", "image": %q, "args": ["serve", "--addr", ":8080"],
      "securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}}}]}}`, ns, probeImage)
	if _, err := kubectl(t, "rogue", holder, "create", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	uid, err := kubectl(t, "rogue", "", "-n", ns, "get", "pod", "token-holder", "-o", "jsonpath={.metadata.uid}")
	if err != nil || uid == "" {
		t.Fatalf("UID of the token holder pod in rogue: %q, %v", uid, err)
	}
	token, err = kubectl(t, "rogue", "", "-n", ns, "create", "token", "otel-uplink",
		"--audience", clusterjwt.Audience(pocEnv, "rogue"), "--duration", "10m",
		"--bound-object-kind", "Pod", "--bound-object-name", "token-holder", "--bound-object-uid", uid)
	if err != nil {
		t.Fatalf("TokenRequest in rogue: %v", err)
	}
	token = strings.TrimSpace(token)
	kid = tokenKID(token)
	if kid == "" || slices.Contains(cellKIDs(t, rejectCell), kid) {
		t.Fatalf("the rogue token has the key ID %q, want one that %s does not use (%v)", kid, rejectCell, cellKIDs(t, rejectCell))
	}
	return token, kid
}

// TestM3RogueTelemetryFails checks that the rogue cluster gets no telemetry into the store.
//
// Reach: dials from a pod in rogue to the SPIRE node port and the relay-telemetry node port of dev-cp
// time out within 5 seconds.
//
// Identity, from an admitted address: a pod in dev-cell-1 holds a token that rogue made for the
// subject of the uplink, and the SPIRE server of dev-cp refuses it with unknown_kid, so the pod gets
// no SVID. Then a client presents a certificate for cell/dev-cell-1/otel from a CA that nobody trusts
// through a relay in dev-cell-1 and the real relay path on 30444, and sends OTLP with a rogue marker.
// In the same window, a probe sends a cell marker through the collector and the uplink of dev-cell-1.
// After 3 minutes the gateway log holds peer_untrusted, the cell marker is in Prometheus and Loki, and
// the rogue marker is in no store.
func TestM3RogueTelemetryFails(t *testing.T) {
	envIP := clusterFacts(t, envCluster).NodeIP

	t.Run("reach", func(t *testing.T) {
		for _, port := range []int{spireNodePort, 30444} {
			t.Run(fmt.Sprint(port), func(t *testing.T) {
				t.Parallel()
				if err := probeFromFreshNamespace(t, "rogue", envIP, port, 5*time.Second); err != nil {
					t.Error(err)
				}
			})
		}
	})

	const testNS = "m3-rogue-telemetry"
	t.Run("identity", func(t *testing.T) {
		needAttestprobeImage(t)
		token, kid := rogueTokenInRogue(t, testNS)
		// The test data holds the namespace, the ServiceAccount and the token rights of the subject.
		cleanup := func() {
			if _, err := kubectl(t, rejectCell, "", "delete", "-f", "testdata/rogue-telemetry.yaml", "--ignore-not-found", "--wait=true", "--timeout=180s"); err != nil {
				t.Logf("cleanup of the test data in %s: %v", rejectCell, err)
			}
		}
		cleanup()
		if _, err := kubectl(t, rejectCell, "", "apply", "-f", "testdata/rogue-telemetry.yaml"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(cleanup)
		copyTrustBundle(t, rejectCell, testNS)
		secret := "m3-rogue-token-" + randomHex(t, 4)
		manifest, err := json.Marshal(map[string]any{
			"apiVersion": "v1", "kind": "Secret",
			"metadata": map[string]any{"name": secret, "namespace": testNS, "labels": map[string]string{probeLabel: secret}},
			"data":     map[string]string{"token": base64.StdEncoding.EncodeToString([]byte(token))},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kubectl(t, rejectCell, string(manifest), "create", "-f", "-"); err != nil {
			t.Fatal(err)
		}
		res := runAttestProbe(t, probe{cell: rejectCell, namespace: testNS, account: "otel-uplink", variant: "good", tokenSecret: secret})
		expectRefusal(t, res, rejectCell, "unknown_kid", []string{kid})
	})

	t.Run("telemetry", func(t *testing.T) {
		since := time.Now().Add(-2 * time.Second)
		rogueMarker, cellMarker := "m3rogue"+randomHex(t, 4), "m3cell"+randomHex(t, 4)
		ns := freshNamespace(t, rejectCell)
		pod := startRelayForwarder(t, rejectCell, ns, fmt.Sprintf("%s:%d", envIP, 30444))

		// The rogue sender: a certificate for the ID of a registered cell, from a CA that the gateway does
		// not trust, through the relay of dev-cp.
		id := "spiffe://" + envTrustDomain + "/cell/" + rejectCell + "/otel"
		conn := gatewayConnTo(t, portForward(t, rejectCell, ns, "pod/"+pod, 8444), rogueSender(t, id))
		rogueRes := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{strAttr("service.name", "rogue-"+rogueMarker[len("m3rogue"):])}}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := collmetrics.NewMetricsServiceClient(conn).Export(ctx, &collmetrics.ExportMetricsServiceRequest{})
		cancel()
		if err == nil {
			t.Error("the gateway accepted an export from a certificate of an untrusted CA, want a refusal")
		}
		if err := sendSignalsErr(conn, rogueRes, rogueMarker); err == nil {
			t.Error("the gateway accepted signals from a certificate of an untrusted CA, want a refusal")
		}

		// The cell sender: a probe sends through the collector, the real uplink, the relay and the gateway.
		cellConn := plaintextConn(t, portForward(t, rejectCell, obsNamespace, "svc/otel-collector", 4317))
		cellRes := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{strAttr("service.name", "cell-"+cellMarker[len("m3cell"):])}}
		sendSignals(t, cellConn, cellRes, cellMarker)
		sentAt := time.Now()

		cellMetric := "m3_spoof_" + cellMarker
		waitFor(t, "the cell marker in Prometheus", signalWait, func() (bool, string) {
			s := promSamples(t, fmt.Sprintf(`{__name__=%q}`, cellMetric))
			if len(s) == 1 {
				requireRow(t, "the cell marker series", s[0].labels, rowOf(rejectCell))
			}
			return len(s) == 1, fmt.Sprintf("%d series", len(s))
		})
		waitFor(t, "the cell marker in Loki", signalWait, func() (bool, string) {
			l := lokiLines(t, fmt.Sprintf(`{k8s_cluster_name=%q} |= %q`, rejectCell, "log "+cellMarker))
			return len(l) > 0, fmt.Sprintf("%d lines", len(l))
		})
		waitFor(t, "the cell marker in Tempo", signalWait, func() (bool, string) {
			n := tempoTraces(t, fmt.Sprintf(`{ name = %q }`, "span "+cellMarker))
			return n > 0, fmt.Sprintf("%d traces", n)
		})

		// The rogue marker must stay out of every store for 3 minutes from the send.
		if wait := time.Until(sentAt.Add(3 * time.Minute)); wait > 0 {
			time.Sleep(wait)
		}
		waitFor(t, "the gateway line peer_untrusted for "+id, time.Minute, func() (bool, string) {
			for _, rec := range gatewayLogs(t, since) {
				if rec["reason"] == "peer_untrusted" && (rec["spiffe_id"] == id || rec["unverified_spiffe_id"] == id) {
					return true, ""
				}
			}
			return false, "no such line"
		})
		if s := promSamples(t, fmt.Sprintf(`{__name__=%q}`, "m3_spoof_"+rogueMarker)); len(s) > 0 {
			t.Errorf("Prometheus holds the rogue marker: %v", s[0].labels)
		}
		if l := lokiLines(t, fmt.Sprintf(`{k8s_cluster_name=~".+"} |= %q`, "log "+rogueMarker)); len(l) > 0 {
			t.Errorf("Loki holds the rogue marker: %v", l[0].labels)
		}
		if n := tempoTraces(t, fmt.Sprintf(`{ name = %q }`, "span "+rogueMarker)); n > 0 {
			t.Errorf("Tempo holds %d traces with the rogue marker", n)
		}
	})
}
