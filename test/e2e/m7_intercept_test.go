//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// m7Hop describes one hop and its client. The client runs in an m7 namespace of its cluster with a copy of the production trust
// ConfigMap, and expects one exact server ID.
type m7Hop struct {
	name    string
	cluster string
	// expect is the exact server ID that the production client requires.
	expect string
	// bundleNS and bundleCM name the production ConfigMap in the client cluster, and bundleKey its key.
	bundleNS, bundleCM, bundleKey string
	// trustCluster is the cluster whose CA the bundle holds. wrongID is an ID under that CA that is not expect.
	trustCluster, wrongID string
	// devPathID, when set, is the ID for case (c): the same path as expect under the dev-cp CA. Only hops that trust the management root have it.
	devPathID string
}

func (h m7Hop) bundlePath() string { return "/run/m7/" + h.bundleCM + "/" + h.bundleKey }

// m7Case is one certificate that the impostor presents.
type m7Case struct {
	name, reason string
	chain, key   []byte
}

// m7Cases returns the certificates of a hop: (a) a self-made CA with the expected ID, (b) an SVID of the trusted CA with another ID, and
// (c) for a hop with devPathID, an SVID of the dev-cp CA with the expected path.
func m7Cases(t *testing.T, h m7Hop) []m7Case {
	t.Helper()
	var cases []m7Case
	chain, key := selfMadeChain(t, h.expect)
	cases = append(cases, m7Case{"a_self_made_ca", "peer_untrusted", chain, key})
	chain, key = mintSVID(t, h.trustCluster, h.wrongID, 10*time.Minute)
	cases = append(cases, m7Case{"b_wrong_id_from_trusted_ca", "peer_not_allowed", chain, key})
	if h.devPathID != "" {
		chain, key = mintSVID(t, envCluster, h.devPathID, 10*time.Minute)
		cases = append(cases, m7Case{"c_dev_cp_ca_with_expected_path", "peer_untrusted", chain, key})
	}
	return cases
}

// m7Intercept runs one subtest for each certificate of a hop. run starts the client against the impostor address in the namespace, and
// returns what the client printed and whether it ended in failure. check reads that output. The test then waits for the impostor log
// and requires 0 bytes after the handshake on every connection.
func m7Intercept(t *testing.T, h m7Hop, run func(t *testing.T, ns, addr string, c m7Case) string, check func(t *testing.T, out string, c m7Case)) {
	t.Helper()
	needProbeImage(t)
	for _, c := range m7Cases(t, h) {
		t.Run(c.name, func(t *testing.T) {
			ns := m7Namespace(t, h.cluster, false)
			copyConfigMap(t, h.cluster, h.bundleNS, h.bundleCM, h.cluster, ns)
			addr, closed := startImpostor(t, h.cluster, ns, c.chain, c.key)
			out := run(t, ns, addr, c)
			t.Logf("%s %s: the client printed %q", h.name, c.name, out)
			check(t, out, c)
			requireImpostorSilent(t, h.name+" "+c.name, closed)
		})
	}
}

const (
	celldCell = "dev-cell-1"
	// spireServerID is the exact ID that the SPIRE agent sidecar requires of the SPIRE server.
	spireServerID = "spiffe://" + envTrustDomain + "/spire/server"
)

var (
	devCellTrust = m7Hop{cluster: celldCell, bundleNS: celldNamespace, bundleCM: trustBundleMap, bundleKey: "bundle.crt",
		trustCluster: envCluster, wrongID: "spiffe://" + envTrustDomain + "/cp/otel"}
	// The wrong ID of a hop that trusts management is a real management ID.
	mgmtTrustWrong = "spiffe://" + mgmtTD + "/api"
)

func hopWith(base m7Hop, name, expect string) m7Hop {
	base.name, base.expect = name, expect
	return base
}

// TestM7InterceptCelldBind (hop A) points the bind client of celld, through the attestprobe gw-bind target that uses internal/bind, at
// an impostor. celld has no mode that runs only the bind client, so the probe stands in; it builds the same TLS settings with
// bind.ClientTLS. The nonce request is the first request of every bind, and it fails before any token exists. The error names the
// reason of the refusal, and the impostor receives no byte after the handshake.
func TestM7InterceptCelldBind(t *testing.T) {
	needAttestprobeImage(t)
	h := hopWith(devCellTrust, "hop A celld bind", gatewayID)
	vol, mount := configMapMount(trustBundleMap)
	m7Intercept(t, h, func(t *testing.T, ns, addr string, c m7Case) string {
		phase, logs := runM7Client(t, h.cluster, ns, attestprobeImage, []string{"--target", "gw-bind", "--upstream", addr, "--expect-id", h.expect,
			"--trust-bundle", h.bundlePath(), "--cell", celldCell, "--nonce-only", "--timeout", "30s"},
			[]map[string]any{vol}, []map[string]any{mount}, nil)
		if phase != "Failed" {
			t.Errorf("the bind client ended in phase %s, want Failed", phase)
		}
		return logs
	}, func(t *testing.T, out string, c m7Case) {
		if !strings.Contains(out, c.reason+":") || strings.Contains(out, "nonce:") {
			t.Errorf("the bind client printed %q, want the error text to name %s and no nonce", out, c.reason)
		}
	})
}

// TestM7InterceptCelldStream (hop B) dials an impostor gateway as the stream client of celld does: mutual TLS with an SVID of
// spiffe://.../cell/dev-cell-1/celld, and the exact gateway ID. celld cannot run in an m7 namespace, because the SPIRE agent
// gives an SVID only to the celld namespace, so netprobe tlsdial stands in. It uses cellproxy.ProbeTLS, which builds the same checks as
// cellproxy.ClientTLS. The impostor never asks for the client certificate, so the SVID of celld stays with the client.
func TestM7InterceptCelldStream(t *testing.T) {
	h := hopWith(devCellTrust, "hop B celld stream", gatewayID)
	vol, mount := configMapMount(trustBundleMap)
	clientChain, clientKey := mintSVID(t, envCluster, "spiffe://"+envTrustDomain+"/cell/"+celldCell+"/celld", 10*time.Minute)
	m7Intercept(t, h, func(t *testing.T, ns, addr string, c m7Case) string {
		_, logs := runM7Client(t, h.cluster, ns, probeImage, []string{"tlsdial", "--addr", addr, "--expect-id", h.expect, "--bundle", h.bundlePath(),
			"--client-cert-stdin"}, []map[string]any{vol}, []map[string]any{mount}, append(append([]byte{}, clientChain...), clientKey...))
		return logs
	}, checkTLSDialRefused)
}

// checkTLSDialRefused requires the tlsdial result of a failed handshake with the reason of the case.
func checkTLSDialRefused(t *testing.T, out string, c m7Case) {
	t.Helper()
	var res map[string]any
	if json.Unmarshal([]byte(lastOutputLine(out)), &res) != nil {
		t.Fatalf("tlsdial printed %q, want one JSON line", out)
	}
	if res["handshake"] != "failed" || res["reason"] != c.reason || res["verified"] == true {
		t.Errorf("tlsdial gave %v, want a failed handshake with the reason %s", res, c.reason)
	}
}

func lastOutputLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// TestM7InterceptSpireSidecar (hop C) runs attestprobe with the production bundle against an impostor SPIRE server. The client
// holds a canary token file, so it would send a token if it trusted the server. It sends none: the impostor receives no byte after
// the handshake, and the probe prints no outcome. The text of the failure differs for each case, and the bundle check comes first.
func TestM7InterceptSpireSidecar(t *testing.T) {
	needAttestprobeImage(t)
	h := hopWith(devCellTrust, "hop C spire sidecar", spireServerID)
	vol, mount := configMapMount(trustBundleMap)
	m7Intercept(t, h, func(t *testing.T, ns, addr string, c m7Case) string {
		secretName := tokenSecret(t, h.cluster, ns, "m7-canary-token-not-a-credential")
		tvol := map[string]any{"name": "token", "secret": map[string]any{"secretName": secretName}}
		tmount := map[string]any{"name": "token", "mountPath": "/run/attestprobe", "readOnly": true}
		phase, logs := runM7Client(t, h.cluster, ns, attestprobeImage, []string{"--variant", "good", "--cell", celldCell, "--env", pocEnv, "--server", addr,
			"--bundle", h.bundlePath(), "--token-file", "/run/attestprobe/token", "--timeout", "20s"},
			[]map[string]any{vol, tvol}, []map[string]any{mount, tmount}, nil)
		if phase != "Failed" {
			t.Errorf("the SPIRE client ended in phase %s, want Failed", phase)
		}
		return logs
	}, func(t *testing.T, out string, c m7Case) {
		if strings.Contains(out, "issued:") || strings.Contains(out, "denied:") {
			t.Errorf("the SPIRE client printed an outcome %q, want only an error", out)
		}
		want := map[string]string{"peer_untrusted": "could not verify leaf certificate", "peer_not_allowed": "unexpected ID"}[c.reason]
		if !strings.Contains(out, want) {
			t.Errorf("the SPIRE client printed %q, want %q for %s", out, want, c.reason)
		}
	})
}

// proxyHop describes the three hops that cell-proxy serves and the hop of envd.
func proxyHops(cell string) []m7Hop {
	mgmtTrust := func(name, cluster, expect, ns, cm, key, wrong string) m7Hop {
		path := expect[strings.Index(expect, mgmtTD)+len(mgmtTD):]
		return m7Hop{name: name, cluster: cluster, expect: expect, bundleNS: ns, bundleCM: cm, bundleKey: key, trustCluster: mgmtCluster,
			wrongID: wrong, devPathID: "spiffe://" + envTrustDomain + path}
	}
	return []m7Hop{
		mgmtTrust("hop D argocd agent", cell, principalID, agentNamespace, "mgmt-root", "root.crt", "spiffe://"+mgmtTD+"/telemetry"),
		mgmtTrust("hop E otel uplink", cell, telemetryID, "observability-system", "mgmt-root", "root.crt", mgmtTrustWrong),
		mgmtTrust("hop F mesh view", cell, hubID, "mesh-view-system", "mgmt-root", "root.crt", mgmtTrustWrong),
		mgmtTrust("hop G envd to mgmtd", envCluster, mgmtAPIID, "envd-system", "peer-root", "root.crt", "spiffe://"+mgmtTD+"/telemetry"),
	}
}

// TestM7InterceptCellProxyHops (hops D, E, F and G) points the client of each hop at an impostor with the production management root
// and the exact server ID. (a) and (c) give peer_untrusted, and (b) an SVID of management with another ID gives peer_not_allowed. The
// clients of D, E and F are cell-proxy probe, which builds ProbeTLS, the checks of cell-proxy spiffe-client and tunnel without the
// client certificate; those two modes get their SVID from the workload API, which an m7 namespace has not. Hop G is netprobe tlsdial with
// the root of envd, because envd gets its SVID from the workload API too.
func TestM7InterceptCellProxyHops(t *testing.T) {
	if cellProxyImage == "" {
		t.Fatal("build/images.env has no IMAGE_CELL_PROXY. Run mise run images")
	}
	for _, h := range proxyHops(celldCell) {
		t.Run(strings.ReplaceAll(h.name, " ", "_"), func(t *testing.T) {
			vol, mount := configMapMount(h.bundleCM)
			vols, mounts := []map[string]any{vol}, []map[string]any{mount}
			if h.cluster == envCluster {
				m7Intercept(t, h, func(t *testing.T, ns, addr string, c m7Case) string {
					_, logs := runM7Client(t, h.cluster, ns, probeImage, []string{"tlsdial", "--addr", addr, "--expect-id", h.expect, "--bundle", h.bundlePath()}, vols, mounts, nil)
					return logs
				}, checkTLSDialRefused)
				return
			}
			m7Intercept(t, h, func(t *testing.T, ns, addr string, c m7Case) string {
				_, logs := runM7Client(t, h.cluster, ns, cellProxyImage, []string{"probe", "--upstream", addr, "--expect-id", h.expect,
					"--peer-bundle", h.bundlePath(), "--peer-trust-domain", mgmtTD}, vols, mounts, nil)
				return logs
			}, func(t *testing.T, out string, c m7Case) {
				var res map[string]any
				if json.Unmarshal([]byte(lastOutputLine(out)), &res) != nil || res["reason"] != c.reason || res["verified"] == true {
					t.Errorf("cell-proxy probe printed %q, want the reason %s", out, c.reason)
				}
			})
		})
	}
}

// hostsvcSource is one client of the host service in TestM7RogueHandshakeToHostService.
type hostsvcSource struct {
	name       string
	chain, key []byte
}

// readHostLog returns the JSON lines of the host service log.
func readHostLog(t *testing.T) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(hostsvcLogFile)
	if err != nil {
		t.Fatalf("read the host service log: %v", err)
	}
	var out []map[string]any
	for l := range strings.SplitSeq(string(data), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(l), &rec) == nil {
			out = append(out, rec)
		}
	}
	return out
}

// hostRefusalAfter returns the time of the first "handshake refused" line of the host service after since, or the zero time.
func hostRefusalAfter(t *testing.T, since time.Time) time.Time {
	t.Helper()
	for _, rec := range readHostLog(t) {
		if rec["msg"] != "handshake refused" || rec["reason"] != "handshake_failed" {
			continue
		}
		if at, err := time.Parse(time.RFC3339Nano, fmt.Sprint(rec["time"])); err == nil && at.After(since) {
			return at
		}
	}
	return time.Time{}
}

// TestM7RogueHandshakeToHostService starts a TLS handshake with the host service from a pod in an m7 namespace of rogue, at the address
// that pods use (host.docker.internal in the node, port 17443). A control with an SVID of management with the ID of mgmtd shows that the
// pod reaches the service and that the handshake passes. No certificate, a self-made certificate with the ID of mgmtd, and an SVID of
// dev-cp with the path /cp/otel all end in a TLS alert from the server, and the host service log has a "handshake refused" line with
// the reason handshake_failed for each source. The log holds one line of each reason in each 10 s window, so the test waits for a new
// window before each source. The host service checks the ID during the handshake, so a dev-cp SVID with another ID fails there and gets
// no request, and the reason peer_not_allowed of the router needs a valid certificate.
func TestM7RogueHandshakeToHostService(t *testing.T) {
	needProbeImage(t)
	ns := m7Namespace(t, "rogue", false)
	host := fmt.Sprintf("%s:%d", hostsvcAddressIn(t, "rogue"), 17443)
	dial := func(src *hostsvcSource) map[string]any {
		args := []string{"tlsdial", "--addr", host, "--no-verify"}
		var stdin []byte
		if src != nil {
			args = append(args, "--client-cert-stdin")
			stdin = append(append([]byte{}, src.chain...), src.key...)
		}
		_, logs := runM7Client(t, "rogue", ns, probeImage, args, nil, nil, stdin)
		return lastJSONLine(t, logs)
	}

	chain, key := mintSVID(t, mgmtCluster, mgmtAPIID, 10*time.Minute)
	control := dial(&hostsvcSource{"control", chain, key})
	if control["handshake"] != "ok" || strings.HasPrefix(fmt.Sprint(control["after"]), "alert:") {
		t.Fatalf("the control with a real SVID of mgmtd gave %v, want a passed handshake, so the refusals below prove nothing otherwise", control)
	}

	selfChain, selfKey := selfMadeChain(t, mgmtAPIID)
	devChain, devKey := mintSVID(t, envCluster, "spiffe://"+envTrustDomain+"/cp/otel", 10*time.Minute)
	sources := []*hostsvcSource{nil, {"self_made_with_mgmtd_id", selfChain, selfKey}, {"dev_cp_cp_otel", devChain, devKey}}
	var last time.Time
	for _, src := range sources {
		name := "no_certificate"
		if src != nil {
			name = src.name
		}
		waitFor(t, "a new log window of the host service before "+name, time.Minute, func() (bool, string) {
			return last.IsZero() || time.Since(last) > 11*time.Second, "waiting for the 10 s window to end"
		})
		start := time.Now().Add(-time.Second)
		res := dial(src)
		if !strings.HasPrefix(fmt.Sprint(res["after"]), "alert:") && res["handshake"] != "failed" {
			t.Errorf("%s: tlsdial gave %v, want a TLS alert from the server", name, res)
		}
		waitFor(t, "a handshake refused line of the host service for "+name, time.Minute, func() (bool, string) {
			last = hostRefusalAfter(t, start)
			return !last.IsZero(), "no line after " + start.Format(time.RFC3339Nano)
		})
	}
}
