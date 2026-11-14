//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	envdNamespace  = "envd-system"
	envdDeployment = "envd"
	recordsMap     = "cell-records"
	// envdUID is the user of the ko images, which the entry of envd selects.
	envdUID        = "65532"
	envdApplyWait  = 60 * time.Second
	envdIslandWait = 2 * time.Minute
)

// recordsConfigMap returns the data and the metadata of ConfigMap spire-system/cell-records in dev-cp.
func recordsConfigMap(t *testing.T) (data map[string]string, annotations map[string]string, resourceVersion string, err error) {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "configmap", recordsMap, "-o", "json")
	if err != nil {
		return nil, nil, "", err
	}
	var cm struct {
		Metadata struct {
			Annotations     map[string]string `json:"annotations"`
			ResourceVersion string            `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &cm); err != nil {
		return nil, nil, "", fmt.Errorf("decode ConfigMap %s: %w", recordsMap, err)
	}
	return cm.Data, cm.Metadata.Annotations, cm.Metadata.ResourceVersion, nil
}

// liveRecords reads ConfigMap cell-records in dev-cp and verifies it under the key of ConfigMap mgmt-signing-pub: the
// signed spec, and each record that the spec indexes, against its entry. It fails the test on any difference.
func liveRecords(t *testing.T) (spec.Spec, map[string]record.Cell) {
	t.Helper()
	sp, cells, err := readLiveRecords(t)
	if err != nil {
		t.Fatal(err)
	}
	return sp, cells
}

func readLiveRecords(t *testing.T) (spec.Spec, map[string]record.Cell, error) {
	t.Helper()
	data, _, _, err := recordsConfigMap(t)
	if err != nil {
		return spec.Spec{}, nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(mgmtSigningPub(t))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return spec.Spec{}, nil, fmt.Errorf("mgmt-signing-pub is no Ed25519 key: %v", err)
	}
	keys := []ed25519.PublicKey{ed25519.PublicKey(raw)}
	sp, _, err := spec.Verify([]byte(data["spec-envelope.json"]), keys)
	if err != nil {
		return spec.Spec{}, nil, fmt.Errorf("the spec in %s does not verify under mgmt-signing-pub: %w", recordsMap, err)
	}
	cells := map[string]record.Cell{}
	for _, e := range sp.Cells {
		envelope, ok := data[e.Name+".dsse.json"]
		if !ok {
			return spec.Spec{}, nil, fmt.Errorf("%s holds no record for %s", recordsMap, e.Name)
		}
		c, payload, err := record.VerifyWithPayload([]byte(envelope), keys)
		if err != nil {
			return spec.Spec{}, nil, fmt.Errorf("the record of %s does not verify: %w", e.Name, err)
		}
		if err := sp.CheckRecord(e.Name, c, payload); err != nil {
			return spec.Spec{}, nil, fmt.Errorf("the record of %s differs from its spec entry: %w", e.Name, err)
		}
		cells[e.Name] = c
	}
	return sp, cells, nil
}

func compactJSON(t *testing.T, raw string) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(raw)); err != nil {
		t.Fatalf("not JSON: %v: %.200s", err, raw)
	}
	return b.String()
}

// TestM4EnvdAppliesSignedSpec: within a minute, the spec in cell-records verifies under mgmt-signing-pub, its counter equals
// the signed counter in mgmtd, and each record equals the one that mgmtd serves.
func TestM4EnvdAppliesSignedSpec(t *testing.T) {
	waitFor(t, "ConfigMap cell-records at the signed counter of mgmtd", envdApplyWait, func() (bool, string) {
		status := mgmtStatus(t)
		sp, _, err := readLiveRecords(t)
		if err != nil {
			return false, err.Error()
		}
		if sp.Revision != status.Signed {
			return false, fmt.Sprintf("cell-records holds %+v, mgmtd signed %+v", sp.Revision, status.Signed)
		}
		return true, ""
	})
	sp, cells := liveRecords(t)
	if sp.Env != pocEnv {
		t.Errorf("the spec is for env %q, want %q", sp.Env, pocEnv)
	}
	var served map[string]json.RawMessage
	if err := json.Unmarshal([]byte(mgmtCtl(t, "records")), &served); err != nil {
		t.Fatalf("mgmtd ctl records is no map of records: %v", err)
	}
	data, annotations, _, err := recordsConfigMap(t)
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.FormatUint(sp.Revision.Counter, 10); annotations["poc.internal/spec-counter"] != want {
		t.Errorf("annotation spec-counter is %q, want %s", annotations["poc.internal/spec-counter"], want)
	}
	for name := range cells {
		raw, ok := served[name]
		if !ok {
			t.Errorf("mgmtd serves no record for %s", name)
			continue
		}
		if got, want := compactJSON(t, data[name+".dsse.json"]), compactJSON(t, string(raw)); got != want {
			t.Errorf("the record of %s in cell-records differs from the one that mgmtd serves", name)
		}
	}
	for name := range served {
		if _, ok := cells[name]; !ok {
			t.Errorf("mgmtd serves a record for %s, and the spec of cell-records has no entry for it", name)
		}
	}
	t.Logf("cell-records holds spec revision %+v with %d records", sp.Revision, len(cells))
}

// TestM4CellsBound: mgmtd shows each cell of the harness as bound, with a record, and each celld logs its bound line.
func TestM4CellsBound(t *testing.T) {
	t.Skip("the M4 bind path is gone, and a new celld cannot bind until Task 12. Task 12 removes this skip when celld binds through the cell gateway")
	status := mgmtStatus(t)
	byName := map[string]mgmt.CellStatus{}
	for _, c := range status.Cells {
		byName[c.Name] = c
	}
	for _, cell := range clustersWith(t, agentCellSet) {
		t.Run(cell, func(t *testing.T) {
			c, ok := byName[cell]
			if !ok || !c.Bound || c.Record.Counter < 1 || c.Issuer == "" {
				t.Fatalf("mgmtd shows %+v for %s, want a bound cell with an issuer and a record", c, cell)
			}
			logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", "deploy/"+celldDeployment, "-c", celldContainer)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(logs, `"msg":"bound"`) {
				t.Errorf("celld in %s logs no bound line: %s", cell, lastLines(logs, 5))
			}
		})
	}
}

// TestM4ServerTrustsOnlyManagementKey: the cluster_jwt plugin of dev-cp pins exactly the key of mgmtd, ConfigMap
// mgmt-spec-key holds the same key, and no ConfigMap cell-record-<cell> of M2 is left in spire-system.
func TestM4ServerTrustsOnlyManagementKey(t *testing.T) {
	pub := mgmtSigningPub(t)
	conf, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "configmap", "spire-server", "-o", `jsonpath={.data.server\.conf}`)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*record_public_keys = \[(.*)\]$`).FindStringSubmatch(conf)
	if m == nil {
		t.Fatalf("server.conf holds no record_public_keys:\n%s", conf)
	}
	if got := strings.ReplaceAll(strings.ReplaceAll(m[1], `"`, ""), " ", ""); got != pub {
		t.Errorf("record_public_keys is %q, want only the key of mgmt-signing-pub %q", got, pub)
	}
	specKey, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "get", "configmap", "mgmt-spec-key", "-o", `jsonpath={.data.spec\.pub}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(specKey) != pub {
		t.Errorf("mgmt-spec-key holds %q, want %q", specKey, pub)
	}
	names, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "configmaps", "-o", "name")
	if err != nil {
		t.Fatal(err)
	}
	for name := range strings.FieldsSeq(names) {
		if strings.HasPrefix(strings.TrimPrefix(name, "configmap/"), "cell-record-") {
			t.Errorf("spire-system still holds %s, a record of the M2 render (verify row 4)", name)
		}
	}
}

// TestM4NewPodAttestsAfterBind: a new celld pod in each cell attests and logs its SVID, with the record that mgmtd signed.
func TestM4NewPodAttestsAfterBind(t *testing.T) {
	for _, cell := range clustersWith(t, agentCellSet) {
		t.Run(cell, func(t *testing.T) {
			t.Parallel()
			pod := replaceCelldPod(t, cell)
			waitCelldSVID(t, cell, pod)
			t.Logf("agent ID %s", agentIDOf(t, cell, pod))
		})
	}
}

// envdPod returns the name of the live envd pod: the one that has no deletion timestamp.
func envdPod(t *testing.T) string {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+envdDeployment, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name              string  `json:"name"`
				DeletionTimestamp *string `json:"deletionTimestamp"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("decode the envd pods: %v", err)
	}
	var names []string
	for _, p := range list.Items {
		if p.Metadata.DeletionTimestamp == nil {
			names = append(names, p.Metadata.Name)
		}
	}
	if len(names) != 1 {
		t.Fatalf("want one envd pod, got %v", names)
	}
	return names[0]
}

// TestM4EnvdPortsClosed: envd listens on its health port only, and a pod in another namespace of dev-cp cannot reach it.
func TestM4EnvdPortsClosed(t *testing.T) {
	pod := envdPod(t)
	addrs := listenAddrs(t, spireCluster, envdNamespace, pod, envdDeployment)
	for _, a := range addrs {
		if _, port, err := net.SplitHostPort(a); err != nil || port != "8080" {
			t.Errorf("envd listens on %s, want only port 8080", a)
		}
	}
	if len(addrs) == 0 {
		t.Error("envd listens on no port, so its health endpoint is down")
	}
	ip, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "get", "pod", pod, "-o", "jsonpath={.status.podIP}")
	if err != nil {
		t.Fatal(err)
	}
	if err := probeFromFreshNamespace(t, spireCluster, strings.TrimSpace(ip), 8080, 10*time.Second); err != nil {
		t.Errorf("a pod in another namespace reaches the health port of envd: %v", err)
	}
}

// TestM4EnvdEntry: the entry of envd is spiffe://dev.env.poc.internal/envd with the selector unix:uid:<ko uid>, under the node
// alias of its own namespace and ServiceAccount.
func TestM4EnvdEntry(t *testing.T) {
	out, err := spireServerIn(t, spireCluster, "entry", "show", "-socketPath", spireSocket, "-spiffeID", envdID, "-output", "json")
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
		t.Fatalf("want one entry for %s, got %d: %s", envdID, len(res.Entries), out)
	}
	e := res.Entries[0]
	var selectors []string
	for _, s := range e.Selectors {
		selectors = append(selectors, s.Type+":"+s.Value)
	}
	if !slices.Equal(selectors, []string{"unix:uid:" + envdUID}) {
		t.Errorf("selectors are %v, want [unix:uid:%s]", selectors, envdUID)
	}
	if e.ParentID.Path != "/agents/"+envdNamespace+"/"+envdDeployment {
		t.Errorf("the parent is %s, want the node alias /agents/%s/%s", e.ParentID.Path, envdNamespace, envdDeployment)
	}
}

// TestM4EnvdEgressClosed: from the envd pod, the API port of mgmtd (31446) connects, because flow N30 admits it, and the
// bind port (31447) times out, because no policy and no Service names it.
func TestM4EnvdEgressClosed(t *testing.T) {
	mgmtIP := clusterFacts(t, mgmtCluster).NodeIP
	pod := envdPod(t)
	// The ephemeral containers stay in the pod spec, so the Deployment starts a clean pod when the test ends.
	t.Cleanup(func() {
		if _, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "delete", "pod", pod, "--wait=false"); err != nil {
			t.Logf("could not delete the probed envd pod: %v", err)
		}
	})
	if got := ephemeralDial(t, spireCluster, envdNamespace, pod, net.JoinHostPort(mgmtIP, "31446"), 10*time.Second); got != "connected" {
		t.Fatalf("the control dial to %s:31446 gave %q, want connected, so a timeout on 31447 would prove nothing", mgmtIP, got)
	}
	if got := ephemeralDial(t, spireCluster, envdNamespace, pod, net.JoinHostPort(mgmtIP, "31447"), 10*time.Second); got != "timeout" {
		t.Errorf("the dial from envd to %s:31447 gave %q, want a timeout", mgmtIP, got)
	}
}

// TestM4EnvdIslandKeepsRecords: with mgmtd at zero replicas, a new envd pod is Ready within two minutes, cell-records keeps its
// resourceVersion, the envd log shows a transport error, and a new celld pod attests from the records that stay. After mgmtd
// returns, envd reports again within two minutes, and cell:verify of management passes.
func TestM4EnvdIslandKeepsRecords(t *testing.T) {
	const mgmtd = "statefulset/mgmtd"
	_, _, before, err := recordsConfigMap(t)
	if err != nil {
		t.Fatal(err)
	}
	setReplicas(t, mgmtCluster, mgmtNamespace, mgmtd, 0)
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		setReplicas(t, mgmtCluster, mgmtNamespace, mgmtd, 1)
	}
	t.Cleanup(restore)
	waitFor(t, "mgmtd-0 gone", envdIslandWait, func() (bool, string) {
		out, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "get", "pods", "-l", "app.kubernetes.io/name=mgmtd", "-o", "name")
		return err == nil && strings.TrimSpace(out) == "", out
	})

	old := envdPod(t)
	if _, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "delete", "pod", old, "--wait=false"); err != nil {
		t.Fatal(err)
	}
	var fresh string
	waitFor(t, "a new envd pod, Ready with mgmtd away", envdIslandWait, func() (bool, string) {
		out, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+envdDeployment, "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var list struct {
			Items []struct {
				Metadata struct {
					Name              string  `json:"name"`
					DeletionTimestamp *string `json:"deletionTimestamp"`
				} `json:"metadata"`
				Status struct {
					Conditions []struct{ Type, Status string } `json:"conditions"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			return false, err.Error()
		}
		var seen []string
		for _, p := range list.Items {
			if p.Metadata.DeletionTimestamp != nil || p.Metadata.Name == old {
				continue
			}
			for _, c := range p.Status.Conditions {
				if c.Type == "Ready" && c.Status == "True" {
					fresh = p.Metadata.Name
					return true, ""
				}
			}
			seen = append(seen, p.Metadata.Name)
		}
		return false, fmt.Sprintf("pods not Ready: %v", seen)
	})
	waitFor(t, "a transport error in the log of the new envd pod", envdIslandWait, func() (bool, string) {
		logs, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "logs", fresh, "-c", envdDeployment)
		if err != nil {
			return false, err.Error()
		}
		for line := range strings.SplitSeq(logs, "\n") {
			var rec struct{ Level, Msg, Error string }
			if json.Unmarshal([]byte(line), &rec) == nil && (rec.Level == "WARN" || rec.Level == "ERROR") && rec.Error != "" {
				t.Logf("envd log: %s", line)
				return true, ""
			}
		}
		return false, lastLines(logs, 5)
	})
	if _, _, after, err := recordsConfigMap(t); err != nil || after != before {
		t.Errorf("cell-records has the resourceVersion %q (error %v), want %q: envd must leave the records alone while mgmtd is away", after, err, before)
	}
	cell := clustersWith(t, agentCellSet)[0]
	pod := replaceCelldPod(t, cell)
	waitCelldSVID(t, cell, pod)

	returned := time.Now()
	restore()
	statefulSetReady(t, mgmtCluster, mgmtNamespace, "mgmtd")
	waitFor(t, "envd to report to mgmtd again", envdIslandWait, func() (bool, string) {
		out, err := mgmtCtlErr("status")
		if err != nil {
			return false, err.Error()
		}
		var s mgmt.Status
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			return false, err.Error()
		}
		return s.LastReportAt.After(returned), fmt.Sprintf("last report at %s, mgmtd returned at %s", s.LastReportAt, returned)
	})
	if out, err := command("", "env", "CELL=management", "mise", "run", "cell:verify"); err != nil {
		t.Errorf("CELL=management mise run cell:verify: %v\n%s", err, out)
	}
}
