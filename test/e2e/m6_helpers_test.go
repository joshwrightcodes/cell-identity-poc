//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

const (
	// cellControllerID is the only peer that the step route of the host service admits.
	cellControllerID = "spiffe://dev.env.poc.internal/cp/cell-controller"
	cpClusterName    = "dev-cp"
	hostsvcLogFile   = "../../build/hostsvc/serve.log"
	// m6StepsFile lists the IDs of the steps that tests of the gate sign, one on each line. gate:m6:repair cancels the open ones
	// among them, and never a step that the provision test signed.
	m6StepsFile = "../../build/gate/m6-steps"
	// m6TestCell is the cell that the signed-step refusal tests name. It is in the catalog, and no test creates it.
	m6TestCell = "dev-cell-2"
)

// portal runs `mise run portal -- <args>` and returns the one JSON line that it prints. A refusal exits 1 and prints one error
// line with the fields error and reason, so the map is filled in that case too, together with the error.
func portal(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mise", append([]string{"run", "portal", "--"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	line := strings.TrimSpace(stdout.String())
	if line == "" {
		if runErr == nil {
			runErr = fmt.Errorf("portal %s printed nothing", strings.Join(args, " "))
		}
		return nil, fmt.Errorf("portal %s: %w: %s", strings.Join(args, " "), runErr, stderr.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return nil, fmt.Errorf("portal %s printed no JSON object: %q: %w", strings.Join(args, " "), line, err)
	}
	if runErr != nil {
		return m, fmt.Errorf("portal %s: %w: %v", strings.Join(args, " "), runErr, m["error"])
	}
	return m, nil
}

// hostSteps returns the steps of the journal of the host service by step ID. It reads them through mise run hostsvc:serve -- steps.
func hostSteps(t *testing.T) map[string]mgmtapi.StepStatus {
	t.Helper()
	out, err := exec.Command("mise", "run", "hostsvc:serve", "--", "steps").Output()
	if err != nil {
		t.Fatalf("mise run hostsvc:serve -- steps: %v", err)
	}
	var doc struct {
		Steps   []mgmtapi.StepStatus `json:"steps"`
		Corrupt bool                 `json:"corrupt"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &doc); err != nil {
		t.Fatalf("hostsvc:serve -- steps printed no journal: %v\n%s", err, out)
	}
	if doc.Corrupt {
		t.Fatal("the step journal of the host service is corrupt. Run: mise run hostsvc:serve -- steps --reset")
	}
	steps := map[string]mgmtapi.StepStatus{}
	for _, s := range doc.Steps {
		steps[s.ID] = s
	}
	return steps
}

// hostLog returns the lines of the log of the host service that carry the request ID, as one string. The refusal handlers log
// the detail in the field reason and as the message, and each line has the field request_id. The router logs "request denied"
// with the reason. A line is logged at most once for each reason in each 10 s, so a test that waits for a reason waits for the
// line.
func hostLog(t *testing.T, requestID string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		data, err := os.ReadFile(hostsvcLogFile)
		if err != nil {
			t.Fatalf("read the host service log: %v", err)
		}
		var found []string
		for line := range strings.SplitSeq(string(data), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) == nil && rec["request_id"] == requestID {
				found = append(found, line)
			}
		}
		if len(found) > 0 || time.Now().After(deadline) {
			return strings.Join(found, "\n")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// stepSign signs the step with `mise run mgmt -- step sign`, which reads the JSON of the step on standard input, and returns the
// DSSE envelope. The command signs only a step with step.TestDigest, and it records nothing.
func stepSign(t *testing.T, s step.Step) []byte {
	t.Helper()
	if s.BootstrapSHA256 != step.TestDigest {
		t.Fatalf("stepSign signs only a step with step.TestDigest, not %q", s.BootstrapSHA256)
	}
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("mise", "run", "mgmt", "--", "step", "sign")
	cmd.Stdin = bytes.NewReader(body)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("mise run mgmt -- step sign: %v\n%s", err, stdout.String())
	}
	return bytes.TrimSpace(stdout.Bytes())
}

// testStep returns a step for cell with the digest of the tests, valid from now for the minimum lifetime of an hour, with the
// cluster object of the topology and a new ID.
func testStep(t *testing.T, cell string) step.Step {
	t.Helper()
	topo := clusterObject(t, cell)
	now := time.Now().UTC().Truncate(time.Second)
	return step.Step{ID: step.NewID(), Env: pocEnv, Cell: cell, Kind: step.KindCellCreate, Version: 1, KeyEpoch: mgmtStatus(t).Signed.Epoch,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Cluster: topo, BootstrapSHA256: step.TestDigest}
}

// recordM6Step adds the ID of a step to build/gate/m6-steps, so that gate:m6:repair can cancel it after an aborted run.
func recordM6Step(t *testing.T, id string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(m6StepsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(m6StepsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, id); err != nil {
		t.Fatal(err)
	}
}

// cellControllerCert mints the SVID of the cell controller, as a compromised dev-cp could.
func cellControllerCert(t *testing.T) tls.Certificate {
	t.Helper()
	certPEM, keyPEM := mintSVID(t, cpClusterName, cellControllerID, 10*time.Minute)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// mgmtAPICert mints the SVID of mgmtd, the only peer that the key and spec routes admit.
func mgmtAPICert(t *testing.T) tls.Certificate {
	t.Helper()
	_, cert := svidFor(t, mgmtCluster, mgmtAPIID)
	return cert
}

// hostClient returns an HTTP client for the host service with the certificate. It trusts only the pin in ConfigMap
// mgmt-system/hostsvc-pin: the SHA-256 of the DER certificate that the server presents must equal the pin. keepAlive reuses one
// connection for the requests of the client.
func hostClient(t *testing.T, cert tls.Certificate, keepAlive bool) *http.Client {
	t.Helper()
	pin, err := hostsvc.PinFromPEM(hostsvcPinPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: hostsvc.KeyServerHost, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return fmt.Errorf("the host service presented no certificate")
			}
			if sum := sha256.Sum256(raw[0]); !bytes.Equal(sum[:], pin) {
				return fmt.Errorf("the host service certificate does not match the pin")
			}
			return nil
		}}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: !keepAlive, MaxIdleConnsPerHost: 1}}
}

// hostAnswer is the answer of the host service to one request.
type hostAnswer struct {
	Code       int
	RetryAfter string
	Body       []byte
}

// denied decodes a Denied body. It returns the request ID, and empty when the body is no Denied.
func (a hostAnswer) denied() string {
	var d mgmtapi.Denied
	if json.Unmarshal(a.Body, &d) != nil || d.Error != mgmtapi.DeniedError {
		return ""
	}
	return d.RequestID
}

// hostDoErr makes one request and returns the answer, or the error of the transport. It does not call t, so a goroutine can use it.
func hostDoErr(client *http.Client, method, path string, body io.Reader) (hostAnswer, error) {
	req, err := http.NewRequest(method, "https://"+hostsvcAddr+path, body)
	if err != nil {
		return hostAnswer{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return hostAnswer{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return hostAnswer{Code: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After"), Body: data}, nil
}

func hostDo(t *testing.T, client *http.Client, method, path string, body io.Reader) hostAnswer {
	t.Helper()
	a, err := hostDoErr(client, method, path, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return a
}

// putStepOnce sends one PUT of the step to the host service with the certificate, on a connection of its own.
func putStepOnce(t *testing.T, cert tls.Certificate, id string, envelope []byte) hostAnswer {
	t.Helper()
	return hostDo(t, hostClient(t, cert, false), http.MethodPut, mgmtapi.StepPath(id), bytes.NewReader(envelope))
}

// putStep sends the step, and sends it once more after the Retry-After of 60 s on a 503. The 503 of rate_limited, queue_full and the
// cap on requests in flight have the same body, and only Retry-After tells them from spec_behind: 60 for the first three and 30 for
// spec_behind. A 503 with Retry-After 30 goes back to the caller as it is, because spec_behind is an answer that a test checks.
func putStep(t *testing.T, cert tls.Certificate, id string, envelope []byte) hostAnswer {
	t.Helper()
	a := putStepOnce(t, cert, id, envelope)
	if a.Code == http.StatusServiceUnavailable && a.RetryAfter == "60" {
		wait, _ := strconv.Atoi(a.RetryAfter)
		t.Logf("503 with Retry-After %d: waiting before the second PUT", wait)
		time.Sleep(time.Duration(wait) * time.Second)
		a = putStepOnce(t, cert, id, envelope)
	}
	return a
}

// clusterObject returns the cluster object of a cell from harness/topology.yaml, the one that the catalog and a step carry.
func clusterObject(t *testing.T, cell string) step.ClusterRef {
	t.Helper()
	topo, err := topology.Load(topologyPath)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := topo.Cluster(cell)
	if !ok {
		t.Fatalf("cell %s is not in %s", cell, topologyPath)
	}
	return step.ClusterRef{PodSubnet: c.PodSubnet, ServiceSubnet: c.ServiceSubnet, Issuer: c.Issuer}
}

// kindClusters returns the sorted list that `kind get clusters` prints.
func kindClusters(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("kind", "get", "clusters").Output()
	if err != nil {
		t.Fatalf("kind get clusters: %v", err)
	}
	names := strings.Fields(string(out))
	sort.Strings(names)
	return names
}
