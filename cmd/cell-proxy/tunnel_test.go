package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

const meshPattern = `^spiffe://dev\.env\.poc\.internal/cell/[a-z0-9-]+/mesh-view$`

// waitLine waits up to 30 seconds for a stdout line with msg, and returns it.
func waitLine(t *testing.T, out *syncBuffer, msg string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		for _, l := range jsonLines(t, out.String()) {
			if l["msg"] == msg {
				return l
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q line in:\n%s", msg, out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// runUntilCanceled runs execute in the background. The returned stop cancels it and checks for
// exit status 0.
func runUntilCanceled(t *testing.T, args []string, out *syncBuffer) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() { done <- execute(ctx, args, out) }()
	return func() {
		t.Helper()
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Fatalf("exit code %d after cancel\n%s", code, out.String())
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the command did not stop")
		}
	}
}

func assertConfigError(t *testing.T, args []string) {
	t.Helper()
	var out bytes.Buffer
	if code := execute(t.Context(), args, &out); code != 2 {
		t.Fatalf("exit code %d, want 2\n%s", code, out.String())
	}
	lines := jsonLines(t, out.String())
	if len(lines) != 1 || lines[0]["level"] != "ERROR" || lines[0]["error"] == nil {
		t.Fatalf("output is %v, want one JSON error line", lines)
	}
}

func tunnelServerArgs(t *testing.T, envCA testCA) []string {
	t.Helper()
	dir := registryDir(t)
	return []string{
		"spiffe-server", "--listen", "127.0.0.1:0",
		"--peer-bundle", envCA.bundleFile(t), "--peer-trust-domain", "dev.env.poc.internal",
		"--allow-id", meshPattern, "--registry-dir", dir, "--registry-signer", signerFile(t, dir),
		"--backend", "tunnel", "--tunnel-cell", "dev-cell-1=127.0.0.1:0", "--tunnel-wait", "200ms",
		"--proof-subject", "mesh-view=cell-identity-system/celld",
	}
}

func TestTunnelBackendFlags(t *testing.T) {
	envCA := newCA(t, "dev.env.poc.internal")
	args := tunnelServerArgs(t, envCA)
	cases := map[string][]string{
		"no --tunnel-cell":             without(args, "--tunnel-cell"),
		"no address":                   with(args, "--tunnel-cell", "dev-cell-1"),
		"no cell name":                 with(args, "--tunnel-cell", "=127.0.0.1:18001"),
		"cell name not a label":        with(args, "--tunnel-cell", "Dev_Cell=127.0.0.1:18001"),
		"address with no port":         with(args, "--tunnel-cell", "dev-cell-1=127.0.0.1"),
		"same cell twice":              append(slicesClone(args), "--tunnel-cell", "dev-cell-1=127.0.0.1:18002"),
		"same address twice":           append(with(args, "--tunnel-cell", "dev-cell-1=127.0.0.1:18001"), "--tunnel-cell", "dev-cell-2=127.0.0.1:18001"),
		"negative --tunnel-wait":       with(args, "--tunnel-wait", "-1s"),
		"unparsable --tunnel-wait":     with(args, "--tunnel-wait", "soon"),
		"cell on the --listen address": with(with(args, "--listen", "127.0.0.1:18001"), "--tunnel-cell", "dev-cell-1=127.0.0.1:18001"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) { assertConfigError(t, a) })
	}
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

func TestTunnelBackendServesHubListener(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "300")
	mgmt, envCA := newCA(t, mgmtTD), newCA(t, "dev.env.poc.internal")
	serveWorkloadAPI(t, mgmt, "spiffe://mgmt.poc.internal/kiali")
	out := &syncBuffer{}
	stop := runUntilCanceled(t, tunnelServerArgs(t, envCA), out)
	line := waitLine(t, out, "tunnel_listening")
	if line["cell"] != "dev-cell-1" {
		t.Fatalf("tunnel listening line %v", line)
	}
	waitLine(t, out, "listening")
	resp, err := http.Get("http://" + line["addr"].(string) + "/api/v1/pods")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil || resp.StatusCode != http.StatusServiceUnavailable || m["error"] != "upstream_unavailable" {
		t.Fatalf("status %d, body %s", resp.StatusCode, body)
	}
	stop()
}

func tunnelArgs(t *testing.T) []string {
	t.Helper()
	return []string{
		"tunnel", "--upstream", "127.0.0.1:1", "--expect-id", "spiffe://mgmt.poc.internal/kiali",
		"--peer-bundle", newCA(t, mgmtTD).bundleFile(t), "--peer-trust-domain", mgmtTD,
	}
}

func TestTunnelModeFlags(t *testing.T) {
	args := tunnelArgs(t)
	cases := map[string][]string{
		"no --upstream":                 without(args, "--upstream"),
		"no --expect-id":                without(args, "--expect-id"),
		"no --peer-bundle":              without(args, "--peer-bundle"),
		"no --peer-trust-domain":        without(args, "--peer-trust-domain"),
		"--expect-id in another domain": with(args, "--expect-id", "spiffe://dev.env.poc.internal/kiali"),
		"--upstream not host:port":      with(args, "--upstream", "https://10.0.0.1:30445"),
		"--upstream with no port":       with(args, "--upstream", "10.0.0.1"),
		"argument that is not a flag":   append(slicesClone(args), "extra"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) { assertConfigError(t, a) })
	}
}

func TestTunnelModeNeedsCluster(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "300")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	envCA := newCA(t, "dev.env.poc.internal")
	serveWorkloadAPI(t, envCA, "spiffe://dev.env.poc.internal/cell/dev-cell-1/mesh-view")
	var out bytes.Buffer
	if code := execute(t.Context(), tunnelArgs(t), &out); code != 1 {
		t.Fatalf("exit code %d, want 1\n%s", code, out.String())
	}
	var failed map[string]any
	for _, l := range jsonLines(t, out.String()) {
		if l["level"] == "ERROR" {
			failed = l
		}
	}
	if failed == nil || !strings.Contains(failed["error"].(string), "in-cluster config") {
		t.Fatalf("no error line about the in-cluster config in:\n%s", out.String())
	}
}

func TestPromqlProxyFlags(t *testing.T) {
	args := []string{"promql-proxy", "--listen", "127.0.0.1:0", "--upstream", "http://127.0.0.1:9090"}
	cases := map[string][]string{
		"no --listen":         without(args, "--listen"),
		"no --upstream":       without(args, "--upstream"),
		"upstream not a URL":  with(args, "--upstream", "127.0.0.1:9090"),
		"upstream with query": with(args, "--upstream", "http://127.0.0.1:9090?x=1"),
		"upstream ftp":        with(args, "--upstream", "ftp://127.0.0.1:9090"),
		"argument not a flag": append(slicesClone(args), "extra"),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) { assertConfigError(t, a) })
	}
}

func TestPromqlProxyServes(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "300")
	var mu sync.Mutex
	var hits []string
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer prom.Close()
	out := &syncBuffer{}
	stop := runUntilCanceled(t, []string{"promql-proxy", "--listen", "127.0.0.1:0", "--upstream", prom.URL}, out)
	base := "http://" + waitLine(t, out, "listening")["addr"].(string)

	resp, err := http.Get(base + "/api/v1/query?query=up")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query status %d", resp.StatusCode)
	}
	resp, err = http.Post(base+"/api/v1/write", "application/x-protobuf", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write status %d, want 403", resp.StatusCode)
	}
	stop()
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 1 || hits[0] != "GET /api/v1/query?query=up" {
		t.Fatalf("upstream got %v", hits)
	}
}

// TestTunnelRunOptionsCarryTheLogger checks that the command gives RunTunnel the logger of its telemetry, so the HTTP/2
// server of the cell logs through slog.
func TestTunnelRunOptionsCarryTheLogger(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if got := cellproxy.OptionsLogger(tunnelModeConfig{}.runOptions(log)); got != log {
		t.Fatalf("the run options carry the logger %v, want the telemetry logger", got)
	}
}

// TestServeTelemetryBridgesTheStandardLogger checks that a line of the standard logger, which the HTTP/2 client of the
// hub writes, leaves the process as a JSON line on standard output.
func TestServeTelemetryBridgesTheStandardLogger(t *testing.T) {
	var prevOut io.Writer = stdlog.Writer()
	prevFlags := stdlog.Flags()
	t.Cleanup(func() { stdlog.SetOutput(prevOut); stdlog.SetFlags(prevFlags) })
	var stray bytes.Buffer
	stdlog.SetOutput(&stray)
	var out syncBuffer
	code := serveTelemetry(t.Context(), &out, func(context.Context, *telemetry.T) error {
		stdlog.Printf("http2: Transport: a line of the hub transport")
		return nil
	})
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	if stray.Len() != 0 {
		t.Errorf("the standard logger kept the plain line %q", stray.String())
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("a line of standard output is not JSON: %q", line)
		}
		found = found || m["msg"] == "http2: Transport: a line of the hub transport"
	}
	if !found {
		t.Errorf("standard output has no JSON line for the bridged message:\n%s", out.String())
	}
}

func TestTunnelModeProofFlag(t *testing.T) {
	cfg, err := parseTunnel(append(tunnelArgs(t), "--proof")[1:])
	if err != nil || !cfg.proof {
		t.Fatalf("got %+v %v", cfg, err)
	}
	if cfg, err = parseTunnel(tunnelArgs(t)[1:]); err != nil || cfg.proof {
		t.Fatalf("got %+v %v, want no proof by default", cfg, err)
	}
}
