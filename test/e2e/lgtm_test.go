//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	colllogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	colltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	obsNamespace   = "observability-system"
	lgtmPod        = "lgtm-0"
	lgtmContainer  = "lgtm"
	gatewayName    = "telemetry-gateway"
	gatewayProxy   = "cell-proxy"
	gatewayService = "svc/telemetry-listener"
	telemetryID    = "spiffe://mgmt.poc.internal/telemetry"
	telemetryPort  = 31444
	// signalWait bounds the wait until a stored signal is queryable. The OpenTelemetry SDK of the
	// gateway exports its metrics every 60 seconds, and the counter reaches Prometheus after that.
	signalWait = 4 * time.Minute
)

// grafanaPassword reads the admin password from Secret grafana-admin into memory.
func grafanaPassword(t *testing.T) string {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "get", "secret", "grafana-admin", "-o", "jsonpath={.data.password}")
	if err != nil {
		t.Fatalf("read Secret grafana-admin: %v", err)
	}
	pw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil || len(pw) == 0 {
		t.Fatalf("Secret grafana-admin holds no valid password key (decode error %v)", err)
	}
	return string(pw)
}

// grafanaCall sends one request to Grafana from inside the lgtm pod, where Grafana listens on
// 127.0.0.1:3000 and the pod has curl. The credentials and the body go to curl on its standard input
// as a curl config, so no password reaches an argument list. creds may be empty for an anonymous
// call. It returns the HTTP status code and the response body.
func grafanaCall(t *testing.T, creds, method, path, body string) (int, []byte) {
	t.Helper()
	quote := func(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) }
	var cfg strings.Builder
	if creds != "" {
		fmt.Fprintf(&cfg, "user = \"%s\"\n", quote(creds))
	}
	fmt.Fprintf(&cfg, "request = \"%s\"\nurl = \"http://127.0.0.1:3000%s\"\n", method, path)
	if body != "" {
		fmt.Fprintf(&cfg, "header = \"Content-Type: application/json\"\ndata = \"%s\"\n", quote(body))
	}
	cfg.WriteString("silent\nshow-error\nmax-time = 30\nwrite-out = \"\\n%{http_code}\"\n")
	out, err := kubectl(t, mgmtCluster, cfg.String(), "-n", obsNamespace, "exec", "-i", lgtmPod, "-c", lgtmContainer, "--", "curl", "-K", "-")
	if err != nil {
		t.Fatalf("grafana %s %s: %v", method, path, err)
	}
	i := strings.LastIndex(out, "\n")
	code, err := strconv.Atoi(strings.TrimSpace(out[i+1:]))
	if err != nil {
		t.Fatalf("grafana %s %s: no status code in %q", method, path, out)
	}
	return code, []byte(out[:i])
}

// grafanaQuery posts one query to Grafana /api/ds/query with the admin password, read from Secret
// grafana-admin into memory, and returns the response body. datasource is the uid prometheus, loki
// or tempo. The query is PromQL, LogQL or TraceQL. Prometheus and Loki queries cover the last hour,
// and Tempo queries the last 30 minutes. The call fails the test on any status but 200.
func grafanaQuery(t *testing.T, datasource, query string) []byte {
	t.Helper()
	return grafanaQueryFrom(t, datasource, query, "")
}

// grafanaQueryFrom is grafanaQuery with a start time of Grafana syntax, for example now-15m. An empty
// from keeps the default of the data source.
func grafanaQueryFrom(t *testing.T, datasource, query, fromOverride string) []byte {
	t.Helper()
	q := map[string]any{"refId": "A", "datasource": map[string]string{"uid": datasource, "type": datasource}}
	from := "now-1h"
	switch datasource {
	case "prometheus":
		q["expr"], q["range"], q["instant"], q["intervalMs"], q["maxDataPoints"] = query, true, false, 15000, 1000
	case "loki":
		q["expr"], q["queryType"], q["maxLines"] = query, "range", 200
	case "tempo":
		q["query"], q["queryType"], q["tableType"], q["limit"] = query, "traceql", "traces", 50
		from = "now-30m"
	default:
		t.Fatalf("grafanaQuery: unknown data source %q", datasource)
	}
	if fromOverride != "" {
		from = fromOverride
	}
	body, err := json.Marshal(map[string]any{"queries": []any{q}, "from": from, "to": "now"})
	if err != nil {
		t.Fatal(err)
	}
	code, resp := grafanaCall(t, "admin:"+grafanaPassword(t), "POST", "/api/ds/query", string(body))
	if code != 200 {
		t.Fatalf("grafana query %s %q: HTTP %d: %s", datasource, query, code, resp)
	}
	return resp
}

// frame is one data frame of a /api/ds/query answer.
type frame struct {
	Schema struct {
		Fields []struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"fields"`
	} `json:"schema"`
	Data struct {
		Values [][]json.RawMessage `json:"values"`
	} `json:"data"`
}

func framesOf(t *testing.T, resp []byte) []frame {
	t.Helper()
	var r struct {
		Results map[string]struct {
			Error  string  `json:"error"`
			Frames []frame `json:"frames"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		t.Fatalf("decode the query answer: %v: %.300s", err, resp)
	}
	a, ok := r.Results["A"]
	if !ok || a.Error != "" {
		t.Fatalf("the query answer has no result A or an error %q: %.300s", a.Error, resp)
	}
	return a.Frames
}

// sample is one time series of a Prometheus answer: its labels and its last value.
type sample struct {
	labels map[string]string
	last   float64
}

// promSamples runs a PromQL query over the last hour and returns each series that has a point.
func promSamples(t *testing.T, query string) []sample {
	t.Helper()
	var out []sample
	for _, f := range framesOf(t, grafanaQuery(t, "prometheus", query)) {
		if len(f.Schema.Fields) < 2 || len(f.Data.Values) < 2 || len(f.Data.Values[1]) == 0 {
			continue
		}
		var vals []*float64
		if err := json.Unmarshal(mustJSON(t, f.Data.Values[1]), &vals); err != nil {
			t.Fatalf("decode the values of a Prometheus frame: %v", err)
		}
		for i := len(vals) - 1; i >= 0; i-- {
			if vals[i] != nil {
				out = append(out, sample{labels: f.Schema.Fields[1].Labels, last: *vals[i]})
				break
			}
		}
	}
	return out
}

// lokiLine is one line of a Loki answer with its stream labels and structured metadata.
type lokiLine struct {
	labels map[string]string
	line   string
}

// lokiLines runs a LogQL query over the last hour and returns its lines.
func lokiLines(t *testing.T, query string) []lokiLine {
	t.Helper()
	return lokiLinesFrom(t, query, "")
}

// lokiLinesFrom is lokiLines with a start time of Grafana syntax, for example now-15m.
func lokiLinesFrom(t *testing.T, query, from string) []lokiLine {
	t.Helper()
	var out []lokiLine
	for _, f := range framesOf(t, grafanaQueryFrom(t, "loki", query, from)) {
		li, ll := -1, -1
		for i, fld := range f.Schema.Fields {
			switch fld.Name {
			case "labels":
				li = i
			case "Line":
				ll = i
			}
		}
		if li < 0 || ll < 0 || len(f.Data.Values) <= max(li, ll) {
			continue
		}
		var labels []map[string]any
		var lines []string
		if err := json.Unmarshal(mustJSON(t, f.Data.Values[li]), &labels); err != nil {
			t.Fatalf("decode the labels of a Loki frame: %v", err)
		}
		if err := json.Unmarshal(mustJSON(t, f.Data.Values[ll]), &lines); err != nil {
			t.Fatalf("decode the lines of a Loki frame: %v", err)
		}
		for i := range lines {
			m := map[string]string{}
			for k, v := range labels[i] {
				m[k] = fmt.Sprint(v)
			}
			out = append(out, lokiLine{labels: m, line: lines[i]})
		}
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tempoTraces runs a TraceQL query over the last 30 minutes and returns how many traces it finds.
func tempoTraces(t *testing.T, query string) int {
	t.Helper()
	n := 0
	for _, f := range framesOf(t, grafanaQuery(t, "tempo", query)) {
		if len(f.Data.Values) > 0 {
			n += len(f.Data.Values[0])
		}
	}
	return n
}

// readyPod returns the name and UID of the Ready pod with the app label in a namespace of management.
func readyPod(t *testing.T, ns, app string) (name, uid string) {
	t.Helper()
	return readyPodIn(t, mgmtCluster, ns, app)
}

// readyPodIn returns the name and UID of the Ready pod with the app label in a namespace of a cluster.
func readyPodIn(t *testing.T, cluster, ns, app string) (name, uid string) {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "get", "pods", "-l", "app.kubernetes.io/name="+app, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				Name, UID string
				Deleted   *string `json:"deletionTimestamp"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct{ Type, Status string } `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &pods); err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		for _, c := range p.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" && p.Metadata.Deleted == nil {
				return p.Metadata.Name, p.Metadata.UID
			}
		}
	}
	t.Fatalf("no Ready pod with the label app.kubernetes.io/name=%s in %s/%s", app, cluster, ns)
	return "", ""
}

// mgmtPodIP returns the pod address of a pod in management.
func mgmtPodIP(t *testing.T, ns, pod string) string {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", ns, "get", "pod", pod, "-o", "jsonpath={.status.podIP}")
	if err != nil || net.ParseIP(strings.TrimSpace(out)) == nil {
		t.Fatalf("pod address of %s/%s: %q, %v", ns, pod, out, err)
	}
	return strings.TrimSpace(out)
}

// bakedPlugins are the plugins that /api/plugins?embedded=0 lists for the image
// grafana/otel-lgtm v0.38.0 with GF_PLUGINS_PREINSTALL_DISABLED=true: the core data source and
// panel plugins of Grafana 13.2.4. vendor/README.md records the list. The image downloads the
// Drilldown apps and grafana-llm-app from grafana.com at start, and none of them is here.
var bakedPlugins = []string{
	"alertlist", "alertmanager", "annolist", "barchart", "bargauge", "candlestick", "canvas", "cloudwatch",
	"dashlist", "elasticsearch", "flamegraph", "gauge", "geomap", "gettingstarted", "grafana-azure-monitor-datasource",
	"grafana-postgresql-datasource", "grafana-pyroscope-datasource", "grafana-testdata-datasource", "graphite",
	"heatmap", "histogram", "influxdb", "jaeger", "logs", "logstable", "loki", "mssql", "mysql", "news", "nodeGraph",
	"opentsdb", "piechart", "prometheus", "stackdriver", "stat", "state-timeline", "status-history", "table", "tempo",
	"text", "timeseries", "traces", "trend", "welcome", "xychart", "zipkin",
}

// TestM3LgtmHardened checks the store: it runs as user 10001 on a read-only root file system,
// Grafana is up and refuses an anonymous or default login, the data sources work, no downloaded
// plugin is present, the pod cannot reach the Internet, and no pod reaches its ports.
func TestM3LgtmHardened(t *testing.T) {
	needProbeImage(t)
	statefulSetReady(t, mgmtCluster, obsNamespace, "lgtm")

	if out, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "exec", lgtmPod, "-c", lgtmContainer, "--", "id", "-u"); err != nil || strings.TrimSpace(out) != "10001" {
		t.Fatalf("id -u in %s prints %q (error %v), want 10001", lgtmPod, out, err)
	}
	ro, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "get", "pod", lgtmPod, "-o", "jsonpath={.spec.containers[0].securityContext.readOnlyRootFilesystem}")
	if err != nil || ro != "true" {
		t.Errorf("readOnlyRootFilesystem of %s is %q (error %v), want true", lgtmPod, ro, err)
	}

	if code, body := grafanaCall(t, "", "GET", "/api/health", ""); code != 200 {
		t.Fatalf("/api/health answers HTTP %d: %s", code, body)
	}
	if code, _ := grafanaCall(t, "", "GET", "/api/datasources", ""); code != 401 {
		t.Errorf("an anonymous GET /api/datasources answers HTTP %d, want 401", code)
	}
	// Grafana creates the admin user with the password admin unless it reads the generated one.
	if code, _ := grafanaCall(t, "admin:admin", "GET", "/api/datasources", ""); code != 401 {
		t.Errorf("the default login admin:admin answers HTTP %d, want 401", code)
	}

	creds := "admin:" + grafanaPassword(t)
	code, body := grafanaCall(t, creds, "GET", "/api/datasources", "")
	if code != 200 {
		t.Fatalf("GET /api/datasources with the admin password answers HTTP %d: %s", code, body)
	}
	var sources []struct{ UID, Name, Type string }
	if err := json.Unmarshal(body, &sources); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, s := range sources {
		have[s.UID] = true
	}
	// The image also provisions Pyroscope. vendor/README.md records it.
	for _, uid := range []string{"prometheus", "loki", "tempo", "pyroscope"} {
		if !have[uid] {
			t.Errorf("the data sources %v lack %q", sources, uid)
			continue
		}
		code, body := grafanaCall(t, creds, "GET", "/api/datasources/uid/"+uid+"/health", "")
		var h struct{ Status, Message string }
		_ = json.Unmarshal(body, &h)
		if code != 200 || h.Status != "OK" {
			t.Errorf("health of data source %s: HTTP %d, status %q, message %q", uid, code, h.Status, h.Message)
		}
	}
	if len(sources) != 4 {
		t.Errorf("Grafana has %d data sources %v, want prometheus, loki, tempo and pyroscope", len(sources), sources)
	}

	code, body = grafanaCall(t, creds, "GET", "/api/plugins?embedded=0", "")
	if code != 200 {
		t.Fatalf("GET /api/plugins answers HTTP %d: %s", code, body)
	}
	var plugins []struct{ ID, Type string }
	if err := json.Unmarshal(body, &plugins); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range plugins {
		ids = append(ids, p.ID)
	}
	slices.Sort(ids)
	want := slices.Clone(bakedPlugins)
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Errorf("/api/plugins?embedded=0 lists %v, want the baked-in plugins %v", ids, want)
	}

	// The pod has no route out and no DNS. The dial fails within 5 seconds, by name and by address, so
	// a failed name lookup does not hide an open route. The resolver of curl can outlast the timeouts
	// of curl itself, so timeout ends the process at 5 seconds.
	for _, target := range []string{"https://grafana.com", "https://1.1.1.1"} {
		t.Run("egress "+target, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			_, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "exec", lgtmPod, "-c", lgtmContainer, "--",
				"timeout", "5", "curl", "-sS", "--connect-timeout", "5", "-o", "/dev/null", target)
			if err == nil {
				t.Errorf("curl to %s from %s succeeded, want a failure", target, lgtmPod)
			} else if d := time.Since(start); d > 9*time.Second {
				t.Errorf("curl to %s from %s took %s to fail, want within 5 seconds of the process start", target, lgtmPod, d)
			}
		})
	}

	// The pod listens on more ports than its Service names: Loki push 3100, Tempo 3200, Pyroscope ingest
	// 4040 and OTLP over HTTP 4318 accept data, and Prometheus on 9090 accepts remote write and OTLP. No
	// pod may reach any of them.
	ip := mgmtPodIP(t, obsNamespace, lgtmPod)
	for _, port := range []int{4317, 9090, 3000, 3100, 3200, 4040, 4318} {
		t.Run("ingress "+strconv.Itoa(port), func(t *testing.T) {
			t.Parallel()
			if err := probeFromFreshNamespace(t, mgmtCluster, ip, port, 3*time.Second); err != nil {
				t.Errorf("a pod in a fresh namespace reaches lgtm on %d: %v", port, err)
			}
		})
	}
}

// collectorConn dials the OTLP gRPC port of the management collector through a port-forward. The
// collector listens in plaintext, as every workload of management reaches it.
func collectorConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	return plaintextConn(t, portForward(t, mgmtCluster, obsNamespace, "svc/otel-collector", 4317))
}

// plaintextConn dials a plaintext gRPC address, for example a port-forward to a collector.
func plaintextConn(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestM3ManagementSignals checks that the management collector reaches the store with its own source
// attributes, and that a pod of management cannot forge the signals of a cell through it. Traces and
// logs of management carry k8s.cluster.name and platform.plane. No workload of management sends
// metrics yet. So the test sends a gauge, a log and a span through the collector with every source
// attribute spoofed at the resource, at the record and at the data point, in several forms. The stores
// must return them with the values of management only. No series, stream or trace of management may
// carry platform_cell, deployment_environment_name, source_cluster, or a cluster of a cell.
func TestM3ManagementSignals(t *testing.T) {
	marker := "m3mgmt" + randomHex(t, 4)
	metric := "m3_spoof_" + marker
	res := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		strAttr("service.name", "m3-mgmt"), strAttr("k8s.cluster.name", "dev-cell-1"), strAttr("platform.plane", "cell"),
		strAttr("platform.cell", "dev-cell-1"), strAttr("deployment.environment.name", "dev"), strAttr("Platform-Cell", "dev-cell-1")}}
	sendSignals(t, collectorConn(t), res, marker,
		strAttr("m3.marker", marker), strAttr("platform_cell", "dev-cell-1"), strAttr("platform.cell", "dev-cell-1"), strAttr("k8s_cluster_name", "dev-cell-1"),
		strAttr("k8s.cluster.name", "dev-cell-1"), strAttr("platform_plane", "cell"), strAttr("deployment_environment_name", "dev"),
		strAttr("source_cluster", "dev-cell-1"), strAttr("destination_cluster", "dev-cell-1"), strAttr("_Platform_Cell_", "dev-cell-1"))
	forged := []string{"platform_cell", "deployment_environment_name", "source_cluster", "destination_cluster"}

	waitFor(t, "the metric "+metric+" with the management labels in Prometheus", signalWait, func() (bool, string) {
		s := promSamples(t, fmt.Sprintf(`{__name__=%q}`, metric))
		if len(s) != 1 {
			return false, fmt.Sprintf("%d series", len(s))
		}
		l := s[0].labels
		if l["k8s_cluster_name"] != "management" || l["platform_plane"] != "management" {
			t.Fatalf("the series %s has the labels %v, want k8s_cluster_name and platform_plane management", metric, l)
		}
		for _, k := range forged {
			if v, ok := l[k]; ok {
				t.Errorf("the series %s keeps the forged label %s=%s: %v", metric, k, v, l)
			}
		}
		return true, ""
	})
	for _, q := range []string{
		`{k8s_cluster_name="management", platform_cell!=""}`, `{k8s_cluster_name="management", source_cluster!=""}`,
		`{k8s_cluster_name="management", deployment_environment_name!=""}`, `{platform_cell=~".+", platform_plane="management"}`,
		`{k8s_cluster_name=~"dev-cell-.+", platform_plane="management"}`,
	} {
		if n := len(promSamples(t, q)); n != 0 {
			t.Errorf("Prometheus returns %d series for %s, want none", n, q)
		}
	}

	waitFor(t, "the log with the management labels in Loki", signalWait, func() (bool, string) {
		lines := lokiLines(t, fmt.Sprintf(`{k8s_cluster_name="management", platform_plane="management"} |= %q`, marker))
		if len(lines) != 1 {
			return false, fmt.Sprintf("%d lines", len(lines))
		}
		for k, v := range lines[0].labels {
			for _, f := range forged {
				if strings.HasPrefix(k, f) {
					t.Errorf("the log line keeps %s=%s: %v", k, v, lines[0].labels)
				}
			}
		}
		return true, ""
	})
	for _, q := range []string{`{platform_cell=~".+"} |= %q`, `{k8s_cluster_name=~"dev-cell-.+"} |= %q`, `{deployment_environment_name=~".+", platform_plane="management"} |= %q`} {
		if n := len(lokiLines(t, fmt.Sprintf(q, marker))); n != 0 {
			t.Errorf("Loki returns %d lines with the marker for %s, want none", n, q)
		}
	}

	waitFor(t, "the span with the management values in Tempo", signalWait, func() (bool, string) {
		n := tempoTraces(t, fmt.Sprintf(`{ span.m3.marker = %q && resource.k8s.cluster.name = "management" && resource.platform.plane = "management" }`, marker))
		return n == 1, fmt.Sprintf("%d traces", n)
	})
	for _, q := range []string{
		`resource.k8s.cluster.name = "dev-cell-1"`, `resource.platform.plane = "cell"`, `resource.platform.cell != nil`, `resource.deployment.environment.name != nil`,
		`span.platform_cell != nil`, `span.platform.cell != nil`, `span.k8s_cluster_name != nil`, `span.k8s.cluster.name != nil`, `span.source_cluster != nil`, `span.destination_cluster != nil`,
	} {
		if n := tempoTraces(t, fmt.Sprintf(`{ span.m3.marker = %q && %s }`, marker, q)); n != 0 {
			t.Errorf("Tempo returns %d traces for the marker with %s, want 0", n, q)
		}
	}

	waitFor(t, "a trace from management in Tempo", signalWait, func() (bool, string) {
		// The mesh sends spans for the requests of the demo workloads.
		if _, err := kubectl(t, mgmtCluster, "", "-n", "apps-demo", "exec", "deploy/client", "-c", "curl", "--", "curl", "-sS", "-o", "/dev/null", "--max-time", "10", "http://echo/hostname"); err != nil {
			return false, err.Error()
		}
		n := tempoTraces(t, `{ resource.k8s.cluster.name = "management" && resource.platform.plane = "management" }`)
		return n > 0, fmt.Sprintf("%d traces", n)
	})
	waitFor(t, "log lines with the management labels in Loki", signalWait, func() (bool, string) {
		l := lokiLines(t, `{k8s_cluster_name="management", platform_plane="management"}`)
		return len(l) > 0, fmt.Sprintf("%d lines", len(l))
	})
}

// gatewayConn dials the telemetry gateway through a port-forward to its Service, as a sender with the
// SPIFFE ID id from the SPIRE server of dev-cp. It checks the server certificate against the roots of
// management and the exact ID of the gateway.
func gatewayConn(t *testing.T, cert tls.Certificate) *grpc.ClientConn {
	t.Helper()
	return dialTLS(t, portForward(t, mgmtCluster, obsNamespace, gatewayService, 8444), gatewayTLS(t, cert))
}

// gatewayTLS returns the client TLS config for the gateway of management: the sender certificate, the
// roots of management and the exact ID of the gateway.
func gatewayTLS(t *testing.T, cert tls.Certificate) *tls.Config {
	t.Helper()
	roots := x509.NewCertPool()
	for _, c := range bundleRoots(t, mgmtCluster) {
		roots.AddCert(c)
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert},
		// SPIFFE certificates carry no DNS name, so the callback checks the chain and the URI.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			var chain []*x509.Certificate
			for _, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				chain = append(chain, c)
			}
			inter := x509.NewCertPool()
			for _, c := range chain[1:] {
				inter.AddCert(c)
			}
			if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				return err
			}
			if len(chain[0].URIs) != 1 || chain[0].URIs[0].String() != telemetryID {
				return fmt.Errorf("server ID %v, want %s", chain[0].URIs, telemetryID)
			}
			return nil
		},
	}
	return cfg
}

// gatewayConnTo is gatewayConn for a gateway that answers at addr, for example through a relay.
func gatewayConnTo(t *testing.T, addr string, cert tls.Certificate) *grpc.ClientConn {
	t.Helper()
	return dialTLS(t, addr, gatewayTLS(t, cert))
}

func dialTLS(t *testing.T, addr string, cfg *tls.Config) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatalf("dial the gateway at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// senderCert mints an SVID for the SPIFFE ID id in dev-cp, as a sender of the environment.
func senderCert(t *testing.T, id string) tls.Certificate {
	t.Helper()
	certPEM, keyPEM := mintSVID(t, envCluster, id, 10*time.Minute)
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func strAttr(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

// spoofResource claims the cluster and cell dev-cell-2, which no sender of dev-cell-1 may claim.
func spoofResource(service string) *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		strAttr("service.name", service), strAttr("k8s.cluster.name", "dev-cell-2"), strAttr("platform.cell", "dev-cell-2")}}
}

// sendMetric sends one gauge through the gateway. attrs are the attributes of the data point, and
// at is its timestamp.
func sendMetric(t *testing.T, conn *grpc.ClientConn, res *resourcepb.Resource, name string, at time.Time, attrs ...*commonpb.KeyValue) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := collmetrics.NewMetricsServiceClient(conn).Export(ctx, &collmetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: res,
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: name, Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
				Attributes: attrs, TimeUnixNano: uint64(at.UnixNano()), Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: 42},
			}}}},
		}}}},
	}}})
	if err != nil {
		t.Fatalf("export the metric %s through the gateway: %v", name, err)
	}
}

// sendSignals sends one gauge, one log and one span through conn. Each carries res and the record
// attributes attrs, and the log body and the span name carry the marker. The gauge is named
// m3_spoof_<marker>.
func sendSignals(t *testing.T, conn *grpc.ClientConn, res *resourcepb.Resource, marker string, attrs ...*commonpb.KeyValue) {
	t.Helper()
	if err := sendSignalsErr(conn, res, marker, attrs...); err != nil {
		t.Fatal(err)
	}
}

// sendSignalsErr is sendSignals, and it returns the first error of an export. It stops there.
func sendSignalsErr(conn *grpc.ClientConn, res *resourcepb.Resource, marker string, attrs ...*commonpb.KeyValue) error {
	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := collmetrics.NewMetricsServiceClient(conn).Export(ctx, &collmetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: res,
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "m3_spoof_" + marker, Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
				Attributes: attrs, TimeUnixNano: uint64(now.UnixNano()), Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: 42},
			}}}},
		}}}},
	}}}); err != nil {
		return fmt.Errorf("export the metric m3_spoof_%s: %w", marker, err)
	}
	if _, err := colllogs.NewLogsServiceClient(conn).Export(ctx, &colllogs.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: res,
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			TimeUnixNano: uint64(now.UnixNano()), SeverityText: "INFO", Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "log " + marker}},
			Attributes: attrs,
		}}}},
	}}}); err != nil {
		return fmt.Errorf("export the log: %w", err)
	}
	traceID, spanID := bytes.Repeat([]byte{0x3a}, 16), bytes.Repeat([]byte{0x5c}, 8)
	copy(traceID, []byte(marker))
	if _, err := colltrace.NewTraceServiceClient(conn).Export(ctx, &colltrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: res,
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			TraceId: traceID, SpanId: spanID, Name: "span " + marker, Kind: tracepb.Span_SPAN_KIND_INTERNAL,
			StartTimeUnixNano: uint64(now.Add(-time.Second).UnixNano()), EndTimeUnixNano: uint64(now.UnixNano()),
			Attributes: attrs,
		}}}},
	}}}); err != nil {
		return fmt.Errorf("export the span: %w", err)
	}
	return nil
}

// overwriteSeries reads each series of the resource-level overwrite counter of one sender cluster
// from Prometheus, with its last value. The key is the sorted label set, so every attribute and every
// gateway process has its own entry.
func overwriteSeries(t *testing.T, sender string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, s := range promSamples(t, fmt.Sprintf(`cellproxy_gateway_attribute_overwrites_total{sender_cluster=%q,level="resource"}`, sender)) {
		out[fmt.Sprint(s.labels)] = s.last
	}
	return out
}

// overwriteRise returns how much the counters rose since base. A counter is cumulative for one gateway
// process, and a restart of the gateway starts new series, so the rise adds the difference of each series
// that was there before, and the whole value of each new series or of a counter that started again.
func overwriteRise(base, now map[string]float64) float64 {
	rise := 0.0
	for key, v := range now {
		switch b, ok := base[key]; {
		case !ok || v < b:
			rise += v
		default:
			rise += v - b
		}
	}
	return rise
}

// TestM3GatewayResetsSpoofedAttributes sends a metric, a log and a span as cell/dev-cell-1/otel. Each
// resource claims dev-cell-2, and each record and data point also carries platform_cell=dev-cell-2.
// The stores must return each marker with the values of dev-cell-1 and with no record-level source
// key, and the overwrite counter must rise by exactly 6. Then dev-cp sends a metric that claims
// source_cluster=dev-cell-1, and Prometheus must hold dev-cp.
func TestM3GatewayResetsSpoofedAttributes(t *testing.T) {
	marker := "m3spoof" + randomHex(t, 4)
	metric := "m3_spoof_" + marker
	conn := gatewayConn(t, senderCert(t, "spiffe://"+envTrustDomain+"/cell/dev-cell-1/otel"))
	base := overwriteSeries(t, "dev-cell-1")

	sendSignals(t, conn, spoofResource("m3-spoof"), marker, strAttr("platform_cell", "dev-cell-2"), strAttr("m3.marker", marker))

	waitFor(t, "the metric "+metric+" with the values of dev-cell-1 in Prometheus", signalWait, func() (bool, string) {
		s := promSamples(t, fmt.Sprintf(`{__name__=%q}`, metric))
		if len(s) != 1 {
			return false, fmt.Sprintf("%d series", len(s))
		}
		l := s[0].labels
		if l["k8s_cluster_name"] != "dev-cell-1" || l["platform_cell"] != "dev-cell-1" || l["platform_plane"] != "cell" {
			t.Fatalf("the series %s has the labels %v, want k8s_cluster_name and platform_cell dev-cell-1 and platform_plane cell", metric, l)
		}
		return true, ""
	})
	waitFor(t, "the log with the values of dev-cell-1 in Loki", signalWait, func() (bool, string) {
		lines := lokiLines(t, fmt.Sprintf(`{k8s_cluster_name="dev-cell-1"} |= %q`, marker))
		if len(lines) != 1 {
			return false, fmt.Sprintf("%d lines", len(lines))
		}
		l := lines[0].labels
		if l["k8s_cluster_name"] != "dev-cell-1" || l["platform_cell"] != "dev-cell-1" {
			t.Fatalf("the log line has the labels %v, want k8s_cluster_name and platform_cell dev-cell-1", l)
		}
		return true, ""
	})
	for _, l := range lokiLines(t, fmt.Sprintf(`{k8s_cluster_name="dev-cell-1"} |= %q`, marker)) {
		// A record attribute with the name of an index label would show as <name>_extracted.
		if _, ok := l.labels["platform_cell_extracted"]; ok {
			t.Errorf("the log line keeps the record attribute platform_cell: %v", l.labels)
		}
	}
	if n := len(lokiLines(t, fmt.Sprintf(`{platform_cell="dev-cell-2"} |= %q`, marker))); n != 0 {
		t.Errorf("Loki returns %d lines with the marker under platform_cell dev-cell-2, want 0", n)
	}
	waitFor(t, "the span with the values of dev-cell-1 in Tempo", signalWait, func() (bool, string) {
		n := tempoTraces(t, fmt.Sprintf(`{ span.m3.marker = %q && resource.k8s.cluster.name = "dev-cell-1" && resource.platform.cell = "dev-cell-1" }`, marker))
		return n == 1, fmt.Sprintf("%d traces", n)
	})
	for _, q := range []string{
		`resource.k8s.cluster.name = "dev-cell-2"`, `resource.platform.cell = "dev-cell-2"`, `span.platform_cell != nil`,
	} {
		if n := tempoTraces(t, fmt.Sprintf(`{ span.m3.marker = %q && %s }`, marker, q)); n != 0 {
			t.Errorf("Tempo returns %d traces for the marker with %s, want 0", n, q)
		}
	}

	waitFor(t, "the overwrite counter of dev-cell-1 to rise by 6", signalWait, func() (bool, string) {
		got := overwriteRise(base, overwriteSeries(t, "dev-cell-1"))
		if got > 6 {
			t.Fatalf("the overwrite counter of dev-cell-1 rose by %v, want exactly 6", got)
		}
		return got == 6, fmt.Sprintf("rose by %v", got)
	})

	// dev-cp sends a metric that claims another cluster in an Istio label.
	cp := gatewayConn(t, senderCert(t, "spiffe://"+envTrustDomain+"/cp/otel"))
	cpMetric := "m3_cp_" + marker
	sendMetric(t, cp, &resourcepb.Resource{Attributes: []*commonpb.KeyValue{strAttr("service.name", "m3-spoof")}}, cpMetric, time.Now(),
		strAttr("source_cluster", "dev-cell-1"))
	waitFor(t, "the metric "+cpMetric+" with source_cluster dev-cp in Prometheus", signalWait, func() (bool, string) {
		s := promSamples(t, fmt.Sprintf(`{__name__=%q}`, cpMetric))
		if len(s) != 1 {
			return false, fmt.Sprintf("%d series", len(s))
		}
		if s[0].labels["source_cluster"] != "dev-cp" || s[0].labels["k8s_cluster_name"] != "dev-cp" {
			t.Fatalf("the series %s has the labels %v, want source_cluster and k8s_cluster_name dev-cp", cpMetric, s[0].labels)
		}
		return true, ""
	})
}

// gatewayLogs returns the cell-proxy log of the gateway since a time.
func gatewayLogs(t *testing.T, since time.Time) []map[string]any {
	t.Helper()
	pod, _ := readyPod(t, obsNamespace, gatewayName)
	out, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "logs", pod, "-c", gatewayProxy, "--since-time="+since.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	for l := range strings.SplitSeq(out, "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(l), &rec) == nil {
			recs = append(recs, rec)
		}
	}
	return recs
}

// TestM3GatewayRefusesUnknownSenders sends from IDs that the gateway must refuse: a cell that is
// not in the registry, a role other than otel, and a self-signed certificate. Each fails, and the
// gateway log names the reason.
func TestM3GatewayRefusesUnknownSenders(t *testing.T) {
	since := time.Now().Add(-2 * time.Second)
	rogue := "spiffe://" + envTrustDomain + "/cell/rogue/otel"
	agent := "spiffe://" + envTrustDomain + "/cell/dev-cell-1/argocd-agent"
	forged := "spiffe://" + envTrustDomain + "/cell/dev-cell-1/otel"
	for name, cert := range map[string]tls.Certificate{rogue: senderCert(t, rogue), agent: senderCert(t, agent), "self-signed " + forged: selfSigned(t, forged)} {
		conn := gatewayConn(t, cert)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := collmetrics.NewMetricsServiceClient(conn).Export(ctx, &collmetrics.ExportMetricsServiceRequest{})
		cancel()
		if err == nil {
			t.Errorf("%s: the gateway accepted an export, want a refusal", name)
		} else {
			t.Logf("%s: refused: %v", name, err)
		}
	}
	want := map[string]string{rogue: "peer_not_allowed", agent: "peer_not_allowed", forged: "peer_untrusted"}
	waitFor(t, "the gateway refusal lines", time.Minute, func() (bool, string) {
		var missing []string
		recs := gatewayLogs(t, since)
		for id, reason := range want {
			found := false
			for _, rec := range recs {
				found = found || rec["reason"] == reason && (rec["spiffe_id"] == id || rec["unverified_spiffe_id"] == id)
			}
			if !found {
				missing = append(missing, reason+" for "+id)
			}
		}
		return len(missing) == 0, "missing: " + strings.Join(missing, "; ")
	})
}

// TestM3OldSamplesAccepted sends a gauge with a timestamp 30 minutes in the past through the gateway.
// The store accepts it, because Prometheus holds an out-of-order window of 25 hours.
func TestM3OldSamplesAccepted(t *testing.T) {
	name := "m3_old_" + randomHex(t, 4)
	conn := gatewayConn(t, senderCert(t, "spiffe://"+envTrustDomain+"/cell/dev-cell-1/otel"))
	// A newer sample first, so the old one is out of order for the series, as a drained queue makes it.
	sendMetric(t, conn, &resourcepb.Resource{Attributes: []*commonpb.KeyValue{strAttr("service.name", "m3-old")}}, name, time.Now())
	sendMetric(t, conn, &resourcepb.Resource{Attributes: []*commonpb.KeyValue{strAttr("service.name", "m3-old")}}, name, time.Now().Add(-30*time.Minute))
	waitFor(t, "the old sample of "+name+" in Prometheus", signalWait, func() (bool, string) {
		out := grafanaQuery(t, "prometheus", fmt.Sprintf(`{__name__=%q}`, name))
		for _, f := range framesOf(t, out) {
			if len(f.Data.Values) == 2 {
				var ts []float64
				if err := json.Unmarshal(mustJSON(t, f.Data.Values[0]), &ts); err == nil {
					for _, ms := range ts {
						if time.UnixMilli(int64(ms)).Before(time.Now().Add(-20 * time.Minute)) {
							return true, ""
						}
					}
					return false, fmt.Sprintf("%d points, none older than 20 minutes", len(ts))
				}
			}
		}
		return false, "no series"
	})
}

// agentPaths returns the SPIFFE ID paths of the agents that the SPIRE server of management lists.
func agentPaths(t *testing.T) []string {
	t.Helper()
	out, err := spireServerIn(t, mgmtCluster, "agent", "list", "-socketPath", spireSocket, "-output", "json")
	if err != nil {
		t.Fatalf("spire-server agent list in %s: %v", mgmtCluster, err)
	}
	var res struct {
		Agents []struct {
			ID struct {
				TrustDomain string `json:"trust_domain"`
				Path        string `json:"path"`
			} `json:"id"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode agent list %q: %v", out, err)
	}
	var paths []string
	for _, a := range res.Agents {
		paths = append(paths, "spiffe://"+a.ID.TrustDomain+a.ID.Path)
	}
	return paths
}

// TestM3PlaneAgentsDistinct checks that the principal pod and the gateway pod each have their own
// agent ID from the pod UID, although they share a node. Stale agents stay listed, so the test
// does not count agents.
func TestM3PlaneAgentsDistinct(t *testing.T) {
	_, _, principalUID := principalPod(t)
	_, gatewayUID := readyPod(t, obsNamespace, gatewayName)
	if principalUID == gatewayUID {
		t.Fatalf("the principal and the gateway share the pod UID %s", principalUID)
	}
	paths := agentPaths(t)
	for name, uid := range map[string]string{"principal": principalUID, "gateway": gatewayUID} {
		want := "spiffe://" + mgmtTD + "/spire/agent/k8s_psat/" + mgmtCluster + "/pod/" + uid
		if !slices.Contains(paths, want) {
			t.Errorf("spire-server agent list lacks %s for the %s pod. It lists %v", want, name, paths)
		}
	}
}

// aliasSelectors returns the selectors of the node alias entry of a plane workload, as
// "<type>:<value>" strings, or nil when the SPIRE server of management holds no such entry.
func aliasSelectors(t *testing.T, alias string) []string {
	t.Helper()
	out, err := spireServerIn(t, mgmtCluster, "entry", "show", "-socketPath", spireSocket, "-output", "json")
	if err != nil {
		t.Fatalf("spire-server entry show in %s: %v", mgmtCluster, err)
	}
	var res struct {
		Entries []struct {
			ID struct {
				TrustDomain string `json:"trust_domain"`
				Path        string `json:"path"`
			} `json:"spiffe_id"`
			Selectors []struct{ Type, Value string } `json:"selectors"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode entry show %q: %v", out, err)
	}
	for _, e := range res.Entries {
		if e.ID.TrustDomain == mgmtTD && e.ID.Path == alias {
			var sel []string
			for _, s := range e.Selectors {
				sel = append(sel, s.Type+":"+s.Value)
			}
			slices.Sort(sel)
			return sel
		}
	}
	return nil
}

// TestM3WorkloadAPIOwnSVIDOnly checks that cell-proxy of each plane pod gets only its own SVID from
// the Workload API of its sidecar. The node alias of each plane workload pins the cluster, the
// namespace and the ServiceAccount of the agent, so the sidecar of another ServiceAccount gets none
// of its entries. No second plane pod shares a namespace yet, so the test reads the selectors of
// each alias from the SPIRE server as well.
func TestM3WorkloadAPIOwnSVIDOnly(t *testing.T) {
	for _, w := range []struct{ ns, sa string }{{viewNamespace, principalName}, {obsNamespace, gatewayName}} {
		want := []string{"k8s_psat:agent_ns:" + w.ns, "k8s_psat:agent_sa:" + w.sa, "k8s_psat:cluster:" + mgmtCluster}
		if got := aliasSelectors(t, "/agents/"+w.ns+"/"+w.sa); !slices.Equal(got, want) {
			t.Errorf("the alias of %s/%s has the selectors %v, want %v", w.ns, w.sa, got, want)
		}
	}
	principal, _, _ := principalPod(t)
	gateway, _ := readyPod(t, obsNamespace, gatewayName)
	for _, tc := range []struct{ ns, pod, container, want string }{
		{viewNamespace, principal, viewCellProxy, "spiffe://mgmt.poc.internal/argocd/principal"},
		{obsNamespace, gateway, gatewayProxy, "spiffe://mgmt.poc.internal/telemetry"},
	} {
		out, err := kubectl(t, mgmtCluster, "", "-n", tc.ns, "exec", tc.pod, "-c", tc.container, "--", "/ko-app/cell-proxy", "whoami")
		if err != nil {
			t.Errorf("cell-proxy whoami in %s/%s: %v", tc.ns, tc.pod, err)
			continue
		}
		var got struct {
			IDs []string `json:"ids"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil || !slices.Equal(got.IDs, []string{tc.want}) {
			t.Errorf("cell-proxy whoami in %s/%s prints %q, want only %s", tc.ns, tc.pod, out, tc.want)
		}
	}
	// The uplink of each cluster gets only its own otel ID too.
	for _, cluster := range []string{envCluster, "dev-cell-1", "dev-cell-2"} {
		t.Run("uplink "+cluster, func(t *testing.T) { uplinkOwnSVID(t, cluster) })
	}
}

// TestM3GrafanaPasswordRotates runs mise run obs:rotate-password. Afterwards the old password gets
// 401 and the password in Secret grafana-admin gets 200.
func TestM3GrafanaPasswordRotates(t *testing.T) {
	old := grafanaPassword(t)
	cmd := exec.Command("mise", "run", "obs:rotate-password")
	cmd.Dir = "../.."
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("mise run obs:rotate-password: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	var res struct{ Rotated bool }
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); err != nil || !res.Rotated {
		t.Fatalf("obs:rotate-password printed %q, want one JSON line with rotated true", stdout.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), old) {
		t.Errorf("the output of obs:rotate-password holds the old password")
	}
	fresh := grafanaPassword(t)
	if fresh == old || len(fresh) != 32 {
		t.Fatalf("Secret grafana-admin holds a password of length %d that equals the old one: %v", len(fresh), fresh == old)
	}
	if strings.Contains(stdout.String()+stderr.String(), fresh) {
		t.Errorf("the output of obs:rotate-password holds the new password")
	}
	// A client-side apply would copy the password into this annotation.
	if out, err := kubectl(t, mgmtCluster, "", "-n", obsNamespace, "get", "secrets", "-o", `jsonpath={range .items[*]}{.metadata.annotations.kubectl\.kubernetes\.io/last-applied-configuration}{end}`); err != nil || strings.TrimSpace(out) != "" {
		t.Errorf("a Secret of %s carries the annotation last-applied-configuration (error %v)", obsNamespace, err)
	}
	if code, _ := grafanaCall(t, "admin:"+old, "GET", "/api/user", ""); code != 401 {
		t.Errorf("the old password answers HTTP %d, want 401", code)
	}
	if code, _ := grafanaCall(t, "admin:"+fresh, "GET", "/api/user", ""); code != 200 {
		t.Errorf("the new password answers HTTP %d, want 200", code)
	}
}

// TestM3GrafanaRestoreCommand makes Grafana and Secret grafana-admin differ on purpose, as a failed rotation
// does. It then runs the command that obs-rotate-password.sh prints for that case, and requires that
// Grafana accepts the password of the Secret again. The test makes no failed login on purpose: Grafana
// blocks a user for 5 minutes after 5 failed logins, and the block refuses the right password too.
func TestM3GrafanaRestoreCommand(t *testing.T) {
	secretPW := grafanaPassword(t)
	other := randomHex(t, 16)
	body, _ := json.Marshal(map[string]string{"oldPassword": secretPW, "newPassword": other, "confirmNew": other})
	if code, out := grafanaCall(t, "admin:"+secretPW, "PUT", "/api/user/password", string(body)); code != 200 {
		t.Fatalf("PUT /api/user/password answers HTTP %d: %s", code, out)
	}
	show := exec.Command("bash", "scripts/obs-rotate-password.sh", "--restore-command")
	show.Dir = "../.."
	show.Env = append(os.Environ(), "CELL=management")
	command, err := show.Output()
	if err != nil {
		t.Fatalf("obs-rotate-password.sh --restore-command: %v", err)
	}
	restore := exec.Command("bash", "-c", strings.TrimSpace(string(command)))
	restore.Dir = "../.."
	var out bytes.Buffer
	restore.Stdout, restore.Stderr = &out, &out
	if err := restore.Run(); err != nil {
		t.Fatalf("the restore command failed: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), secretPW) || strings.Contains(out.String(), other) {
		t.Errorf("the output of the restore command holds a password")
	}
	if code, _ := grafanaCall(t, "admin:"+secretPW, "GET", "/api/user", ""); code != 200 {
		t.Errorf("after the restore, the Secret password gets HTTP %d, want 200\n%s", code, out.String())
	}
}

// TestM3TelemetryNodePortAdmission dials the telemetry node port of management from a pod in dev-cp,
// in dev-cell-1 and in rogue. Only the dev-cp node address may connect.
func TestM3TelemetryNodePortAdmission(t *testing.T) {
	needProbeImage(t)
	ip := clusterFacts(t, mgmtCluster).NodeIP
	if net.ParseIP(ip) == nil {
		t.Fatalf("management node address %q", ip)
	}
	for cluster, want := range map[string]string{envCluster: "connected", "dev-cell-1": "timeout", "rogue": "timeout"} {
		t.Run(cluster, func(t *testing.T) {
			t.Parallel()
			ns := freshNamespace(t, cluster)
			if got := dialFrom(t, cluster, ns, ip, telemetryPort, 3*time.Second); got != want {
				t.Errorf("dial from %s to %s:%d gave %q, want %q", cluster, ip, telemetryPort, got, want)
			}
		})
	}
}

// TestM3CollectorIngressLimited checks that a pod in a fresh namespace of each cluster cannot reach the
// collector on 4317 or 4318. Only the named senders of the cluster may, so no other pod can send forged
// signals.
func TestM3CollectorIngressLimited(t *testing.T) {
	needProbeImage(t)
	for _, cluster := range telemetryClusters {
		pod, _ := readyPodIn(t, cluster, obsNamespace, "otel-collector")
		out, err := kubectl(t, cluster, "", "-n", obsNamespace, "get", "pod", pod, "-o", "jsonpath={.status.podIP}")
		if err != nil || net.ParseIP(strings.TrimSpace(out)) == nil {
			t.Fatalf("pod address of %s/%s in %s: %q, %v", obsNamespace, pod, cluster, out, err)
		}
		ip := strings.TrimSpace(out)
		for _, port := range []int{4317, 4318} {
			t.Run(cluster+" "+strconv.Itoa(port), func(t *testing.T) {
				t.Parallel()
				if err := probeFromFreshNamespace(t, cluster, ip, port, 3*time.Second); err != nil {
					t.Errorf("a pod in a fresh namespace of %s reaches the collector on %d: %v", cluster, port, err)
				}
			})
		}
	}
}
