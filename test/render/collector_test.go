package render

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
)

// collectorClusters are the clusters that run the collector, with the plane and the scrape jobs that
// each one adds to envoy, istiod and argocd.
var collectorClusters = []struct {
	name, plane string
	jobs        []string
}{
	{"management", "management", []string{"argocd-agent-principal", "spire-server"}},
	{"dev-cp", "environment", []string{"spire-server"}},
	{"dev-cell-1", "cell", []string{"argocd-agent"}},
	{"dev-cell-2", "cell", []string{"argocd-agent"}},
}

// collectorConfig returns the parsed config of the collector in a cluster.
func collectorConfig(t *testing.T, objs map[string]object) map[string]any {
	t.Helper()
	text := get[string](t, objs["ConfigMap observability-system/otel-collector"], "data", "config.yaml")
	var conf map[string]any
	if err := yaml.Unmarshal([]byte(text), &conf); err != nil {
		t.Fatalf("the collector config does not parse: %v\n%s", err, text)
	}
	return conf
}

// policyRule is one rule of a NetworkPolicy: its peers as text, and its ports.
type policyRule struct {
	peers string
	ports []string
}

func (r policyRule) String() string { return r.peers + " " + strings.Join(r.ports, ",") }

// peerRules returns the rules of a NetworkPolicy in one direction.
func peerRules(t *testing.T, np object, dir string) []policyRule {
	t.Helper()
	peers := "from"
	if dir == "egress" {
		peers = "to"
	}
	var out []policyRule
	rules, _ := lookup(np, "spec", dir)
	list, _ := rules.([]any)
	for _, r := range list {
		rule := policyRule{peers: fmt.Sprint(lookupOr(r, peers))}
		if pl, ok := lookup(r, "ports"); ok {
			for _, p := range pl.([]any) {
				rule.ports = append(rule.ports, fmt.Sprint(lookupOr(p, "port")))
			}
		}
		out = append(out, rule)
	}
	return out
}

// TestCollectorRender pins the collector of each cluster: the StatefulSet with its queue volume and
// the API token in the collector container only, the read-only ClusterRole, the config with the
// limits that the gateway needs, the source attributes of the row of the cluster, and the
// NetworkPolicies of the flows N11, N10, N15, N16 and N19.
func TestCollectorRender(t *testing.T) {
	for _, cl := range collectorClusters {
		t.Run(cl.name, func(t *testing.T) {
			objs := clusterComponent(t, cl.name, "observability-system")
			if _, ok := objs["Deployment observability-system/otel-collector"]; ok {
				t.Error("the bundle still renders the Deployment otel-collector")
			}
			sts := objs["StatefulSet observability-system/otel-collector"]
			if sts == nil {
				t.Fatalf("no StatefulSet otel-collector in %v", keysOfObjects(objs))
			}
			spec := get[map[string]any](t, sts, "spec", "template", "spec")
			ctr := named(t, get[[]any](t, spec, "containers"), "otel-collector")
			if got := get[string](t, ctr, "image"); !strings.HasPrefix(got, "docker.io/otel/opentelemetry-collector-k8s:0.164.0@sha256:") {
				t.Errorf("image %s, want the Kubernetes distribution 0.164.0 pinned by digest", got)
			}
			if get[float64](t, sts, "spec", "replicas") != 1 {
				t.Error("the collector must run one replica")
			}
			if lookupOr(spec, "automountServiceAccountToken") != false || get[float64](t, spec, "securityContext", "runAsUser") != 10001 {
				t.Errorf("the pod must mount no token by default and run as 10001")
			}
			// The projected token goes to the collector container only. The pod has no other container.
			if n := len(get[[]any](t, spec, "containers")); n != 1 {
				t.Errorf("the collector pod has %d containers, want 1 (no SPIRE sidecar)", n)
			}
			mounts := map[string]bool{}
			for _, m := range get[[]any](t, ctr, "volumeMounts") {
				mounts[get[string](t, m, "mountPath")] = true
			}
			if !mounts["/var/run/secrets/kubernetes.io/serviceaccount"] || !mounts["/var/lib/otelcol"] || !mounts["/etc/otelcol"] {
				t.Errorf("volume mounts %v lack the token, the queue or the config", mounts)
			}
			if lookupOr(ctr, "securityContext", "readOnlyRootFilesystem") != true {
				t.Error("the root file system must be read-only")
			}
			claims := get[[]any](t, sts, "spec", "volumeClaimTemplates")
			if len(claims) != 1 || get[string](t, claims[0], "spec", "resources", "requests", "storage") != "2Gi" || get[string](t, claims[0], "metadata", "name") != "queue" {
				t.Errorf("volume claims %v, want one claim queue of 2Gi", claims)
			}
			if env := envOf(t, ctr); env["GOMEMLIMIT"] != "600MiB" || get[string](t, ctr, "resources", "limits", "memory") != "768Mi" {
				t.Errorf("GOMEMLIMIT %q and limit %v, want 600MiB below 768Mi", env["GOMEMLIMIT"], lookupOr(ctr, "resources", "limits", "memory"))
			}
			if get[string](t, ctr, "readinessProbe", "tcpSocket", "port") != "otlp-grpc" {
				t.Errorf("readiness probe %v, want a TCP probe of 4317", ctr["readinessProbe"])
			}
			if s := get[string](t, sts, "spec", "template", "metadata", "annotations", "poc.internal/collector-config-sha256"); len(s) != 64 {
				t.Errorf("the config checksum is %q, want a SHA-256", s)
			}

			role := objs["ClusterRole otel-collector"]
			want := "[map[apiGroups:[] resources:[pods events] verbs:[list watch]] map[apiGroups:[events.k8s.io] resources:[events] verbs:[list watch]]]"
			if got := fmt.Sprint(lookupOr(role, "rules")); got != want {
				t.Errorf("ClusterRole rules %s, want %s", got, want)
			}
			if lookupOr(objs["ClusterRoleBinding otel-collector"], "metadata", "namespace") != nil || lookupOr(role, "metadata", "namespace") != nil {
				t.Error("a cluster-scoped object has a namespace")
			}

			conf := collectorConfig(t, objs)
			row := rowOfCluster(cl.name)

			// Receivers.
			grpc := get[map[string]any](t, conf, "receivers", "otlp", "protocols", "grpc")
			if grpc["endpoint"] != "0.0.0.0:4317" || get[float64](t, grpc, "max_recv_msg_size_mib") != 3 {
				t.Errorf("the gRPC receiver is %v, want 4317 with a limit of 3 MiB", grpc)
			}
			var jobs []string
			for _, j := range get[[]any](t, conf, "receivers", "prometheus", "config", "scrape_configs") {
				jobs = append(jobs, get[string](t, j, "job_name"))
				if !strings.Contains(fmt.Sprint(j), "target_label:pod") || !strings.Contains(fmt.Sprint(j), "target_label:namespace") {
					t.Errorf("job %v does not copy pod and namespace", lookupOr(j, "job_name"))
				}
			}
			wantJobs := append([]string{"envoy", "istiod", "argocd"}, cl.jobs...)
			if !slices.Equal(jobs, wantJobs) {
				t.Errorf("scrape jobs %v, want %v", jobs, wantJobs)
			}
			if !strings.Contains(get[string](t, objs["ConfigMap observability-system/otel-collector"], "data", "config.yaml"), "$$1:15014") {
				t.Error("the replacement of the istiod job does not escape the dollar sign")
			}
			objects := get[[]any](t, conf, "receivers", "k8s_objects", "objects")
			if len(objects) != 1 || get[string](t, objects[0], "name") != "events" || get[string](t, objects[0], "mode") != "watch" {
				t.Errorf("k8s_objects %v, want watch on events", objects)
			}

			// The exporter limits of the gateway: Task 2 and Task 9.
			exp := get[map[string]any](t, conf, "exporters", "otlp_grpc")
			wantEndpoint := "otel-uplink.observability-system.svc.cluster.local:4319"
			if cl.name == "management" {
				wantEndpoint = "lgtm.observability-system.svc.cluster.local:4317"
			}
			if exp["endpoint"] != wantEndpoint {
				t.Errorf("exporter endpoint %v, want %s", exp["endpoint"], wantEndpoint)
			}
			if exp["timeout"] != "15s" {
				t.Errorf("exporter timeout %v, want 15s, above the 10 s cap of the gateway plus its 1 s margin", exp["timeout"])
			}
			if get[float64](t, exp, "retry_on_failure", "max_elapsed_time") != 0 || get[bool](t, exp, "retry_on_failure", "enabled") != true {
				t.Errorf("retry_on_failure %v, want retries with no end", exp["retry_on_failure"])
			}
			ka := get[map[string]any](t, exp, "keepalive")
			if ka["time"] != "30s" || ka["timeout"] != "10s" || ka["permit_without_stream"] != true {
				t.Errorf("keepalive %v, want 30s, 10s and permit_without_stream, which the gateway enforcement allows from 10 s", ka)
			}
			q := get[map[string]any](t, exp, "sending_queue")
			if q["storage"] != "file_storage" || q["sizer"] != "bytes" || get[float64](t, q, "num_consumers") > 4 {
				t.Errorf("sending_queue %v, want file_storage, the bytes sizer and at most 4 consumers", q)
			}
			// One queue for each signal shares the volume of 2 GiB, and the queues stay below 1.5 GiB.
			if total := 3 * get[float64](t, q, "queue_size"); total > 1.5*1024*1024*1024 {
				t.Errorf("three queues of %v bytes hold %v, over 1.5 GiB", q["queue_size"], total)
			}
			b := get[map[string]any](t, q, "batch")
			// The gateway refuses a request above 3,670,016 bytes after its reset, and a request of more than
			// 1,024 resources, with ResourceExhausted and no RetryInfo. The exporter then drops the batch. The
			// batcher appends resources and bounds bytes only, and every resource holds at least the attributes
			// that the resource processor sets, so the byte bound must hold at most 1,024 such resources.
			minResource := 0.0
			for _, a := range get[[]any](t, conf, "processors", "resource", "attributes") {
				minResource += float64(len(get[string](t, a, "key")) + len(get[string](t, a, "value")) + 8)
			}
			maxSize, minSize := get[float64](t, b, "max_size"), get[float64](t, b, "min_size")
			if b["sizer"] != "bytes" || maxSize+400*1024 >= 3670016 {
				t.Errorf("batch %v, want the bytes sizer and a bound that leaves the headroom of the gateway", b)
			}
			if cl.name == "management" {
				// The store has no resource cap, so management sends requests up to the byte cap.
				if maxSize != 3000000 {
					t.Errorf("management batch max_size %v, want 3,000,000", maxSize)
				}
			} else if resources := maxSize / minResource; resources > 1024 {
				t.Errorf("a batch of %v bytes can hold %.0f resources of %v bytes, over the gateway cap of 1,024", maxSize, resources, minResource)
			}
			if minSize <= 0 || minSize > maxSize {
				t.Errorf("batch min_size %v, want above 0 and at most max_size %v, or the collector refuses the config", minSize, maxSize)
			}
			fs := get[map[string]any](t, conf, "extensions", "file_storage")
			if get[bool](t, fs, "compaction", "on_start") != true || get[bool](t, fs, "compaction", "on_rebound") != true {
				t.Errorf("file_storage %v, want compaction on start and on rebound", fs)
			}

			// The collector sends its own metrics to its own port 4317.
			readers := get[[]any](t, conf, "service", "telemetry", "metrics", "readers")
			if got := fmt.Sprint(lookupOr(readers[0], "periodic", "exporter", "otlp", "endpoint")); got != "http://127.0.0.1:4317" {
				t.Errorf("the own metrics go to %s, want http://127.0.0.1:4317", got)
			}
			if lookupOr(conf, "service", "telemetry", "logs", "encoding") != "json" {
				t.Error("the collector must log JSON")
			}
			if strings.Contains(get[string](t, objs["ConfigMap observability-system/otel-collector"], "data", "config.yaml"), "debug") {
				t.Error("the config keeps the debug exporter")
			}

			// Pipelines: every signal passes the memory limiter, a transform and the resource processor.
			pipes := get[map[string]any](t, conf, "service", "pipelines")
			for name, p := range map[string]string{"traces": "transform/otlp", "logs": "transform/otlp", "metrics": "transform/otlp", "metrics/scrape": "transform/scrape"} {
				got := fmt.Sprint(lookupOr(pipes[name], "processors"))
				want := "[memory_limiter " + p + " resource]"
				if cl.name == "management" && strings.HasPrefix(name, "metrics") {
					want = "[memory_limiter filter/alarm " + p + " resource]"
				}
				if got != want {
					t.Errorf("pipeline %s runs %s, want %s", name, got, want)
				}
				if fmt.Sprint(lookupOr(pipes[name], "exporters")) != "[otlp_grpc]" {
					t.Errorf("pipeline %s exports to %v", name, lookupOr(pipes[name], "exporters"))
				}
			}
			if fmt.Sprint(lookupOr(pipes["metrics/scrape"], "receivers")) != "[prometheus]" || fmt.Sprint(lookupOr(pipes["logs"], "receivers")) != "[otlp k8s_objects]" {
				t.Errorf("receivers: scrape %v, logs %v", lookupOr(pipes["metrics/scrape"], "receivers"), lookupOr(pipes["logs"], "receivers"))
			}

			// The resource processor sets exactly the row of the cluster.
			var set []string
			for _, a := range get[[]any](t, conf, "processors", "resource", "attributes") {
				if get[string](t, a, "action") != "upsert" {
					t.Errorf("attribute %v is not an upsert", a)
				}
				set = append(set, get[string](t, a, "key")+"="+get[string](t, a, "value"))
			}
			if want := row; !slices.Equal(set, want) {
				t.Errorf("resource attributes %v, want %v", set, want)
			}

			// Every form of every source attribute goes at every level before the values are set.
			for _, tc := range []struct {
				proc  string
				kinds map[string][]string
				all   bool
			}{
				{"transform/otlp", map[string][]string{"trace_statements": {"resource", "scope", "span", "spanevent"},
					"metric_statements": {"resource", "scope", "datapoint"}, "log_statements": {"resource", "scope", "log"}}, true},
				{"transform/scrape", map[string][]string{"metric_statements": {"resource", "scope", "datapoint"}}, false},
			} {
				proc := get[map[string]any](t, conf, "processors", tc.proc)
				if proc["error_mode"] != "propagate" {
					t.Errorf("%s has error_mode %v, want propagate", tc.proc, proc["error_mode"])
				}
				for kind, contexts := range tc.kinds {
					var got []string
					for _, s := range get[[]any](t, proc, kind) {
						got = append(got, get[string](t, s, "context"))
						re := stripRegexp(t, get[[]any](t, s, "statements")[0].(string))
						checkStripRegexp(t, tc.proc+" "+kind, re, tc.all)
					}
					if !slices.Equal(got, contexts) {
						t.Errorf("%s %s runs in the contexts %v, want %v", tc.proc, kind, got, contexts)
					}
				}
				for k := range proc {
					if k != "error_mode" && tc.kinds[k] == nil {
						t.Errorf("%s has the unexpected key %s", tc.proc, k)
					}
				}
			}
		})
	}
}

// TestManagementCollectorDropsTheAlarmSeries checks that the management collector drops every metric whose name maps
// to the series of the spoof alarm, and that no other collector has the filter. The gateway sends its own metrics
// straight to the store, so it never passes this filter.
func TestManagementCollectorDropsTheAlarmSeries(t *testing.T) {
	for _, cl := range collectorClusters {
		t.Run(cl.name, func(t *testing.T) {
			conf := collectorConfig(t, clusterComponent(t, cl.name, "observability-system"))
			procs := get[map[string]any](t, conf, "processors")
			f, ok := procs["filter/alarm"]
			if cl.name != "management" {
				if ok {
					t.Errorf("the collector of %s has the processor filter/alarm", cl.name)
				}
				return
			}
			if !ok {
				t.Fatal("the management collector has no processor filter/alarm")
			}
			if get[string](t, f, "error_mode") != "propagate" {
				t.Errorf("filter/alarm has error_mode %v, want propagate", lookupOr(f, "error_mode"))
			}
			conds := get[[]any](t, f, "metrics", "metric")
			if len(conds) != 2 {
				t.Fatalf("filter/alarm has the conditions %v, want two", conds)
			}
			var res []*regexp.Regexp
			for i, form := range []string{`^IsMatch\(name, "(.*)"\)$`, `^IsMatch\(Concat\(\[name, "_", unit\], ""\), "(.*)"\)$`} {
				m := regexp.MustCompile(form).FindStringSubmatch(conds[i].(string))
				if m == nil {
					t.Fatalf("condition %d %q does not match the form %s", i, conds[i], form)
				}
				res = append(res, regexp.MustCompile(m[1]))
			}
			// Prometheus drops a unit in braces, so the name alone matters then. Any other unit joins the name.
			drops := func(name, unit string) bool {
				return res[0].MatchString(name) || res[1].MatchString(name+"_"+unit)
			}
			// Prometheus builds the series name from the name, the unit and _total, so the filter reads the name
			// and the unit together. Each pair below maps to cellproxy_gateway_attribute_overwrites_total.
			for _, nu := range [][2]string{
				{cellproxy.OverwriteCounterName, ""}, {"cellproxy_gateway_attribute_overwrites", ""}, {"cellproxy_gateway_attribute_overwrites_total", ""},
				{"cellproxy.gateway.attribute.overwrites.total", ""}, {"cellproxy/gateway/attribute/overwrites", ""},
				{"CellProxy:Gateway:Attribute:Overwrites_total", ""}, {"cellproxy gateway attribute overwrites", ""},
				{"cellproxy.gateway.attribute", "overwrites"}, {"cellproxy.gateway", "attribute.overwrites"},
				{"cellproxy", "gateway_attribute_overwrites"}, {"cellproxy.gateway.attribute", "overwrites_total"},
				{"cellproxy\u212agateway.attribute.overwrites", ""}, {"cellproxy.gateway\u017fattribute.overwrites", ""},
				{cellproxy.OverwriteCounterName, "{override}"},
			} {
				if !drops(nu[0], nu[1]) {
					t.Errorf("filter/alarm does not drop the metric %q with the unit %q", nu[0], nu[1])
				}
			}
			for _, nu := range [][2]string{
				{"cellproxy.gateway.exports.denied", ""}, {"cellproxy.gateway.attribute.overwritesx", ""}, {"xcellproxy.gateway.attribute.overwrites", ""},
				{"cellproxy.gateway.attribute", ""}, {"http.server.duration", "s"}, {"cellproxy.gateway.attribute", "bytes"},
			} {
				if drops(nu[0], nu[1]) {
					t.Errorf("filter/alarm drops the unrelated metric %q with the unit %q", nu[0], nu[1])
				}
			}
		})
	}
}

// rowOfCluster returns the resource attributes that the collector of a cluster sets, in order.
func rowOfCluster(cluster string) []string {
	switch cluster {
	case "management":
		return []string{"k8s.cluster.name=management", "platform.plane=management"}
	case "dev-cp":
		return []string{"k8s.cluster.name=dev-cp", "platform.plane=environment", "deployment.environment.name=" + "dev"}
	default:
		return []string{"k8s.cluster.name=" + cluster, "platform.plane=cell", "deployment.environment.name=dev", "platform.cell=" + cluster}
	}
}

var deleteStatement = regexp.MustCompile(`^delete_matching_keys\(attributes, "(.*)"\)$`)

// stripRegexp returns the regular expression of a delete_matching_keys statement.
func stripRegexp(t *testing.T, statement string) *regexp.Regexp {
	t.Helper()
	m := deleteStatement.FindStringSubmatch(statement)
	if m == nil {
		t.Fatalf("statement %q is not a delete_matching_keys call", statement)
	}
	re, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("regular expression %q: %v", m[1], err)
	}
	return re
}

// checkStripRegexp checks that a strip expression matches every form of the four source attributes,
// and of the two Istio labels when all is set. A form has . _ - as separators, any case, and
// separators at both ends. It also checks that unrelated keys stay.
func checkStripRegexp(t *testing.T, what string, re *regexp.Regexp, all bool) {
	t.Helper()
	sources := [][]string{{"k8s", "cluster", "name"}, {"platform", "plane"}, {"platform", "cell"}, {"deployment", "environment", "name"}}
	istio := [][]string{{"source", "cluster"}, {"destination", "cluster"}}
	for _, parts := range sources {
		for _, sep := range []string{".", "_", "-", "/", ":", " ", "__", "/.", "@", "\u00b7", "\u212a", "\u017f", "\u212a\u017f"} {
			for _, edge := range []string{"", "_", ".", "-", "/", " ", ":"} {
				key := edge + strings.Join(parts, sep) + edge
				for _, k := range []string{key, asciiUpper(key)} {
					if !re.MatchString(k) {
						t.Errorf("%s: the expression does not match %q", what, k)
					}
				}
			}
		}
	}
	for _, parts := range istio {
		for _, k := range []string{strings.Join(parts, "_"), strings.Join(parts, "."), strings.ToUpper(strings.Join(parts, "_")), "_" + strings.Join(parts, "_")} {
			if re.MatchString(k) != all {
				t.Errorf("%s: matches %q is %v, want %v", what, k, re.MatchString(k), all)
			}
		}
	}
	for _, k := range []string{"platform.cellar", "k8s.cluster.names", "pod", "namespace", "service.name", "xplatform.cell", "k8s.cluster", "platformcell", "platform/cellar", "9platform.cell"} {
		if re.MatchString(k) {
			t.Errorf("%s: the expression matches the unrelated key %q", what, k)
		}
	}
}

// asciiUpper upper-cases ASCII letters only. strings.ToUpper turns U+212A and U+017F into K and S, which
// are letters and not the separators that the test means.
func asciiUpper(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, s)
}

// TestCollectorPolicies pins flow N11 in, and the flows out of the collector. Only the named
// namespaces send on 4317, the bundle store alone sends on 4318, and a node address reaches 4317 for
// the probe. The collector may reach its exporter target, the API server, and each scrape target of
// its cluster on the port of the job.
func TestCollectorPolicies(t *testing.T) {
	for _, cl := range collectorClusters {
		t.Run(cl.name, func(t *testing.T) {
			objs := clusterComponent(t, cl.name, "observability-system")
			senders := strings.Fields(cellEnv(t, cl.name, "COLLECTOR_SENDERS"))
			target := "otel-uplink 4319"
			if cl.name == "management" {
				target = "lgtm 4317"
			}
			col := objs["NetworkPolicy observability-system/collector"]
			if fmt.Sprint(lookupOr(col, "spec", "podSelector", "matchLabels")) != "map[app.kubernetes.io/name:otel-collector]" || fmt.Sprint(lookupOr(col, "spec", "policyTypes")) != "[Ingress]" {
				t.Fatalf("the collector policy selects %v", lookupOr(col, "spec", "podSelector"))
			}
			in := peerRules(t, col, "ingress")
			// The management gateway sends its own telemetry to the store, so only a cell or dev-cp
			// collector admits an uplink.
			wantRules := 4
			if cl.name == "management" {
				wantRules = 3
			}
			if len(in) != wantRules {
				t.Fatalf("the collector admits %d rules, want %d: %v", len(in), wantRules, in)
			}
			ns := "[map[namespaceSelector:map[matchExpressions:[map[key:kubernetes.io/metadata.name operator:In values:[" + strings.Join(senders, " ") + "]]]]]] 4317"
			if in[0].String() != ns {
				t.Errorf("rule 0 is %q, want %q", in[0], ns)
			}
			rest := in[1:]
			if cl.name != "management" {
				if want := "[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-uplink]]]] 4317"; in[1].String() != want {
					t.Errorf("rule 1 is %q, want %q", in[1], want)
				}
				rest = in[2:]
			}
			if want := "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:cell-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:bundle-store]]]] 4318"; rest[0].String() != want {
				t.Errorf("the bundle store rule is %q, want %q", rest[0], want)
			}
			if !strings.HasPrefix(rest[1].String(), "[map[ipBlock:map[cidr:") || !strings.HasSuffix(rest[1].String(), "/32]]] 4317") {
				t.Errorf("the node rule is %q, want node addresses on 4317", rest[1])
			}
			for _, r := range in {
				if strings.Contains(r.peers, "telemetry-gateway") {
					t.Errorf("the collector admits the gateway: %q", r)
				}
			}
			for _, r := range in {
				if strings.Contains(r.peers, "namespaceSelector:map[]") || strings.Contains(r.peers, "podSelector:map[]") {
					t.Errorf("rule %q admits every pod", r)
				}
			}

			egress := objs["NetworkPolicy observability-system/collector-egress"]
			out := peerRules(t, egress, "egress")
			wantTarget := "[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:" + strings.Fields(target)[0] + "]]]] " + strings.Fields(target)[1]
			if out[0].String() != wantTarget {
				t.Errorf("the exporter rule is %q, want %q", out[0], wantTarget)
			}
			hasPorts := func(ports string) bool {
				return slices.ContainsFunc(out, func(r policyRule) bool { return strings.Join(r.ports, ",") == ports })
			}
			for _, want := range []string{"6443", "443", "15090", "15014", "8082,8084"} {
				if !hasPorts(want) {
					t.Errorf("collector egress %v lacks a rule on %s", out, want)
				}
			}
			for job, port := range map[string]string{"argocd-agent": "8181", "argocd-agent-principal": "8000", "spire-server": "9988"} {
				if has, want := hasPorts(port), slices.Contains(cl.jobs, job); has != want {
					t.Errorf("collector egress has a rule on %s (%s) is %v, want %v", port, job, has, want)
				}
			}
			// Each scrape rule names its target pod and namespace, not a whole namespace.
			peerOf := func(ports string) string {
				for _, r := range out {
					if strings.Join(r.ports, ",") == ports {
						return r.peers
					}
				}
				return ""
			}
			for ports, want := range map[string]string{
				"9988":  "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:spire-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:spire-server]]]]",
				"8181":  "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:argocd]] podSelector:map[matchLabels:map[app.kubernetes.io/name:argocd-agent]]]]",
				"8000":  "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:central-view-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:argocd-agent-principal]]]]",
				"15014": "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:istio-system]] podSelector:map[matchLabels:map[app:istiod]]]]",
			} {
				if got := peerOf(ports); got != "" && got != want {
					t.Errorf("the collector egress on %s reaches %s, want %s", ports, got, want)
				}
			}
			// The Envoy job keeps only the istio-proxy container on 15090.
			for _, j := range get[[]any](t, collectorConfig(t, objs), "receivers", "prometheus", "config", "scrape_configs") {
				if get[string](t, j, "job_name") == "envoy" && !strings.Contains(fmt.Sprint(get[[]any](t, j, "relabel_configs")[0]), "regex:istio-proxy;15090") {
					t.Errorf("the envoy job keeps %v, want regex istio-proxy;15090", get[[]any](t, j, "relabel_configs")[0])
				}
			}
			// The bundle store sends OTLP to the collector pod only.
			store := clusterComponent(t, cl.name, "network-policy")["NetworkPolicy cell-system/bundle-store"]
			if eg := peerRules(t, store, "egress"); len(eg) != 1 || eg[0].String() != "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:observability-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-collector]]]] 4318" {
				t.Errorf("the bundle store egress is %v, want the collector pod on 4318", eg)
			}
			if has := hasPorts("8083,8084"); has != (cl.name == "management") {
				t.Errorf("the central argocd-server rule on 8083 is %v in %s", has, cl.name)
			}
		})
	}
}

// TestMetricsPortsAdmitOnlyTheCollector pins flow N15: the policy of each metrics port admits the
// collector pod of observability-system, and no other pod, on that port. A node address may use only
// the health port 8084 of the central repo server, which is also its metrics port.
func TestMetricsPortsAdmitOnlyTheCollector(t *testing.T) {
	collectorPeer := "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:observability-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-collector]]]]"
	type port struct{ component, policy, port string }
	ports := map[string][]port{
		"base": {{"network-policy", "NetworkPolicy argocd/argocd", "8082,8084"}, {"network-policy", "NetworkPolicy istio-system/istio-system", "15014"},
			{"network-policy", "NetworkPolicy apps-demo/workloads", "15090"}, {"network-policy", "NetworkPolicy istio-egress/egress-gateway", "15090"}},
		"dev-cell-1": {{"argocd-agent", "NetworkPolicy argocd/argocd-agent", "8181"}},
		"dev-cp":     {{"spire-server", "NetworkPolicy spire-system/spire-server-metrics", "9988"}},
		"management": {{"spire-server", "NetworkPolicy spire-system/spire-server-metrics", "9988"},
			{"central-view", "NetworkPolicy central-view-system/argocd-agent-principal", "8000"},
			{"central-view", "NetworkPolicy central-view-system/argocd-server", "8083"},
			{"central-view", "NetworkPolicy central-view-system/argocd-repo-server", "8084"}},
	}
	ports["dev-cell-2"] = ports["dev-cell-1"]
	for _, cl := range collectorClusters {
		t.Run(cl.name, func(t *testing.T) {
			for _, p := range append(slices.Clone(ports["base"]), ports[cl.name]...) {
				np := clusterComponent(t, cl.name, p.component)[p.policy]
				if np == nil {
					t.Errorf("no %s in %s", p.policy, p.component)
					continue
				}
				found := false
				for _, r := range peerRules(t, np, "ingress") {
					if strings.Join(r.ports, ",") == p.port {
						if r.peers != collectorPeer && !strings.Contains(r.peers, "ipBlock") {
							t.Errorf("%s admits %s on %s, want only the collector", p.policy, r.peers, p.port)
						}
						found = found || r.peers == collectorPeer
						continue
					}
					for _, one := range strings.Split(p.port, ",") {
						if slices.Contains(r.ports, one) && !strings.Contains(r.peers, "ipBlock") {
							t.Errorf("%s admits %s on %s through the rule %q, want the collector only", p.policy, r.peers, one, r)
						}
					}
				}
				if !found {
					t.Errorf("%s has no rule that admits the collector on %s", p.policy, p.port)
				}
			}
		})
	}
}

// TestIstiodNamesTheCluster checks that Istio gets the cluster name as its cluster ID, in istiod and
// in the sidecar values, so that source_cluster equals the cluster name and not the default
// Kubernetes. It also checks that the Envoy metrics of Istio are on, because the collector scrapes them.
func TestIstiodNamesTheCluster(t *testing.T) {
	for _, cl := range collectorClusters {
		t.Run(cl.name, func(t *testing.T) {
			objs := clusterComponent(t, cl.name, "istiod")
			dep := objs["Deployment istio-system/istiod"]
			ctr := get[[]any](t, dep, "spec", "template", "spec", "containers")[0].(map[string]any)
			found := false
			for _, e := range get[[]any](t, ctr, "env") {
				if get[string](t, e, "name") == "CLUSTER_ID" {
					found = true
					if got := get[string](t, e, "value"); got != cl.name {
						t.Errorf("istiod has CLUSTER_ID %q, want %q", got, cl.name)
					}
				}
			}
			if !found {
				t.Error("istiod sets no CLUSTER_ID")
			}
			var values struct {
				Global    struct{ MultiCluster struct{ ClusterName string } }
				Telemetry struct {
					V2 struct{ Prometheus struct{ Enabled bool } }
				}
			}
			if err := yaml.Unmarshal([]byte(get[string](t, objs["ConfigMap istio-system/istio-sidecar-injector"], "data", "values")), &values); err != nil {
				t.Fatal(err)
			}
			if values.Global.MultiCluster.ClusterName != cl.name {
				t.Errorf("the sidecar values have clusterName %q, want %q", values.Global.MultiCluster.ClusterName, cl.name)
			}
			// The merged values hold the telemetry settings, which istiod reads.
			if err := yaml.Unmarshal([]byte(get[string](t, objs["ConfigMap istio-system/values"], "data", "merged-values")), &values); err != nil {
				t.Fatal(err)
			}
			if !values.Telemetry.V2.Prometheus.Enabled {
				t.Error("telemetry.v2.prometheus.enabled is false, so Envoy emits no Istio metric")
			}
			mesh := get[string](t, objs["ConfigMap istio-system/istio"], "data", "mesh")
			if !strings.Contains(mesh, "enablePrometheusMerge: false") {
				t.Errorf("the mesh config does not set enablePrometheusMerge: false:\n%s", mesh)
			}
		})
	}
}

// TestArgoCDMetricsPortsAdmitOnlyTheCollector checks, across every NetworkPolicy of the argocd component,
// that each rule which names port 8082 (application controller) or 8084 (repo server) admits only the
// collector pod, that no rule names 7000 or 8080 (ApplicationSet controller) for another namespace, and
// that a rule with no ports, which covers every port, admits only the pods of its own namespace or the
// node address. Policies add up, so one open rule leaves the port open.
func TestArgoCDMetricsPortsAdmitOnlyTheCollector(t *testing.T) {
	collectorPeer := "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:observability-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-collector]]]]"
	// ownNamespaceOrNode says whether peers are only the pods of the namespace or node addresses.
	ownNamespaceOrNode := func(peers string) bool {
		return peers == "[map[podSelector:map[]]]" || strings.Contains(peers, "ipBlock") && !strings.Contains(peers, "namespaceSelector")
	}
	for _, cl := range collectorClusters {
		t.Run(cl.name, func(t *testing.T) {
			seen := map[string]bool{}
			for _, o := range clusterComponent(t, cl.name, "argocd") {
				if o["kind"] != "NetworkPolicy" {
					continue
				}
				for _, r := range peerRules(t, o, "ingress") {
					if len(r.ports) == 0 && !ownNamespaceOrNode(r.peers) {
						t.Errorf("%s has a rule with no ports that admits %s, so it opens every port", objName(o), r.peers)
					}
					for _, p := range r.ports {
						switch p {
						case "8082", "8084":
							seen[p] = true
							if r.peers != collectorPeer {
								t.Errorf("%s admits %s on %s, want only the collector", objName(o), r.peers, p)
							}
						case "7000", "8080":
							if !ownNamespaceOrNode(r.peers) {
								t.Errorf("%s admits %s on %s, want the pods of the namespace at most", objName(o), r.peers, p)
							}
						}
					}
				}
			}
			if !seen["8082"] || !seen["8084"] {
				t.Errorf("the argocd component has no rule for 8082 or 8084: %v", seen)
			}
		})
	}
}
