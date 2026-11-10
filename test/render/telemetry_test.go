package render

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// clusterComponent returns the render of one component of one cluster, as renderAll made it.
func clusterComponent(t *testing.T, cluster, name string) map[string]object {
	t.Helper()
	for _, cr := range renderAll(t) {
		if cr.name != cluster {
			continue
		}
		for _, c := range cr.components {
			if c.name == name {
				m := map[string]object{}
				for _, o := range c.objs {
					m[objName(o)] = o
				}
				return m
			}
		}
	}
	t.Fatalf("cluster %s has no component %s", cluster, name)
	return nil
}

func envOf(t *testing.T, ctr map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	list, _ := ctr["env"].([]any)
	for _, e := range list {
		out[get[string](t, e, "name")] = fmt.Sprint(lookupOr(e, "value"))
	}
	return out
}

// TestLgtmRender pins the hardening of the telemetry store: the image by digest, user 10001 with a
// read-only root file system, the writable volumes, the environment, and the NetworkPolicy that
// admits 4317 for the collector and the gateway only and gives the pod no egress.
func TestLgtmRender(t *testing.T) {
	objs := clusterComponent(t, "management", "observability-store")
	sts := objs["StatefulSet observability-system/lgtm"]
	if sts == nil {
		t.Fatalf("no StatefulSet lgtm in %v", keysOfObjects(objs))
	}
	spec := get[map[string]any](t, sts, "spec", "template", "spec")
	ctr := named(t, get[[]any](t, spec, "containers"), "lgtm")
	if got, want := get[string](t, ctr, "image"), "docker.io/grafana/otel-lgtm:0.38.0@sha256:75cdf892daffadf3763ef61c16a6d7f8586216fce0b40bba7874a0b053121084"; got != want {
		t.Errorf("image %s, want %s", got, want)
	}
	for _, f := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
		if got := get[float64](t, spec, "securityContext", f); got != 10001 {
			t.Errorf("%s is %v, want 10001", f, got)
		}
	}
	if get[bool](t, spec, "securityContext", "runAsNonRoot") != true || get[bool](t, spec, "automountServiceAccountToken") != false {
		t.Error("the pod must run as non-root and mount no service account token")
	}
	sc := get[map[string]any](t, ctr, "securityContext")
	if sc["readOnlyRootFilesystem"] != true || sc["allowPrivilegeEscalation"] != false || fmt.Sprint(lookupOr(sc, "capabilities", "drop")) != "[ALL]" {
		t.Errorf("container securityContext %v, want a read-only root file system, no escalation and no capability", sc)
	}
	// The environment is exactly the set of the brief, with the password setting that works in this image.
	wantEnv := map[string]string{
		"GF_AUTH_ANONYMOUS_ENABLED":             "false",
		"GF_SECURITY_ADMIN_PASSWORD":            "$__file{/run/grafana-admin/password}",
		"GF_PLUGINS_PREINSTALL_AUTO_UPDATE":     "false",
		"GF_PLUGINS_PREINSTALL_DISABLED":        "true",
		"GF_ANALYTICS_REPORTING_ENABLED":        "false",
		"GF_ANALYTICS_CHECK_FOR_UPDATES":        "false",
		"GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES": "false",
		"TEMPO_EXTRA_ARGS":                      "-reporting.enabled=false",
		"PYROSCOPE_EXTRA_ARGS":                  "-usage-stats.enabled=false",
	}
	if got := envOf(t, ctr); fmt.Sprint(got) != fmt.Sprint(wantEnv) {
		t.Errorf("env %v, want %v", got, wantEnv)
	}
	for k := range envOf(t, ctr) {
		if strings.HasPrefix(k, "OTEL_EXPORTER_OTLP") || strings.HasSuffix(k, "__FILE") {
			t.Errorf("env %s must not be set: an OTEL_EXPORTER_OTLP variable adds an export, and Grafana ignores a __FILE variable in this image", k)
		}
	}
	mounts := map[string]string{}
	for _, m := range get[[]any](t, ctr, "volumeMounts") {
		mounts[get[string](t, m, "mountPath")] = get[string](t, m, "name")
	}
	for path, vol := range map[string]string{"/data": "data", "/var/tempo": "tempo", "/tmp": "tmp", "/run/grafana-admin": "grafana-admin"} {
		if mounts[path] != vol {
			t.Errorf("mount %s is %q, want %s", path, mounts[path], vol)
		}
	}
	for _, v := range []string{"tempo", "tmp"} {
		if _, ok := lookup(named(t, get[[]any](t, spec, "volumes"), v), "emptyDir"); !ok {
			t.Errorf("volume %s is not an emptyDir", v)
		}
	}
	if got := fmt.Sprint(lookupOr(get[[]any](t, sts, "spec", "volumeClaimTemplates")[0], "spec", "resources", "requests", "storage")); got != "10Gi" {
		t.Errorf("data volume %s, want 10Gi", got)
	}
	if got := get[string](t, named(t, get[[]any](t, spec, "volumes"), "grafana-admin"), "secret", "secretName"); got != "grafana-admin" {
		t.Errorf("the admin password volume reads Secret %s, want grafana-admin", got)
	}

	svc := objs["Service observability-system/lgtm"]
	var ports []int
	for _, p := range get[[]any](t, svc, "spec", "ports") {
		ports = append(ports, int(get[float64](t, p, "port")))
	}
	if !slices.Equal(ports, []int{4317, 3000, 9090}) {
		t.Errorf("Service lgtm ports %v, want 4317, 3000, 9090", ports)
	}

	np := objs["NetworkPolicy observability-system/lgtm"]
	if fmt.Sprint(get[[]any](t, np, "spec", "policyTypes")) != "[Ingress Egress]" {
		t.Errorf("policyTypes %v, want Ingress and Egress", lookupOr(np, "spec", "policyTypes"))
	}
	if eg, _ := lookup(np, "spec", "egress"); eg != nil && len(eg.([]any)) != 0 {
		t.Errorf("lgtm has egress rules %v, want none", eg)
	}
	ing := get[[]any](t, np, "spec", "ingress")
	if len(ing) != 1 {
		t.Fatalf("lgtm has %d ingress rules, want 1", len(ing))
	}
	var from []string
	for _, f := range get[[]any](t, ing[0], "from") {
		from = append(from, fmt.Sprint(lookupOr(f, "podSelector", "matchLabels", "app.kubernetes.io/name")))
	}
	if !slices.Equal(from, []string{"otel-collector", "telemetry-gateway"}) || fmt.Sprint(lookupOr(get[[]any](t, ing[0], "ports")[0], "port")) != "4317" || len(get[[]any](t, ing[0], "ports")) != 1 {
		t.Errorf("lgtm ingress admits %v on %v, want otel-collector and telemetry-gateway on 4317 only", from, lookupOr(ing[0], "ports"))
	}
}

// TestLgtmConfigRender pins the Prometheus and Loki overrides, and the Grafana password objects.
func TestLgtmConfigRender(t *testing.T) {
	objs := clusterComponent(t, "management", "observability-store")
	cm := objs["ConfigMap observability-system/lgtm-config"]
	if cm == nil {
		t.Fatal("no ConfigMap lgtm-config")
	}
	var prom struct {
		OTLP struct {
			Promote []string `json:"promote_resource_attributes"`
		} `json:"otlp"`
		Storage struct {
			TSDB struct {
				Window string `json:"out_of_order_time_window"`
			} `json:"tsdb"`
		} `json:"storage"`
	}
	if err := yaml.Unmarshal([]byte(get[string](t, cm, "data", "prometheus.yaml")), &prom); err != nil {
		t.Fatal(err)
	}
	if prom.Storage.TSDB.Window != "25h" {
		t.Errorf("out_of_order_time_window %q, want 25h", prom.Storage.TSDB.Window)
	}
	for _, a := range []string{"platform.plane", "platform.cell", "deployment.environment.name", "k8s.cluster.name", "service.name"} {
		if n := countOf(prom.OTLP.Promote, a); n != 1 {
			t.Errorf("promote_resource_attributes holds %s %d times, want once", a, n)
		}
	}
	var loki struct {
		Limits struct {
			OTLP struct {
				Resource struct {
					Attrs []struct {
						Action     string   `json:"action"`
						Attributes []string `json:"attributes"`
					} `json:"attributes_config"`
				} `json:"resource_attributes"`
			} `json:"otlp_config"`
		} `json:"limits_config"`
		Analytics struct {
			Reporting bool `json:"reporting_enabled"`
		} `json:"analytics"`
	}
	if err := yaml.Unmarshal([]byte(get[string](t, cm, "data", "loki.yaml")), &loki); err != nil {
		t.Fatal(err)
	}
	var indexed []string
	for _, a := range loki.Limits.OTLP.Resource.Attrs {
		if a.Action == "index_label" {
			indexed = append(indexed, a.Attributes...)
		}
	}
	slices.Sort(indexed)
	if want := []string{"deployment.environment.name", "k8s.cluster.name", "platform.cell", "platform.plane"}; !slices.Equal(indexed, want) {
		t.Errorf("Loki index labels %v, want %v", indexed, want)
	}
	if loki.Analytics.Reporting {
		t.Error("Loki usage reporting is on")
	}

	gen := objs["Password observability-system/grafana-admin"]
	if gen == nil {
		t.Fatal("no Password generator grafana-admin")
	}
	if get[string](t, gen, "apiVersion") != "generators.external-secrets.io/v1alpha1" || get[float64](t, gen, "spec", "length") != 32 ||
		get[float64](t, gen, "spec", "symbols") != 0 || get[bool](t, gen, "spec", "allowRepeat") != true {
		t.Errorf("generator %v, want v1alpha1 with length 32, symbols 0 and allowRepeat true", gen)
	}
	es := objs["ExternalSecret observability-system/grafana-admin"]
	if es == nil {
		t.Fatal("no ExternalSecret grafana-admin")
	}
	if get[string](t, es, "spec", "refreshPolicy") != "CreatedOnce" {
		t.Errorf("refreshPolicy %v, want CreatedOnce", lookupOr(es, "spec", "refreshPolicy"))
	}
	if get[string](t, es, "metadata", "annotations", "argocd.argoproj.io/sync-options") != "SkipDryRunOnMissingResource=true" {
		t.Error("the ExternalSecret lacks SkipDryRunOnMissingResource=true")
	}
	if _, ok := lookup(es, "spec", "secretStoreRef"); ok {
		t.Error("the ExternalSecret names a store")
	}
	if _, ok := lookup(es, "spec", "target", "template", "metadata"); !ok {
		t.Error("the ExternalSecret has no target template metadata, so the Argo CD tracking label would reach the Secret")
	}
	ref := get[[]any](t, es, "spec", "dataFrom")
	if len(ref) != 1 || fmt.Sprint(lookupOr(ref[0], "sourceRef", "generatorRef", "kind")) != "Password" || fmt.Sprint(lookupOr(ref[0], "sourceRef", "generatorRef", "name")) != "grafana-admin" {
		t.Errorf("dataFrom %v, want one generatorRef to Password grafana-admin", ref)
	}
}

func countOf(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

// TestTelemetryGatewayRender pins the gateway pod: the exact arguments of cell-proxy, the node port
// with the local traffic policy, the checksums that restart the pod, the harness label on each
// object, the memory bounds, the probes, and the NetworkPolicy of the flows N2, N8, N10 and N11.
func TestTelemetryGatewayRender(t *testing.T) {
	objs := clusterComponent(t, "management", "telemetry-gateway")
	dep := objs["Deployment observability-system/telemetry-gateway"]
	if dep == nil {
		t.Fatalf("no Deployment telemetry-gateway in %v", keysOfObjects(objs))
	}
	for name, o := range objs {
		if lookupOr(o, "metadata", "labels", "cell.poc.internal/harness") != "telemetry-gateway" {
			t.Errorf("%s lacks the harness label telemetry-gateway", name)
		}
		if o["kind"] == "Namespace" {
			t.Errorf("the link component holds %s, but the namespaces bundle owns the namespace", name)
		}
	}
	if lookupOr(dep, "spec", "template", "metadata", "labels", "cell.poc.internal/harness") != "telemetry-gateway" {
		t.Error("the pod template lacks the harness label")
	}
	spec := get[map[string]any](t, dep, "spec", "template", "spec")
	if get[string](t, spec, "serviceAccountName") != "telemetry-gateway" {
		t.Errorf("serviceAccountName %v", spec["serviceAccountName"])
	}
	ctr := named(t, get[[]any](t, spec, "containers"), "cell-proxy")
	var args []string
	for _, a := range get[[]any](t, ctr, "args") {
		args = append(args, a.(string))
	}
	want := []string{"spiffe-server", "--listen=:8444", "--backend=otlp", "--upstream=lgtm.observability-system.svc:4317", "--upstream-wait=2m",
		`--allow-id=^spiffe://dev\.env\.poc\.internal/(cell/[a-z0-9-]+|cp)/otel$`, "--registry-dir=/run/cell-proxy/registry",
		"--peer-bundle=/run/cell-proxy/peer-root/root.crt", "--peer-trust-domain=dev.env.poc.internal"}
	if !slices.Equal(args, want) {
		t.Errorf("args %q, want %q", args, want)
	}
	if got := get[string](t, named(t, get[[]any](t, spec, "volumes"), "peer-root"), "configMap", "name"); got != "peer-root" {
		t.Errorf("peer-root volume reads ConfigMap %s", got)
	}
	ann := get[map[string]any](t, dep, "spec", "template", "metadata", "annotations")
	for _, k := range []string{"poc.internal/peer-root-sha256", "poc.internal/registry-content-sha256", "cell.poc.internal/config-checksum"} {
		if s, _ := ann[k].(string); len(s) != 64 {
			t.Errorf("annotation %s is %q, want a SHA-256", k, ann[k])
		}
	}
	// The heap peaks near 860 MiB, so the limit holds it with room, and GOMEMLIMIT sits below the limit.
	if env := envOf(t, ctr); env["GOMEMLIMIT"] != "1000MiB" || get[string](t, ctr, "resources", "limits", "memory") != "1280Mi" {
		t.Errorf("GOMEMLIMIT %q and limit %v, want 1000MiB below 1280Mi", env["GOMEMLIMIT"], lookupOr(ctr, "resources", "limits", "memory"))
	}
	if env := envOf(t, ctr); env["OTEL_RESOURCE_ATTRIBUTES"] != "service.instance.id=$(POD_NAME)" || get[string](t, named(t, get[[]any](t, ctr, "env"), "POD_NAME"), "valueFrom", "fieldRef", "fieldPath") != "metadata.name" {
		t.Errorf("the gateway must carry its pod name as service.instance.id, got %q", env["OTEL_RESOURCE_ATTRIBUTES"])
	}
	for _, p := range []string{"startupProbe", "readinessProbe", "livenessProbe"} {
		cmd := get[[]any](t, ctr, p, "exec", "command")
		if fmt.Sprint(cmd[:2]) != "[/ko-app/cell-proxy probe]" || !strings.Contains(fmt.Sprint(cmd), "--expect-id=spiffe://mgmt.poc.internal/telemetry") {
			t.Errorf("%s runs %v, want cell-proxy probe for the gateway ID", p, cmd)
		}
	}
	if _, ok := lookup(named(t, get[[]any](t, spec, "containers"), "spire-agent"), "image"); !ok {
		t.Error("the pod has no spire-agent sidecar")
	}

	svc := objs["Service observability-system/telemetry-listener"]
	port := get[[]any](t, svc, "spec", "ports")[0]
	if get[string](t, svc, "spec", "type") != "NodePort" || get[string](t, svc, "spec", "externalTrafficPolicy") != "Local" || get[float64](t, port, "nodePort") != 31444 {
		t.Errorf("Service %v, want a NodePort on 31444 with externalTrafficPolicy Local", svc["spec"])
	}

	np := objs["NetworkPolicy observability-system/telemetry-gateway"]
	var flows []string
	for _, r := range get[[]any](t, np, "spec", "ingress") {
		for _, f := range get[[]any](t, r, "from") {
			flows = append(flows, "in:"+fmt.Sprint(lookupOr(f, "ipBlock", "cidr"))+":"+fmt.Sprint(lookupOr(get[[]any](t, r, "ports")[0], "port")))
		}
	}
	for _, r := range get[[]any](t, np, "spec", "egress") {
		to := get[[]any](t, r, "to")[0]
		app := fmt.Sprint(lookupOr(to, "podSelector", "matchLabels", "app.kubernetes.io/name"))
		flows = append(flows, "out:"+app+":"+fmt.Sprint(lookupOr(get[[]any](t, r, "ports")[0], "port")))
	}
	if len(flows) != 4 || !strings.HasSuffix(flows[0], "/32:8444") || !strings.HasPrefix(flows[0], "in:") {
		t.Errorf("gateway flows %v, want one ingress from a node address on 8444 and three egress rules", flows)
	}
	if !slices.Contains(flows, "out:lgtm:4317") || !slices.Contains(flows, "out:spire-server:8081") || !slices.Contains(flows, "out:otel-collector:4317") {
		t.Errorf("gateway flows %v lack N8, N10 or N11", flows)
	}
}

// TestManagementCollectorRender checks the collector of each cluster. In management it sets the
// plane attributes and exports to the store, and it may reach the store only. Every other cluster
// keeps the debug exporter.
func TestManagementCollectorRender(t *testing.T) {
	for _, cluster := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
		t.Run(cluster, func(t *testing.T) {
			objs := clusterComponent(t, cluster, "observability-system")
			conf := get[string](t, objs["ConfigMap observability-system/otel-collector"], "data", "config.yaml")
			dep := objs["Deployment observability-system/otel-collector"]
			image := get[string](t, get[[]any](t, dep, "spec", "template", "spec", "containers")[0], "image")
			_, hasEgress := objs["NetworkPolicy observability-system/collector-egress"]
			if cluster != "management" {
				if !strings.Contains(conf, "debug:") || strings.Contains(conf, "otlp:\n    endpoint") || strings.Contains(conf, "resource:") || hasEgress || strings.Contains(image, "-k8s") {
					t.Errorf("the collector of %s changed: egress %v image %s\n%s", cluster, hasEgress, image, conf)
				}
				return
			}
			for _, want := range []string{"endpoint: lgtm.observability-system.svc.cluster.local:4317", "key: k8s.cluster.name", "value: management", "key: platform.plane", "action: upsert"} {
				if !strings.Contains(conf, want) {
					t.Errorf("the management collector config lacks %q:\n%s", want, conf)
				}
			}
			if strings.Contains(conf, "debug") {
				t.Errorf("the management collector keeps the debug exporter:\n%s", conf)
			}
			if !hasEgress || !strings.HasPrefix(image, "docker.io/otel/opentelemetry-collector-k8s:0.164.0@sha256:") {
				t.Errorf("egress policy %v, image %s", hasEgress, image)
			}
			eg := get[[]any](t, objs["NetworkPolicy observability-system/collector-egress"], "spec", "egress")
			if len(eg) != 1 || fmt.Sprint(lookupOr(eg[0], "to")) != "[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:lgtm]]]]" || fmt.Sprint(lookupOr(get[[]any](t, eg[0], "ports")[0], "port")) != "4317" {
				t.Errorf("collector egress %v, want lgtm on 4317 only", eg)
			}
			dns := objs["NetworkPolicy observability-system/allow-dns"]
			if fmt.Sprint(lookupOr(dns, "spec", "podSelector", "matchExpressions")) != "[map[key:app.kubernetes.io/name operator:NotIn values:[lgtm]]]" {
				t.Errorf("allow-dns selects %v, want every pod except lgtm", lookupOr(dns, "spec", "podSelector"))
			}
			col := objs["NetworkPolicy observability-system/collector"]
			if fmt.Sprint(lookupOr(col, "spec", "podSelector", "matchLabels")) != "map[app.kubernetes.io/name:otel-collector]" {
				t.Errorf("the collector ingress policy selects %v, want only the collector", lookupOr(col, "spec", "podSelector"))
			}
		})
	}
}
