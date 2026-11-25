package render

import (
	"fmt"
	"os"
	"path/filepath"
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
	t.Parallel()
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
		"TEMPO_EXTRA_ARGS":                      "-reporting.enabled=false -backend-worker.compaction.block-retention=48h -backend-scheduler.provider.work.compaction.block-retention=48h",
		"PYROSCOPE_EXTRA_ARGS":                  "-usage-stats.enabled=false -retention-period=48h",
		"PROMETHEUS_EXTRA_ARGS":                 "--storage.tsdb.retention.time=48h --storage.tsdb.retention.size=3GB",
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
	if len(ing) != 2 {
		t.Fatalf("lgtm has %d ingress rules, want 2", len(ing))
	}
	var from []string
	for _, f := range get[[]any](t, ing[0], "from") {
		from = append(from, fmt.Sprint(lookupOr(f, "podSelector", "matchLabels", "app.kubernetes.io/name")))
	}
	if !slices.Equal(from, []string{"otel-collector", "telemetry-gateway"}) || fmt.Sprint(lookupOr(get[[]any](t, ing[0], "ports")[0], "port")) != "4317" || len(get[[]any](t, ing[0], "ports")) != 1 {
		t.Errorf("lgtm ingress admits %v on %v, want otel-collector and telemetry-gateway on 4317 only", from, lookupOr(ing[0], "ports"))
	}
	// Flow N12: only prom-readonly reaches the Prometheus port.
	if got := fmt.Sprint(lookupOr(ing[1], "from")); got != "[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:prom-readonly]]]]" ||
		len(get[[]any](t, ing[1], "ports")) != 1 || fmt.Sprint(lookupOr(get[[]any](t, ing[1], "ports")[0], "port")) != "9090" {
		t.Errorf("lgtm admits %v on %v, want prom-readonly on 9090 only", got, lookupOr(ing[1], "ports"))
	}
}

// TestLgtmConfigRender pins the Prometheus and Loki overrides, and the Grafana password objects.
func TestLgtmConfigRender(t *testing.T) {
	t.Parallel()
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
			Retention string `json:"retention_period"`
			OTLP      struct {
				Resource struct {
					Attrs []struct {
						Action     string   `json:"action"`
						Attributes []string `json:"attributes"`
					} `json:"attributes_config"`
				} `json:"resource_attributes"`
			} `json:"otlp_config"`
		} `json:"limits_config"`
		Compactor struct {
			Enabled bool   `json:"retention_enabled"`
			Store   string `json:"delete_request_store"`
		} `json:"compactor"`
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
	if loki.Limits.Retention != "48h" || !loki.Compactor.Enabled || loki.Compactor.Store == "" {
		t.Errorf("Loki retention %q, compactor %+v, want 48h with the compactor and its delete request store on", loki.Limits.Retention, loki.Compactor)
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
	t.Parallel()
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
	want := []string{"spiffe-server", "--listen=:8444", "--backend=otlp", "--upstream=lgtm.observability-system.svc.cluster.local:4317", "--upstream-wait=2m",
		`--allow-id=^spiffe://dev\.env\.poc\.internal/(cell/[a-z0-9-]+|cp)/otel$`, "--registry-dir=/run/cell-proxy/registry",
		"--registry-signer=/run/cell-proxy/registry-signer/signer.pub", "--registry-reload=10s", "--proof-subject=otel=observability-system/otel-uplink",
		"--peer-bundle=/run/cell-proxy/peer-root/root.crt", "--peer-trust-domain=dev.env.poc.internal"}
	if !slices.Equal(args, want) {
		t.Errorf("args %q, want %q", args, want)
	}
	if got := get[string](t, named(t, get[[]any](t, spec, "volumes"), "peer-root"), "configMap", "name"); got != "peer-root" {
		t.Errorf("peer-root volume reads ConfigMap %s", got)
	}
	ann := get[map[string]any](t, dep, "spec", "template", "metadata", "annotations")
	for _, k := range []string{"poc.internal/peer-root-sha256", "poc.internal/registry-signer-sha256", "cell.poc.internal/config-checksum"} {
		if s, _ := ann[k].(string); len(s) != 64 {
			t.Errorf("annotation %s is %q, want a SHA-256", k, ann[k])
		}
	}
	if _, ok := ann["poc.internal/registry-content-sha256"]; ok {
		t.Error("the pod template carries the registry content checksum, and the render holds no registry")
	}
	// The heap peaks near 860 MiB, so the limit holds it with room, and GOMEMLIMIT sits below the limit.
	if env := envOf(t, ctr); env["GOMEMLIMIT"] != "1000MiB" || get[string](t, ctr, "resources", "limits", "memory") != "1280Mi" {
		t.Errorf("GOMEMLIMIT %q and limit %v, want 1000MiB below 1280Mi", env["GOMEMLIMIT"], lookupOr(ctr, "resources", "limits", "memory"))
	}
	if env := envOf(t, ctr); !strings.HasPrefix(env["OTEL_RESOURCE_ATTRIBUTES"], "service.instance.id=$(POD_NAME),") || get[string](t, named(t, get[[]any](t, ctr, "env"), "POD_NAME"), "valueFrom", "fieldRef", "fieldPath") != "metadata.name" {
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
	if len(flows) != 3 || !strings.HasSuffix(flows[0], "/32:8444") || !strings.HasPrefix(flows[0], "in:") {
		t.Errorf("gateway flows %v, want one ingress from a node address on 8444 and two egress rules", flows)
	}
	if !slices.Contains(flows, "out:lgtm:4317") || !slices.Contains(flows, "out:spire-server:8081") || slices.Contains(flows, "out:otel-collector:4317") {
		t.Errorf("gateway flows %v lack N8 or N10, or reach the collector", flows)
	}
	// The gateway sends its own telemetry straight to the store, and sets the row of the management collector itself.
	env := envOf(t, named(t, get[[]any](t, spec, "containers"), "cell-proxy"))
	if env["OTEL_EXPORTER_OTLP_ENDPOINT"] != "http://lgtm.observability-system.svc.cluster.local:4317" ||
		env["OTEL_RESOURCE_ATTRIBUTES"] != "service.instance.id=$(POD_NAME),k8s.cluster.name=management,platform.plane=management" {
		t.Errorf("the gateway exports to %q with the resource %q, want the store and the management row",
			env["OTEL_EXPORTER_OTLP_ENDPOINT"], env["OTEL_RESOURCE_ATTRIBUTES"])
	}
}

// storeRender runs the render of the observability-store component from the tree at root, as the render of management does.
func storeRender(t *testing.T, root string) result {
	t.Helper()
	return runStubbed(t, "/ko-app/stub", "", []string{filepath.Join(root, "components", "observability-store", "render.sh")},
		append([]string{"STUB_CELL=management"}, bundleFacts...)...)
}

// storeTree copies the files of the store into a new tree that links the shared scripts, so a test can change a file.
func storeTree(t *testing.T) string {
	t.Helper()
	real := repoRoot(t)
	root := t.TempDir()
	for _, link := range []string{"scripts", "cells", "harness"} {
		if err := os.Symlink(filepath.Join(real, link), filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "components", "lib"), filepath.Join(root, "components", "lib")); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(root, "components", "observability-store"), os.DirFS(filepath.Join(real, "components", "observability-store"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "components", "observability-store", "render.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestLgtmGrafanaProvisioning checks that each dashboard has its own ConfigMap, that lgtm-grafana holds the provider file and the
// rules, that the pod mounts them where Grafana reads them, and that the checksum of the pod covers every file.
func TestLgtmGrafanaProvisioning(t *testing.T) {
	t.Parallel()
	objs := clusterComponent(t, "management", "observability-store")
	files, err := filepath.Glob("../../components/observability-store/grafana/dashboards/*.json")
	if err != nil || len(files) != 8 {
		t.Fatalf("dashboards %v (%v), want 8 files", files, err)
	}
	var sources []any
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		want, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		cm := objs["ConfigMap observability-system/lgtm-dashboard-"+name]
		if cm == nil {
			t.Errorf("no ConfigMap lgtm-dashboard-%s in %v", name, keysOfObjects(objs))
			continue
		}
		data := get[map[string]any](t, cm, "data")
		if len(data) != 1 || data[name+".json"] != string(want) {
			t.Errorf("ConfigMap lgtm-dashboard-%s has keys %v, want only %s.json with the file content", name, keysOf(data), name)
		}
		if len(want) > 256<<10 {
			t.Errorf("%s has %d bytes, want at most 256 KiB", f, len(want))
		}
		sources = append(sources, map[string]any{"configMap": map[string]any{"name": "lgtm-dashboard-" + name}})
	}
	grafana := objs["ConfigMap observability-system/lgtm-grafana"]
	if grafana == nil {
		t.Fatal("no ConfigMap lgtm-grafana")
	}
	for key, file := range map[string]string{"provider.yaml": "provider.yaml", "rules.json": "alerting/rules.json"} {
		want, err := os.ReadFile("../../components/observability-store/grafana/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if got := get[map[string]any](t, grafana, "data"); len(got) != 2 || got[key] != string(want) {
			t.Errorf("ConfigMap lgtm-grafana key %s differs from %s, or the ConfigMap has keys %v", key, file, keysOf(got))
		}
	}

	sts := objs["StatefulSet observability-system/lgtm"]
	spec := get[map[string]any](t, sts, "spec", "template", "spec")
	ctr := named(t, get[[]any](t, spec, "containers"), "lgtm")
	type mount struct{ name, subPath string }
	mounts := map[string]mount{}
	for _, m := range get[[]any](t, ctr, "volumeMounts") {
		mounts[get[string](t, m, "mountPath")] = mount{get[string](t, m, "name"), fmt.Sprint(lookupOr(m, "subPath"))}
		if strings.Contains(get[string](t, m, "mountPath"), "/otel-lgtm/") && lookupOr(m, "readOnly") != true && get[string](t, m, "name") != "data" {
			t.Errorf("mount %v is not read-only", m)
		}
	}
	for path, want := range map[string]mount{
		"/otel-lgtm/grafana/conf/provisioning/dashboards/poc.yaml":     {"grafana-config", "provider.yaml"},
		"/otel-lgtm/grafana/conf/provisioning/alerting/poc-rules.json": {"grafana-config", "rules.json"},
		"/otel-lgtm/poc-dashboards":                                    {"grafana-dashboards", "<nil>"},
	} {
		if mounts[path] != want {
			t.Errorf("mount %s is %v, want %v", path, mounts[path], want)
		}
	}
	vols := get[[]any](t, spec, "volumes")
	if got := get[string](t, named(t, vols, "grafana-config"), "configMap", "name"); got != "lgtm-grafana" {
		t.Errorf("volume grafana-config reads %s, want lgtm-grafana", got)
	}
	if got := fmt.Sprint(get[[]any](t, named(t, vols, "grafana-dashboards"), "projected", "sources")); got != fmt.Sprint(sources) {
		t.Errorf("the projected volume has sources %s, want %s", got, fmt.Sprint(sources))
	}

	t.Run("checksum", func(t *testing.T) {
		t.Parallel()
		sumOf := func(root string) string {
			r := storeRender(t, root)
			if r.err != nil {
				t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
			}
			sts := docsIn(t, r.stdout, "observability-system")["StatefulSet/lgtm"]
			return get[string](t, sts, "spec", "template", "metadata", "annotations", "poc.internal/lgtm-config-sha256")
		}
		root := storeTree(t)
		base := sumOf(root)
		if len(base) != 64 {
			t.Fatalf("checksum %q, want 64 hex digits", base)
		}
		for _, f := range []string{"dashboards/mesh.json", "provider.yaml", "alerting/rules.json"} {
			p := filepath.Join(root, "components", "observability-store", "grafana", f)
			orig, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append(slices.Clone(orig), ' '), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := sumOf(root); got == base {
				t.Errorf("checksum does not change when %s gets one byte", f)
			}
			if err := os.WriteFile(p, orig, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got := sumOf(root); got != base {
			t.Errorf("checksum %s after the restore, want %s", got, base)
		}
	})
	t.Run("size cap", func(t *testing.T) {
		t.Parallel()
		root := storeTree(t)
		p := filepath.Join(root, "components", "observability-store", "grafana", "dashboards", "mesh.json")
		if err := os.WriteFile(p, []byte(strings.Repeat("x", 256<<10+1)), 0o644); err != nil {
			t.Fatal(err)
		}
		r := storeRender(t, root)
		if r.err == nil || !strings.Contains(r.stderr, "mesh.json") || !strings.Contains(r.stderr, "the limit is 262144") {
			t.Errorf("render of a dashboard above 256 KiB gave %v and %q, want a failure that names the file", r.err, r.stderr)
		}
	})
	t.Run("size cap of one ConfigMap", func(t *testing.T) {
		t.Parallel()
		root := storeTree(t)
		dir := filepath.Join(root, "components", "observability-store", "grafana")
		if err := os.WriteFile(filepath.Join(dir, "provider.yaml"), []byte(strings.Repeat("#", 130<<10)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "alerting", "rules.json"), []byte(strings.Repeat(" ", 130<<10)+"{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := storeRender(t, root)
		if r.err == nil || !strings.Contains(r.stderr, "provider.yaml") || !strings.Contains(r.stderr, "the limit is 262144") {
			t.Errorf("render of lgtm-grafana files above 256 KiB together gave %v and %q, want a failure that names the files", r.err, r.stderr)
		}
	})
}

// TestCollectorIstioAgentJob checks the job that reads the certificate expiry of each proxy on 15020. The container declares
// 15090 only, so the job keeps that port and rewrites the address.
func TestCollectorIstioAgentJob(t *testing.T) {
	t.Parallel()
	for _, cl := range collectorClusters {
		t.Run(cl.name, func(t *testing.T) {
			objs := clusterComponent(t, cl.name, "observability-system")
			var job map[string]any
			for _, j := range get[[]any](t, collectorConfig(t, objs), "receivers", "prometheus", "config", "scrape_configs") {
				if get[string](t, j, "job_name") == "istio-agent" {
					job = j.(map[string]any)
				}
			}
			if job == nil {
				t.Fatal("no job istio-agent")
			}
			if got := get[string](t, job, "metrics_path"); got != "/stats/prometheus" {
				t.Errorf("metrics_path %s, want /stats/prometheus", got)
			}
			if got := get[string](t, job, "scrape_interval"); got != "30s" {
				t.Errorf("scrape_interval %s, want 30s", got)
			}
			if got := fmt.Sprint(get[[]any](t, job, "kubernetes_sd_configs")[0]); !strings.Contains(got, "names:[apps-demo apps-sample istio-egress]") {
				t.Errorf("the job reads %s, want apps-demo, apps-sample and istio-egress", got)
			}
			relabel := fmt.Sprint(get[[]any](t, job, "relabel_configs"))
			if want := "map[regex:(.+) replacement:$$1:15020 source_labels:[__meta_kubernetes_pod_ip] target_label:__address__]"; !strings.Contains(relabel, want) {
				t.Errorf("relabel_configs %s lack the address rewrite %s", relabel, want)
			}
			for _, want := range []string{"regex:istio-proxy;15090", "action:keep", "target_label:pod", "target_label:namespace"} {
				if !strings.Contains(relabel, want) {
					t.Errorf("relabel_configs %s lack %s", relabel, want)
				}
			}
			if strings.Contains(relabel, "15090") && strings.Contains(relabel, "replacement:$$1:15090") {
				t.Errorf("relabel_configs %s scrape 15090", relabel)
			}
			if got := fmt.Sprint(get[[]any](t, job, "metric_relabel_configs")); got != "[map[action:keep regex:istio_agent_cert_expiry_seconds;default source_labels:[__name__ resource_name]]]" {
				t.Errorf("metric_relabel_configs %s, want a keep of istio_agent_cert_expiry_seconds with resource_name default", got)
			}
			if !strings.Contains(get[string](t, objs["ConfigMap observability-system/otel-collector"], "data", "config.yaml"), "$$1:15020") {
				t.Error("the replacement of the istio-agent job does not escape the dollar sign")
			}
			rule := ""
			for _, r := range get[[]any](t, objs["NetworkPolicy observability-system/collector-egress"], "spec", "egress") {
				if ports := fmt.Sprint(lookupOr(r, "ports")); strings.Contains(ports, "15020") && ports != "[map[port:15020 protocol:TCP]]" {
					t.Errorf("the collector egress rule on 15020 has ports %s, want only TCP 15020", ports)
				}
			}
			for _, r := range peerRules(t, objs["NetworkPolicy observability-system/collector-egress"], "egress") {
				if strings.Join(r.ports, ",") == "15020" {
					rule = r.peers
				}
			}
			for _, ns := range []string{"apps-demo", "apps-sample", "istio-egress"} {
				if !strings.Contains(rule, ns) {
					t.Errorf("the collector egress on 15020 is %q, want it to name %s", rule, ns)
				}
			}
		})
	}
}

// TestNetworkPolicyIstioAgentPort checks that each policy that admits the collector on 15090 also admits it on 15020, and no other peer.
func TestNetworkPolicyIstioAgentPort(t *testing.T) {
	t.Parallel()
	collectorPeer := "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:observability-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-collector]]]]"
	for _, cl := range collectorClusters {
		t.Run(cl.name, func(t *testing.T) {
			for _, name := range []string{"NetworkPolicy apps-demo/workloads", "NetworkPolicy apps-sample/workloads", "NetworkPolicy istio-egress/egress-gateway"} {
				np := clusterComponent(t, cl.name, "network-policy")[name]
				if np == nil {
					t.Errorf("no %s", name)
					continue
				}
				for _, r := range get[[]any](t, np, "spec", "ingress") {
					if ports := fmt.Sprint(lookupOr(r, "ports")); strings.Contains(ports, "15020") && ports != "[map[port:15020 protocol:TCP]]" {
						t.Errorf("%s has an ingress rule with ports %s, want only TCP 15020", name, ports)
					}
				}
				var on15090, on15020 []string
				for _, r := range peerRules(t, np, "ingress") {
					if slices.Contains(r.ports, "15090") {
						on15090 = append(on15090, r.peers)
					}
					if slices.Contains(r.ports, "15020") {
						on15020 = append(on15020, r.peers)
					}
				}
				if !slices.Equal(on15090, []string{collectorPeer}) || !slices.Equal(on15020, []string{collectorPeer}) {
					t.Errorf("%s admits %v on 15090 and %v on 15020, want only the collector on both", name, on15090, on15020)
				}
			}
		})
	}
}

// TestSpireServerPluginTelemetry checks that container spire-server of dev-cp sends OTLP to the collector, so the plugin that it
// starts inherits the endpoint. The container sets no service name, because the plugin would take it. A cluster with no live
// cell keeps no cluster_jwt plugin and no variable.
func TestSpireServerPluginTelemetry(t *testing.T) {
	t.Parallel()
	server := func(t *testing.T, r result, cluster string) map[string]any {
		t.Helper()
		if r.err != nil {
			t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
		}
		pod := get[map[string]any](t, docs(t, hydrated(r.stdout, cluster))["StatefulSet/spire-server"], "spec", "template", "spec")
		return named(t, get[[]any](t, pod, "containers"), "spire-server")
	}
	env := envOf(t, server(t, renderCell(t, "dev-cp"), "dev-cp"))
	if env["OTEL_EXPORTER_OTLP_ENDPOINT"] != "http://otel-collector.observability-system.svc.cluster.local:4317" {
		t.Errorf("spire-server sends OTLP to %q, want the collector Service on 4317", env["OTEL_EXPORTER_OTLP_ENDPOINT"])
	}
	if env["OTEL_METRIC_EXPORT_INTERVAL"] != "15000" {
		t.Errorf("spire-server exports every %q ms, want 15000", env["OTEL_METRIC_EXPORT_INTERVAL"])
	}
	for k := range env {
		if k == "OTEL_SERVICE_NAME" || k == "OTEL_RESOURCE_ATTRIBUTES" {
			t.Errorf("spire-server sets %s, which would rename the plugin service", k)
		}
	}
	t.Run("no live cell", func(t *testing.T) {
		if env := envOf(t, server(t, renderCell(t, "dev-cp", liveEnv("management dev-cp rogue")), "dev-cp")); len(env) != 0 {
			t.Errorf("spire-server has the environment %v with no cluster_jwt section, want none", env)
		}
	})
}

// TestExportInterval checks the four emitters on the paths of the gate: mgmtd, the cell gateway, agent-ban and spire-server.
func TestExportInterval(t *testing.T) {
	t.Parallel()
	found := map[string]int{}
	for _, cr := range renderAll(t) {
		for _, c := range cr.components {
			for _, o := range c.objs {
				for _, pod := range podSpecs(o) {
					for _, ctr := range containersOf(pod) {
						name := get[string](t, ctr, "name")
						env := envOf(t, ctr)
						switch name {
						case "mgmtd", "cellgw", "agent-ban", "spire-server":
						default:
							if env["OTEL_METRIC_EXPORT_INTERVAL"] != "" && c.name != "telemetry-gateway" {
								t.Errorf("%s/%s container %s sets an export interval of %s", cr.name, c.name, name, env["OTEL_METRIC_EXPORT_INTERVAL"])
							}
							continue
						}
						if _, ok := env["OTEL_EXPORTER_OTLP_ENDPOINT"]; !ok {
							continue
						}
						found[name]++
						if env["OTEL_METRIC_EXPORT_INTERVAL"] != "15000" {
							t.Errorf("%s/%s container %s exports every %q ms, want 15000", cr.name, c.name, name, env["OTEL_METRIC_EXPORT_INTERVAL"])
						}
					}
				}
			}
		}
	}
	for _, name := range []string{"mgmtd", "cellgw", "agent-ban", "spire-server"} {
		if found[name] == 0 {
			t.Errorf("no container %s sends OTLP in any render", name)
		}
	}
}
