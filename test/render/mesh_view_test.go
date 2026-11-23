package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

func strList(t *testing.T, v any) []string {
	t.Helper()
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

// harnessLabelled checks that every object of a render and its pod template carry the harness label.
func harnessLabelled(t *testing.T, objs map[string]object, comp string) {
	t.Helper()
	for name, o := range objs {
		if lookupOr(o, "metadata", "labels", "cell.poc.internal/harness") != comp {
			t.Errorf("%s lacks the harness label %s", name, comp)
		}
		if _, ok := lookup(o, "spec", "template"); ok && lookupOr(o, "spec", "template", "metadata", "labels", "cell.poc.internal/harness") != comp {
			t.Errorf("the pod template of %s lacks the harness label", name)
		}
	}
}

func argsOf(t *testing.T, ctr map[string]any) []string {
	t.Helper()
	return strList(t, ctr["args"])
}

// TestMeshViewCellRender pins the tunnel of a cell: the arguments of cell-proxy, one replica with
// the Recreate strategy, the token mount of the cell-proxy container alone, the probes, the
// telemetry name, and the policy that admits no connection and reaches only the relay, the SPIRE
// server, the API server and the collector.
func TestMeshViewCellRender(t *testing.T) {
	t.Parallel()
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
		t.Run(cell, func(t *testing.T) {
			objs := clusterComponent(t, cell, "mesh-view")
			harnessLabelled(t, objs, "mesh-view")
			dep := objs["Deployment mesh-view-system/mesh-view"]
			if dep == nil {
				t.Fatalf("no Deployment mesh-view in %v", keysOfObjects(objs))
			}
			if get[float64](t, dep, "spec", "replicas") != 1 || get[string](t, dep, "spec", "strategy", "type") != "Recreate" {
				t.Errorf("replicas %v and strategy %v, want 1 and Recreate", lookupOr(dep, "spec", "replicas"), lookupOr(dep, "spec", "strategy"))
			}
			spec := get[map[string]any](t, dep, "spec", "template", "spec")
			if get[string](t, spec, "serviceAccountName") != "mesh-view" || get[bool](t, spec, "automountServiceAccountToken") != false {
				t.Errorf("ServiceAccount %v with automount %v, want mesh-view and false", spec["serviceAccountName"], spec["automountServiceAccountToken"])
			}
			ctr := named(t, get[[]any](t, spec, "containers"), "cell-proxy")
			want := []string{"tunnel", "--upstream=10.9.0.9:30445", "--expect-id=spiffe://mgmt.poc.internal/kiali",
				"--peer-bundle=/run/cell-proxy/mgmt-root/root.crt", "--peer-trust-domain=mgmt.poc.internal", "--read-idle=10s", "--ping-timeout=5s", "--proof"}
			if got := argsOf(t, ctr); !slices.Equal(got, want) {
				t.Errorf("args %q, want %q", got, want)
			}
			if env := envOf(t, ctr); env["OTEL_SERVICE_NAME"] != "cell-proxy-mesh-tunnel" || env["OTEL_RESOURCE_ATTRIBUTES"] != "service.instance.id=$(POD_NAME)" {
				t.Errorf("env %v, want OTEL_SERVICE_NAME cell-proxy-mesh-tunnel and the pod name as instance", env)
			}
			// TestTunnelLivenessNoWorkloadAPI checks the liveness probe.
			for _, p := range []string{"startupProbe", "readinessProbe"} {
				if cmd := fmt.Sprint(get[[]any](t, ctr, p, "exec", "command")); cmd != "[/ko-app/cell-proxy whoami]" {
					t.Errorf("%s runs %s, want cell-proxy whoami", p, cmd)
				}
			}
			// Only the cell-proxy container mounts the token of the ServiceAccount.
			for _, c := range get[[]any](t, spec, "containers") {
				mounts := fmt.Sprint(lookupOr(c, "volumeMounts"))
				has := strings.Contains(mounts, "/var/run/secrets/kubernetes.io/serviceaccount") && strings.Contains(mounts, "kube-api-access")
				if name := lookupOr(c, "name"); has != (name == "cell-proxy") {
					t.Errorf("container %v mounts the API token: %v", name, has)
				}
			}
			if _, ok := lookup(named(t, get[[]any](t, spec, "containers"), "spire-agent"), "image"); !ok {
				t.Error("the pod has no spire-agent sidecar")
			}
			if sum, _ := lookupOr(dep, "spec", "template", "metadata", "annotations", "poc.internal/peer-root-sha256").(string); len(sum) != 64 {
				t.Errorf("peer root checksum annotation %q", sum)
			}

			ns := objs["Namespace mesh-view-system"]
			if ns == nil || lookupOr(ns, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "restricted" || lookupOr(ns, "metadata", "labels", "istio-injection") != "disabled" {
				t.Errorf("Namespace mesh-view-system is %v, want Pod Security restricted and no mesh proxy", ns)
			}

			np := objs["NetworkPolicy mesh-view-system/mesh-view"]
			if np == nil {
				t.Fatal("no NetworkPolicy mesh-view")
			}
			// A policy with the type Ingress and no ingress rule admits no connection.
			if in, ok := lookup(np, "spec", "ingress"); ok && len(in.([]any)) != 0 {
				t.Errorf("the tunnel pod admits %v, want no ingress", in)
			}
			if got := fmt.Sprint(lookupOr(np, "spec", "policyTypes")); got != "[Ingress Egress]" {
				t.Errorf("policyTypes %s, want Ingress and Egress", got)
			}
			var out []string
			for _, r := range peerRules(t, np, "egress") {
				out = append(out, r.String())
			}
			wantOut := []string{
				"[map[ipBlock:map[cidr:10.9.0.9/32]]] 30445,30081",
				"[map[ipBlock:map[cidr:172.18.0.4/32]]] 6443",
				"[map[ipBlock:map[cidr:10.111.0.1/32]]] 443",
				"[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:observability-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-collector]]]] 4317",
			}
			if !slices.Equal(out, wantOut) {
				t.Errorf("egress %q, want %q", out, wantOut)
			}
			for _, name := range []string{"NetworkPolicy mesh-view-system/default-deny", "NetworkPolicy mesh-view-system/allow-dns"} {
				if objs[name] == nil {
					t.Errorf("no %s", name)
				}
			}
			// The guard denies update, delete and connect, and every create but the bound token of its own
			// SPIRE agent and the access review of the allow-list.
			vap := objs["ValidatingAdmissionPolicy mesh-view-read-only"]
			if vap == nil || objs["ValidatingAdmissionPolicyBinding mesh-view-read-only"] == nil {
				t.Fatal("no ValidatingAdmissionPolicy and binding mesh-view-read-only")
			}
			if got := get[string](t, vap, "spec", "matchConditions", 0, "expression"); !strings.Contains(got, `"system:serviceaccount:mesh-view-system:mesh-view"`) {
				t.Errorf("the guard matches %s, want the ServiceAccount mesh-view", got)
			}
			ops := fmt.Sprint(lookupOr(vap, "spec", "matchConstraints", "resourceRules", 0, "operations"))
			if ops != "[CREATE UPDATE DELETE CONNECT]" || lookupOr(vap, "spec", "failurePolicy") != "Fail" {
				t.Errorf("the guard covers %s with failurePolicy %v", ops, lookupOr(vap, "spec", "failurePolicy"))
			}
			var all strings.Builder
			for _, v := range get[[]any](t, vap, "spec", "validations") {
				all.WriteString(get[string](t, v, "expression") + "\n")
			}
			for _, want := range []string{"'DELETE', 'CONNECT'", "request.operation != 'UPDATE'", "request.namespace == 'mesh-view-system'", "request.name == 'mesh-view'",
				"object.spec.audiences.size() == 1", "^spire-" + commonEnv(t, "POC_ENV") + "/", "boundObjectRef.kind == 'Pod'", "authentication.kubernetes.io/pod-uid", "selfsubjectaccessreviews"} {
				if !strings.Contains(all.String(), want) {
					t.Errorf("the guard expressions lack %q:\n%s", want, all.String())
				}
			}
			if strings.Contains(all.String(), "@POC_ENV@") {
				t.Error("the guard keeps a token")
			}
		})
	}
}

// TestMeshViewReadRole checks that the ClusterRole of the tunnel grants get, list and watch on the
// kinds of the tunnel allow-list and nothing else, and that ConfigMaps come only through the Role in
// istio-system.
func TestMeshViewReadRole(t *testing.T) {
	t.Parallel()
	objs := clusterComponent(t, "dev-cell-1", "mesh-view")
	role := objs["ClusterRole mesh-view-read"]
	if role == nil {
		t.Fatal("no ClusterRole mesh-view-read")
	}
	got := map[string][]string{}
	for _, r := range get[[]any](t, role, "rules") {
		if v := strList(t, lookupOr(r, "verbs")); !slices.Equal(v, []string{"get", "list", "watch"}) {
			t.Errorf("rule %v has the verbs %v, want get, list and watch", r, v)
		}
		groups := strList(t, lookupOr(r, "apiGroups"))
		if len(groups) != 1 {
			t.Fatalf("rule %v names %d API groups, want 1", r, len(groups))
		}
		got[groups[0]] = append(got[groups[0]], strList(t, lookupOr(r, "resources"))...)
	}
	want := map[string][]string{}
	for _, rr := range cellproxy.ReadResources() {
		want[rr.Group] = rr.Resources
	}
	for g := range got {
		slices.Sort(got[g])
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the ClusterRole grants\n%v\nand the tunnel allow-list reads\n%v", got, want)
	}
	for g, rs := range got {
		for _, r := range rs {
			if r == "secrets" || strings.Contains(r, "/") || r == "*" || r == "configmaps" {
				t.Errorf("the ClusterRole grants %s in %q", r, g)
			}
		}
	}
	cm := objs["Role istio-system/mesh-view-read"]
	if cm == nil || fmt.Sprint(lookupOr(get[[]any](t, cm, "rules")[0], "resources")) != "[configmaps]" || len(get[[]any](t, cm, "rules")) != 1 {
		t.Errorf("Role mesh-view-read in istio-system is %v, want ConfigMaps alone", cm)
	}
	for _, b := range []string{"ClusterRoleBinding mesh-view-read", "RoleBinding istio-system/mesh-view-read"} {
		if got := fmt.Sprint(lookupOr(objs[b], "subjects")); got != "[map[kind:ServiceAccount name:mesh-view namespace:mesh-view-system]]" {
			t.Errorf("%s binds %s", b, got)
		}
	}
}

// TestMeshViewHubRender pins the hub: the arguments with one tunnel listener for each cell, the node
// port with the local traffic policy, the ports of the ClusterIP Service, and the policies of flows
// N3, N8, N11, N12, N13, N14, N23 and N25.
func TestMeshViewHubRender(t *testing.T) {
	t.Parallel()
	objs := clusterComponent(t, "management", "mesh-view-hub")
	harnessLabelled(t, objs, "mesh-view-hub")
	dep := objs["Deployment mesh-view-system/mesh-view-hub"]
	if dep == nil {
		t.Fatalf("no Deployment mesh-view-hub in %v", keysOfObjects(objs))
	}
	if get[float64](t, dep, "spec", "replicas") != 1 || get[string](t, dep, "spec", "strategy", "type") != "Recreate" {
		t.Errorf("replicas %v and strategy %v, want 1 and Recreate", lookupOr(dep, "spec", "replicas"), lookupOr(dep, "spec", "strategy"))
	}
	spec := get[map[string]any](t, dep, "spec", "template", "spec")
	ctr := named(t, get[[]any](t, spec, "containers"), "cell-proxy")
	want := []string{"spiffe-server", "--listen=:8444", "--backend=tunnel",
		`--allow-id=^spiffe://dev\.env\.poc\.internal/cell/([a-z0-9-]+)/mesh-view$`, "--registry-dir=/run/cell-proxy/registry",
		"--registry-signer=/run/cell-proxy/registry-signer/signer.pub", "--registry-reload=10s", "--proof-subject=mesh-view=mesh-view-system/mesh-view",
		"--peer-bundle=/run/cell-proxy/peer-root/root.crt", "--peer-trust-domain=dev.env.poc.internal",
		"--tunnel-read-idle=10s", "--tunnel-ping-timeout=5s", "--tunnel-cell=dev-cell-1=:18001", "--tunnel-cell=dev-cell-2=:18002"}
	if got := argsOf(t, ctr); !slices.Equal(got, want) {
		t.Errorf("args %q, want %q", got, want)
	}
	if env := envOf(t, ctr); env["OTEL_SERVICE_NAME"] != "cell-proxy-mesh-hub" {
		t.Errorf("OTEL_SERVICE_NAME %q, want cell-proxy-mesh-hub", env["OTEL_SERVICE_NAME"])
	}
	for _, p := range []string{"startupProbe", "readinessProbe", "livenessProbe"} {
		cmd := get[[]any](t, ctr, p, "exec", "command")
		if fmt.Sprint(cmd[:2]) != "[/ko-app/cell-proxy probe]" || !strings.Contains(fmt.Sprint(cmd), "--expect-id=spiffe://mgmt.poc.internal/kiali") {
			t.Errorf("%s runs %v, want cell-proxy probe for the ID of the hub", p, cmd)
		}
	}
	if _, ok := lookup(named(t, get[[]any](t, spec, "containers"), "spire-agent"), "image"); !ok {
		t.Error("the pod has no spire-agent sidecar")
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

	svc := objs["Service mesh-view-system/mesh-view-listener"]
	port := get[[]any](t, svc, "spec", "ports")[0]
	if get[string](t, svc, "spec", "type") != "NodePort" || get[string](t, svc, "spec", "externalTrafficPolicy") != "Local" || get[float64](t, port, "nodePort") != 31445 {
		t.Errorf("Service %v, want a NodePort on 31445 with externalTrafficPolicy Local", svc["spec"])
	}
	var ports []string
	for _, p := range get[[]any](t, objs["Service mesh-view-system/mesh-view-hub"], "spec", "ports") {
		ports = append(ports, fmt.Sprint(lookupOr(p, "port")))
	}
	if !slices.Equal(ports, []string{"18001", "18002"}) {
		t.Errorf("Service mesh-view-hub ports %v, want 18001 and 18002", ports)
	}

	np := objs["NetworkPolicy mesh-view-system/mesh-view-hub"]
	var in, out []string
	for _, r := range peerRules(t, np, "ingress") {
		in = append(in, r.String())
	}
	for _, r := range peerRules(t, np, "egress") {
		out = append(out, r.String())
	}
	wantIn := []string{
		"[map[ipBlock:map[cidr:10.9.0.9/32]]] 8444",
		"[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:kiali]]]] 18001,18002",
	}
	if !slices.Equal(in, wantIn) {
		t.Errorf("hub ingress %q, want %q", in, wantIn)
	}
	if len(out) != 2 || !strings.HasSuffix(out[0], "] 8081") || !strings.HasSuffix(out[1], "] 4317") {
		t.Errorf("hub egress %q, want the SPIRE server on 8081 and the collector on 4317", out)
	}
	for _, n := range []string{"NetworkPolicy mesh-view-system/default-deny", "NetworkPolicy mesh-view-system/allow-dns"} {
		if objs[n] == nil {
			t.Errorf("no %s", n)
		}
	}
}

// TestKialiRender pins Kiali: the digest of the image, the read-only configuration, the viewer Role
// without port forwarding, the remote cluster Secret without a credential, the start order
// annotation, and the policy that admits no pod on port 20001.
func TestKialiRender(t *testing.T) {
	t.Parallel()
	objs := clusterComponent(t, "management", "mesh-view-hub")
	dep := objs["Deployment mesh-view-system/kiali"]
	if dep == nil {
		t.Fatalf("no Deployment kiali in %v", keysOfObjects(objs))
	}
	if get[string](t, dep, "spec", "strategy", "type") != "Recreate" || lookupOr(dep, "metadata", "annotations", "poc.internal/link-stage") != "after-tunnels" {
		t.Errorf("Kiali needs the Recreate strategy and the start order annotation, got %v", dep["metadata"])
	}
	ctr := get[[]any](t, dep, "spec", "template", "spec", "containers")[0].(map[string]any)
	if got, want := get[string](t, ctr, "image"), commonEnv(t, "KIALI_IMAGE"); got != want || !strings.Contains(got, "@sha256:") {
		t.Errorf("image %s, want %s", got, want)
	}
	if _, ok := lookup(dep, "spec", "template", "metadata", "annotations", "proxy.istio.io/config"); ok {
		t.Error("the pod keeps the Istio proxy annotation")
	}
	var conf map[string]any
	if err := yaml.Unmarshal([]byte(get[string](t, objs["ConfigMap mesh-view-system/kiali"], "data", "config.yaml")), &conf); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]any{
		"auth.strategy":                             "anonymous",
		"deployment.view_only_mode":                 true,
		"deployment.cluster_wide_access":            false,
		"external_services.istio.istio_api_enabled": false,
		"kubernetes_config.cluster_name":            "management",
		"clustering.ignore_home_cluster":            true,
		"external_services.prometheus.url":          "http://prom-readonly.observability-system.svc:9091",
		"external_services.prometheus.query_scope":  map[string]any{"platform_plane": "cell"},
		"external_services.tracing.enabled":         false,
		"external_services.grafana.enabled":         false,
		"kiali_feature_flags.disabled_features":     []any{"logs-tab"},
		"deployment.logger.log_format":              "json",
		"deployment.image_name":                     "quay.io/kiali/kiali",
		"deployment.version_label":                  "v2.34.1",
		"deployment.discovery_selectors": map[string]any{"default": []any{map[string]any{"matchExpressions": []any{map[string]any{
			"key": "kubernetes.io/metadata.name", "operator": "In", "values": []any{"apps-demo", "apps-sample", "istio-system", "istio-egress", "mesh-view-system"}}}}}},
		"server.observability.metrics.enabled":           false,
		"external_services.prometheus.health_check_url":  nil,
		"external_services.prometheus.auth":              nil,
		"external_services.custom_dashboards.prometheus": nil,
	} {
		parts := strings.Split(path, ".")
		got, ok := lookup(conf, anySlice(parts)...)
		if want == nil {
			if ok {
				t.Errorf("Kiali config sets %s to %v", path, got)
			}
			continue
		}
		if !ok || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("Kiali config %s is %v, want %v", path, got, want)
		}
	}
	// The config checksum of the pod follows the config that the render patched, so a new namespace
	// list restarts Kiali.
	cfgText := strings.TrimRight(get[string](t, objs["ConfigMap mesh-view-system/kiali"], "data", "config.yaml"), "\n")
	if got := get[string](t, dep, "spec", "template", "metadata", "annotations", "checksum/config"); got != sha256Hex(cfgText) {
		t.Errorf("the pod checksum/config is %s, want the SHA-256 of the config, %s", got, sha256Hex(cfgText))
	}
	// No viewer rule lets Kiali forward a port, and no rule names Secrets or a write verb.
	role := objs["Role mesh-view-system/kiali-viewer"]
	if role == nil {
		t.Fatal("no Role kiali-viewer in mesh-view-system")
	}
	for _, r := range get[[]any](t, role, "rules") {
		res := strList(t, lookupOr(r, "resources"))
		if slices.Contains(res, "pods/portforward") || slices.Contains(res, "secrets") {
			t.Errorf("the viewer Role grants %v", res)
		}
	}
	// The home manager does not cache ConfigMaps, so the Roles in management grant none.
	for _, ns := range []string{"apps-demo", "apps-sample", "istio-system", "istio-egress"} {
		for _, rule := range get[[]any](t, objs["Role "+ns+"/kiali-viewer"], "rules") {
			if len(strList(t, lookupOr(rule, "resources"))) == 0 {
				t.Errorf("the viewer Role in %s has a rule with no resource, which the API server refuses", ns)
			}
			if slices.Contains(strList(t, lookupOr(rule, "resources")), "configmaps") {
				t.Errorf("the viewer Role in %s grants ConfigMaps", ns)
			}
		}
	}
	// The login signing key is not a fixed value of the repository, and it follows the cluster root.
	if got := get[map[string]any](t, objs["ConfigMap mesh-view-system/kiali"], "data"); !strings.Contains(fmt.Sprint(got["config.yaml"]), "signing_key:") ||
		strings.Contains(fmt.Sprint(got["config.yaml"]), "0d89aa340a280b663793fcd998d76be6") {
		t.Error("the Kiali config has no signing key, or the old fixed one")
	}
	// The home cluster cache of Kiali watches each namespace of the list, so each has the viewer Role.
	for _, ns := range []string{"apps-demo", "apps-sample", "istio-system", "istio-egress", "mesh-view-system"} {
		r := objs["Role "+ns+"/kiali-viewer"]
		b := objs["RoleBinding "+ns+"/kiali-viewer"]
		if r == nil || b == nil {
			t.Errorf("namespace %s has no viewer Role or RoleBinding of Kiali", ns)
			continue
		}
		for _, rule := range get[[]any](t, r, "rules") {
			if res := strList(t, lookupOr(rule, "resources")); slices.Contains(res, "pods/portforward") || slices.Contains(res, "secrets") {
				t.Errorf("the viewer Role in %s grants %v", ns, res)
			}
		}
		if got := fmt.Sprint(lookupOr(b, "subjects")); got != "[map[kind:ServiceAccount name:kiali namespace:mesh-view-system]]" {
			t.Errorf("the viewer RoleBinding in %s binds %s", ns, got)
		}
	}
	sec := objs["Secret mesh-view-system/kiali-multi-cluster-secret"]
	data := get[map[string]any](t, sec, "stringData")
	if len(data) != 2 {
		t.Fatalf("the remote cluster Secret holds %d files, want 2", len(data))
	}
	for cell, port := range map[string]string{"dev-cell-1": "18001", "dev-cell-2": "18002"} {
		var kc map[string]any
		if err := yaml.Unmarshal([]byte(data[cell].(string)), &kc); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(lookupOr(kc, "clusters")); got != fmt.Sprintf("[map[cluster:map[server:http://mesh-view-hub.mesh-view-system.svc:%s] name:%s]]", port, cell) {
			t.Errorf("kubeconfig of %s has the clusters %s", cell, got)
		}
		if got := fmt.Sprint(lookupOr(kc, "users")); got != fmt.Sprintf("[map[name:%s user:map[]]]", cell) {
			t.Errorf("kubeconfig of %s has the users %s, want one empty user", cell, got)
		}
		if lookupOr(kc, "current-context") != cell {
			t.Errorf("kubeconfig of %s has current-context %v", cell, lookupOr(kc, "current-context"))
		}
		if txt := data[cell].(string); strings.Contains(txt, "token") || strings.Contains(txt, "password") || strings.Contains(txt, "client-key") {
			t.Errorf("kubeconfig of %s holds a credential:\n%s", cell, txt)
		}
	}
	if s, _ := lookupOr(dep, "spec", "template", "metadata", "annotations", "poc.internal/clusters-sha256").(string); len(s) != 64 {
		t.Errorf("the pod template has no checksum of the remote cluster Secret: %q", s)
	}

	np := objs["NetworkPolicy mesh-view-system/kiali"]
	var in, out []string
	for _, r := range peerRules(t, np, "ingress") {
		in = append(in, r.String())
	}
	for _, r := range peerRules(t, np, "egress") {
		out = append(out, r.String())
	}
	// The API port must be a number: a string port is invalid and stops the apply.
	for _, r := range get[[]any](t, np, "spec", "egress") {
		for _, p := range get[[]any](t, r, "ports") {
			if _, ok := lookupOr(p, "port").(float64); !ok {
				t.Errorf("Kiali egress port %v is %T, want a number", lookupOr(p, "port"), lookupOr(p, "port"))
			}
		}
	}
	if len(in) != 1 || !strings.HasPrefix(in[0], "[map[ipBlock:map[cidr:172.18.0.4/32]]]") || !strings.HasSuffix(in[0], " 20001") {
		t.Errorf("Kiali ingress %q, want the node addresses on 20001 only", in)
	}
	wantOut := []string{
		"[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:mesh-view-hub]]]] 18001,18002",
		"[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:observability-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:prom-readonly]]]] 9091",
		"[map[ipBlock:map[cidr:172.18.0.4/32]]] 6443",
		"[map[ipBlock:map[cidr:10.111.0.1/32]]] 443",
	}
	if !slices.Equal(out, wantOut) {
		t.Errorf("Kiali egress %q, want %q", out, wantOut)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func anySlice(s []string) []any {
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

// TestPromReadonlyRender pins the read-only Prometheus proxy and the policies around it: the proxy
// admits Kiali and the kubelet on 9091, reaches only the store on 9090 and the collector on 4317, and
// the collector admits its telemetry.
func TestPromReadonlyRender(t *testing.T) {
	t.Parallel()
	objs := clusterComponent(t, "management", "observability-store")
	dep := objs["Deployment observability-system/prom-readonly"]
	if dep == nil {
		t.Fatalf("no Deployment prom-readonly in %v", keysOfObjects(objs))
	}
	if get[float64](t, dep, "spec", "replicas") != 1 || get[string](t, dep, "spec", "strategy", "type") != "Recreate" {
		t.Errorf("replicas %v and strategy %v, want 1 and Recreate", lookupOr(dep, "spec", "replicas"), lookupOr(dep, "spec", "strategy"))
	}
	spec := get[map[string]any](t, dep, "spec", "template", "spec")
	if get[bool](t, spec, "automountServiceAccountToken") != false {
		t.Error("prom-readonly mounts an API token")
	}
	ctr := named(t, get[[]any](t, spec, "containers"), "cell-proxy")
	want := []string{"promql-proxy", "--listen=:9091", "--upstream=http://lgtm.observability-system.svc:9090"}
	if got := argsOf(t, ctr); !slices.Equal(got, want) {
		t.Errorf("args %q, want %q", got, want)
	}
	if env := envOf(t, ctr); env["OTEL_SERVICE_NAME"] != "cell-proxy-prom-readonly" {
		t.Errorf("OTEL_SERVICE_NAME %q", env["OTEL_SERVICE_NAME"])
	}
	for _, p := range []string{"readinessProbe", "livenessProbe"} {
		if got := get[string](t, ctr, p, "httpGet", "path"); got != "/-/healthy" {
			t.Errorf("%s probes %s, want /-/healthy", p, got)
		}
	}
	np := objs["NetworkPolicy observability-system/prom-readonly"]
	var in, out []string
	for _, r := range peerRules(t, np, "ingress") {
		in = append(in, r.String())
	}
	for _, r := range peerRules(t, np, "egress") {
		out = append(out, r.String())
	}
	wantIn := []string{
		"[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:mesh-view-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:kiali]]]] 9091",
		"[map[ipBlock:map[cidr:172.18.0.4/32]]] 9091",
	}
	wantOut := []string{
		"[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:lgtm]]]] 9090",
		"[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-collector]]]] 4317",
	}
	if !slices.Equal(in, wantIn) || !slices.Equal(out, wantOut) {
		t.Errorf("ingress %q and egress %q, want %q and %q", in, out, wantIn, wantOut)
	}
	col := objs["NetworkPolicy observability-system/collector-from-prom-readonly"]
	if col == nil || fmt.Sprint(lookupOr(col, "spec", "podSelector", "matchLabels")) != "map[app.kubernetes.io/name:otel-collector]" {
		t.Fatalf("collector-from-prom-readonly is %v", col)
	}
	if r := peerRules(t, col, "ingress"); len(r) != 1 || r[0].String() != "[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:prom-readonly]]]] 4317" {
		t.Errorf("the collector admits %v from prom-readonly", r)
	}
}

// The mesh view lists exactly the clusters with the mesh-view set, and each of them has a record
// source in SPIRE_AGENT_CELLS of dev-cp. The collectors of management and of each cell admit the
// namespace of the tunnel pods for their own OTLP.
func TestMeshViewCellsMatchTopology(t *testing.T) {
	t.Parallel()
	topo, err := topology.Load("../../harness/topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := topo.WithComponent("mesh-view")
	var cells []string
	for _, e := range strings.Fields(cellSetting(t, "management", "MESH_VIEW_CELLS")) {
		cell, _, ok := strings.Cut(e, "=")
		if !ok {
			t.Fatalf("MESH_VIEW_CELLS entry %q is not <cell>=<port>", e)
		}
		cells = append(cells, cell)
	}
	slices.Sort(cells)
	slices.Sort(want)
	if !slices.Equal(cells, want) {
		t.Errorf("MESH_VIEW_CELLS of management is %v, and the clusters with the mesh-view set are %v", cells, want)
	}
	agents := strings.Fields(cellSetting(t, "dev-cp", "SPIRE_AGENT_CELLS"))
	for _, c := range want {
		if !slices.Contains(agents, c) {
			t.Errorf("%s has the mesh-view set and is not in SPIRE_AGENT_CELLS of dev-cp", c)
		}
		if !slices.Contains(topo.WithComponent("cell-identity"), c) {
			t.Errorf("%s has the mesh-view set and not the cell-identity set", c)
		}
		if !slices.Contains(strings.Fields(cellSetting(t, c, "COLLECTOR_SENDERS")), "mesh-view-system") {
			t.Errorf("the collector of %s does not admit mesh-view-system", c)
		}
	}
	if !slices.Contains(topo.WithComponent("mesh-view-hub"), "management") || !slices.Contains(strings.Fields(cellSetting(t, "management", "COLLECTOR_SENDERS")), "mesh-view-system") {
		t.Error("management lacks the mesh-view-hub set, or its collector does not admit mesh-view-system")
	}
	ports := map[string]bool{}
	for _, e := range strings.Fields(cellSetting(t, "management", "MESH_VIEW_CELLS")) {
		_, p, _ := strings.Cut(e, "=")
		if ports[p] {
			t.Errorf("MESH_VIEW_CELLS gives the port %s twice", p)
		}
		ports[p] = true
	}
}

// The render of the hub refuses a bad cell list, an unpinned Kiali image and a missing chart.
func TestRenderMeshViewHubFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ env, want string }{
		{"MESH_VIEW_CELLS=rogue=18001", "reserved name rogue"},
		{"MESH_VIEW_CELLS=dev-cell-1=18001 dev-cell-1=18002", "names dev-cell-1 twice"},
		{"MESH_VIEW_CELLS=dev-cell-1=18001 dev-cell-2=18001", "gives the port 18001 to two cells"},
		{"MESH_VIEW_CELLS=dev-cell-1=8444", "out of range or in use"},
		{"MESH_VIEW_CELLS=dev-cell-1", "is not <cell>=<port>"},
		{"MESH_VIEW_NAMESPACES=Bad_Name", "is not a namespace name"},
		{"KIALI_IMAGE=quay.io/kiali/kiali:v2.34.1", "pinned by digest"},
		{"KIALI_VERSION=v9.9.9", "pinned by digest"},
		{"STUB_NO_SERVER=1", "could not read the trust bundle"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			base := []string{"STUB_CELL=management", "CELL_NAME=management"}
			r := renderScript(t, "mesh-view-hub", "/ko-app/stub", append(append(base, bundleFacts...), tc.env)...)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

// renderCopyWithout copies the render of a component into a new root, with the line strip removed, and returns the path of the copy.
// Every other file of the repository is a symbolic link into the root of the copy, so the copy reads the same charts and libraries.
func renderCopyWithout(t *testing.T, component, strip string) string {
	t.Helper()
	repo, root := repoRoot(t), t.TempDir()
	for _, dir := range []string{"components", filepath.Join("components", component)} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for from, to := range map[string]string{repo: root, filepath.Join(repo, "components"): filepath.Join(root, "components"),
		filepath.Join(repo, "components", component): filepath.Join(root, "components", component)} {
		entries, err := os.ReadDir(from)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if p := filepath.Join(to, e.Name()); !slices.Contains([]string{filepath.Join(root, "components"), filepath.Join(root, "components", component),
				filepath.Join(root, "components", component, "render.sh")}, p) {
				if err := os.Symlink(filepath.Join(from, e.Name()), p); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	src, err := os.ReadFile(filepath.Join(repo, "components", component, "render.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), strip+"\n"); n != 1 {
		t.Fatalf("the render of %s holds the line %q %d times, want once", component, strip, n)
	}
	script := filepath.Join(root, "components", component, "render.sh")
	if err := os.WriteFile(script, []byte(strings.Replace(string(src), strip+"\n", "", 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// The render removes pods/portforward from the Roles of the chart, and a guard stops the render when a Role still names it. The test
// removes the strip from a copy of the render, so the Role keeps pods/portforward, and expects the guard to stop the render. The yq call
// of the guard prints one line at a time with a pause, so a guard that pipes yq into grep -q would see SIGPIPE and let the Role through.
func TestRenderMeshViewHubGuardStopsPortForward(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "helm")
	script := renderCopyWithout(t, "mesh-view-hub",
		`    | (select(.kind == "Role" or .kind == "ClusterRole") | .rules) |= map(select((.resources // []) | contains(["pods/portforward"]) | not))`)
	env := append([]string{"STUB_CELL=management", "CELL_NAME=management", "STUB_SLOW_YQ=.rules[].resources[]"}, bundleFacts...)
	r := runStubbed(t, "/ko-app/stub", "", []string{script}, env...)
	if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, "a rule of the kiali viewer Role still names pods/portforward") {
		t.Fatalf("err %v, stdout %d bytes, stderr %q; want the guard to stop the render", r.err, len(r.stdout), r.stderr)
	}
}

// TestTunnelLivenessNoWorkloadAPI: the liveness probe of the mesh-view tunnel runs cell-proxy tunnel-status, which answers
// from the local status listener with or without a tunnel and reads no Workload API (Controller call 5). So a SPIRE agent
// that is down in a cell island restarts no cell-proxy container. The startup and readiness probes keep whoami.
func TestTunnelLivenessNoWorkloadAPI(t *testing.T) {
	t.Parallel()
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
		t.Run(cell, func(t *testing.T) {
			objs := clusterComponent(t, cell, "mesh-view")
			ctr := named(t, get[[]any](t, objs["Deployment mesh-view-system/mesh-view"], "spec", "template", "spec", "containers"), "cell-proxy")
			want := map[string]string{"startupProbe": "[/ko-app/cell-proxy whoami]", "readinessProbe": "[/ko-app/cell-proxy whoami]",
				"livenessProbe": "[/ko-app/cell-proxy tunnel-status]"}
			for p, cmd := range want {
				if got := fmt.Sprint(get[[]any](t, ctr, p, "exec", "command")); got != cmd {
					t.Errorf("%s runs %s, want %s", p, got, cmd)
				}
			}
			for _, a := range argsOf(t, ctr) {
				if strings.HasPrefix(a, "--status-listen") {
					t.Errorf("the tunnel sets %s, and tunnel-status reads the default address", a)
				}
			}
		})
	}
}
