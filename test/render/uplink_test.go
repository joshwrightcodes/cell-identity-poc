package render

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestUplinkRender pins both forms of the uplink. In a cell, cell-proxy dials the relay of dev-cp on
// 30444 with a cluster_jwt sidecar, and ConfigMap mgmt-root holds the peer roots. In dev-cp, it dials
// the gateway of management on 31444 with a k8s_psat sidecar, and ConfigMap peer-root holds them. In
// both, cell-proxy accepts only the exact gateway ID, listens on 4319 only, and every object carries
// the harness label.
func TestUplinkRender(t *testing.T) {
	for _, tc := range []struct{ cluster, peerRoot, mode, port, id string }{
		{"dev-cell-1", "mgmt-root", `NodeAttestor "cluster_jwt"`, "30444", "dev-cell-1"},
		{"dev-cell-2", "mgmt-root", `NodeAttestor "cluster_jwt"`, "30444", "dev-cell-2"},
		{"dev-cp", "peer-root", `NodeAttestor "k8s_psat"`, "31444", "dev-cp"},
	} {
		t.Run(tc.cluster, func(t *testing.T) {
			objs := clusterComponent(t, tc.cluster, "otel-uplink")
			for name, o := range objs {
				if lookupOr(o, "metadata", "labels", "cell.poc.internal/harness") != "otel-uplink" {
					t.Errorf("%s lacks the harness label otel-uplink", name)
				}
				if o["kind"] == "Namespace" {
					t.Errorf("the harness component holds %s, but the namespaces bundle owns the namespace", name)
				}
			}
			dep := objs["Deployment observability-system/otel-uplink"]
			if dep == nil {
				t.Fatalf("no Deployment otel-uplink in %v", keysOfObjects(objs))
			}
			if lookupOr(dep, "spec", "template", "metadata", "labels", "cell.poc.internal/harness") != "otel-uplink" ||
				lookupOr(dep, "spec", "template", "metadata", "labels", "app.kubernetes.io/name") != "otel-uplink" {
				t.Error("the pod template lacks the harness label or the app label")
			}
			spec := get[map[string]any](t, dep, "spec", "template", "spec")
			if get[string](t, spec, "serviceAccountName") != "otel-uplink" || lookupOr(spec, "automountServiceAccountToken") != false {
				t.Errorf("service account %v, automount %v", spec["serviceAccountName"], spec["automountServiceAccountToken"])
			}
			ctr := named(t, get[[]any](t, spec, "containers"), "cell-proxy")
			var args []string
			for _, a := range get[[]any](t, ctr, "args") {
				args = append(args, a.(string))
			}
			upstream := ""
			for _, a := range args {
				if v, ok := strings.CutPrefix(a, "--upstream="); ok {
					upstream = v
				}
			}
			if !regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}:` + tc.port + `$`).MatchString(upstream) {
				t.Errorf("upstream %q, want <node address>:%s", upstream, tc.port)
			}
			want := []string{"spiffe-client", "--listen=:4319", "--upstream=" + upstream, "--expect-id=spiffe://mgmt.poc.internal/telemetry",
				"--peer-bundle=/run/cell-proxy/peer-root/root.crt", "--peer-trust-domain=mgmt.poc.internal"}
			if !slices.Equal(args, want) {
				t.Errorf("args %q, want %q", args, want)
			}
			if got := get[string](t, named(t, get[[]any](t, spec, "volumes"), "peer-root"), "configMap", "name"); got != tc.peerRoot {
				t.Errorf("the peer root volume reads ConfigMap %s, want %s", got, tc.peerRoot)
			}
			cm := objs["ConfigMap observability-system/"+tc.peerRoot]
			if cm == nil {
				t.Fatalf("no ConfigMap %s", tc.peerRoot)
			}
			ann := get[map[string]any](t, dep, "spec", "template", "metadata", "annotations")
			if ann["poc.internal/peer-root-sha256"] != lookupOr(cm, "metadata", "annotations", "poc.internal/peer-root-sha256") || len(fmt.Sprint(ann["poc.internal/peer-root-sha256"])) != 64 {
				t.Errorf("the pod annotation %v does not carry the checksum of the peer root", ann["poc.internal/peer-root-sha256"])
			}
			if s, _ := ann["cell.poc.internal/config-checksum"].(string); len(s) != 64 {
				t.Error("the pod lacks the checksum of the sidecar config")
			}
			if ports := get[[]any](t, ctr, "ports"); len(ports) != 1 || get[float64](t, ports[0], "containerPort") != 4319 {
				t.Errorf("container ports %v, want 4319 only", ports)
			}
			if get[string](t, ctr, "resources", "limits", "memory") == "" || get[string](t, ctr, "resources", "requests", "memory") == "" {
				t.Error("cell-proxy has no memory request or limit")
			}
			if env := envOf(t, ctr); env["OTEL_RESOURCE_ATTRIBUTES"] != "service.instance.id=$(POD_NAME)" {
				t.Errorf("OTEL_RESOURCE_ATTRIBUTES %q, want the pod name as service.instance.id", env["OTEL_RESOURCE_ATTRIBUTES"])
			}
			// The only token is the one that the sidecar mounts for the cluster_jwt plugin.
			for _, m := range get[[]any](t, ctr, "volumeMounts") {
				if strings.Contains(get[string](t, m, "mountPath"), "serviceaccount") {
					t.Errorf("cell-proxy mounts %v", m)
				}
			}
			sidecar := named(t, get[[]any](t, spec, "containers"), "spire-agent")
			conf := get[string](t, objs["ConfigMap observability-system/spire-agent-otel-uplink"], "data", "agent.conf")
			if !strings.Contains(conf, tc.mode) || sidecar == nil {
				t.Errorf("the SPIRE agent config lacks %s:\n%s", tc.mode, conf)
			}
			if tc.mode == `NodeAttestor "cluster_jwt"` && (!strings.Contains(conf, `cell = "`+tc.id+`"`) || !strings.Contains(conf, "30081")) {
				t.Errorf("the cluster_jwt config does not name the cell %s and the node port 30081:\n%s", tc.id, conf)
			}
			if tc.mode == `NodeAttestor "k8s_psat"` && !strings.Contains(conf, "spire-server.spire-system.svc.cluster.local") {
				t.Errorf("the k8s_psat config does not reach the server of the cluster:\n%s", conf)
			}

			svc := objs["Service observability-system/otel-uplink"]
			if p := get[[]any](t, svc, "spec", "ports"); len(p) != 1 || get[float64](t, p[0], "port") != 4319 {
				t.Errorf("service ports %v, want 4319 only", p)
			}

			np := objs["NetworkPolicy observability-system/otel-uplink"]
			if fmt.Sprint(lookupOr(np, "spec", "policyTypes")) != "[Ingress Egress]" {
				t.Errorf("policy types %v", lookupOr(np, "spec", "policyTypes"))
			}
			in := peerRules(t, np, "ingress")
			if len(in) != 2 || in[0].String() != "[map[podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-collector]]]] 4319" ||
				!strings.HasPrefix(in[1].String(), "[map[ipBlock:map[cidr:") || !strings.HasSuffix(in[1].String(), "/32]]] 4319") {
				t.Errorf("ingress %v, want the collector and a node address on 4319 only", in)
			}
			eg := peerRules(t, np, "egress")
			var ports []string
			for _, r := range eg {
				ports = append(ports, strings.Join(r.ports, ","))
			}
			wantPorts := []string{"4317", tc.port + ",30081", "6443", "443"}
			if tc.cluster == "dev-cp" {
				wantPorts = []string{"4317", "8081", tc.port}
			}
			if !slices.Equal(ports, wantPorts) {
				t.Errorf("egress ports %v, want %v", ports, wantPorts)
			}
			if !strings.Contains(eg[1].peers, strings.Split(upstream, ":")[0]+"/32") && tc.cluster != "dev-cp" {
				t.Errorf("the upstream rule %q does not name %s", eg[1], upstream)
			}
			if tc.cluster == "dev-cp" && !strings.Contains(eg[2].peers, strings.Split(upstream, ":")[0]+"/32") {
				t.Errorf("the gateway rule %q does not name %s", eg[2], upstream)
			}
		})
	}
}
