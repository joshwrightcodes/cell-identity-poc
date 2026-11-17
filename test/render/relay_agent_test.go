package render

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// objectsIn parses a render that holds objects in several namespaces, by "<kind> <namespace>/<name>"
// or "<kind> <name>" for a cluster-scoped object.
func objectsIn(t *testing.T, out string) map[string]object {
	t.Helper()
	objs, err := parseDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]object{}
	for _, o := range objs {
		key := objName(o)
		if _, dup := m[key]; dup {
			t.Fatalf("%s appears twice", key)
		}
		m[key] = o
	}
	return m
}

func renderRelay(t *testing.T, env ...string) result {
	t.Helper()
	return renderScript(t, "relay-system", "/ko-app/stub", append(append([]string{"STUB_CELL=dev-cp"}, bundleFacts...), env...)...)
}

// TestRenderRelaySystem renders the relay of dev-cp with cells/dev-cp.env. Each Deployment routes
// its ports to the management node, each NodePort Service keeps the source address, and the
// NetworkPolicy admits only the cell nodes on the routes and the own node on the health port.
func TestRenderRelaySystem(t *testing.T) {
	r := renderRelay(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	want := map[string]struct {
		args      []string
		ports     []int
		nodePorts map[int]int
		targets   []int
	}{
		"relay-view":      {[]string{"--route", "8443=10.9.0.10:31443", "--route", "8445=10.9.0.10:31445", "--health", ":8080"}, []int{8443, 8445}, map[int]int{8443: 30443, 8445: 30445}, []int{31443, 31445}},
		"relay-telemetry": {[]string{"--route", "8444=10.9.0.10:31444", "--health", ":8080"}, []int{8444}, map[int]int{8444: 30444}, []int{31444}},
	}
	for name, w := range want {
		t.Run(name, func(t *testing.T) {
			d := objs["Deployment relay-system/"+name]
			if d == nil {
				t.Fatalf("no Deployment %s in %v", name, keysOfObjects(objs))
			}
			ctr := named(t, get[[]any](t, d, "spec", "template", "spec", "containers"), "relay")
			if got := fmt.Sprint(get[[]any](t, ctr, "args")); got != fmt.Sprint(w.args) {
				t.Errorf("args %s, want %v", got, w.args)
			}
			if img := get[string](t, ctr, "image"); !strings.HasPrefix(img, "localhost:5001/relay@sha256:") {
				t.Errorf("image %s, want the relay image by digest", img)
			}
			if get[string](t, ctr, "readinessProbe", "httpGet", "path") != "/healthz" || get[float64](t, ctr, "readinessProbe", "httpGet", "port") != 8080 {
				t.Errorf("readiness probe %v, want /healthz on 8080", ctr["readinessProbe"])
			}
			svc := objs["Service relay-system/"+name]
			if get[string](t, svc, "spec", "type") != "NodePort" || get[string](t, svc, "spec", "externalTrafficPolicy") != "Local" {
				t.Errorf("Service %s is %v with traffic policy %v, want NodePort with Local", name, lookupOr(svc, "spec", "type"), lookupOr(svc, "spec", "externalTrafficPolicy"))
			}
			got := map[int]int{}
			for _, p := range get[[]any](t, svc, "spec", "ports") {
				got[int(get[float64](t, p, "targetPort"))] = int(get[float64](t, p, "nodePort"))
			}
			if fmt.Sprint(got) != fmt.Sprint(w.nodePorts) {
				t.Errorf("node ports %v, want %v", got, w.nodePorts)
			}
			np := objs["NetworkPolicy relay-system/"+name]
			ingress := get[[]any](t, np, "spec", "ingress")
			if len(ingress) != 2 {
				t.Fatalf("ingress has %d rules, want the routes and the health port", len(ingress))
			}
			if peers := fmt.Sprint(get[[]any](t, ingress[0], "from")); peers != "[map[ipBlock:map[cidr:10.9.0.1/32]] map[ipBlock:map[cidr:10.9.0.2/32]]]" {
				t.Errorf("the route rule admits %s, want the two cell nodes only", peers)
			}
			if ports := portList(t, ingress[0]); !slices.Equal(ports, w.ports) {
				t.Errorf("the route rule opens %v, want %v", ports, w.ports)
			}
			if peers, ports := fmt.Sprint(get[[]any](t, ingress[1], "from")), portList(t, ingress[1]); peers != "[map[ipBlock:map[cidr:172.18.0.4/32]]]" || !slices.Equal(ports, []int{8080}) {
				t.Errorf("the probe rule admits %s on %v, want the own node on 8080", peers, ports)
			}
			egress := get[[]any](t, np, "spec", "egress")
			if peers, ports := fmt.Sprint(get[[]any](t, egress[0], "to")), portList(t, egress[0]); peers != "[map[ipBlock:map[cidr:10.9.0.10/32]]]" || !slices.Equal(ports, w.targets) {
				t.Errorf("the target rule reaches %s on %v, want the management node on %v", peers, ports, w.targets)
			}
		})
	}
	if objs["NetworkPolicy relay-system/default-deny"] == nil || objs["Namespace relay-system"] == nil {
		t.Error("the render holds no Namespace relay-system or no default deny")
	}
}

// TestRelayHasNoBindRoute checks that the render of dev-cp holds the view and telemetry relays only. It holds no
// relay-bind Deployment, Service or NetworkPolicy, no route to 8447, and no node port 30447, even when the settings
// still carry the old RELAY_BIND_ROUTES value.
func TestRelayHasNoBindRoute(t *testing.T) {
	for _, env := range [][]string{nil, {"RELAY_BIND_ROUTES=30447:8447=31447"}} {
		r := renderRelay(t, env...)
		if r.err != nil {
			t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
		}
		objs := objectsIn(t, r.stdout)
		for key := range objs {
			if strings.Contains(key, "relay-bind") {
				t.Errorf("the render holds %s", key)
			}
		}
		for _, bad := range []string{"8447", "30447", "31447"} {
			if strings.Contains(r.stdout, bad) {
				t.Errorf("the render mentions %s", bad)
			}
		}
		view := named(t, get[[]any](t, objs["Deployment relay-system/relay-view"], "spec", "template", "spec", "containers"), "relay")
		if got := fmt.Sprint(get[[]any](t, view, "args")); got != "[--route 8443=10.9.0.10:31443 --route 8445=10.9.0.10:31445 --health :8080]" {
			t.Errorf("relay-view args are %s, want the two routes of M3", got)
		}
	}
}

// TestRenderRelaySystemFailsClosed gives the relay bad routes and inputs. Each stops the render.
func TestRenderRelaySystemFailsClosed(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"RELAY_VIEW_ROUTES=8443=31443", "is not <node port>:<container port>=<target node port>"},
		{"RELAY_VIEW_ROUTES=29999:8443=31443", "outside 30000 to 32767"},
		{"RELAY_VIEW_ROUTES=30443:8080=31443", "not the health port 8080"},
		{"RELAY_TELEMETRY_ROUTES=30443:8446=31444", "the node port 30443 appears in two routes"},
		{"RELAY_TELEMETRY_ROUTES=30446:8443=31444", "the container port 8443 appears in two routes"},
		{"RELAY_VIEW_ROUTES= ", "relay-view has no route"},
		{"RELAY_TARGET=missing", "no host service facts for missing"},
		{"STUB_FACTS_FAIL=dev-cell-2", "no host service facts for dev-cell-2"},
		{"SPIRE_AGENT_CELLS=dev-cell-1 management", "names the relay target management"},
		{"NODE_IPS= ", "NODE_IPS holds no address"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			r := renderRelay(t, tc.env)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

func renderAgent(t *testing.T, cell string, env ...string) result {
	t.Helper()
	return renderScript(t, "argocd-agent", "/ko-app/cluster-jwt-agent", append(append([]string{"STUB_CELL=" + cell}, bundleFacts...), env...)...)
}

// TestRenderArgoCDAgent renders the agent of dev-cell-1 from the fixture bundles. It checks the
// agent and cell-proxy arguments, the RBAC limits, the copy of AppProject cell, the root pin and
// the harness label.
func TestRenderArgoCDAgent(t *testing.T) {
	r := renderAgent(t, "dev-cell-1")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, strings.ReplaceAll(r.stdout, "@CELL_NAME@", "dev-cell-1"))
	for key, o := range objs {
		if v, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); v != "argocd-agent" {
			t.Errorf("%s has no harness label argocd-agent", key)
		}
	}
	d := objs["Deployment argocd/argocd-agent"]
	if d == nil {
		t.Fatalf("no Deployment argocd/argocd-agent in %v", keysOfObjects(objs))
	}
	pod := get[map[string]any](t, d, "spec", "template", "spec")
	if get[string](t, pod, "serviceAccountName") != "argocd-agent" || get[bool](t, pod, "automountServiceAccountToken") {
		t.Errorf("pod runs as %v with automount %v, want argocd-agent with no automatic token", pod["serviceAccountName"], pod["automountServiceAccountToken"])
	}
	if v, _ := lookup(d, "spec", "template", "metadata", "labels", "cell.poc.internal/harness"); v != "argocd-agent" {
		t.Error("the pod template has no harness label")
	}
	containers := get[[]any](t, pod, "containers")
	var names []string
	for _, c := range containers {
		names = append(names, get[string](t, c, "name"))
	}
	if !slices.Equal(names, []string{"spire-agent", "argocd-agent", "cell-proxy"}) {
		t.Fatalf("containers %v, want spire-agent, argocd-agent and cell-proxy", names)
	}
	agentArgs := fmt.Sprint(get[[]any](t, named(t, containers, "argocd-agent"), "args"))
	for _, want := range []string{"agent", "--agent-mode=autonomous", "--creds=header:", "--insecure-plaintext", "--server-address=127.0.0.1",
		"--server-port=8443", "--namespace=argocd", "--metrics-port=8181", "--log-format=json", "--enable-compression=false",
		"--redis-creds-dir-path=/run/argocd-agent/redis"} {
		if !strings.Contains(" "+strings.Trim(agentArgs, "[]")+" ", " "+want+" ") {
			t.Errorf("agent args %s lack %s", agentArgs, want)
		}
	}
	if probe := fmt.Sprint(lookupOr(named(t, containers, "argocd-agent"), "readinessProbe", "exec", "command")); strings.Contains(probe, "healthz") {
		t.Errorf("the readiness probe %s reads /healthz, which needs the remote stream", probe)
	}
	proxyArgs := fmt.Sprint(get[[]any](t, named(t, containers, "cell-proxy"), "args"))
	if want := "[spiffe-client --listen=127.0.0.1:8443 --upstream=10.9.0.9:30443 --expect-id=spiffe://mgmt.poc.internal/argocd/principal --peer-bundle=/run/cell-proxy/mgmt-root/root.crt --peer-trust-domain=mgmt.poc.internal --proof]"; proxyArgs != want {
		t.Errorf("cell-proxy args %s, want %s", proxyArgs, want)
	}
	root := objs["ConfigMap argocd/mgmt-root"]
	sum := get[string](t, root, "metadata", "annotations", "poc.internal/peer-root-sha256")
	if got := get[string](t, d, "spec", "template", "metadata", "annotations", "poc.internal/peer-root-sha256"); got != sum || len(sum) != 64 {
		t.Errorf("the pod pins the root %q, and mgmt-root has %q", got, sum)
	}
	if !strings.Contains(get[string](t, root, "data", "root.crt"), "BEGIN CERTIFICATE") {
		t.Error("mgmt-root holds no certificate")
	}
	for key, o := range objs {
		if o["kind"] == "AppProject" {
			t.Errorf("the agent bundle holds %s", key)
		}
	}

	t.Run("RBAC", func(t *testing.T) {
		rulesOf := func(key string) string {
			o := objs[key]
			if o == nil {
				t.Fatalf("no %s in %v", key, keysOfObjects(objs))
			}
			var out []string
			for _, rule := range get[[]any](t, o, "rules") {
				out = append(out, fmt.Sprintf("%v %v %v", lookupOr(rule, "apiGroups"), lookupOr(rule, "resources"), lookupOr(rule, "verbs")))
			}
			return strings.Join(out, "; ")
		}
		for key, want := range map[string]string{
			"Role argocd/argocd-agent": "[argoproj.io] [applications] [get list watch]; [argoproj.io] [appprojects] [get list watch]; " +
				"[] [configmaps] [get list watch]; [] [secrets] [list watch]",
			"Role argocd/argocd-agent-token":      "[] [serviceaccounts/token] [create]",
			"Role apps-demo/argocd-agent-read":    "[] [services] [get list watch]; [apps] [deployments] [get list watch]; [security.istio.io] [authorizationpolicies] [get list watch]",
			"Role argocd/argocd-agent-read":       "[apps] [statefulsets] [get list watch]; [argoproj.io] [appprojects] [get list watch]",
			"Role istio-system/argocd-agent-read": "[] [configmaps] [get list watch]",
			"ClusterRole argocd-agent-read": "[] [namespaces] [get list watch]; [admissionregistration.k8s.io] [validatingwebhookconfigurations] [get list watch]; " +
				"[apiextensions.k8s.io] [customresourcedefinitions] [get list watch]; [rbac.authorization.k8s.io] [clusterroles] [get list watch]",
		} {
			if got := rulesOf(key); got != want {
				t.Errorf("%s rules:\n got %s\nwant %s", key, got, want)
			}
		}
		if names := get[[]any](t, objs["Role argocd/argocd-agent-token"], "rules", 0, "resourceNames"); fmt.Sprint(names) != "[argocd-agent]" {
			t.Errorf("the token Role names %v, want only argocd-agent", names)
		}
		for key, o := range objs {
			if o["kind"] != "Role" && o["kind"] != "ClusterRole" {
				continue
			}
			for _, rule := range get[[]any](t, o, "rules") {
				for _, res := range get[[]any](t, rule, "resources") {
					s := res.(string)
					if s == "*" || s == "events" || strings.HasSuffix(s, "/exec") || strings.HasSuffix(s, "/attach") ||
						strings.HasSuffix(s, "/portforward") || strings.HasSuffix(s, "/proxy") || (s == "secrets" && key != "Role argocd/argocd-agent") {
						t.Errorf("%s grants %s", key, s)
					}
				}
				for _, v := range get[[]any](t, rule, "verbs") {
					if v == "*" {
						t.Errorf("%s grants the verb *", key)
					}
				}
			}
		}
		for _, key := range []string{"RoleBinding cell-identity-system/argocd-agent-read", "Role cell-identity-system/argocd-agent-read"} {
			if objs[key] != nil {
				t.Errorf("the render reads the objects of the harness bundle: %s", key)
			}
		}
		for _, key := range []string{"RoleBinding argocd/argocd-agent", "RoleBinding apps-demo/argocd-agent-read", "ClusterRoleBinding argocd-agent-read"} {
			if fmt.Sprint(lookupOr(objs[key], "subjects")) != "[map[kind:ServiceAccount name:argocd-agent namespace:argocd]]" {
				t.Errorf("%s binds %v, want argocd/argocd-agent only", key, lookupOr(objs[key], "subjects"))
			}
		}
	})

	t.Run("network policy of flow N20", func(t *testing.T) {
		np := objs["NetworkPolicy argocd/argocd-agent"]
		if fmt.Sprint(lookupOr(np, "spec", "podSelector")) != "map[matchLabels:map[app.kubernetes.io/name:argocd-agent]]" ||
			fmt.Sprint(lookupOr(np, "spec", "policyTypes")) != "[Ingress Egress]" {
			t.Fatalf("policy selects %v with types %v", lookupOr(np, "spec", "podSelector"), lookupOr(np, "spec", "policyTypes"))
		}
		egress := get[[]any](t, np, "spec", "egress")
		if peers, ports := fmt.Sprint(lookupOr(egress[0], "to")), portList(t, egress[0]); peers != "[map[ipBlock:map[cidr:10.9.0.9/32]]]" || !slices.Equal(ports, []int{30443, 30081}) {
			t.Errorf("the first rule reaches %s on %v, want the dev-cp node on 30443 and 30081", peers, ports)
		}
		if peers := fmt.Sprint(lookupOr(egress[1], "to")); peers != "[map[ipBlock:map[cidr:172.18.0.4/32]]]" {
			t.Errorf("the API rule reaches %s", peers)
		}
		// Flow N15: the collector scrapes the metrics port, and no other pod reaches an agent port.
		ingress := get[[]any](t, np, "spec", "ingress")
		if len(ingress) != 1 || fmt.Sprint(lookupOr(ingress[0], "from")) != "[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:observability-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:otel-collector]]]]" ||
			!slices.Equal(portList(t, ingress[0]), []int{8181}) {
			t.Errorf("the agent policy admits %v, want only the collector on 8181", ingress)
		}
		var targets []string
		for _, rule := range egress {
			for _, to := range get[[]any](t, rule, "to") {
				switch {
				case lookupOr(to, "ipBlock", "cidr") != nil:
					targets = append(targets, fmt.Sprint(lookupOr(to, "ipBlock", "cidr")))
				default:
					targets = append(targets, fmt.Sprint(lookupOr(to, "namespaceSelector", "matchLabels"))+fmt.Sprint(lookupOr(to, "podSelector", "matchLabels")))
				}
			}
		}
		want := []string{"10.9.0.9/32", "172.18.0.4/32", "10.111.0.1/32", "<nil>map[app.kubernetes.io/name:argocd-redis]",
			"map[kubernetes.io/metadata.name:observability-system]map[app.kubernetes.io/name:otel-collector]"}
		if !slices.Equal(targets, want) {
			t.Errorf("the agent egress reaches %v, want exactly %v", targets, want)
		}
	})
}

// TestRenderArgoCDAgentFailsClosed stops the render for a missing bundle directory, a failed
// api-resources call, a kind with no resource, and an unpinned agent image.
func TestRenderArgoCDAgentFailsClosed(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"AGENT_BUNDLES=/nonexistent", "no bundles in /nonexistent"},
		{"STUB_NO_API=1", "kubectl api-resources failed"},
		{"ARGOCD_AGENT_IMAGE=quay.io/argoprojlabs/argocd-agent:v0.10.0", "is not pinned by digest"},
		{"SPIRE_SERVER_CLUSTER=missing", "no host service facts for missing"},
		{"STUB_NO_SERVER=1", "could not read the trust bundle"},
		{"API_SERVER_IPS= ", "API_SERVER_IPS holds no address"},
		{"POC_ENV=a.b", "is not a short DNS label"},
		{"POC_ENV=a|b", "is not a short DNS label"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			r := renderAgent(t, "dev-cell-1", tc.env)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

func portList(t *testing.T, rule any) []int {
	t.Helper()
	var out []int
	for _, p := range get[[]any](t, rule, "ports") {
		out = append(out, int(get[float64](t, p, "port")))
	}
	return out
}

func lookupOr(v any, path ...any) any {
	x, _ := lookup(v, path...)
	return x
}

func keysOfObjects(m map[string]object) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// relayIngress lists the ingress rules of NetworkPolicy relay-system/<name> as "<peers> <ports>".
func relayIngress(t *testing.T, objs map[string]object, name string) []string {
	t.Helper()
	var out []string
	for _, rule := range get[[]any](t, objs["NetworkPolicy relay-system/"+name], "spec", "ingress") {
		out = append(out, fmt.Sprintf("%s %v", peerList(t, rule, "from"), portList(t, rule)))
	}
	return out
}

// TestRenderRelaySystemNoLiveCells: with no cell cluster the render succeeds, reads no cell facts, and holds only the
// node rule in each ingress policy.
func TestRenderRelaySystemNoLiveCells(t *testing.T) {
	r := renderRelay(t, "STUB_KIND_CLUSTERS=management dev-cp rogue")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	if strings.Contains(r.log, "facts --cluster dev-cell") {
		t.Errorf("the render read the facts of a cell that has no cluster:\n%s", r.log)
	}
	objs := objectsIn(t, r.stdout)
	for _, name := range []string{"relay-view", "relay-telemetry"} {
		if got := relayIngress(t, objs, name); !slices.Equal(got, []string{"172.18.0.4/32 [8080]"}) {
			t.Errorf("ingress rules of %s are %v, want the node rule only", name, got)
		}
	}
}

// TestRenderRelaySystemOneLiveCell: one live cell gives one address in the route rule.
func TestRenderRelaySystemOneLiveCell(t *testing.T) {
	r := renderRelay(t, "STUB_KIND_CLUSTERS=management dev-cp rogue dev-cell-1")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	if got := relayIngress(t, objs, "relay-view"); !slices.Equal(got, []string{"10.9.0.1/32 [8443 8445]", "172.18.0.4/32 [8080]"}) {
		t.Errorf("ingress rules of relay-view are %v", got)
	}
}
