package render

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

// envdObjects renders envd for dev-cp and returns every object, keyed as "<Kind> <namespace>/<name>", or "<Kind> <name>"
// for a cluster object.
func envdObjects(t *testing.T, env ...string) map[string]object {
	t.Helper()
	r := renderEnvd(t, env...)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	return objectsIn(t, r.stdout)
}

func envdContainer(t *testing.T, objs map[string]object) map[string]any {
	t.Helper()
	pod := get[map[string]any](t, objs["Deployment envd-system/envd"], "spec", "template", "spec")
	return named(t, get[[]any](t, pod, "containers"), "envd")
}

// TestEnvdBundleFlags checks what envd needs to apply signed bundle sets in dev-cp: the cluster name, the five bundle flags
// with the mirror address from the host service, the store token that only envd mounts (projected, audience bundle-store,
// 600 s, read only), and the memory limit of 256Mi, which is a hypothesis that the live part of M8 measures. No flag
// names a list of cells: the plane policies carry the cell flows.
func TestEnvdBundleFlags(t *testing.T) {
	objs := envdObjects(t)
	pod := get[map[string]any](t, objs["Deployment envd-system/envd"], "spec", "template", "spec")
	envd := envdContainer(t, objs)
	args := get[[]any](t, envd, "args")
	if len(args) != 19 {
		t.Fatalf("envd has %d args, want 19: %v", len(args), args)
	}
	if got, want := fmt.Sprint(args[13:]), fmt.Sprint([]string{
		"--cluster=dev-cp",
		"--bundle-mirror=172.18.0.7:5000",
		"--bundle-store=bundle-store.cell-system.svc.cluster.local:5000",
		"--bundle-store-token=/var/run/secrets/bundle-store/token",
		"--bundle-state-configmap=envd-system/bundle-state",
		"--bundle-health-timeout=5m"}); got != want {
		t.Errorf("the bundle flags are %s, want %s", got, want)
	}
	for _, a := range args {
		if strings.Contains(fmt.Sprint(a), "plane-cells") || strings.Contains(fmt.Sprint(a), "--cell-node") {
			t.Errorf("flag %v names cells", a)
		}
	}
	other := envdObjects(t, "STUB_REGISTRY_IP=172.18.0.99")
	if otherArgs := get[[]any](t, envdContainer(t, other), "args"); !slices.Contains(otherArgs, any("--bundle-mirror=172.18.0.99:5000")) {
		t.Errorf("another mirror address gives the args %v", otherArgs)
	}

	vol := named(t, get[[]any](t, pod, "volumes"), "bundle-store-token")
	sources := get[[]any](t, vol, "projected", "sources")
	if len(sources) != 1 {
		t.Fatalf("volume bundle-store-token has %d sources, want the token alone: %v", len(sources), vol)
	}
	tok := get[map[string]any](t, sources[0], "serviceAccountToken")
	if tok["audience"] != "bundle-store" || tok["expirationSeconds"] != float64(600) || tok["path"] != "token" {
		t.Errorf("the store token is %v, want audience bundle-store, 600 s and path token", tok)
	}
	users := map[string]bool{}
	for _, c := range get[[]any](t, pod, "containers") {
		for _, m := range get[[]any](t, c, "volumeMounts") {
			if get[string](t, m, "name") != "bundle-store-token" {
				continue
			}
			users[get[string](t, c, "name")] = true
			if get[string](t, m, "mountPath") != "/var/run/secrets/bundle-store" || m.(map[string]any)["readOnly"] != true {
				t.Errorf("the store token mount is %v, want a read-only mount at /var/run/secrets/bundle-store", m)
			}
		}
	}
	if len(users) != 1 || !users["envd"] {
		t.Errorf("containers that mount the store token: %v, want envd alone", users)
	}
	if got := get[string](t, envd, "resources", "limits", "memory"); got != "256Mi" {
		t.Errorf("envd memory limit is %s, want 256Mi", got)
	}
	if pod["automountServiceAccountToken"] != false {
		t.Error("the pod mounts the default API token")
	}
	r := renderEnvd(t, "STUB_REGISTRY_FAIL=1")
	if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, "no registry mirror address") {
		t.Errorf("a render without the mirror address: err %v, stdout %q, stderr %q", r.err, r.stdout, r.stderr)
	}
}

// TestEnvdRBACExact checks every right that the apply engine needs, and no other: Role envd-argocd in argocd (list
// Applications, and patch only the Application root), ClusterRole envd-netpol-read (list NetworkPolicies), Role
// envd-bundle-state in envd-system (create ConfigMaps, and get and update only bundle-state), the earlier Role envd-records, and a
// binding of each to the envd account of envd-system. Every object carries the harness label.
func TestEnvdRBACExact(t *testing.T) {
	objs := envdObjects(t)
	role := objs["Role argocd/envd-argocd"]
	if role == nil {
		t.Fatal("the render prints no Role envd-argocd in argocd")
	}
	wantRules := `[map[apiGroups:[argoproj.io] resources:[applications] verbs:[list]] map[apiGroups:[argoproj.io] resourceNames:[root] resources:[applications] verbs:[patch]]]`
	if got := fmt.Sprint(get[[]any](t, role, "rules")); got != wantRules {
		t.Errorf("Role envd-argocd rules are %s, want %s", got, wantRules)
	}
	cr := objs["ClusterRole envd-netpol-read"]
	if cr == nil {
		t.Fatal("the render prints no ClusterRole envd-netpol-read")
	}
	if got, want := fmt.Sprint(get[[]any](t, cr, "rules")), `[map[apiGroups:[networking.k8s.io] resources:[networkpolicies] verbs:[list]]]`; got != want {
		t.Errorf("ClusterRole envd-netpol-read rules are %s, want %s", got, want)
	}
	state := objs["Role envd-system/envd-bundle-state"]
	if state == nil {
		t.Fatal("the render prints no Role envd-bundle-state in envd-system")
	}
	wantState := `[map[apiGroups:[] resources:[configmaps] verbs:[create]] map[apiGroups:[] resourceNames:[bundle-state] resources:[configmaps] verbs:[get update]]]`
	if got := fmt.Sprint(get[[]any](t, state, "rules")); got != wantState {
		t.Errorf("Role envd-bundle-state rules are %s, want %s", got, wantState)
	}
	subject := `[map[kind:ServiceAccount name:envd namespace:envd-system]]`
	for key, want := range map[string]string{
		"RoleBinding argocd/envd-argocd":            "Role envd-argocd",
		"ClusterRoleBinding envd-netpol-read":       "ClusterRole envd-netpol-read",
		"RoleBinding envd-system/envd-bundle-state": "Role envd-bundle-state",
		"RoleBinding spire-system/envd-records":     "Role envd-records",
	} {
		b := objs[key]
		if b == nil {
			t.Fatalf("the render prints no %s", key)
		}
		if got := get[string](t, b, "roleRef", "kind") + " " + get[string](t, b, "roleRef", "name"); got != want || get[string](t, b, "roleRef", "apiGroup") != "rbac.authorization.k8s.io" {
			t.Errorf("%s binds %s, want %s", key, got, want)
		}
		if got := fmt.Sprint(get[[]any](t, b, "subjects")); got != subject {
			t.Errorf("%s has the subjects %s, want %s", key, got, subject)
		}
	}
	var rights, bindings []string
	for key, o := range objs {
		if v, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); v != "envd" {
			t.Errorf("%s has harness label %v, want envd", key, v)
		}
		if strings.HasPrefix(key, "Role ") || strings.HasPrefix(key, "ClusterRole ") {
			rights = append(rights, key)
		}
		if strings.Contains(key, "RoleBinding ") {
			bindings = append(bindings, key)
		}
	}
	slices.Sort(rights)
	slices.Sort(bindings)
	if want := []string{"ClusterRole envd-netpol-read", "Role argocd/envd-argocd", "Role envd-system/envd-bundle-state", "Role spire-system/envd-records"}; !slices.Equal(rights, want) {
		t.Errorf("the render prints the roles %v, want %v", rights, want)
	}
	if len(bindings) != 4 {
		t.Errorf("the render prints the bindings %v, want one for each right", bindings)
	}
}

// TestEnvdMirrorRule checks flow N48 (envd to the registry mirror on the kind network, port 5000) and flow N46 (envd to the
// pods of bundle-store, port 5000), as the last two egress rules of policy envd. The mirror address comes from the host
// service.
func TestEnvdMirrorRule(t *testing.T) {
	for _, ip := range []string{"172.18.0.7", "172.18.0.99"} {
		egress := get[[]any](t, envdObjects(t, "STUB_REGISTRY_IP="+ip)["NetworkPolicy envd-system/envd"], "spec", "egress")
		if len(egress) != 8 {
			t.Fatalf("policy envd has %d egress rules, want 8", len(egress))
		}
		if got, want := fmt.Sprint(egress[6]), "map[ports:[map[port:5000 protocol:TCP]] to:[map[ipBlock:map[cidr:"+ip+"/32]]]]"; got != want {
			t.Errorf("rule N48 is %s, want %s", got, want)
		}
		wantStore := "map[ports:[map[port:5000 protocol:TCP]] to:[map[namespaceSelector:map[matchLabels:map[kubernetes.io/metadata.name:cell-system]] podSelector:map[matchLabels:map[app.kubernetes.io/name:bundle-store]]]]]"
		if got := fmt.Sprint(egress[7]); got != wantStore {
			t.Errorf("rule N46 is %s, want %s", got, wantStore)
		}
	}
}

// planePolicy returns the spec of a harness plane policy of the render, and fails the test when it is absent.
func planePolicy(t *testing.T, objs map[string]object, ns, name string) map[string]any {
	t.Helper()
	np := objs["NetworkPolicy "+ns+"/"+name]
	if np == nil {
		t.Fatalf("the render prints no NetworkPolicy %s/%s", ns, name)
	}
	if v, _ := lookup(np, "metadata", "labels", "cell.poc.internal/harness"); v != "envd" {
		t.Errorf("%s/%s has harness label %v, want envd", ns, name, v)
	}
	spec := get[map[string]any](t, np, "spec")
	if len(get[map[string]any](t, spec, "podSelector")) != 0 {
		t.Errorf("%s/%s podSelector is %v, want {}", ns, name, spec["podSelector"])
	}
	return spec
}

const envdPeer = "envd-system/envd"

// TestCpPlanePolicies checks each harness plane policy of role cp with no live cell, with one and with two: the ports, the
// peers and the direction come from the rules that the M7 renders of spire-server and relay-system held, and the pod
// selector is {} so that a bundle cannot move a pod out of the policy by a label. The plane-cells policies are absent
// while no cell is live. The set of policies equals the plane policies of role cp in allow.json.
func TestCpPlanePolicies(t *testing.T) {
	variants := []struct {
		name, kind string
		cells      []string
	}{
		{"no live cell", "STUB_KIND_CLUSTERS=management dev-cp rogue", nil},
		{"one live cell", "STUB_KIND_CLUSTERS=management dev-cp rogue dev-cell-2", []string{"10.9.0.2/32"}},
		{"two live cells", "STUB_KIND_CLUSTERS=management dev-cp rogue dev-cell-1 dev-cell-2", []string{"10.9.0.1/32", "10.9.0.2/32"}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			r := renderEnvd(t, v.kind)
			if r.err != nil {
				t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
			}
			objs := objectsIn(t, r.stdout)
			if strings.Contains(r.log, "facts --cluster dev-cell-1") != slices.Contains(v.cells, "10.9.0.1/32") ||
				strings.Contains(r.log, "facts --cluster dev-cell-2") != slices.Contains(v.cells, "10.9.0.2/32") {
				t.Errorf("the render read the facts of cells that do not match %v:\n%s", v.cells, r.log)
			}
			cellPeers := strings.Join(v.cells, ",")

			store := planePolicy(t, objs, "cell-system", "plane-envd-store")
			wantFromEnvd := func(spec map[string]any, port int) {
				t.Helper()
				ingress := get[[]any](t, spec, "ingress")
				if fmt.Sprint(spec["policyTypes"]) != "[Ingress]" || len(spec) != 3 || len(ingress) != 1 ||
					peerList(t, ingress[0], "from") != envdPeer || !slices.Equal(portList(t, ingress[0]), []int{port}) {
					t.Errorf("spec is %v, want one ingress rule from %s on %d", spec, envdPeer, port)
				}
			}
			wantFromEnvd(store, 5000)
			wantFromEnvd(planePolicy(t, objs, "spire-system", "plane-envd"), 8081)

			workloads := planePolicy(t, objs, "spire-system", "plane-workloads")
			wIngress := get[[]any](t, workloads, "ingress")
			if fmt.Sprint(workloads["policyTypes"]) != "[Ingress]" || len(workloads) != 3 || len(wIngress) != 1 ||
				peerList(t, wIngress[0], "from") != "observability-system/otel-uplink,gateway-system/cell-gateway,cell-controller-system/cell-controller" ||
				!slices.Equal(portList(t, wIngress[0]), []int{8081}) {
				t.Errorf("plane-workloads spec is %v, want one ingress rule from otel-uplink, cell-gateway and cell-controller on 8081", workloads)
			}

			upstream := planePolicy(t, objs, "relay-system", "plane-upstream")
			egress := get[[]any](t, upstream, "egress")
			if fmt.Sprint(upstream["policyTypes"]) != "[Egress]" || len(upstream) != 3 || len(egress) != 1 ||
				peerList(t, egress[0], "to") != "10.9.0.10/32" || !slices.Equal(portList(t, egress[0]), []int{31443, 31445, 31444}) {
				t.Errorf("plane-upstream spec is %v, want one egress rule to 10.9.0.10/32 on 31443 31445 31444", upstream)
			}

			wantCells := map[string][]int{"spire-system": {8081}, "relay-system": {8443, 8445, 8444}}
			for ns, ports := range wantCells {
				key := "NetworkPolicy " + ns + "/plane-cells"
				if len(v.cells) == 0 {
					if objs[key] != nil {
						t.Errorf("the render prints %s with no live cell", key)
					}
					continue
				}
				spec := planePolicy(t, objs, ns, "plane-cells")
				ingress := get[[]any](t, spec, "ingress")
				if fmt.Sprint(spec["policyTypes"]) != "[Ingress]" || len(spec) != 3 || len(ingress) != 1 ||
					peerList(t, ingress[0], "from") != cellPeers || !slices.Equal(portList(t, ingress[0]), ports) {
					t.Errorf("%s spec is %v, want one ingress rule from %s on %v", key, spec, cellPeers, ports)
				}
			}

			// The plane policies of the render are the ones that allow.json lists for role cp, apart from the envd policy itself.
			var got []string
			for key, o := range objs {
				if o["kind"] != "NetworkPolicy" || strings.HasSuffix(key, "/default-deny") || strings.HasSuffix(key, "/allow-dns") {
					continue
				}
				got = append(got, strings.TrimPrefix(key, "NetworkPolicy "))
			}
			var want []string
			for _, ref := range bundle.DefaultPolicy().Roles["cp"].PlanePolicies {
				if len(v.cells) == 0 && ref.Name == "plane-cells" {
					continue
				}
				want = append(want, ref.Namespace+"/"+ref.Name)
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("the render prints the policies %v, and allow.json lists %v for role cp", got, want)
			}
		})
	}
}

// TestEnvdRenderCellsFailClosed gives the cell part of the render a wrong input. A live cell whose facts fail, or that has
// no node address, stops the render, because a cell that the render left out would lose its place in the admit lists.
func TestEnvdRenderCellsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		env        []string
	}{
		{"live cell without facts", "no host service facts for the live cell dev-cell-2", []string{"STUB_FACTS_FAIL=dev-cell-2"}},
		{"live cell without facts names the read command", "Read them: mise run hostsvc -- facts --cluster dev-cell-2", []string{"STUB_FACTS_FAIL=dev-cell-2"}},
		{"live cell without node address", "node address of dev-cell-1", []string{"STUB_FACTS_NOIP=dev-cell-1"}},
		{"a relay target in the catalog", "names the relay target management", []string{"SPIRE_AGENT_CELLS=dev-cell-1 management"}},
		{"kind does not answer", "kind get clusters failed", []string{"STUB_KIND_FAIL=1"}},
		{"a bad route", "is not <node port>:<container port>=<target node port>", []string{"RELAY_VIEW_ROUTES=8443=31443"}},
		{"no route", "has no route", []string{"RELAY_TELEMETRY_ROUTES= "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := renderEnvd(t, tc.env...)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

// TestEnvdRenderFollowsTheCells: a cell that goes away leaves the addresses of both plane-cells policies at the next render, as
// the render that cell:down starts for dev-cp, and a cell that has no node address is not live.
func TestEnvdRenderFollowsTheCells(t *testing.T) {
	both := envdObjects(t)
	for _, env := range [][]string{{"STUB_KIND_CLUSTERS=management dev-cp rogue dev-cell-1"}, {"STUB_NO_NODE_IP=dev-cell-2"}} {
		one := envdObjects(t, env...)
		for _, ns := range []string{"spire-system", "relay-system"} {
			key := "NetworkPolicy " + ns + "/plane-cells"
			if got := peerList(t, get[[]any](t, both[key], "spec", "ingress")[0], "from"); got != "10.9.0.1/32,10.9.0.2/32" {
				t.Errorf("%s admits %s with two cells", key, got)
			}
			if got := peerList(t, get[[]any](t, one[key], "spec", "ingress")[0], "from"); got != "10.9.0.1/32" {
				t.Errorf("%s admits %s after dev-cell-2 left (%v)", key, got, env)
			}
		}
	}
}

// TestSpireServerHasNoCellRules checks that no rule of the SPIRE server bundle of dev-cp admits a cell address or envd,
// while the cluster_jwt section and the entries of both live cells stay. The cell and envd flows live in harness plane
// policies, which a bundle cannot take away.
func TestSpireServerHasNoCellRules(t *testing.T) {
	r := renderCell(t, "dev-cp")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docs(t, hydrated(r.stdout, "dev-cp"))
	if _, ok := objs["NetworkPolicy/spire-server-agents"]; ok {
		t.Error("the render prints NetworkPolicy spire-server-agents")
	}
	for key, o := range objs {
		if o["kind"] != "NetworkPolicy" {
			continue
		}
		for _, dir := range []string{"ingress", "egress"} {
			rules, _ := lookupOr(o, "spec", dir).([]any)
			for _, rule := range rules {
				peers, _ := lookupOr(rule, "from").([]any)
				peers = append(peers, func() []any { p, _ := lookupOr(rule, "to").([]any); return p }()...)
				for _, p := range peers {
					if cidr, ok := lookup(p, "ipBlock", "cidr"); ok {
						prefix, err := netip.ParsePrefix(cidr.(string))
						if err != nil {
							t.Fatalf("%s has the ipBlock %v: %v", key, cidr, err)
						}
						for _, addr := range []string{"10.9.0.1", "10.9.0.2", "10.9.0.10"} {
							if prefix.Contains(netip.MustParseAddr(addr)) {
								t.Errorf("%s admits %v, which holds the address %s of a cell or of management", key, cidr, addr)
							}
						}
					}
					if ns, ok := lookup(p, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); ok && ns == "envd-system" {
						t.Errorf("%s admits envd: %v", key, rule)
					}
				}
			}
		}
	}
	if np, ok := objs["NetworkPolicy/spire-server-workloads"]; ok {
		t.Errorf("the render prints NetworkPolicy spire-server-workloads, which the harness plane policy spire-system/plane-workloads replaces: %v", np["spec"])
	}
	if conf := get[string](t, objs["ConfigMap/spire-server"], "data", "server.conf"); !strings.Contains(conf, `NodeAttestor "cluster_jwt"`) {
		t.Error("server.conf lacks the cluster_jwt section with two live cells")
	}
	entries := get[map[string]any](t, objs["ConfigMap/spire-entries"], "data")
	for _, name := range []string{"workload-envd.yaml", "agents-envd-system-envd.yaml", "dev-cell-1-celld.yaml", "dev-cell-2-celld.yaml"} {
		if _, ok := entries[name]; !ok {
			t.Errorf("spire-entries has no %s", name)
		}
	}
}

// TestRelayHasNoCellRules checks that no rule of the relay bundle admits a cell address or reaches management, in any
// policy, whichever cells are live.
func TestRelayHasNoCellRules(t *testing.T) {
	r := renderRelay(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	n := 0
	for key, o := range objs {
		if o["kind"] != "NetworkPolicy" || strings.HasSuffix(key, "/allow-dns") {
			continue
		}
		n++
		for _, dir := range []string{"ingress", "egress"} {
			rules, _ := lookupOr(o, "spec", dir).([]any)
			for _, rule := range rules {
				for _, side := range []string{"from", "to"} {
					peers, _ := lookupOr(rule, side).([]any)
					for _, p := range peers {
						if cidr, ok := lookup(p, "ipBlock", "cidr"); ok && cidr != "172.18.0.4/32" {
							t.Errorf("%s has a %s rule for %v, want the own node only", key, dir, cidr)
						}
					}
				}
				for _, port := range portList(t, rule) {
					if port != 8080 && port != 4317 && port != 53 {
						t.Errorf("%s has a %s rule on port %d, which is a route or an upstream port", key, dir, port)
					}
				}
			}
		}
	}
	if n != 3 {
		t.Errorf("the render has %d NetworkPolicies, want default-deny and one for each relay", n)
	}
	for _, bad := range []string{"10.9.0.1", "10.9.0.2", "10.9.0.10/32", "31443", "31444", "31445"} {
		for key, o := range objs {
			if o["kind"] == "NetworkPolicy" && strings.Contains(fmt.Sprint(o["spec"]), bad) {
				t.Errorf("%s mentions %s", key, bad)
			}
		}
	}
}

// admits reports whether a rule list of the policies in ns, each with an empty pod selector, admits a peer on a port in a
// direction. A peer is an IPv4 address, matched against ipBlock cidrs, or <namespace>/<app>, matched against a namespace
// selector and an app label.
func admits(t *testing.T, objs map[string]object, ns, dir, peer string, port int) bool {
	t.Helper()
	side := map[string]string{"ingress": "from", "egress": "to"}[dir]
	for _, o := range objs {
		if o["kind"] != "NetworkPolicy" || lookupOr(o, "metadata", "namespace") != ns || len(get[map[string]any](t, o, "spec", "podSelector")) != 0 {
			continue
		}
		rules, _ := lookupOr(o, "spec", dir).([]any)
		for _, rule := range rules {
			if !slices.Contains(portList(t, rule), port) {
				continue
			}
			peers, _ := lookupOr(rule, side).([]any)
			for _, p := range peers {
				if cidr, ok := lookup(p, "ipBlock", "cidr"); ok {
					if addr, err := netip.ParseAddr(peer); err == nil {
						if prefix, err := netip.ParsePrefix(cidr.(string)); err == nil && prefix.Contains(addr) {
							return true
						}
					}
					continue
				}
				pns, _ := lookup(p, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")
				app, _ := lookup(p, "podSelector", "matchLabels", "app.kubernetes.io/name")
				if fmt.Sprintf("%v/%v", pns, app) == peer {
					return true
				}
			}
		}
	}
	return false
}

// TestPlaneFlowsHarnessOnly checks that each plane flow of the M7 renders has a rule in a harness policy with an empty pod
// selector, and that the bundle renders of spire-server and relay-system hold no policy for any of them. The evaluator reads
// only the harness renders, so a bundle that drops every NetworkPolicy leaves each flow open. The flows are the M7 rules: the
// cell nodes to the SPIRE server (8081) and to the relay routes, the relay to the management routes, envd to the SPIRE
// server, and the applier of each role to the bundle store (5000).
func TestPlaneFlowsHarnessOnly(t *testing.T) {
	cp := envdObjects(t)
	for _, f := range []struct {
		ns, dir, peer string
		port          int
	}{
		{"spire-system", "ingress", "10.9.0.1", 8081}, {"spire-system", "ingress", "10.9.0.2", 8081},
		{"spire-system", "ingress", envdPeer, 8081},
		{"spire-system", "ingress", "observability-system/otel-uplink", 8081}, {"spire-system", "ingress", "gateway-system/cell-gateway", 8081},
		{"spire-system", "ingress", "cell-controller-system/cell-controller", 8081},
		{"relay-system", "ingress", "10.9.0.1", 8443}, {"relay-system", "ingress", "10.9.0.1", 8445}, {"relay-system", "ingress", "10.9.0.1", 8444},
		{"relay-system", "ingress", "10.9.0.2", 8443}, {"relay-system", "ingress", "10.9.0.2", 8445}, {"relay-system", "ingress", "10.9.0.2", 8444},
		{"relay-system", "egress", "10.9.0.10", 31443}, {"relay-system", "egress", "10.9.0.10", 31445}, {"relay-system", "egress", "10.9.0.10", 31444},
		{"cell-system", "ingress", envdPeer, 5000},
	} {
		if !admits(t, cp, f.ns, f.dir, f.peer, f.port) {
			t.Errorf("role cp: no harness policy admits %s %s of %s on %d", f.ns, f.dir, f.peer, f.port)
		}
	}
	// A flow that M7 did not have stays closed: the evaluator does not admit by accident.
	for _, f := range []struct {
		ns, dir, peer string
		port          int
	}{
		{"spire-system", "ingress", "10.9.0.3", 8081}, {"spire-system", "ingress", "10.9.0.1", 8082}, {"cell-system", "ingress", "10.9.0.1", 5000},
	} {
		if admits(t, cp, f.ns, f.dir, f.peer, f.port) {
			t.Errorf("role cp: a harness policy admits %s %s of %s on %d, which M7 never had", f.ns, f.dir, f.peer, f.port)
		}
	}
	if !admits(t, cellObjects(t), "cell-system", "ingress", "cell-identity-system/celld", 5000) {
		t.Error("role cell: no harness policy admits celld to the bundle store on 5000")
	}

	// The bundle renders hold none of these flows, so removing every bundle policy leaves the flows as they are.
	spire := map[string]object{}
	for k, o := range docs(t, hydrated(renderCell(t, "dev-cp").stdout, "dev-cp")) {
		spire["NetworkPolicy spire-system/"+strings.TrimPrefix(k, "NetworkPolicy/")] = o
	}
	for name, objs := range map[string]map[string]object{"spire-server": spire, "relay-system": objectsIn(t, renderRelay(t).stdout)} {
		for key, o := range objs {
			if o["kind"] != "NetworkPolicy" {
				continue
			}
			rules, _ := lookupOr(o, "spec", "ingress").([]any)
			for _, rule := range rules {
				for _, port := range portList(t, rule) {
					if port == 8081 {
						t.Errorf("%s of the %s bundle has an ingress rule on the SPIRE server port %d", key, name, port)
					}
				}
			}
		}
	}
}

// TestEnvdPlaneCellsFollowTheCatalog: a cell that is live but that SPIRE_AGENT_CELLS leaves out gets no address in either
// plane-cells policy, and the render reads no facts of it.
func TestEnvdPlaneCellsFollowTheCatalog(t *testing.T) {
	r := renderEnvd(t, "SPIRE_AGENT_CELLS=dev-cell-1")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	for _, ns := range []string{"spire-system", "relay-system"} {
		if got := peerList(t, get[[]any](t, objs["NetworkPolicy "+ns+"/plane-cells"], "spec", "ingress")[0], "from"); got != "10.9.0.1/32" {
			t.Errorf("%s/plane-cells admits %s, want 10.9.0.1/32 only", ns, got)
		}
	}
	if strings.Contains(r.log, "facts --cluster dev-cell-2") {
		t.Errorf("the render read the facts of a cell outside the catalog:\n%s", r.log)
	}
}

// TestEnvdMirrorPortCheck: a registry mirror on another port stops the render, because rule N48 admits port 5000 only.
func TestEnvdMirrorPortCheck(t *testing.T) {
	r := renderEnvd(t, "STUB_REGISTRY_PORT=5001")
	if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, "the registry mirror port is '5001'") {
		t.Errorf("err %v, stdout %d bytes, stderr %q; want a stop that names the port", r.err, len(r.stdout), r.stderr)
	}
}
