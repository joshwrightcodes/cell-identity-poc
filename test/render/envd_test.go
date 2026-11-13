package render

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func renderEnvd(t *testing.T, env ...string) result {
	t.Helper()
	return renderScript(t, "envd", "/ko-app/stub", append(append([]string{"STUB_CELL=dev-cp"}, bundleFacts...), env...)...)
}

// peerList prints the peers of one NetworkPolicy rule as "<cidr or namespace/app>", sorted into rule order.
func peerList(t *testing.T, rule any, key string) string {
	t.Helper()
	var peers []string
	for _, p := range get[[]any](t, rule, key) {
		if cidr, ok := lookup(p, "ipBlock", "cidr"); ok {
			peers = append(peers, cidr.(string))
			continue
		}
		peers = append(peers, get[string](t, p, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")+"/"+get[string](t, p, "podSelector", "matchLabels", "app.kubernetes.io/name"))
	}
	return strings.Join(peers, ",")
}

// TestEnvdRender renders envd for dev-cp with cells/dev-cp.env. It checks the arguments, the images by digest,
// the bounds, the two checksum annotations, the token in the envd container only, the Role of cell-records,
// the two ConfigMaps and the NetworkPolicies.
func TestEnvdRender(t *testing.T) {
	r := renderEnvd(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	if left := regexp.MustCompile(`@[A-Z_]+@`).FindAllString(r.stdout, -1); len(left) > 0 {
		t.Fatalf("render left tokens %v", left)
	}
	for key, o := range objs {
		if v, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); v != "envd" {
			t.Errorf("%s has harness label %v, want envd", key, v)
		}
	}
	for _, want := range []string{"run hostsvc -- facts --cluster management",
		"kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show",
		"kubectl --context kind-dev-cp -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show"} {
		if !strings.Contains(r.log, want) {
			t.Errorf("render did not run %q; it ran:\n%s", want, r.log)
		}
	}
	if labels := get[map[string]any](t, objs["Namespace envd-system"], "metadata", "labels"); labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["istio-injection"] != "disabled" {
		t.Errorf("namespace labels are %v", labels)
	}

	t.Run("the ServiceAccount mounts no token", func(t *testing.T) {
		if sa := objs["ServiceAccount envd-system/envd"]; sa == nil || sa["automountServiceAccountToken"] != false {
			t.Errorf("ServiceAccount envd is %v, want automountServiceAccountToken: false", sa)
		}
	})

	t.Run("deployment", func(t *testing.T) {
		dep := objs["Deployment envd-system/envd"]
		if dep == nil {
			t.Fatalf("no Deployment envd in %v", keysOfObjects(objs))
		}
		if get[float64](t, dep, "spec", "replicas") != 1 || get[string](t, dep, "spec", "strategy", "type") != "Recreate" {
			t.Errorf("envd has replicas %v and strategy %v, want one replica and Recreate", lookupOr(dep, "spec", "replicas"), lookupOr(dep, "spec", "strategy"))
		}
		pod := get[map[string]any](t, dep, "spec", "template", "spec")
		if pod["serviceAccountName"] != "envd" || pod["automountServiceAccountToken"] != false || pod["shareProcessNamespace"] != true {
			t.Errorf("pod spec is %v", pod)
		}
		if lookupOr(dep, "spec", "template", "metadata", "labels", "app.kubernetes.io/name") != "envd" ||
			lookupOr(dep, "spec", "template", "metadata", "labels", "cell.poc.internal/harness") != "envd" {
			t.Errorf("pod labels are %v, want the app label envd that the server policy selects, and the harness label", lookupOr(dep, "spec", "template", "metadata", "labels"))
		}
		containers := get[[]any](t, pod, "containers")
		if names := []string{get[string](t, containers[0], "name"), get[string](t, containers[1], "name")}; len(containers) != 2 || !slices.Equal(names, []string{"spire-agent", "envd"}) {
			t.Fatalf("containers are %v, want spire-agent and envd", names)
		}
		ctr := named(t, containers, "envd")
		wantArgs := []string{"run", "--upstream=10.9.0.10:31446", "--expect-id=spiffe://mgmt.poc.internal/api", "--peer-bundle=/run/envd/peer-root/root.crt",
			"--peer-trust-domain=mgmt.poc.internal", "--spec-key-file=/run/envd/spec-key/spec.pub", "--env=dev", "--output-configmap=spire-system/cell-records",
			"--gateway=https://cell-gateway.gateway-system.svc.cluster.local:8452", "--gateway-id=spiffe://dev.env.poc.internal/cp/gateway", "--hints-configmap=spire-system/attest-hints"}
		if got := fmt.Sprint(get[[]any](t, ctr, "args")); got != fmt.Sprint(wantArgs) {
			t.Errorf("envd args are %s, want %v", got, wantArgs)
		}
		if got := get[string](t, ctr, "image"); got != "localhost:5001/envd@"+r.digest {
			t.Errorf("envd image is %q, want the envd image by digest", got)
		}
		for _, c := range containers {
			name := get[string](t, c, "name")
			if image := get[string](t, c, "image"); !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(image) {
				t.Errorf("%s image %q is not pinned by digest", name, image)
			}
			for _, path := range [][]any{{"requests", "cpu"}, {"requests", "memory"}, {"limits", "memory"}} {
				if _, ok := lookup(c, append([]any{"resources"}, path...)...); !ok {
					t.Errorf("%s has no resources %v", name, path)
				}
			}
			sc := get[map[string]any](t, c, "securityContext")
			if sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true || !slices.Equal(get[[]any](t, sc, "capabilities", "drop"), []any{"ALL"}) {
				t.Errorf("%s securityContext is %v", name, sc)
			}
		}
		user, ok := lookup(ctr, "securityContext", "runAsUser")
		if !ok {
			user = lookupOr(pod, "securityContext", "runAsUser")
		}
		if user != float64(65532) {
			t.Errorf("envd runs as %v, want 65532, the user of the envd entry", user)
		}
		// The token of the ServiceAccount goes to the envd container only. The agent has its own token for the server.
		const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount"
		for _, c := range containers {
			name := get[string](t, c, "name")
			has := false
			for _, m := range get[[]any](t, c, "volumeMounts") {
				if get[string](t, m, "mountPath") == tokenPath || get[string](t, m, "name") == "envd-api-token" {
					has = true
					if get[bool](t, m, "readOnly") != true {
						t.Errorf("%s mounts the token read-write", name)
					}
				}
			}
			if has != (name == "envd") {
				t.Errorf("container %s: token mount is %v, want it in envd only", name, has)
			}
		}
		// Each ConfigMap checksum on the pod is the SHA-256 of the file that the pod reads.
		ann := get[map[string]any](t, dep, "spec", "template", "metadata", "annotations")
		peer := get[string](t, objs["ConfigMap envd-system/peer-root"], "data", "root.crt")
		if ann["poc.internal/peer-root-sha256"] != sha256Hex(strings.TrimRight(peer, "\n")) {
			t.Errorf("peer-root annotation is %v, want the SHA-256 of ConfigMap peer-root", ann["poc.internal/peer-root-sha256"])
		}
		if ann["poc.internal/spec-key-sha256"] != sha256Hex(stubMgmtKey) {
			t.Errorf("spec-key annotation is %v, want the SHA-256 of the key", ann["poc.internal/spec-key-sha256"])
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fmt.Sprint(ann["cell.poc.internal/config-checksum"])) {
			t.Errorf("config checksum annotation is %v", ann["cell.poc.internal/config-checksum"])
		}
		if lookupOr(objs["ConfigMap envd-system/peer-root"], "metadata", "annotations", "poc.internal/peer-root-sha256") != ann["poc.internal/peer-root-sha256"] {
			t.Errorf("the annotation of ConfigMap peer-root and the pod annotation differ")
		}
		if get[string](t, objs["ConfigMap envd-system/mgmt-spec-key"], "data", "spec.pub") != stubMgmtKey {
			t.Errorf("mgmt-spec-key holds %v, want the key of mgmt-signing-pub", objs["ConfigMap envd-system/mgmt-spec-key"]["data"])
		}
		for _, v := range get[[]any](t, pod, "volumes") {
			if _, ok := lookup(v, "hostPath"); ok {
				t.Errorf("volume %v uses a host path", v)
			}
			if name, ok := lookup(v, "configMap", "name"); ok && objs["ConfigMap envd-system/"+name.(string)] == nil && name != "spire-agent-envd" && name != "spire-trust-bundle-envd" {
				t.Errorf("volume uses ConfigMap %v, which the render does not print", name)
			}
		}
	})

	t.Run("the Role writes only cell-records and reads attest-hints", func(t *testing.T) {
		role := objs["Role spire-system/envd-records"]
		if role == nil {
			t.Fatalf("no Role envd-records in spire-system: %v", keysOfObjects(objs))
		}
		var rules []string
		for _, rule := range get[[]any](t, role, "rules") {
			if len(rule.(map[string]any)) < 3 || len(rule.(map[string]any)) > 4 {
				t.Errorf("rule %v has an unexpected shape", rule)
			}
			rules = append(rules, fmt.Sprintf("%v %v %v %v", lookupOr(rule, "apiGroups"), lookupOr(rule, "resources"), lookupOr(rule, "resourceNames"), lookupOr(rule, "verbs")))
		}
		if want := []string{"[] [configmaps] <nil> [create]", "[] [configmaps] [cell-records] [get update]", "[] [configmaps] [attest-hints] [get]"}; !slices.Equal(rules, want) {
			t.Errorf("rules are %v, want %v", rules, want)
		}
		rb := objs["RoleBinding spire-system/envd-records"]
		if get[string](t, rb, "roleRef", "name") != "envd-records" || get[string](t, rb, "subjects", 0, "name") != "envd" || get[string](t, rb, "subjects", 0, "namespace") != "envd-system" || len(get[[]any](t, rb, "subjects")) != 1 {
			t.Errorf("RoleBinding is %v", rb)
		}
		// Only the Role objects live outside envd-system.
		for key := range objs {
			if strings.Contains(key, " spire-system/") && key != "Role spire-system/envd-records" && key != "RoleBinding spire-system/envd-records" {
				t.Errorf("the render prints %s in spire-system", key)
			}
		}
	})

	t.Run("network policies", func(t *testing.T) {
		deny := objs["NetworkPolicy envd-system/default-deny"]
		if deny == nil || len(get[map[string]any](t, deny, "spec", "podSelector")) != 0 || len(get[[]any](t, deny, "spec", "policyTypes")) != 2 {
			t.Fatalf("default-deny is %v", deny)
		}
		dns := objs["NetworkPolicy envd-system/allow-dns"]
		if dns == nil || get[string](t, dns, "spec", "egress", 0, "to", 1, "ipBlock", "cidr") != "10.111.0.10/32" {
			t.Errorf("allow-dns is %v, want the DNS service peer", dns)
		}
		np := objs["NetworkPolicy envd-system/envd"]
		var egress []string
		for _, rule := range get[[]any](t, np, "spec", "egress") {
			egress = append(egress, fmt.Sprintf("%s %v", peerList(t, rule, "to"), portList(t, rule)))
		}
		want := []string{"10.9.0.10/32 [31446]", "172.18.0.4/32 [6443]", "10.111.0.1/32 [443]", "spire-system/spire-server [8081]", "gateway-system/cell-gateway [8452]", "observability-system/otel-collector [4317]"}
		if !slices.Equal(egress, want) {
			t.Errorf("egress rules are %v, want %v", egress, want)
		}
		ingress := get[[]any](t, np, "spec", "ingress")
		if len(ingress) != 1 || peerList(t, ingress[0], "from") != "172.18.0.4/32" || !slices.Equal(portList(t, ingress[0]), []int{8080}) {
			t.Errorf("ingress is %v, want the node on the health port only", ingress)
		}
	})
}

// TestEnvdRenderFailsClosed gives the render a missing or wrong input. Each stops it with no output.
func TestEnvdRenderFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		env        []string
	}{
		{"no signing key", "ConfigMap mgmt-system/mgmt-signing-pub is absent. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link", []string{"STUB_NO_MGMT_KEY=1"}},
		{"a key of the wrong size", "is not the base64 of 32 bytes", []string{"STUB_MGMT_KEY=c2hvcnQ="}},
		{"no management SPIRE server", "could not read the trust bundle from spire-server-0 in management", []string{"STUB_NO_SERVER_IN=management"}},
		{"no dev-cp SPIRE server", "could not read the trust bundle from spire-server-0 in dev-cp", []string{"STUB_NO_SERVER_IN=dev-cp"}},
		{"a management bundle of another domain", "want spiffe://mgmt.poc.internal", []string{"STUB_MGMT_BUNDLE_FILE=testdata/dev-env-ca.pem"}},
		{"no management node", "no host service facts for missing", []string{"RELAY_TARGET=missing"}},
		{"a node address list that is blank", "NODE_IPS holds no address", []string{"NODE_IPS= "}},
		{"an API address that is not IPv4", "is not IPv4", []string{"API_SERVER_IPS=api.example"}},
		{"another trust domain", "is not dev.env.poc.internal", []string{"SPIRE_TRUST_DOMAIN=rogue.example"}},
		{"no images file", "Run mise run images first", []string{"STUB_IMAGES=missing"}},
		{"a stale images file", "Run mise run images again", []string{"STUB_IMAGES=stale"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := renderEnvd(t, tc.env...)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

// TestEnvdRenderFollowsTheKey: a new signing key changes the key ConfigMap and the pod annotation, so the pod restarts.
func TestEnvdRenderFollowsTheKey(t *testing.T) {
	other := "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="
	a, b := renderEnvd(t), renderEnvd(t, "STUB_MGMT_KEY="+other)
	if a.err != nil || b.err != nil {
		t.Fatalf("renders failed: %v %v\n%s%s", a.err, b.err, a.stderr, b.stderr)
	}
	annotation := func(r result) any {
		return lookupOr(objectsIn(t, r.stdout)["Deployment envd-system/envd"], "spec", "template", "metadata", "annotations", "poc.internal/spec-key-sha256")
	}
	if annotation(a) == annotation(b) || annotation(b) != sha256Hex(other) {
		t.Errorf("the key annotations are %v and %v, want two digests that follow the key", annotation(a), annotation(b))
	}
}

// TestEnvdRenderGatewayFlags checks the three gateway flags of envd, which an envd of Task 5 needs to start, the flow N39
// rule to the gateway pod on 8452 and nothing else, and the Role rule that reads the hints ConfigMap by name.
func TestEnvdRenderGatewayFlags(t *testing.T) {
	r := renderEnvd(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	ctr := named(t, get[[]any](t, objs["Deployment envd-system/envd"], "spec", "template", "spec", "containers"), "envd")
	args := fmt.Sprint(get[[]any](t, ctr, "args"))
	for _, want := range []string{"--gateway=https://cell-gateway.gateway-system.svc.cluster.local:8452", "--gateway-id=spiffe://dev.env.poc.internal/cp/gateway", "--hints-configmap=spire-system/attest-hints"} {
		if !strings.Contains(args, want) {
			t.Errorf("envd args %s lack %s", args, want)
		}
	}
	np := objs["NetworkPolicy envd-system/envd"]
	count := 0
	for _, rule := range get[[]any](t, np, "spec", "egress") {
		for _, port := range portList(t, rule) {
			if port == 8452 {
				count++
				if got := peerList(t, rule, "to"); got != "gateway-system/cell-gateway" {
					t.Errorf("the rule on 8452 admits %s, want the pod cell-gateway of gateway-system", got)
				}
			}
		}
	}
	if count != 1 {
		t.Errorf("%d egress rules name 8452, want 1", count)
	}
	var found bool
	for _, rule := range get[[]any](t, objs["Role spire-system/envd-records"], "rules") {
		if fmt.Sprint(lookupOr(rule, "resourceNames")) == "[attest-hints]" {
			found = fmt.Sprint(lookupOr(rule, "verbs")) == "[get]" && fmt.Sprint(lookupOr(rule, "resources")) == "[configmaps]"
		}
	}
	if !found {
		t.Error("the Role has no rule with get on configmaps attest-hints")
	}
}
