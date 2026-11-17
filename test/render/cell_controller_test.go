package render

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func renderCellController(t *testing.T, env ...string) result {
	t.Helper()
	return renderScript(t, "cell-controller", "/ko-app/stub", append(append([]string{"STUB_CELL=dev-cp"}, bundleFacts...), env...)...)
}

// TestCellControllerRender renders the cell controller for dev-cp with cells/dev-cp.env. It checks the arguments, the
// images by digest, the bounds, the checksum annotations, the token in the cell-controller container only, the two Roles of
// namespace cell-controller-system, the two ConfigMaps and the NetworkPolicies of flows N42, N43, N44, N8, N11 and N23.
func TestCellControllerRender(t *testing.T) {
	r := renderCellController(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	if left := regexp.MustCompile(`@[A-Z_]+@`).FindAllString(r.stdout, -1); len(left) > 0 {
		t.Fatalf("render left tokens %v", left)
	}
	for key, o := range objs {
		if v, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); v != "cell-controller" {
			t.Errorf("%s has harness label %v, want cell-controller", key, v)
		}
		if ns, ok := lookup(o, "metadata", "namespace"); ok && ns != "cell-controller-system" {
			t.Errorf("%s is in namespace %v, want cell-controller-system", key, ns)
		}
	}
	for _, want := range []string{"hostsvc-serve start", "hostsvc-serve status", "hostsvc-serve pin",
		"docker exec dev-cp-control-plane getent ahostsv4 host.docker.internal",
		"kubectl --context kind-dev-cp -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show"} {
		if !strings.Contains(r.log, want) {
			t.Errorf("render did not run %q; it ran:\n%s", want, r.log)
		}
	}
	if labels := get[map[string]any](t, objs["Namespace cell-controller-system"], "metadata", "labels"); labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["istio-injection"] != "disabled" {
		t.Errorf("namespace labels are %v", labels)
	}

	t.Run("the ServiceAccount mounts no token", func(t *testing.T) {
		if sa := objs["ServiceAccount cell-controller-system/cell-controller"]; sa == nil || sa["automountServiceAccountToken"] != false {
			t.Errorf("ServiceAccount cell-controller is %v, want automountServiceAccountToken: false", sa)
		}
	})

	t.Run("deployment", func(t *testing.T) {
		dep := objs["Deployment cell-controller-system/cell-controller"]
		if dep == nil {
			t.Fatalf("no Deployment cell-controller in %v", keysOfObjects(objs))
		}
		if get[float64](t, dep, "spec", "replicas") != 1 || get[string](t, dep, "spec", "strategy", "type") != "Recreate" {
			t.Errorf("cell-controller has replicas %v and strategy %v, want one replica and Recreate", lookupOr(dep, "spec", "replicas"), lookupOr(dep, "spec", "strategy"))
		}
		pod := get[map[string]any](t, dep, "spec", "template", "spec")
		if pod["serviceAccountName"] != "cell-controller" || pod["automountServiceAccountToken"] != false || pod["shareProcessNamespace"] != true {
			t.Errorf("pod spec is %v", pod)
		}
		if lookupOr(dep, "spec", "template", "metadata", "labels", "app.kubernetes.io/name") != "cell-controller" ||
			lookupOr(dep, "spec", "template", "metadata", "labels", "cell.poc.internal/harness") != "cell-controller" {
			t.Errorf("pod labels are %v, want the app label cell-controller that the server policy selects, and the harness label", lookupOr(dep, "spec", "template", "metadata", "labels"))
		}
		containers := get[[]any](t, pod, "containers")
		if names := []string{get[string](t, containers[0], "name"), get[string](t, containers[1], "name")}; len(containers) != 2 || !slices.Equal(names, []string{"spire-agent", "cell-controller"}) {
			t.Fatalf("containers are %v, want spire-agent and cell-controller", names)
		}
		ctr := named(t, containers, "cell-controller")
		wantArgs := []string{"run", "--env=dev", "--steps-configmap=cell-controller-system/cell-steps", "--status-configmap=cell-controller-system/step-status",
			"--spec-key-dir=/run/cell-controller/spec-key", "--hostsvc-addr=192.168.5.2:17443", "--hostsvc-server-name=host.docker.internal",
			"--hostsvc-pin=/run/cell-controller/hostsvc-pin/hostsvc.crt", "--health-listen=:8080"}
		if got := fmt.Sprint(get[[]any](t, ctr, "args")); got != fmt.Sprint(wantArgs) {
			t.Errorf("cell-controller args are %s, want %v", got, wantArgs)
		}
		if got := get[string](t, ctr, "image"); got != "localhost:5001/cell-controller@"+r.digest {
			t.Errorf("cell-controller image is %q, want the cell-controller image by digest", got)
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
			t.Errorf("cell-controller runs as %v, want 65532, the user that the entry selects", user)
		}
		const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount"
		for _, c := range containers {
			name := get[string](t, c, "name")
			has := false
			for _, m := range get[[]any](t, c, "volumeMounts") {
				if get[string](t, m, "mountPath") == tokenPath || get[string](t, m, "name") == "cell-controller-api-token" {
					has = true
					if get[bool](t, m, "readOnly") != true {
						t.Errorf("%s mounts the token read-write", name)
					}
				}
			}
			if has != (name == "cell-controller") {
				t.Errorf("container %s: token mount is %v, want it in cell-controller only", name, has)
			}
		}
		// The container listens on the health port only: one declared port, and the one listen flag.
		if ports := get[[]any](t, ctr, "ports"); len(ports) != 1 || get[float64](t, ports[0], "containerPort") != 8080 {
			t.Errorf("cell-controller declares the ports %v, want only 8080", ports)
		}
		for _, a := range get[[]any](t, ctr, "args") {
			if f := fmt.Sprint(a); strings.Contains(f, "listen") && f != "--health-listen=:8080" {
				t.Errorf("cell-controller argument %s opens a listener other than the health port", f)
			}
		}
		for _, path := range []string{"/healthz"} {
			for _, probe := range []string{"readinessProbe", "livenessProbe"} {
				if lookupOr(ctr, probe, "httpGet", "path") != path || lookupOr(ctr, probe, "httpGet", "port") != float64(8080) {
					t.Errorf("%s is %v, want %s on 8080", probe, lookupOr(ctr, probe), path)
				}
			}
		}
		// Each checksum on the pod is the SHA-256 of the file that the pod reads.
		ann := get[map[string]any](t, dep, "spec", "template", "metadata", "annotations")
		pin := get[string](t, objs["ConfigMap cell-controller-system/hostsvc-pin"], "data", "hostsvc.crt")
		if strings.TrimSpace(pin) != strings.TrimSpace(caPEM(t, "host.docker.internal")) {
			t.Errorf("hostsvc-pin holds %q, want the certificate that the host service presents", pin)
		}
		if ann["poc.internal/hostsvc-pin-sha256"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
			lookupOr(objs["ConfigMap cell-controller-system/hostsvc-pin"], "metadata", "annotations", "poc.internal/hostsvc-pin-sha256") != ann["poc.internal/hostsvc-pin-sha256"] {
			t.Errorf("the pin annotation is %v on the pod, want the digest that the host service status holds, also on the ConfigMap", ann["poc.internal/hostsvc-pin-sha256"])
		}
		if ann["poc.internal/spec-key-sha256"] != sha256Hex(stubMgmtKey) {
			t.Errorf("spec-key annotation is %v, want the SHA-256 of the key", ann["poc.internal/spec-key-sha256"])
		}
		if lookupOr(objs["ConfigMap cell-controller-system/mgmt-spec-key"], "metadata", "annotations", "poc.internal/spec-key-sha256") != ann["poc.internal/spec-key-sha256"] {
			t.Errorf("the key annotation of ConfigMap mgmt-spec-key and the pod annotation differ")
		}
		keys := get[map[string]any](t, objs["ConfigMap cell-controller-system/mgmt-spec-key"], "data")
		if len(keys) != 1 || keys["spec.pub"] != stubMgmtKey {
			t.Errorf("mgmt-spec-key holds %v, want spec.pub with the key of mgmt-signing-pub and nothing else", keys)
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fmt.Sprint(ann["cell.poc.internal/config-checksum"])) {
			t.Errorf("config checksum annotation is %v", ann["cell.poc.internal/config-checksum"])
		}
		for _, v := range get[[]any](t, pod, "volumes") {
			if _, ok := lookup(v, "hostPath"); ok {
				t.Errorf("volume %v uses a host path", v)
			}
			if name, ok := lookup(v, "configMap", "name"); ok && objs["ConfigMap cell-controller-system/"+name.(string)] == nil && name != "spire-agent-cell-controller" && name != "spire-trust-bundle-cell-controller" && name != "kube-root-ca.crt" {
				t.Errorf("volume uses ConfigMap %v, which the render does not print", name)
			}
		}
	})

	roleRules := func(role object) []string {
		var rules []string
		for _, rule := range get[[]any](t, role, "rules") {
			if len(rule.(map[string]any)) < 3 || len(rule.(map[string]any)) > 4 {
				t.Errorf("rule %v has an unexpected shape", rule)
			}
			rules = append(rules, fmt.Sprintf("%v %v %v %v", lookupOr(rule, "apiGroups"), lookupOr(rule, "resources"), lookupOr(rule, "resourceNames"), lookupOr(rule, "verbs")))
		}
		return rules
	}
	subjects := func(rb object) string {
		var out []string
		for _, s := range get[[]any](t, rb, "subjects") {
			out = append(out, fmt.Sprintf("%v %v/%v", lookupOr(s, "kind"), lookupOr(s, "namespace"), lookupOr(s, "name")))
		}
		return strings.Join(out, ",")
	}

	t.Run("the Role of the cell controller reads cell-steps and writes step-status", func(t *testing.T) {
		role, rb := objs["Role cell-controller-system/cell-controller"], objs["RoleBinding cell-controller-system/cell-controller"]
		if role == nil || rb == nil {
			t.Fatalf("no Role or RoleBinding cell-controller: %v", keysOfObjects(objs))
		}
		if want := []string{"[] [configmaps] <nil> [create]", "[] [configmaps] [cell-steps] [get]", "[] [configmaps] [step-status] [get update]"}; !slices.Equal(roleRules(role), want) {
			t.Errorf("rules are %v, want %v", roleRules(role), want)
		}
		if get[string](t, rb, "roleRef", "name") != "cell-controller" || subjects(rb) != "ServiceAccount cell-controller-system/cell-controller" {
			t.Errorf("RoleBinding is %v", rb)
		}
	})

	t.Run("the Role of envd names create, get and update on cell-steps, and get on step-status, and envd is its only subject", func(t *testing.T) {
		role, rb := objs["Role cell-controller-system/envd-steps"], objs["RoleBinding cell-controller-system/envd-steps"]
		if role == nil || rb == nil {
			t.Fatalf("no Role or RoleBinding envd-steps: %v", keysOfObjects(objs))
		}
		rules := roleRules(role)
		if want := []string{"[] [configmaps] <nil> [create]", "[] [configmaps] [cell-steps] [get update]", "[] [configmaps] [step-status] [get]"}; !slices.Equal(rules, want) {
			t.Errorf("rules are %v, want %v", rules, want)
		}
		if get[string](t, rb, "roleRef", "name") != "envd-steps" || get[string](t, rb, "roleRef", "kind") != "Role" || subjects(rb) != "ServiceAccount envd-system/envd" {
			t.Errorf("RoleBinding is %v, want the Role envd-steps for ServiceAccount envd-system/envd only", rb)
		}
	})

	t.Run("network policies", func(t *testing.T) {
		deny := objs["NetworkPolicy cell-controller-system/default-deny"]
		if deny == nil || len(get[map[string]any](t, deny, "spec", "podSelector")) != 0 || len(get[[]any](t, deny, "spec", "policyTypes")) != 2 {
			t.Fatalf("default-deny is %v", deny)
		}
		dns := objs["NetworkPolicy cell-controller-system/allow-dns"]
		if dns == nil || get[string](t, dns, "spec", "egress", 0, "to", 1, "ipBlock", "cidr") != "10.111.0.10/32" {
			t.Errorf("allow-dns is %v, want the DNS service peer", dns)
		}
		np := objs["NetworkPolicy cell-controller-system/cell-controller"]
		var egress []string
		for _, rule := range get[[]any](t, np, "spec", "egress") {
			egress = append(egress, fmt.Sprintf("%s %v", peerList(t, rule, "to"), portList(t, rule)))
		}
		// N42 names the one host address and one port. N43 is the API server. N8 and N11 follow.
		want := []string{"192.168.5.2/32 [17443]", "172.18.0.4/32 [6443]", "10.111.0.1/32 [443]", "spire-system/spire-server [8081]", "observability-system/otel-collector [4317]"}
		if !slices.Equal(egress, want) {
			t.Errorf("egress rules are %v, want %v", egress, want)
		}
		ingress := get[[]any](t, np, "spec", "ingress")
		if len(ingress) != 1 || peerList(t, ingress[0], "from") != "172.18.0.4/32" || !slices.Equal(portList(t, ingress[0]), []int{8080}) {
			t.Errorf("ingress is %v, want the node on the health port only", ingress)
		}
	})
}

// TestCellControllerRenderFollowsTheHostAddress: the address that the node resolves goes into --hostsvc-addr and into the
// only rule of flow N42, so a changed address changes both.
func TestCellControllerRenderFollowsTheHostAddress(t *testing.T) {
	r := renderCellController(t, "STUB_GETENT=192.168.5.9 STREAM host.docker.internal\\n")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	ctr := named(t, get[[]any](t, objs["Deployment cell-controller-system/cell-controller"], "spec", "template", "spec", "containers"), "cell-controller")
	if args := fmt.Sprint(get[[]any](t, ctr, "args")); !strings.Contains(args, "--hostsvc-addr=192.168.5.9:17443") {
		t.Errorf("args are %s, want --hostsvc-addr=192.168.5.9:17443", args)
	}
	rule := get[[]any](t, objs["NetworkPolicy cell-controller-system/cell-controller"], "spec", "egress")[0]
	if peerList(t, rule, "to") != "192.168.5.9/32" || !slices.Equal(portList(t, rule), []int{17443}) {
		t.Errorf("rule N42 is %v, want 192.168.5.9/32 on 17443", rule)
	}
}

// TestCellControllerRenderFollowsTheKeys: a new signing key, and a staged key, change the key ConfigMap and the pod
// annotation, so the pod restarts. A staged key goes in as next.pub, and the checksum covers both keys.
func TestCellControllerRenderFollowsTheKeys(t *testing.T) {
	other := "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="
	next := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	annotation := func(r result) any {
		return lookupOr(objectsIn(t, r.stdout)["Deployment cell-controller-system/cell-controller"], "spec", "template", "metadata", "annotations", "poc.internal/spec-key-sha256")
	}
	a, b, c := renderCellController(t), renderCellController(t, "STUB_MGMT_KEY="+other), renderCellController(t, "STUB_NEXT_PUB="+next)
	for _, r := range []result{a, b, c} {
		if r.err != nil {
			t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
		}
	}
	if annotation(a) == annotation(b) || annotation(b) != sha256Hex(other) {
		t.Errorf("the key annotations are %v and %v, want two digests that follow the key", annotation(a), annotation(b))
	}
	keys := get[map[string]any](t, objectsIn(t, c.stdout)["ConfigMap cell-controller-system/mgmt-spec-key"], "data")
	if keys["spec.pub"] != stubMgmtKey || keys["next.pub"] != next || len(keys) != 2 {
		t.Errorf("mgmt-spec-key holds %v, want spec.pub and next.pub with the staged key", keys)
	}
	if want := sha256Hex(stubMgmtKey + "\n" + next); annotation(c) != want {
		t.Errorf("the annotation is %v with a staged key, want %s over both keys", annotation(c), want)
	}
	// The staged key must equal the stagedKey of mgmtd: the render refuses any other.
	for name, tc := range map[string]struct {
		env  []string
		want string
	}{
		"next.pub with another hash than stagedKey": {[]string{"STUB_NEXT_PUB=" + next, "STUB_STAGED_KEY=" + strings.Repeat("0", 64)}, "has the SHA-256"},
		"a stagedKey and no next.pub":               {[]string{"STUB_STAGED_KEY=" + strings.Repeat("a", 64)}, "next.pub is not the base64 of 32 bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			r := renderCellController(t, tc.env...)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

// TestCellControllerRenderFailsClosed gives the render a missing or wrong input. Each stops it with no output.
func TestCellControllerRenderFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		env        []string
	}{
		{"no signing key", "ConfigMap mgmt-system/mgmt-signing-pub is absent. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link", []string{"STUB_NO_MGMT_KEY=1"}},
		{"a key of the wrong size", "is not the base64 of 32 bytes", []string{"STUB_MGMT_KEY=c2hvcnQ="}},
		{"a host service that does not start", "the host service does not serve", []string{"STUB_HOSTSVC_FAIL=1"}},
		{"two host addresses", "gives 2 addresses", []string{"STUB_GETENT=192.168.5.2 STREAM host.docker.internal\\n192.168.5.3 STREAM host.docker.internal\\n"}},
		{"no dev-cp SPIRE server", "could not read the trust bundle from spire-server-0 in dev-cp", []string{"STUB_NO_SERVER_IN=dev-cp"}},
		{"a node address list that is blank", "NODE_IPS holds no address", []string{"NODE_IPS= "}},
		{"an API address that is not IPv4", "is not IPv4", []string{"API_SERVER_IPS=api.example"}},
		{"another trust domain", "is not dev.env.poc.internal", []string{"SPIRE_TRUST_DOMAIN=rogue.example"}},
		{"a host port that is no port", "is not a port", []string{"HOSTSVC_PORT=99999"}},
		{"no images file", "Run mise run images first", []string{"STUB_IMAGES=missing"}},
		{"a stale images file", "Run mise run images again", []string{"STUB_IMAGES=stale"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := renderCellController(t, tc.env...)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

// TestCellControllerSettingsOfDevCP: the settings of dev-cp name the cell controller where other renders read it. The SPIRE
// server admits cp/cell-controller as a local workload (flow N8), and the collector admits its namespace as a sender (flow N11).
func TestCellControllerSettingsOfDevCP(t *testing.T) {
	if !slices.Contains(strings.Fields(cellEnv(t, "dev-cp", "SPIRE_LOCAL_WORKLOADS")), "cp/cell-controller=cell-controller-system/cell-controller") {
		t.Errorf("SPIRE_LOCAL_WORKLOADS of dev-cp is %q, want the entry cp/cell-controller=cell-controller-system/cell-controller", cellEnv(t, "dev-cp", "SPIRE_LOCAL_WORKLOADS"))
	}
	if !slices.Contains(strings.Fields(cellEnv(t, "dev-cp", "COLLECTOR_SENDERS")), "cell-controller-system") {
		t.Errorf("COLLECTOR_SENDERS of dev-cp is %q, want cell-controller-system", cellEnv(t, "dev-cp", "COLLECTOR_SENDERS"))
	}
}
