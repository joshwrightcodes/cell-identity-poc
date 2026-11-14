package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
)

var cellIdentityFacts = []string{
	"CELL_NAME=dev-cell-1",
	"SPIRE_SERVER_CLUSTER=dev-cp",
	"API_SERVER_IPS=172.18.0.5",
	"API_SERVER_PORT=6443",
	"API_SERVICE_IP=10.120.0.1",
	"DNS_SERVICE_IP=10.120.0.10",
}

func renderCellIdentity(t *testing.T, env ...string) result {
	t.Helper()
	return renderScript(t, "cell-identity", "/ko-app/cluster-jwt-agent", append(slices.Clone(cellIdentityFacts), env...)...)
}

func TestRenderCellIdentity(t *testing.T) {
	r := renderCellIdentity(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docsIn(t, r.stdout, "cell-identity-system")
	if left := regexp.MustCompile(`@[A-Z_]+@`).FindAllString(r.stdout, -1); slices.ContainsFunc(left, func(s string) bool { return s != "@CELL_NAME@" }) {
		t.Fatalf("render left tokens %v", left)
	}
	for _, want := range []string{
		"run hostsvc -- facts --cluster dev-cp",
		"kubectl --context kind-dev-cp -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem",
	} {
		if !strings.Contains(r.log, want) {
			t.Fatalf("render did not run %q; it ran:\n%s", want, r.log)
		}
	}

	t.Run("every object carries the harness label", func(t *testing.T) {
		for key, o := range objs {
			if v, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); v != "cell-identity" {
				t.Errorf("%s has harness label %v, want cell-identity", key, v)
			}
		}
	})

	t.Run("namespace is restricted and outside the mesh", func(t *testing.T) {
		labels := get[map[string]any](t, objs["Namespace/cell-identity-system"], "metadata", "labels")
		if labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["istio-injection"] != "disabled" {
			t.Fatalf("namespace labels are %v", labels)
		}
	})

	t.Run("role allows tokens for the celld account only", func(t *testing.T) {
		rules := get[[]any](t, objs["Role/celld-token"], "rules")
		if len(rules) != 1 {
			t.Fatalf("got %d rules", len(rules))
		}
		r := rules[0]
		if !slices.Equal(get[[]any](t, r, "resources"), []any{"serviceaccounts/token"}) || !slices.Equal(get[[]any](t, r, "resourceNames"), []any{"celld"}) ||
			!slices.Equal(get[[]any](t, r, "verbs"), []any{"create"}) {
			t.Fatalf("rule is %v", r)
		}
		rb := objs["RoleBinding/celld-token"]
		if get[string](t, rb, "roleRef", "name") != "celld-token" || get[string](t, rb, "subjects", 0, "name") != "celld" {
			t.Fatalf("RoleBinding is %v", rb)
		}
	})

	t.Run("pod", func(t *testing.T) {
		dep := objs["Deployment/celld"]
		pod := get[map[string]any](t, dep, "spec", "template", "spec")
		if pod["shareProcessNamespace"] != true || pod["automountServiceAccountToken"] != false || pod["serviceAccountName"] != "celld" {
			t.Fatalf("pod spec is %v", pod)
		}
		sc := get[map[string]any](t, pod, "securityContext")
		if sc["runAsNonRoot"] != true || get[string](t, sc, "seccompProfile", "type") != "RuntimeDefault" {
			t.Fatalf("pod securityContext is %v", sc)
		}
		inits, mains := get[[]any](t, pod, "initContainers"), get[[]any](t, pod, "containers")
		if len(inits) != 1 || len(mains) != 2 {
			t.Fatalf("got %d init containers and %d containers", len(inits), len(mains))
		}
		users := map[string]float64{}
		for _, c := range append(slices.Clone(inits), mains...) {
			name := get[string](t, c, "name")
			if image := get[string](t, c, "image"); !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(image) {
				t.Fatalf("%s image %q is not pinned by digest", name, image)
			}
			csc := get[map[string]any](t, c, "securityContext")
			if csc["allowPrivilegeEscalation"] != false || csc["readOnlyRootFilesystem"] != true ||
				!slices.Equal(get[[]any](t, csc, "capabilities", "drop"), []any{"ALL"}) {
				t.Fatalf("%s securityContext is %v", name, csc)
			}
			users[name] = get[float64](t, csc, "runAsUser")
			if _, ok := c.(map[string]any)["ports"]; ok {
				t.Fatalf("%s declares ports", name)
			}
		}
		if users["celld"] != 65532 || users["spire-agent"] == 65532 || users["spire-agent"] == 0 ||
			users["install-agent-plugin"] == 0 || users["install-agent-plugin"] == 65532 || users["install-agent-plugin"] == users["spire-agent"] {
			t.Fatalf("container users are %v; celld must be 65532, and the agent and the installer two other non-root users", users)
		}
		var ttl float64
		for _, v := range get[[]any](t, pod, "volumes") {
			if v.(map[string]any)["name"] != "api-token" {
				continue
			}
			if e, ok := lookup(v, "projected", "sources", 0, "serviceAccountToken", "expirationSeconds"); ok {
				ttl = e.(float64)
			}
		}
		if ttl != 600 {
			t.Fatalf("API token lifetime of the agent is %v seconds, want 600", ttl)
		}
		if got := get[string](t, inits[0], "image"); got != "localhost:5001/cluster-jwt-agent@"+r.digest {
			t.Fatalf("plugin image is %q", got)
		}
		if got := get[string](t, named(t, mains, "celld"), "image"); got != "localhost:5001/celld@"+r.digest {
			t.Fatalf("celld image is %q", got)
		}
		if ann := get[string](t, dep, "spec", "template", "metadata", "annotations", "cell.poc.internal/config-checksum"); !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(ann) {
			t.Fatalf("config checksum annotation is %q", ann)
		}

		// Each of the two containers that call the API server mounts a projected token of its own, and only celld
		// and the agent share the socket. TestCellIdentityGatewayFlags checks the celld volumes.
		mounts := func(name string) []string {
			var out []string
			for _, m := range get[[]any](t, named(t, mains, name), "volumeMounts") {
				out = append(out, get[string](t, m, "name"))
			}
			return out
		}
		if m := mounts("celld"); !slices.Equal(m, []string{"agent-socket", "spire-trust-bundle", "mgmt-op-key", "celld-api-token"}) {
			t.Fatalf("celld mounts %v", m)
		}
		if m := mounts("spire-agent"); !slices.Contains(m, "api-token") || !slices.Contains(m, "agent-socket") || !slices.Contains(m, "trust-bundle") {
			t.Fatalf("spire-agent mounts %v", m)
		}
		env := map[string]string{}
		for _, e := range get[[]any](t, named(t, mains, "celld"), "env") {
			v, _ := lookup(e, "value")
			s, _ := v.(string)
			env[get[string](t, e, "name")] = s
		}
		if env["SPIFFE_ENDPOINT_SOCKET"] != "unix:///run/spire/agent/agent.sock" || !strings.HasPrefix(env["OTEL_EXPORTER_OTLP_ENDPOINT"], "http://otel-collector.observability-system.") {
			t.Fatalf("celld env is %v", env)
		}
		var agentEnv []string
		for _, e := range get[[]any](t, named(t, mains, "spire-agent"), "env") {
			agentEnv = append(agentEnv, get[string](t, e, "name")+"="+get[string](t, e, "valueFrom", "fieldRef", "fieldPath"))
		}
		// The agent plugin reads these names, so they come from the wire contract of internal/clusterjwt.
		wantEnv := []string{
			clusterjwt.EnvPodName + "=metadata.name", clusterjwt.EnvPodUID + "=metadata.uid",
			clusterjwt.EnvPodNamespace + "=metadata.namespace", clusterjwt.EnvServiceAccount + "=spec.serviceAccountName",
		}
		if !slices.Equal(agentEnv, wantEnv) {
			t.Fatalf("spire-agent env is %v", agentEnv)
		}
		for _, v := range get[[]any](t, pod, "volumes") {
			if name, ok := lookup(v, "configMap", "name"); ok {
				if _, found := objs["ConfigMap/"+name.(string)]; !found {
					t.Fatalf("volume uses ConfigMap %v, which the render does not print", name)
				}
			}
			if _, ok := lookup(v, "hostPath"); ok {
				t.Fatalf("volume %v uses a host path", v)
			}
		}
	})

	t.Run("agent config", func(t *testing.T) {
		text := get[string](t, objs["ConfigMap/spire-agent"], "data", "agent.conf")
		var conf struct {
			Agent struct {
				ServerAddress   string `hcl:"server_address"`
				ServerPort      int    `hcl:"server_port"`
				TrustDomain     string `hcl:"trust_domain"`
				TrustBundlePath string `hcl:"trust_bundle_path"`
				LogFormat       string `hcl:"log_format"`
				SocketPath      string `hcl:"socket_path"`
				Insecure        bool   `hcl:"insecure_bootstrap"`
			} `hcl:"agent"`
		}
		if err := hcl.Decode(&conf, text); err != nil {
			t.Fatalf("agent.conf does not parse: %v", err)
		}
		a := conf.Agent
		if a.ServerAddress != "10.9.0.9" || a.ServerPort != 30081 || a.TrustDomain != "dev.env.poc.internal" || a.LogFormat != "json" ||
			a.TrustBundlePath != "/run/spire/bundle/bundle.crt" || a.SocketPath != "/run/spire/agent/agent.sock" || a.Insecure {
			t.Fatalf("agent block is %+v", a)
		}
		sum := sha256.Sum256([]byte(stubBinary))
		for _, want := range []string{
			`plugin_checksum = "` + hex.EncodeToString(sum[:]) + `"`,
			`plugin_cmd = "/run/spire/plugins/cluster-jwt-agent"`,
			`cell = "@CELL_NAME@"`,
			`WorkloadAttestor "unix"`,
			`KeyManager "disk"`,
			`directory = "/run/spire/data"`,
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("agent.conf lacks %q", want)
			}
		}
		if got := get[string](t, objs["ConfigMap/spire-trust-bundle"], "data", "bundle.crt"); strings.TrimSpace(got) != strings.TrimSpace(r.bundle) {
			t.Fatalf("trust bundle is %q", got)
		}
	})

	t.Run("network policy allows only the SPIRE and gateway node ports, the API server and the collector", func(t *testing.T) {
		var names []string
		for key := range objs {
			if name, ok := strings.CutPrefix(key, "NetworkPolicy/"); ok {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"allow-dns", "celld", "default-deny"}) {
			t.Fatalf("NetworkPolicies are %v", names)
		}
		deny := objs["NetworkPolicy/default-deny"]
		if types := get[[]any](t, deny, "spec", "policyTypes"); len(types) != 2 || len(get[map[string]any](t, deny, "spec", "podSelector")) != 0 {
			t.Fatalf("default-deny spec is %v", deny["spec"])
		}
		if spec := get[map[string]any](t, deny, "spec"); len(spec) != 2 {
			t.Fatalf("default-deny has rules: %v", spec)
		}
		np := objs["NetworkPolicy/celld"]
		if _, ok := lookup(np, "spec", "ingress"); ok {
			t.Fatal("the celld policy allows ingress")
		}
		var rules []string
		for _, rule := range get[[]any](t, np, "spec", "egress") {
			var peers []string
			for _, p := range get[[]any](t, rule, "to") {
				if cidr, ok := lookup(p, "ipBlock", "cidr"); ok {
					peers = append(peers, cidr.(string))
				} else {
					peer := "ns=" + get[string](t, p, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")
					if app, ok := lookup(p, "podSelector", "matchLabels", "app.kubernetes.io/name"); ok {
						peer += "/app=" + app.(string)
					}
					peers = append(peers, peer)
				}
			}
			var ports []string
			for _, p := range get[[]any](t, rule, "ports") {
				ports = append(ports, fmt.Sprintf("%s/%d", get[string](t, p, "protocol"), int(get[float64](t, p, "port"))))
			}
			rules = append(rules, strings.Join(peers, ",")+" "+strings.Join(ports, ","))
		}
		want := []string{"10.9.0.9/32 TCP/30081", "10.9.0.9/32 TCP/30450,TCP/30451", "172.18.0.5/32 TCP/6443", "10.120.0.1/32 TCP/443", "ns=observability-system/app=otel-collector TCP/4317"}
		if !slices.Equal(rules, want) {
			t.Fatalf("egress rules are %v, want %v", rules, want)
		}
		dns := objs["NetworkPolicy/allow-dns"]
		if cidr := get[string](t, dns, "spec", "egress", 0, "to", 1, "ipBlock", "cidr"); cidr != "10.120.0.10/32" {
			t.Fatalf("DNS service peer is %q", cidr)
		}
	})
}

// TestCellIdentityGatewayFlags checks what celld needs to bind and to claim work through the cell gateway: the
// flags, the four pod variables, the read-only projected API token that only celld and the agent mount, the mounts
// of the trust bundle and of the operation key, the checksums of both on the pod template, and ConfigMap mgmt-op-key
// with the live signing key of mgmtd. It also checks that the render names no mgmt-root, port 30447 or --bind- flag.
func TestCellIdentityGatewayFlags(t *testing.T) {
	r := renderCellIdentity(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docsIn(t, r.stdout, "cell-identity-system")
	dep := objs["Deployment/celld"]
	pod := get[map[string]any](t, dep, "spec", "template", "spec")
	celld := named(t, get[[]any](t, pod, "containers"), "celld")
	if got, want := fmt.Sprint(get[[]any](t, celld, "args")), fmt.Sprint([]string{
		"--cell=dev-cell-1", "--env=dev", "--gateway=10.9.0.9:30450", "--gateway-bind=10.9.0.9:30451",
		"--gateway-id=spiffe://dev.env.poc.internal/cp/gateway", "--trust-bundle=/run/celld/trust-bundle/bundle.crt",
		"--op-key-dir=/run/celld/op-key", "--ops-namespace=cell-ops-system"}); got != want {
		t.Errorf("celld args are %s, want %s", got, want)
	}
	fields := map[string]string{}
	for _, e := range get[[]any](t, celld, "env") {
		if path, ok := lookup(e, "valueFrom", "fieldRef", "fieldPath"); ok {
			fields[get[string](t, e, "name")] = path.(string)
		}
	}
	if want := map[string]string{"POD_NAME": "metadata.name", "POD_UID": "metadata.uid", "POD_NAMESPACE": "metadata.namespace", "SERVICE_ACCOUNT": "spec.serviceAccountName"}; !reflect.DeepEqual(fields, want) {
		t.Errorf("celld pod variables are %v, want %v", fields, want)
	}
	mounts := map[string]map[string]any{}
	for _, m := range get[[]any](t, celld, "volumeMounts") {
		mounts[get[string](t, m, "name")] = m.(map[string]any)
	}
	for name, path := range map[string]string{"spire-trust-bundle": "/run/celld/trust-bundle", "mgmt-op-key": "/run/celld/op-key",
		"celld-api-token": "/var/run/secrets/kubernetes.io/serviceaccount"} {
		m := mounts[name]
		if m == nil || m["mountPath"] != path || m["readOnly"] != true {
			t.Errorf("celld mount %s is %v, want a read-only mount at %s", name, m, path)
		}
	}
	volumes := get[[]any](t, pod, "volumes")
	for name, cm := range map[string]string{"spire-trust-bundle": "spire-trust-bundle", "mgmt-op-key": "mgmt-op-key"} {
		if got := get[string](t, named(t, volumes, name), "configMap", "name"); got != cm {
			t.Errorf("volume %s is ConfigMap %s, want %s", name, got, cm)
		}
	}
	token := named(t, volumes, "celld-api-token")
	if get[float64](t, token, "projected", "sources", 0, "serviceAccountToken", "expirationSeconds") != 3600 || get[string](t, token, "projected", "sources", 0, "serviceAccountToken", "path") != "token" {
		t.Errorf("volume celld-api-token is %v, want a projected token with the path token and 3600 s", token)
	}
	// The token goes only to the containers that call the API server: celld for its token requests and its operation
	// records, and the agent for its own. The installer gets none.
	for _, c := range append(slices.Clone(get[[]any](t, pod, "initContainers")), get[[]any](t, pod, "containers")...) {
		name := get[string](t, c, "name")
		for _, m := range get[[]any](t, c, "volumeMounts") {
			if get[string](t, m, "mountPath") == "/var/run/secrets/kubernetes.io/serviceaccount" && name != "celld" && name != "spire-agent" {
				t.Errorf("container %s mounts the API token", name)
			}
		}
	}
	if _, ok := objs["ConfigMap/mgmt-root"]; ok {
		t.Error("the render still prints ConfigMap mgmt-root")
	}
	if strings.Contains(r.stdout, "mgmt-root") || strings.Contains(r.stdout, "30447") || strings.Contains(r.stdout, "--bind-") {
		t.Error("the render still names mgmt-root, port 30447 or a --bind- flag")
	}

	// The key ConfigMap holds the stub signing key of mgmtd, and both checksums on the pod template follow the content.
	key := objs["ConfigMap/mgmt-op-key"]
	if key == nil || get[string](t, key, "data", "op.pub") != stubMgmtKey {
		t.Fatalf("ConfigMap mgmt-op-key is %v, want op.pub = %s", key, stubMgmtKey)
	}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	ann := get[map[string]any](t, dep, "spec", "template", "metadata", "annotations")
	if ann["poc.internal/op-key-sha256"] != sum(stubMgmtKey) || get[string](t, key, "metadata", "annotations", "poc.internal/op-key-sha256") != sum(stubMgmtKey) {
		t.Errorf("op key checksum is %v, want %s", ann["poc.internal/op-key-sha256"], sum(stubMgmtKey))
	}
	if ann["poc.internal/trust-bundle-sha256"] != sum(strings.TrimRight(r.bundle, "\n")) && ann["poc.internal/trust-bundle-sha256"] != sum(r.bundle) {
		t.Errorf("trust bundle checksum is %v, want the SHA-256 of the bundle", ann["poc.internal/trust-bundle-sha256"])
	}
	other := renderCellIdentity(t, "STUB_MGMT_KEY="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if other.err != nil {
		t.Fatalf("render with another key failed: %v\n%s", other.err, other.stderr)
	}
	annOther := get[map[string]any](t, docsIn(t, other.stdout, "cell-identity-system")["Deployment/celld"], "spec", "template", "metadata", "annotations")
	if annOther["poc.internal/op-key-sha256"] == ann["poc.internal/op-key-sha256"] {
		t.Error("a new signing key leaves the op key checksum as it was, so the pod would not restart")
	}
	// A render in another cell names that cell.
	r2 := renderCellIdentity(t, "CELL_NAME=dev-cell-2")
	celld2 := named(t, get[[]any](t, get[map[string]any](t, docsIn(t, r2.stdout, "cell-identity-system")["Deployment/celld"], "spec", "template", "spec"), "containers"), "celld")
	if args := fmt.Sprint(get[[]any](t, celld2, "args")); !strings.Contains(args, "--cell=dev-cell-2") {
		t.Errorf("celld args in dev-cell-2 are %s", args)
	}
}

// TestCellOpsNamespace checks the namespace of the operation records: restricted, out of the mesh, a default deny,
// no pod, and Role celld-ops with only the five ConfigMap verbs, bound to the celld account of cell-identity-system.
func TestCellOpsNamespace(t *testing.T) {
	r := renderCellIdentity(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	all := objectsIn(t, r.stdout)
	objs := map[string]object{}
	for _, o := range all {
		if v, _ := lookup(o, "metadata", "namespace"); v == "cell-ops-system" {
			objs[get[string](t, o, "kind")+"/"+get[string](t, o, "metadata", "name")] = o
		}
	}
	ns := all["Namespace cell-ops-system"]
	if ns == nil {
		t.Fatal("the render prints no Namespace cell-ops-system")
	}
	if labels := get[map[string]any](t, ns, "metadata", "labels"); labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["istio-injection"] != "disabled" ||
		labels["cell.poc.internal/harness"] != "cell-identity" {
		t.Errorf("namespace labels are %v", labels)
	}
	var kinds []string
	for key, o := range objs {
		kinds = append(kinds, key)
		if v, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); v != "cell-identity" {
			t.Errorf("%s has harness label %v, want cell-identity", key, v)
		}
	}
	slices.Sort(kinds)
	if want := []string{"NetworkPolicy/default-deny", "Role/celld-ops", "RoleBinding/celld-ops"}; !slices.Equal(kinds, want) {
		t.Fatalf("objects in cell-ops-system are %v, want %v", kinds, want)
	}
	deny := objs["NetworkPolicy/default-deny"]
	if len(get[[]any](t, deny, "spec", "policyTypes")) != 2 || len(get[map[string]any](t, deny, "spec", "podSelector")) != 0 || len(get[map[string]any](t, deny, "spec")) != 2 {
		t.Errorf("default-deny spec is %v", deny["spec"])
	}
	rules := get[[]any](t, objs["Role/celld-ops"], "rules")
	if len(rules) != 1 || fmt.Sprint(lookupOr(rules[0], "resources")) != "[configmaps]" || fmt.Sprint(lookupOr(rules[0], "apiGroups")) != "[]" ||
		fmt.Sprint(lookupOr(rules[0], "verbs")) != "[create get list update delete]" {
		t.Errorf("Role celld-ops rules are %v, want configmaps with create, get, list, update, delete only", rules)
	}
	if _, ok := lookup(rules[0], "resourceNames"); ok {
		t.Error("Role celld-ops has resourceNames, and create cannot name an object")
	}
	rb := objs["RoleBinding/celld-ops"]
	if get[string](t, rb, "roleRef", "name") != "celld-ops" || len(get[[]any](t, rb, "subjects")) != 1 ||
		get[string](t, rb, "subjects", 0, "name") != "celld" || get[string](t, rb, "subjects", 0, "namespace") != "cell-identity-system" ||
		get[string](t, rb, "subjects", 0, "kind") != "ServiceAccount" {
		t.Errorf("RoleBinding celld-ops is %v", rb)
	}
}

func TestRenderCellIdentityChecksumDiffersByCell(t *testing.T) {
	sums := map[string]string{}
	for _, cell := range []string{"dev-cell-1", "dev-cell-2", "dev-cell-1 again"} {
		r := renderCellIdentity(t, "CELL_NAME="+strings.TrimSuffix(cell, " again"))
		if r.err != nil {
			t.Fatalf("render for %s failed: %v\n%s", cell, r.err, r.stderr)
		}
		sums[cell] = get[string](t, docsIn(t, r.stdout, "cell-identity-system")["Deployment/celld"],
			"spec", "template", "metadata", "annotations", "cell.poc.internal/config-checksum")
	}
	if sums["dev-cell-1"] == sums["dev-cell-2"] {
		t.Fatalf("both cells have config checksum %s", sums["dev-cell-1"])
	}
	if sums["dev-cell-1"] != sums["dev-cell-1 again"] {
		t.Fatalf("two renders of dev-cell-1 have checksums %s and %s", sums["dev-cell-1"], sums["dev-cell-1 again"])
	}
}

func TestRenderCellIdentityFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"no management signing key", []string{"STUB_NO_MGMT_KEY=1"}, "ConfigMap mgmt-system/mgmt-signing-pub is absent. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
		{"no SPIRE server", []string{"STUB_NO_SERVER=1"}, "could not read the trust bundle from spire-server-0 in dev-cp. Run CELL=dev-cp mise run cell:up first"},
		{"bundle with other text", []string{"STUB_BAD_BUNDLE=1"}, "trust bundle holds text other than PEM certificates"},
		{"bundle of another trust domain", []string{"STUB_TRUST_DOMAIN=rogue.example"}, "want spiffe://dev.env.poc.internal"},
		{"server cluster without facts", []string{"SPIRE_SERVER_CLUSTER=bad-facts"}, "no host service facts for bad-facts"},
		{"server cluster without node address", []string{"SPIRE_SERVER_CLUSTER=no-ip"}, "node address of no-ip"},
		{"no images file", []string{"STUB_IMAGES=missing"}, "Run mise run images first"},
		{"stale images file", []string{"STUB_IMAGES=stale"}, "Run mise run images again"},
		{"bad API server address", []string{"API_SERVER_IPS=api.example"}, "not IPv4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := renderCellIdentity(t, tc.env...)
			if r.err == nil {
				t.Fatal("render succeeded")
			}
			if r.stdout != "" {
				t.Fatalf("render printed manifests on failure:\n%s", r.stdout)
			}
			if !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("stderr %q does not contain %q", r.stderr, tc.want)
			}
		})
	}
}

// TestCellIdentityNextKey: while mgmtd has staged a key, ConfigMap mgmt-op-key holds both files, op.pub with the live key and
// op.next.pub with the staged key, and the checksum of the ConfigMap and of the pod template covers both, so the stage pass
// restarts celld. The staged key must match `mgmt -- status`: a next.pub that mgmtd did not stage, a stagedKey with no next.pub,
// and a next.pub with another hash each fail the render, and MGMT_KEY_ACCEPT_CHANGE does not override it. With nothing staged,
// the ConfigMap holds op.pub only.
func TestCellIdentityNextKey(t *testing.T) {
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	next := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

	t.Run("staged key", func(t *testing.T) {
		r := renderCellIdentity(t, "STUB_NEXT_PUB="+next)
		if r.err != nil {
			t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
		}
		objs := docsIn(t, r.stdout, "cell-identity-system")
		key := objs["ConfigMap/mgmt-op-key"]
		if key == nil || get[string](t, key, "data", "op.pub") != stubMgmtKey || get[string](t, key, "data", "op.next.pub") != next {
			t.Fatalf("ConfigMap mgmt-op-key is %v, want op.pub = %s and op.next.pub = %s", key, stubMgmtKey, next)
		}
		want := sum(stubMgmtKey + "\n" + next)
		ann := get[map[string]any](t, objs["Deployment/celld"], "spec", "template", "metadata", "annotations")
		if got := get[string](t, key, "metadata", "annotations", "poc.internal/op-key-sha256"); got != want || ann["poc.internal/op-key-sha256"] != want {
			t.Errorf("op key checksums are %s (ConfigMap) and %v (pod template), want %s over both keys", got, ann["poc.internal/op-key-sha256"], want)
		}
		plain := renderCellIdentity(t)
		if plain.err != nil {
			t.Fatal(plain.err)
		}
		plainAnn := get[map[string]any](t, docsIn(t, plain.stdout, "cell-identity-system")["Deployment/celld"], "spec", "template", "metadata", "annotations")
		if plainAnn["poc.internal/op-key-sha256"] == ann["poc.internal/op-key-sha256"] {
			t.Error("the pod template checksum is the same with and without a staged key, so the stage pass would not restart celld")
		}
	})

	t.Run("nothing staged", func(t *testing.T) {
		r := renderCellIdentity(t)
		if r.err != nil {
			t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
		}
		key := docsIn(t, r.stdout, "cell-identity-system")["ConfigMap/mgmt-op-key"]
		if data := get[map[string]any](t, key, "data"); len(data) != 1 || data["op.pub"] != stubMgmtKey {
			t.Errorf("ConfigMap mgmt-op-key data is %v, want op.pub only", data)
		}
		if get[string](t, key, "metadata", "annotations", "poc.internal/op-key-sha256") != sum(stubMgmtKey) {
			t.Errorf("the checksum with no staged key is not the SHA-256 of op.pub")
		}
	})

	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"next.pub with another hash than stagedKey", []string{"STUB_NEXT_PUB=" + next, "STUB_STAGED_KEY=" + strings.Repeat("0", 64)}, "has the SHA-256"},
		{"stagedKey and no next.pub", []string{"STUB_STAGED_KEY=" + strings.Repeat("a", 64)}, "next.pub is not the base64 of 32 bytes"},
		{"next.pub that is not a key", []string{"STUB_NEXT_PUB=bm90LWEta2V5", "STUB_STAGED_KEY=" + strings.Repeat("a", 64)}, "next.pub is not the base64 of 32 bytes"},
		{"no override", []string{"STUB_NEXT_PUB=" + next, "STUB_STAGED_KEY=" + strings.Repeat("0", 64), "MGMT_KEY_ACCEPT_CHANGE=1"}, "has the SHA-256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := renderCellIdentity(t, tc.env...)
			if r.err == nil {
				t.Fatalf("the render succeeded, want a failure with %q:\n%s", tc.want, r.stdout)
			}
			if !strings.Contains(r.stderr, tc.want) {
				t.Errorf("stderr %q does not contain %q", r.stderr, tc.want)
			}
			if strings.Contains(r.stdout, "op.next.pub") {
				t.Error("the failed render still printed a staged key")
			}
		})
	}
}
