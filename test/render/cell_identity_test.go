package render

import (
	"crypto/sha256"
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
		// and the agent share the socket. TestRenderCellIdentityBindFlags checks the celld volumes.
		mounts := func(name string) []string {
			var out []string
			for _, m := range get[[]any](t, named(t, mains, name), "volumeMounts") {
				out = append(out, get[string](t, m, "name"))
			}
			return out
		}
		if m := mounts("celld"); !slices.Equal(m, []string{"agent-socket", "mgmt-root", "celld-api-token"}) {
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

	t.Run("network policy allows only the SPIRE and bind node ports, the API server and the collector", func(t *testing.T) {
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
		want := []string{"10.9.0.9/32 TCP/30081,TCP/30447", "172.18.0.5/32 TCP/6443", "10.120.0.1/32 TCP/443", "ns=observability-system/app=otel-collector TCP/4317"}
		if !slices.Equal(rules, want) {
			t.Fatalf("egress rules are %v, want %v", rules, want)
		}
		dns := objs["NetworkPolicy/allow-dns"]
		if cidr := get[string](t, dns, "spec", "egress", 0, "to", 1, "ipBlock", "cidr"); cidr != "10.120.0.10/32" {
			t.Fatalf("DNS service peer is %q", cidr)
		}
	})
}

// TestRenderCellIdentityBindFlags checks what celld needs to bind its cell to the management plane: the four
// flags, the four pod variables, a read-only projected API token that only celld and the agent mount, the
// mgmt-root mount, and the checksum of the management root on the pod template.
func TestRenderCellIdentityBindFlags(t *testing.T) {
	r := renderCellIdentity(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docsIn(t, r.stdout, "cell-identity-system")
	dep := objs["Deployment/celld"]
	pod := get[map[string]any](t, dep, "spec", "template", "spec")
	celld := named(t, get[[]any](t, pod, "containers"), "celld")
	if got, want := fmt.Sprint(get[[]any](t, celld, "args")), fmt.Sprint([]string{
		"--cell=dev-cell-1", "--bind-upstream=10.9.0.9:30447", "--bind-expect-id=spiffe://mgmt.poc.internal/api",
		"--bind-peer-bundle=/run/celld/mgmt-root/root.crt"}); got != want {
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
	for name, path := range map[string]string{"mgmt-root": "/run/celld/mgmt-root", "celld-api-token": "/var/run/secrets/kubernetes.io/serviceaccount"} {
		m := mounts[name]
		if m == nil || m["mountPath"] != path || m["readOnly"] != true {
			t.Errorf("celld mount %s is %v, want a read-only mount at %s", name, m, path)
		}
	}
	volumes := get[[]any](t, pod, "volumes")
	root := named(t, volumes, "mgmt-root")
	if get[string](t, root, "configMap", "name") != "mgmt-root" {
		t.Errorf("volume mgmt-root is %v, want ConfigMap mgmt-root", root)
	}
	token := named(t, volumes, "celld-api-token")
	if get[float64](t, token, "projected", "sources", 0, "serviceAccountToken", "expirationSeconds") != 3600 || get[string](t, token, "projected", "sources", 0, "serviceAccountToken", "path") != "token" {
		t.Errorf("volume celld-api-token is %v, want a projected token with the path token and 3600 s", token)
	}
	// The token goes only to the containers that call the API server: celld for its bind token request,
	// and the agent for its own. The installer gets none.
	for _, c := range append(slices.Clone(get[[]any](t, pod, "initContainers")), get[[]any](t, pod, "containers")...) {
		name := get[string](t, c, "name")
		for _, m := range get[[]any](t, c, "volumeMounts") {
			if get[string](t, m, "mountPath") == "/var/run/secrets/kubernetes.io/serviceaccount" && name != "celld" && name != "spire-agent" {
				t.Errorf("container %s mounts the API token", name)
			}
		}
	}
	cm := objs["ConfigMap/mgmt-root"]
	if cm == nil || get[string](t, cm, "data", "root.crt") == "" {
		t.Fatal("the render prints no ConfigMap mgmt-root with the key root.crt")
	}
	if got := get[string](t, cm, "data", "root.crt"); !strings.Contains(got, "BEGIN CERTIFICATE") || strings.TrimSpace(got) == strings.TrimSpace(r.bundle) {
		t.Errorf("mgmt-root holds %q, want the root of the management trust domain and not the one of dev-cp", got)
	}
	sum := get[string](t, dep, "spec", "template", "metadata", "annotations", "poc.internal/peer-root-sha256")
	if want := sha256.Sum256([]byte(strings.TrimRight(get[string](t, cm, "data", "root.crt"), "\n"))); sum != hex.EncodeToString(want[:]) {
		t.Errorf("the pod carries the root digest %s, want the SHA-256 of mgmt-root", sum)
	}
	for _, want := range []string{"kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show"} {
		if !strings.Contains(r.log, want) {
			t.Errorf("render did not run %q; it ran:\n%s", want, r.log)
		}
	}
	// A render in another cell names that cell.
	r2 := renderCellIdentity(t, "CELL_NAME=dev-cell-2")
	celld2 := named(t, get[[]any](t, get[map[string]any](t, docsIn(t, r2.stdout, "cell-identity-system")["Deployment/celld"], "spec", "template", "spec"), "containers"), "celld")
	if args := fmt.Sprint(get[[]any](t, celld2, "args")); !strings.Contains(args, "--cell=dev-cell-2") {
		t.Errorf("celld args in dev-cell-2 are %s", args)
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
		{"no management SPIRE server", []string{"STUB_NO_SERVER_IN=management"}, "could not read the trust bundle from spire-server-0 in management. Run CELL=management mise run cell:up first"},
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
