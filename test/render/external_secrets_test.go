package render

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const (
	esoNamespace = "external-secrets"
	// storeNamespace is SECRET_STORE_NAMESPACES of cells/dev-cp.env: the one namespace where the
	// operator works.
	storeNamespace = "spire-system"
)

// esoFacts are the cluster facts that render.sh reads, in the form of build/<cluster>/facts.env,
// and the store namespace from cells/dev-cp.env.
var esoFacts = []string{
	"SECRET_STORE_NAMESPACES=" + storeNamespace,
	"POD_CIDR=10.11.0.0/16",
	"SERVICE_CIDR=10.111.0.0/16",
	"API_SERVER_IPS=172.18.0.4",
	"API_SERVER_PORT=6443",
	"API_SERVICE_IP=10.111.0.1",
	"DNS_SERVICE_IP=10.111.0.10",
}

// commonEnv reads one setting from cells/common.env.
func commonEnv(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../../cells/common.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, name+"="); ok {
			return v
		}
	}
	t.Fatalf("cells/common.env sets no %s", name)
	return ""
}

func renderExternalSecrets(t *testing.T, env ...string) (string, string, error) {
	t.Helper()
	testtool.Need(t, "helm", "bash")
	script, err := filepath.Abs("../../components/external-secrets/render.sh")
	if err != nil {
		t.Fatal(err)
	}
	// helm reads the values file in a child process. Reading it here puts it in the go test cache key.
	if _, err := os.ReadFile("../../components/external-secrets/values.yaml"); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"EXTERNAL_SECRETS_VERSION=" + commonEnv(t, "EXTERNAL_SECRETS_VERSION")}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	return stdout.String(), stderr.String(), err
}

// esoDocs parses the render into objects keyed by kind/name. Namespaced objects must be in
// external-secrets, apart from the Roles and RoleBindings of the store namespace.
func esoDocs(t *testing.T, out string) map[string]object {
	t.Helper()
	clusterScoped := []string{"Namespace", "CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding",
		"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}
	byKey := map[string]object{}
	for _, d := range regexp.MustCompile(`(?m)^---\s*$`).Split(out, -1) {
		var o object
		if err := yaml.Unmarshal([]byte(d), &o); err != nil {
			t.Fatalf("output document does not parse: %v\n%s", err, d)
		}
		if o == nil {
			continue
		}
		kind := get[string](t, o, "kind")
		key := kind + "/" + get[string](t, o, "metadata", "name")
		if _, dup := byKey[key]; dup {
			t.Fatalf("%s appears twice", key)
		}
		ns, _ := lookup(o, "metadata", "namespace")
		if slices.Contains(clusterScoped, kind) {
			if ns != nil {
				t.Fatalf("cluster-scoped %s has namespace %v", key, ns)
			}
		} else if ns != esoNamespace && !(ns == storeNamespace && (kind == "Role" || kind == "RoleBinding")) {
			t.Fatalf("%s has namespace %v, want %s", key, ns, esoNamespace)
		}
		byKey[key] = o
	}
	return byKey
}

func TestRenderExternalSecrets(t *testing.T) {
	out, stderr, err := renderExternalSecrets(t, esoFacts...)
	if err != nil {
		t.Fatalf("render failed: %v\n%s", err, stderr)
	}
	objs := esoDocs(t, out)

	t.Run("only the controller runs", func(t *testing.T) {
		var workloads []string
		for key := range objs {
			kind := strings.Split(key, "/")[0]
			switch kind {
			case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod":
				workloads = append(workloads, key)
			case "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "Service", "Certificate", "ServiceMonitor":
				t.Fatalf("render contains %s", key)
			}
		}
		if !slices.Equal(workloads, []string{"Deployment/external-secrets"}) {
			t.Fatalf("workloads are %v, want only the controller", workloads)
		}
		if strings.Contains(out, "cert-controller") || strings.Contains(out, "-webhook") {
			t.Fatal("render contains cert controller or webhook objects")
		}
	})

	t.Run("namespace enforces restricted pod security outside the mesh", func(t *testing.T) {
		labels := get[map[string]any](t, objs["Namespace/"+esoNamespace], "metadata", "labels")
		if labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["istio-injection"] != "disabled" {
			t.Fatalf("namespace labels are %v", labels)
		}
	})

	t.Run("controller", func(t *testing.T) {
		pod := get[map[string]any](t, objs["Deployment/external-secrets"], "spec", "template", "spec")
		containers := get[[]any](t, pod, "containers")
		if len(containers) != 1 {
			t.Fatalf("got %d containers", len(containers))
		}
		if _, ok := pod["initContainers"]; ok {
			t.Fatal("the pod has init containers")
		}
		c := containers[0]
		if image := get[string](t, c, "image"); image != "ghcr.io/external-secrets/external-secrets:v2.14.0@sha256:10608eb53e636e744903d5f3657a4d9c44e28d9d9c181b73e07bc7dd2e6884dc" {
			t.Fatalf("image is %q", image)
		}
		sc := get[map[string]any](t, c, "securityContext")
		if sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true || sc["runAsNonRoot"] != true ||
			get[string](t, sc, "seccompProfile", "type") != "RuntimeDefault" ||
			!slices.Equal(get[[]any](t, sc, "capabilities", "drop"), []any{"ALL"}) {
			t.Fatalf("securityContext is %v", sc)
		}
		if pod["hostNetwork"] == true {
			t.Fatal("the pod uses the host network")
		}
		var args []string
		for _, a := range get[[]any](t, c, "args") {
			args = append(args, a.(string))
		}
		for _, want := range []string{
			"--live-addr=0",
			"--namespace=" + storeNamespace,
			"--enable-cluster-store-reconciler=false",
			"--enable-cluster-external-secret-reconciler=false",
			"--enable-push-secret-reconciler=false",
			"--enable-cluster-push-secret-reconciler=false",
			"--zap-time-encoding=iso8601",
		} {
			if !slices.Contains(args, want) {
				t.Fatalf("args %v lack %s", args, want)
			}
		}
		// The SecretStore reconciler sets the Ready condition that secrets:connect waits for.
		if slices.Contains(args, "--enable-secret-store-reconciler=false") {
			t.Fatalf("args %v turn off the SecretStore reconciler", args)
		}
		if _, ok := lookup(c, "resources", "limits", "memory"); !ok {
			t.Fatal("the controller has no memory limit")
		}
	})

	t.Run("CRDs cover only the kinds the cell uses, with no conversion webhook", func(t *testing.T) {
		var crds []string
		for key, o := range objs {
			name, ok := strings.CutPrefix(key, "CustomResourceDefinition/")
			if !ok {
				continue
			}
			crds = append(crds, name)
			if strategy, ok := lookup(o, "spec", "conversion", "strategy"); ok && strategy != "None" {
				t.Fatalf("%s has conversion strategy %v", name, strategy)
			}
		}
		for _, want := range []string{"externalsecrets.external-secrets.io", "secretstores.external-secrets.io", "generatorstates.generators.external-secrets.io"} {
			if !slices.Contains(crds, want) {
				t.Fatalf("CRDs %v lack %s", crds, want)
			}
		}
		for _, unwanted := range []string{"pushsecrets", "clusterpushsecrets", "clusterexternalsecrets", "clustersecretstores"} {
			if slices.Contains(crds, unwanted+".external-secrets.io") {
				t.Fatalf("CRDs include %s", unwanted)
			}
		}
		if slices.Contains(crds, "clustergenerators.generators.external-secrets.io") {
			t.Fatal("CRDs include clustergenerators")
		}
	})

	// The operator can read and write Secrets only in the store namespace, and it reads no store
	// that spans namespaces.
	t.Run("RBAC is scoped to the store namespace", func(t *testing.T) {
		for key := range objs {
			if kind := strings.Split(key, "/")[0]; kind == "ClusterRole" || kind == "ClusterRoleBinding" {
				t.Fatalf("render contains %s", key)
			}
		}
		binding := objs["RoleBinding/external-secrets-controller"]
		if binding == nil {
			t.Fatal("render has no RoleBinding external-secrets-controller")
		}
		if ns := get[string](t, binding, "metadata", "namespace"); ns != storeNamespace {
			t.Fatalf("the controller RoleBinding is in %s, want %s", ns, storeNamespace)
		}
		if ref := get[map[string]any](t, binding, "roleRef"); ref["kind"] != "Role" || ref["name"] != "external-secrets-controller" {
			t.Fatalf("the controller RoleBinding refers to %v", ref)
		}
		subjects := get[[]any](t, binding, "subjects")
		if len(subjects) != 1 || get[string](t, subjects[0], "name") != "external-secrets" ||
			get[string](t, subjects[0], "namespace") != esoNamespace || get[string](t, subjects[0], "kind") != "ServiceAccount" {
			t.Fatalf("the controller RoleBinding binds %v", subjects)
		}
		for key, o := range objs {
			if !strings.HasPrefix(key, "Role/") {
				continue
			}
			rules, _ := lookup(o, "rules")
			list, _ := rules.([]any)
			for _, rule := range list {
				if res, ok := lookup(rule, "resources"); ok && slices.Contains(res.([]any), any("clustersecretstores")) {
					t.Fatalf("%s grants access to ClusterSecretStore objects", key)
				}
			}
		}
	})

	// The operator bundle holds the store namespace, because its Role lives there and the bundle of
	// the namespace comes in a later sync wave. Prune=false keeps the namespace and its data when a
	// bundle drops it.
	t.Run("store namespace enforces restricted pod security outside the mesh and is never pruned", func(t *testing.T) {
		ns := objs["Namespace/"+storeNamespace]
		if ns == nil {
			t.Fatalf("render has no Namespace %s", storeNamespace)
		}
		labels := get[map[string]any](t, ns, "metadata", "labels")
		if labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["istio-injection"] != "disabled" {
			t.Fatalf("namespace labels are %v", labels)
		}
		if got := get[string](t, ns, "metadata", "annotations", "argocd.argoproj.io/sync-options"); got != "Prune=false" {
			t.Fatalf("the sync options of Namespace %s are %q, want Prune=false", storeNamespace, got)
		}
	})

	t.Run("RBAC grants no token minting, wildcards or aggregation", func(t *testing.T) {
		for key, o := range objs {
			kind := strings.Split(key, "/")[0]
			if kind != "ClusterRole" && kind != "Role" {
				continue
			}
			if labels, ok := lookup(o, "metadata", "labels"); ok {
				for l := range labels.(map[string]any) {
					if strings.HasPrefix(l, "rbac.authorization.k8s.io/aggregate-to-") {
						t.Fatalf("%s aggregates to a user role with %s", key, l)
					}
				}
			}
			rules, _ := lookup(o, "rules")
			list, _ := rules.([]any)
			for _, rule := range list {
				for _, field := range []string{"apiGroups", "resources", "verbs"} {
					if v, ok := lookup(rule, field); ok && slices.Contains(v.([]any), any("*")) {
						t.Fatalf("%s has a wildcard in %s", key, field)
					}
				}
				if res, ok := lookup(rule, "resources"); ok && slices.Contains(res.([]any), any("serviceaccounts/token")) {
					t.Fatalf("%s can create ServiceAccount tokens", key)
				}
				if res, ok := lookup(rule, "resources"); ok && slices.Contains(res.([]any), any("namespaces")) {
					if verbs := get[[]any](t, rule, "verbs"); slices.Contains(verbs, any("update")) || slices.Contains(verbs, any("patch")) {
						t.Fatalf("%s can change namespaces", key)
					}
				}
			}
		}
	})

	// The chart renders the view and edit ClusterRoles whenever rbac.create is true. They grant
	// nothing while no binding and no aggregation label refers to them.
	t.Run("no binding refers to the view or edit ClusterRole", func(t *testing.T) {
		for key, o := range objs {
			kind := strings.Split(key, "/")[0]
			if kind != "ClusterRoleBinding" && kind != "RoleBinding" {
				continue
			}
			if role := get[string](t, o, "roleRef", "name"); role == "external-secrets-view" || role == "external-secrets-edit" {
				t.Fatalf("%s binds %s", key, role)
			}
		}
	})

	t.Run("network policy", func(t *testing.T) {
		var policies []object
		for key, o := range objs {
			if strings.HasPrefix(key, "NetworkPolicy/") {
				policies = append(policies, o)
				if _, ok := lookup(o, "spec", "ingress"); ok {
					t.Fatalf("%s allows ingress", key)
				}
			}
		}
		deny := objs["NetworkPolicy/default-deny"]
		if types := get[[]any](t, deny, "spec", "policyTypes"); !slices.Equal(types, []any{"Ingress", "Egress"}) ||
			len(get[map[string]any](t, deny, "spec", "podSelector")) != 0 {
			t.Fatalf("default-deny spec is %v", deny["spec"])
		}
		if _, ok := lookup(deny, "spec", "egress"); ok {
			t.Fatal("default-deny has egress rules")
		}

		// Collect every egress rule as peer -> ports.
		type rule struct {
			peers []any
			ports []string
		}
		var rules []rule
		for _, p := range policies {
			egress, _ := lookup(p, "spec", "egress")
			list, _ := egress.([]any)
			for _, e := range list {
				var r rule
				r.peers = get[[]any](t, e, "to")
				for _, port := range get[[]any](t, e, "ports") {
					r.ports = append(r.ports, get[string](t, port, "protocol")+"/"+fmt.Sprint(get[any](t, port, "port")))
				}
				slices.Sort(r.ports)
				rules = append(rules, r)
			}
		}

		var internet []any
		cidrs := map[string][]string{}
		for _, r := range rules {
			for _, peer := range r.peers {
				if cidr, ok := lookup(peer, "ipBlock", "cidr"); ok {
					if cidr == "0.0.0.0/0" {
						if !slices.Equal(r.ports, []string{"TCP/443"}) {
							t.Fatalf("internet egress ports are %v, want only TCP/443", r.ports)
						}
						internet = append(internet, peer)
						continue
					}
					cidrs[cidr.(string)] = r.ports
				}
			}
		}
		if got := cidrs["172.18.0.4/32"]; !slices.Equal(got, []string{"TCP/6443"}) {
			t.Fatalf("API server egress ports are %v", got)
		}
		if got := cidrs["10.111.0.1/32"]; !slices.Equal(got, []string{"TCP/443"}) {
			t.Fatalf("API service egress ports are %v", got)
		}
		if got := cidrs["10.111.0.10/32"]; !slices.Equal(got, []string{"TCP/53", "UDP/53"}) {
			t.Fatalf("DNS egress ports are %v", got)
		}
		if len(internet) != 1 {
			t.Fatalf("got %d internet peers", len(internet))
		}
		var except []netip.Prefix
		for _, e := range get[[]any](t, internet[0], "ipBlock", "except") {
			except = append(except, netip.MustParsePrefix(e.(string)))
		}
		// The pod, service and kind network ranges must be outside the internet rule.
		for _, inner := range []string{"10.11.0.0/16", "10.111.0.0/16", "172.18.0.0/16", "192.168.5.0/24", "127.0.0.0/8"} {
			p := netip.MustParsePrefix(inner)
			if !slices.ContainsFunc(except, func(e netip.Prefix) bool { return e.Bits() <= p.Bits() && e.Contains(p.Addr()) }) {
				t.Fatalf("internet egress does not exclude %s; except is %v", inner, except)
			}
		}
	})
}

func TestRenderExternalSecretsNeedsOneStoreNamespace(t *testing.T) {
	for name, value := range map[string]string{"none": "", "two": "spire-system other", "not a label": "Spire_System"} {
		t.Run(name, func(t *testing.T) {
			env := append(slices.Clone(esoFacts[1:]), "SECRET_STORE_NAMESPACES="+value)
			out, stderr, err := renderExternalSecrets(t, env...)
			if err == nil || out != "" {
				t.Fatalf("render succeeded or printed manifests, err %v", err)
			}
			if !strings.Contains(stderr, "SECRET_STORE_NAMESPACES") {
				t.Fatalf("stderr %q does not name SECRET_STORE_NAMESPACES", stderr)
			}
		})
	}
}

func TestRenderExternalSecretsFailsClosed(t *testing.T) {
	for _, missing := range []string{"API_SERVER_IPS", "API_SERVER_PORT", "API_SERVICE_IP", "DNS_SERVICE_IP"} {
		t.Run(missing, func(t *testing.T) {
			var env []string
			for _, f := range esoFacts {
				if !strings.HasPrefix(f, missing+"=") {
					env = append(env, f)
				}
			}
			out, stderr, err := renderExternalSecrets(t, env...)
			if err == nil {
				t.Fatal("render succeeded")
			}
			if out != "" {
				t.Fatalf("render printed manifests on failure:\n%s", out)
			}
			if !strings.Contains(stderr, missing) {
				t.Fatalf("stderr %q does not name %s", stderr, missing)
			}
		})
	}
}
