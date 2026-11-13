package render

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

const viewNS = "central-view-system"

// renderCentralView renders the central view with cells/common.env and cells/management.env, as
// the link phase does. The env values override them.
func renderCentralView(t *testing.T, env ...string) result {
	t.Helper()
	base := []string{"STUB_CELL=management", "CELL_NAME=management"}
	return renderScript(t, "central-view", "/ko-app/stub", append(append(base, bundleFacts...), env...)...)
}

// viewDocs parses a central view render by kind, namespace and name.
func viewDocs(t *testing.T, out string) map[string]object {
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

func principalTemplate(t *testing.T, objs map[string]object) map[string]any {
	t.Helper()
	d, ok := objs["Deployment "+viewNS+"/argocd-agent-principal"]
	if !ok {
		t.Fatal("no Deployment argocd-agent-principal")
	}
	return get[map[string]any](t, d, "spec", "template")
}

// Two renders, each with new record signatures and a new signing key, give the same registry
// checksum and the same principal pod template, so a new hydrate with the same cells restarts
// nothing. A revoked flag changes the checksum. The checksum is the SHA-256 of the sorted
// "<name> <env> <revoked>" lines, as cell-proxy computes it.
func TestRegistryChecksumIgnoresSignature(t *testing.T) {
	sumOf := func(r result) (string, string) {
		t.Helper()
		if r.err != nil {
			t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
		}
		objs := viewDocs(t, r.stdout)
		reg := objs["ConfigMap "+viewNS+"/cell-registry"]
		if reg == nil {
			t.Fatal("no ConfigMap cell-registry")
		}
		sum := get[string](t, reg, "metadata", "annotations", "poc.internal/registry-content-sha256")
		annotation := get[string](t, principalTemplate(t, objs), "metadata", "annotations", "poc.internal/registry-content-sha256")
		if annotation != sum {
			t.Fatalf("pod annotation %s, ConfigMap annotation %s", annotation, sum)
		}
		tmpl, _ := yaml.Marshal(principalTemplate(t, objs))
		return sum, string(tmpl)
	}
	sha := func(lines string) string {
		want := sha256.Sum256([]byte(lines))
		return hex.EncodeToString(want[:])
	}
	first, firstTmpl := sumOf(renderCentralView(t))
	if first != sha("dev-cell-1 dev false\ndev-cell-2 dev false\n") {
		t.Fatalf("registry checksum %s, want the SHA-256 of the sorted record lines", first)
	}
	second, secondTmpl := sumOf(renderCentralView(t, "STUB_RANDOM_SIG=1", "STUB_MGMT_KEY=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="))
	if first != second || firstTmpl != secondTmpl {
		t.Fatalf("the renders differ: checksums %s and %s, templates equal %v", first, second, firstTmpl == secondTmpl)
	}
	revoked, _ := sumOf(renderCentralView(t, "STUB_REVOKED=dev-cell-2"))
	if revoked == first || revoked != sha("dev-cell-1 dev false\ndev-cell-2 dev true\n") {
		t.Fatalf("a revoked record gives checksum %s, and an open one gives %s", revoked, first)
	}
}

// The registry holds the records of the management plane unchanged, and its key in signers.pub.
// A cell without a bound record, or a management plane that cannot answer, stops the render.
func TestRegistryFromManagement(t *testing.T) {
	r := renderCentralView(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	reg := viewDocs(t, r.stdout)["ConfigMap "+viewNS+"/cell-registry"]
	if reg == nil {
		t.Fatal("no ConfigMap cell-registry")
	}
	if got := strings.TrimSpace(get[string](t, reg, "data", "signers.pub")); got != stubMgmtKey {
		t.Fatalf("signers.pub holds %q, want only the stub key %q", got, stubMgmtKey)
	}
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
		payload := base64.StdEncoding.EncodeToString([]byte(`{"name":"` + cell + `","env":"dev","revoked":false}`))
		want := `{"payloadType":"application/vnd.poc.cell-record+json","payload":"` + payload + `","signatures":[{"keyid":"","sig":"sig-` + cell + `"}]}`
		if got := get[string](t, reg, "data", cell+".dsse.json"); got != want {
			t.Errorf("%s.dsse.json is %s, want the record of mgmtd unchanged: %s", cell, got, want)
		}
	}
	if !strings.Contains(r.log, "run mgmt -- records") {
		t.Errorf("the render did not read the records through mise run mgmt:\n%s", r.log)
	}
	if got := len(get[map[string]any](t, reg, "data")); got != 3 {
		t.Errorf("the registry holds %d entries, want 2 records and signers.pub", got)
	}
	for _, tc := range []struct {
		name, want string
		env        []string
	}{
		{"unbound cell", "Run CELL=bad-facts mise run cell:up, so its celld binds", []string{"VIEW_CELLS=dev-cell-1 bad-facts"}},
		{"no answer", "could not read the records of mgmtd", []string{"STUB_NO_MGMT=1"}},
		{"no key", "ConfigMap mgmt-system/mgmt-signing-pub is absent", []string{"STUB_NO_MGMT_KEY=1"}},
		{"other env", "is not a record of dev-cell-1 in env other-env", []string{"POC_ENV=other-env", "STUB_RECORD_ENV=dev"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := renderCentralView(t, tc.env...)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

// The central view renders the principal with its exact settings, from VIEW_CELLS and POC_ENV.
func TestRenderCentralView(t *testing.T) {
	r := renderCentralView(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := viewDocs(t, r.stdout)
	for _, key := range []string{"Namespace central-view-system", "Namespace dev-dev-cell-1", "Namespace dev-dev-cell-2",
		"NetworkPolicy dev-dev-cell-1/default-deny", "NetworkPolicy dev-dev-cell-2/default-deny", "NetworkPolicy central-view-system/default-deny",
		"Deployment central-view-system/argocd-server", "Deployment central-view-system/argocd-repo-server", "Deployment central-view-system/argocd-redis",
		"Job central-view-system/viewkeys", "Service central-view-system/view-listener", "ConfigMap central-view-system/peer-root"} {
		if objs[key] == nil {
			t.Errorf("no %s", key)
		}
	}
	for key, o := range objs {
		if l, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); l != "central-view" {
			t.Errorf("%s has no harness label central-view", key)
		}
		if strings.HasPrefix(key, "Namespace ") && get[string](t, o, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "restricted" {
			t.Errorf("%s is not restricted", key)
		}
		for _, kind := range []string{"CustomResourceDefinition", "StatefulSet"} {
			if o["kind"] == kind {
				t.Errorf("the view renders %s", key)
			}
		}
		if strings.Contains(key, "dex") || strings.Contains(key, "notifications") || strings.Contains(key, "applicationset-controller") ||
			strings.Contains(key, "application-controller") || key == "Secret central-view-system/argocd-secret" {
			t.Errorf("the view renders %s", key)
		}
	}
	tmpl := principalTemplate(t, objs)
	if get[string](t, tmpl, "metadata", "labels", "cell.poc.internal/harness") != "central-view" {
		t.Error("the principal pod template has no harness label")
	}
	containers := get[[]any](t, tmpl, "spec", "containers")
	args := func(name string) []string {
		var out []string
		for _, a := range get[[]any](t, named(t, containers, name), "args") {
			out = append(out, a.(string))
		}
		return out
	}
	for _, want := range []string{"--listen-host=127.0.0.1", "--listen-port=8443", "--insecure-plaintext",
		"--auth=header:x-cell-agent:^(dev-[a-z0-9-]{1,59})$", "--allowed-namespaces=dev-dev-cell-1,dev-dev-cell-2",
		"--namespace-create-enable=false", "--metrics-port=8000", "--healthz-port=8003", "--log-format=json"} {
		if !slices.Contains(args("argocd-agent-principal"), want) {
			t.Errorf("principal args %v lack %s", args("argocd-agent-principal"), want)
		}
	}
	for _, want := range []string{"spiffe-server", "--listen=:8444", "--backend=grpc-header", "--upstream=127.0.0.1:8443",
		`--allow-id=^spiffe://dev\.env\.poc\.internal/cell/([a-z0-9-]+)/argocd-agent$`, "--registry-dir=/run/cell-proxy/registry",
		"--peer-bundle=/run/cell-proxy/peer-root/root.crt", "--peer-trust-domain=dev.env.poc.internal"} {
		if !slices.Contains(args("cell-proxy"), want) {
			t.Errorf("cell-proxy args %v lack %s", args("cell-proxy"), want)
		}
	}
	peer := objs["ConfigMap "+viewNS+"/peer-root"]
	if got := get[string](t, tmpl, "metadata", "annotations", "poc.internal/peer-root-sha256"); got != get[string](t, peer, "metadata", "annotations", "poc.internal/peer-root-sha256") {
		t.Errorf("pod peer root checksum %s differs from the ConfigMap", got)
	}
	cm := get[string](t, objs["ConfigMap "+viewNS+"/argocd-cmd-params-cm"], "data", "application.namespaces")
	if cm != "dev-dev-cell-1,dev-dev-cell-2" {
		t.Errorf("application.namespaces %q", cm)
	}
	if _, ok := lookup(objs["ConfigMap "+viewNS+"/argocd-cmd-params-cm"], "data", "redis.server"); ok {
		t.Error("argocd-cmd-params-cm names a Redis server")
	}
	argoCM := objs["ConfigMap "+viewNS+"/argocd-cm"]
	for k, v := range map[string]string{"users.anonymous.enabled": "true", "admin.enabled": "false", "exec.enabled": "false"} {
		if got, _ := lookup(argoCM, "data", k); got != v {
			t.Errorf("argocd-cm %s = %v, want %s", k, got, v)
		}
	}
	rbac := objs["ConfigMap "+viewNS+"/argocd-rbac-cm"]
	if get[string](t, rbac, "data", "policy.default") != "role:readonly" {
		t.Error("policy.default is not role:readonly")
	}
	for _, action := range []string{"applications, sync", "applications, update", "applications, delete", "applications, override", "applications, action/*", "exec, create"} {
		if !strings.Contains(get[string](t, rbac, "data", "policy.csv"), "p, role:readonly, "+action+", *, deny") {
			t.Errorf("policy.csv has no deny line for %s", action)
		}
	}
	server := get[[]any](t, objs["Deployment "+viewNS+"/argocd-server"], "spec", "template", "spec", "containers")
	env := get[[]any](t, named(t, server, "argocd-server"), "env")
	if v := named(t, env, "REDIS_SERVER")["value"]; v != "argocd-agent-redis-proxy:6379" {
		t.Errorf("argocd-server REDIS_SERVER %v", v)
	}
	role := objs["Role "+viewNS+"/argocd-server"]
	for _, rule := range get[[]any](t, role, "rules") {
		res := fmt.Sprint(get[[]any](t, rule, "resources"))
		if strings.Contains(res, "secrets") || strings.Contains(res, "configmaps") {
			if got := fmt.Sprint(get[[]any](t, rule, "verbs")); got != "[get list watch]" {
				t.Errorf("argocd-server may %s on %s", got, res)
			}
		}
	}
	for _, rule := range get[[]any](t, objs["ClusterRole argocd-server"], "rules") {
		if got := fmt.Sprint(get[[]any](t, rule, "verbs")); got != "[get list watch]" {
			t.Errorf("the argocd-server ClusterRole grants %s", got)
		}
	}
	// In the agent namespaces, only the principal writes, and only Applications.
	for key, o := range objs {
		ns, _ := lookup(o, "metadata", "namespace")
		if ns != "dev-dev-cell-1" && ns != "dev-dev-cell-2" {
			continue
		}
		switch o["kind"] {
		case "Role":
			if key != "Role "+ns.(string)+"/argocd-agent-principal" ||
				fmt.Sprint(o["rules"]) != "[map[apiGroups:[argoproj.io] resources:[applications] verbs:[create get list watch update patch delete]]]" {
				t.Errorf("%s grants %v, want only the principal Role on applications", key, o["rules"])
			}
		case "RoleBinding":
			if subj := fmt.Sprint(o["subjects"]); subj != "[map[kind:ServiceAccount name:argocd-agent-principal namespace:central-view-system]]" {
				t.Errorf("%s binds %s, want the principal only", key, subj)
			}
		}
	}
	crb := objs["ClusterRoleBinding argocd-server"]
	if ns := get[string](t, get[[]any](t, crb, "subjects")[0], "namespace"); ns != viewNS {
		t.Errorf("ClusterRoleBinding argocd-server names namespace %s", ns)
	}
	svc := objs["Service "+viewNS+"/view-listener"]
	if get[string](t, svc, "spec", "externalTrafficPolicy") != "Local" || get[float64](t, get[[]any](t, svc, "spec", "ports")[0], "nodePort") != 31443 {
		t.Errorf("view-listener spec %v", svc["spec"])
	}
	// N1: only the dev-cp node address reaches cell-proxy.
	np := objs["NetworkPolicy "+viewNS+"/argocd-agent-principal"]
	first := get[[]any](t, np, "spec", "ingress")[0]
	if got := fmt.Sprint(get[[]any](t, first, "from")); got != "[map[ipBlock:map[cidr:10.9.0.9/32]]]" {
		t.Errorf("the 8444 rule admits %s, want the dev-cp node only", got)
	}
}

// VIEW_CELLS must name the clusters with the argocd-agent set in harness/topology.yaml, and each
// of them must be in SPIRE_AGENT_CELLS of dev-cp.
func TestViewCellsMatchTopology(t *testing.T) {
	topo, err := topology.Load("../../harness/topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := topo.WithComponent("argocd-agent")
	view := strings.Fields(cellSetting(t, "management", "VIEW_CELLS"))
	slices.Sort(want)
	slices.Sort(view)
	if !slices.Equal(view, want) {
		t.Errorf("VIEW_CELLS of management is %v, and the clusters with an Argo CD Agent are %v", view, want)
	}
	// An agent attests with cluster_jwt, so each agent cluster also runs the cell identity.
	for _, c := range want {
		if !slices.Contains(topo.WithComponent("cell-identity"), c) {
			t.Errorf("%s has the argocd-agent set and not the cell-identity set", c)
		}
	}
	agents := strings.Fields(cellSetting(t, "dev-cp", "SPIRE_AGENT_CELLS"))
	for _, c := range view {
		if !slices.Contains(agents, c) {
			t.Errorf("VIEW_CELLS names %s, which SPIRE_AGENT_CELLS of dev-cp does not hold", c)
		}
	}
}

// The render refuses a reserved or long cell name, an unpinned agent image, and a missing input.
func TestRenderCentralViewFailsClosed(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"VIEW_CELLS=rogue", "reserved name rogue"},
		{"VIEW_CELLS=" + strings.Repeat("a", 60), "at most 59 characters"},
		{"VIEW_CELLS= ", "VIEW_CELLS"},
		{"ARGOCD_AGENT_IMAGE=quay.io/argoprojlabs/argocd-agent:v0.10.0", "not pinned by digest"},
		{"STUB_NO_SERVER=1", "could not read the trust bundle"},
		{"VIEW_CELLS=bad-facts", "Run CELL=bad-facts mise run cell:up, so its celld binds"},
		{"VIEW_CELLS=" + strings.Repeat("a", 59) + " POC_ENV=" + strings.Repeat("e", 10), ""},
		{"VIEW_CELLS=dev-cell-1 dev-cell-1-x", "starts with the agent name dev-dev-cell-1 and a dash"},
		{"VIEW_CELLS=dev-cell-1 dev-cell-1", "names dev-dev-cell-1 twice"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			env := []string{tc.env}
			if before, after, ok := strings.Cut(tc.env, " POC_ENV="); ok {
				env = []string{before, "POC_ENV=" + after}
				tc.want = "is longer than 63 characters"
			}
			r := renderCentralView(t, env...)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

// The vendored Argo CD Agent manifests match ARGOCD_AGENT_MANIFESTS_SHA256, computed as
// scripts/vendor-fetch.sh computes it.
func TestAgentManifestsPinned(t *testing.T) {
	version := commonEnv(t, "ARGOCD_AGENT_VERSION")
	dir := filepath.Join("../../vendor/argocd-agent", version)
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			files = append(files, rel)
		}
		return err
	})
	if err != nil || len(files) == 0 {
		t.Fatalf("no vendored manifests in %s: %v", dir, err)
	}
	slices.Sort(files)
	var list strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		fmt.Fprintf(&list, "%s  %s\n", hex.EncodeToString(sum[:]), f)
	}
	sum := sha256.Sum256([]byte(list.String()))
	if got, want := hex.EncodeToString(sum[:]), commonEnv(t, "ARGOCD_AGENT_MANIFESTS_SHA256"); got != want {
		t.Fatalf("the vendored manifests have SHA-256 %s, and cells/common.env pins %s", got, want)
	}
	if !regexp.MustCompile(`^quay\.io/argoprojlabs/argocd-agent:` + regexp.QuoteMeta(version) + `@sha256:[0-9a-f]{64}$`).MatchString(commonEnv(t, "ARGOCD_AGENT_IMAGE")) {
		t.Fatalf("ARGOCD_AGENT_IMAGE %q is not the %s image by digest", commonEnv(t, "ARGOCD_AGENT_IMAGE"), version)
	}
}
