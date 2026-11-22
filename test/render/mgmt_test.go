package render

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

// mgmtAPI renders the component mgmt-api for management with the stub host commands. The stub
// host service has a pin ConfigMap, and the stub docker resolves host.docker.internal to 192.168.5.2.
func mgmtAPI(t *testing.T, env ...string) result {
	t.Helper()
	return renderScript(t, "mgmt-api", "/ko-app/stub", append(append([]string{"STUB_CELL=management"}, bundleFacts...), env...)...)
}

func mgmtObjects(t *testing.T, env ...string) (map[string]object, result) {
	t.Helper()
	r := mgmtAPI(t, env...)
	if r.err != nil {
		t.Fatalf("render mgmt-api: %v\n%s", r.err, r.stderr)
	}
	return docsIn(t, r.stdout, "mgmt-system"), r
}

func containerArgs(t *testing.T, ctr map[string]any) []string {
	t.Helper()
	var out []string
	for _, a := range get[[]any](t, ctr, "args") {
		out = append(out, a.(string))
	}
	return out
}

func mountPaths(ctr map[string]any) map[string]string {
	out := map[string]string{}
	list, _ := ctr["volumeMounts"].([]any)
	for _, m := range list {
		out[fmt.Sprint(lookupOr(m, "name"))] = fmt.Sprint(lookupOr(m, "mountPath"))
	}
	return out
}

func ruleCIDRs(t *testing.T, rule any, dir string) []string {
	t.Helper()
	var out []string
	for _, p := range get[[]any](t, rule, dir) {
		out = append(out, fmt.Sprint(lookupOr(p, "ipBlock", "cidr")))
	}
	return out
}

func rulePorts(t *testing.T, rule any) []string {
	t.Helper()
	var out []string
	for _, p := range get[[]any](t, rule, "ports") {
		out = append(out, fmt.Sprint(lookupOr(p, "port")))
	}
	return out
}

// TestMgmtAPIRender pins the render of mgmtd: the flags of Task 6 with the shared values, the three
// annotations that restart the pod, the volume and the token mounts, the images by digest with their
// limits, the NodePort Services, the Role, and the policies of the flows N26 to N29, N36, N8, N11 and N23.
func TestMgmtAPIRender(t *testing.T) {
	objs, r := mgmtObjects(t)
	sts := objs["StatefulSet/mgmtd"]
	if sts == nil {
		t.Fatalf("no StatefulSet mgmtd in %v", keysOfObjects(objs))
	}
	for key, o := range objs {
		if o["kind"] == "Secret" {
			t.Errorf("the render holds %s, and no Secret may exist in mgmt-system", key)
		}
		if got := lookupOr(o, "metadata", "labels", "cell.poc.internal/harness"); got != "mgmt-api" {
			t.Errorf("%s has the harness label %v, want mgmt-api", key, got)
		}
	}
	if get[float64](t, sts, "spec", "replicas") != 1 {
		t.Errorf("replicas %v, want 1", lookupOr(sts, "spec", "replicas"))
	}
	tmpl := get[map[string]any](t, sts, "spec", "template")
	spec := get[map[string]any](t, tmpl, "spec")
	if got := get[float64](t, spec, "securityContext", "fsGroup"); got != 65532 {
		t.Errorf("fsGroup %v, want 65532", got)
	}
	if get[bool](t, spec, "automountServiceAccountToken") != false || get[bool](t, objs["ServiceAccount/mgmtd"], "automountServiceAccountToken") != false {
		t.Error("the pod and the ServiceAccount must not mount a token automatically")
	}
	if get[string](t, spec, "serviceAccountName") != "mgmtd" {
		t.Errorf("serviceAccountName %v, want mgmtd", lookupOr(spec, "serviceAccountName"))
	}
	if get[string](t, tmpl, "metadata", "labels", "app.kubernetes.io/name") != "mgmtd" {
		t.Error("the pod needs the label app.kubernetes.io/name=mgmtd, which the N8 ingress of the SPIRE server selects")
	}

	mgmtd := named(t, get[[]any](t, spec, "containers"), "mgmtd")
	wantArgs := []string{"serve", "--intent=/etc/mgmtd/intent/intent.json", "--data-dir=/var/lib/mgmtd", "--peer-bundle=/etc/mgmtd/peer-root/root.crt",
		"--peer-trust-domain=dev.env.poc.internal", "--allow-id=spiffe://dev.env.poc.internal/envd", "--hostsvc-addr=192.168.5.2:17443",
		"--hostsvc-server-name=host.docker.internal", "--hostsvc-pin=/etc/mgmtd/hostsvc-pin/hostsvc.crt", "--public-configmap=mgmt-system/mgmt-signing-pub",
		"--registry-namespaces=central-view-system,observability-system,mesh-view-system", "--operator-key-file=/etc/mgmtd/operator-key/keys.pub"}
	if got := containerArgs(t, mgmtd); !slices.Equal(got, wantArgs) {
		t.Errorf("mgmtd args\n%v\nwant\n%v", got, wantArgs)
	}
	if got := envOf(t, mgmtd)["SPIFFE_ENDPOINT_SOCKET"]; got != "unix:///run/spire/agent/agent.sock" {
		t.Errorf("SPIFFE_ENDPOINT_SOCKET %q", got)
	}

	// The three annotations.
	peer := objs["ConfigMap/peer-root"]
	if peer == nil {
		t.Fatal("no ConfigMap peer-root, though the stub dev-cp server answers")
	}
	ann := get[map[string]any](t, tmpl, "metadata", "annotations")
	wantAnn := map[string]string{
		"poc.internal/peer-root-sha256":   sha256Hex(get[string](t, peer, "data", "root.crt")),
		"poc.internal/hostsvc-pin-sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"poc.internal/intent-sha256":      sha256Hex(get[string](t, objs["ConfigMap/mgmt-intent"], "data", "intent.json")),
	}
	for k, want := range wantAnn {
		if ann[k] != want {
			t.Errorf("annotation %s is %v, want %s", k, ann[k], want)
		}
	}
	if got := get[string](t, objs["ConfigMap/peer-root"], "metadata", "annotations", "poc.internal/peer-root-sha256"); got != wantAnn["poc.internal/peer-root-sha256"] {
		t.Errorf("the peer-root annotation %s differs from the pod annotation", got)
	}
	if got := get[string](t, objs["ConfigMap/hostsvc-pin"], "data", "hostsvc.crt"); !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Errorf("hostsvc-pin holds %q, want a PEM certificate", got)
	}

	// The token and the admin socket volume belong to the mgmtd container only.
	for _, ctr := range get[[]any](t, spec, "containers") {
		c := ctr.(map[string]any)
		name := get[string](t, c, "name")
		mounts := mountPaths(c)
		for _, only := range []string{"mgmtd-api-token", "admin", "state", "intent", "peer-root", "hostsvc-pin"} {
			if _, ok := mounts[only]; ok != (name == "mgmtd") {
				t.Errorf("container %s mounts %s: %v, want %v", name, only, ok, name == "mgmtd")
			}
		}
	}
	m := mountPaths(mgmtd)
	for vol, path := range map[string]string{"mgmtd-api-token": "/var/run/secrets/kubernetes.io/serviceaccount", "admin": "/run/mgmtd", "state": "/var/lib/mgmtd",
		"spire-agent-socket": "/run/spire/agent"} {
		if m[vol] != path {
			t.Errorf("mgmtd mounts %s at %q, want %q", vol, m[vol], path)
		}
	}
	for _, v := range get[[]any](t, spec, "volumes") {
		if _, ok := lookup(v, "secret"); ok {
			t.Errorf("volume %v is a Secret volume", lookupOr(v, "name"))
		}
	}
	if opt, _ := lookup(named(t, get[[]any](t, spec, "volumes"), "peer-root"), "configMap", "optional"); opt != true {
		t.Errorf("volume peer-root has optional %v, want true", opt)
	}
	claim := get[[]any](t, sts, "spec", "volumeClaimTemplates")[0]
	if get[string](t, claim, "metadata", "name") != "state" || get[string](t, claim, "spec", "resources", "requests", "storage") != "64Mi" {
		t.Errorf("volume claim %v, want state with 64Mi, which makes PVC state-mgmtd-0", claim)
	}

	// Every container pins its image by digest and has requests and a memory limit.
	for _, ctr := range get[[]any](t, spec, "containers") {
		c := ctr.(map[string]any)
		if image := get[string](t, c, "image"); !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(image) {
			t.Errorf("container %v image %q is not pinned by digest", c["name"], image)
		}
		for _, path := range [][]any{{"requests", "cpu"}, {"requests", "memory"}, {"limits", "memory"}} {
			if _, ok := lookup(c, append([]any{"resources"}, path...)...); !ok {
				t.Errorf("container %v has no resources %v", c["name"], path)
			}
		}
	}

	// The probes name the liveness and readiness paths of Task 6.
	if get[string](t, mgmtd, "livenessProbe", "httpGet", "path") != "/livez" || get[string](t, mgmtd, "readinessProbe", "httpGet", "path") != "/healthz" {
		t.Error("mgmtd probes must use /livez for liveness and /healthz for readiness")
	}

	// The Service keeps the source address of the dev-cp node.
	for name, port := range map[string]float64{"mgmt-api": 31446} {
		svc := objs["Service/"+name]
		if svc == nil {
			t.Errorf("no Service %s", name)
			continue
		}
		if get[string](t, svc, "spec", "externalTrafficPolicy") != "Local" || get[string](t, svc, "spec", "type") != "NodePort" ||
			get[float64](t, get[[]any](t, svc, "spec", "ports")[0], "nodePort") != port {
			t.Errorf("Service %s is %v, want a NodePort %v with externalTrafficPolicy Local", name, svc["spec"], port)
		}
	}
	if objs["NetworkPolicy/allow-dns"] == nil || objs["NetworkPolicy/default-deny"] == nil {
		t.Error("the namespace needs default-deny and allow-dns")
	}
	ns := objs["Namespace/mgmt-system"]
	if ns == nil || get[string](t, ns, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "restricted" ||
		get[string](t, ns, "metadata", "labels", "istio-injection") != "disabled" {
		t.Errorf("Namespace mgmt-system is %v, want restricted and out of the mesh", ns)
	}

	// The Role has exactly two rules: create on ConfigMaps, and get and update on mgmt-signing-pub.
	rules := get[[]any](t, objs["Role/mgmtd-publish"], "rules")
	if len(rules) != 2 {
		t.Fatalf("the Role has %d rules, want 2: %v", len(rules), rules)
	}
	if fmt.Sprint(lookupOr(rules[0], "verbs"), lookupOr(rules[0], "resources"), lookupOr(rules[0], "resourceNames")) != "[create] [configmaps] <nil>" {
		t.Errorf("rule 1 is %v, want create on configmaps with no name", rules[0])
	}
	if fmt.Sprint(lookupOr(rules[1], "verbs"), lookupOr(rules[1], "resources"), lookupOr(rules[1], "resourceNames")) != "[get update] [configmaps] [mgmt-signing-pub]" {
		t.Errorf("rule 2 is %v, want get and update on mgmt-signing-pub only", rules[1])
	}

	// The policy of the pod: N26 from the dev-cp node only, N23 from the own node, and the egress
	// of N8, N28, N29 and N11.
	np := objs["NetworkPolicy/mgmtd"]
	ing := get[[]any](t, np, "spec", "ingress")
	if len(ing) != 2 {
		t.Fatalf("the mgmtd policy has %d ingress rules, want 2", len(ing))
	}
	if got := ruleCIDRs(t, ing[0], "from"); !slices.Equal(got, []string{"10.9.0.9/32"}) || !slices.Equal(rulePorts(t, ing[0]), []string{"8446"}) {
		t.Errorf("ingress rule 1 admits %v on %v, want the dev-cp node 10.9.0.9/32 on 8446", got, rulePorts(t, ing[0]))
	}
	if got := ruleCIDRs(t, ing[1], "from"); !slices.Equal(got, []string{"172.18.0.4/32"}) || !slices.Equal(rulePorts(t, ing[1]), []string{"8080"}) {
		t.Errorf("ingress rule 2 admits %v on %v, want the own node on 8080 for the kubelet probes", got, rulePorts(t, ing[1]))
	}
	var egress []string
	for _, rule := range get[[]any](t, np, "spec", "egress") {
		to := get[[]any](t, rule, "to")
		var peers string
		if ip, ok := lookup(to[0], "ipBlock", "cidr"); ok {
			peers = fmt.Sprint(ip)
		} else {
			peers = fmt.Sprint(lookupOr(to[0], "podSelector", "matchLabels", "app.kubernetes.io/name"))
		}
		egress = append(egress, peers+":"+strings.Join(rulePorts(t, rule), ","))
	}
	wantEgress := []string{"spire-server:8081", "192.168.5.2/32:17443", "172.18.0.4/32:6443", "10.111.0.1/32:443", "otel-collector:4317"}
	if !slices.Equal(egress, wantEgress) {
		t.Errorf("egress %v, want %v", egress, wantEgress)
	}
	if r.stderr != "" && strings.Contains(r.stderr, "error") {
		t.Errorf("the render printed an error: %s", r.stderr)
	}
}

// With the dev-cp stub server down, or with no dev-cp cluster, no peer-root renders, and the annotation says
// absent. A missing cluster leaves out the ingress rules of N26 and N27 too, because no node address exists.
func TestMgmtAPIRendersWithoutDevCP(t *testing.T) {
	for _, tc := range []struct {
		name     string
		env      []string
		wantRule bool
	}{
		{"no StatefulSet", []string{"STUB_NO_STS=1"}, true},
		{"no cluster", []string{"STUB_KIND_CLUSTERS=management"}, false},
		{"no kind cluster at all", []string{"STUB_KIND_CLUSTERS=none"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, _ := mgmtObjects(t, tc.env...)
			if objs["ConfigMap/peer-root"] != nil {
				t.Fatal("peer-root renders, though the dev-cp server does not answer")
			}
			sts := objs["StatefulSet/mgmtd"]
			if got := get[string](t, sts, "spec", "template", "metadata", "annotations", "poc.internal/peer-root-sha256"); got != "absent" {
				t.Errorf("annotation peer-root-sha256 is %q, want absent", got)
			}
			ing := get[[]any](t, objs["NetworkPolicy/mgmtd"], "spec", "ingress")
			if tc.wantRule != (len(ing) == 2) {
				t.Errorf("the policy has %d ingress rules, want the dev-cp rule present: %v", len(ing), tc.wantRule)
			}
			if len(ing) == 0 || fmt.Sprint(rulePorts(t, ing[len(ing)-1])) != "[8080]" {
				t.Errorf("the policy keeps no kubelet rule on 8080: %v", ing)
			}
		})
	}
}

// When kind does not answer, the render cannot tell whether dev-cp exists. It stops with the error of kind, and never renders
// mgmt-api as if dev-cp were absent, with no peer root and no rule for flow N26.
func TestMgmtAPIRenderStopsWhenKindFails(t *testing.T) {
	r := mgmtAPI(t, "STUB_KIND_FAIL=1", "KIND_CLUSTERS_PAUSE=0")
	if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, "kind get clusters failed") {
		t.Fatalf("err %v, stdout %d bytes, stderr %q; want a failed render that names kind", r.err, len(r.stdout), r.stderr)
	}
}

// When the dev-cp SPIRE server StatefulSet exists and the server does not answer, a quiet render
// would leave the API of mgmtd with no trust root. The render stops with the M3 hint instead.
func TestMgmtAPIPeerRootRequiredWhenServerExists(t *testing.T) {
	r := mgmtAPI(t, "STUB_NO_SERVER_IN=dev-cp")
	if r.err == nil || r.stdout != "" {
		t.Fatalf("err %v, stdout %d bytes; want a failed render with no output", r.err, len(r.stdout))
	}
	if !strings.Contains(r.stderr, "could not read the trust bundle from spire-server-0 in dev-cp. Run CELL=dev-cp mise run cell:up first") {
		t.Errorf("stderr %q does not give the M3 hint", r.stderr)
	}
}

// The render stops when the host service does not serve, so no pod starts with an old pin.
func TestMgmtAPIStopsWithoutHostService(t *testing.T) {
	r := mgmtAPI(t, "STUB_HOSTSVC_FAIL=1")
	if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, "mise run hostsvc:serve -- start") {
		t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that names the start command", r.err, len(r.stdout), r.stderr)
	}
}

// TestMgmtIntentFromTopology checks that intent.json, the catalog, holds POC_ENV, exactly the clusters with the
// cell-identity set (each with the cluster object of harness/topology.yaml: podSubnet, serviceSubnet and issuer), and
// the subjects of SPIRE_CELL_SUBJECTS in cells/dev-cp.env, without the roles. The catalog lists each cell whether its
// cluster exists or not, so it holds both cells with no live cell. The bind subject comes from the shared table.
// mgmt.LoadIntent must accept the file, which pins the shape that mgmtd reads.
func TestMgmtIntentFromTopology(t *testing.T) {
	objs, _ := mgmtObjects(t)
	raw := get[string](t, objs["ConfigMap/mgmt-intent"], "data", "intent.json")
	var intent struct {
		Env         string `json:"env"`
		BindSubject struct{ Namespace, ServiceAccount string }
		Cells       []struct {
			Name     string
			Subjects []struct{ Namespace, ServiceAccount string }
			Cluster  struct{ PodSubnet, ServiceSubnet, Issuer string }
		}
	}
	if err := json.Unmarshal([]byte(raw), &intent); err != nil {
		t.Fatal(err)
	}
	if intent.Env != commonEnv(t, "POC_ENV") {
		t.Errorf("env %q, want %q", intent.Env, commonEnv(t, "POC_ENV"))
	}
	topo, err := topology.Load("../../harness/topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cells []string
	for _, c := range intent.Cells {
		cells = append(cells, c.Name)
	}
	if want := topo.WithComponent("cell-identity"); !slices.Equal(cells, want) {
		t.Errorf("cells %v, want the clusters with cell-identity %v", cells, want)
	}
	for _, c := range intent.Cells {
		want, ok := topo.Cluster(c.Name)
		if !ok {
			t.Fatalf("cell %s is no cluster of the topology", c.Name)
		}
		if c.Cluster.PodSubnet != want.PodSubnet || c.Cluster.ServiceSubnet != want.ServiceSubnet || c.Cluster.Issuer != want.Issuer ||
			c.Cluster.PodSubnet == "" || c.Cluster.ServiceSubnet == "" || c.Cluster.Issuer == "" {
			t.Errorf("cell %s cluster %+v, want the subnets and issuer of the topology %+v", c.Name, c.Cluster, want)
		}
	}
	file, err := os.ReadFile("../../cells/dev-cp.env")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^SPIRE_CELL_SUBJECTS="([^"]*)"`).FindStringSubmatch(string(file))
	if m == nil {
		t.Fatal("cells/dev-cp.env sets no SPIRE_CELL_SUBJECTS")
	}
	var want []string
	for entry := range strings.FieldsSeq(m[1]) {
		want = append(want, strings.SplitN(entry, "=", 2)[0])
	}
	for _, c := range intent.Cells {
		var got []string
		for _, s := range c.Subjects {
			got = append(got, s.Namespace+"/"+s.ServiceAccount)
		}
		if !slices.Equal(got, want) {
			t.Errorf("cell %s subjects %v, want %v", c.Name, got, want)
		}
	}
	if intent.BindSubject.Namespace != "cell-identity-system" || intent.BindSubject.ServiceAccount != "celld" {
		t.Errorf("bindSubject %+v, want cell-identity-system/celld", intent.BindSubject)
	}
	path := filepath.Join(t.TempDir(), "intent.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mgmt.LoadIntent(path); err != nil {
		t.Errorf("mgmt.LoadIntent refuses the rendered intent: %v", err)
	}

	// The catalog does not depend on the clusters that exist: it lists both cells when no cell cluster exists.
	noCells, _ := mgmtObjects(t, "STUB_KIND_CLUSTERS=management dev-cp rogue")
	if got := get[string](t, noCells["ConfigMap/mgmt-intent"], "data", "intent.json"); got != raw {
		t.Errorf("the intent with no live cell is\n%s\nwant the same catalog\n%s", got, raw)
	}

	mgmtEnv, err := os.ReadFile("../../cells/management.env")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^SPIRE_CELL_SUBJECTS=`).Match(mgmtEnv) {
		t.Error("cells/management.env sets SPIRE_CELL_SUBJECTS, which only dev-cp may set")
	}
	if out := renderCell(t, "management"); out.err != nil || strings.Contains(out.stdout, `NodeAttestor "cluster_jwt"`) {
		t.Errorf("the management SPIRE render has a cluster_jwt block, or failed: %v", out.err)
	}
}

// A render with no cell-identity cluster, or a subject list without the bind subject, stops.
func TestMgmtIntentNeedsTheBindSubject(t *testing.T) {
	testtool.Need(t, "bash")
	root := t.TempDir()
	for _, d := range []string{"cells", "harness", "components/mgmt-api", "components/lib", "scripts"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"components/mgmt-api/render.sh", "components/mgmt-api/manifests.yaml", "scripts/ko-image.sh", "harness/topology.yaml"} {
		b, err := os.ReadFile(filepath.Join("../..", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	libs, _ := filepath.Glob("../../components/lib/*")
	for _, f := range libs {
		b, _ := os.ReadFile(f)
		_ = os.WriteFile(filepath.Join(root, "components/lib", filepath.Base(f)), b, 0o755)
	}
	if err := os.WriteFile(filepath.Join(root, "cells/dev-cp.env"), []byte("SPIRE_CELL_SUBJECTS=\"argocd/argocd-agent=argocd-agent\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(root, "components/mgmt-api/render.sh"))
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL_NAME=management", "POC_ENV=dev",
		"SPIRE_TRUST_DOMAIN=mgmt.poc.internal", "VIEW_CONTROL_PLANE=dev-cp", "HOSTSVC_PORT=17443"}, bundleFacts...)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "lacks the bind subject cell-identity-system/celld") {
		t.Fatalf("err %v, output %s; want a stop that names the bind subject", err, out)
	}
}

// TestHostsvcAddressSingle: hostsvc_address prints the one address that getent gives, also when the
// answer repeats it for each socket type. No address or two addresses fail.
func TestHostsvcAddressSingle(t *testing.T) {
	testtool.Need(t, "bash")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(stubDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	lib, err := filepath.Abs("../../components/lib/hostsvc-pin.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, getent, want, fail string }{
		{"the address twice", "192.168.5.2 STREAM host.docker.internal\n192.168.5.2 DGRAM\n", "192.168.5.2", ""},
		{"the default answer", "", "192.168.5.2", ""},
		{"no address", "\n", "", "gives 0 addresses"},
		{"two addresses", "192.168.5.2 STREAM host.docker.internal\n192.168.5.3 STREAM host.docker.internal\n", "", "gives 2 addresses"},
		{"an address that is not IPv4", "fe80::1 STREAM host.docker.internal\n", "", "gives 0 addresses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `source "$1"; hostsvc_address management`, "_", lib)
			cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "STUB_LOG=" + filepath.Join(dir, "log")}
			if tc.getent != "" {
				cmd.Env = append(cmd.Env, "STUB_GETENT="+tc.getent)
			}
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if tc.fail != "" {
				if err == nil || stdout.String() != "" || !strings.Contains(stderr.String(), tc.fail) {
					t.Fatalf("err %v, stdout %q, stderr %q; want a failure that says %q", err, stdout.String(), stderr.String(), tc.fail)
				}
				return
			}
			if err != nil || strings.TrimSpace(stdout.String()) != tc.want {
				t.Fatalf("err %v, stdout %q, stderr %q; want %s", err, stdout.String(), stderr.String(), tc.want)
			}
		})
	}
}

// TestMgmtAPIRenderNoBindListener checks that the render of management has no bind path: no Service mgmt-bind, no port 8447
// on the container, the Services or the policy, and no node port 31447.
func TestMgmtAPIRenderNoBindListener(t *testing.T) {
	r := renderScript(t, "mgmt-api", "/ko-app/stub", append([]string{"STUB_CELL=management"}, bundleFacts...)...)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	// A ConfigMap holds certificates, whose text can hold any digits.
	var text strings.Builder
	for _, o := range objs {
		if o["kind"] != "ConfigMap" {
			b, _ := json.Marshal(o)
			text.Write(b)
		}
	}
	for _, bad := range []string{"mgmt-bind", `"name":"bind"`} {
		if strings.Contains(text.String(), bad) {
			t.Errorf("the render of mgmt-api mentions %q", bad)
		}
	}
	// The port numbers count only as whole numbers: a hex digest in an annotation can hold the same digits.
	for _, port := range []string{"8447", "31447"} {
		if regexp.MustCompile(`(^|[^0-9a-fA-F])` + port + `($|[^0-9a-fA-F])`).MatchString(text.String()) {
			t.Errorf("the render of mgmt-api mentions the port %s", port)
		}
	}
	if objs["Service mgmt-system/mgmt-api"] == nil {
		t.Errorf("the render holds no Service mgmt-api: %v", keysOfObjects(objs))
	}
	for key, o := range objs {
		if o["kind"] == "Service" && key != "Service mgmt-system/mgmt-api" {
			t.Errorf("the render holds %s, and only Service mgmt-api may serve a port", key)
		}
	}
}

// TestMgmtdOperatorKeyFile: mgmtd has one --operator-key-file, and reads it at start only. The render copies spec.pub and,
// during a rotation, next.pub of ConfigMap operator-pub into key keys.pub of ConfigMap mgmt-system/operator-key, one key on each
// line, which only mgmtd mounts read-only. The pod template carries the SHA-256 of the file, so each change of the keys
// restarts mgmtd. The render never prints operator-pub, which the operator script owns. With no operator-pub yet, mgmtd runs
// with no operator key and adopts no local revocation. A failed read of operator-pub stops the render.
func TestMgmtdOperatorKeyFile(t *testing.T) {
	sums := map[string]string{}
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"one key", nil, operatorKeysPub(stubOperatorKey)},
		{"a rotation", []string{"STUB_OPERATOR_NEXT=" + stubOperatorNext}, operatorKeysPub(stubOperatorKey, stubOperatorNext)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, r := mgmtObjects(t, tc.env...)
			if !strings.Contains(r.log, "kubectl --context kind-management -n mgmt-system get configmap operator-pub") {
				t.Errorf("the render did not read ConfigMap operator-pub; it ran:\n%s", r.log)
			}
			if objs["ConfigMap/operator-pub"] != nil {
				t.Error("the render prints ConfigMap operator-pub, which only the operator script writes")
			}
			cm := objs["ConfigMap/operator-key"]
			if cm == nil {
				t.Fatalf("no ConfigMap mgmt-system/operator-key in %v", keysOfObjects(objs))
			}
			if data := get[map[string]any](t, cm, "data"); len(data) != 1 || data["keys.pub"] != tc.want {
				t.Errorf("operator-key holds %q, want only keys.pub %q", data, tc.want)
			}
			sts := objs["StatefulSet/mgmtd"]
			pod := get[map[string]any](t, sts, "spec", "template", "spec")
			args := containerArgs(t, named(t, get[[]any](t, pod, "containers"), "mgmtd"))
			if n := len(slices.DeleteFunc(slices.Clone(args), func(a string) bool { return a != "--operator-key-file=/etc/mgmtd/operator-key/keys.pub" })); n != 1 {
				t.Errorf("mgmtd args %v hold --operator-key-file=/etc/mgmtd/operator-key/keys.pub %d times, want once", args, n)
			}
			if v := named(t, get[[]any](t, pod, "volumes"), "operator-key"); get[string](t, v, "configMap", "name") != "operator-key" {
				t.Errorf("volume operator-key is %v, want ConfigMap operator-key", v)
			}
			for _, c := range get[[]any](t, pod, "containers") {
				name := get[string](t, c, "name")
				var got []string
				for _, m := range mountList(t, c) {
					if strings.HasPrefix(m, "operator-key=") {
						got = append(got, m)
					}
				}
				if want := map[bool][]string{true: {"operator-key=/etc/mgmtd/operator-key,true"}}[name == "mgmtd"]; !slices.Equal(got, want) {
					t.Errorf("container %s mounts the keys as %v, want %v", name, got, want)
				}
			}
			sum := fmt.Sprint(lookupOr(sts, "spec", "template", "metadata", "annotations", "poc.internal/operator-key-sha256"))
			if sum != sha256Hex(tc.want) {
				t.Errorf("the pod annotation poc.internal/operator-key-sha256 is %s, want the SHA-256 of keys.pub %s", sum, sha256Hex(tc.want))
			}
			sums[tc.name] = sum
		})
	}
	if sums["one key"] == sums["a rotation"] {
		t.Error("a rotation leaves the pod annotation as it was, so mgmtd would keep the old keys")
	}

	t.Run("no operator-pub yet", func(t *testing.T) {
		objs, _ := mgmtObjects(t, "STUB_NO_OPERATOR_PUB=1")
		if objs["ConfigMap/operator-key"] != nil {
			t.Error("the render prints ConfigMap operator-key with no operator-pub")
		}
		sts := objs["StatefulSet/mgmtd"]
		pod := get[map[string]any](t, sts, "spec", "template", "spec")
		mgmtd := named(t, get[[]any](t, pod, "containers"), "mgmtd")
		if args := containerArgs(t, mgmtd); slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--operator-key-file") }) {
			t.Errorf("mgmtd args %v name an operator key file with no operator-pub", args)
		}
		if strings.Contains(fmt.Sprint(lookupOr(pod, "volumes"), mountList(t, mgmtd)), "operator-key") {
			t.Error("the pod mounts an operator key with no operator-pub")
		}
		if got := lookupOr(sts, "spec", "template", "metadata", "annotations", "poc.internal/operator-key-sha256"); got != "absent" {
			t.Errorf("the pod annotation poc.internal/operator-key-sha256 is %v, want absent", got)
		}
	})

	t.Run("operator-pub unreadable", func(t *testing.T) {
		r := mgmtAPI(t, "STUB_OPERATOR_PUB_FAIL=1")
		if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, "operator-pub") {
			t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that names operator-pub", r.err, len(r.stdout), r.stderr)
		}
	})
}
