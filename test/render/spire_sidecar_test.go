package render

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl"
	"sigs.k8s.io/yaml"
)

// goldenCelld holds the cell-identity render of M2 at commit 2d8cb64, before the sidecar helper
// existed, and the changes that M4 Task 9 made on purpose to celld (the bind flags, the pod fields, the
// token and root mounts, ConfigMap mgmt-root and the bind port in the policy). Review the diff of the
// file by hand before each commit. The image
// digest of the stub registry is replaced by stubDigest, so the file does not depend on the gzip
// output of one Go version. UPDATE_GOLDEN=1 writes the file again from the current render.
const (
	goldenCelld = "testdata/celld-deployment.golden.yaml"
	stubDigest  = "sha256:stub"
)

// devEnvCA is a fixed CA certificate of dev.env.poc.internal. The golden render uses it as the
// trust bundle, so its config checksum is the same in every run. The key was discarded.
func devEnvCA(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("testdata/dev-env-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// mgmtCA is a fixed CA certificate of mgmt.poc.internal, for the ConfigMap mgmt-root of the golden render.
func mgmtCA(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("testdata/mgmt-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// sameObjects compares two renders object by object, with list order kept.
func sameObjects(t *testing.T, got, want map[string]object) {
	t.Helper()
	var keys []string
	for k := range want {
		keys = append(keys, k)
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		g, w := got[k], want[k]
		if !reflect.DeepEqual(g, w) {
			gy, _ := yaml.Marshal(g)
			wy, _ := yaml.Marshal(w)
			t.Errorf("%s differs from the golden render.\ngot:\n%s\nwant:\n%s", k, gy, wy)
		}
	}
}

// TestSpireSidecarClusterJWTMatchesCelld renders celld through the sidecar helper and compares
// every object with the M2 render, so the helper keeps the deployed celld pod as it is.
func TestSpireSidecarClusterJWTMatchesCelld(t *testing.T) {
	r := renderCellIdentity(t, "STUB_BUNDLE_FILE="+devEnvCA(t), "STUB_MGMT_BUNDLE_FILE="+mgmtCA(t))
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	out := strings.ReplaceAll(r.stdout, r.digest, stubDigest)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(goldenCelld, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenCelld)
	if err != nil {
		t.Fatal(err)
	}
	sameObjects(t, docsIn(t, out, "cell-identity-system"), docsIn(t, string(want), "cell-identity-system"))
}

// planeWorkload is a Deployment of a plane workload before the sidecar helper adds the agent. Its
// container mounts the socket volume, as each container that needs an SVID must.
const planeWorkload = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-uplink
  namespace: observability-system
  labels:
    app.kubernetes.io/name: otel-uplink
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: otel-uplink
  template:
    metadata:
      labels:
        app.kubernetes.io/name: otel-uplink
    spec:
      serviceAccountName: otel-uplink
      automountServiceAccountToken: false
      containers:
        - name: uplink
          image: localhost:5001/celld@sha256:0000000000000000000000000000000000000000000000000000000000000000
          securityContext:
            runAsUser: 65532
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/agent
              readOnly: true
`

// sidecar runs spire_sidecar from components/lib/spire-sidecar.sh on a workload.
func sidecar(t *testing.T, workload, mode, input string, env ...string) result {
	t.Helper()
	lib, err := filepath.Abs("../../components/lib/spire-sidecar.sh")
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"bash", "-c", `source "$1" && spire_sidecar "$2" "$3"`, "_", lib, workload, mode}
	return runStubbed(t, "/ko-app/cluster-jwt-agent", input, argv, env...)
}

var psatSidecarEnv = []string{
	"SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local",
	"SPIRE_SIDECAR_SERVER_PORT=8081",
	"SPIRE_SIDECAR_TRUST_DOMAIN=mgmt.poc.internal",
	"SPIRE_SIDECAR_CLUSTER=management",
}

func TestSpireSidecarK8sPSAT(t *testing.T) {
	bundle := caPEM(t, "mgmt.poc.internal")
	r := sidecar(t, "otel-uplink", "k8s_psat", planeWorkload, append(slices.Clone(psatSidecarEnv), "SPIRE_SIDECAR_BUNDLE="+bundle)...)
	if r.err != nil {
		t.Fatalf("helper failed: %v\n%s", r.err, r.stderr)
	}
	objs := docsIn(t, r.stdout, "observability-system")
	var keys []string
	for k := range objs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"ConfigMap/spire-agent-otel-uplink", "ConfigMap/spire-trust-bundle-otel-uplink", "Deployment/otel-uplink"}; !slices.Equal(keys, want) {
		t.Fatalf("objects are %v, want %v: no token Role for k8s_psat", keys, want)
	}
	if strings.Contains(r.log, "oras ") {
		t.Fatalf("the k8s_psat helper fetched an image:\n%s", r.log)
	}
	dep := objs["Deployment/otel-uplink"]
	pod := get[map[string]any](t, dep, "spec", "template", "spec")
	if pod["shareProcessNamespace"] != true || pod["automountServiceAccountToken"] != false {
		t.Fatalf("pod spec is %v", pod)
	}
	if _, ok := pod["initContainers"]; ok {
		t.Fatal("the k8s_psat pod has an init container")
	}
	mains := get[[]any](t, pod, "containers")
	if len(mains) != 2 || get[string](t, mains[0], "name") != "spire-agent" || get[string](t, mains[1], "name") != "uplink" {
		t.Fatalf("containers are %v", mains)
	}
	agent := mains[0].(map[string]any)
	if image := get[string](t, agent, "image"); !regexp.MustCompile(`^ghcr\.io/spiffe/spire-agent:1\.15\.5@sha256:[0-9a-f]{64}$`).MatchString(image) {
		t.Fatalf("agent image is %q", image)
	}
	for _, path := range [][]any{{"requests", "cpu"}, {"requests", "memory"}, {"limits", "memory"}} {
		if _, ok := lookup(agent, append([]any{"resources"}, path...)...); !ok {
			t.Fatalf("agent has no resources %v", path)
		}
	}
	csc := get[map[string]any](t, agent, "securityContext")
	if csc["runAsUser"] != float64(1000) || csc["allowPrivilegeEscalation"] != false || csc["readOnlyRootFilesystem"] != true ||
		!slices.Equal(get[[]any](t, csc, "capabilities", "drop"), []any{"ALL"}) {
		t.Fatalf("agent securityContext is %v", csc)
	}
	if _, ok := agent["env"]; ok {
		t.Fatal("the k8s_psat agent gets the downward API variables of the cluster_jwt plugin")
	}

	// The projected token has the audience that the server plugin checks, and only the agent mounts it.
	var token map[string]any
	for _, v := range get[[]any](t, pod, "volumes") {
		if src, ok := lookup(v, "projected", "sources", 0, "serviceAccountToken"); ok {
			if token != nil {
				t.Fatal("the pod has two projected tokens")
			}
			token = v.(map[string]any)
			sat := src.(map[string]any)
			if sat["audience"] != "spire-server" || sat["path"] != "spire-agent" || sat["expirationSeconds"] != float64(600) {
				t.Fatalf("projected token is %v", sat)
			}
		}
	}
	if token == nil {
		t.Fatal("the pod has no projected token")
	}
	mounts := map[string][]string{}
	for _, c := range mains {
		for _, m := range get[[]any](t, c, "volumeMounts") {
			mounts[get[string](t, m, "name")] = append(mounts[get[string](t, m, "name")], get[string](t, c, "name")+":"+get[string](t, m, "mountPath"))
		}
	}
	if got := mounts[token["name"].(string)]; !slices.Equal(got, []string{"spire-agent:/var/run/secrets/tokens"}) {
		t.Fatalf("token mounts are %v", got)
	}
	if got := mounts["spire-agent-socket"]; !slices.Equal(got, []string{"spire-agent:/run/spire/agent", "uplink:/run/spire/agent"}) {
		t.Fatalf("socket mounts are %v", got)
	}
	socket := named(t, get[[]any](t, pod, "volumes"), "spire-agent-socket")
	if get[string](t, socket, "emptyDir", "medium") != "Memory" {
		t.Fatalf("socket volume is %v", socket)
	}
	for _, v := range get[[]any](t, pod, "volumes") {
		if name, ok := lookup(v, "configMap", "name"); ok {
			if _, found := objs["ConfigMap/"+name.(string)]; !found {
				t.Fatalf("volume uses ConfigMap %v, which the helper does not print", name)
			}
		}
	}
	if ann := get[string](t, dep, "spec", "template", "metadata", "annotations", "cell.poc.internal/config-checksum"); !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(ann) {
		t.Fatalf("config checksum annotation is %q", ann)
	}

	text := get[string](t, objs["ConfigMap/spire-agent-otel-uplink"], "data", "agent.conf")
	var conf struct {
		Agent struct {
			ServerAddress   string `hcl:"server_address"`
			ServerPort      int    `hcl:"server_port"`
			TrustDomain     string `hcl:"trust_domain"`
			TrustBundlePath string `hcl:"trust_bundle_path"`
			SocketPath      string `hcl:"socket_path"`
			LogFormat       string `hcl:"log_format"`
		} `hcl:"agent"`
	}
	if err := hcl.Decode(&conf, text); err != nil {
		t.Fatalf("agent.conf does not parse: %v", err)
	}
	if a := conf.Agent; a.ServerAddress != "spire-server.spire-system.svc.cluster.local" || a.ServerPort != 8081 || a.TrustDomain != "mgmt.poc.internal" ||
		a.TrustBundlePath != "/run/spire/bundle/bundle.crt" || a.SocketPath != "/run/spire/agent/agent.sock" || a.LogFormat != "json" {
		t.Fatalf("agent block is %+v", a)
	}
	for _, want := range []string{`NodeAttestor "k8s_psat"`, `cluster = "management"`, `token_path = "/var/run/secrets/tokens/spire-agent"`, `WorkloadAttestor "unix"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("agent.conf lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "cluster_jwt") {
		t.Fatalf("agent.conf names cluster_jwt:\n%s", text)
	}
	if got := get[string](t, objs["ConfigMap/spire-trust-bundle-otel-uplink"], "data", "bundle.crt"); strings.TrimSpace(got) != strings.TrimSpace(bundle) {
		t.Fatalf("trust bundle is %q", got)
	}
}

// TestSpireSidecarClusterJWTDefaults renders a cell workload with the default names. The token
// Role names only the ServiceAccount of the workload.
func TestSpireSidecarClusterJWTDefaults(t *testing.T) {
	input := strings.NewReplacer("otel-uplink", "argocd-agent", "observability-system", "argocd").Replace(planeWorkload)
	r := sidecar(t, "argocd-agent", "cluster_jwt", input,
		"SPIRE_SIDECAR_SERVER_ADDRESS=10.9.0.9", "SPIRE_SIDECAR_SERVER_PORT=30091", "SPIRE_SIDECAR_TRUST_DOMAIN=test.env.poc.internal",
		"SPIRE_SIDECAR_CELL=@CELL_NAME@", "SPIRE_SIDECAR_BUNDLE="+caPEM(t, "test.env.poc.internal"), "CELL_NAME=dev-cell-1")
	if r.err != nil {
		t.Fatalf("helper failed: %v\n%s", r.err, r.stderr)
	}
	objs := docsIn(t, r.stdout, "argocd")
	rule := get[map[string]any](t, objs["Role/argocd-agent-token"], "rules", 0)
	if !slices.Equal(get[[]any](t, rule, "resources"), []any{"serviceaccounts/token"}) || !slices.Equal(get[[]any](t, rule, "resourceNames"), []any{"argocd-agent"}) {
		t.Fatalf("token rule is %v", rule)
	}
	if get[string](t, objs["RoleBinding/argocd-agent-token"], "subjects", 0, "name") != "argocd-agent" {
		t.Fatal("the token RoleBinding binds another account")
	}
	pod := get[map[string]any](t, objs["Deployment/argocd-agent"], "spec", "template", "spec")
	if get[string](t, pod, "initContainers", 0, "name") != "install-agent-plugin" {
		t.Fatal("no plugin installer")
	}
	text := get[string](t, objs["ConfigMap/spire-agent-argocd-agent"], "data", "agent.conf")
	// The port and the trust domain come from the inputs, not from the M2 literals 30081 and dev.env.poc.internal.
	for _, want := range []string{`server_port = 30091`, `trust_domain = "test.env.poc.internal"`, `spiffe://test.env.poc.internal/spire/server`,
		`cell = "@CELL_NAME@"`, `NodeAttestor "cluster_jwt"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("agent.conf lacks %q:\n%s", want, text)
		}
	}
	if _, ok := objs["ConfigMap/spire-trust-bundle-argocd-agent"]; !ok {
		t.Fatal("no trust bundle ConfigMap with the default name")
	}
}

func TestSpireSidecarFailsClosed(t *testing.T) {
	bundle := "SPIRE_SIDECAR_BUNDLE=" + caPEM(t, "mgmt.poc.internal")
	collide := strings.Replace(planeWorkload, "      containers:", "      volumes:\n        - name: data\n          emptyDir: {}\n      containers:", 1)
	cases := []struct {
		name, mode, input string
		env               []string
		want              string
	}{
		{"unknown mode", "x509pop", planeWorkload, []string{bundle}, "mode 'x509pop' is not cluster_jwt or k8s_psat"},
		{"k8s_psat without a cluster", "k8s_psat", planeWorkload, []string{bundle, "SPIRE_SIDECAR_CLUSTER="}, "SPIRE_SIDECAR_CLUSTER"},
		{"cluster_jwt without a cell", "cluster_jwt", planeWorkload, []string{bundle}, "SPIRE_SIDECAR_CELL"},
		{"no trust bundle", "k8s_psat", planeWorkload, nil, "SPIRE_SIDECAR_BUNDLE"},
		{"bad port", "k8s_psat", planeWorkload, []string{bundle, "SPIRE_SIDECAR_SERVER_PORT=http"}, "SPIRE_SIDECAR_SERVER_PORT"},
		{"not a workload", "k8s_psat", strings.Replace(planeWorkload, "kind: Deployment", "kind: Job", 1), []string{bundle}, "not one Deployment or StatefulSet"},
		{"volume name taken", "k8s_psat", collide, []string{bundle}, "already has a volume or container named data"},
		{"socket volume not mounted", "k8s_psat", strings.Replace(planeWorkload, "name: spire-agent-socket", "name: other", 1), []string{bundle}, "no container mounts spire-agent-socket"},
		{"container without a user", "k8s_psat", strings.Replace(planeWorkload, "            runAsUser: 65532\n", "            runAsGroup: 65532\n", 1), []string{bundle}, "container uplink sets no runAsUser"},
		{"container as the agent user", "k8s_psat", strings.Replace(planeWorkload, "runAsUser: 65532", "runAsUser: 1000", 1), []string{bundle}, "container uplink runs as user 1000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := sidecar(t, "otel-uplink", tc.mode, tc.input, append(slices.Clone(psatSidecarEnv), tc.env...)...)
			if r.err == nil {
				t.Fatal("helper succeeded")
			}
			if r.stdout != "" {
				t.Fatalf("helper printed manifests on failure:\n%s", r.stdout)
			}
			if !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("stderr %q does not contain %q", r.stderr, tc.want)
			}
		})
	}
}

// peerRoot runs peer_root_configmap from components/lib/peer-root.sh against the stub server.
func peerRoot(t *testing.T, env ...string) result {
	t.Helper()
	lib, err := filepath.Abs("../../components/lib/peer-root.sh")
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"bash", "-c", `source "$1" && peer_root_configmap peer-root relay-system dev-cp dev.env.poc.internal`, "_", lib}
	return runStubbed(t, "/ko-app/stub", "", argv, env...)
}

func TestPeerRootConfigMap(t *testing.T) {
	r := peerRoot(t)
	if r.err != nil {
		t.Fatalf("peer_root_configmap failed: %v\n%s", r.err, r.stderr)
	}
	if want := "kubectl --context kind-dev-cp -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem"; !strings.Contains(r.log, want) {
		t.Fatalf("the helper did not run %q; it ran:\n%s", want, r.log)
	}
	cm := docsIn(t, r.stdout, "relay-system")["ConfigMap/peer-root"]
	root := get[string](t, cm, "data", "root.crt")
	if strings.TrimSpace(root) != strings.TrimSpace(r.bundle) {
		t.Fatalf("root.crt is %q", root)
	}
	sum := sha256.Sum256([]byte(root))
	if got := get[string](t, cm, "metadata", "annotations", "poc.internal/peer-root-sha256"); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("the annotation is %q, want the SHA-256 of root.crt %x", got, sum)
	}
}

func TestPeerRootConfigMapFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, env, want string }{
		{"no server", "STUB_NO_SERVER=1", "Run CELL=dev-cp mise run cell:up first"},
		{"other trust domain", "STUB_TRUST_DOMAIN=mgmt.poc.internal", "want spiffe://dev.env.poc.internal"},
		{"text in the bundle", "STUB_BAD_BUNDLE=1", "text other than PEM certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := peerRoot(t, tc.env)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %q, stderr %q; want a failure that says %q", r.err, r.stdout, r.stderr, tc.want)
			}
		})
	}
}
