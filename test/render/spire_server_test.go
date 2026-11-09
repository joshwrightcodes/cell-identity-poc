// Package render tests the component render scripts with stub host commands.
package render

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/hcl"
	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const stubBinary = "stub plugin binary"

// stubMise answers "mise run hostsvc -- facts" and "mise run record:fixture" for the cells below,
// and runs the real pkigen for "mise run pki". The cell bad-facts fails the way hostsvc fails, and
// no-ip has no node address.
const stubMise = `#!/usr/bin/env bash
set -euo pipefail
echo "$*" >>"$STUB_LOG"
case "$2" in
  hostsvc)
    cell="$6"
    case "$cell" in
      dev-cell-1) echo '{"name":"dev-cell-1","nodeIP":"10.9.0.1"}' ;;
      dev-cell-2) echo '{"name":"dev-cell-2","nodeIP":"10.9.0.2"}' ;;
      dev-cp) echo '{"name":"dev-cp","nodeIP":"10.9.0.9"}' ;;
      no-ip) echo '{"name":"no-ip","nodeIP":""}' ;;
      *) echo '{"level":"ERROR","msg":"hostsvc failed","error":"cluster does not exist"}'; exit 1 ;;
    esac ;;
  record:fixture)
    cell="$5"
    cat <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: cell-record-$cell
data:
  record.dsse.json: "{\"payload\":\"$cell\"}"
  signer.pub: "stubkey${cell##*-}="
EOF
    ;;
  pki) shift 3; exec "$STUB_PKIGEN" "$@" ;;
  *) exit 2 ;;
esac
`

// stubOras serves one image manifest and its last layer. STUB_NO_REGISTRY makes every fetch fail.
// STUB_BAD_MANIFEST serves a manifest, and STUB_BAD_LAYER a layer, whose digest does not match.
const stubOras = `#!/usr/bin/env bash
set -euo pipefail
[[ -z "${STUB_NO_REGISTRY:-}" ]] || exit 1
out=-
args=()
while (($#)); do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
case "${args[0]} ${args[1]}" in
  "manifest fetch") src="$STUB_MANIFEST_FILE"; [[ -z "${STUB_BAD_MANIFEST:-}" ]] || src="$STUB_MANIFEST_FILE.bad" ;;
  "blob fetch") src="$STUB_LAYER_FILE"; [[ -z "${STUB_BAD_LAYER:-}" ]] || src="$STUB_MANIFEST_FILE" ;;
  *) exit 2 ;;
esac
if [[ "$out" == - ]]; then cat "$src"; else cat "$src" >"$out"; fi
`

// stubKubectl answers "spire-server bundle show" with the file STUB_BUNDLE_FILE. STUB_NO_SERVER
// makes it fail the way kubectl does when the pod is missing, and STUB_BAD_BUNDLE adds a line
// that is not PEM.
const stubKubectl = `#!/usr/bin/env bash
set -euo pipefail
echo "kubectl $*" >>"$STUB_LOG"
if [[ " $* " == *" get node "* ]]; then
  echo 10.9.0.7
  exit 0
fi
if [[ -n "${STUB_NO_SERVER:-}" ]]; then
  echo 'Error from server (NotFound): pods "spire-server-0" not found' >&2
  exit 1
fi
cat "$STUB_BUNDLE_FILE"
[[ -z "${STUB_BAD_BUNDLE:-}" ]] || echo "not a certificate"
`

// stubDocker answers the node checks of scripts/gate-traces.sh. Every node has the address 10.9.0.7
// unless STUB_DOCKER_IP sets another one. STUB_KEYTEST_TRACE names a cell whose node holds a trace of
// the key rotation test.
const stubDocker = `#!/usr/bin/env bash
set -euo pipefail
echo "docker $*" >>"$STUB_LOG"
case "$1" in
  inspect) echo "${STUB_DOCKER_IP:-10.9.0.7} " ;;
  exec)
    if [[ "$2" == "${STUB_KEYTEST_TRACE:-none}-control-plane" ]]; then
      echo "/etc/kubernetes/manifests/kube-apiserver.yaml names the test key"
    fi ;;
  *) exit 1 ;;
esac
`

type result struct {
	stdout, stderr string
	err            error
	log            string
	// digest is the manifest digest of the stub image that the render must pin.
	digest string
	// bundle is the PEM trust bundle that the stub server prints.
	bundle string
}

var (
	pkigenOnce sync.Once
	pkigenPath string
	pkigenErr  error
)

// pkigen builds cmd/pkigen once for every test in the package.
func pkigen(t *testing.T) string {
	t.Helper()
	pkigenOnce.Do(func() {
		dir, err := os.MkdirTemp("", "render-pkigen")
		if err != nil {
			pkigenErr = err
			return
		}
		pkigenPath = filepath.Join(dir, "pkigen")
		out, err := exec.Command("go", "build", "-o", pkigenPath, "../../cmd/pkigen").CombinedOutput()
		if err != nil {
			pkigenErr = fmt.Errorf("build pkigen: %v: %s", err, out)
		}
	})
	if pkigenErr != nil {
		t.Fatal(pkigenErr)
	}
	return pkigenPath
}

var caCache sync.Map

// caPEM returns a self-signed CA certificate with the URI SAN spiffe://<td>. Every render in the
// package gets the same certificate for one trust domain, so renders differ only by their inputs.
func caPEM(t *testing.T, td string) string {
	t.Helper()
	if v, ok := caCache.Load(td); ok {
		return v.(string)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://" + td)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, URIs: []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := caCache.LoadOrStore(td, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	return v.(string)
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func render(t *testing.T, env ...string) result {
	t.Helper()
	return renderScript(t, "spire-server", "/ko-app/cluster-jwt-server", append([]string{"SPIRE_SVID_TTL=1m"}, env...)...)
}

// renderScript runs the render script of a component with stub host commands. The stub image
// holds one file at binary, and every image in images.env pins that stub image. STUB_IMAGES=missing
// and STUB_IMAGES=stale make images.env missing or older than the Go sources. STUB_TRUST_DOMAIN
// sets the trust domain of the bundle that the stub server prints.
func renderScript(t *testing.T, component, binary string, env ...string) result {
	t.Helper()
	testtool.Need(t, "yq", "jq", "tar", "bash", "go")
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	opts := map[string]string{}
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && strings.HasPrefix(k, "STUB_") {
			opts[k] = v
		}
	}
	write("mise", stubMise, 0o755)
	write("oras", stubOras, 0o755)
	write("kubectl", stubKubectl, 0o755)
	write("docker", stubDocker, 0o755)
	layerBytes := layerTarGz(t, binary)
	layer := write("layer.tar.gz", string(layerBytes), 0o644)
	manifestBytes := []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{"digest":"sha256:0000"},{"digest":"` + digestOf(layerBytes) + `"}]}`)
	manifest := write("manifest.json", string(manifestBytes), 0o644)
	write("manifest.json.bad", string(manifestBytes)+" ", 0o644)
	digest := digestOf(manifestBytes)
	var images strings.Builder
	for _, repo := range []string{"netprobe", "cluster-jwt-server", "cluster-jwt-agent", "celld"} {
		fmt.Fprintf(&images, "IMAGE_%s=localhost:5001/%s@%s\n", strings.ToUpper(strings.ReplaceAll(repo, "-", "_")), repo, digest)
	}
	imagesFile := write("images.env", images.String(), 0o644)
	switch opts["STUB_IMAGES"] {
	case "missing":
		imagesFile = filepath.Join(dir, "no-images.env")
	case "stale":
		old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		if err := os.Chtimes(imagesFile, old, old); err != nil {
			t.Fatal(err)
		}
	}
	td := "dev.env.poc.internal"
	if v := opts["STUB_TRUST_DOMAIN"]; v != "" {
		td = v
	}
	bundle := caPEM(t, td)
	bundleFile := write("bundle.pem", bundle, 0o644)
	logFile := filepath.Join(dir, "mise.log")

	script, err := filepath.Abs("../../components/" + component + "/render.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script)
	cmd.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+logFile, "STUB_LAYER_FILE="+layer, "STUB_MANIFEST_FILE="+manifest,
		"STUB_BUNDLE_FILE="+bundleFile, "STUB_PKIGEN="+pkigen(t), "IMAGES_ENV="+imagesFile,
		"SPIRE_AGENT_SUBJECT=cell-identity-system/celld")
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	logData, _ := os.ReadFile(logFile)
	return result{stdout.String(), stderr.String(), err, string(logData), digest, bundle}
}

func layerTarGz(t *testing.T, binary string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "ko-app", Typeflag: tar.TypeDir, Mode: 0o555}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: binary, Mode: 0o555, Size: int64(len(stubBinary))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(stubBinary)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type object map[string]any

func docs(t *testing.T, out string) map[string]object {
	t.Helper()
	return docsIn(t, out, "spire-system")
}

// docsIn parses the render output by kind and name. Every object except the Namespace must be in ns.
func docsIn(t *testing.T, out, ns string) map[string]object {
	t.Helper()
	byKey := map[string]object{}
	for _, d := range regexp.MustCompile(`(?m)^---$`).Split(out, -1) {
		if strings.TrimSpace(d) == "" {
			continue
		}
		var o object
		if err := yaml.Unmarshal([]byte(d), &o); err != nil {
			t.Fatalf("output document does not parse: %v\n%s", err, d)
		}
		if o == nil {
			continue
		}
		key := get[string](t, o, "kind") + "/" + get[string](t, o, "metadata", "name")
		if _, dup := byKey[key]; dup {
			t.Fatalf("%s appears twice", key)
		}
		if got, _ := lookup(o, "metadata", "namespace"); key != "Namespace/"+ns && got != ns {
			t.Fatalf("%s has namespace %v, want %s", key, got, ns)
		}
		byKey[key] = o
	}
	return byKey
}

func lookup(v any, path ...any) (any, bool) {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				if o, isObj := v.(object); isObj {
					m, ok = map[string]any(o), true
				}
			}
			if !ok {
				return nil, false
			}
			if v, ok = m[k]; !ok {
				return nil, false
			}
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				return nil, false
			}
			v = l[k]
		}
	}
	return v, true
}

func get[T any](t *testing.T, v any, path ...any) T {
	t.Helper()
	x, ok := lookup(v, path...)
	if !ok {
		t.Fatalf("no value at %v", path)
	}
	typed, ok := x.(T)
	if !ok {
		t.Fatalf("value at %v is %T", path, x)
	}
	return typed
}

func named(t *testing.T, list []any, name string) map[string]any {
	t.Helper()
	for _, x := range list {
		if m, ok := x.(map[string]any); ok && m["name"] == name {
			return m
		}
	}
	t.Fatalf("no item named %q", name)
	return nil
}

func TestRenderSpireServer(t *testing.T) {
	r := render(t, "SPIRE_AGENT_CELLS=dev-cell-1 dev-cell-2")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docs(t, r.stdout)

	if left := regexp.MustCompile(`@[A-Z_]+@`).FindAllString(r.stdout, -1); slices.ContainsFunc(left, func(s string) bool { return s != "@CELL_NAME@" }) {
		t.Fatalf("render left tokens %v", left)
	}
	for _, want := range []string{"run hostsvc -- facts --cluster dev-cell-1", "run record:fixture -- --cluster dev-cell-2 --subject cell-identity-system/celld"} {
		if !strings.Contains(r.log, want) {
			t.Fatalf("render did not run mise %q; it ran:\n%s", want, r.log)
		}
	}

	t.Run("network policy admits only the agent nodes", func(t *testing.T) {
		deny := objs["NetworkPolicy/default-deny"]
		if types := get[[]any](t, deny, "spec", "policyTypes"); len(types) != 2 || len(get[map[string]any](t, deny, "spec", "podSelector")) != 0 {
			t.Fatalf("default-deny spec is %v", deny["spec"])
		}
		if _, ok := lookup(deny, "spec", "ingress"); ok {
			t.Fatal("default-deny has ingress rules")
		}
		np := objs["NetworkPolicy/spire-server-agents"]
		rules := get[[]any](t, np, "spec", "ingress")
		if len(rules) != 1 {
			t.Fatalf("got %d ingress rules", len(rules))
		}
		var cidrs []string
		for _, peer := range get[[]any](t, rules[0], "from") {
			if len(peer.(map[string]any)) != 1 {
				t.Fatalf("peer %v has more than an ipBlock", peer)
			}
			cidrs = append(cidrs, get[string](t, peer, "ipBlock", "cidr"))
		}
		if !slices.Equal(cidrs, []string{"10.9.0.1/32", "10.9.0.2/32"}) {
			t.Fatalf("peers are %v", cidrs)
		}
		ports := get[[]any](t, rules[0], "ports")
		if len(ports) != 1 || get[float64](t, ports[0], "port") != 8081 {
			t.Fatalf("ports are %v", ports)
		}
		if _, ok := lookup(np, "spec", "egress"); ok {
			t.Fatal("the agent policy allows egress")
		}
	})

	t.Run("service exposes only the server API with the client address kept", func(t *testing.T) {
		svc := objs["Service/spire-server"]
		ports := get[[]any](t, svc, "spec", "ports")
		if get[string](t, svc, "spec", "type") != "NodePort" || get[string](t, svc, "spec", "externalTrafficPolicy") != "Local" ||
			len(ports) != 1 || get[float64](t, ports[0], "nodePort") != 30081 || get[float64](t, ports[0], "port") != 8081 {
			t.Fatalf("service spec is %v", svc["spec"])
		}
	})

	t.Run("statefulset", func(t *testing.T) {
		pod := get[map[string]any](t, objs["StatefulSet/spire-server"], "spec", "template", "spec")
		if pod["automountServiceAccountToken"] != false {
			t.Fatal("the pod mounts a ServiceAccount token")
		}
		sc := get[map[string]any](t, pod, "securityContext")
		if sc["runAsNonRoot"] != true || sc["runAsUser"] != float64(1000) || get[string](t, sc, "seccompProfile", "type") != "RuntimeDefault" {
			t.Fatalf("pod securityContext is %v", sc)
		}
		containers := append(get[[]any](t, pod, "initContainers"), get[[]any](t, pod, "containers")...)
		if len(containers) != 3 {
			t.Fatalf("got %d containers", len(containers))
		}
		for _, c := range containers {
			name := get[string](t, c, "name")
			if image := get[string](t, c, "image"); !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(image) {
				t.Fatalf("%s image %q is not pinned by digest", name, image)
			}
			csc := get[map[string]any](t, c, "securityContext")
			if csc["allowPrivilegeEscalation"] != false || csc["readOnlyRootFilesystem"] != true ||
				!slices.Equal(get[[]any](t, csc, "capabilities", "drop"), []any{"ALL"}) {
				t.Fatalf("%s securityContext is %v", name, csc)
			}
			if _, ok := c.(map[string]any)["ports"]; ok && name != "spire-server" {
				t.Fatalf("%s declares ports", name)
			}
		}
		if got := get[string](t, containers[0], "image"); got != "localhost:5001/cluster-jwt-server@"+r.digest {
			t.Fatalf("plugin image is %q", got)
		}
		if ann := get[string](t, objs["StatefulSet/spire-server"], "spec", "template", "metadata", "annotations", "cell.poc.internal/config-checksum"); !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(ann) {
			t.Fatalf("config checksum annotation is %q", ann)
		}

		volumes := get[[]any](t, pod, "volumes")
		var items []string
		for _, src := range get[[]any](t, named(t, volumes, "records"), "projected", "sources") {
			name := get[string](t, src, "configMap", "name")
			if _, ok := objs["ConfigMap/"+name]; !ok {
				t.Fatalf("records volume uses %s, which the render does not print", name)
			}
			for _, it := range get[[]any](t, src, "configMap", "items") {
				items = append(items, get[string](t, it, "key")+"->"+get[string](t, it, "path"))
			}
		}
		if !slices.Equal(items, []string{"record.dsse.json->dev-cell-1.dsse.json", "record.dsse.json->dev-cell-2.dsse.json"}) {
			t.Fatalf("record items are %v", items)
		}
		upstream := named(t, volumes, "upstream")
		if get[string](t, upstream, "secret", "secretName") != "spire-upstream" {
			t.Fatal("upstream volume does not use Secret spire-upstream")
		}
		var keys []string
		for _, it := range get[[]any](t, upstream, "secret", "items") {
			keys = append(keys, get[string](t, it, "key")+"->"+get[string](t, it, "path"))
		}
		if !slices.Equal(keys, []string{"intermediate-key->intermediate.key", "intermediate-cert->intermediate.crt", "root-cert->root.crt"}) {
			t.Fatalf("upstream items are %v", keys)
		}
	})

	t.Run("server config", func(t *testing.T) {
		text := get[string](t, objs["ConfigMap/spire-server"], "data", "server.conf")
		var top map[string]any
		if err := hcl.Decode(&top, text); err != nil {
			t.Fatalf("server.conf does not parse: %v", err)
		}
		if len(top) != 2 || top["server"] == nil || top["plugins"] == nil {
			t.Fatalf("server.conf top-level blocks: %v; want only server and plugins, so no telemetry or health listener", keysOf(top))
		}
		var conf struct {
			Server struct {
				TrustDomain     string `hcl:"trust_domain"`
				BindPort        int    `hcl:"bind_port"`
				SocketPath      string `hcl:"socket_path"`
				LogFormat       string `hcl:"log_format"`
				PruneTOFU       bool   `hcl:"prune_tofu_nodes"`
				CATTL           string `hcl:"ca_ttl"`
				AgentTTL        string `hcl:"agent_ttl"`
				X509TTL         string `hcl:"default_x509_svid_ttl"`
				PruneExpiredFor string `hcl:"prune_attested_nodes_expired_for"`
				RateLimit       struct {
					Attestation *bool `hcl:"attestation"`
				} `hcl:"ratelimit"`
			} `hcl:"server"`
		}
		if err := hcl.Decode(&conf, text); err != nil {
			t.Fatal(err)
		}
		s := conf.Server
		if s.TrustDomain != "dev.env.poc.internal" || s.BindPort != 8081 || s.LogFormat != "json" || !s.PruneTOFU ||
			s.PruneExpiredFor == "" || s.RateLimit.Attestation == nil || *s.RateLimit.Attestation ||
			s.SocketPath != "/run/spire/sockets/api.sock" {
			t.Fatalf("server block is %+v", s)
		}
		if s.CATTL != "24h" || s.AgentTTL != "1m" || s.X509TTL != "1m" {
			t.Fatalf("lifetimes: ca_ttl %q, agent_ttl %q, default_x509_svid_ttl %q; want 24h, and SPIRE_SVID_TTL 1m for both SVIDs", s.CATTL, s.AgentTTL, s.X509TTL)
		}

		sum := sha256.Sum256([]byte(stubBinary))
		for _, want := range []string{
			`plugin_checksum = "` + hex.EncodeToString(sum[:]) + `"`,
			`record_public_keys = ["stubkey1=", "stubkey2="]`,
			`UpstreamAuthority "disk"`,
			`bundle_file_path = "/run/spire/upstream/root.crt"`,
			`records_dir = "/run/spire/records"`,
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("server.conf lacks %q", want)
			}
		}
	})

	t.Run("controller manager config", func(t *testing.T) {
		var cm map[string]any
		if err := yaml.Unmarshal([]byte(get[string](t, objs["ConfigMap/spire-controller-manager"], "data", "config.yaml")), &cm); err != nil {
			t.Fatal(err)
		}
		if cm["kind"] != "ControllerManagerConfig" || cm["entryIDPrefix"] != "poc" || cm["clusterDomain"] == "" ||
			cm["staticManifestPath"] != "/run/spire/entries" || cm["spireServerSocketPath"] != "/run/spire/sockets/api.sock" ||
			cm["trustDomain"] != "dev.env.poc.internal" || cm["logEncoding"] != "json" {
			t.Fatalf("config is %v", cm)
		}
		if _, ok := cm["entryIDPrefixCleanup"]; ok {
			t.Fatal("entryIDPrefixCleanup is set")
		}
		rec := get[map[string]any](t, cm, "reconcile")
		if rec["clusterStaticEntries"] != true || rec["clusterFederatedTrustDomains"] != false || rec["clusterSPIFFEIDs"] != false {
			t.Fatalf("reconcile is %v", rec)
		}
		if get[string](t, cm, "metrics", "bindAddress") != "0" || get[string](t, cm, "health", "healthProbeBindAddress") != "0" {
			t.Fatal("the controller manager opens a metrics or health listener")
		}
	})

	t.Run("external secret fills the upstream Secret from the cluster store", func(t *testing.T) {
		es, ok := objs["ExternalSecret/spire-upstream"]
		if !ok {
			t.Fatal("render prints no ExternalSecret spire-upstream")
		}
		if get[string](t, es, "apiVersion") != "external-secrets.io/v1" {
			t.Fatalf("apiVersion is %v", es["apiVersion"])
		}
		if opts := get[string](t, es, "metadata", "annotations", "argocd.argoproj.io/sync-options"); !strings.Contains(opts, "SkipDryRunOnMissingResource=true") {
			t.Fatalf("sync options are %q", opts)
		}
		spec := get[map[string]any](t, es, "spec")
		if get[string](t, spec, "secretStoreRef", "kind") != "ClusterSecretStore" || get[string](t, spec, "secretStoreRef", "name") != "poc-secrets" {
			t.Fatalf("secretStoreRef is %v", spec["secretStoreRef"])
		}
		if get[string](t, spec, "target", "name") != "spire-upstream" || get[string](t, spec, "target", "creationPolicy") != "Owner" {
			t.Fatalf("target is %v", spec["target"])
		}
		// A template stops ESO from copying the Argo CD annotations of the ExternalSecret to the Secret.
		tpl := get[map[string]any](t, spec, "target", "template")
		if _, ok := tpl["metadata"]; !ok {
			t.Fatal("target template has no metadata")
		}
		if _, ok := tpl["data"]; ok {
			t.Fatal("target template rewrites the data")
		}
		var pairs []string
		for _, d := range get[[]any](t, spec, "data") {
			pairs = append(pairs, get[string](t, d, "secretKey")+"<-"+get[string](t, d, "remoteRef", "key"))
		}
		if !slices.Equal(pairs, []string{
			"intermediate-key<-@CELL_NAME@/spire-server/intermediate-key",
			"intermediate-cert<-@CELL_NAME@/spire-server/intermediate-cert",
			"root-cert<-@CELL_NAME@/spire-server/root-cert",
		}) {
			t.Fatalf("data is %v", pairs)
		}
	})

	t.Run("entries declare a node alias and the celld ID for each cell", func(t *testing.T) {
		data := get[map[string]any](t, objs["ConfigMap/spire-entries"], "data")
		if got := keysOf(data); !slices.Equal(got, []string{"dev-cell-1-celld.yaml", "dev-cell-1-nodes.yaml", "dev-cell-2-celld.yaml", "dev-cell-2-nodes.yaml"}) {
			t.Fatalf("spire-entries keys are %v", got)
		}
		type entry struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Metadata   struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec entrySpec `json:"spec"`
		}
		for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
			alias := "spiffe://dev.env.poc.internal/cell/" + cell + "/nodes"
			for file, want := range map[string]entry{
				cell + "-nodes.yaml": {Spec: entrySpec{alias, "spiffe://dev.env.poc.internal/spire/server", []string{"cluster_jwt:cell:" + cell, "cluster_jwt:sa:cell-identity-system:celld"}}},
				cell + "-celld.yaml": {Spec: entrySpec{"spiffe://dev.env.poc.internal/cell/" + cell + "/celld", alias, []string{"unix:uid:65532"}}},
			} {
				var got entry
				if err := yaml.UnmarshalStrict([]byte(get[string](t, data, file)), &got); err != nil {
					t.Fatalf("%s: %v", file, err)
				}
				if got.APIVersion != "spire.spiffe.io/v1alpha1" || got.Kind != "ClusterStaticEntry" || got.Metadata.Name+".yaml" != file {
					t.Fatalf("%s header is %+v", file, got)
				}
				if got.Spec.SPIFFEID != want.Spec.SPIFFEID || got.Spec.ParentID != want.Spec.ParentID || !slices.Equal(got.Spec.Selectors, want.Spec.Selectors) {
					t.Fatalf("%s spec is %+v, want %+v", file, got.Spec, want.Spec)
				}
			}
		}
	})

	t.Run("pod mounts only rendered config maps", func(t *testing.T) {
		pod := get[map[string]any](t, objs["StatefulSet/spire-server"], "spec", "template", "spec")
		for _, v := range get[[]any](t, pod, "volumes") {
			if name, ok := lookup(v, "configMap", "name"); ok {
				if _, found := objs["ConfigMap/"+name.(string)]; !found {
					t.Fatalf("volume uses ConfigMap %v, which the render does not print", name)
				}
			}
		}
	})
}

type entrySpec struct {
	SPIFFEID  string   `json:"spiffeID"`
	ParentID  string   `json:"parentID"`
	Selectors []string `json:"selectors"`
}

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TestRenderSVIDLifetime renders the lifetime that a long-lived environment sets.
func TestRenderSVIDLifetime(t *testing.T) {
	r := render(t, "SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL=1h")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	text := get[string](t, docs(t, r.stdout)["ConfigMap/spire-server"], "data", "server.conf")
	for _, want := range []string{`agent_ttl = "1h"`, `default_x509_svid_ttl = "1h"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("server.conf lacks %q", want)
		}
	}
}

func TestRenderFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"cell without facts", []string{"SPIRE_AGENT_CELLS=dev-cell-1 bad-facts"}, "no host service facts for bad-facts"},
		{"cell without node address", []string{"SPIRE_AGENT_CELLS=no-ip"}, "node address of no-ip"},
		{"no cells", []string{"SPIRE_AGENT_CELLS= "}, "names no cell"},
		{"unset cells", []string{"SPIRE_AGENT_CELLS="}, "SPIRE_AGENT_CELLS"},
		{"no images file", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_IMAGES=missing"}, "Run mise run images first"},
		{"stale images file", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_IMAGES=stale"}, "Run mise run images again"},
		{"image not in the registry", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_NO_REGISTRY=1"}, "the registry has no localhost:5001/cluster-jwt-server@sha256:"},
		{"layer with another digest", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_BAD_LAYER=1"}, "could not fetch layer"},
		{"manifest with another digest", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_BAD_MANIFEST=1"}, "could not fetch the manifest of localhost:5001/cluster-jwt-server@sha256:"},
		{"subject without a namespace", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_AGENT_SUBJECT=celld"}, "is not <namespace>/<service account>"},
		{"key test trace on an agent cell", []string{"SPIRE_AGENT_CELLS=dev-cell-1 dev-cell-2", "STUB_KEYTEST_TRACE=dev-cell-2"}, "Run: mise run gate:m2:repair"},
		{"docker reaches another daemon", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_DOCKER_IP=10.0.0.99"}, "reports '10.9.0.7'"},
		{"unset SVID lifetime", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL="}, "SPIRE_SVID_TTL"},
		{"SVID lifetime in days", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL=1d"}, "SPIRE_SVID_TTL '1d' is not"},
		{"SVID lifetime below the tested floor", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL=30s"}, "SPIRE_SVID_TTL '30s' is not"},
		{"SVID lifetime above ca_ttl / 6", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL=5h"}, "above ca_ttl / 6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := render(t, tc.env...)
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
