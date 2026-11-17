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

// stubMgmtKey is the public key of mgmtd that the stub ConfigMap mgmt-signing-pub holds: the bytes 1 to 32.
const stubMgmtKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

// stubMise answers "mise run hostsvc -- facts" for the cells below, "mise run mgmt -- records" with
// the records of dev-cell-1 and dev-cell-2, and runs the real pkigen for "mise run pki". The cell
// bad-facts fails the way hostsvc fails, and no-ip has no node address. STUB_RANDOM_SIG gives each
// record a new signature, STUB_FACTS_FAIL=<cells> makes the facts of those cells fail, STUB_FACTS_NOIP=<cells> gives them no node address, STUB_REVOKED=<cell> revokes one record, STUB_RECORD_NAME=<cell>=<name> signs the record of a cell with another name, and STUB_NO_MGMT makes mgmt fail.
const stubMise = `#!/usr/bin/env bash
set -euo pipefail
echo "$*" >>"$STUB_LOG"
case "$2" in
  hostsvc)
    cell="$6"
    # STUB_FACTS_FAIL and STUB_FACTS_NOIP name cells (space separated) whose facts fail, or have no node address.
    if [[ " ${STUB_FACTS_FAIL:-} " == *" $cell "* ]]; then
      echo '{"level":"ERROR","msg":"hostsvc failed","error":"cluster does not exist"}'; exit 1
    fi
    if [[ " ${STUB_FACTS_NOIP:-} " == *" $cell "* ]]; then
      printf '{"name":"%s","nodeIP":""}\n' "$cell"; exit 0
    fi
    case "$cell" in
      dev-cell-1) echo '{"name":"dev-cell-1","nodeIP":"10.9.0.1"}' ;;
      dev-cell-2) echo '{"name":"dev-cell-2","nodeIP":"10.9.0.2"}' ;;
      dev-cp) echo '{"name":"dev-cp","nodeIP":"10.9.0.9"}' ;;
      management) echo '{"name":"management","nodeIP":"10.9.0.10"}' ;;
      no-ip) echo '{"name":"no-ip","nodeIP":""}' ;;
      *) echo '{"level":"ERROR","msg":"hostsvc failed","error":"cluster does not exist"}'; exit 1 ;;
    esac ;;
  mgmt)
    # With STUB_NEXT_PUB set, mgmtd has staged a key: pubkey answers the live key, and status answers stagedKey, the SHA-256 of the
    # bytes of STUB_NEXT_PUB, or STUB_STAGED_KEY when that is set. STUB_STAGED_KEY alone makes status show a stagedKey while the
    # ConfigMap holds no next.pub.
    case "$4" in
      pubkey) printf '{"spec.pub":"%s"}\n' "${STUB_MGMT_KEY:-AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=}"; exit 0 ;;
      status)
        staged="${STUB_STAGED_KEY:-}"
        if [[ -z "$staged" && -n "${STUB_NEXT_PUB:-}" ]]; then staged="$(printf '%s' "$STUB_NEXT_PUB" | base64 -d | shasum -a 256 | cut -d' ' -f1)"; fi
        printf '{"signed":{"epoch":1,"counter":1},"stagedKey":"%s"}\n' "$staged"
        exit 0 ;;
    esac
    [[ "$4" == records ]] || exit 2
    if [[ -n "${STUB_NO_MGMT:-}" ]]; then
      echo '{"level":"ERROR","msg":"mgmt failed","error":"pod mgmtd-0 is absent or not Ready"}'
      exit 1
    fi
    out='{}'
    for cell in dev-cell-1 dev-cell-2; do
      revoked=false
      [[ "${STUB_REVOKED:-}" != "$cell" ]] || revoked=true
      sig="sig-$cell"
      name="$cell"
      [[ "${STUB_RECORD_NAME:-}" != "$cell="* ]] || name="${STUB_RECORD_NAME#*=}"
      [[ -z "${STUB_RANDOM_SIG:-}" ]] || sig="$RANDOM$RANDOM"
      payload="$(printf '{"name":"%s","env":"%s","revoked":%s}' "$name" "${STUB_RECORD_ENV:-${POC_ENV:-dev}}" "$revoked" | base64 | tr -d '\n')"
      out="$(jq -c --arg c "$cell" --arg p "$payload" --arg s "$sig" '.[$c] = {payloadType: "application/vnd.poc.cell-record+json", payload: $p, signatures: [{keyid: "", sig: $s}]}' <<<"$out")"
    done
    echo "$out"
    ;;
  pki) shift 3; exec "$STUB_PKIGEN" "$@" ;;
  *) exit 2 ;;
esac
`

// stubOras serves one image manifest and its last layer. STUB_NO_REGISTRY makes every fetch fail.
// STUB_BAD_MANIFEST serves a manifest, and STUB_BAD_LAYER a layer, whose digest does not match.
const stubOras = `#!/usr/bin/env bash
set -euo pipefail
echo "oras $*" >>"$STUB_LOG"
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

// stubKubectl answers "get configmap mgmt-signing-pub" with the key stubMgmtKey (STUB_MGMT_KEY
// replaces it, and STUB_NO_MGMT_KEY makes the ConfigMap absent), and "get pod mgmtd-0" with no
// status, so the key helper makes no call to mgmtd. It answers "get configmap mgmt-spec-key" with
// STUB_PINNED_KEY, which is empty by default, so the key is a first pin. It answers "spire-server bundle show" with the
// file STUB_BUNDLE_FILE, and in the context
// kind-management with STUB_MGMT_BUNDLE_FILE, the root of mgmt.poc.internal. It answers
// "api-resources" with a fixed table, or fails with STUB_NO_API. STUB_NO_SERVER
// makes it fail the way kubectl does when the pod is missing, and STUB_BAD_BUNDLE adds a line
// that is not PEM. It answers "get statefulset spire-server" with the name, or with nothing under
// STUB_NO_STS, whatever STUB_NO_SERVER says. STUB_NO_SERVER_IN=<cluster> makes it fail the way
// STUB_NO_SERVER does, but only in that cluster.
const stubKubectl = `#!/usr/bin/env bash
set -euo pipefail
echo "kubectl $*" >>"$STUB_LOG"
if [[ " $* " == *" get configmap mgmt-signing-pub "* ]]; then
  if [[ -n "${STUB_NO_MGMT_KEY:-}" ]]; then
    echo 'Error from server (NotFound): configmaps "mgmt-signing-pub" not found' >&2
    exit 1
  fi
  if [[ -n "${STUB_NEXT_PUB:-}" ]]; then
    printf '{"data":{"spec.pub":"%s","next.pub":"%s"}}\n' "${STUB_MGMT_KEY:-AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=}" "$STUB_NEXT_PUB"
  else
    printf '{"data":{"spec.pub":"%s"}}\n' "${STUB_MGMT_KEY:-AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=}"
  fi
  exit 0
fi
if [[ " $* " == *" get configmap mgmt-spec-key "* ]]; then
  printf '%s' "${STUB_PINNED_KEY:-}"
  exit 0
fi
if [[ " $* " == *" get pod mgmtd-0 "* ]]; then
  # mgmtd-0 is Ready only when the test stages a key, so the key helper checks the staged key against mgmtd.
  # STUB_MGMTD_DOWN keeps it not Ready while a key is staged.
  if [[ -n "${STUB_NEXT_PUB:-}${STUB_STAGED_KEY:-}" && -z "${STUB_MGMTD_DOWN:-}" ]]; then printf 'True'; fi
  exit 0
fi
if [[ " $* " == *" get node "* ]]; then
  echo 10.9.0.7
  exit 0
fi
if [[ " $* " == *" api-resources "* ]]; then
  [[ -z "${STUB_NO_API:-}" ]] || exit 1
  cat <<'TABLE'
configmaps                          cm           v1                                true         ConfigMap
events                              ev           v1                                true         Event
namespaces                          ns           v1                                false        Namespace
pods                                po           v1                                true         Pod
secrets                                          v1                                true         Secret
serviceaccounts                     sa           v1                                true         ServiceAccount
services                            svc          v1                                true         Service
validatingwebhookconfigurations                  admissionregistration.k8s.io/v1   false        ValidatingWebhookConfiguration
customresourcedefinitions           crd,crds     apiextensions.k8s.io/v1           false        CustomResourceDefinition
deployments                         deploy       apps/v1                           true         Deployment
statefulsets                        sts          apps/v1                           true         StatefulSet
events                              ev           events.k8s.io/v1                  true         Event
clusterroles                                     rbac.authorization.k8s.io/v1      false        ClusterRole
authorizationpolicies               ap           security.istio.io/v1              true         AuthorizationPolicy
TABLE
  exit 0
fi
if [[ " $* " == *" get statefulset spire-server "* ]]; then
  [[ -n "${STUB_NO_STS:-}" ]] || echo statefulset.apps/spire-server
  exit 0
fi
if [[ -n "${STUB_NO_SERVER_IN:-}" && " $* " == *" --context kind-$STUB_NO_SERVER_IN "* ]]; then
  echo "Error from server (NotFound): pods \"spire-server-0\" not found" >&2
  exit 1
fi
if [[ -n "${STUB_NO_SERVER:-}" ]]; then
  echo 'Error from server (NotFound): pods "spire-server-0" not found' >&2
  exit 1
fi
if [[ " $* " == *" --context kind-management "* ]]; then
  cat "$STUB_MGMT_BUNDLE_FILE"
  exit 0
fi
cat "$STUB_BUNDLE_FILE"
[[ -z "${STUB_BAD_BUNDLE:-}" ]] || echo "not a certificate"
`

// stubDocker answers the node checks of scripts/gate-traces.sh. Every node has the address 10.9.0.7
// unless STUB_DOCKER_IP sets another one. STUB_KEYTEST_TRACE names a cell whose node holds a trace of
// the key rotation test, and STUB_NO_NODE_IP names cells with no node address. It also answers getent for host.docker.internal in a node container.
const stubDocker = `#!/usr/bin/env bash
set -euo pipefail
echo "docker $*" >>"$STUB_LOG"
case "$1" in
  inspect)
    # STUB_NO_NODE_IP names the cells (space separated) whose node container has no address on the network kind.
    name="${*: -1}"
    if [[ " ${STUB_NO_NODE_IP:-} " == *" ${name%-control-plane} "* ]]; then echo " "; else echo "${STUB_DOCKER_IP:-10.9.0.7} "; fi ;;
  exec)
    if [[ " $* " == *" getent ahostsv4 host.docker.internal "* ]]; then
      # STUB_GETENT replaces the answer. The default is one address in three socket types.
      printf '%b' "${STUB_GETENT:-192.168.5.2 STREAM host.docker.internal\\n192.168.5.2 DGRAM\\n192.168.5.2 RAW\\n}"
      exit 0
    fi
    if [[ "$2" == "${STUB_KEYTEST_TRACE:-none}-control-plane" ]]; then
      echo "/etc/kubernetes/manifests/kube-apiserver.yaml names the test key"
    fi ;;
  *) exit 1 ;;
esac
`

// stubKind answers "kind get clusters" with the five clusters of the harness, or with the names in
// STUB_KIND_CLUSTERS (one for each word). STUB_KIND_CLUSTERS=none prints kind's message for no cluster.
const stubKind = `#!/usr/bin/env bash
set -euo pipefail
echo "kind $*" >>"$STUB_LOG"
[[ "$*" == "get clusters" ]] || exit 2
case "${STUB_KIND_CLUSTERS:-management dev-cp dev-cell-1 dev-cell-2 rogue}" in
  none) echo "No kind clusters found." >&2 ;;
  *) printf '%s\n' ${STUB_KIND_CLUSTERS:-management dev-cp dev-cell-1 dev-cell-2 rogue} ;;
esac
`

// stubHostsvcServe stands for scripts/hostsvc-serve.sh. It runs no process: start does nothing,
// status prints a fixed certificate SHA-256 (STUB_HOSTSVC_SHA overrides it), and pin prints the
// certificate in STUB_PIN_FILE. STUB_HOSTSVC_FAIL makes start fail.
const stubHostsvcServe = `#!/usr/bin/env bash
set -euo pipefail
echo "hostsvc-serve $*" >>"$STUB_LOG"
case "$1" in
  start) [[ -z "${STUB_HOSTSVC_FAIL:-}" ]] || { echo "the host service does not start" >&2; exit 1; } ;;
  status) printf '{"running":true,"pid":4242,"cert_sha256":"%s","root_sha256":"","expires_soon":false,"last_error":""}\n' \
    "${STUB_HOSTSVC_SHA:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" ;;
  pin) cat "$STUB_PIN_FILE" ;;
  *) exit 2 ;;
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

// serverFacts are the cluster facts of build/<cluster>/facts.env that the server render reads.
var serverFacts = []string{"API_SERVER_IPS=172.18.0.4", "API_SERVER_PORT=6443", "API_SERVICE_IP=10.111.0.1", "DNS_SERVICE_IP=10.111.0.10"}

// render renders the server with the settings of an environment server like dev-cp, with no local
// workload. The env values override them.
func render(t *testing.T, env ...string) result {
	t.Helper()
	defaults := []string{"SPIRE_SVID_TTL=1m", "SPIRE_TRUST_DOMAIN=dev.env.poc.internal", "SPIRE_UPSTREAM=disk",
		"SPIRE_CELL_SUBJECTS=cell-identity-system/celld=celld", "SECRET_STORE_NAMESPACES=spire-system"}
	return renderScript(t, "spire-server", "/ko-app/cluster-jwt-server", append(append(defaults, serverFacts...), env...)...)
}

// renderCell renders the server with cells/common.env and cells/<cluster>.env, as hydrate does.
func renderCell(t *testing.T, cluster string, env ...string) result {
	t.Helper()
	return renderScript(t, "spire-server", "/ko-app/cluster-jwt-server", append(append([]string{"STUB_CELL=" + cluster}, serverFacts...), env...)...)
}

// hydrated replaces @CELL_NAME@ as scripts/hydrate.sh does.
func hydrated(out, cluster string) string {
	return strings.ReplaceAll(out, "@CELL_NAME@", cluster)
}

// cellEnvKeys returns every setting name of cells/*.env. mise loads the file of one cluster into
// the environment of go test, so the stub runner drops these names, and a render reads only the
// settings that a test passes.
func cellEnvKeys(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("../../cells/*.env")
	if err != nil || len(files) == 0 {
		t.Fatalf("no cells/*.env files: %v", err)
	}
	keys := map[string]bool{"CELL": true}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if k, _, ok := strings.Cut(line, "="); ok && regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`).MatchString(k) {
				keys[k] = true
			}
		}
	}
	return keys
}

// renderScript runs the render script of a component with stub host commands.
func renderScript(t *testing.T, component, binary string, env ...string) result {
	t.Helper()
	script, err := filepath.Abs("../../components/" + component + "/render.sh")
	if err != nil {
		t.Fatal(err)
	}
	return runStubbed(t, binary, "", []string{script}, env...)
}

// runStubbed runs argv with stub host commands and stdin. The stub image holds one file at binary,
// and every image in images.env pins that stub image. STUB_IMAGES=missing and STUB_IMAGES=stale
// make images.env missing or older than the Go sources. STUB_TRUST_DOMAIN sets the trust domain of
// the bundle that the stub server prints. STUB_CELL=<cluster> loads cells/common.env and
// cells/<cluster>.env first, as hydrate does. The other values of env then override them.
func runStubbed(t *testing.T, binary, stdin string, argv []string, env ...string) result {
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
	write("kind", stubKind, 0o755)
	hostsvcServe := write("hostsvc-serve", stubHostsvcServe, 0o755)
	layerBytes := layerTarGz(t, binary)
	layer := write("layer.tar.gz", string(layerBytes), 0o644)
	manifestBytes := []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{"digest":"sha256:0000"},{"digest":"` + digestOf(layerBytes) + `"}]}`)
	manifest := write("manifest.json", string(manifestBytes), 0o644)
	write("manifest.json.bad", string(manifestBytes)+" ", 0o644)
	digest := digestOf(manifestBytes)
	var images strings.Builder
	for _, repo := range []string{"netprobe", "cluster-jwt-server", "cluster-jwt-agent", "celld", "cell-proxy", "viewkeys", "relay", "mgmtd", "envd", "cellgw"} {
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
	mgmtBundleFile := write("mgmt-bundle.pem", caPEM(t, "mgmt.poc.internal"), 0o644)
	logFile := filepath.Join(dir, "mise.log")

	if cell := opts["STUB_CELL"]; cell != "" {
		common, _ := filepath.Abs("../../cells/common.env")
		file, _ := filepath.Abs("../../cells/" + cell + ".env")
		var overrides []string
		for _, e := range env {
			if !strings.HasPrefix(e, "STUB_") {
				overrides = append(overrides, e)
			}
		}
		argv = append([]string{"bash", "-c", `set -a; source "$1"; source "$2"; set +a; shift 2
for kv in "${@:2}"; do export "$kv"; done
exec "$1"`, "_", common, file, argv[0]}, overrides...)
	}
	cellKeys := cellEnvKeys(t)
	var base []string
	for _, e := range os.Environ() {
		if k, _, _ := strings.Cut(e, "="); !cellKeys[k] {
			base = append(base, e)
		}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	agentBundles, _ := filepath.Abs("testdata/agent-bundles")
	cmd.Env = append(base,
		"AGENT_BUNDLES="+agentBundles,
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+logFile, "STUB_LAYER_FILE="+layer, "STUB_MANIFEST_FILE="+manifest,
		"STUB_BUNDLE_FILE="+bundleFile, "STUB_MGMT_BUNDLE_FILE="+mgmtBundleFile, "STUB_PKIGEN="+pkigen(t), "IMAGES_ENV="+imagesFile,
		"HOSTSVC_SERVE="+hostsvcServe, "STUB_PIN_FILE="+write("hostsvc.crt", caPEM(t, "host.docker.internal"), 0o644),
		"POC_ENV="+commonEnv(t, "POC_ENV"))
	cmd.Env = append(cmd.Env, env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
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

// clusterScoped lists the cluster-scoped kinds that a render can print.
var clusterScoped = []string{"Namespace", "CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding",
	"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}

// docsIn parses the render output by kind and name. Every namespaced object must be in ns, and no
// Namespace other than ns may appear. The cell-identity render also holds the objects of namespace
// cell-ops-system (TestCellOpsNamespace), and docsIn skips them for ns cell-identity-system.
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
		if ns == "cell-identity-system" {
			if opsNS, _ := lookup(o, "metadata", "namespace"); opsNS == "cell-ops-system" || key == "Namespace/cell-ops-system" {
				continue
			}
		}
		if _, dup := byKey[key]; dup {
			t.Fatalf("%s appears twice", key)
		}
		got, _ := lookup(o, "metadata", "namespace")
		switch kind := get[string](t, o, "kind"); {
		case kind == "Namespace" && key != "Namespace/"+ns:
			t.Fatalf("render prints %s, want only Namespace/%s", key, ns)
		case slices.Contains(clusterScoped, kind):
			if got != nil {
				t.Fatalf("cluster-scoped %s has namespace %v", key, got)
			}
		case got != ns:
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

// TestRenderSpireServer renders the environment server with cells/dev-cp.env. It keeps the M2
// checks, and checks the k8s_psat path for the dev-cp plane workload cp/otel.
func TestRenderSpireServer(t *testing.T) {
	r := renderCell(t, "dev-cp")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docs(t, hydrated(r.stdout, "dev-cp"))

	t.Run("k8s_psat admits the plane workloads cp/otel, envd and cp/gateway", func(t *testing.T) {
		checkPSAT(t, objs, "dev-cp", "dev.env.poc.internal", map[string]string{"cp/otel": "observability-system/otel-uplink", "envd": "envd-system/envd", "cp/gateway": "gateway-system/cell-gateway"})
	})

	if left := regexp.MustCompile(`@[A-Z_]+@`).FindAllString(r.stdout, -1); slices.ContainsFunc(left, func(s string) bool { return s != "@CELL_NAME@" }) {
		t.Fatalf("render left tokens %v", left)
	}
	if want := "run hostsvc -- facts --cluster dev-cell-1"; !strings.Contains(r.log, want) {
		t.Fatalf("render did not run mise %q; it ran:\n%s", want, r.log)
	}

	// The external-secrets bundle holds Namespace spire-system, because the Role of the operator
	// lives there and comes in an earlier sync wave. Two bundles must not hold one object.
	t.Run("the bundle holds no Namespace", func(t *testing.T) {
		for key := range objs {
			if strings.HasPrefix(key, "Namespace/") {
				t.Fatalf("render contains %s", key)
			}
		}
	})

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
		// envd writes ConfigMap cell-records, so the records volume is an optional ConfigMap volume, and
		// the render prints no ConfigMap cell-record-*.
		records := named(t, volumes, "records")
		if get[string](t, records, "configMap", "name") != "cell-records" || get[bool](t, records, "configMap", "optional") != true {
			t.Fatalf("the records volume is %v, want the optional ConfigMap cell-records", records)
		}
		if _, ok := records["projected"]; ok {
			t.Fatalf("the records volume is projected: %v", records)
		}
		for key := range objs {
			if strings.HasPrefix(key, "ConfigMap/cell-record") {
				t.Fatalf("the render prints %s", key)
			}
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
		if len(top) != 3 || top["server"] == nil || top["plugins"] == nil || top["telemetry"] == nil {
			t.Fatalf("server.conf top-level blocks: %v; want only server, plugins and telemetry, so no health listener", keysOf(top))
		}
		checkPrometheus(t, text)
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
			// Only the key of mgmtd signs records, and the plugin reloads and keeps its marks on the data volume.
			`record_public_keys = ["` + stubMgmtKey + `"]`,
			`reload_interval = "10s"`,
			`marks_file = "/run/spire/data/cluster_jwt-marks.json"`,
			`UpstreamAuthority "disk"`,
			`bundle_file_path = "/run/spire/upstream/root.crt"`,
			`records_dir = "/run/spire/records"`,
			// Three times the slowest challenge reply of the gate:m2 runs, with a floor of 10s.
			`challenge_timeout = "10s"`,
			// The upstream authority signs a new CA after each restart, so the keys stay in memory.
			`KeyManager "memory"`,
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("server.conf lacks %q", want)
			}
		}
		if strings.Contains(text, `KeyManager "disk"`) {
			t.Fatal("the dev-cp server keeps its CA key on disk")
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
		if get[string](t, spec, "secretStoreRef", "kind") != "SecretStore" || get[string](t, spec, "secretStoreRef", "name") != "poc-secrets" {
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
			"intermediate-key<-dev-cp/spire-server/intermediate-key",
			"intermediate-cert<-dev-cp/spire-server/intermediate-cert",
			"root-cert<-dev-cp/spire-server/root-cert",
		}) {
			t.Fatalf("data is %v", pairs)
		}
	})

	t.Run("entries declare a node alias and the role ID for each subject of each cell", func(t *testing.T) {
		data := get[map[string]any](t, objs["ConfigMap/spire-entries"], "data")
		subjects := map[string]string{"celld": "cell-identity-system:celld", "argocd-agent": "argocd:argocd-agent",
			"otel": "observability-system:otel-uplink", "mesh-view": "mesh-view-system:mesh-view"}
		wantKeys := []string{"agents-observability-system-otel-uplink.yaml", "workload-cp-otel.yaml", "agents-envd-system-envd.yaml", "workload-envd.yaml",
			"agents-gateway-system-cell-gateway.yaml", "workload-cp-gateway.yaml"}
		for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
			for role := range subjects {
				wantKeys = append(wantKeys, cell+"-agents-"+role+".yaml", cell+"-"+role+".yaml")
			}
		}
		slices.Sort(wantKeys)
		if got := keysOf(data); !slices.Equal(got, wantKeys) {
			t.Fatalf("spire-entries keys are %v, want %v", got, wantKeys)
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
			for role, sa := range subjects {
				alias := "spiffe://dev.env.poc.internal/cell/" + cell + "/agents/" + role
				for file, want := range map[string]entry{
					cell + "-agents-" + role + ".yaml": {Spec: entrySpec{alias, "spiffe://dev.env.poc.internal/spire/server", []string{"cluster_jwt:cell:" + cell, "cluster_jwt:sa:" + sa}}},
					cell + "-" + role + ".yaml":        {Spec: entrySpec{"spiffe://dev.env.poc.internal/cell/" + cell + "/" + role, alias, []string{"unix:uid:65532"}}},
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
		}
	})

	t.Run("pod mounts only rendered config maps", func(t *testing.T) {
		pod := get[map[string]any](t, objs["StatefulSet/spire-server"], "spec", "template", "spec")
		for _, v := range get[[]any](t, pod, "volumes") {
			if name, ok := lookup(v, "configMap", "name"); ok {
				// cell-records is the one ConfigMap that envd makes at run time, so the volume must be optional.
				if name == "cell-records" {
					if opt, _ := lookup(v, "configMap", "optional"); opt != true {
						t.Fatalf("volume uses ConfigMap cell-records without optional: true: %v", v)
					}
					continue
				}
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
		{"live cell without facts", []string{"SPIRE_AGENT_CELLS=dev-cell-1 dev-cell-2", "STUB_FACTS_FAIL=dev-cell-2"}, "no host service facts for the live cell dev-cell-2"},
		{"live cell without facts names the read command", []string{"SPIRE_AGENT_CELLS=dev-cell-1 dev-cell-2", "STUB_FACTS_FAIL=dev-cell-2"}, "Read them: mise run hostsvc -- facts --cluster dev-cell-2"},
		{"live cell without node address", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_FACTS_NOIP=dev-cell-1"}, "node address of dev-cell-1"},
		{"blank cells with subjects", []string{"SPIRE_AGENT_CELLS= "}, "SPIRE_AGENT_CELLS and SPIRE_CELL_SUBJECTS must both be set or both be unset"},
		{"cells without subjects", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CELL_SUBJECTS="}, "SPIRE_AGENT_CELLS and SPIRE_CELL_SUBJECTS must both be set or both be unset"},
		{"no cell and no local workload", []string{"SPIRE_AGENT_CELLS=", "SPIRE_CELL_SUBJECTS="}, "names no agent cell and no local workload"},
		{"no images file", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_IMAGES=missing"}, "Run mise run images first"},
		{"stale images file", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_IMAGES=stale"}, "Run mise run images again"},
		{"image not in the registry", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_NO_REGISTRY=1"}, "the registry has no localhost:5001/cluster-jwt-server@sha256:"},
		{"layer with another digest", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_BAD_LAYER=1"}, "could not fetch layer"},
		{"manifest with another digest", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_BAD_MANIFEST=1"}, "could not fetch the manifest of localhost:5001/cluster-jwt-server@sha256:"},
		{"subject without a namespace", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CELL_SUBJECTS=celld=celld"}, "is not <namespace>/<service account>=<role>"},
		{"subject without a role", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CELL_SUBJECTS=cell-identity-system/celld"}, "is not <namespace>/<service account>=<role>"},
		{"one role twice", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CELL_SUBJECTS=cell-identity-system/celld=celld argocd/argocd-agent=celld"}, "names the role celld twice"},
		{"one ServiceAccount twice", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CELL_SUBJECTS=cell-identity-system/celld=celld cell-identity-system/celld=other"}, "names the ServiceAccount cell-identity-system/celld twice"},
		{"the alias path as a role", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CELL_SUBJECTS=cell-identity-system/celld=agents"}, "the path of the node aliases"},
		{"a role that names an alias entry", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CELL_SUBJECTS=cell-identity-system/celld=agents-celld"}, "the path of the node aliases, or names an alias entry"},
		{"no management signing key", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_NO_MGMT_KEY=1"}, "ConfigMap mgmt-system/mgmt-signing-pub is absent. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
		{"management signing key of the wrong size", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_MGMT_KEY=c2hvcnQ="}, "is not the base64 of 32 bytes"},
		{"key test trace on an agent cell", []string{"SPIRE_AGENT_CELLS=dev-cell-1 dev-cell-2", "STUB_KEYTEST_TRACE=dev-cell-2"}, "Run: mise run gate:m2:repair"},
		{"docker reaches another daemon", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_DOCKER_IP=10.0.0.99"}, "reports '10.9.0.7'"},
		{"unset SVID lifetime", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL="}, "SPIRE_SVID_TTL"},
		{"SVID lifetime in days", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL=1d"}, "SPIRE_SVID_TTL '1d' is not"},
		{"SVID lifetime below the tested floor", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL=30s"}, "SPIRE_SVID_TTL '30s' is not"},
		{"SVID lifetime above ca_ttl / 6", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_SVID_TTL=5h"}, "above ca_ttl / 6"},
		{"CA lifetime in days", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CA_TTL=90d"}, "SPIRE_CA_TTL '90d' is not"},
		{"CA lifetime below the JWT floor", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_CA_TTL=20m"}, "below 30m"},
		{"unset trust domain", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_TRUST_DOMAIN="}, "SPIRE_TRUST_DOMAIN"},
		{"trust domain with a path", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_TRUST_DOMAIN=dev.env.poc.internal/x"}, "is not a trust domain name"},
		{"unknown upstream", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "SPIRE_UPSTREAM=vault"}, "SPIRE_UPSTREAM 'vault' is not disk"},
		{"local workload without a path", []string{"SPIRE_CELL_SUBJECTS=", "SPIRE_LOCAL_WORKLOADS=observability-system/otel-uplink"}, "is not <spiffe path>=<namespace>/<service account>"},
		{"local workload with an agent path", []string{"SPIRE_CELL_SUBJECTS=", "SPIRE_LOCAL_WORKLOADS=spire/agent/x=observability-system/otel-uplink"}, "reserved"},
		{"local workload with a cell path", []string{"SPIRE_CELL_SUBJECTS=", "SPIRE_LOCAL_WORKLOADS=cell/dev-cell-1/celld=observability-system/otel-uplink"}, "reserved"},
		{"local workload with an alias path", []string{"SPIRE_CELL_SUBJECTS=", "SPIRE_LOCAL_WORKLOADS=agents/x=observability-system/otel-uplink"}, "reserved"},
		{"local workload path twice", []string{"SPIRE_CELL_SUBJECTS=", "SPIRE_LOCAL_WORKLOADS=cp/otel=observability-system/otel-uplink cp/otel=observability-system/other"}, "names cp/otel twice"},
		{"local workloads without API facts", []string{"SPIRE_CELL_SUBJECTS=", "SPIRE_LOCAL_WORKLOADS=cp/otel=observability-system/otel-uplink", "API_SERVER_IPS="}, "API_SERVER_IPS"},
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

// goldenSpireDevCP holds the dev-cp render of M2 at commit 2d8cb64 and the changes that M4 made on purpose:
// the records volume, record_public_keys, reload_interval and marks_file in server.conf, and two ConfigMaps
// less. The stub image digest is replaced by stubDigest. The tests compare the parts that matter.
const goldenSpireDevCP = "testdata/spire-server-dev-cp.golden.yaml"

// psatOnly matches the lines that the k8s_psat path and the telemetry block add to server.conf.
var psatOnly = regexp.MustCompile(`(?ms)^  NodeAttestor "k8s_psat" \{$.*?^  \}$\n|^telemetry \{$.*?^\}$\n?`)

// configLines returns the lines of a SPIRE config without comments and blank lines.
func configLines(text string) []string {
	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, line)
		}
	}
	return out
}

// TestSpireServerDevCPKeepsM2Objects renders the server with cells/dev-cp.env and compares each
// object with the M2 render, after it removes the k8s_psat additions: the plugin and telemetry
// blocks, the cp/otel entries, the token volume and the objects that only k8s_psat needs.
func TestSpireServerDevCPKeepsM2Objects(t *testing.T) {
	r := renderCell(t, "dev-cp")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	want, err := os.ReadFile(goldenSpireDevCP)
	if err != nil {
		t.Fatal(err)
	}
	got := docs(t, strings.ReplaceAll(r.stdout, r.digest, stubDigest))
	m2 := docs(t, string(want))
	for _, key := range []string{"ClusterRole/spire-server-psat", "ClusterRoleBinding/spire-server-psat", "NetworkPolicy/spire-server-workloads", "NetworkPolicy/spire-server-api", "NetworkPolicy/spire-server-metrics",
		"Role/spire-server-hints", "RoleBinding/spire-server-hints"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("render has no %s", key)
		}
		delete(got, key)
	}
	// The per-subject aliases cell/<cell>/agents/<role> replace the M2 alias cell/<cell>/nodes, so the
	// entries differ from M2. TestRenderSpireServer checks every entry.
	got["ConfigMap/spire-entries"]["data"] = map[string]any{}
	m2["ConfigMap/spire-entries"]["data"] = map[string]any{}

	conf := get[string](t, got["ConfigMap/spire-server"], "data", "server.conf")
	if n := len(psatOnly.FindAllString(conf, -1)); n != 2 {
		t.Fatalf("server.conf has %d k8s_psat or telemetry blocks, want 2:\n%s", n, conf)
	}
	gotLines := configLines(psatOnly.ReplaceAllString(conf, ""))
	wantLines := configLines(get[string](t, m2["ConfigMap/spire-server"], "data", "server.conf"))
	if !slices.Equal(gotLines, wantLines) {
		t.Errorf("server.conf without the k8s_psat and telemetry blocks differs from M2.\ngot:\n%s\nwant:\n%s", strings.Join(gotLines, "\n"), strings.Join(wantLines, "\n"))
	}
	delete(got, "ConfigMap/spire-server")
	delete(m2, "ConfigMap/spire-server")

	pod := get[map[string]any](t, got["StatefulSet/spire-server"], "spec", "template", "spec")
	pod["volumes"] = slices.DeleteFunc(get[[]any](t, pod, "volumes"), func(v any) bool { return get[string](t, v, "name") == "api-token" })
	server := named(t, get[[]any](t, pod, "containers"), "spire-server")
	server["volumeMounts"] = slices.DeleteFunc(get[[]any](t, server, "volumeMounts"), func(v any) bool { return get[string](t, v, "name") == "api-token" })
	for _, o := range []object{got["StatefulSet/spire-server"], m2["StatefulSet/spire-server"]} {
		delete(get[map[string]any](t, o, "spec", "template", "metadata", "annotations"), "cell.poc.internal/config-checksum")
	}
	sameObjects(t, got, m2)
}

// hclAt walks a config that hcl.Decode read into a map. HCL gives each block as a list of maps, so
// at a list the walk takes the first map that holds the next key.
func hclAt(t *testing.T, v any, keys ...string) any {
	t.Helper()
	for _, k := range keys {
		var next any
		var found bool
		switch x := v.(type) {
		case map[string]any:
			next, found = x[k]
		case []map[string]any:
			for _, m := range x {
				if next, found = m[k]; found {
					break
				}
			}
		}
		if !found {
			t.Fatalf("config has no %q on the path %v", k, keys)
		}
		v = next
	}
	return v
}

// checkPrometheus checks that the telemetry block serves Prometheus on all addresses at 9988, so
// the collector in the same cluster can scrape it.
func checkPrometheus(t *testing.T, text string) {
	t.Helper()
	var top map[string]any
	if err := hcl.Decode(&top, text); err != nil {
		t.Fatalf("server.conf does not parse: %v", err)
	}
	prom := hclAt(t, top, "telemetry", "Prometheus").([]map[string]any)
	if len(prom) != 1 || prom[0]["host"] != "0.0.0.0" || prom[0]["port"] != 9988 {
		t.Fatalf("telemetry Prometheus is %v, want host 0.0.0.0 and port 9988", prom)
	}
}

// checkPSAT checks the k8s_psat path of a server render: the plugin config, the API access of the
// server, the ingress rule for each local workload, and the alias and entry of each workload.
// workloads maps each SPIFFE path to <namespace>/<service account>.
func checkPSAT(t *testing.T, objs map[string]object, cluster, td string, workloads map[string]string) {
	t.Helper()
	text := get[string](t, objs["ConfigMap/spire-server"], "data", "server.conf")
	// k8s_psat ignores unknown keys, so only this exact key gives each sidecar its own agent ID.
	if !regexp.MustCompile(`(?m)^ +use_pod_uid_for_agent_id = true$`).MatchString(text) {
		t.Fatalf("server.conf lacks the literal key use_pod_uid_for_agent_id = true:\n%s", text)
	}
	var top map[string]any
	if err := hcl.Decode(&top, text); err != nil {
		t.Fatalf("server.conf does not parse: %v", err)
	}
	clusters := hclAt(t, top, "plugins", "NodeAttestor", "k8s_psat", "plugin_data", "clusters").([]map[string]any)
	if len(clusters) != 1 || len(clusters[0]) != 1 {
		t.Fatalf("k8s_psat clusters are %v, want only %s", clusters, cluster)
	}
	c := hclAt(t, clusters, cluster).([]map[string]any)
	var accounts, wantAccounts []string
	for _, a := range c[0]["service_account_allow_list"].([]any) {
		accounts = append(accounts, a.(string))
	}
	for _, sub := range workloads {
		wantAccounts = append(wantAccounts, strings.Replace(sub, "/", ":", 1))
	}
	slices.Sort(accounts)
	slices.Sort(wantAccounts)
	wantAccounts = slices.Compact(wantAccounts)
	if !slices.Equal(accounts, wantAccounts) || c[0]["use_pod_uid_for_agent_id"] != true || len(c[0]) != 2 {
		t.Fatalf("k8s_psat cluster %s is %v, want the accounts %v and use_pod_uid_for_agent_id", cluster, c[0], wantAccounts)
	}

	role := objs["ClusterRole/spire-server-psat"]
	var rules []string
	for _, r := range get[[]any](t, role, "rules") {
		if len(r.(map[string]any)) != 3 {
			t.Fatalf("rule %v has more than apiGroups, resources and verbs", r)
		}
		rules = append(rules, fmt.Sprintf("%v %v %v", get[[]any](t, r, "apiGroups"), get[[]any](t, r, "resources"), get[[]any](t, r, "verbs")))
	}
	if want := []string{"[authentication.k8s.io] [tokenreviews] [create]", "[] [pods] [get]", "[] [nodes] [get]"}; !slices.Equal(rules, want) {
		t.Fatalf("ClusterRole spire-server-psat rules are %v, want %v", rules, want)
	}
	binding := objs["ClusterRoleBinding/spire-server-psat"]
	if get[string](t, binding, "roleRef", "kind") != "ClusterRole" || get[string](t, binding, "roleRef", "name") != "spire-server-psat" ||
		len(get[[]any](t, binding, "subjects")) != 1 || get[string](t, binding, "subjects", 0, "name") != "spire-server" ||
		get[string](t, binding, "subjects", 0, "namespace") != "spire-system" {
		t.Fatalf("ClusterRoleBinding is %v", binding)
	}

	// The account mounts no token. Only the server container gets one, for TokenReview and the pod
	// and node reads.
	if objs["ServiceAccount/spire-server"]["automountServiceAccountToken"] != false {
		t.Fatal("the ServiceAccount mounts a token")
	}
	pod := get[map[string]any](t, objs["StatefulSet/spire-server"], "spec", "template", "spec")
	if pod["automountServiceAccountToken"] != false {
		t.Fatal("the pod mounts the automatic token")
	}
	token := named(t, get[[]any](t, pod, "volumes"), "api-token")
	if e, ok := lookup(token, "projected", "sources", 0, "serviceAccountToken", "expirationSeconds"); !ok || e != float64(600) {
		t.Fatalf("api-token volume is %v", token)
	}
	if _, ok := lookup(token, "projected", "sources", 0, "serviceAccountToken", "audience"); ok {
		t.Fatal("the server token has an audience, so the API server would refuse it")
	}
	for _, c := range append(get[[]any](t, pod, "containers"), func() []any { l, _ := lookup(pod, "initContainers"); s, _ := l.([]any); return s }()...) {
		var paths []string
		for _, m := range get[[]any](t, c, "volumeMounts") {
			if get[string](t, m, "name") == "api-token" {
				paths = append(paths, get[string](t, m, "mountPath"))
			}
		}
		want := []string(nil)
		if get[string](t, c, "name") == "spire-server" {
			want = []string{"/var/run/secrets/kubernetes.io/serviceaccount"}
		}
		if !slices.Equal(paths, want) {
			t.Fatalf("%s mounts api-token at %v, want %v", get[string](t, c, "name"), paths, want)
		}
	}

	// Flow N8: each local workload pod reaches the server API. Flow N9: the server reaches the API server.
	np := objs["NetworkPolicy/spire-server-workloads"]
	if get[string](t, np, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name") != "spire-server" {
		t.Fatalf("workload policy selects %v", get[map[string]any](t, np, "spec", "podSelector"))
	}
	ingress := get[[]any](t, np, "spec", "ingress")
	if len(ingress) != 1 || !slices.Equal(get[[]any](t, np, "spec", "policyTypes"), []any{"Ingress"}) {
		t.Fatalf("workload policy spec is %v", np["spec"])
	}
	var peers, wantPeers []string
	for _, p := range get[[]any](t, ingress[0], "from") {
		if len(p.(map[string]any)) != 2 {
			t.Fatalf("peer %v needs exactly a namespace and a pod selector", p)
		}
		peers = append(peers, get[string](t, p, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")+"/"+
			get[string](t, p, "podSelector", "matchLabels", "app.kubernetes.io/name"))
	}
	for _, sub := range workloads {
		wantPeers = append(wantPeers, sub)
	}
	slices.Sort(peers)
	slices.Sort(wantPeers)
	if !slices.Equal(peers, slices.Compact(wantPeers)) {
		t.Fatalf("workload peers are %v, want %v", peers, wantPeers)
	}
	if ports := get[[]any](t, ingress[0], "ports"); len(ports) != 1 || get[float64](t, ports[0], "port") != 8081 {
		t.Fatalf("workload ports are %v", ports)
	}
	api := objs["NetworkPolicy/spire-server-api"]
	if !slices.Equal(get[[]any](t, api, "spec", "policyTypes"), []any{"Egress"}) ||
		get[string](t, api, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name") != "spire-server" {
		t.Fatalf("API policy spec is %v", api["spec"])
	}
	var egress []string
	for _, rule := range get[[]any](t, api, "spec", "egress") {
		var to []string
		for _, p := range get[[]any](t, rule, "to") {
			to = append(to, get[string](t, p, "ipBlock", "cidr"))
		}
		var ports []string
		for _, p := range get[[]any](t, rule, "ports") {
			ports = append(ports, fmt.Sprintf("%s/%v", get[string](t, p, "protocol"), get[float64](t, p, "port")))
		}
		egress = append(egress, strings.Join(to, ",")+" "+strings.Join(ports, ","))
	}
	if want := []string{"172.18.0.4/32 TCP/6443", "10.111.0.1/32 TCP/443"}; !slices.Equal(egress, want) {
		t.Fatalf("API egress is %v, want %v", egress, want)
	}

	data := get[map[string]any](t, objs["ConfigMap/spire-entries"], "data")
	for path, sub := range workloads {
		ns, sa, _ := strings.Cut(sub, "/")
		alias := "spiffe://" + td + "/agents/" + ns + "/" + sa
		for file, want := range map[string]entrySpec{
			"agents-" + ns + "-" + sa + ".yaml": {alias, "spiffe://" + td + "/spire/server",
				[]string{"k8s_psat:cluster:" + cluster, "k8s_psat:agent_ns:" + ns, "k8s_psat:agent_sa:" + sa}},
			"workload-" + strings.ReplaceAll(path, "/", "-") + ".yaml": {"spiffe://" + td + "/" + path, alias, []string{"unix:uid:65532"}},
		} {
			var got struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Metadata   struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Spec entrySpec `json:"spec"`
			}
			text, ok := data[file].(string)
			if !ok {
				t.Fatalf("spire-entries has no %s; keys %v", file, keysOf(data))
			}
			if err := yaml.UnmarshalStrict([]byte(text), &got); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			if got.Kind != "ClusterStaticEntry" || got.Metadata.Name+".yaml" != file || got.Spec.SPIFFEID != want.SPIFFEID ||
				got.Spec.ParentID != want.ParentID || !slices.Equal(got.Spec.Selectors, want.Selectors) {
				t.Fatalf("%s is %+v, want spec %+v", file, got, want)
			}
		}
	}
}

// managementWorkloads are the plane workloads of cells/management.env.
var managementWorkloads = map[string]string{
	"argocd/principal": "central-view-system/argocd-agent-principal",
	"telemetry":        "observability-system/telemetry-gateway",
	"kiali":            "mesh-view-system/mesh-view-hub",
	"api":              "mgmt-system/mgmtd",
}

// TestSpireServerRenderManagement renders the management plane server with cells/management.env.
// It has its own CA with no upstream authority, admits only its local workloads, and needs nothing
// from a cell, the host service or the secret manager.
func TestSpireServerRenderManagement(t *testing.T) {
	r := renderCell(t, "management")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	if left := regexp.MustCompile(`@[A-Z_]+@`).FindAllString(r.stdout, -1); slices.ContainsFunc(left, func(s string) bool { return s != "@CELL_NAME@" }) {
		t.Fatalf("render left tokens %v", left)
	}
	if strings.TrimSpace(r.log) != "" {
		t.Fatalf("the render ran host commands; want no image fetch, record or host service call:\n%s", r.log)
	}
	objs := docs(t, hydrated(r.stdout, "management"))
	checkPSAT(t, objs, "management", "mgmt.poc.internal", managementWorkloads)

	var kinds []string
	for k := range objs {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	want := []string{"ClusterRole/spire-server-psat", "ClusterRoleBinding/spire-server-psat", "ConfigMap/spire-controller-manager",
		"ConfigMap/spire-entries", "ConfigMap/spire-server", "Namespace/spire-system", "NetworkPolicy/default-deny",
		"NetworkPolicy/spire-server-api", "NetworkPolicy/spire-server-metrics", "NetworkPolicy/spire-server-workloads", "Service/spire-server",
		"ServiceAccount/spire-server", "StatefulSet/spire-server"}
	if !slices.Equal(kinds, want) {
		t.Fatalf("objects are %v, want %v: no ExternalSecret, no record and no agent node policy", kinds, want)
	}

	t.Run("the bundle holds Namespace spire-system, never pruned", func(t *testing.T) {
		ns := objs["Namespace/spire-system"]
		labels := get[map[string]any](t, ns, "metadata", "labels")
		if labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["istio-injection"] != "disabled" {
			t.Fatalf("namespace labels are %v", labels)
		}
		if got := get[string](t, ns, "metadata", "annotations", "argocd.argoproj.io/sync-options"); got != "Prune=false,Delete=false" {
			t.Fatalf("sync options are %q", got)
		}
	})

	t.Run("server config", func(t *testing.T) {
		text := get[string](t, objs["ConfigMap/spire-server"], "data", "server.conf")
		var conf struct {
			Server struct {
				TrustDomain string `hcl:"trust_domain"`
				CATTL       string `hcl:"ca_ttl"`
				AgentTTL    string `hcl:"agent_ttl"`
				X509TTL     string `hcl:"default_x509_svid_ttl"`
				LogFormat   string `hcl:"log_format"`
			} `hcl:"server"`
		}
		if err := hcl.Decode(&conf, text); err != nil {
			t.Fatalf("server.conf does not parse: %v", err)
		}
		if s := conf.Server; s.TrustDomain != "mgmt.poc.internal" || s.CATTL != "2160h" || s.AgentTTL != "1h" || s.X509TTL != "1h" || s.LogFormat != "json" {
			t.Fatalf("server block is %+v", s)
		}
		checkPrometheus(t, text)
		for _, unwanted := range []string{"UpstreamAuthority", `NodeAttestor "cluster_jwt"`, `KeyManager "memory"`, "record_public_keys"} {
			if strings.Contains(text, unwanted) {
				t.Fatalf("server.conf holds %q:\n%s", unwanted, text)
			}
		}
		// A restart keeps the CA key, so every peer copy of the root stays valid.
		if !regexp.MustCompile(`(?s)KeyManager "disk" \{\s*plugin_data \{\s*keys_path = "/run/spire/data/keys\.json"\s*\}`).MatchString(text) {
			t.Fatalf("server.conf has no disk KeyManager on the data volume:\n%s", text)
		}
	})

	t.Run("controller manager config", func(t *testing.T) {
		var cm map[string]any
		if err := yaml.Unmarshal([]byte(get[string](t, objs["ConfigMap/spire-controller-manager"], "data", "config.yaml")), &cm); err != nil {
			t.Fatal(err)
		}
		if cm["trustDomain"] != "mgmt.poc.internal" || cm["clusterName"] != "management" {
			t.Fatalf("config is %v", cm)
		}
	})

	t.Run("statefulset runs only the server and the controller manager", func(t *testing.T) {
		pod := get[map[string]any](t, objs["StatefulSet/spire-server"], "spec", "template", "spec")
		if _, ok := pod["initContainers"]; ok {
			t.Fatal("the pod has an init container")
		}
		var volumes []string
		for _, v := range get[[]any](t, pod, "volumes") {
			volumes = append(volumes, get[string](t, v, "name"))
			if name, ok := lookup(v, "configMap", "name"); ok {
				if _, found := objs["ConfigMap/"+name.(string)]; !found {
					t.Fatalf("volume uses ConfigMap %v, which the render does not print", name)
				}
			}
		}
		for _, unwanted := range []string{"upstream", "records", "plugins"} {
			if slices.Contains(volumes, unwanted) {
				t.Fatalf("volumes %v hold %s", volumes, unwanted)
			}
		}
		for _, claim := range get[[]any](t, objs["StatefulSet/spire-server"], "spec", "volumeClaimTemplates") {
			volumes = append(volumes, get[string](t, claim, "metadata", "name"))
		}
		for _, c := range get[[]any](t, pod, "containers") {
			for _, m := range get[[]any](t, c, "volumeMounts") {
				if !slices.Contains(volumes, get[string](t, m, "name")) {
					t.Fatalf("%s mounts %s, which the pod does not have", get[string](t, c, "name"), get[string](t, m, "name"))
				}
			}
		}
		if claims := get[[]any](t, objs["StatefulSet/spire-server"], "spec", "volumeClaimTemplates"); len(claims) != 1 || get[string](t, claims[0], "metadata", "name") != "data" {
			t.Fatalf("volume claims are %v", claims)
		}
	})

	t.Run("agents reach the server only through its ClusterIP service", func(t *testing.T) {
		svc := objs["Service/spire-server"]
		spec := get[map[string]any](t, svc, "spec")
		ports := get[[]any](t, spec, "ports")
		if typ, _ := spec["type"].(string); (typ != "" && typ != "ClusterIP") || len(ports) != 1 || get[float64](t, ports[0], "port") != 8081 {
			t.Fatalf("service spec is %v", spec)
		}
		if _, ok := lookup(ports[0], "nodePort"); ok {
			t.Fatal("the service has a node port")
		}
		if _, ok := spec["externalTrafficPolicy"]; ok {
			t.Fatal("a ClusterIP service sets externalTrafficPolicy")
		}
	})
}

// TestSpireServerHintConfig: the server of dev-cp, which has agent cells and local workloads, sets hint_configmap to
// spire-system/attest-hints in the cluster_jwt plugin, and a Role that reads and patches that one ConfigMap and nothing
// else, with its RoleBinding for the server account. A server that has agent cells but no local workload has no API token,
// so it gets no hint line and no Role. A server with no agent cell has no cluster_jwt plugin.
func TestSpireServerHintConfig(t *testing.T) {
	r := renderCell(t, "dev-cp")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docs(t, hydrated(r.stdout, "dev-cp"))
	var top map[string]any
	if err := hcl.Decode(&top, get[string](t, objs["ConfigMap/spire-server"], "data", "server.conf")); err != nil {
		t.Fatalf("server.conf does not parse: %v", err)
	}
	if got := hclAt(t, top, "plugins", "NodeAttestor", "cluster_jwt", "plugin_data", "hint_configmap"); got != "spire-system/attest-hints" {
		t.Errorf("hint_configmap is %v, want spire-system/attest-hints", got)
	}
	role := objs["Role/spire-server-hints"]
	if role == nil {
		t.Fatal("the render has no Role spire-server-hints")
	}
	if get[string](t, role, "metadata", "namespace") != "spire-system" {
		t.Errorf("Role namespace is %v, want spire-system", get[string](t, role, "metadata", "namespace"))
	}
	rules := get[[]any](t, role, "rules")
	if len(rules) != 1 {
		t.Fatalf("Role spire-server-hints has %d rules, want 1: %v", len(rules), rules)
	}
	rule := rules[0]
	if !slices.Equal(get[[]any](t, rule, "apiGroups"), []any{""}) || !slices.Equal(get[[]any](t, rule, "resources"), []any{"configmaps"}) ||
		!slices.Equal(get[[]any](t, rule, "resourceNames"), []any{"attest-hints"}) || !slices.Equal(get[[]any](t, rule, "verbs"), []any{"get", "patch"}) {
		t.Errorf("the rule is %v, want configmaps named attest-hints with only get and patch", rule)
	}
	binding := objs["RoleBinding/spire-server-hints"]
	if binding == nil || get[string](t, binding, "roleRef", "kind") != "Role" || get[string](t, binding, "roleRef", "name") != "spire-server-hints" ||
		get[string](t, binding, "subjects", 0, "kind") != "ServiceAccount" || get[string](t, binding, "subjects", 0, "name") != "spire-server" ||
		get[string](t, binding, "subjects", 0, "namespace") != "spire-system" {
		t.Errorf("RoleBinding is %v, want Role spire-server-hints for ServiceAccount spire-system/spire-server", binding)
	}

	t.Run("agent cells without a local workload", func(t *testing.T) {
		r := render(t, "SPIRE_AGENT_CELLS=dev-cell-1")
		if r.err != nil {
			t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
		}
		if strings.Contains(r.stdout, "hint_configmap") || strings.Contains(r.stdout, "spire-server-hints") {
			t.Errorf("a server with no API token has a hint line or a hint Role:\n%s", r.stdout)
		}
	})
}

// liveEnv sets the clusters that kind lists. STUB_NO_NODE_IP and the rest of the stubs then decide which of the
// topology cells are live.
func liveEnv(clusters string) string { return "STUB_KIND_CLUSTERS=" + clusters }

// agentPolicyRules returns the ingress rules of NetworkPolicy spire-server-agents, or nil when the render has none.
func agentPolicyRules(t *testing.T, objs map[string]object) []any {
	t.Helper()
	np, ok := objs["NetworkPolicy/spire-server-agents"]
	if !ok {
		return nil
	}
	return get[[]any](t, np, "spec", "ingress")
}

// TestSpireServerRenderNoLiveCells: dev-cp with a catalog of two cells and no cluster for either of them. The render
// succeeds with no cell fact, drops the cluster_jwt section and the policy of the agent node port, and keeps the
// ClusterStaticEntry pairs of both cells.
func TestSpireServerRenderNoLiveCells(t *testing.T) {
	r := renderCell(t, "dev-cp", liveEnv("management dev-cp rogue"))
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docs(t, hydrated(r.stdout, "dev-cp"))
	conf := get[string](t, objs["ConfigMap/spire-server"], "data", "server.conf")
	if strings.Contains(conf, `NodeAttestor "cluster_jwt"`) || strings.Contains(conf, "record_public_keys") {
		t.Errorf("server.conf holds the cluster_jwt section with no live cell:\n%s", conf)
	}
	for _, rule := range agentPolicyRules(t, objs) {
		t.Errorf("NetworkPolicy spire-server-agents has a rule with no live cell: %v", rule)
	}
	// No rule that names port 8081 may admit an ipBlock: only the local workloads reach the server.
	for key, o := range objs {
		if o["kind"] != "NetworkPolicy" {
			continue
		}
		ingress, _ := lookupOr(o, "spec", "ingress").([]any)
		for _, rule := range ingress {
			ports, _ := lookup(rule, "ports")
			from, _ := lookup(rule, "from")
			if !strings.Contains(fmt.Sprint(ports), "port:8081") {
				continue
			}
			for _, p := range from.([]any) {
				if _, isBlock := lookup(p, "ipBlock"); isBlock {
					t.Errorf("%s: a rule for port 8081 admits an ipBlock: %v", key, rule)
				}
			}
		}
	}
	entries := get[map[string]any](t, objs["ConfigMap/spire-entries"], "data")
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
		for _, role := range []string{"celld", "argocd-agent", "otel", "mesh-view"} {
			for _, name := range []string{cell + "-agents-" + role + ".yaml", cell + "-" + role + ".yaml"} {
				if _, ok := entries[name]; !ok {
					t.Errorf("spire-entries has no %s", name)
				}
			}
		}
	}
	for _, bad := range []string{"hostsvc -- facts --cluster dev-cell", "spire-server bundle show", "get configmap mgmt-signing-pub"} {
		if strings.Contains(r.log, bad) {
			t.Errorf("the render ran %q with no live cell:\n%s", bad, r.log)
		}
	}
	if _, ok := objs["ConfigMap/spire-entries"]; !ok {
		t.Error("no ConfigMap spire-entries")
	}
}

// TestSpireServerRenderOneLiveCell: dev-cell-1 is live and dev-cell-2 is not. The policy admits only the node of
// dev-cell-1, the facts of dev-cell-2 are never read, and the entries of both cells stay.
func TestSpireServerRenderOneLiveCell(t *testing.T) {
	r := renderCell(t, "dev-cp", liveEnv("management dev-cp rogue dev-cell-1"))
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := docs(t, hydrated(r.stdout, "dev-cp"))
	rules := agentPolicyRules(t, objs)
	if len(rules) != 1 || peerList(t, rules[0], "from") != "10.9.0.1/32" {
		t.Fatalf("agent policy rules %v, want one rule that admits 10.9.0.1/32", rules)
	}
	conf := get[string](t, objs["ConfigMap/spire-server"], "data", "server.conf")
	if !strings.Contains(conf, `NodeAttestor "cluster_jwt"`) {
		t.Error("server.conf lacks the cluster_jwt section with one live cell")
	}
	if strings.Contains(r.log, "facts --cluster dev-cell-2") {
		t.Errorf("the render read the facts of a cell that has no cluster:\n%s", r.log)
	}
	entries := get[map[string]any](t, objs["ConfigMap/spire-entries"], "data")
	for _, name := range []string{"dev-cell-1-celld.yaml", "dev-cell-2-celld.yaml", "dev-cell-1-agents-celld.yaml", "dev-cell-2-agents-celld.yaml"} {
		if _, ok := entries[name]; !ok {
			t.Errorf("spire-entries has no %s", name)
		}
	}
}

// TestSpireServerRenderNoNodeAddressIsNotLive: a cluster whose node container has no address on the network kind is
// not live, so the render leaves it out and does not read its facts.
func TestSpireServerRenderNoNodeAddressIsNotLive(t *testing.T) {
	r := renderCell(t, "dev-cp", "STUB_NO_NODE_IP=dev-cell-2")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	rules := agentPolicyRules(t, docs(t, hydrated(r.stdout, "dev-cp")))
	if len(rules) != 1 || peerList(t, rules[0], "from") != "10.9.0.1/32" {
		t.Fatalf("agent policy rules %v, want one rule that admits only dev-cell-1", rules)
	}
}
