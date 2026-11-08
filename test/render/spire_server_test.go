// Package render tests the component render scripts with stub host commands.
package render

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl"
	"sigs.k8s.io/yaml"
)

const (
	stubDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	stubLayer  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	stubBinary = "stub plugin binary"
)

// stubMise answers "mise run hostsvc -- facts" and "mise run record:fixture" for the cells below.
// The cell bad-facts fails the way hostsvc fails, and no-ip has no node address.
const stubMise = `#!/usr/bin/env bash
set -euo pipefail
echo "$*" >>"$STUB_LOG"
case "$2" in
  hostsvc)
    cell="$6"
    case "$cell" in
      dev-cell-1) echo '{"name":"dev-cell-1","nodeIP":"10.9.0.1"}' ;;
      dev-cell-2) echo '{"name":"dev-cell-2","nodeIP":"10.9.0.2"}' ;;
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
  *) exit 2 ;;
esac
`

// stubOras serves one image from the local registry, unless STUB_NO_IMAGE is set.
const stubOras = `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  resolve) [[ -z "${STUB_NO_IMAGE:-}" ]] || exit 1; echo "` + stubDigest + `" ;;
  manifest) echo '{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{"digest":"sha256:0000"},{"digest":"` + stubLayer + `"}]}' ;;
  blob) cat "$STUB_LAYER_FILE" ;;
  *) exit 2 ;;
esac
`

type result struct {
	stdout, stderr string
	err            error
	log            string
}

func render(t *testing.T, env ...string) result {
	t.Helper()
	for _, tool := range []string{"yq", "jq", "tar", "bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH; run the test through mise run test", tool)
		}
	}
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("mise", stubMise, 0o755)
	write("oras", stubOras, 0o755)
	layer := write("layer.tar.gz", string(layerTarGz(t)), 0o644)
	logFile := filepath.Join(dir, "mise.log")

	script, err := filepath.Abs("../../components/spire-server/render.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script)
	cmd.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+logFile, "STUB_LAYER_FILE="+layer,
		"SPIRE_AGENT_SUBJECT=spire-system/spire-agent")
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	logData, _ := os.ReadFile(logFile)
	return result{stdout.String(), stderr.String(), err, string(logData)}
}

func layerTarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "ko-app", Typeflag: tar.TypeDir, Mode: 0o555}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "/ko-app/cluster-jwt-server", Mode: 0o555, Size: int64(len(stubBinary))}); err != nil {
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
		if ns, _ := lookup(o, "metadata", "namespace"); key != "Namespace/spire-system" && ns != "spire-system" {
			t.Fatalf("%s has namespace %v, want spire-system", key, ns)
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
	for _, want := range []string{"run hostsvc -- facts --cluster dev-cell-1", "run record:fixture -- --cluster dev-cell-2 --subject spire-system/spire-agent"} {
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
		if got := get[string](t, containers[0], "image"); got != "localhost:5001/cluster-jwt-server@"+stubDigest {
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

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
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
		{"no plugin image", []string{"SPIRE_AGENT_CELLS=dev-cell-1", "STUB_NO_IMAGE=1"}, "mise run images"},
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
