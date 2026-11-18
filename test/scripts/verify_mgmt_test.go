package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// verifyKubectl answers the reads of the six mgmt-api checks of cell:verify from files in $STUB_DIR. A case changes
// one file.
const verifyKubectl = `#!/usr/bin/env bash
d="$STUB_DIR"
case " $* " in
  *" --context kind-management "*" exec spire-server-0 "*) cat "$d/mgmt-root.pem" ;;
  *" --context kind-dev-cp "*" exec spire-server-0 "*) cat "$d/cp-root.pem" ;;
  *" get configmap mgmt-signing-pub "*) cat "$d/signing-pub.json" ;;
  *" get configmap hostsvc-pin "*) printf '%s' "$(cat "$d/cm-pin.pem")" ;;
  *" get pod mgmtd-0 "*) printf '%s' "$(cat "$d/pod-pin-annotation")" ;;
  *" get networkpolicy mgmtd "*) cat "$d/policy.json" ;;
  *" get statefulset mgmtd "*) cat "$d/sts.json" ;;
  *" get configmap peer-root "*) printf '%s' "$(cat "$d/cm-peer-root.pem")" ;;
  *" get pods -l app.kubernetes.io/name=mgmtd "*) cat "$d/pods.json" ;;
  *" get configmap cell-registry "*) [ "$(cat "$d/registry.json")" = ABSENT ] && { echo "Error from server (NotFound): configmaps cell-registry not found" >&2; exit 1; }; cat "$d/registry.json" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const verifyMise = `#!/usr/bin/env bash
case "$1 $2 $3 $4" in
  "run pki -- trust-bundle") cat ;;
  "run mgmt -- records") cat "$STUB_DIR/records.json" ;;
  "run hostsvc -- facts") printf '{"name":"dev-cp","nodeIP":"%s"}\n' "$(cat "$STUB_DIR/cp-node-ip")" ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

const verifyKind = `#!/usr/bin/env bash
cat "$STUB_DIR/kind-clusters"
`

const verifyServe = `#!/usr/bin/env bash
d="$STUB_DIR"
case "$1" in
  status) printf '{"running":true,"pid":1,"cert_sha256":"%s","root_sha256":"%s","expires_soon":false,"last_error":""}\n' "$(cat "$d/serve-cert-sha")" "$(cat "$d/serve-root-sha")" ;;
  pin) cat "$d/live-pin.pem" ;;
  *) exit 2 ;;
esac
`

// TestVerifyMgmtChecks runs each of the six mgmt-api checks of cell:verify with fakes: once on a healthy state, and
// once for each mismatch. A mismatch prints its reason and the repair command.
func TestVerifyMgmtChecks(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash", "base64", "shasum")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	stub := filepath.Join(root, "stub")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"bin/kubectl": verifyKubectl, "bin/mise": verifyMise, "bin/kind": verifyKind, "bin/docker": `#!/usr/bin/env bash
printf '%b' "$(cat "$STUB_DIR/getent")"
`, "stub/serve": verifyServe} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pinPEM, otherPin := caPEM(t, 10), caPEM(t, 11)
	mgmtRoot, cpRoot, otherRoot := caPEM(t, 1), caPEM(t, 2), caPEM(t, 3)
	block, _ := pem.Decode([]byte(pinPEM))
	pinSum := sha256.Sum256(block.Bytes)
	pinSHA := hex.EncodeToString(pinSum[:])
	cpSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimRight(cpRoot, "\n"))))
	policy := func(host, cp string) string {
		return fmt.Sprintf(`{"spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"%s/32"}}],"ports":[{"port":8446}]},{"from":[{"ipBlock":{"cidr":"172.18.0.4/32"}}],"ports":[{"port":8080}]}],
"egress":[{"to":[{"ipBlock":{"cidr":"%s/32"}}],"ports":[{"port":17443}]}]}}`, cp, host)
	}
	sts := func(host string) string {
		return fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":"mgmtd","args":["serve","--hostsvc-addr=%s:17443"]}]}}}}`, host)
	}
	pods := func(sha string) string {
		return fmt.Sprintf(`{"items":[{"metadata":{"name":"mgmtd-0","annotations":{"poc.internal/peer-root-sha256":"%s"}}}]}`, sha)
	}
	// registry is ConfigMap cell-registry with the record of dev-cell-1 as given and one of dev-cell-2. The stored JSON has
	// other spacing than the served one, so only a compact comparison finds them equal.
	const signingKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	registry := func(cell1 string, labels map[string]string, signers string) string {
		b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": labels}, "data": map[string]string{"dev-cell-1.dsse.json": cell1,
			"dev-cell-2.dsse.json": `{ "payload": "counter2", "signatures": [1] }`, "signers.pub": signers}})
		return string(b)
	}
	madeBy := map[string]string{"poc.internal/made-by": "mgmtd"}
	healthy := map[string]string{
		"mgmt-root.pem": mgmtRoot, "cp-root.pem": cpRoot, "cm-pin.pem": pinPEM, "live-pin.pem": pinPEM, "pod-pin-annotation": pinSHA,
		"serve-cert-sha": pinSHA, "serve-root-sha": goRootSHA(t, mgmtRoot), "policy.json": policy("192.168.5.2", "10.9.0.9"),
		"sts.json": sts("192.168.5.2"), "getent": `192.168.5.2 STREAM host.docker.internal\n`, "cp-node-ip": "10.9.0.9",
		"kind-clusters": "management\ndev-cp\ndev-cell-1\ndev-cell-2\nrogue\n", "cm-peer-root.pem": cpRoot, "pods.json": pods(cpSHA),
		"records.json":     `{"dev-cell-1":{"payload":"counter7","signatures":[1]},"dev-cell-2":{"payload":"counter2","signatures":[1]}}`,
		"registry.json":    registry(`{"payload":"counter7", "signatures":[1]}`, madeBy, signingKey+"\n"),
		"signing-pub.json": `{"data":{"spec.pub":"` + signingKey + `"}}`,
	}
	registryNext := "mise run mgmt -- status"
	restart := "mise run hostsvc:serve -- restart"
	link := "CELL=management mise run cell:link"
	for _, tc := range []struct {
		name, check string
		change      map[string]string
		want        []string
	}{
		{"pin ok", "check_mgmt_hostsvc_pin", nil, nil},
		{"pin: ConfigMap differs", "check_mgmt_hostsvc_pin", map[string]string{"cm-pin.pem": otherPin}, []string{"holds another certificate", restart}},
		{"pin: pod digest differs", "check_mgmt_hostsvc_pin", map[string]string{"pod-pin-annotation": strings.Repeat("0", 64)}, []string{"carries the pin digest", restart}},
		{"root ok", "check_mgmt_hostsvc_root", nil, nil},
		{"root: the service trusts an old root", "check_mgmt_hostsvc_root", map[string]string{"serve-root-sha": goRootSHA(t, otherRoot)}, []string{"trusts the management root", restart}},
		{"address ok", "check_mgmt_hostsvc_address", nil, nil},
		{"address: the node resolves another address", "check_mgmt_hostsvc_address", map[string]string{"getent": `192.168.5.3 STREAM host.docker.internal\n`},
			[]string{"host.docker.internal is 192.168.5.3", link}},
		{"address: the policy admits another address", "check_mgmt_hostsvc_address", map[string]string{"policy.json": policy("192.168.5.9", "10.9.0.9")}, []string{"the policy admits", link}},
		{"address: mgmtd runs another argument", "check_mgmt_hostsvc_address", map[string]string{"sts.json": sts("192.168.5.9")}, []string{"mgmtd runs", link}},
		{"env address ok", "check_mgmt_env_address", nil, nil},
		{"env address: dev-cp has a new node address", "check_mgmt_env_address", map[string]string{"cp-node-ip": "10.9.0.77"}, []string{"the dev-cp node is 10.9.0.77", link}},
		{"env address: no dev-cp and no rule", "check_mgmt_env_address", map[string]string{"kind-clusters": "management\n",
			"policy.json": `{"spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"172.18.0.4/32"}}],"ports":[{"port":8080}]}],"egress":[]}}`}, nil},
		{"env address: no dev-cp but a rule", "check_mgmt_env_address", map[string]string{"kind-clusters": "management\n"}, []string{"does not exist, but the API port admits", link}},
		{"peer root ok", "check_mgmt_peer_root", nil, nil},
		{"peer root: dev-cp has a new root", "check_mgmt_peer_root", map[string]string{"cp-root.pem": otherRoot}, []string{"absent or holds other roots", link}},
		{"peer root: a pod holds an old root", "check_mgmt_peer_root", map[string]string{"pods.json": pods(strings.Repeat("0", 64))}, []string{"carries the root digest", link}},
		{"peer root: the ConfigMap is absent", "check_mgmt_peer_root", map[string]string{"cm-peer-root.pem": ""}, []string{"absent or holds other roots", link}},
		{"registry ok", "check_registry_published central-view-system", nil, nil},
		{"registry: a signed registry with no record, as mgmtd publishes after the last cell drops", "check_registry_published central-view-system",
			map[string]string{"records.json": `{}`, "registry.json": `{"metadata":{"labels":{"poc.internal/made-by":"mgmtd"}},"data":{"signers.pub":"` + signingKey + `\n"}}`}, nil},
		{"registry: no record held, and mgmtd serves one", "check_registry_published central-view-system",
			map[string]string{"registry.json": `{"metadata":{"labels":{"poc.internal/made-by":"mgmtd"}},"data":{"signers.pub":"` + signingKey + `\n"}}`}, []string{"has another record than mgmtd serves, or none", registryNext}},
		{"registry: a record is older than the one mgmtd serves", "check_registry_published central-view-system",
			map[string]string{"registry.json": registry(`{"payload":"counter1","signatures":[1]}`, madeBy, signingKey+"\n")}, []string{"dev-cell-1 has another record than mgmtd serves", registryNext, "logs mgmtd-0"}},
		{"registry: a record of a cell that mgmtd does not serve", "check_registry_published central-view-system",
			map[string]string{"records.json": `{"dev-cell-1":{"payload":"counter7","signatures":[1]}}`}, []string{"holds the record dev-cell-2, which mgmtd does not serve", registryNext}},
		{"registry: a harness label is still on the object", "check_registry_published central-view-system",
			map[string]string{"registry.json": registry(`{"payload":"counter7", "signatures":[1]}`, map[string]string{"poc.internal/made-by": "mgmtd", "cell.poc.internal/harness": "central-view"}, signingKey+"\n")},
			[]string{"has the labels", "cell.poc.internal/harness", registryNext}},
		{"registry: no made-by label", "check_registry_published central-view-system",
			map[string]string{"registry.json": registry(`{"payload":"counter7", "signatures":[1]}`, nil, signingKey+"\n")}, []string{"has the labels", registryNext}},
		{"registry: another signing key", "check_registry_published central-view-system",
			map[string]string{"registry.json": registry(`{"payload":"counter7", "signatures":[1]}`, madeBy, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n")}, []string{"signers.pub of central-view-system/cell-registry", registryNext}},
		{"registry: the ConfigMap is absent", "check_registry_published central-view-system",
			map[string]string{"registry.json": "ABSENT"}, []string{"could not read ConfigMap central-view-system/cell-registry", registryNext}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range healthy {
				files[k] = v
			}
			for k, v := range tc.change {
				files[k] = v
			}
			for k, v := range files {
				if err := os.WriteFile(filepath.Join(stub, k), []byte(v), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; source "$1/components/lib/peer-root.sh"; source "$1/components/lib/hostsvc-pin.sh"
source "$1/components/lib/mgmt-key.sh"; source "$1/scripts/verify-lib.sh"; set +e; `+tc.check, "_", root)
			cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=management",
				"POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_DIR=" + stub, "MGMT_KEY_ACCEPT_CHANGE=1", "REGISTRY_PUBLISHED_WAIT=0", "HOSTSVC_SERVE=" + filepath.Join(stub, "serve")}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("the check fails on a healthy state: %v\n%s", err, out.String())
				}
				return
			}
			if err == nil {
				t.Fatalf("the check passes though %s", tc.name)
			}
			for _, w := range tc.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output %q lacks %q", out.String(), w)
				}
			}
		})
	}
}

// TestGateM4PreCheck: gate.sh m4 runs the repair check and compares the images of the workloads that the M4 tests use:
// mgmtd, envd, the SPIRE server of dev-cp (with its plugin) and celld in each cell (with the agent plugin). It stops
// before the tests on a drift or on a stale image, and names the command that brings the workload up to date.
func TestGateM4PreCheck(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, stale string
		repairFails bool
		want        string
	}{
		{name: "healthy"},
		{name: "a stale mgmtd", stale: "mgmtd", want: "Run: mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
		{name: "a stale envd", stale: "envd", want: "Run: mise run images -- envd, then CELL=dev-cp mise run cell:up"},
		{name: "a stale SPIRE server plugin", stale: "cluster-jwt-server", want: "Run: mise run images -- cluster-jwt-server, then CELL=dev-cp mise run cell:up"},
		{name: "a stale celld in the second cell", stale: "celld@dev-cell-2", want: "Run: mise run images -- celld cluster-jwt-agent, then CELL=dev-cell-2 mise run cell:up"},
		{name: "a stale agent plugin", stale: "cluster-jwt-agent@dev-cell-1", want: "Run: mise run images -- celld cluster-jwt-agent, then CELL=dev-cell-1 mise run cell:up"},
		{name: "a drift", repairFails: true, want: "drift reported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
				copyFiles(t, root, d)
			}
			write := func(path, body string) {
				p := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			ref := func(name, c string) string { return "localhost:5001/" + name + "@sha256:" + strings.Repeat(c, 64) }
			var env strings.Builder
			for _, n := range []string{"mgmtd", "envd", "celld", "cluster-jwt-server", "cluster-jwt-agent"} {
				fmt.Fprintf(&env, "IMAGE_%s=%s\n", strings.ToUpper(strings.ReplaceAll(n, "-", "_")), ref(n, "a"))
			}
			write("build/images.env", env.String())
			for _, cluster := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
				write("build/"+cluster+"/facts.env", "")
			}
			repair := "exit 0"
			if tc.repairFails {
				repair = "echo 'drift reported'; exit 1"
			}
			write("scripts/gate-m4-repair.sh", "#!/usr/bin/env bash\n"+repair+"\n")
			write("bin/go", "#!/usr/bin/env bash\necho \"go $*\" >>\"$STUB_LOG\"\n")
			writeLiveStubs(t, filepath.Join(root, "bin"))
			// The fake answers "get <workload> -o json" for the cluster in --context. Each workload runs the images that
			// build/images.env records, except the one that STUB_STALE names, as <image> or <image>@<cluster>.
			write("bin/kubectl", `#!/usr/bin/env bash
cluster="${2#kind-}"
img() { # img <name> prints the reference that the workload runs
  local c=a
  [[ "$STUB_STALE" == "$1" || "$STUB_STALE" == "$1@$cluster" ]] && c=b
  printf 'localhost:5001/%s@sha256:%s' "$1" "$(printf "$c%.0s" $(seq 64))"
}
case " $* " in
  *" get statefulset/mgmtd "*) printf '{"spec":{"template":{"spec":{"containers":[{"name":"mgmtd","image":"%s"}]}}}}\n' "$(img mgmtd)" ;;
  *" get deployment/envd "*) printf '{"spec":{"template":{"spec":{"containers":[{"name":"envd","image":"%s"}]}}}}\n' "$(img envd)" ;;
  *" get statefulset/spire-server "*) printf '{"spec":{"template":{"spec":{"initContainers":[{"name":"install-plugin","image":"%s"}],"containers":[{"name":"spire-server","image":"ghcr.io/spiffe/spire-server:1"}]}}}}\n' "$(img cluster-jwt-server)" ;;
  *" get deployment/celld "*) printf '{"spec":{"template":{"spec":{"initContainers":[{"name":"install-agent-plugin","image":"%s"}],"containers":[{"name":"celld","image":"%s"}]}}}}\n' "$(img cluster-jwt-agent)" "$(img celld)" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`)
			cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), "m4")
			cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_STALE=" + tc.stale}
			out, err := cmd.CombinedOutput()
			calls, _ := os.ReadFile(filepath.Join(root, "calls"))
			ran := strings.Contains(string(calls), "-run M4")
			if tc.want == "" {
				if err != nil || !ran {
					t.Fatalf("err %v, ran %v, output %s\ncalls %s", err, ran, out, calls)
				}
				return
			}
			if err == nil || ran || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err %v, tests ran %v, output %s; want a stop before the tests that says %q", err, ran, out, tc.want)
			}
		})
	}
}
