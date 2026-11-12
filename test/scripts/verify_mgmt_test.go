package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
  *" get configmap hostsvc-pin "*) printf '%s' "$(cat "$d/cm-pin.pem")" ;;
  *" get pod mgmtd-0 "*) printf '%s' "$(cat "$d/pod-pin-annotation")" ;;
  *" get networkpolicy mgmtd "*) cat "$d/policy.json" ;;
  *" get statefulset mgmtd "*) cat "$d/sts.json" ;;
  *" get configmap peer-root "*) printf '%s' "$(cat "$d/cm-peer-root.pem")" ;;
  *" get pods -l app.kubernetes.io/name=mgmtd "*) cat "$d/pods.json" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const verifyMise = `#!/usr/bin/env bash
case "$1 $2 $3 $4" in
  "run pki -- trust-bundle") cat ;;
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
		return fmt.Sprintf(`{"spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"%s/32"}}],"ports":[{"port":8446},{"port":8447}]},{"from":[{"ipBlock":{"cidr":"172.18.0.4/32"}}],"ports":[{"port":8080}]}],
"egress":[{"to":[{"ipBlock":{"cidr":"%s/32"}}],"ports":[{"port":17443}]}]}}`, cp, host)
	}
	sts := func(host string) string {
		return fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":"mgmtd","args":["serve","--hostsvc-addr=%s:17443"]}]}}}}`, host)
	}
	pods := func(sha string) string {
		return fmt.Sprintf(`{"items":[{"metadata":{"name":"mgmtd-0","annotations":{"poc.internal/peer-root-sha256":"%s"}}}]}`, sha)
	}
	healthy := map[string]string{
		"mgmt-root.pem": mgmtRoot, "cp-root.pem": cpRoot, "cm-pin.pem": pinPEM, "live-pin.pem": pinPEM, "pod-pin-annotation": pinSHA,
		"serve-cert-sha": pinSHA, "serve-root-sha": goRootSHA(t, mgmtRoot), "policy.json": policy("192.168.5.2", "10.9.0.9"),
		"sts.json": sts("192.168.5.2"), "getent": `192.168.5.2 STREAM host.docker.internal\n`, "cp-node-ip": "10.9.0.9",
		"kind-clusters": "management\ndev-cp\ndev-cell-1\ndev-cell-2\nrogue\n", "cm-peer-root.pem": cpRoot, "pods.json": pods(cpSHA),
	}
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
		{"env address: no dev-cp but a rule", "check_mgmt_env_address", map[string]string{"kind-clusters": "management\n"}, []string{"does not exist, but the API and bind ports admit", link}},
		{"peer root ok", "check_mgmt_peer_root", nil, nil},
		{"peer root: dev-cp has a new root", "check_mgmt_peer_root", map[string]string{"cp-root.pem": otherRoot}, []string{"absent or holds other roots", link}},
		{"peer root: a pod holds an old root", "check_mgmt_peer_root", map[string]string{"pods.json": pods(strings.Repeat("0", 64))}, []string{"carries the root digest", link}},
		{"peer root: the ConfigMap is absent", "check_mgmt_peer_root", map[string]string{"cm-peer-root.pem": ""}, []string{"absent or holds other roots", link}},
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
				"POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_DIR=" + stub, "HOSTSVC_SERVE=" + filepath.Join(stub, "serve")}
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

// TestGateM4PreCheck: gate.sh m4 runs the repair check and compares the image of statefulset mgmtd only. It stops
// before the tests on a drift or a stale image.
func TestGateM4PreCheck(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, image string
		repairFails bool
		want        string
	}{
		{name: "healthy", image: "good"},
		{name: "a stale image", image: "stale", want: "Run: mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
		{name: "a drift", image: "good", repairFails: true, want: "drift reported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range []string{"scripts", "cells", "harness"} {
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
			good := "localhost:5001/mgmtd@sha256:" + strings.Repeat("a", 64)
			stale := "localhost:5001/mgmtd@sha256:" + strings.Repeat("b", 64)
			running := good
			if tc.image == "stale" {
				running = stale
			}
			write("build/images.env", "IMAGE_MGMTD="+good+"\n")
			repair := "exit 0"
			if tc.repairFails {
				repair = "echo 'drift reported'; exit 1"
			}
			write("scripts/gate-m4-repair.sh", "#!/usr/bin/env bash\n"+repair+"\n")
			write("bin/go", "#!/usr/bin/env bash\necho \"go $*\" >>\"$STUB_LOG\"\n")
			write("bin/kubectl", `#!/usr/bin/env bash
printf '{"spec":{"template":{"spec":{"containers":[{"name":"mgmtd","image":"%s"}]}}}}\n' "$STUB_RUNNING"
`)
			cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), "m4")
			cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_RUNNING=" + running}
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
