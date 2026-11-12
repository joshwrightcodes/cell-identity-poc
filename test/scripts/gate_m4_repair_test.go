package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const repairKubectl = `#!/usr/bin/env bash
case " $* " in
  *" exec spire-server-0 "*) cat "$STUB_DIR/live-root.pem" ;;
  *" get configmap hostsvc-pin "*) cat "$STUB_DIR/pin.pem" ;;
  *" get statefulset mgmtd -o jsonpath="*) [[ -z "${STUB_NO_STS:-}" ]] || exit 1; printf '%s' "${STUB_REPLICAS:-1}" ;;
  *" get deployment envd -o jsonpath="*) [[ -z "${STUB_NO_ENVD:-}" ]] || exit 1; printf '%s' "${STUB_ENVD_REPLICAS:-1}" ;;
  *" rollout status "*) echo "rollout $*" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const repairMise = `#!/usr/bin/env bash
[[ "$1 $2 $3 $4" == "run pki -- trust-bundle" ]] && exec cat
echo "unexpected mise call: $*" >&2; exit 2
`

const repairServe = `#!/usr/bin/env bash
case "$1" in
  status) printf '{"running":%s,"pid":1,"cert_sha256":"%s","root_sha256":"%s","expires_soon":false,"last_error":""}\n' "${STUB_RUNNING:-true}" "$STUB_CERT" "$STUB_ROOT" ;;
  restart) echo "hostsvc-serve restart" >>"$STUB_DIR/calls" ;;
esac
`

const repairReplicas = `#!/usr/bin/env bash
echo "harness-replicas $*" >>"$STUB_DIR/calls"
`

// TestGateM4Repair: gate-m4-repair.sh restarts the host service and links mgmt-api when the service does not run,
// or serves another pin or another management root than the deployed ones, and it sets the replicas of mgmtd and
// envd back to 1 through harness-replicas.sh. With --check it only reports each drift with the repair command.
func TestGateM4Repair(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash", "base64")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	stub := filepath.Join(root, "stub")
	if err := os.MkdirAll(stub, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"bin/kubectl": repairKubectl, "bin/mise": repairMise, "stub/serve": repairServe, "stub/replicas": repairReplicas} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	live := caPEM(t, 1)
	pin := caPEM(t, 2)
	for name, content := range map[string]string{"live-root.pem": live, "pin.pem": pin} {
		if err := os.WriteFile(filepath.Join(stub, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	block, _ := pem.Decode([]byte(pin))
	pinSum := sha256.Sum256(block.Bytes)
	good := []string{"STUB_CERT=" + hex.EncodeToString(pinSum[:]), "STUB_ROOT=" + goRootSHA(t, live)}
	run := func(args []string, env ...string) (string, string, error) {
		_ = os.Remove(filepath.Join(stub, "calls"))
		cmd := exec.Command(filepath.Join(root, "scripts", "gate-m4-repair.sh"), args...)
		cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "POC_BUILD_ROOT=" + filepath.Join(root, "build"),
			"STUB_DIR=" + stub, "HOSTSVC_SERVE=" + filepath.Join(stub, "serve"), "HARNESS_REPLICAS=" + filepath.Join(stub, "replicas")}, append(good, env...)...)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		calls, _ := os.ReadFile(filepath.Join(stub, "calls"))
		return out.String() + errOut.String(), string(calls), err
	}

	if out, calls, err := run([]string{"--check"}); err != nil || calls != "" {
		t.Fatalf("a clean state: err %v, output %q, calls %q; want success and no change", err, out, calls)
	}
	if out, calls, err := run(nil); err != nil || calls != "" {
		t.Fatalf("a clean repair: err %v, output %q, calls %q", err, out, calls)
	}
	repair := "Run: mise run gate:m4:repair"
	for _, tc := range []struct {
		name, want, call string
		env              []string
	}{
		{"envd replicas", "Deployment envd has 0 replicas. " + repair, "harness-replicas dev-cp envd-system deployment/envd 1", []string{"STUB_ENVD_REPLICAS=0"}},
		{"replicas", "StatefulSet mgmtd has 0 replicas. " + repair, "harness-replicas management mgmt-system statefulset/mgmtd 1", []string{"STUB_REPLICAS=0"}},
		{"another pin", "holds the certificate " + hex.EncodeToString(pinSum[:]) + ", and the host service presents " + strings.Repeat("a", 64), "hostsvc-serve restart", []string{"STUB_CERT=" + strings.Repeat("a", 64)}},
		{"another root", "the host service trusts the management root " + strings.Repeat("b", 64), "hostsvc-serve restart", []string{"STUB_ROOT=" + strings.Repeat("b", 64)}},
		{"not running", "the host service does not run. " + repair, "hostsvc-serve restart", []string{"STUB_RUNNING=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, err := run([]string{"--check"}, tc.env...)
			if err == nil || !strings.Contains(out, tc.want) || !strings.Contains(out, repair) || calls != "" {
				t.Fatalf("--check: err %v, output %q, calls %q; want a report that names the repair and changes nothing", err, out, calls)
			}
			out, calls, err = run(nil, tc.env...)
			if err != nil || !strings.Contains(calls, tc.call) {
				t.Fatalf("repair: err %v, output %q, calls %q; want %q", err, out, calls, tc.call)
			}
		})
	}
	out, _, err := run([]string{"--check"}, "STUB_NO_STS=1")
	if err == nil || !strings.Contains(out, "StatefulSet mgmtd is absent in management. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link") {
		t.Fatalf("an absent StatefulSet: err %v, output %q", err, out)
	}
	out, _, err = run([]string{"--check"}, "STUB_NO_ENVD=1")
	if err == nil || !strings.Contains(out, "Deployment envd is absent in dev-cp. Run: CELL=dev-cp mise run cell:up") {
		t.Fatalf("an absent Deployment envd: err %v, output %q", err, out)
	}
}
