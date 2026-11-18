package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// ccKubectl answers the reads of the cell controller checks of cell:verify from the files in $STUB_DIR. A case changes one file.
const ccKubectl = `#!/usr/bin/env bash
d="$STUB_DIR"
case " $* " in
  *" --context kind-management "*" get configmap mgmt-signing-pub "*) cat "$d/signing-pub.json" ;;
  *" --context kind-management "*" get pod mgmtd-0 "*) printf 'True' ;;
  *" -n cell-controller-system get configmap hostsvc-pin "*) cat "$d/pin.pem" ;;
  *" -n cell-controller-system get configmap mgmt-spec-key "*"next"*) printf '%s' "$(cat "$d/spec-next" 2>/dev/null)" ;;
  *" -n cell-controller-system get configmap mgmt-spec-key "*) printf '%s' "$(cat "$d/spec-pub")" ;;
  *" -n cell-controller-system get configmap cell-steps "*) cat "$d/cell-steps.json" ;;
  *" -n cell-controller-system get pods -l app.kubernetes.io/name=cell-controller "*) cat "$d/pods.json" ;;
  *" -n cell-controller-system get deployment cell-controller "*"jsonpath"*) printf '%s' "$(cat "$d/template-sum")" ;;
  *" -n cell-controller-system get deployment cell-controller "*) cat "$d/deployment.json" ;;
  *" -n cell-controller-system get networkpolicy cell-controller "*) cat "$d/policy.json" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const ccMise = `#!/usr/bin/env bash
d="$STUB_DIR"
case "$1 $2 $3 $4" in
  "run mgmt -- pubkey") printf '{"spec.pub":"%s"}\n' "$(cat "$d/live-pub")" ;;
  "run mgmt -- status") echo '[mgmt] $ scripts/mgmt.sh status' >&2; cat "$d/status.json" ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

const ccServe = `#!/usr/bin/env bash
d="$STUB_DIR"
case "$1" in
  pin) cat "$d/live-pin.pem" ;;
  status) cat "$d/serve-status.json" ;;
  *) exit 2 ;;
esac
`

const ccDocker = `#!/usr/bin/env bash
if [[ "$1" == exec && " $* " == *" getent ahostsv4 host.docker.internal "* ]]; then
  printf '%s STREAM host.docker.internal\n' "${STUB_HOST_IP:-192.168.5.2}"
  exit 0
fi
exit 2
`

func ccSum(s string) string { h := sha256.Sum256([]byte(s)); return fmt.Sprintf("%x", h) }

// ccFixture is the healthy state of the cell controller: the pin of the host service, the key of mgmtd with no staged key, the
// steps of the signed revision 1/7, and the host address 192.168.5.2.
func ccFixture(t *testing.T) map[string]string {
	t.Helper()
	pub := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	pin := caPEM(t, 41)
	pinSum := ccSum("the certificate of the host service")
	policy := `{"spec":{"egress":[{"to":[{"ipBlock":{"cidr":"172.18.0.4/32"}}],"ports":[{"port":6443}]},{"to":[{"ipBlock":{"cidr":"192.168.5.2/32"}}],"ports":[{"port":17443}]}]}}`
	return map[string]string{
		"signing-pub.json":  `{"data":{"spec.pub":"` + pub + `"}}`,
		"live-pub":          pub,
		"spec-pub":          pub,
		"template-sum":      ccSum(pub),
		"status.json":       `{"signed":{"epoch":1,"counter":7}}`,
		"pin.pem":           pin,
		"live-pin.pem":      pin,
		"serve-status.json": `{"running":true,"cert_sha256":"` + pinSum + `"}`,
		"pods.json":         `{"items":[{"metadata":{"name":"cell-controller-abc","annotations":{"poc.internal/hostsvc-pin-sha256":"` + pinSum + `"}}}]}`,
		"cell-steps.json":   `{"metadata":{"labels":{"poc.internal/made-by":"envd"},"annotations":{"poc.internal/spec-epoch":"1","poc.internal/spec-counter":"7"}},"data":{"spec-envelope.json":"{}"}}`,
		"policy.json":       policy,
		"deployment.json":   `{"spec":{"template":{"spec":{"containers":[{"name":"spire-agent","args":[]},{"name":"cell-controller","args":["run","--hostsvc-addr=192.168.5.2:17443"]}]}}}}`,
	}
}

func runCC(t *testing.T, check string, files map[string]string, env ...string) (string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "base64", "shasum")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	bin, stub := filepath.Join(root, "bin"), filepath.Join(root, "stub")
	for _, d := range []string{bin, stub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"kubectl": ccKubectl, "mise": ccMise, "docker": ccDocker} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	serve := filepath.Join(bin, "hostsvc-serve")
	if err := os.WriteFile(serve, []byte(ccServe), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(stub, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; source "$1/components/lib/peer-root.sh"; source "$1/components/lib/hostsvc-pin.sh"
source "$1/components/lib/mgmt-key.sh"; source "$1/scripts/verify-lib.sh"
set +e; `+check, "_", root)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cp",
		"POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_DIR=" + stub, "HOSTSVC_SERVE=" + serve}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// TestCellControllerChecks runs each cell controller check of cell:verify with fakes: once on the healthy state, and once for
// each mismatch. A mismatch prints its reason and the render of the cell controller alone.
func TestCellControllerChecks(t *testing.T) {
	fix := "CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:up"
	pub := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	otherPub := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
	next := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	nextRaw := bytes.Repeat([]byte{7}, 32)
	nextFP := fmt.Sprintf("%x", sha256.Sum256(nextRaw))
	healthy := ccFixture(t)
	stagedSigning := `{"data":{"spec.pub":"` + pub + `","next.pub":"` + next + `"}}`
	stagedStatus := `{"signed":{"epoch":1,"counter":7},"stagedKey":"` + nextFP + `"}`

	for _, tc := range []struct {
		name, check string
		change      map[string]string
		wanted      []string
	}{
		{name: "pin: healthy", check: "check_cell_controller_pin"},
		{name: "pin: the ConfigMap holds another certificate", check: "check_cell_controller_pin", change: map[string]string{"pin.pem": caPEM(t, 42)},
			wanted: []string{"hostsvc-pin holds another certificate than the host service presents", "Run: " + fix}},
		{name: "pin: the pod carries an old digest", check: "check_cell_controller_pin",
			change: map[string]string{"pods.json": `{"items":[{"metadata":{"name":"cell-controller-abc","annotations":{"poc.internal/hostsvc-pin-sha256":"` + strings.Repeat("0", 64) + `"}}}]}`},
			wanted: []string{"cell-controller-abc carries the pin digest " + strings.Repeat("0", 64), "Run: " + fix}},
		{name: "pin: no pod", check: "check_cell_controller_pin", change: map[string]string{"pods.json": `{"items":[]}`},
			wanted: []string{"cell-controller has no running pod", "Run: " + fix}},

		{name: "key: healthy", check: "check_cell_controller_key"},
		{name: "key: the ConfigMap holds an old key", check: "check_cell_controller_key", change: map[string]string{"spec-pub": otherPub},
			wanted: []string{"mgmt-spec-key of the cell controller holds '" + otherPub + "'", "Run: " + fix}},
		{name: "key: the pod template carries an old checksum", check: "check_cell_controller_key", change: map[string]string{"template-sum": ccSum(otherPub)},
			wanted: []string{"the pod template carries '" + ccSum(otherPub) + "'", "Run: " + fix}},
		{name: "key: a staged key that the ConfigMap lacks", check: "check_cell_controller_key",
			change: map[string]string{"signing-pub.json": stagedSigning, "status.json": stagedStatus},
			wanted: []string{"stages '" + next + "'", "Run: " + fix}},
		{name: "key: a staged key that the ConfigMap and the pod hold", check: "check_cell_controller_key",
			change: map[string]string{"signing-pub.json": stagedSigning, "status.json": stagedStatus, "spec-next": next, "template-sum": ccSum(pub + "\n" + next)}},
		{name: "key: next.pub that mgmtd did not stage", check: "check_cell_controller_key",
			change: map[string]string{"signing-pub.json": stagedSigning, "status.json": `{"signed":{"epoch":1,"counter":7},"stagedKey":"` + strings.Repeat("a", 64) + `"}`},
			wanted: []string{"has the SHA-256 " + nextFP}},
		{name: "key: a next.pub that mgmtd no longer stages", check: "check_cell_controller_key", change: map[string]string{"spec-next": next},
			wanted: []string{"holds '" + pub + "' and '" + next + "'", "Run: " + fix}},
		{name: "key: mgmtd signs with another key", check: "check_cell_controller_key", change: map[string]string{"live-pub": otherPub},
			wanted: []string{"mgmtd-0 signs with " + otherPub}},

		{name: "steps: healthy", check: "check_cell_steps_current"},
		{name: "steps: an older counter", check: "check_cell_steps_current", change: map[string]string{"status.json": `{"signed":{"epoch":1,"counter":8}}`},
			wanted: []string{"cell-steps holds the spec revision 1/7", "mgmtd signed 1/8"}},
		{name: "steps: no envd marker", check: "check_cell_steps_current",
			change: map[string]string{"cell-steps.json": `{"metadata":{"annotations":{"poc.internal/spec-epoch":"1","poc.internal/spec-counter":"7"}}}`},
			wanted: []string{"the marker 'none'"}},

		{name: "address: healthy", check: "check_cell_controller_address"},
		{name: "address: the node resolves another address", check: "check_cell_controller_address", change: map[string]string{},
			wanted: []string{"host.docker.internal is 192.168.5.9 in the node, but the policy admits '192.168.5.2/32' and the cell controller runs '--hostsvc-addr=192.168.5.2:17443'", "Run: " + fix}},
		{name: "address: the argument is old and the policy is current", check: "check_cell_controller_address",
			change: map[string]string{"deployment.json": `{"spec":{"template":{"spec":{"containers":[{"name":"cell-controller","args":["run","--hostsvc-addr=192.168.5.7:17443"]}]}}}}`},
			wanted: []string{"the cell controller runs '--hostsvc-addr=192.168.5.7:17443'"}},
		{name: "address: the rule of N42 names another port too", check: "check_cell_controller_address",
			change: map[string]string{"policy.json": `{"spec":{"egress":[{"to":[{"ipBlock":{"cidr":"192.168.5.2/32"}}],"ports":[{"port":17443},{"port":17444}]}]}}`},
			wanted: []string{"the policy admits ''", "Run: " + fix}},
		{name: "address: the policy admits a second address", check: "check_cell_controller_address",
			change: map[string]string{"policy.json": `{"spec":{"egress":[{"to":[{"ipBlock":{"cidr":"192.168.5.2/32"}},{"ipBlock":{"cidr":"192.168.5.3/32"}}],"ports":[{"port":17443}]}]}}`},
			wanted: []string{"the policy admits '192.168.5.2/32 192.168.5.3/32'"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := withFiles(healthy, tc.change)
			var env []string
			if tc.name == "address: the node resolves another address" {
				env = append(env, "STUB_HOST_IP=192.168.5.9")
			}
			out, err := runCC(t, tc.check, files, env...)
			if len(tc.wanted) == 0 {
				if err != nil || out != "" {
					t.Fatalf("the check fails on a good state: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("the check passes though %s", tc.name)
			}
			for _, w := range tc.wanted {
				if !strings.Contains(out, w) {
					t.Errorf("output %q lacks %q", out, w)
				}
			}
		})
	}
}
