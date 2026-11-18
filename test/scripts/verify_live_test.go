package scripts

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// admitKubectl answers the reads of the checks of the admit lists from the files in $STUB_DIR: policy-spire.json,
// policy-relay-view.json, policy-relay-telemetry.json, policy-gateway.json and gateway.json (the StatefulSet).
const admitKubectl = `#!/usr/bin/env bash
d="$STUB_DIR"
case " $* " in
  *" -n spire-system get networkpolicy spire-server-agents "*) cat "$d/policy-spire.json" ;;
  *" -n relay-system get networkpolicy relay-view "*) cat "$d/policy-relay-view.json" ;;
  *" -n relay-system get networkpolicy relay-telemetry "*) cat "$d/policy-relay-telemetry.json" ;;
  *" -n relay-system get deployment "*) cat "$d/relay-deployment.json" ;;
  *" -n gateway-system get networkpolicy cell-gateway "*) cat "$d/policy-gateway.json" ;;
  *" -n gateway-system get statefulset cell-gateway "*) cat "$d/gateway.json" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

func cidrRule(port int, cidrs ...string) string {
	var from []string
	for _, c := range cidrs {
		from = append(from, `{"ipBlock":{"cidr":"`+c+`"}}`)
	}
	return fmt.Sprintf(`{"from":[%s],"ports":[{"protocol":"TCP","port":%d}]}`, strings.Join(from, ","), port)
}

func policyJSON(ingress ...string) string {
	return `{"spec":{"ingress":[` + strings.Join(ingress, ",") + `]}}`
}

// admitFixture holds the healthy state of dev-cp with both cells live at 172.18.0.5 and 172.18.0.6. The cell rules are not the first
// rule of any policy, so a check that reads a rule by its index reads the wrong one.
func admitFixture() map[string]string {
	decoy := cidrRule(9999, "10.250.0.1/32")
	cells := []string{"172.18.0.5/32", "172.18.0.6/32"}
	return map[string]string{
		"policy-spire.json":           policyJSON(decoy, cidrRule(8081, cells...)),
		"policy-relay-view.json":      policyJSON(cidrRule(8080, "172.18.0.3/32"), cidrRule(8443, cells...)),
		"policy-relay-telemetry.json": policyJSON(cidrRule(8080, "172.18.0.3/32"), cidrRule(8444, cells...)),
		"policy-gateway.json": policyJSON(cidrRule(8452, "10.250.0.2/32"), cidrRule(8450, cells...), cidrRule(8451, cells...),
			cidrRule(8080, "172.18.0.3/32")),
		"gateway.json": `{"spec":{"template":{"spec":{"containers":[{"name":"spire-agent","args":[]},{"name":"cellgw","args":["serve","--cell-node=dev-cell-1=172.18.0.5","--cell-node=dev-cell-2=172.18.0.6"]}]}}}}`,
	}
}

func runAdmit(t *testing.T, check string, files map[string]string, env ...string) (string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
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
	writeLiveStubs(t, bin)
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(admitKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(stub, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; source "$1/components/lib/peer-root.sh"; source "$1/components/lib/hostsvc-pin.sh"
source "$1/components/lib/mgmt-key.sh"; source "$1/scripts/verify-lib.sh"
node_ip() { case "$1" in management) echo 172.18.0.3 ;; dev-cell-1) echo 172.18.0.5 ;; dev-cell-2) echo 172.18.0.6 ;; *) return 1 ;; esac; }
RELAY_TARGET=management
set +e; `+check, "_", root)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cp",
		"POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_DIR=" + stub}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func withFiles(files map[string]string, change map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range files {
		out[k] = v
	}
	for k, v := range change {
		out[k] = v
	}
	return out
}

// TestCheckAdmitLists: the SPIRE server, the relay and the gateway admit the node addresses of the live cells and no others, and
// the gateway runs one --cell-node for each live cell. A stale address, a missing one, and an argument of a dead cell fail with
// CELL=dev-cp mise run cell:up. While no cell is live, each cell rule is absent and the check passes; a rule that stays fails.
func TestCheckAdmitLists(t *testing.T) {
	healthy := admitFixture()
	empty := map[string]string{
		"policy-spire.json":           policyJSON(cidrRule(9999, "10.250.0.1/32")),
		"policy-relay-view.json":      policyJSON(cidrRule(8080, "172.18.0.3/32")),
		"policy-relay-telemetry.json": policyJSON(cidrRule(8080, "172.18.0.3/32")),
		"policy-gateway.json":         policyJSON(cidrRule(8452, "10.250.0.2/32"), cidrRule(8080, "172.18.0.3/32")),
		"gateway.json":                `{"spec":{"template":{"spec":{"containers":[{"name":"cellgw","args":["serve"]}]}}}}`,
	}
	cells := []string{"172.18.0.5/32", "172.18.0.6/32"}
	for _, tc := range []struct {
		name   string
		files  map[string]string
		env    []string
		fail   bool
		wanted []string
	}{
		{name: "healthy", files: healthy},
		{name: "a stale address in the SPIRE server policy", files: withFiles(healthy, map[string]string{"policy-spire.json": policyJSON(cidrRule(9999, "10.250.0.1/32"), cidrRule(8081, append(cells, "172.18.0.99/32")...))}),
			fail: true, wanted: []string{"the SPIRE server admits '172.18.0.5/32 172.18.0.6/32 172.18.0.99/32' on port 8081", "Run: CELL=dev-cp mise run cell:up"}},
		{name: "a live cell is missing from the relay", files: withFiles(healthy, map[string]string{"policy-relay-telemetry.json": policyJSON(cidrRule(8080, "172.18.0.3/32"), cidrRule(8444, "172.18.0.5/32"))}),
			fail: true, wanted: []string{"the relay relay-telemetry admits '172.18.0.5/32' on its route ports", "Run: CELL=dev-cp mise run cell:up"}},
		{name: "a stale address on port 8451 of the gateway", files: withFiles(healthy, map[string]string{"policy-gateway.json": policyJSON(cidrRule(8450, cells...), cidrRule(8451, "172.18.0.5/32", "172.18.0.77/32"))}),
			fail: true, wanted: []string{"the gateway admits '172.18.0.5/32 172.18.0.77/32' on port 8451"}},
		{name: "a fake stale --cell-node address", files: withFiles(healthy, map[string]string{"gateway.json": `{"spec":{"template":{"spec":{"containers":[{"name":"cellgw","args":["serve","--cell-node=dev-cell-1=172.18.0.50","--cell-node=dev-cell-2=172.18.0.6"]}]}}}}`}),
			fail: true, wanted: []string{"the gateway runs '--cell-node=dev-cell-1=172.18.0.50 --cell-node=dev-cell-2=172.18.0.6'", "Run: CELL=dev-cp mise run cell:up"}},
		{name: "one live cell: the policies must drop the other", files: healthy, env: []string{"STUB_KIND=management dev-cp rogue dev-cell-1"},
			fail: true, wanted: []string{"the live cells are '172.18.0.5/32'"}},
		{name: "no live cell and no cell rule", files: empty, env: []string{"STUB_KIND=management dev-cp rogue"}},
		{name: "no live cell, but the rules of the cells stay", files: healthy, env: []string{"STUB_KIND=management dev-cp rogue"},
			fail: true, wanted: []string{"the live cells are ''", "Run: CELL=dev-cp mise run cell:up"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runAdmit(t, "check_admit_lists", tc.files, tc.env...)
			if !tc.fail {
				if err != nil {
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

// TestVerifySelectsRulesByPort: check_agent_cells_current, check_relay_current and check_gateway_cells read a rule by its ports. With a
// rule in front of the cell rule, or no cell rule at all, they still read the right one.
func TestVerifySelectsRulesByPort(t *testing.T) {
	healthy := admitFixture()
	t.Run("check_relay_current reads the route rule behind the node rule", func(t *testing.T) {
		files := withFiles(healthy, map[string]string{
			"relay-deployment.json": `{"spec":{"template":{"spec":{"containers":[{"args":["--route","8443=172.18.0.3:31443","--health",":8080"]}]}}}}`,
			"policy-relay-view.json": `{"spec":{"ingress":[` + cidrRule(8080, "172.18.0.3/32") + `,` + cidrRule(8443, "172.18.0.5/32", "172.18.0.6/32") + `],"egress":[` +
				`{"to":[{"namespaceSelector":{}}],"ports":[{"port":4317}]},` + cidrToRule(31443, "172.18.0.3/32") + `]}}`,
			"policy-relay-telemetry.json": `{"spec":{"ingress":[` + cidrRule(8080, "172.18.0.3/32") + `,` + cidrRule(8444, "172.18.0.5/32", "172.18.0.6/32") + `],"egress":[` +
				`{"to":[{"namespaceSelector":{}}],"ports":[{"port":4317}]},` + cidrToRule(31444, "172.18.0.3/32") + `]}}`,
		})
		out, err := runAdmit(t, "check_relay_current", files)
		if err != nil {
			t.Fatalf("check_relay_current failed on a state with the rules in another order: %v\n%s", err, out)
		}
		// With a stale cell address in the route rule, it still fails, and it names that rule.
		files["policy-relay-view.json"] = strings.Replace(files["policy-relay-view.json"], "172.18.0.6/32", "172.18.0.66/32", 1)
		if out, err = runAdmit(t, "check_relay_current", files); err == nil || !strings.Contains(out, "the ingress policy of relay-view admits") {
			t.Fatalf("err %v, output %q; want a failure for the stale address on the route ports", err, out)
		}
	})
	t.Run("check_relay_current passes with no live cell and no cell rule", func(t *testing.T) {
		files := withFiles(healthy, map[string]string{
			"relay-deployment.json":       `{"spec":{"template":{"spec":{"containers":[{"args":["--route","8443=172.18.0.3:31443"]}]}}}}`,
			"policy-relay-view.json":      `{"spec":{"ingress":[` + cidrRule(8080, "172.18.0.3/32") + `],"egress":[` + cidrToRule(31443, "172.18.0.3/32") + `]}}`,
			"policy-relay-telemetry.json": `{"spec":{"ingress":[` + cidrRule(8080, "172.18.0.3/32") + `],"egress":[` + cidrToRule(31444, "172.18.0.3/32") + `]}}`,
		})
		if out, err := runAdmit(t, "check_relay_current", files, "STUB_KIND=management dev-cp rogue"); err != nil {
			t.Fatalf("a relay with no cell rule fails while no cell is live: %v\n%s", err, out)
		}
	})
	t.Run("check_gateway_cells reads the arguments, and the policy is the other check", func(t *testing.T) {
		if out, err := runAdmit(t, "check_gateway_cells", healthy); err != nil {
			t.Fatalf("check_gateway_cells: %v\n%s", err, out)
		}
		stale := withFiles(healthy, map[string]string{"gateway.json": `{"spec":{"template":{"spec":{"containers":[{"name":"cellgw","args":["serve","--cell-node=dev-cell-1=172.18.0.5"]}]}}}}`})
		if out, err := runAdmit(t, "check_gateway_cells", stale); err == nil || !strings.Contains(out, "the node of dev-cell-2 is 172.18.0.6, but the gateway runs 'no --cell-node'") {
			t.Fatalf("err %v, output %q", err, out)
		}
	})
}

func cidrToRule(port int, cidrs ...string) string {
	var to []string
	for _, c := range cidrs {
		to = append(to, `{"ipBlock":{"cidr":"`+c+`"}}`)
	}
	return fmt.Sprintf(`{"to":[%s],"ports":[{"protocol":"TCP","port":%d}]}`, strings.Join(to, ","), port)
}

// TestCheckHostsvcRoots: the host service serves the live dev root, the keys of mgmtd and the signed spec revision. A mismatch prints
// mise run hostsvc:serve -- sync, and a mgmtd that does not answer prints the link of mgmt-api.
func TestCheckHostsvcRoots(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash", "base64", "shasum")
	pub := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	rawSum := func(b64 string) string {
		out, err := exec.Command("bash", "-c", `printf '%s' "$1" | base64 -d | shasum -a 256 | cut -d' ' -f1`, "_", b64).Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	staged := strings.Repeat("c", 64)
	status := func(dev string, keys []string, rev string) string {
		quoted := make([]string, len(keys))
		for i, k := range keys {
			quoted[i] = `"` + k + `"`
		}
		return fmt.Sprintf(`{"running":true,"dev_root_sha256":"%s","keys":[%s],"spec_revision":%s}`, dev, strings.Join(quoted, ","), rev)
	}
	devPEM := caPEM(t, 31)
	devSum := func() string {
		out, err := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; pem_der_sha256 <<<"$2"`, "_", "../..", devPEM).Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}()
	keysWant := []string{rawSum(pub)}
	rev := `{"epoch":1,"counter":7}`
	for _, tc := range []struct {
		name, status string
		env          []string
		mgmtDown     bool
		wanted       []string
	}{
		{name: "healthy without dev-cp", status: status("", keysWant, rev), env: []string{"STUB_KIND=management rogue"}},
		{name: "healthy with the staged key and dev-cp", status: status(devSum, []string{rawSum(pub), staged}, rev), env: []string{"STUB_STAGED=" + staged}},
		{name: "the dev root is old", status: status(strings.Repeat("e", 64), keysWant, rev),
			wanted: []string{"serves the dev root '" + strings.Repeat("e", 64) + "'", "mise run hostsvc:serve -- sync"}},
		{name: "a key is missing", status: status(devSum, keysWant, rev), env: []string{"STUB_STAGED=" + staged},
			wanted: []string{"the host service trusts the keys", "mise run hostsvc:serve -- sync"}},
		{name: "the spec is behind", status: status(devSum, keysWant, `{"epoch":1,"counter":6}`),
			wanted: []string{"knows the spec revision {\"epoch\":1,\"counter\":6}", "mise run hostsvc:serve -- sync"}},
		{name: "mgmtd does not answer", status: status(devSum, keysWant, rev), mgmtDown: true,
			wanted: []string{"CELL=management LINK_ONLY=mgmt-api mise run cell:link"}},
		{name: "the host service does not run", status: `{"running":false}`, wanted: []string{"Run: mise run hostsvc:serve -- start"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeLiveStubs(t, filepath.Join(dir, "bin"))
			write := func(name, body string, mode os.FileMode) {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			write("bin/mise", `#!/usr/bin/env bash
[[ -z "${STUB_MGMT_DOWN:-}" ]] || exit 1
case "$1 $2 $3 $4" in
  "run mgmt -- status") printf '{"signed":{"epoch":1,"counter":7},"stagedKey":"%s"}\n' "${STUB_STAGED:-}" ;;
  "run mgmt -- pubkey") printf '{"spec.pub":"%s"}\n' "$STUB_PUB" ;;
  "run pki -- trust-bundle") cat ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`, 0o755)
			write("bin/kubectl", "#!/usr/bin/env bash\ncat \"$STUB_DEV_PEM\"\n", 0o755)
			write("serve", "#!/usr/bin/env bash\ncat \"$STUB_STATUS\"\n", 0o755)
			write("status.json", tc.status+"\n", 0o644)
			write("dev.pem", devPEM, 0o644)
			lib, _ := filepath.Abs("../../scripts/lib.sh")
			root, _ := filepath.Abs("../..")
			cmd := exec.Command("bash", "-c", `source "$1"; source "$2/components/lib/peer-root.sh"; source "$2/components/lib/hostsvc-pin.sh"; source "$2/scripts/verify-lib.sh"
set +e; check_hostsvc_roots`, "_", lib, root)
			cmd.Env = append([]string{"PATH=" + filepath.Join(dir, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=management",
				"POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "HOSTSVC_SERVE=" + filepath.Join(dir, "serve"), "STUB_STATUS=" + filepath.Join(dir, "status.json"),
				"STUB_PUB=" + pub, "STUB_DEV_PEM=" + filepath.Join(dir, "dev.pem")}, tc.env...)
			if tc.mgmtDown {
				cmd.Env = append(cmd.Env, "STUB_MGMT_DOWN=1")
			}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			if tc.wanted == nil {
				if err != nil {
					t.Fatalf("the check fails on a good state: %v\n%s", err, out.String())
				}
				return
			}
			if err == nil {
				t.Fatalf("the check passes though %s", tc.name)
			}
			for _, w := range tc.wanted {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output %q lacks %q", out.String(), w)
				}
			}
		})
	}
}
