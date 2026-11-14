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

// envdVerifyKubectl answers the reads of the envd checks of cell:verify from files in $STUB_DIR. A case changes one file.
const envdVerifyKubectl = `#!/usr/bin/env bash
d="$STUB_DIR"
case " $* " in
  *" --context kind-management "*" exec spire-server-0 "*) cat "$d/mgmt-root.pem" ;;
  *" --context kind-management "*" get configmap mgmt-signing-pub "*) printf '{"data":{"spec.pub":"%s"}}\n' "$(cat "$d/signing-pub")" ;;
  *" --context kind-management "*" get pod mgmtd-0 "*) printf 'True' ;;
  *" -n spire-system get configmap cell-records -o json "*) cat "$d/cell-records.json" ;;
  *" -n spire-system get networkpolicy spire-server-agents "*) cat "$d/agents-policy.json" ;;
  *" -n spire-system get configmap spire-server "*) cat "$d/server.conf" ;;
  *" -n envd-system get configmap mgmt-spec-key "*) printf '%s' "$(cat "$d/spec-key")" ;;
  *" -n envd-system get deployment envd "*) cat "$d/envd-deployment.json" ;;
  *" -n envd-system get networkpolicy envd "*) cat "$d/envd-policy.json" ;;
  *" -n envd-system get configmap peer-root "*) printf '%s' "$(cat "$d/envd-peer-root.pem")" ;;
  *" -n envd-system get pods -l app.kubernetes.io/name=envd "*) cat "$d/envd-pods.json" ;;
  *" -n cell-identity-system get configmap mgmt-op-key "*) cat "$d/op-key.json" ;;
  *" -n cell-identity-system get pods -l app.kubernetes.io/name=celld "*) cat "$d/celld-pods.json" ;;
  *" get --raw /openid/v1/jwks "*) cat "$d/live-jwks.json" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const envdVerifyMise = `#!/usr/bin/env bash
d="$STUB_DIR"
case "$1 $2 $3 $4" in
  "run pki -- trust-bundle") cat ;;
  "run mgmt -- status") echo '[mgmt] $ scripts/mgmt.sh status' >&2; [[ -s "$d/status.json" ]] || exit 1; cat "$d/status.json" ;;
  "run mgmt -- pubkey") printf '{"spec.pub":"%s"}\n' "$(cat "$d/signing-pub")" ;;
  "run hostsvc -- facts")
    cell="$6"
    [[ -f "$d/facts-$cell.json" ]] || { echo "no facts" >&2; exit 1; }
    cat "$d/facts-$cell.json" ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

func sha256sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// TestVerifyEnvdChecks runs each envd check of cell:verify, and the two checks that read cell-records, with fakes: once on
// a healthy state, and once for each mismatch. A mismatch prints its reason and the repair command.
func TestVerifyEnvdChecks(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash", "base64", "shasum")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	stub, bin := filepath.Join(root, "stub"), filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"kubectl": envdVerifyKubectl, "mise": envdVerifyMise} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pub := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	otherPub := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
	mgmtRoot, otherRoot := caPEM(t, 1), caPEM(t, 2)
	rootSum := func(root string) string { return fmt.Sprintf("%x", sha256sum(strings.TrimRight(root, "\n"))) }
	jwks := func(kids ...string) string {
		var keys []string
		for _, k := range kids {
			keys = append(keys, `{"kid":"`+k+`","kty":"RSA"}`)
		}
		return `{"keys":[` + strings.Join(keys, ",") + `]}`
	}
	records := func(counter string, perCell map[string]string) string {
		data := []string{`"spec-envelope.json":"{}"`}
		for cell, keys := range perCell {
			payload := base64.StdEncoding.EncodeToString([]byte(`{"name":"` + cell + `","jwks":` + keys + `}`))
			envelope := `{"payloadType":"x","payload":"` + payload + `","signatures":[]}`
			data = append(data, fmt.Sprintf("%q:%q", cell+".dsse.json", envelope))
		}
		return `{"metadata":{"annotations":{"poc.internal/spec-epoch":"1","poc.internal/spec-counter":"` + counter + `"}},"data":{` + strings.Join(data, ",") + `}}`
	}
	conf := func(key string) string {
		return "      reload_interval = \"10s\"\n      record_public_keys = [\"" + key + "\"]\n      challenge_timeout = \"10s\"\n"
	}
	envd := func(ip string) string {
		return `{"spec":{"template":{"spec":{"containers":[{"name":"spire-agent","args":[]},{"name":"envd","args":["run","--upstream=` + ip + `:31446","--env=dev"]}]}}}}`
	}
	envdPolicy := func(ip string) string {
		return `{"spec":{"egress":[{"to":[{"ipBlock":{"cidr":"` + ip + `/32"}}],"ports":[{"port":31446}]},{"to":[{"ipBlock":{"cidr":"10.9.0.9/32"}}],"ports":[{"port":6443}]}]}}`
	}
	pods := func(app, sum string) string {
		return `{"items":[{"metadata":{"name":"` + app + `-0","annotations":{"poc.internal/peer-root-sha256":"` + sum + `"}}}]}`
	}
	// opSum is the checksum annotation of the render: the SHA-256 of the op.pub text.
	opSum := func(key string) string { return fmt.Sprintf("%x", sha256sum(key)) }
	opKey := func(keys map[string]string) string {
		var data []string
		for name, key := range keys {
			data = append(data, fmt.Sprintf("%q:%q", name, key))
		}
		return `{"metadata":{"annotations":{"poc.internal/op-key-sha256":"` + opSum(pub) + `"}},"data":{` + strings.Join(data, ",") + `}}`
	}
	opPods := func(sum string) string {
		return `{"items":[{"metadata":{"name":"celld-0","annotations":{"poc.internal/op-key-sha256":"` + sum + `"}}}]}`
	}
	stagedStatus := func(key string) string {
		raw, _ := base64.StdEncoding.DecodeString(key)
		return fmt.Sprintf(`{"signed":{"epoch":1,"counter":7},"stagedKey":"%x"}`, sha256sum(string(raw)))
	}
	healthy := map[string]string{
		"mgmt-root.pem": mgmtRoot, "signing-pub": pub, "status.json": `{"signed":{"epoch":1,"counter":7}}`,
		"cell-records.json":  records("7", map[string]string{"dev-cell-1": jwks("a", "b"), "dev-cell-2": jwks("c")}),
		"agents-policy.json": `{"spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"10.9.0.1/32"}},{"ipBlock":{"cidr":"10.9.0.2/32"}}]}]}}`,
		"server.conf":        conf(pub), "spec-key": pub, "envd-deployment.json": envd("10.9.0.10"), "envd-policy.json": envdPolicy("10.9.0.10"),
		"envd-peer-root.pem": mgmtRoot, "envd-pods.json": pods("envd", rootSum(mgmtRoot)), "op-key.json": opKey(map[string]string{"op.pub": pub}), "celld-pods.json": opPods(opSum(pub)), "gw-status.json": `{"epoch":1,"streams":{"dev-cell-1":1,"dev-cell-2":2}}`,
		"live-jwks.json": jwks("a", "b"), "traces": "",
		"facts-management.json": `{"name":"management","nodeIP":"10.9.0.10"}`,
		"facts-dev-cell-1.json": `{"name":"dev-cell-1","nodeIP":"10.9.0.1","jwks":` + jwks("a", "b") + `}`,
		"facts-dev-cell-2.json": `{"name":"dev-cell-2","nodeIP":"10.9.0.2","jwks":` + jwks("c") + `}`,
	}
	up := "Run: CELL=dev-cp mise run cell:up"
	for _, tc := range []struct {
		name, check, cell string
		change            map[string]string
		want              []string
	}{
		{name: "envd applied ok", check: "check_envd_applied", cell: "dev-cp"},
		{name: "envd applied: the counter is behind", check: "check_envd_applied", cell: "dev-cp", change: map[string]string{"cell-records.json": records("6", nil)},
			want: []string{"cell-records holds the spec revision 1/6, and mgmtd signed 1/7", "mise run mgmt -- status", "kubectl --context kind-dev-cp -n envd-system logs deploy/envd"}},
		{name: "envd applied: the epoch is behind", check: "check_envd_applied", cell: "dev-cp", change: map[string]string{"status.json": `{"signed":{"epoch":2,"counter":7}}`},
			want: []string{"holds the spec revision 1/7, and mgmtd signed 2/7"}},
		{name: "envd applied: mgmtd does not answer", check: "check_envd_applied", cell: "dev-cp", change: map[string]string{"status.json": ""},
			want: []string{"CELL=management LINK_ONLY=mgmt-api mise run cell:link"}},
		{name: "spec key ok", check: "check_spec_key_pinned", cell: "dev-cp"},
		{name: "spec key: the server pins an old key", check: "check_spec_key_pinned", cell: "dev-cp", change: map[string]string{"server.conf": conf(otherPub)}, want: []string{"the server config pins '" + otherPub + "'", up}},
		{name: "spec key: the server pins two keys", check: "check_spec_key_pinned", cell: "dev-cp", change: map[string]string{"server.conf": conf(pub + `", "` + otherPub)}, want: []string{"the server config pins", up}},
		{name: "spec key: envd holds an old key", check: "check_spec_key_pinned", cell: "dev-cp", change: map[string]string{"spec-key": otherPub}, want: []string{"mgmt-spec-key holds '" + otherPub + "'", up}},
		{name: "spec key: mgmtd signs with a new key", check: "check_spec_key_pinned", cell: "dev-cp", change: map[string]string{"signing-pub": otherPub}, want: []string{"mgmt-signing-pub holds " + otherPub, up}},
		{name: "management address ok", check: "check_envd_mgmt_address", cell: "dev-cp"},
		{name: "management address: the node moved", check: "check_envd_mgmt_address", cell: "dev-cp", change: map[string]string{"facts-management.json": `{"name":"management","nodeIP":"10.9.0.77"}`},
			want: []string{"the management node is 10.9.0.77", "runs '--upstream=10.9.0.10:31446'", up}},
		{name: "management address: the policy is behind", check: "check_envd_mgmt_address", cell: "dev-cp", change: map[string]string{"envd-policy.json": envdPolicy("10.9.0.11")},
			want: []string{"the policy admits '10.9.0.11/32'", up}},
		{name: "envd peer root ok", check: "check_envd_peer_root", cell: "dev-cp"},
		{name: "envd peer root: management has a new root", check: "check_envd_peer_root", cell: "dev-cp", change: map[string]string{"mgmt-root.pem": otherRoot}, want: []string{"absent or holds other roots", up}},
		{name: "envd peer root: the pod holds an old digest", check: "check_envd_peer_root", cell: "dev-cp", change: map[string]string{"envd-pods.json": pods("envd", strings.Repeat("0", 64))},
			want: []string{"envd-0 carries the root digest", up}},
		{name: "op key ok", check: "check_op_key_pinned", cell: "dev-cell-1"},
		{name: "op key ok during a rotation: the staged key is mounted too", check: "check_op_key_pinned", cell: "dev-cell-1",
			change: map[string]string{"op-key.json": opKey(map[string]string{"op.pub": pub, "op.next.pub": otherPub}), "status.json": stagedStatus(otherPub)}},
		{name: "op key: mgmtd signs with a new key", check: "check_op_key_pinned", cell: "dev-cell-1", change: map[string]string{"signing-pub": otherPub},
			want: []string{"mgmt-op-key holds op.pub = " + pub, "holds no key that equals the live key " + otherPub, "Run: CELL=dev-cell-1 mise run cell:up"}},
		{name: "op key: a key that nobody staged", check: "check_op_key_pinned", cell: "dev-cell-1",
			change: map[string]string{"op-key.json": opKey(map[string]string{"op.pub": pub, "op.next.pub": otherPub})},
			want:   []string{"mgmt-op-key holds op.next.pub = " + otherPub + ", which is neither the live key of mgmtd nor its staged key", "Run: CELL=dev-cell-1 mise run cell:up"}},
		{name: "op key: the staged key differs from the mounted one", check: "check_op_key_pinned", cell: "dev-cell-1",
			change: map[string]string{"op-key.json": opKey(map[string]string{"op.pub": pub, "op.next.pub": otherPub}), "status.json": stagedStatus(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))},
			want:   []string{"op.next.pub", "neither the live key"}},
		{name: "op key: the pod started with another key", check: "check_op_key_pinned", cell: "dev-cell-1", change: map[string]string{"celld-pods.json": opPods(strings.Repeat("0", 64))},
			want: []string{"celld-0 carries the key checksum " + strings.Repeat("0", 64), "Run: CELL=dev-cell-1 mise run cell:up"}},
		{name: "op key: no ConfigMap", check: "check_op_key_pinned", cell: "dev-cell-1", change: map[string]string{"op-key.json": ""},
			want: []string{"Run: CELL=dev-cell-1 mise run cell:up"}},
		{name: "celld streams ok", check: "check_celld_streams", cell: "dev-cp"},
		{name: "celld streams: a cell has none", check: "check_celld_streams", cell: "dev-cp", change: map[string]string{"gw-status.json": `{"epoch":1,"streams":{"dev-cell-1":1}}`},
			want: []string{"the gateway holds no stream of dev-cell-2", "CELL=dev-cell-2 mise run cell:up"}},
		{name: "celld streams: a stream count of zero", check: "check_celld_streams", cell: "dev-cp", change: map[string]string{"gw-status.json": `{"epoch":1,"streams":{"dev-cell-1":0,"dev-cell-2":1}}`},
			want: []string{"the gateway holds no stream of dev-cell-1", "CELL=dev-cell-1 mise run cell:up"}},
		{name: "agent cells ok", check: "check_agent_cells_current", cell: "dev-cp"},
		{name: "agent cells: a record holds old keys", check: "check_agent_cells_current", cell: "dev-cp",
			change: map[string]string{"cell-records.json": records("7", map[string]string{"dev-cell-1": jwks("a"), "dev-cell-2": jwks("c")})},
			want:   []string{"the record of dev-cell-1 in ConfigMap cell-records holds other service account keys", "Run: mise run mgmt -- keycheck --cell dev-cell-1"}},
		{name: "agent cells: no record for a cell", check: "check_agent_cells_current", cell: "dev-cp",
			change: map[string]string{"cell-records.json": records("7", map[string]string{"dev-cell-1": jwks("a", "b")})},
			want:   []string{"the record of dev-cell-2", "Run: mise run mgmt -- keycheck --cell dev-cell-2"}},
		{name: "agent cells: a node moved", check: "check_agent_cells_current", cell: "dev-cp",
			change: map[string]string{"facts-dev-cell-2.json": `{"name":"dev-cell-2","nodeIP":"10.9.0.8","jwks":` + jwks("c") + `}`},
			want:   []string{"the NetworkPolicy admits '10.9.0.1/32 10.9.0.2/32'", "Run: CELL=dev-cp mise run cell:up"}},
		{name: "agent cells: a test trace comes first", check: "check_agent_cells_current", cell: "dev-cp",
			change: map[string]string{"cell-records.json": records("7", map[string]string{"dev-cell-1": jwks("a")}), "traces": "the node names the test key"},
			want:   []string{"the node names the test key", "Run: mise run gate:m2:repair"}},
		{name: "key test clean ok", check: "check_keytest_clean", cell: "dev-cell-1"},
		{name: "key test clean: the cell publishes other keys", check: "check_keytest_clean", cell: "dev-cell-1", change: map[string]string{"live-jwks.json": jwks("a", "z")},
			want: []string{"publishes other keys than its record in dev-cp", "Run: mise run mgmt -- keycheck --cell dev-cell-1"}},
		{name: "key test clean: no record", check: "check_keytest_clean", cell: "dev-cell-1", change: map[string]string{"cell-records.json": records("7", map[string]string{"dev-cell-2": jwks("c")})},
			want: []string{"could not read the record of dev-cell-1 in ConfigMap cell-records of dev-cp"}},
		{name: "key test clean: a trace on the node", check: "check_keytest_clean", cell: "dev-cell-1", change: map[string]string{"traces": "kube-apiserver.yaml names the test key"},
			want: []string{"kube-apiserver.yaml names the test key", "Run: mise run gate:m2:repair"}},
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
				p := filepath.Join(stub, k)
				_ = os.Remove(p)
				if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; source "$1/components/lib/peer-root.sh"; source "$1/components/lib/hostsvc-pin.sh"
source "$1/components/lib/mgmt-key.sh"; source "$1/scripts/verify-lib.sh"
keytest_leftover() { cat "$STUB_DIR/traces"; }
gateway_status() { cat "$STUB_DIR/gw-status.json"; }
set +e; `+tc.check, "_", root)
			cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=" + tc.cell,
				"POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_DIR=" + stub}
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
