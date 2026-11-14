package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// envdKubectl answers the reads of check_harness_objects for the component envd. Its bundle spans two
// namespaces: ServiceAccount, Deployment and the NetworkPolicies live in envd-system, and Role and RoleBinding
// envd-records live in spire-system, next to the objects of the spire-server bundle. Every read lists the objects of
// all owners, as the API server does. STUB_EXTRA=<kind>/<name>@<namespace> adds one object with the label
// cell.poc.internal/harness=envd. STUB_UNLABELLED=1 adds a Role of the spire-server bundle without the label.
const envdKubectl = `#!/usr/bin/env bash
set -euo pipefail
args=" $* "
mine='"labels":{"cell.poc.internal/harness":"envd"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]'
item() { printf '{"metadata":{"name":"%s",%s}}' "$1" "$mine"; }
extra() { # extra <kind> <namespace> prints ,<item> when STUB_EXTRA names that kind and namespace
  local want="${STUB_EXTRA:-}"
  [[ "$want" == "$1/"*"@$2" ]] || return 0
  want="${want#*/}"
  printf ',%s' "$(item "${want%@*}")"
}
list() { printf '{"items":[%s]}\n' "$1"; }
case "$args" in
  *" -n envd-system get ServiceAccount -o json "*) list "$(item envd)$(extra ServiceAccount envd-system)" ;;
  *" -n envd-system get Deployment -o json "*) list "$(item envd)$(extra Deployment envd-system)" ;;
  *" -n envd-system get ConfigMap -o json "*) list "$(item peer-root),$(item mgmt-spec-key),{\"metadata\":{\"name\":\"kube-root-ca.crt\",\"managedFields\":[{\"manager\":\"kube-controller-manager\",\"operation\":\"Update\"}]}}$(extra ConfigMap envd-system)" ;;
  *" -n envd-system get NetworkPolicy -o json "*) list "$(item default-deny),$(item allow-dns),$(item envd)$(extra NetworkPolicy envd-system)" ;;
  *" -n envd-system get Role -o json "*) list "$(extra Role envd-system | sed 's/^,//')" ;;
  *" -n envd-system get RoleBinding -o json "*) list "$(extra RoleBinding envd-system | sed 's/^,//')" ;;
  *" -n spire-system get Role -o json "*)
    other=""
    [[ -z "${STUB_UNLABELLED:-}" ]] || other='{"metadata":{"name":"spire-server-reader","managedFields":[{"manager":"argocd-controller","operation":"Update"}]}},'
    list "$other$(item envd-records)$(extra Role spire-system)" ;;
  *" -n spire-system get RoleBinding -o json "*) list "$(item envd-records)$(extra RoleBinding spire-system)" ;;
  *" -n spire-system get ServiceAccount -o json "*) list "$(extra ServiceAccount spire-system | sed 's/^,//')" ;;
  *" -n spire-system get Deployment -o json "*) list "$(extra Deployment spire-system | sed 's/^,//')" ;;
  *" -n spire-system get ConfigMap -o json "*) list "$(extra ConfigMap spire-system | sed 's/^,//')" ;;
  *" -n spire-system get NetworkPolicy -o json "*) list "$(extra NetworkPolicy spire-system | sed 's/^,//')" ;;
  *" -n spire-system get "*) list "" ;;
  *" get Namespace -l cell.poc.internal/harness=envd -o json "*) list "$(item envd-system)" ;;
  *" get namespace envd-system -o json "*) echo "{\"metadata\":{\"name\":\"envd-system\",$mine}}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const envdBundle = `apiVersion: v1
kind: Namespace
metadata:
  name: envd-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: envd
  namespace: envd-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: envd-records
  namespace: spire-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: envd-records
  namespace: spire-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: envd
  namespace: envd-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: peer-root
  namespace: envd-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mgmt-spec-key
  namespace: envd-system
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: envd-system
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: envd-system
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: envd
  namespace: envd-system
`

// TestHarnessObjectsByNamespace: the bundle of envd holds objects in envd-system and spire-system. The check runs for both
// namespaces. The Role and RoleBinding in spire-system with the harness label count as owned, so both calls pass. An object
// with the label and a name or a kind that the bundle lacks fails the call for its namespace, in either namespace. An object
// of another owner without the label does not count.
func TestHarnessObjectsByNamespace(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, extra, unlabelled string
		fail                    map[string]string // namespace to the text that the failure holds
	}{
		{name: "the bundle as applied"},
		{name: "an object of the spire-server bundle without the label", unlabelled: "1"},
		{name: "an extra Role in spire-system", extra: "Role/envd-extra@spire-system", fail: map[string]string{"spire-system": "'envd-extra envd-records'"}},
		{name: "an extra RoleBinding in spire-system", extra: "RoleBinding/envd-extra@spire-system", fail: map[string]string{"spire-system": "'envd-extra envd-records'"}},
		{name: "an extra Role in envd-system", extra: "Role/envd-extra@envd-system", fail: map[string]string{"envd-system": "Role objects 'envd-extra'"}},
		{name: "a stray NetworkPolicy in spire-system, a kind that the bundle holds only in envd-system", extra: "NetworkPolicy/envd-stray@spire-system", fail: map[string]string{"spire-system": "NetworkPolicy objects 'envd-stray'"}},
		{name: "a stray ServiceAccount in spire-system", extra: "ServiceAccount/envd-stray@spire-system", fail: map[string]string{"spire-system": "ServiceAccount objects 'envd-stray'"}},
		{name: "an extra ConfigMap in envd-system", extra: "ConfigMap/envd-extra@envd-system", fail: map[string]string{"envd-system": "'envd-extra mgmt-spec-key peer-root'"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(envdKubectl), 0o755); err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(dir, "build", "dev-cp", "bundles", "envd")
			if err := os.MkdirAll(bundle, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte(envdBundle), 0o644); err != nil {
				t.Fatal(err)
			}
			lib, err := filepath.Abs("../../scripts/lib.sh")
			if err != nil {
				t.Fatal(err)
			}
			for _, ns := range []string{"envd-system", "spire-system"} {
				cmd := exec.Command("bash", "-c", `source "$1"; check_harness_objects envd "$2"`, "_", lib, ns)
				cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
					"CELL=dev-cp", "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_EXTRA=" + tc.extra, "STUB_UNLABELLED=" + tc.unlabelled}
				var out bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &out
				err := cmd.Run()
				want, fails := tc.fail[ns]
				if !fails {
					if err != nil {
						t.Errorf("envd %s fails: %v\n%s", ns, err, out.String())
					}
					continue
				}
				if err == nil || !strings.Contains(out.String(), want) {
					t.Errorf("envd %s: err %v, output %q; want a failure that holds %s", ns, err, out.String(), want)
				}
			}
		})
	}
}

// opsKubectl answers the reads of check_harness_objects for namespace cell-ops-system of the component cell-identity.
// The bundle holds a Namespace, a Role, a NetworkPolicy and a ConfigMap in cell-identity-system, so the check lists the
// ConfigMaps of cell-ops-system too. celld writes the objects op-<id> and demo-log there at run time.
// STUB_RECORD describes the ConfigMap that celld wrote: "ok" (label made-by=celld, manager celld), "nolabel" (no
// made-by label), "person" (label made-by=celld, manager kubectl-edit) or "name" (an unexpected name, label made-by=celld).
const opsKubectl = `#!/usr/bin/env bash
set -euo pipefail
args=" $* "
mine='"labels":{"cell.poc.internal/harness":"cell-identity"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]'
item() { printf '{"metadata":{"name":"%s",%s}}' "$1" "$mine"; }
celld() { # celld <name> <label> <manager>
  printf '{"metadata":{"name":"%s","labels":{%s},"managedFields":[{"manager":"%s","operation":"Update"}]}}' "$1" "$2" "$3"
}
made='"poc.internal/made-by":"celld"'
list() { printf '{"items":[%s]}\n' "$1"; }
records() {
  local id=0123456789abcdef0123456789abcdef
  case "${STUB_RECORD:-ok}" in
    ok) printf '%s,%s' "$(celld "op-$id" "$made" celld)" "$(celld demo-log "$made" celld)" ;;
    nolabel) celld "op-$id" "" celld ;;
    person) celld "op-$id" "$made" kubectl-edit ;;
    name) celld "op-other" "$made" celld ;;
  esac
}
case "$args" in
  *" -n cell-identity-system get ConfigMap -o json "*) list "$(item mgmt-op-key),$(item spire-agent)" ;;
  *" -n cell-identity-system get Role -o json "*) list "" ;;
  *" -n cell-identity-system get NetworkPolicy -o json "*) list "" ;;
  *" -n cell-ops-system get ConfigMap -o json "*)
    list "$(item kube-root-ca.crt | sed 's/"labels":{[^}]*},//; s/"manager":"kubectl","operation":"Apply"/"manager":"kube-controller-manager","operation":"Update"/'),$(records)" ;;
  *" -n cell-ops-system get Role -o json "*) list "$(item celld-ops)" ;;
  *" -n cell-ops-system get NetworkPolicy -o json "*) list "$(item default-deny)" ;;
  *" get Namespace -l cell.poc.internal/harness=cell-identity -o json "*) list "$(item cell-identity-system),$(item cell-ops-system)" ;;
  *" get namespace cell-ops-system -o json "*) echo "{\"metadata\":{\"name\":\"cell-ops-system\",$mine}}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const opsBundle = `apiVersion: v1
kind: Namespace
metadata:
  name: cell-identity-system
---
apiVersion: v1
kind: Namespace
metadata:
  name: cell-ops-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mgmt-op-key
  namespace: cell-identity-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-agent
  namespace: cell-identity-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: celld-ops
  namespace: cell-ops-system
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: cell-ops-system
`

// TestHarnessObjectsIgnoresCelldRecords: the ConfigMaps op-<id> and demo-log that celld writes in cell-ops-system carry
// the label poc.internal/made-by=celld and only the field manager celld. The check passes with them, and prints no
// delete hint. A record without the label, with another field manager or with another name still fails, so a person
// cannot hide an object there.
func TestHarnessObjectsIgnoresCelldRecords(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, record string
		want         string // text of the failure, empty when the check passes
	}{
		{name: "an op record and demo-log of celld", record: "ok"},
		{name: "a record without the made-by label", record: "nolabel", want: "ConfigMap objects 'op-0123456789abcdef0123456789abcdef'"},
		{name: "a record that another manager wrote", record: "person", want: "ConfigMap objects 'op-0123456789abcdef0123456789abcdef'"},
		{name: "a ConfigMap with another name", record: "name", want: "ConfigMap objects 'op-other'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(opsKubectl), 0o755); err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(dir, "build", "dev-cell-1", "bundles", "cell-identity")
			if err := os.MkdirAll(bundle, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte(opsBundle), 0o644); err != nil {
				t.Fatal(err)
			}
			lib, err := filepath.Abs("../../scripts/lib.sh")
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `source "$1"; check_harness_objects cell-identity cell-ops-system`, "_", lib)
			cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=dev-cell-1", "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_RECORD=" + tc.record}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err = cmd.Run()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("the check fails with a record of celld: %v\n%s", err, out.String())
				}
				if strings.Contains(strings.ToLower(out.String()), "delete") || out.Len() != 0 {
					t.Fatalf("the check printed %q for a record of celld, want no output and no delete hint", out.String())
				}
				return
			}
			if err == nil || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("err %v, output %q; want a failure that holds %s", err, out.String(), tc.want)
			}
		})
	}
}
