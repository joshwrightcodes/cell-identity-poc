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
