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
// made-by label), "outside" (a celld record in cell-identity-system), "person" (label made-by=celld, manager kubectl-edit) or "name" (an unexpected name, label made-by=celld).
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
  *" -n cell-identity-system get ConfigMap -o json "*)
    extra=""
    [[ "${STUB_RECORD:-ok}" != outside ]] || extra=",$(celld op-0123456789abcdef0123456789abcdef "$made" celld)"
    list "$(item mgmt-op-key),$(item spire-agent)$extra" ;;
  *" -n cell-identity-system get Role -o json "*) list "" ;;
  *" -n cell-identity-system get NetworkPolicy -o json "*) list "" ;;
  *" -n cell-ops-system get ConfigMap -o json "*)
    list "$(item kube-root-ca.crt | sed 's/"labels":{[^}]*},//; s/"manager":"kubectl","operation":"Apply"/"manager":"kube-controller-manager","operation":"Update"/'),$(records)" ;;
  *" -n cell-ops-system get Role -o json "*) list "$(item celld-ops)" ;;
  *" -n cell-ops-system get NetworkPolicy -o json "*) list "$(item default-deny)" ;;
  *" get Namespace -l cell.poc.internal/harness=cell-identity -o json "*) list "$(item cell-identity-system),$(item cell-ops-system)" ;;
  *" get namespace cell-identity-system -o json "*) echo "{\"metadata\":{\"name\":\"cell-identity-system\",$mine}}" ;;
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
		ns           string // the namespace to check, cell-ops-system when empty
		want         string // text of the failure, empty when the check passes
	}{
		{name: "an op record and demo-log of celld", record: "ok"},
		{name: "a record without the made-by label", record: "nolabel", want: "ConfigMap objects 'op-0123456789abcdef0123456789abcdef'"},
		{name: "a record that another manager wrote", record: "person", want: "ConfigMap objects 'op-0123456789abcdef0123456789abcdef'"},
		{name: "a celld record outside cell-ops-system is reported", record: "outside", ns: "cell-identity-system", want: "ConfigMap objects 'mgmt-op-key op-0123456789abcdef0123456789abcdef spire-agent'"},
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
			ns := tc.ns
			if ns == "" {
				ns = "cell-ops-system"
			}
			cmd := exec.Command("bash", "-c", `source "$1"; check_harness_objects cell-identity "$2"`, "_", lib, ns)
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

// registryKubectl answers the reads of check_harness_objects for a view component that owns its namespace. The bundle
// holds the Namespace and ConfigMap registry-signer. mgmtd publishes ConfigMap cell-registry at run time.
// STUB_REGISTRY describes it: "ok" (label made-by=mgmtd only, manager mgmtd), "harness" (the harness label of the
// component too, as an old render left it), "nolabel" (no made-by label), "person" (manager kubectl-edit) or "name"
// (another name, label made-by=mgmtd). STUB_NS and STUB_COMP name the namespace and the component.
const registryKubectl = `#!/usr/bin/env bash
set -euo pipefail
args=" $* "
mine="\"labels\":{\"cell.poc.internal/harness\":\"$STUB_COMP\"},\"managedFields\":[{\"manager\":\"kubectl\",\"operation\":\"Apply\"}]"
item() { printf '{"metadata":{"name":"%s",%s}}' "$1" "$mine"; }
reg() { # reg <name> <labels> <manager>
  printf '{"metadata":{"name":"%s","labels":{%s},"managedFields":[{"manager":"%s","operation":"Update"}]}}' "$1" "$2" "$3"
}
made='"poc.internal/made-by":"mgmtd"'
list() { printf '{"items":[%s]}\n' "$1"; }
registry() {
  case "${STUB_REGISTRY:-ok}" in
    ok) reg cell-registry "$made" mgmtd ;;
    harness) reg cell-registry "$made,\"cell.poc.internal/harness\":\"$STUB_COMP\"" mgmtd ;;
    nolabel) reg cell-registry "" mgmtd ;;
    person) reg cell-registry "$made" kubectl-edit ;;
    name) reg cell-registry-other "$made" mgmtd ;;
  esac
}
case "$args" in
  *" -n $STUB_NS get ConfigMap -o json "*) list "$(item registry-signer),$(registry)" ;;
  *" get Namespace -l cell.poc.internal/harness=$STUB_COMP -o json "*) list "$(item "$STUB_NS")" ;;
  *" get namespace $STUB_NS -o json "*) echo "{\"metadata\":{\"name\":\"$STUB_NS\",$mine}}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestHarnessObjectsAcceptsPublishedRegistry: ConfigMap cell-registry, which mgmtd publishes into a view namespace,
// carries only the label poc.internal/made-by=mgmtd and the field manager mgmtd. check_harness_objects accepts it by
// name and prints no delete hint. An object that keeps the harness label of an old render, one without the marker, one
// that another manager wrote, and one with another name are reported.
func TestHarnessObjectsAcceptsPublishedRegistry(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	// telemetry-gateway shares observability-system with other bundles, so its bundle does not hold the Namespace.
	for _, comp := range []struct {
		name, ns, cluster string
		shared            bool
	}{
		{"central-view", "central-view-system", "management", false},
		{"mesh-view-hub", "mesh-view-system", "management", false},
		{"telemetry-gateway", "observability-system", "management", true},
	} {
		for _, tc := range []struct {
			name, registry, want string
		}{
			{name: "the registry that mgmtd published", registry: "ok"},
			{name: "an old render left the harness label", registry: "harness", want: "ConfigMap objects 'cell-registry registry-signer'"},
			{name: "no made-by label", registry: "nolabel", want: "ConfigMap objects 'cell-registry registry-signer'"},
			{name: "another manager wrote it", registry: "person", want: "ConfigMap objects 'cell-registry registry-signer'"},
			{name: "another name", registry: "name", want: "ConfigMap objects 'cell-registry-other registry-signer'"},
		} {
			if comp.shared && tc.registry == "name" {
				continue // a shared namespace lists only the objects that carry the harness label or a runtime name
			}
			if comp.shared && (tc.registry == "nolabel" || tc.registry == "person") {
				tc.want = "runtime ConfigMap objects 'cell-registry'"
			}
			t.Run(comp.name+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(registryKubectl), 0o755); err != nil {
					t.Fatal(err)
				}
				bundle := filepath.Join(dir, "build", comp.cluster, "bundles", comp.name)
				if err := os.MkdirAll(bundle, 0o755); err != nil {
					t.Fatal(err)
				}
				manifests := "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + comp.ns + "\n---\n"
				if comp.shared {
					manifests = ""
				}
				manifests += "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: registry-signer\n  namespace: " + comp.ns + "\n"
				if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte(manifests), 0o644); err != nil {
					t.Fatal(err)
				}
				lib, err := filepath.Abs("../../scripts/lib.sh")
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", "-c", `source "$1"; check_harness_objects "$2" "$3"`, "_", lib, comp.name, comp.ns)
				cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
					"CELL=" + comp.cluster, "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_REGISTRY=" + tc.registry, "STUB_NS=" + comp.ns, "STUB_COMP=" + comp.name}
				var out bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &out
				err = cmd.Run()
				if tc.want == "" {
					if err != nil || out.Len() != 0 {
						t.Fatalf("the check fails with the registry of mgmtd: %v\n%s", err, out.String())
					}
					return
				}
				if err == nil || !strings.Contains(out.String(), tc.want) {
					t.Fatalf("err %v, output %q; want a failure that holds %s", err, out.String(), tc.want)
				}
			})
		}
	}
}

// controllerKubectl answers the reads of check_harness_objects for the component cell-controller, which owns namespace
// cell-controller-system. The bundle holds the Namespace, ConfigMaps hostsvc-pin and mgmt-spec-key, and the Role and RoleBinding
// envd-steps for ServiceAccount envd. At run time envd writes ConfigMap cell-steps and the cell controller writes step-status.
// STUB_STEPS describes the two: "ok" (each carries only the made-by label of its writer and the field manager of its writer),
// "harness" (cell-steps also carries the harness label), "nomarker" (cell-steps has no made-by label), "swapped" (cell-steps
// carries the marker and manager of the cell controller), "person" (step-status has the manager kubectl-edit), "crossed" (step-status has the manager envd), "other" (a third
// ConfigMap with the marker envd) or "name" (cell-steps under another name). STUB_EXTRA=<kind>/<name>@<label> adds one object of
// that kind with the harness label <label>.
const controllerKubectl = `#!/usr/bin/env bash
set -euo pipefail
args=" $* "
mine='"labels":{"cell.poc.internal/harness":"cell-controller"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]'
item() { printf '{"metadata":{"name":"%s",%s}}' "$1" "$mine"; }
rt() { # rt <name> <labels> <manager>
  printf '{"metadata":{"name":"%s","labels":{%s},"managedFields":[{"manager":"%s","operation":"Update"}]}}' "$1" "$2" "$3"
}
envd='"poc.internal/made-by":"envd"'
ctl='"poc.internal/made-by":"cell-controller"'
steps() {
  case "${STUB_STEPS:-ok}" in
    ok) printf '%s,%s' "$(rt cell-steps "$envd" envd)" "$(rt step-status "$ctl" cell-controller)" ;;
    harness) printf '%s,%s' "$(rt cell-steps "$envd,\"cell.poc.internal/harness\":\"cell-controller\"" envd)" "$(rt step-status "$ctl" cell-controller)" ;;
    nomarker) printf '%s,%s' "$(rt cell-steps "" envd)" "$(rt step-status "$ctl" cell-controller)" ;;
    swapped) printf '%s,%s' "$(rt cell-steps "$ctl" cell-controller)" "$(rt step-status "$ctl" cell-controller)" ;;
    person) printf '%s,%s' "$(rt cell-steps "$envd" envd)" "$(rt step-status "$ctl" kubectl-edit)" ;;
    crossed) printf '%s,%s' "$(rt cell-steps "$envd" envd)" "$(rt step-status "$ctl" envd)" ;;
    other) printf '%s,%s,%s' "$(rt cell-steps "$envd" envd)" "$(rt step-status "$ctl" cell-controller)" "$(rt step-other "$envd" envd)" ;;
    name) printf '%s,%s' "$(rt cell-steps-old "$envd" envd)" "$(rt step-status "$ctl" cell-controller)" ;;
  esac
}
extra() { # extra <kind> prints ,<item> when STUB_EXTRA names that kind
  local want="${STUB_EXTRA:-}"
  [[ "$want" == "$1/"* ]] || return 0
  want="${want#*/}"
  printf ',{"metadata":{"name":"%s","labels":{"cell.poc.internal/harness":"%s"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]}}' "${want%@*}" "${want#*@}"
}
list() { printf '{"items":[%s]}\n' "$1"; }
case "$args" in
  *" -n cell-controller-system get ConfigMap -o json "*)
    list "$(item hostsvc-pin),$(item mgmt-spec-key),{\"metadata\":{\"name\":\"kube-root-ca.crt\",\"managedFields\":[{\"manager\":\"kube-controller-manager\",\"operation\":\"Update\"}]}},$(steps)$(extra ConfigMap)" ;;
  *" -n cell-controller-system get Role -o json "*) list "$(item envd-steps)$(extra Role)" ;;
  *" -n cell-controller-system get RoleBinding -o json "*) list "$(item envd-steps)$(extra RoleBinding)" ;;
  *" get Namespace -l cell.poc.internal/harness=cell-controller -o json "*) list "$(item cell-controller-system)" ;;
  *" get namespace cell-controller-system -o json "*) echo "{\"metadata\":{\"name\":\"cell-controller-system\",$mine}}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const controllerBundle = `apiVersion: v1
kind: Namespace
metadata:
  name: cell-controller-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: hostsvc-pin
  namespace: cell-controller-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mgmt-spec-key
  namespace: cell-controller-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: envd-steps
  namespace: cell-controller-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: envd-steps
  namespace: cell-controller-system
`

// runControllerObjects runs check_harness_objects for the cell controller with the fake kubectl above.
func runControllerObjects(t *testing.T, steps, extra string) (string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(controllerKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "build", "dev-cp", "bundles", "cell-controller")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte(controllerBundle), 0o644); err != nil {
		t.Fatal(err)
	}
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; check_harness_objects cell-controller cell-controller-system`, "_", lib)
	cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cp", "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_STEPS=" + steps, "STUB_EXTRA=" + extra}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return out.String(), err
}

// TestHarnessObjectsAcceptsStepConfigMaps: cell-controller-system holds two ConfigMaps that the bundle cannot hold. envd writes
// cell-steps with the field manager envd and the marker label poc.internal/made-by=envd, and the cell controller writes
// step-status with its own manager and marker. check_harness_objects accepts each by name, marker and manager, and prints no
// delete hint. A ConfigMap with the right name and the marker or the manager of the other writer, one with no marker, one that
// a person edited, one with the harness label of the bundle and one with another name are reported.
func TestHarnessObjectsAcceptsStepConfigMaps(t *testing.T) {
	for _, tc := range []struct {
		name, steps, want string
	}{
		{name: "both ConfigMaps as their writers made them", steps: "ok"},
		{name: "cell-steps with the harness label of the bundle", steps: "harness", want: "ConfigMap objects 'cell-steps hostsvc-pin mgmt-spec-key'"},
		{name: "cell-steps with no marker", steps: "nomarker", want: "ConfigMap objects 'cell-steps hostsvc-pin mgmt-spec-key'"},
		{name: "cell-steps with the marker and manager of the cell controller", steps: "swapped", want: "ConfigMap objects 'cell-steps hostsvc-pin mgmt-spec-key'"},
		{name: "step-status that a person edited", steps: "person", want: "ConfigMap objects 'hostsvc-pin mgmt-spec-key step-status'"},
		{name: "step-status that envd wrote", steps: "crossed", want: "ConfigMap objects 'hostsvc-pin mgmt-spec-key step-status'"},
		{name: "a third ConfigMap with the marker of envd", steps: "other", want: "ConfigMap objects 'hostsvc-pin mgmt-spec-key step-other'"},
		{name: "cell-steps under another name", steps: "name", want: "ConfigMap objects 'cell-steps-old hostsvc-pin mgmt-spec-key'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runControllerObjects(t, tc.steps, "")
			if tc.want == "" {
				if err != nil || out != "" {
					t.Fatalf("the check fails with the step ConfigMaps: %v\n%s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("err %v, output %q; want a failure that holds %s", err, out, tc.want)
			}
		})
	}
}

// TestHarnessObjectsOwnedNamespaceRefusesOtherLabels: cell-controller-system is an owned namespace. A Role or RoleBinding that carries
// the harness label of another component, such as the old Role envd-steps of an envd render, is an extra object, and the check
// fails. The Role envd-steps of the bundle itself, with the label cell-controller, passes.
func TestHarnessObjectsOwnedNamespaceRefusesOtherLabels(t *testing.T) {
	for _, tc := range []struct {
		name, extra, want string
	}{
		{name: "the bundle as applied"},
		{name: "a Role of envd", extra: "Role/envd-records@envd", want: "Role objects 'envd-records envd-steps'"},
		{name: "a RoleBinding of envd", extra: "RoleBinding/envd-records@envd", want: "RoleBinding objects 'envd-records envd-steps'"},
		{name: "a Role of the cell controller that the bundle lacks", extra: "Role/cell-controller@cell-controller", want: "Role objects 'cell-controller envd-steps'"},
		{name: "a ConfigMap of envd", extra: "ConfigMap/envd-extra@envd", want: "ConfigMap objects 'envd-extra hostsvc-pin mgmt-spec-key'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runControllerObjects(t, "ok", tc.extra)
			if tc.want == "" {
				if err != nil || out != "" {
					t.Fatalf("the check fails on the bundle as applied: %v\n%s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("err %v, output %q; want a failure that holds %s", err, out, tc.want)
			}
		})
	}
}
