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

// bundleVerifyKubectl answers the reads of the bundle checks of cell:verify from files in $STUB_DIR. A case changes one file. The
// stub copies the standard input of kubectl diff to diff.in, so a test can read which guards the check renders.
const bundleVerifyKubectl = `#!/usr/bin/env bash
d="$STUB_DIR"
echo "kubectl $*" >>"$d/calls"
case " $* " in
  *" get configmap bundle-state "*) [[ -f "$d/state.json" ]] && cat "$d/state.json"; exit 0 ;;
  *" diff --server-side "*) cat >"$d/diff.in"; cat "$d/diff.out"; exit "$(cat "$d/diff.rc")" ;;
  *" get validatingadmissionpolicy "*) name="${*: -3:1}"; [[ -f "$d/live-policy-$name.json" ]] || { echo "NotFound" >&2; exit 1; }; cat "$d/live-policy-$name.json" ;;
  *" get validatingadmissionpolicybinding "*) name="${*: -3:1}"; [[ -f "$d/live-binding-$name.json" ]] || { echo "NotFound" >&2; exit 1; }; cat "$d/live-binding-$name.json" ;;
  *" -n cell-system get statefulset/bundle-store -o json "*) cat "$d/store.json" ;;
  *" -n argocd get deployment/argocd-repo-server -o json "*) cat "$d/repo-server.json" ;;
  *" get networkpolicy "*)
    name="${*: -3:1}"
    [[ -f "$d/policy-$name.json" ]] || { echo "Error from server (NotFound): networkpolicies \"$name\" not found" >&2; exit 1; }
    cat "$d/policy-$name.json" ;;
  *" -n argocd get appproject "*)
    name="${*: -3:1}"
    [[ -f "$d/project-$name" ]] && cat "$d/project-$name"
    exit 0 ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// bundleVerifyMise answers mise run bundle -- verify (the exit status and the output come from files) and mise run mgmt -- status.
const bundleVerifyMise = `#!/usr/bin/env bash
d="$STUB_DIR"
echo "mise CELL=${CELL:-} $*" >>"$d/calls"
case "$*" in
  "run bundle -- verify --target "*) cat "$d/verify.out"; exit "$(cat "$d/verify.rc")" ;;
  "run mgmt -- status") [[ -s "$d/mgmt-status.json" ]] || exit 1; cat "$d/mgmt-status.json" ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

const (
	allowA        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	allowB        = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	bundleRootD   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	bundleWriter  = "--writer=system:serviceaccount:cell-identity-system:celld"
	bundleWriterC = "--writer=system:serviceaccount:envd-system:envd"
)

// bundleStoreJSON is the StatefulSet bundle-store with the arguments of store-proxy.
func bundleStoreJSON(args ...string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = `"` + a + `"`
	}
	return `{"spec":{"template":{"spec":{"containers":[{"name":"bundle-store","image":"docker.io/library/registry:3"},` +
		`{"name":"store-proxy","image":"localhost:5001/cell-proxy@sha256:` + strings.Repeat("a", 64) + `","args":[` + strings.Join(quoted, ",") + `]}]}}}}`
}

const repoServerJSON = `{"spec":{"template":{"spec":{"containers":[{"name":"argocd-repo-server","image":"quay.io/argoproj/argocd:v3"},` +
	`{"name":"store-token","image":"localhost:5001/cell-proxy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","args":["token-client","--listen=127.0.0.1:5000","--upstream=bundle-store.cell-system.svc.cluster.local:5000"]}]}}}}`

// TestVerifyBundleChecks runs each bundle check of cell:verify with fakes: once on a healthy cluster and once for each mismatch. A
// mismatch prints its reason and the command to run.
func TestVerifyBundleChecks(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib", "internal/bundle"} {
		copyFiles(t, root, d)
	}
	stub, bin := filepath.Join(root, "stub"), filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"kubectl": bundleVerifyKubectl, "mise": bundleVerifyMise} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeLiveStubs(t, bin)
	if err := os.WriteFile(filepath.Join(bin, "images.env"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	signedState := `{"source":"signed","state":"healthy","root":{"digest":"` + bundleRootD + `"}}`
	policy := func(label string) string {
		if label == "" {
			return `{"metadata":{"labels":{}}}`
		}
		return `{"metadata":{"labels":{"cell.poc.internal/harness":"` + label + `"}}}`
	}
	cellStatus := func(sha string) string {
		return `{"cells":[{"name":"dev-cell-1","bundleStatus":{"state":"healthy","allowSHA256":"` + sha + `"}},{"name":"dev-cell-2"}]}`
	}
	cpStatus := func(sha string) string {
		return `{"cells":[],"planeBundleStatus":{"state":"healthy","allowSHA256":"` + sha + `"}}`
	}
	with2 := func(a, b map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range a {
			out[k] = v
		}
		for k, v := range b {
			out[k] = v
		}
		return out
	}
	// guardLive writes the live guards of a role as the render of bundle-guard.sh gives them, one file for each object.
	guardLive := func(role string) map[string]string {
		raw, err := exec.Command("bash", filepath.Join(root, "components", "lib", "bundle-guard.sh"), role).Output()
		if err != nil {
			t.Fatal(err)
		}
		files := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			if line == "" || line == "---" {
				continue
			}
			kind, name := "policy", ""
			if strings.Contains(line, `"kind":"ValidatingAdmissionPolicyBinding"`) {
				kind = "binding"
			}
			i := strings.Index(line, `"name":"`)
			name = line[i+len(`"name":"`):]
			name = name[:strings.Index(name, `"`)]
			files["live-"+kind+"-"+name+".json"] = line
		}
		return files
	}
	cellFiles := func() map[string]string {
		return with2(guardLive("cell"), map[string]string{
			"state.json": signedState, "verify.out": `{"target":"dev-cell-1"}`, "verify.rc": "0", "diff.out": "", "diff.rc": "0",
			"store.json":        bundleStoreJSON("token", "--audience=bundle-store", "--reader=system:serviceaccount:argocd:argocd-repo-server", bundleWriter),
			"repo-server.json":  repoServerJSON,
			"policy-celld.json": policy("cell-identity"), "policy-argocd-agent.json": policy("argocd-agent"), "policy-otel-uplink.json": policy("otel-uplink"),
			"policy-mesh-view.json": policy("mesh-view"), "policy-plane-celld-store.json": policy("cell-identity"),
			"project-cell": allowA, "project-cell-app": allowA, "mgmt-status.json": cellStatus(allowA),
		})
	}
	cpFiles := func() map[string]string {
		return with2(guardLive("cp"), map[string]string{
			"state.json": signedState, "verify.out": `{"target":"dev-cp"}`, "verify.rc": "0", "diff.out": "", "diff.rc": "0",
			"store.json":       bundleStoreJSON("token", "--audience=bundle-store", "--reader=system:serviceaccount:argocd:argocd-repo-server", bundleWriterC),
			"repo-server.json": repoServerJSON,
			"policy-envd.json": policy("envd"), "policy-plane-envd-store.json": policy("envd"), "policy-plane-cells.json": policy("envd"),
			"policy-plane-envd.json": policy("envd"), "policy-plane-workloads.json": policy("envd"), "policy-plane-upstream.json": policy("envd"),
			"project-cell": allowA, "mgmt-status.json": cpStatus(allowA),
		})
	}
	mgmtFiles := func() map[string]string {
		return map[string]string{"store.json": bundleStoreJSON("token", "--audience=bundle-store", "--reader=system:serviceaccount:argocd:argocd-repo-server"),
			"repo-server.json": repoServerJSON}
	}
	with := func(base map[string]string, change map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range change {
			out[k] = v
		}
		return out
	}
	publish := func(c string) string { return "Run: mise run bundle -- publish --target " + c + " --wait" }
	up := func(c string) string { return "Run: CELL=" + c + " mise run cell:up" }
	for _, tc := range []struct {
		name, check, cell string
		files             map[string]string
		want              []string // substrings of the output; nil means the check passes
		deny              []string // substrings that the output of a failed check does not hold
		diff              []string // substrings of the guards that the check renders
		noDiff            []string // substrings that the rendered guards do not hold
	}{
		// check_signed_root
		{name: "signed root ok in a cell", check: "check_signed_root", cell: "dev-cell-1", files: cellFiles()},
		{name: "signed root ok in dev-cp", check: "check_signed_root", cell: "dev-cp", files: cpFiles()},
		{name: "signed root: cosign does not verify the root", check: "check_signed_root", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"verify.rc": "1", "verify.out": "error: cosign does not verify the root sha256:11 of dev-cell-1 against the current key of mgmtd (no matching signatures), so it is not trusted. If the key rotated, run: mise run bundle -- cosign --target dev-cell-1"}),
			want:  []string{"cosign does not verify the root", "bundle -- cosign"}, deny: []string{"bundle -- publish"}},
		{name: "signed root: the mirror is unreachable", check: "check_signed_root", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"verify.rc": "1", "verify.out": "error: could not read the address of the registry mirror"}),
			want:  []string{"registry mirror", "Run: mise run harness:status"}, deny: []string{"bundle -- publish"}},
		{name: "signed root: the state is a bootstrap state", check: "check_signed_root", cell: "dev-cp",
			files: with(cpFiles(), map[string]string{"verify.rc": "1", "verify.out": "error: the bundle state of dev-cp has source 'bootstrap', so its root is a bootstrap root that nobody signed"}),
			want:  []string{"source 'bootstrap'", publish("dev-cp")}},
		// check_bundle_guard
		{name: "bundle guard ok in a cell: both guards", check: "check_bundle_guard", cell: "dev-cell-1", files: cellFiles(),
			diff: []string{"bundles-spare-harness", "bundles-app-limits", "cell.poc.internal/harness: cell-identity"}, noDiff: []string{"harness: envd"}},
		{name: "bundle guard ok in dev-cp: one guard", check: "check_bundle_guard", cell: "dev-cp", files: cpFiles(),
			diff: []string{"bundles-spare-harness", "cell.poc.internal/harness: envd"}, noDiff: []string{"bundles-app-limits", "harness: cell-identity"}},
		{name: "bundle guard: a guard differs from the render", check: "check_bundle_guard", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"diff.rc": "1", "diff.out": "-  failurePolicy: Fail\n+  failurePolicy: Ignore"}),
			want:  []string{"failurePolicy: Ignore", "bundles-spare-harness and bundles-app-limits", up("dev-cell-1")}},
		{name: "bundle guard: a guard is absent in dev-cp", check: "check_bundle_guard", cell: "dev-cp",
			files: with(cpFiles(), map[string]string{"diff.rc": "1", "diff.out": "+kind: ValidatingAdmissionPolicy"}),
			want:  []string{"bundles-spare-harness", up("dev-cp")}},
		{name: "bundle guard: a binding of a cell is narrowed by a namespace selector", check: "check_bundle_guard", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"live-binding-bundles-spare-harness.json": `{"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicyBinding","metadata":{"name":"bundles-spare-harness"},"spec":{"policyName":"bundles-spare-harness","validationActions":["Deny"],"matchResources":{"namespaceSelector":{"matchLabels":{"a":"b"}}}}}`}),
			want:  []string{"bundles-spare-harness", "narrows", up("dev-cell-1")}},
		{name: "bundle guard: a policy has an extra match condition", check: "check_bundle_guard", cell: "dev-cp",
			files: with(cpFiles(), map[string]string{"live-policy-bundles-spare-harness.json": strings.Replace(cpFiles()["live-policy-bundles-spare-harness.json"], `"matchConditions":[`, `"matchConditions":[{"name":"extra","expression":"false"},`, 1)}),
			want:  []string{"bundles-spare-harness", "differs", up("dev-cp")}},
		{name: "bundle guard: the binding is absent", check: "check_bundle_guard", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"live-binding-bundles-app-limits.json": ""}),
			want:  []string{"bundles-app-limits", "cannot read", up("dev-cell-1")}},
		{name: "bundle guard: kubectl diff fails", check: "check_bundle_guard", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"diff.rc": "2", "diff.out": "error: the server is down"}),
			want:  []string{"kubectl diff failed", "the server is down"}},
		// check_store_proxy
		{name: "store proxy ok in a cell", check: "check_store_proxy", cell: "dev-cell-1", files: cellFiles()},
		{name: "store proxy ok in dev-cp", check: "check_store_proxy", cell: "dev-cp", files: cpFiles()},
		{name: "store proxy ok in management: no writer", check: "check_store_proxy", cell: "management", files: mgmtFiles()},
		{name: "store proxy: management has a writer", check: "check_store_proxy", cell: "management",
			files: with(mgmtFiles(), map[string]string{"store.json": bundleStoreJSON("token", "--audience=bundle-store", "--reader=system:serviceaccount:argocd:argocd-repo-server", bundleWriter)}),
			want:  []string{"management has no bundle writer", bundleWriter, up("management")}},
		{name: "store proxy: a cell has no writer", check: "check_store_proxy", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"store.json": bundleStoreJSON("token", "--audience=bundle-store", "--reader=system:serviceaccount:argocd:argocd-repo-server")}),
			want:  []string{"want " + bundleWriter, up("dev-cell-1")}},
		{name: "store proxy: a cell admits the writer of dev-cp", check: "check_store_proxy", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"store.json": bundleStoreJSON("token", "--audience=bundle-store", "--reader=system:serviceaccount:argocd:argocd-repo-server", bundleWriter, bundleWriterC)}),
			want:  []string{bundleWriterC, up("dev-cell-1")}},
		{name: "store proxy: dev-cp admits the writer of a cell", check: "check_store_proxy", cell: "dev-cp",
			files: with(cpFiles(), map[string]string{"store.json": bundleStoreJSON("token", "--audience=bundle-store", "--reader=system:serviceaccount:argocd:argocd-repo-server", bundleWriter)}),
			want:  []string{"want " + bundleWriterC, up("dev-cp")}},
		{name: "store proxy: the reader is another account", check: "check_store_proxy", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"store.json": bundleStoreJSON("token", "--audience=bundle-store", "--reader=system:serviceaccount:argocd:argocd-server", bundleWriter)}),
			want:  []string{"--reader=system:serviceaccount:argocd:argocd-repo-server", up("dev-cell-1")}},
		{name: "store proxy: the audience differs", check: "check_store_proxy", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"store.json": bundleStoreJSON("token", "--audience=other", "--reader=system:serviceaccount:argocd:argocd-repo-server", bundleWriter)}),
			want:  []string{"--audience=bundle-store", up("dev-cell-1")}},
		{name: "store proxy: the repo server has no token client", check: "check_store_proxy", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"repo-server.json": `{"spec":{"template":{"spec":{"containers":[{"name":"argocd-repo-server","image":"quay.io/argoproj/argocd:v3"}]}}}}`}),
			want:  []string{"store-token", "argocd-repo-server", up("dev-cell-1")}},
		// check_plane_policies
		{name: "plane policies ok in a cell", check: "check_plane_policies", cell: "dev-cell-1", files: cellFiles()},
		{name: "plane policies ok in dev-cp", check: "check_plane_policies", cell: "dev-cp", files: cpFiles()},
		{name: "plane policies: a policy is absent in a cell", check: "check_plane_policies", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"policy-plane-celld-store.json": ""}),
			want:  []string{"NetworkPolicy cell-system/plane-celld-store is absent", up("dev-cell-1")}},
		{name: "plane policies: a policy has no harness label", check: "check_plane_policies", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"policy-celld.json": policy("")}),
			want:  []string{"NetworkPolicy cell-identity-system/celld has no label cell.poc.internal/harness", up("dev-cell-1")}},
		{name: "plane policies: a policy of dev-cp is absent", check: "check_plane_policies", cell: "dev-cp",
			files: with(cpFiles(), map[string]string{"policy-plane-upstream.json": ""}),
			want:  []string{"NetworkPolicy relay-system/plane-upstream is absent", up("dev-cp")}},
		{name: "plane policies: a policy of dev-cp has no harness label", check: "check_plane_policies", cell: "dev-cp",
			files: with(cpFiles(), map[string]string{"policy-envd.json": policy("")}),
			want:  []string{"NetworkPolicy envd-system/envd has no label cell.poc.internal/harness", up("dev-cp")}},
		// check_allow_list_version
		{name: "allow list ok in a cell", check: "check_allow_list_version", cell: "dev-cell-1", files: cellFiles()},
		{name: "allow list ok in dev-cp", check: "check_allow_list_version", cell: "dev-cp", files: cpFiles()},
		{name: "allow list: a project carries another digest", check: "check_allow_list_version", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"project-cell-app": allowB}),
			want:  []string{"AppProject cell-app", allowB, allowA, publish("dev-cell-1")}},
		{name: "allow list: a project has no annotation", check: "check_allow_list_version", cell: "dev-cp",
			files: with(cpFiles(), map[string]string{"project-cell": ""}),
			want:  []string{"AppProject cell", "no annotation", allowA, publish("dev-cp")}},
		{name: "allow list: the applier runs another allow list", check: "check_allow_list_version", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"mgmt-status.json": cellStatus(allowB)}),
			want:  []string{"reports allowSHA256 " + allowB, allowA, publish("dev-cell-1")}},
		{name: "allow list: the plane applier of dev-cp runs another allow list", check: "check_allow_list_version", cell: "dev-cp",
			files: with(cpFiles(), map[string]string{"mgmt-status.json": cpStatus(allowB)}),
			want:  []string{"reports allowSHA256 " + allowB, allowA, publish("dev-cp")}},
		{name: "allow list: the applier reports none", check: "check_allow_list_version", cell: "dev-cell-2", files: cellFiles(),
			want: []string{"holds no allowSHA256 for dev-cell-2", publish("dev-cell-2")}},
		{name: "allow list: mgmtd does not answer", check: "check_allow_list_version", cell: "dev-cell-1",
			files: with(cellFiles(), map[string]string{"mgmt-status.json": ""}),
			want:  []string{"could not read mise run mgmt -- status"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, _ := filepath.Glob(filepath.Join(stub, "*"))
			for _, e := range entries {
				_ = os.Remove(e)
			}
			for k, v := range tc.files {
				if v == "" && (strings.HasPrefix(k, "policy-") || strings.HasPrefix(k, "live-")) {
					continue
				}
				if err := os.WriteFile(filepath.Join(stub, k), []byte(v), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; source "$1/components/lib/peer-root.sh"; source "$1/components/lib/hostsvc-pin.sh"
source "$1/components/lib/mgmt-key.sh"; source "$1/scripts/verify-lib.sh"
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
			} else {
				if err == nil {
					t.Fatalf("the check passes though %s", tc.name)
				}
				for _, w := range tc.want {
					if !strings.Contains(out.String(), w) {
						t.Errorf("output %q lacks %q", out.String(), w)
					}
				}
				for _, d := range tc.deny {
					if strings.Contains(out.String(), d) {
						t.Errorf("output %q holds %q", out.String(), d)
					}
				}
			}
			if tc.diff != nil || tc.noDiff != nil {
				in, _ := os.ReadFile(filepath.Join(stub, "diff.in"))
				for _, w := range tc.diff {
					if !strings.Contains(string(in), w) {
						t.Errorf("the guards that the check renders lack %q:\n%s", w, in)
					}
				}
				for _, w := range tc.noDiff {
					if strings.Contains(string(in), w) {
						t.Errorf("the guards that the check renders hold %q:\n%s", w, in)
					}
				}
			}
		})
	}
}

// TestVerifyRunsBundleChecks reads scripts/verify.sh: check_store_proxy runs for every role, and the other four checks run only in the branch of the roles cell and
// cp, so management (role open) runs the store proxy check alone.
func TestVerifyRunsBundleChecks(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, `case "$(bundle_role)" in`)
	end := strings.Index(text[start+1:], "\nesac")
	if start < 0 || end < 0 {
		t.Fatal("scripts/verify.sh has no case on the bundle role")
	}
	branch := text[start : start+1+end]
	outside := text[:start] + text[start+1+end:]
	if !strings.Contains(branch, "cell | cp)") {
		t.Error("the branch of the roles cell and cp is missing")
	}
	for _, fn := range []string{"check_signed_root", "check_bundle_guard", "check_plane_policies", "check_allow_list_version"} {
		if !strings.Contains(branch, " "+fn+"\n") {
			t.Errorf("the branch of the roles cell and cp does not run %s", fn)
		}
		if strings.Contains(outside, " "+fn+"\n") {
			t.Errorf("scripts/verify.sh runs %s outside the branch of the roles cell and cp, so management would run it", fn)
		}
	}
	if !strings.Contains(outside, " check_store_proxy\n") || strings.Contains(branch, "check_store_proxy") {
		t.Error("check_store_proxy must run for every role, before the branch")
	}
}
