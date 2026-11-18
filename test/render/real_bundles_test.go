package render

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const harnessLabel = "cell.poc.internal/harness"

// conftestData writes the data directory that conftest loads: allow.json as data.allow, the context of the
// role and the component as data.context, the live harness NetworkPolicies as data.harness and, when scope is
// not nil, the scope of custom kinds as data.scope. conftest loads a file under the path of its directory.
// It reads no data.scope unless the test gives it one.
func conftestData(t *testing.T, role, component string, nps []map[string]string, scope map[string][]string) string {
	t.Helper()
	dir := t.TempDir()
	allow, err := os.ReadFile("../../internal/bundle/allow.json")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) {
		b, ok := v.([]byte)
		if !ok {
			var err error
			if b, err = json.Marshal(v); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "data.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("allow", allow)
	write("context", map[string]string{"role": role, "component": component})
	if nps == nil {
		nps = []map[string]string{}
	}
	write("harness", map[string]any{"networkPolicies": nps})
	if scope != nil {
		write("scope", scope)
	}
	return dir
}

// conftestDeny runs conftest with bundle.rego over files and returns the deny messages of each file, as a
// sorted list of "reason:detail". Every file appears in the result, with an empty list when nothing is denied.
func conftestDeny(t *testing.T, data string, files ...string) map[string][]string {
	t.Helper()
	testtool.Need(t, "conftest")
	args := append([]string{"test", "--policy", "../../internal/bundleapply/policy", "--namespace", "bundle.allow",
		"--data", data, "--output", "json", "--no-color"}, files...)
	cmd := exec.Command("conftest", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// Exit status 1 means that a file has a failure, which the output lists. Any other failure is an error.
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			t.Fatalf("conftest: %v\n%s", err, stderr.String())
		}
	}
	var res []struct {
		Filename string
		Failures []struct{ Msg string }
	}
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("conftest output is not JSON: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	out := map[string][]string{}
	for _, f := range files {
		out[f] = []string{}
	}
	for _, r := range res {
		for _, f := range r.Failures {
			out[r.Filename] = append(out[r.Filename], f.Msg)
		}
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

// harnessPolicies lists the NetworkPolicies with a harness label in the harness and link components of a
// cluster, as the engine reads them from the live cluster.
func harnessPolicies(cr *clusterRender) []map[string]string {
	var out []map[string]string
	for _, c := range cr.components {
		if c.kind == "bundle" {
			continue
		}
		for _, o := range c.objs {
			if o["kind"] != "NetworkPolicy" {
				continue
			}
			if _, ok := lookup(o, "metadata", "labels", harnessLabel); !ok {
				continue
			}
			out = append(out, map[string]string{"namespace": fmt.Sprint(lookupOr(o, "metadata", "namespace")), "name": fmt.Sprint(lookupOr(o, "metadata", "name"))})
		}
	}
	return out
}

func harnessRefs(nps []map[string]string) bundleapply.HarnessRefs {
	var h bundleapply.HarnessRefs
	for _, n := range nps {
		h.NetworkPolicies = append(h.NetworkPolicies, bundleapply.ObjectRef{Namespace: n["namespace"], Name: n["name"]})
	}
	return h
}

// scopeOf lists the custom kinds that the CRDs among objs define, as the engine reads them (group/Kind).
func scopeOf(objs []map[string]any) map[string][]string {
	scope := map[string][]string{"cluster": {}, "namespaced": {}}
	for _, o := range objs {
		if o["kind"] != "CustomResourceDefinition" {
			continue
		}
		spec, _ := o["spec"].(map[string]any)
		names, _ := spec["names"].(map[string]any)
		key := fmt.Sprintf("%v/%v", spec["group"], names["kind"])
		switch spec["scope"] {
		case "Cluster":
			scope["cluster"] = append(scope["cluster"], key)
		case "Namespaced":
			scope["namespaced"] = append(scope["namespaced"], key)
		}
	}
	return scope
}

// TestRealBundlesPassPolicy runs conftest with bundle.rego over the canonical form of every rendered bundle of
// the roles cell and cp, with allow.json, the role and the component, and the harness NetworkPolicies of the
// cluster, and expects no denial. Each render must first have a canonical form, as the applier requires. The
// scope of custom kinds comes from the CRDs of the same bundle, as the engine learns it. The test runs the
// engine over the same objects too.
func TestRealBundlesPassPolicy(t *testing.T) {
	for _, cr := range renderAll(t) {
		role := roleOf[cr.name]
		if role == "open" {
			continue
		}
		t.Run(cr.name, func(t *testing.T) {
			nps := harnessPolicies(cr)
			checker, err := bundleapply.NewChecker(role, bundle.DefaultPolicy(), harnessRefs(nps))
			if err != nil {
				t.Fatal(err)
			}
			checked := 0
			for _, c := range cr.components {
				if c.kind != "bundle" {
					continue
				}
				checked++
				t.Run(c.name, func(t *testing.T) {
					objs, err := bundle.DecodeManifests([]byte(c.raw), bundle.MaxObjects)
					if err != nil {
						t.Fatalf("the render of %s has no canonical form: %v", c.name, err)
					}
					canon, err := bundle.Canonical(objs)
					if err != nil {
						t.Fatal(err)
					}
					file := filepath.Join(t.TempDir(), bundle.ManifestsFile)
					if err := os.WriteFile(file, canon, 0o644); err != nil {
						t.Fatal(err)
					}
					// Finding: the policy refuses the locked AppProject default of the argocd bundle (appproject_ok lists
					// only the names of appProjects in allow.json). The test holds that one object apart and expects
					// exactly this refusal from both evaluators, so a fix of the policy fails the test and removes
					// the exception. Every other object must pass.
					var rest, locked []map[string]any
					for _, o := range objs {
						if o["kind"] == "AppProject" && lookupOr(o, "metadata", "name") == "default" {
							locked = append(locked, o)
						} else {
							rest = append(rest, o)
						}
					}
					if len(locked) > 0 && c.name != "argocd" {
						t.Fatalf("%s holds an AppProject default", c.name)
					}
					writeFile := func(name string, objs []map[string]any) string {
						body, err := bundle.Canonical(objs)
						if err != nil {
							t.Fatal(err)
						}
						f := filepath.Join(t.TempDir(), name)
						if err := os.WriteFile(f, body, 0o644); err != nil {
							t.Fatal(err)
						}
						return f
					}
					data := conftestData(t, role, c.name, nps, scopeOf(objs))
					restFile := writeFile("rest.yaml", rest)
					if denied := conftestDeny(t, data, restFile)[restFile]; len(denied) > 0 {
						t.Errorf("conftest refuses %s of %s (%s): %v", c.name, cr.name, role, denied)
					}
					decoded, err := bundleapply.DecodeCanonical(canon, bundle.MaxObjects)
					if err != nil {
						t.Fatalf("the engine refuses the canonical bytes of %s: %v", c.name, err)
					}
					err = checker.Check(context.Background(), c.name, decoded)
					var refusal *bundleapply.Refusal
					switch {
					case len(locked) == 0 && err != nil:
						t.Errorf("the engine refuses %s of %s: %v", c.name, cr.name, err)
					case len(locked) > 0:
						lockedFile := writeFile("locked.yaml", locked)
						if got := conftestDeny(t, data, lockedFile)[lockedFile]; !slices.Equal(got, []string{"component_not_allowed:kind"}) {
							t.Errorf("conftest on AppProject default gives %v, want the known refusal component_not_allowed:kind (finding)", got)
						}
						if !errors.As(err, &refusal) || refusal.Detail != "kind" || refusal.Object != "AppProject/argocd/default" {
							t.Errorf("the engine gives %v on the argocd bundle, want the known refusal kind for AppProject/argocd/default (finding)", err)
						}
					}
				})
			}
			if checked == 0 {
				t.Fatal("the cluster has no bundle")
			}
		})
	}
}

// engineVerdict returns "" when the engine accepts the objects, and "reason:detail" of its refusal. The bool
// is true when the refusal comes from the decoder, which the policy does not hold.
func engineVerdict(t *testing.T, checker *bundleapply.Checker, component string, data []byte) (string, bool) {
	t.Helper()
	objs, err := bundleapply.Decode(data, bundle.MaxObjects)
	if err == nil {
		err = checker.Check(context.Background(), component, objs)
	} else {
		var r *bundleapply.Refusal
		if !errors.As(err, &r) {
			t.Fatalf("decode: %v", err)
		}
		return r.Reason + ":" + r.Detail, true
	}
	if err == nil {
		return "", false
	}
	var r *bundleapply.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("check: %v", err)
	}
	return r.Reason + ":" + r.Detail, false
}

// TestConftestMatchesEngine compares, for each fixture of the policy tests of the engine and for several
// roles and components, the deny set of conftest with the refusal of bundleapply.Checker. An object that the
// engine accepts has an empty deny set, and an object that it refuses has a deny set that holds its refusal
// (the engine reports the most specific denial of its set).
//
// Two differences are part of the contract, and the test states each one.
//   - conftest has no data.scope, so it treats a custom kind as unknown scope unless the test passes the scope
//     of the CRDs that the engine learns from the bundle.
//   - The decoder refuses a document with items (items_list), a List (list) and other layouts before it runs
//     the policy, so the policy alone accepts them. The applier and bundlectl decode first, so no render
//     reaches conftest in that form.
func TestConftestMatchesEngine(t *testing.T) {
	testtool.Need(t, "conftest")
	fixtures, err := filepath.Glob("../../internal/bundleapply/testdata/*/*.yaml")
	if err != nil || len(fixtures) < 50 {
		t.Fatalf("fixtures: %d, %v", len(fixtures), err)
	}
	refs := map[string][]map[string]string{
		"cell": {{"namespace": "cell-system", "name": "plane-celld-store"}, {"namespace": "argocd", "name": "argocd-agent"}},
		"cp":   {{"namespace": "relay-system", "name": "plane-cells"}, {"namespace": "spire-system", "name": "plane-cells"}},
		"open": nil,
	}
	pairs := []struct{ role, component string }{
		{"cell", "namespaces"}, {"cell", "apps-sample"}, {"cell", "argocd"}, {"cell", "network-policy"}, {"cell", "nope"},
		{"cp", "spire-server"}, {"cp", "namespaces"}, {"cp", "external-secrets"}, {"open", "namespaces"},
	}
	for _, p := range pairs {
		t.Run(p.role+"/"+p.component, func(t *testing.T) {
			checker, err := bundleapply.NewChecker(p.role, bundle.DefaultPolicy(), harnessRefs(refs[p.role]))
			if err != nil {
				t.Fatal(err)
			}
			denied := conftestDeny(t, conftestData(t, p.role, p.component, refs[p.role], nil), fixtures...)
			compared := 0
			for _, f := range fixtures {
				data, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				verdict, fromDecoder := engineVerdict(t, checker, p.component, data)
				set := denied[f]
				name := filepath.Base(filepath.Dir(f)) + "/" + strings.TrimSuffix(filepath.Base(f), ".yaml")
				switch {
				case fromDecoder:
					t.Errorf("%s: the decoder refuses a fixture: %s", name, verdict)
				case verdict == "" && len(set) != 0:
					t.Errorf("%s: the engine accepts, conftest denies %v", name, set)
				case verdict != "" && !slices.Contains(set, verdict):
					t.Errorf("%s: the engine refuses %s, conftest denies %v", name, verdict, set)
				case verdict != "" && len(set) == 1 && set[0] != verdict:
					t.Errorf("%s: the engine refuses %s, conftest denies only %v", name, verdict, set)
				}
				compared++
			}
			if compared != len(fixtures) {
				t.Fatalf("compared %d of %d fixtures", compared, len(fixtures))
			}
		})
	}

	// The decoder differences. conftest accepts each document, and the engine refuses it before the policy.
	t.Run("items_list", func(t *testing.T) {
		checker, err := bundleapply.NewChecker("cell", bundle.DefaultPolicy(), bundleapply.HarnessRefs{})
		if err != nil {
			t.Fatal(err)
		}
		// conftest is what the policy alone says. The ConfigMap with items passes it, which is the dangerous case:
		// Argo CD would apply the inner ClusterRoleBinding. The two list kinds are unknown kinds to the policy.
		cases := map[string]struct {
			doc, detail string
			conftest    []string
		}{
			"configmap_with_items": {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: apps-demo}\n" +
				"items:\n- apiVersion: rbac.authorization.k8s.io/v1\n  kind: ClusterRoleBinding\n  metadata: {name: x}\n", "items_list", []string{}},
			"configmaplist": {"apiVersion: v1\nkind: ConfigMapList\nmetadata: {name: a, namespace: apps-demo}\nitems: []\n", "items_list",
				[]string{"component_not_allowed:kind_unknown_scope"}},
			"list": {"apiVersion: v1\nkind: List\nitems: []\n", "list", []string{"component_not_allowed:kind_unknown_scope"}},
		}
		dir := t.TempDir()
		var files []string
		for name, c := range cases {
			f := filepath.Join(dir, name+".yaml")
			if err := os.WriteFile(f, []byte(c.doc), 0o644); err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		set := conftestDeny(t, conftestData(t, "cell", "apps-sample", nil, nil), files...)
		for name, c := range cases {
			f := filepath.Join(dir, name+".yaml")
			verdict, fromDecoder := engineVerdict(t, checker, "apps-sample", []byte(c.doc))
			if verdict != "component_not_allowed:"+c.detail || !fromDecoder {
				t.Errorf("%s: the engine gives %q (decoder %v), want component_not_allowed:%s from the decoder", name, verdict, fromDecoder, c.detail)
			}
			if !slices.Equal(set[f], c.conftest) {
				t.Errorf("%s: conftest denies %v, want %v (the policy holds no rule for %s)", name, set[f], c.conftest, c.detail)
			}
		}
		// A render goes through the decoder before conftest, so these forms never reach it.
		for name, c := range cases {
			if _, err := bundle.DecodeManifests([]byte(c.doc), 10); err == nil {
				t.Errorf("%s: bundle.DecodeManifests accepts it, so bundlectl would pack it", name)
			}
		}
	})

	t.Run("custom_kind_scope", func(t *testing.T) {
		crd := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: widgets.example.invalid}\n" +
			"spec: {group: example.invalid, scope: Namespaced, names: {kind: Widget, plural: widgets}}\n"
		cr := "apiVersion: example.invalid/v1\nkind: Widget\nmetadata: {name: w, namespace: apps-demo}\n"
		file := filepath.Join(t.TempDir(), "set.yaml")
		if err := os.WriteFile(file, []byte(crd+"---\n"+cr), 0o644); err != nil {
			t.Fatal(err)
		}
		checker, err := bundleapply.NewChecker("cell", bundle.DefaultPolicy(), bundleapply.HarnessRefs{})
		if err != nil {
			t.Fatal(err)
		}
		if verdict, _ := engineVerdict(t, checker, "namespaces", []byte(crd+"---\n"+cr)); verdict != "" {
			t.Errorf("the engine refuses a CRD with its custom resource: %s", verdict)
		}
		without := conftestDeny(t, conftestData(t, "cell", "namespaces", nil, nil), file)[file]
		if !slices.Equal(without, []string{"component_not_allowed:kind_unknown_scope"}) {
			t.Errorf("conftest with no scope denies %v, want only kind_unknown_scope for the custom resource", without)
		}
		with := conftestDeny(t, conftestData(t, "cell", "namespaces", nil, map[string][]string{"cluster": {}, "namespaced": {"example.invalid/Widget"}}), file)[file]
		if len(with) != 0 {
			t.Errorf("conftest with the scope of the CRD denies %v, want none", with)
		}
	})
}

// TestNoClusterNetworkPolicyKinds checks that no rendered object is an AdminNetworkPolicy, a
// BaselineAdminNetworkPolicy or a ClusterNetworkPolicy, and that no class of allow.json lists them.
func TestNoClusterNetworkPolicyKinds(t *testing.T) {
	banned := []string{"AdminNetworkPolicy", "BaselineAdminNetworkPolicy", "ClusterNetworkPolicy"}
	for _, cr := range renderAll(t) {
		for _, c := range cr.components {
			for _, o := range c.objs {
				if k, _ := o["kind"].(string); slices.Contains(banned, k) {
					t.Errorf("%s/%s renders %s", cr.name, c.name, objName(o))
				}
			}
		}
	}
	for name, class := range bundle.DefaultPolicy().Classes {
		for _, k := range append(slices.Clone(class.ClusterKinds), class.NamespacedKinds...) {
			for _, b := range banned {
				if k == b || strings.HasSuffix(k, "/"+b) {
					t.Errorf("class %s allows %s", name, k)
				}
			}
		}
	}
}
