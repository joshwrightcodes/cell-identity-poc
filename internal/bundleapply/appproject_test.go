package bundleapply

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

func projectObject(t *testing.T, name string, spec map[string]any) Object {
	t.Helper()
	body, err := yaml.Marshal(map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "AppProject",
		"metadata": map[string]any{"name": name, "namespace": "argocd"},
		"spec":     spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	objs, err := Decode(body, 10)
	if err != nil || len(objs) != 1 {
		t.Fatalf("decode: %v", err)
	}
	return objs[0]
}

func TestExpectedAppProjectSpec(t *testing.T) {
	p := bundle.DefaultPolicy()
	app, err := ExpectedAppProjectSpec("cell", "cell-app", p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(app)
	for _, frag := range []string{
		`"namespace":"apps-demo"`, `"kind":"Deployment"`, `"group":"apps"`, `"kind":"ConfigMap"`,
		`"name":"bundles-app-limits"`, `"name":"bundles-spare-harness"`, `oci://127.0.0.1:5000/bundles/*`,
	} {
		if !strings.Contains(string(b), frag) {
			t.Errorf("cell-app spec lacks %s: %s", frag, b)
		}
	}
	if strings.Contains(string(b), "argocd") && strings.Contains(string(b), `"namespace":"argocd"`) {
		t.Errorf("cell-app reaches argocd: %s", b)
	}
	plat, err := ExpectedAppProjectSpec("cell", "cell", p)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := plat["destinations"].([]any); len(d) != len(p.Classes["platform"].DestinationNamespaces) {
		t.Errorf("destinations = %v", plat["destinations"])
	}
	cp, err := ExpectedAppProjectSpec("cp", "cell", p)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := json.Marshal(cp)
	if strings.Contains(string(cb), "bundles-app-limits") || !strings.Contains(string(cb), "spire-system") {
		t.Errorf("cp spec = %s", cb)
	}
	for _, c := range [][2]string{{"cp", "cell-app"}, {"cell", "default"}, {"open", "cell"}, {"nope", "cell"}} {
		if _, err := ExpectedAppProjectSpec(c[0], c[1], p); err == nil {
			t.Errorf("%v has an expected spec", c)
		}
	}
}

func TestCheckAppProjects(t *testing.T) {
	p := bundle.DefaultPolicy()
	spec := func(role, name string) map[string]any {
		s, err := ExpectedAppProjectSpec(role, name, p)
		if err != nil {
			t.Fatal(err)
		}
		// A round trip through YAML gives the shape that Decode gives.
		b, _ := yaml.Marshal(s)
		var out map[string]any
		_ = yaml.Unmarshal(b, &out)
		return out
	}
	cases := []struct {
		name   string
		role   string
		object string
		mutate func(map[string]any)
		ok     bool
	}{
		{"expected cell", "cell", "cell", nil, true},
		{"expected cell-app", "cell", "cell-app", nil, true},
		{"expected cp", "cp", "cell", nil, true},
		{"lists in another order", "cell", "cell-app", func(s map[string]any) {
			d := s["destinations"].([]any)
			slices.Reverse(d)
		}, true},
		{"widened destinations", "cell", "cell-app", func(s map[string]any) {
			s["destinations"] = append(s["destinations"].([]any), map[string]any{"server": "https://kubernetes.default.svc", "namespace": "argocd"})
		}, false},
		{"wildcard destination", "cell", "cell-app", func(s map[string]any) {
			s["destinations"] = []any{map[string]any{"server": "*", "namespace": "*"}}
		}, false},
		{"cluster kind added", "cell", "cell-app", func(s map[string]any) {
			s["clusterResourceWhitelist"] = []any{map[string]any{"group": "*", "kind": "*"}}
		}, false},
		{"source repos widened", "cell", "cell", func(s map[string]any) { s["sourceRepos"] = []any{"*"} }, false},
		{"blacklist removed", "cell", "cell", func(s map[string]any) { delete(s, "clusterResourceBlacklist") }, false},
		{"extra field", "cell", "cell", func(s map[string]any) { s["roles"] = []any{map[string]any{"name": "admin"}} }, false},
		{"missing spec", "cell", "cell", func(s map[string]any) { clear(s) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := spec(tc.role, tc.object)
			if tc.mutate != nil {
				tc.mutate(s)
			}
			objs := []Object{projectObject(t, tc.object, s)}
			err := checkAppProjects(tc.role, p, objs)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if err.Reason != op.ReasonComponentNotAllowed || err.Detail != "appproject_spec" {
				t.Fatalf("refusal = %+v", err)
			}
		})
	}
	t.Run("other objects and unknown names", func(t *testing.T) {
		cm := Object{APIVersion: "v1", Kind: "ConfigMap", Name: "x"}
		if err := checkAppProjects("cell", p, []Object{cm}); err != nil {
			t.Fatal(err)
		}
		if err := checkAppProjects("cell", p, []Object{projectObject(t, "default", spec("cell", "cell"))}); err == nil || err.Detail != "appproject_spec" {
			t.Fatalf("unknown name: %v", err)
		}
	})
}
