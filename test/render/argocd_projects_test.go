package render

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

// readObject reads a file with one object.
func readObject(t *testing.T, path string) object {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	objs, err := parseDocs(string(data))
	if err != nil || len(objs) != 1 {
		t.Fatalf("read %s: %d objects, %v", path, len(objs), err)
	}
	return objs[0]
}

// roleOf gives the bundle role of each cluster, written here as the topology gives it.
var roleOf = map[string]string{"dev-cell-1": "cell", "dev-cell-2": "cell", "dev-cp": "cp", "management": "open"}

// jsonOf returns the JSON form of v, so that two values compare after the same round trip.
func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var back any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(back)
	return string(b)
}

// blacklistNames are the harness cluster objects that each role keeps out of every project, written here
// as the target design gives them, apart from allow.json.
var blacklistNames = map[string][]string{
	"cell": {"ValidatingAdmissionPolicy/bundles-spare-harness", "ValidatingAdmissionPolicyBinding/bundles-spare-harness",
		"ValidatingAdmissionPolicy/bundles-app-limits", "ValidatingAdmissionPolicyBinding/bundles-app-limits"},
	"cp": {"ValidatingAdmissionPolicy/bundles-spare-harness", "ValidatingAdmissionPolicyBinding/bundles-spare-harness"},
}

// TestAppProjectsRepeatAllowList checks that each project of the roles cell and cp equals the spec that
// the applier expects for its class, carries the blacklist names and the SHA-256 of the allow-list, and
// that no other project except default exists. management keeps the project cell of M7.
func TestAppProjectsRepeatAllowList(t *testing.T) {
	policy := bundle.DefaultPolicy()
	m7 := readObject(t, "../../components/argocd/project.yaml")
	for _, cr := range renderAll(t) {
		t.Run(cr.name, func(t *testing.T) {
			role := roleOf[cr.name]
			if role == "" {
				t.Fatalf("no role for cluster %s", cr.name)
			}
			projects := map[string]object{}
			for _, o := range clusterComponent(t, cr.name, "argocd") {
				if o["kind"] == "AppProject" {
					projects[get[string](t, o, "metadata", "name")] = o
				}
			}
			if role == "open" {
				if len(projects) != 2 || projects["cell"] == nil || projects["default"] == nil {
					t.Fatalf("management holds the projects %v, want cell and default", slices.Sorted(mapKeys(projects)))
				}
				if got, want := jsonOf(t, get[any](t, projects["cell"], "spec")), jsonOf(t, get[any](t, m7, "spec")); got != want {
					t.Errorf("the project cell of management is\n%s\nwant the M7 spec\n%s", got, want)
				}
				if _, ok := lookup(projects["cell"], "metadata", "annotations", "poc.internal/allow-sha256"); ok {
					t.Error("the M7 project carries the allow-list annotation")
				}
				return
			}
			want := policy.Roles[role].AppProjects
			if got := slices.Sorted(mapKeys(projects)); !slices.Equal(got, append(slices.Clone(want), "default")) {
				t.Fatalf("the projects are %v, want %v and default", got, want)
			}
			for _, name := range want {
				spec, err := bundle.ExpectedAppProjectSpec(role, name, policy)
				if err != nil {
					t.Fatal(err)
				}
				p := projects[name]
				if got, w := jsonOf(t, get[any](t, p, "spec")), jsonOf(t, spec); got != w {
					t.Errorf("project %s spec is\n%s\nwant\n%s", name, got, w)
				}
				if got, _ := lookup(p, "metadata", "annotations", "poc.internal/allow-sha256"); got != bundle.AllowSHA256() {
					t.Errorf("project %s allow-sha256 = %v, want %s", name, got, bundle.AllowSHA256())
				}
				var names []string
				for _, e := range get[[]any](t, p, "spec", "clusterResourceBlacklist") {
					names = append(names, fmt.Sprintf("%v/%v", lookupOr(e, "kind"), lookupOr(e, "name")))
					if lookupOr(e, "group") != "admissionregistration.k8s.io" {
						t.Errorf("project %s blacklists group %v", name, lookupOr(e, "group"))
					}
				}
				if !reflect.DeepEqual(names, blacklistNames[role]) {
					t.Errorf("project %s blacklists %v, want %v", name, names, blacklistNames[role])
				}
				if got, _ := lookup(p, "metadata", "namespace"); got != "argocd" {
					t.Errorf("project %s namespace = %v, want argocd", name, got)
				}
			}
		})
	}
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
