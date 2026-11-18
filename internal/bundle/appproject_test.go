package bundle

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExpectedAppProjectSpec(t *testing.T) {
	p := DefaultPolicy()
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
	if strings.Contains(string(b), `"namespace":"argocd"`) {
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
