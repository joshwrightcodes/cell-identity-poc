package bundle_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

func canonObjs() []map[string]any {
	return []map[string]any{
		{"kind": "ConfigMap", "apiVersion": "v1", "metadata": map[string]any{"name": "a", "namespace": "apps-demo"}, "data": map[string]any{"k": "v\nw: x"}},
		{"kind": "Secret", "apiVersion": "v1", "metadata": map[string]any{"name": "b", "namespace": "apps-demo"}},
	}
}

func TestCanonicalForm(t *testing.T) {
	got, err := bundle.Canonical(canonObjs())
	if err != nil {
		t.Fatal(err)
	}
	want := "apiVersion: v1\ndata:\n  k: |-\n    v\n    w: x\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: apps-demo\n" +
		"---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: b\n  namespace: apps-demo\n"
	if string(got) != want {
		t.Fatalf("canonical form\n got %q\nwant %q", got, want)
	}
	if strings.HasPrefix(string(got), "---") || strings.HasPrefix(string(got), "{") {
		t.Fatal("the canonical form starts with a separator or a flow mapping")
	}
	one, err := bundle.Canonical(canonObjs()[:1])
	if err != nil || strings.Contains(string(one), "---") {
		t.Fatalf("one object: %q %v", one, err)
	}
	none, err := bundle.Canonical(nil)
	if err != nil || len(none) != 0 {
		t.Fatalf("no objects: %q %v", none, err)
	}
}

func TestPackAcceptsCanonicalManifests(t *testing.T) {
	body, err := bundle.Canonical(canonObjs())
	if err != nil {
		t.Fatal(err)
	}
	a, err := bundle.Pack(map[string][]byte{bundle.ManifestsFile: body})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "testdata/manifests.golden", a)
	got, err := bundle.UnpackComponent(a.Layer, 1<<20)
	if err != nil || string(got) != string(body) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestPackRefusesNonCanonicalManifests(t *testing.T) {
	for name, body := range map[string]string{
		"flow style":       "{apiVersion: v1, kind: ConfigMap, metadata: {name: a}}\n",
		"json first":       `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a"}}` + "\n" + "kind: Secret\n",
		"leading sep":      "---\nkind: Secret\n",
		"trailing sep":     "kind: Secret\n---\n",
		"empty document":   "kind: Secret\n---\n---\nkind: ConfigMap\n",
		"unsorted keys":    "kind: Secret\napiVersion: v1\n",
		"comment":          "# note\nkind: Secret\n",
		"crlf":             "kind: Secret\r\napiVersion: v1\r\n",
		"bom":              "\xef\xbb\xbfkind: Secret\n",
		"utf16":            "\xff\xfek\x00i\x00",
		"anchor":           "a: &x 1\nb: *x\n",
		"no final newline": "kind: Secret",
		"not an object":    "- a\n- b\n",
		"scalar":           "just text\n",
	} {
		_, err := bundle.Pack(map[string][]byte{bundle.ManifestsFile: []byte(body)})
		if !errors.Is(err, bundle.ErrNotCanonical) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Other files are not manifests.
	if _, err := bundle.Pack(map[string][]byte{"root.yaml": []byte("b: 1\na: 2\n")}); err != nil {
		t.Fatalf("a root file is not checked: %v", err)
	}
}

func TestCheckCanonical(t *testing.T) {
	good, _ := bundle.Canonical(canonObjs())
	if err := bundle.CheckCanonical(good); err != nil {
		t.Fatal(err)
	}
	if err := bundle.CheckCanonical(append([]byte("# c\n"), good...)); !errors.Is(err, bundle.ErrNotCanonical) {
		t.Fatalf("comment: %v", err)
	}
}
