package bundle_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

const (
	mGood = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: good\n  namespace: argocd\ndata: {a: b}\n"
	mJSON = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"visible","namespace":"argocd"}}`
	mNP   = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: agent, namespace: argocd}\nspec: {podSelector: {}}\n"
)

func detailOf(err error) string {
	var me *bundle.ManifestError
	if errors.As(err, &me) {
		return me.Detail
	}
	return "NOT A MANIFEST ERROR: " + fmt.Sprint(err)
}

func TestDecodeManifestsRefusals(t *testing.T) {
	two := mGood + "---\n" + mNP
	for name, tc := range map[string]struct{ in, detail string }{
		"bom":                {"\xef\xbb\xbf" + mGood, "layout"},
		"bom in the middle":  {mGood + "---\n\xef\xbb\xbf" + mNP, "layout"},
		"utf16 bom":          {"\xff\xfea\x00", "layout"},
		"nul":                {mGood + "\x00", "layout"},
		"invalid utf8":       {"apiVersion: v1\nkind: Config\xffMap\nmetadata: {name: a}\n", "layout"},
		"json first":         {mJSON + "\n", "layout"},
		"flow first":         {"{apiVersion: v1, kind: ConfigMap, metadata: {name: a}}\n", "layout"},
		"array first":        {"[a]\n", "layout"},
		"lone cr":            {"apiVersion: v1\rkind: ConfigMap\rmetadata: {name: a}\r", "layout"},
		"nel":                {"apiVersion: v1\u0085kind: ConfigMap\n", "layout"},
		"line separator":     {"apiVersion: v1\u2028kind: ConfigMap\n", "layout"},
		"paragraph sep":      {"apiVersion: v1\u2029kind: ConfigMap\n", "layout"},
		"ls in a string":     {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd}\ndata: {k: \"a\u2028b\"}\n", "layout"},
		"ps in a string":     {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd}\ndata: {k: \"a\u2029b\"}\n", "layout"},
		"dots line":          {mGood + "...\n", "layout"},
		"dots then yaml":     {mGood + "...\n" + mNP, "layout"},
		"comment json yaml":  {"# c\n" + mJSON + "\n" + mNP, "layout"},
		"anchor":             {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {x: &a 1}\n", "layout"},
		"alias":              {"apiVersion: v1\nkind: ConfigMap\nmetadata: &m {name: a}\ndata: {x: *m}\n", "layout"},
		"merge key":          {"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  <<: {namespace: argocd}\n  name: a\n", "layout"},
		"custom tag":         {"apiVersion: v1\nkind: !foo ConfigMap\nmetadata: {name: a}\n", "layout"},
		"str tag":            {"apiVersion: v1\nkind: !!str ConfigMap\nmetadata: {name: a}\n", "layout"},
		"duplicate key":      {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd, namespace: b}\n", "layout"},
		"no kind":            {"apiVersion: v1\nmetadata: {name: a}\n", "layout"},
		"no name":            {"apiVersion: v1\nkind: ConfigMap\nmetadata: {}\n", "layout"},
		"bad labels":         {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, labels: {k: 1}}\n", "layout"},
		"two slashes":        {"apiVersion: a/b/c\nkind: ConfigMap\nmetadata: {name: a}\n", "layout"},
		"scalar":             {"text\n", "layout"},
		"kind List":          {"apiVersion: v1\nkind: List\nitems: []\n", "list"},
		"kind List no items": {"apiVersion: v1\nkind: List\n", "list"},
		"items":              {"apiVersion: v1\nkind: ConfigMapList\nmetadata: {name: a}\nitems: []\n", "items_list"},
		"items null":         {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\nitems: null\n", "items_list"},
		"items in later":     {mGood + "---\napiVersion: v1\nkind: Secret\nmetadata: {name: a}\nitems: []\n", "items_list"},
	} {
		if _, err := bundle.DecodeManifests([]byte(tc.in), 10); detailOf(err) != tc.detail {
			t.Errorf("%s: want %s, got %v", name, tc.detail, err)
		}
	}
	_ = two
}

func TestDecodeManifestsAccepts(t *testing.T) {
	for name, in := range map[string]string{
		"quoted merge key": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd, \"<<\": x}\n",
		"comment first":    "# c\n" + mGood,
		"crlf":             strings.ReplaceAll(mGood, "\n", "\r\n"),
		"block scalar":     "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd}\ndata:\n  k: |\n    ---\n    ...\n",
		"two documents":    mGood + "---\n" + mNP,
		"empty documents":  "# comment\n---\n---\n" + mGood + "---\n",
	} {
		if _, err := bundle.DecodeManifests([]byte(in), 10); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	objs, err := bundle.DecodeManifests([]byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: null}\n"), 10)
	if err != nil || len(objs) != 1 {
		t.Fatal(err)
	}
	if _, has := objs[0]["metadata"].(map[string]any)["namespace"]; has {
		t.Error("a null namespace stays in the object")
	}
}

func TestDecodeManifestsLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 11; i++ {
		fmt.Fprintf(&sb, "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: c%d}\n", i)
	}
	if objs, err := bundle.DecodeManifests([]byte(sb.String()), 11); err != nil || len(objs) != 11 {
		t.Fatalf("11 of 11: %d %v", len(objs), err)
	}
	if _, err := bundle.DecodeManifests([]byte(sb.String()), 10); detailOf(err) != "too_large" {
		t.Fatalf("11 of 10: %v", err)
	}
}

func TestDecodeCanonicalManifests(t *testing.T) {
	objs, err := bundle.DecodeManifests([]byte(mGood+"---\n"+mNP), 10)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := bundle.Canonical(objs)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bundle.DecodeCanonical(canon, 10); err != nil || len(got) != 2 {
		t.Fatalf("canonical: %d %v", len(got), err)
	}
	for name, in := range map[string]string{
		"key order":  mGood,
		"comment":    "# c\n" + string(canon),
		"leading":    "---\n" + string(canon),
		"trailing":   string(canon) + "---\n",
		"crlf":       strings.ReplaceAll(string(canon), "\n", "\r\n"),
		"no newline": strings.TrimSuffix(string(canon), "\n"),
	} {
		if _, err := bundle.DecodeCanonical([]byte(in), 10); detailOf(err) != "not_canonical" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := bundle.DecodeCanonical([]byte(mJSON+"\n"+mNP), 10); detailOf(err) != "layout" {
		t.Errorf("json first: %v", err)
	}
}

// Pack refuses the bytes that the applier refuses: the moved checks of the decoder apply to a
// publisher as well.
func TestPackRefusesWhatTheApplierRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"ls in a value":   "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: argocd\ndata:\n  k: 'a\u2028b'\n",
		"ps in a key":     "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: argocd\ndata:\n  'a\u2029b': c\n",
		"ls in a label":   "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  labels:\n    k: 'a\u2028b'\n  name: a\n  namespace: argocd\n",
		"ls in a top key": "apiVersion: v1\nkind: ConfigMap\n'x\u2028y': 1\nmetadata:\n  name: a\n",
		"namespace null":  "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: null\n",
		"kind List":       "apiVersion: v1\nitems: []\nkind: List\n",
		"items field":     "apiVersion: v1\nitems: []\nkind: ConfigMapList\nmetadata:\n  name: a\n",
		"empty object":    "{}\n",
		"no name":         "apiVersion: v1\nkind: ConfigMap\nmetadata: {}\n",
	} {
		if _, err := bundle.Pack(map[string][]byte{bundle.ManifestsFile: []byte(body)}); !errors.Is(err, bundle.ErrNotCanonical) {
			t.Errorf("%s: %v", name, err)
		}
	}
	over := strings.Repeat("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n", 1)
	_ = over
}

func TestCanonicalRefusesWhatHasNoCanonicalForm(t *testing.T) {
	for name, o := range map[string]map[string]any{
		"ls in a value":  {"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "a"}, "data": map[string]any{"k": "a\u2028b"}},
		"null namespace": {"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "a", "namespace": nil}},
		"items":          {"apiVersion": "v1", "kind": "ConfigMapList", "metadata": map[string]any{"name": "a"}, "items": []any{}},
	} {
		if _, err := bundle.Canonical([]map[string]any{o}); !errors.Is(err, bundle.ErrNotCanonical) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A value with U+0085 or U+007F is written with an escape, so it has a canonical form that reads back.
func TestCanonicalEscapesControlCharacters(t *testing.T) {
	for _, v := range []string{"a\u0085b", "a\x7fb", "a\tb"} {
		o := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "a"}, "data": map[string]any{"k": v}}
		b, err := bundle.Canonical([]map[string]any{o})
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		got, err := bundle.DecodeCanonical(b, 1)
		if err != nil || got[0]["data"].(map[string]any)["k"] != v {
			t.Fatalf("%q: read back %v %v", v, got, err)
		}
	}
}

func randKey(r *rand.Rand) string {
	const alpha = "0123456789ABCDEFYZabcxyz_-"
	n := 1 + r.Intn(5)
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.Intn(len(alpha))]
	}
	return string(b)
}

func randTree(r *rand.Rand, depth int) any {
	if depth == 0 || r.Intn(3) == 0 {
		return randKey(r)
	}
	if r.Intn(4) == 0 {
		l := make([]any, 1+r.Intn(3))
		for i := range l {
			l[i] = randTree(r, depth-1)
		}
		return l
	}
	m := map[string]any{}
	for i, n := 0, 1+r.Intn(6); i < n; i++ {
		m[randKey(r)] = randTree(r, depth-1)
	}
	return m
}

// The yaml.v2 map sort is not transitive, so the keys 21, 2B22 and 9YAC can come out in any order.
func TestCanonicalIsDeterministic(t *testing.T) {
	seeds := []map[string]any{{
		"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "a", "namespace": "argocd"},
		"data": map[string]any{"21": "a", "2B22": "b", "9YAC": "c"},
	}}
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 7; i++ {
		o := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "a", "namespace": "argocd"}}
		o["data"] = map[string]any{}
		for j, n := 0, 3+r.Intn(10); j < n; j++ {
			o["data"].(map[string]any)[randKey(r)] = "v"
		}
		o["extra"] = randTree(r, 4)
		seeds = append(seeds, o)
	}
	for i, o := range seeds {
		first, err := bundle.Canonical([]map[string]any{o, o})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		for n := 0; n < 1000; n++ {
			again, err := bundle.Canonical([]map[string]any{o, o})
			if err != nil || !bytes.Equal(again, first) {
				t.Fatalf("seed %d, run %d: the canonical form differs\n%s\n%s", i, n, first, again)
			}
		}
		if _, err := bundle.DecodeCanonical(first, 10); err != nil {
			t.Fatalf("seed %d: the canonical form is refused: %v", i, err)
		}
	}
	got, _ := bundle.Canonical(seeds[:1])
	a, b, c := bytes.Index(got, []byte(`"21"`)), bytes.Index(got, []byte("2B22")), bytes.Index(got, []byte("9YAC"))
	if !(a > 0 && a < b && b < c) {
		t.Fatalf("keys are not in byte order:\n%s", got)
	}
}

func TestSinglePlainDocument(t *testing.T) {
	for in, want := range map[string]bool{
		"a: 1\n":             true,
		"a: 1\n--- b: 2\n":   false,
		"a: 1\n...\nb: 2\n":  false,
		"a: 1\n---\nb: 2\n":  false,
		"":                   true,
		"# only a comment\n": true,
		"a: {b: 1}\n":        true,
		"a: [1, 2]\n":        true,
	} {
		if got := bundle.SinglePlainDocument([]byte(in)); got != want {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
	}
}
