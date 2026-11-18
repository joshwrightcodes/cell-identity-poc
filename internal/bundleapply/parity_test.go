package bundleapply

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

// argoRender mirrors the Argo CD v3.6.1 read path for a directory source with one file: the byte
// order mark reader, NewYAMLOrJSONDecoder with a 4096 byte sniff, and the list expansion of
// GenerateManifests. The second result is not empty when Argo CD fails or ignores the file.
func argoRender(b []byte) ([]map[string]any, string) {
	rd := transform.NewReader(bytes.NewReader(b), unicode.BOMOverride(unicode.UTF8.NewDecoder()))
	d := kubeyaml.NewYAMLOrJSONDecoder(rd, 4096)
	var objs []*unstructured.Unstructured
	for {
		u := &unstructured.Unstructured{}
		if err := d.Decode(&u); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, "error: " + err.Error()
		}
		if u == nil {
			continue
		}
		objs = append(objs, u)
	}
	var out []map[string]any
	for _, obj := range objs {
		if obj.IsList() {
			_ = obj.EachListItem(func(o runtime.Object) error {
				out = append(out, o.(*unstructured.Unstructured).Object)
				return nil
			})
			continue
		}
		if _, ok := obj.Object["spec"]; !ok {
			if _, ok := obj.Object["status"]; !ok {
				if f, ok := obj.Object["items"]; ok && f == nil {
					continue
				}
			}
		}
		out = append(out, obj.Object)
	}
	return out, ""
}

// normal gives the JSON form of an object with a null namespace removed, the one difference that is
// not a bypass because the policy refuses a namespaced kind with no namespace.
func normal(m map[string]any) string {
	b, _ := json.Marshal(m)
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	if md, ok := v["metadata"].(map[string]any); ok {
		if ns, has := md["namespace"]; has && ns == nil {
			delete(md, "namespace")
		}
	}
	b, _ = json.Marshal(v)
	return string(b)
}

// parity fails when decode accepts the bytes and Argo CD would apply other objects than decode shows.
func parity(t testing.TB, name string, in []byte, decode func([]byte) ([]Object, error)) {
	t.Helper()
	objs, err := decode(in)
	if err != nil {
		return
	}
	argo, msg := argoRender(in)
	if msg != "" || len(argo) == 0 {
		return
	}
	var got, want []string
	for _, o := range objs {
		got = append(got, normal(o.Raw))
	}
	for _, o := range argo {
		want = append(want, normal(o))
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s: decode shows %d objects and Argo CD applies %d\n decode: %.300s\n argo:   %.300s",
			name, len(got), len(want), strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func toUTF16(s string, be bool) []byte {
	out := []byte{0xFF, 0xFE}
	if be {
		out = []byte{0xFE, 0xFF}
	}
	for _, c := range utf16.Encode([]rune(s)) {
		if be {
			out = append(out, byte(c>>8), byte(c))
		} else {
			out = append(out, byte(c), byte(c>>8))
		}
	}
	return out
}

const (
	pGood = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: good\n  namespace: argocd\ndata: {a: b}\n"
	pJSON = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"visible","namespace":"argocd"},"data":{"a":"b"}}`
	pNP   = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: argocd-agent, namespace: argocd}\n" +
		"spec: {podSelector: {}, ingress: [{}], egress: [{}], policyTypes: [Ingress, Egress]}\n"
)

type pcase struct {
	name string
	in   []byte
}

func parityCases() []pcase {
	two := pGood + "---\n" + pNP
	return []pcase{
		{"yaml then yaml", []byte(two)},
		{"B1 json then yaml", []byte(pJSON + "\n" + pNP)},
		{"B1 json json no newline", []byte(pJSON + pJSON)},
		{"B1 json comment yaml", []byte(pJSON + " # c\n" + pNP)},
		{"B1 bom json yaml", []byte("\xef\xbb\xbf" + pJSON + "\n" + pNP)},
		{"json sep json", []byte(pJSON + "\n---\n" + pJSON)},
		{"json dots yaml", []byte(pJSON + "\n...\n" + pNP)},
		{"B2 utf16le", toUTF16(two, false)},
		{"B2 utf16be", toUTF16(two, true)},
		{"utf16 one document", toUTF16(pGood, false)},
		{"utf8 bom yaml", []byte("\xef\xbb\xbf" + two)},
		{"bom mid stream", []byte(pGood + "---\n\xef\xbb\xbf" + pNP)},
		{"leading space json", []byte("  \n " + pJSON + "\n" + pNP)},
		{"nbsp json", []byte(" " + pJSON + "\n" + pNP)},
		{"nel json", []byte("\u0085" + pJSON + "\n" + pNP)},
		{"top array", []byte("[" + pJSON + "]\n")},
		{"dots then yaml", []byte(pGood + "...\n" + pNP)},
		{"dots then sep", []byte(pGood + "...\n---\n" + pNP)},
		{"lone cr", []byte(strings.ReplaceAll(two, "\n", "\r"))},
		{"nel lines", []byte(strings.ReplaceAll(two, "\n", "\u0085"))},
		{"ls lines", []byte(strings.ReplaceAll(two, "\n", " "))},
		{"crlf", []byte(strings.ReplaceAll(two, "\n", "\r\n"))},
		{"nul", []byte(pGood + "\x00" + "---\n" + pNP)},
		{"invalid utf8", []byte(strings.Replace(pGood, "good", "go\xffod", 1) + "---\n" + pNP)},
		{"anchor alias", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: &m {name: a, namespace: argocd}\ndata: {x: *m}\n")},
		{"alias across documents", []byte("a: &x 1\n---\nb: *x\n")},
		{"merge key", []byte("base: &b {namespace: argocd}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  <<: {namespace: argocd}\n  name: a\n")},
		{"quoted merge key", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd, \"<<\": x}\n")},
		{"duplicate keys", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd, namespace: apps-demo}\n")},
		{"custom tag", []byte("apiVersion: v1\nkind: !foo ConfigMap\nmetadata: {name: a, namespace: argocd}\n")},
		{"str tag", []byte("apiVersion: v1\nkind: !!str ConfigMap\nmetadata: {name: a, namespace: argocd}\n")},
		{"sep in block scalar", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd}\ndata:\n  k: |\n    x\n---\n" + pNP)},
		{"comment separator", []byte(pGood + "# ---\n" + pNP)},
		{"empty documents", []byte("---\n---\n" + pGood + "---\n")},
		{"null document", []byte("null\n---\n" + pGood)},
		{"items", []byte("apiVersion: v1\nkind: ConfigMapList\nitems: [" + "]\n")},
		{"long line", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd}\ndata: {k: " + strings.Repeat("v", 70000) + "}\n")},
		{"namespace null", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: null}\n")},
		{"scalar", []byte("text\n")},
		{"doc start inline", []byte("--- apiVersion: v1\n")},
		{"yaml directive", []byte("%YAML 1.1\n---\n" + pGood)},
	}
}

func TestDecodeParityWithArgoCD(t *testing.T) {
	for _, c := range parityCases() {
		t.Run(c.name, func(t *testing.T) {
			parity(t, c.name, c.in, func(b []byte) ([]Object, error) { return Decode(b, 2000) })
		})
	}
}

// The B1 and B2 inputs show Argo CD two objects. The decoder refuses them, and the canonical
// check refuses every input that is not the canonical form.
func TestDecodeRefusesTheProbeBypasses(t *testing.T) {
	for _, name := range []string{"B1 json then yaml", "B1 json json no newline", "B1 json comment yaml", "B1 bom json yaml", "B2 utf16le", "B2 utf16be"} {
		for _, c := range parityCases() {
			if c.name != name {
				continue
			}
			if argo, msg := argoRender(c.in); msg != "" || len(argo) < 2 {
				t.Fatalf("%s: Argo CD gives %d objects (%s)", name, len(argo), msg)
			}
			var r *Refusal
			if _, err := Decode(c.in, 2000); !errors.As(err, &r) || r.Detail != "layout" {
				t.Errorf("%s: Decode gives %v", name, err)
			}
			if _, err := DecodeCanonical(c.in, 2000); !errors.As(err, &r) {
				t.Errorf("%s: DecodeCanonical gives %v", name, err)
			}
		}
	}
}

func TestDecodeDefenceInDepth(t *testing.T) {
	for name, in := range map[string]string{
		"bom":               "\xef\xbb\xbf" + pGood,
		"bom in the middle": pGood + "---\n\xef\xbb\xbf" + pNP,
		"utf16 bom":         string(toUTF16(pGood, false)),
		"nul":               pGood + "\x00",
		"invalid utf8":      "apiVersion: v1\nkind: Config\xffMap\nmetadata: {name: a}\n",
		"json first":        pJSON + "\n",
		"flow first":        "{apiVersion: v1, kind: ConfigMap, metadata: {name: a, namespace: argocd}}\n",
		"array first":       "[a]\n",
		"space then json":   "\n  \t" + pJSON + "\n",
		"lone cr":           "apiVersion: v1\rkind: ConfigMap\rmetadata: {name: a}\r",
		"nel":               "apiVersion: v1\u0085kind: ConfigMap\n",
		"line separator":    "apiVersion: v1 kind: ConfigMap\n",
		"paragraph sep":     "apiVersion: v1 kind: ConfigMap\n",
		"dots line":         pGood + "...\n",
		"dots then yaml":    pGood + "...\n" + pNP,
		"second document":   pGood + "apiVersion: v1\n",
		"anchor":            "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd}\ndata: {x: &a 1}\n",
		"alias":             "apiVersion: v1\nkind: ConfigMap\nmetadata: &m {name: a, namespace: argocd}\ndata: {x: *m}\n",
		"merge key":         "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  <<: {namespace: argocd}\n  name: a\n",
		"custom tag":        "apiVersion: v1\nkind: !foo ConfigMap\nmetadata: {name: a, namespace: argocd}\n",
		"str tag":           "apiVersion: v1\nkind: !!str ConfigMap\nmetadata: {name: a, namespace: argocd}\n",
		"duplicate key":     "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd, namespace: apps-demo}\n",
		"duplicate top":     "apiVersion: v1\nkind: ConfigMap\nkind: Secret\nmetadata: {name: a}\n",
	} {
		var r *Refusal
		if _, err := Decode([]byte(in), 10); !errors.As(err, &r) || r.Detail != "layout" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Plain input still decodes: a quoted "<<" key, comments, CRLF, a block scalar with a dash line.
	for name, in := range map[string]string{
		"quoted merge key": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd, \"<<\": x}\n",
		"comment first":    "# c\n" + pGood,
		"crlf":             strings.ReplaceAll(pGood, "\n", "\r\n"),
		"block scalar":     "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd}\ndata:\n  k: |\n    ---\n    ...\n",
		"two documents":    pGood + "---\n" + pNP,
	} {
		if _, err := Decode([]byte(in), 10); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSinglePlainDocument(t *testing.T) {
	for in, want := range map[string]bool{
		"a: 1\n":             false,
		"a: 1\n--- b: 2\n":   false,
		"a: 1\n...\nb: 2\n":  false,
		"a: 1\n---\nb: 2\n":  false,
		"":                   true,
		"# only a comment\n": true,
		"a: {b: 1}\n":        true,
		"a: [1, 2]\n":        true,
	} {
		got := singlePlainDocument([]byte(in))
		if in == "a: 1\n" {
			want = true
		}
		if got != want {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
	}
}

func canonicalOf(t testing.TB, in []byte) []byte {
	t.Helper()
	objs, err := Decode(in, 2000)
	if err != nil {
		t.Fatal(err)
	}
	raws := make([]map[string]any, len(objs))
	for i, o := range objs {
		raws[i] = o.Raw
	}
	b, err := bundle.Canonical(raws)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeCanonical(t *testing.T) {
	canon := canonicalOf(t, []byte(pGood+"---\n"+pNP))
	objs, err := DecodeCanonical(canon, 2000)
	if err != nil || len(objs) != 2 {
		t.Fatalf("canonical input: %d objects, %v", len(objs), err)
	}
	for _, c := range parityCases() {
		_, err := DecodeCanonical(c.in, 2000)
		var r *Refusal
		if err == nil {
			// An input that passes must be the canonical form of itself.
			if got := canonicalOf(t, c.in); !bytes.Equal(got, c.in) {
				t.Errorf("%s: accepted but not canonical", c.name)
			}
			continue
		}
		if !errors.As(err, &r) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// Valid, non-canonical bytes give not_canonical.
	var r *Refusal
	for name, in := range map[string]string{
		"key order":      pGood,
		"flow style":     "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: argocd}\n",
		"comment":        "# c\n" + string(canon),
		"leading sep":    "---\n" + string(canon),
		"empty document": string(canon) + "---\n",
		"crlf":           strings.ReplaceAll(string(canon), "\n", "\r\n"),
	} {
		if _, err := DecodeCanonical([]byte(in), 2000); !errors.As(err, &r) || r.Reason != rNot || r.Detail != "not_canonical" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCanonicalIsStable(t *testing.T) {
	canon := canonicalOf(t, []byte(pGood+"---\n"+pNP))
	if again := canonicalOf(t, canon); !bytes.Equal(again, canon) {
		t.Fatalf("canonical form is not stable\n%s\n%s", canon, again)
	}
	big := generatedRender()
	c1 := canonicalOf(t, big)
	if !bytes.Equal(canonicalOf(t, c1), c1) {
		t.Fatal("the canonical form of the generated render is not stable")
	}
	if _, err := DecodeCanonical(c1, 2000); err != nil {
		t.Fatal(err)
	}
	if got, _ := argoRender(c1); len(got) != 37 {
		t.Fatalf("Argo CD reads %d objects of the canonical render", len(got))
	}
}

func FuzzDecodeParity(f *testing.F) {
	for _, c := range parityCases() {
		f.Add(c.in)
	}
	f.Add(canonicalOf(f, []byte(pGood+"---\n"+pNP)))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 1<<16 {
			return
		}
		parity(t, "fuzz", in, func(b []byte) ([]Object, error) { return Decode(b, 2000) })
		if objs, err := DecodeCanonical(in, 2000); err == nil {
			var raws []map[string]any
			for _, o := range objs {
				raws = append(raws, o.Raw)
			}
			if b, err := bundle.Canonical(raws); err != nil || !bytes.Equal(b, in) {
				t.Fatalf("DecodeCanonical accepted bytes that are not canonical: %q", in)
			}
		}
	})
}

var _ = fmt.Sprint
var _ = os.Getenv
