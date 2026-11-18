package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore/ocitest"
)

const repoRoot = "../.."

// run executes one command with the given standard input and returns the exit code and the output.
func runCLI(t *testing.T, stdin string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := execute(context.Background(), args, strings.NewReader(stdin), &out)
	return code, out.String()
}

// mustRun runs a command that has to succeed and returns its output.
func mustRun(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	code, out := runCLI(t, stdin, args...)
	if code != 0 {
		t.Fatalf("%v: exit %d: %s", args, code, out)
	}
	return out
}

// errorLine checks that out is one JSON error line, and returns its error text.
func errorLine(t *testing.T, out string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one line, got %q", out)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("not JSON: %q: %v", out, err)
	}
	if rec["level"] != "ERROR" || rec["msg"] != "bundlectl failed" {
		t.Fatalf("line %v is not a bundlectl error line", rec)
	}
	s, _ := rec["error"].(string)
	if s == "" {
		t.Fatalf("line %v has no error text", rec)
	}
	return s
}

const cmA = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: x\ndata:\n  k: v\n"

// cmAReordered holds the same object as cmA with a comment and another key order. It is not canonical.
const cmAReordered = "# rendered by a tool\ndata:\n  k: v\nkind: ConfigMap\nmetadata:\n  namespace: x\n  name: a\napiVersion: v1\n"

const cmB = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n  namespace: yy\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: yy\nstringData:\n  k: v\n"

// render writes build/<target>/bundles/<component>/manifests.yaml under dir.
func render(t *testing.T, dir, target string, files map[string]string) string {
	t.Helper()
	build := filepath.Join(dir, "build")
	for name, body := range files {
		d := filepath.Join(build, target, "bundles", name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "manifests.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return build
}

// canonicalOf is the oracle for a render: the objects parsed here, not by the code under test.
func canonicalOf(t *testing.T, body string) []byte {
	t.Helper()
	var objs []map[string]any
	for _, doc := range strings.Split(body, "---\n") {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatal(err)
		}
		if len(m) > 0 {
			objs = append(objs, m)
		}
	}
	c, err := bundle.Canonical(objs)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func packOracle(t *testing.T, body string) bundle.Artifact {
	t.Helper()
	a, err := bundle.Pack(map[string][]byte{"manifests.yaml": canonicalOf(t, body)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func parseComponents(t *testing.T, out string) []bundle.Component {
	t.Helper()
	cs, err := bundle.ParseComponents(json.RawMessage(out))
	if err != nil {
		t.Fatalf("output is not a component list: %v: %s", err, out)
	}
	return cs
}

func names(cs []bundle.Component) []string {
	var n []string
	for _, c := range cs {
		n = append(n, c.Name)
	}
	return n
}

// The components of a set print in order of name, which the set rules require, and not in order of wave.
func TestSetSorted(t *testing.T) {
	build := render(t, t.TempDir(), "dev-cell-1", map[string]string{"namespaces": cmA, "argocd": cmB, "cell-system": cmA, "apps-demo": cmB})
	out := mustRun(t, "", "set", "--target", "dev-cell-1", "--build", build, "--root", t.TempDir(),
		"namespaces:-2:default", "argocd:-1:argocd", "cell-system:-1:cell-system", "apps-demo:5:apps-demo")
	cs := parseComponents(t, out)
	if want := []string{"apps-demo", "argocd", "cell-system", "namespaces"}; !slices.Equal(names(cs), want) {
		t.Fatalf("components = %v, want %v", names(cs), want)
	}
	for _, c := range cs {
		want := map[string]int{"namespaces": -2, "argocd": -1, "cell-system": -1, "apps-demo": 5}[c.Name]
		if c.Wave != want {
			t.Errorf("%s wave = %d, want %d", c.Name, c.Wave, want)
		}
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("output is not one line: %q", out)
	}
}

func TestSetDigestsAreThePackedDigests(t *testing.T) {
	build := render(t, t.TempDir(), "t", map[string]string{"one": cmA, "two": cmB})
	cs := parseComponents(t, mustRun(t, "", "set", "--target", "t", "--build", build, "--root", t.TempDir(), "one:0:x", "two:1:yy"))
	if cs[0].Digest != packOracle(t, cmA).Digest || cs[1].Digest != packOracle(t, cmB).Digest {
		t.Fatalf("digests = %s, %s", cs[0].Digest, cs[1].Digest)
	}
}

// The wave and the namespace come from the entry, and ignoreDifferences from components/<c>/application.yaml.
func TestSetReadsExtras(t *testing.T) {
	build := render(t, t.TempDir(), "t", map[string]string{"istio-base": cmA, "istiod": cmA, "apps-demo": cmB})
	out := mustRun(t, "", "set", "--target", "t", "--build", build, "--root", repoRoot,
		"istio-base:1:istio-system", "istiod:3:istio-system", "apps-demo:5:apps-demo")
	cs := parseComponents(t, out)
	for _, c := range cs {
		raw, err := os.ReadFile(filepath.Join(repoRoot, "components", c.Name, "application.yaml"))
		if os.IsNotExist(err) {
			if len(c.IgnoreDifferences) != 0 {
				t.Errorf("%s has ignoreDifferences %s with no application.yaml", c.Name, c.IgnoreDifferences)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Spec struct {
				Ignore []map[string]any `json:"ignoreDifferences"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Spec.Ignore) == 0 {
			t.Fatalf("%s: %v", c.Name, err)
		}
		var got []map[string]any
		if err := json.Unmarshal(c.IgnoreDifferences, &got); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if !reflect.DeepEqual(got, doc.Spec.Ignore) {
			t.Errorf("%s ignoreDifferences = %v, want %v", c.Name, got, doc.Spec.Ignore)
		}
	}
	if len(cs) != 3 || len(cs[0].IgnoreDifferences) != 0 || len(cs[1].IgnoreDifferences) == 0 || len(cs[2].IgnoreDifferences) == 0 {
		t.Fatalf("components = %+v", cs)
	}
}

func TestSetRefusesExtrasWithOtherFields(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "components", "one")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	build := render(t, t.TempDir(), "t", map[string]string{"one": cmA})
	for name, body := range map[string]string{
		"other spec field": "spec:\n  syncPolicy:\n    automated:\n      prune: false\n",
		"other top field":  "metadata:\n  name: x\nspec:\n  ignoreDifferences:\n    - kind: Secret\n      jsonPointers: [/data]\n",
		"empty list":       "spec:\n  ignoreDifferences: []\n",
	} {
		if err := os.WriteFile(filepath.Join(d, "application.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		code, out := runCLI(t, "", "set", "--target", "t", "--build", build, "--root", root, "one:0:x")
		if code != 1 {
			t.Errorf("%s: exit %d: %s", name, code, out)
			continue
		}
		if msg := errorLine(t, out); !strings.Contains(msg, "application.yaml") {
			t.Errorf("%s: error %q does not name the file", name, msg)
		}
	}
}

func TestSetRefusesBadEntries(t *testing.T) {
	build := render(t, t.TempDir(), "t", map[string]string{"one": cmA, "root": cmA})
	root := t.TempDir()
	for name, args := range map[string][]string{
		"no entries":      {},
		"no wave":         {"one:x"},
		"wave not number": {"one:w:x"},
		"wave range":      {"one:99:x"},
		"duplicate":       {"one:0:x", "one:1:x"},
		"missing render":  {"nope:0:x"},
		"reserved name":   {"root:0:x"},
		"bad namespace":   {"one:0:X_"},
	} {
		code, out := runCLI(t, "", append([]string{"set", "--target", "t", "--build", build, "--root", root}, args...)...)
		if code != 1 {
			t.Errorf("%s: exit %d: %s", name, code, out)
			continue
		}
		errorLine(t, out)
	}
}

func newMirror(t *testing.T) (*ocitest.Registry, string) {
	t.Helper()
	reg := ocitest.NewRegistry(t)
	return reg, reg.URL()
}

// Two pushes of the same objects give the same digests, whatever the layout of the render, and the
// mirror holds the canonical layer under bundles/<target>/<component>.
func TestPushDeterministic(t *testing.T) {
	reg, host := newMirror(t)
	b1 := render(t, t.TempDir(), "dev-cell-1", map[string]string{"one": cmA, "two": cmB})
	b2 := render(t, t.TempDir(), "dev-cell-1", map[string]string{"one": cmAReordered, "two": cmB})
	args := func(build string) []string {
		return []string{"push", "--target", "dev-cell-1", "--build", build, "--root", t.TempDir(), "--registry", host, "one:0:x", "two:1:yy"}
	}
	first := mustRun(t, "", args(b1)...)
	second := mustRun(t, "", args(b2)...)
	if first != second {
		t.Fatalf("pushes differ:\n%s\n%s", first, second)
	}
	cs := parseComponents(t, first)
	for i, body := range []string{cmA, cmB} {
		want := packOracle(t, body)
		if cs[i].Digest != want.Digest {
			t.Fatalf("%s digest = %s, want %s", cs[i].Name, cs[i].Digest, want.Digest)
		}
		repo := "bundles/dev-cell-1/" + cs[i].Name
		m, ok := reg.Manifest(repo, want.Digest)
		if !ok || !bytes.Equal(m, want.Manifest) {
			t.Fatalf("%s: manifest missing or different", repo)
		}
		if l, ok := reg.Blob(repo, want.LayerDigest); !ok || !bytes.Equal(l, want.Layer) {
			t.Fatalf("%s: layer missing or different", repo)
		}
		if _, ok := reg.Blob(repo, want.ConfigDigest); !ok {
			t.Fatalf("%s: config missing", repo)
		}
		if _, ok := reg.Manifest(repo, "current"); ok {
			t.Fatalf("%s has a tag", repo)
		}
		layer, err := bundle.UnpackComponent(want.Layer, bundle.MaxUnpackedBytes)
		if err != nil || !bytes.Equal(layer, canonicalOf(t, body)) {
			t.Fatalf("%s: layer is not the canonical form: %v", repo, err)
		}
	}
}

// A render with no canonical form fails with a clear error, before the first request.
func TestPushRefusesRendersWithNoCanonicalForm(t *testing.T) {
	cases := map[string]string{
		"anchor":      "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  k: &x v\n  j: *x\n",
		"merge key":   "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  <<: {k: v}\n",
		"tag":         "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  k: !!str v\n",
		"duplicate":   "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  k: v\n  k: w\n",
		"flow start":  "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"a\"}}\n",
		"list":        "apiVersion: v1\nkind: List\nitems: []\n",
		"separator":   "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  k: \"a b\"\n",
		"no objects":  "# nothing here\n",
		"empty file":  "",
		"lone cr":     "apiVersion: v1\rkind: ConfigMap\rmetadata:\r  name: a\r",
		"not an obj":  "- a\n- b\n",
		"items field": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\nitems:\n  - x\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			reg, host := newMirror(t)
			build := render(t, t.TempDir(), "t", map[string]string{"good": cmA, "bad": body})
			code, out := runCLI(t, "", "push", "--target", "t", "--build", build, "--root", t.TempDir(), "--registry", host, "bad:0:x", "good:1:x")
			if code != 1 {
				t.Fatalf("exit %d: %s", code, out)
			}
			if msg := errorLine(t, out); !strings.Contains(msg, `"bad"`) {
				t.Errorf("error %q does not name the component", msg)
			}
			if n := len(reg.Requests()); n != 0 {
				t.Errorf("%d requests reached the mirror", n)
			}
		})
	}
}

// Only a loopback host with a port is a mirror. Nothing is sent to another host.
func TestPushRefusesOtherHost(t *testing.T) {
	reg, _ := newMirror(t)
	var sent atomic.Int32
	useTransport(t, countTransport{base: http.DefaultTransport, n: &sent})
	build := render(t, t.TempDir(), "t", map[string]string{"one": cmA})
	for _, host := range []string{
		"registry-mirror:5000", "10.0.0.5:5001", "example.com:5001", "192.168.5.2:5001", "127.0.0.1", ":5001",
		"http://127.0.0.1:5001", "127.0.0.1:5001/x", "user@127.0.0.1:5001", "127.0.0.1:0", "", "bundle-store.cell-system.svc.cluster.local:5000",
	} {
		code, out := runCLI(t, "", "push", "--target", "t", "--build", build, "--root", t.TempDir(), "--registry", host, "one:0:x")
		if code != 1 {
			t.Errorf("%q: exit %d: %s", host, code, out)
			continue
		}
		errorLine(t, out)
	}
	set := writeFile(t, t.TempDir(), "set.json", `[{"name":"one","wave":0,"namespace":"x","digest":"`+packOracle(t, cmA).Digest+`"}]`)
	if code, out := runCLI(t, "", "push-root", "--role", "cell", "--target", "t", "--set", set, "--registry", "10.0.0.5:5001"); code != 1 {
		t.Errorf("push-root to another host: exit %d: %s", code, out)
	}
	if n := len(reg.Requests()); n != 0 {
		t.Errorf("%d requests reached the registry", n)
	}
	if n := sent.Load(); n != 0 {
		t.Errorf("%d requests left the process", n)
	}
}

// countTransport counts the requests that leave the client.
type countTransport struct {
	base http.RoundTripper
	n    *atomic.Int32
}

func (c countTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, errors.New("test transport: no request may leave")
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

type rootOut struct {
	Digest   string            `json:"digest"`
	Manifest string            `json:"manifest"`
	Parts    map[string]string `json:"components"`
}

func decodeRoot(t *testing.T, out string) rootOut {
	t.Helper()
	var r rootOut
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not a root result: %q: %v", out, err)
	}
	return r
}

func cellSet(t *testing.T) (string, []bundle.Component) {
	t.Helper()
	cs := []bundle.Component{
		{Name: "apps-demo", Wave: 5, Namespace: "apps-demo", Digest: packOracle(t, cmA).Digest},
		{Name: "argocd", Wave: -1, Namespace: "argocd", Digest: packOracle(t, cmB).Digest},
	}
	b, err := json.Marshal(cs)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, t.TempDir(), "set.json", string(b)), cs
}

// compose prints the digest and the manifest of the root that bundle.ComposeRoot makes.
func TestComposeMatchesComposeRoot(t *testing.T) {
	file, cs := cellSet(t)
	for _, role := range []string{"cell", "cp"} {
		want, err := bundle.ComposeRoot(role, bundle.Set{Components: cs}, bundle.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		r := decodeRoot(t, mustRun(t, "", "compose", "--role", role, "--set", file))
		if r.Digest != want.Digest {
			t.Errorf("%s digest = %s, want %s", role, r.Digest, want.Digest)
		}
		m, err := base64.StdEncoding.DecodeString(r.Manifest)
		if err != nil || !bytes.Equal(m, want.Manifest) {
			t.Errorf("%s manifest differs: %v", role, err)
		}
	}
	// The set can also come on standard input.
	b, _ := os.ReadFile(file)
	if a, c := mustRun(t, string(b), "compose", "--role", "cell", "--set", "-"), mustRun(t, "", "compose", "--role", "cell", "--set", file); a != c {
		t.Errorf("stdin and file differ: %s %s", a, c)
	}
}

func TestComposeRefusals(t *testing.T) {
	file, _ := cellSet(t)
	other := writeFile(t, t.TempDir(), "other.json", `[{"name":"not-a-component","wave":0,"namespace":"x","digest":"`+packOracle(t, cmA).Digest+`"}]`)
	for name, args := range map[string][]string{
		"open role":        {"compose", "--role", "open", "--set", file},
		"unknown role":     {"compose", "--role", "nope", "--set", file},
		"unknown part":     {"compose", "--role", "cell", "--set", other},
		"no role":          {"compose", "--set", file},
		"no set":           {"compose", "--role", "cell"},
		"missing file":     {"compose", "--role", "cell", "--set", filepath.Join(t.TempDir(), "x")},
		"destination":      {"compose", "--role", "cp", "--set", writeFile(t, t.TempDir(), "d.json", `[{"name":"argocd","wave":0,"namespace":"kube-system","digest":"`+packOracle(t, cmA).Digest+`"}]`)},
		"set is not array": {"compose", "--role", "cell", "--set", writeFile(t, t.TempDir(), "n.json", `{"components":[]}`)},
	} {
		code, out := runCLI(t, "", args...)
		if code != 1 {
			t.Errorf("%s: exit %d: %s", name, code, out)
			continue
		}
		errorLine(t, out)
	}
}

// push-root puts the root of the set under bundles/<target>/root, and its digest is the root subject of the statement.
func TestPushRootMatchesStatement(t *testing.T) {
	reg, host := newMirror(t)
	file, cs := cellSet(t)
	r := decodeRoot(t, mustRun(t, "", "push-root", "--role", "cell", "--target", "dev-cell-1", "--set", file, "--registry", host))
	set := bundle.Set{Version: bundle.Version{Epoch: 1, Counter: 3}, Components: cs}
	st := bundle.NewStatement("dev", "dev-cell-1", set, r.Digest)
	m, ok := reg.Manifest("bundles/dev-cell-1/root", st.RootDigest())
	if !ok {
		t.Fatalf("no manifest at the root subject %s", st.RootDigest())
	}
	if ocitest.Digest(m) != st.RootDigest() {
		t.Fatalf("manifest digest %s differs from the root subject %s", ocitest.Digest(m), st.RootDigest())
	}
	want, _ := bundle.ComposeRoot("cell", set, bundle.DefaultPolicy())
	if st.RootDigest() != want.Digest || !bytes.Equal(m, want.Manifest) {
		t.Fatalf("pushed root differs from ComposeRoot")
	}
	if l, ok := reg.Blob("bundles/dev-cell-1/root", want.LayerDigest); !ok || !bytes.Equal(l, want.Layer) {
		t.Fatal("root layer is missing")
	}
	if _, ok := reg.Manifest("bundles/dev-cell-1/root", "current"); ok {
		t.Fatal("the mirror root has a tag")
	}
	files, err := bundle.Unpack(want.Layer, bundle.MaxUnpackedBytes)
	if err != nil || len(files) != 2 {
		t.Fatalf("root layer: %v, %d files", err, len(files))
	}
	for _, req := range reg.Requests() {
		if strings.Contains(req.Path, "/bundles/root/") {
			t.Errorf("request to the in-cluster path %s", req.Path)
		}
	}
	if code, out := runCLI(t, "", "push-root", "--role", "open", "--target", "management", "--set", file, "--registry", host); code != 1 {
		t.Errorf("role open: exit %d: %s", code, out)
	}
}

// bootstrap pushes each component by digest and the root by digest and under the tag current.
func TestBootstrapTagsCurrent(t *testing.T) {
	reg, host := newMirror(t)
	build := render(t, t.TempDir(), "dev-cell-1", map[string]string{"apps-demo": cmA, "argocd": cmB})
	out := mustRun(t, "", "bootstrap", "--role", "cell", "--target", "dev-cell-1", "--build", build, "--root", t.TempDir(),
		"--registry", host, "argocd:-1:argocd", "apps-demo:5:apps-demo")
	r := decodeRoot(t, out)
	cs := []bundle.Component{
		{Name: "apps-demo", Wave: 5, Namespace: "apps-demo", Digest: packOracle(t, cmA).Digest},
		{Name: "argocd", Wave: -1, Namespace: "argocd", Digest: packOracle(t, cmB).Digest},
	}
	want, err := bundle.ComposeRoot("cell", bundle.Set{Components: cs}, bundle.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if r.Digest != want.Digest {
		t.Fatalf("root digest = %s, want %s", r.Digest, want.Digest)
	}
	if m, ok := base64.StdEncoding.DecodeString(r.Manifest); ok != nil || !bytes.Equal(m, want.Manifest) {
		t.Fatalf("manifest differs: %v", ok)
	}
	if r.Parts["argocd"] != cs[1].Digest || r.Parts["apps-demo"] != cs[0].Digest || len(r.Parts) != 2 {
		t.Fatalf("components = %v", r.Parts)
	}
	if cur, ok := reg.Manifest("bundles/root", "current"); !ok || !bytes.Equal(cur, want.Manifest) {
		t.Fatal("tag current does not hold the root")
	}
	if m, ok := reg.Manifest("bundles/root", want.Digest); !ok || !bytes.Equal(m, want.Manifest) {
		t.Fatal("the root is not there by digest")
	}
	for _, c := range cs {
		repo := "bundles/" + c.Name
		if _, ok := reg.Manifest(repo, c.Digest); !ok {
			t.Errorf("%s is not there by digest", repo)
		}
		if _, ok := reg.Manifest(repo, "current"); ok {
			t.Errorf("%s has a tag", repo)
		}
	}
	if code, out := runCLI(t, "", "bootstrap", "--role", "open", "--target", "management", "--build", build, "--root", t.TempDir(),
		"--registry", host, "argocd:-1:argocd"); code != 1 {
		t.Errorf("role open: exit %d: %s", code, out)
	}
}

// The projects of a role repeat its class, and each carries the harness objects of its role in the blacklist.
func TestProjectsByRole(t *testing.T) {
	allow, err := os.ReadFile(filepath.Join(repoRoot, "internal", "bundle", "allow.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(allow)
	wantSHA := hex.EncodeToString(sum[:])

	type entry struct{ group, kind, name string }
	vap := func(n string) []entry {
		return []entry{{"admissionregistration.k8s.io", "ValidatingAdmissionPolicy", n}, {"admissionregistration.k8s.io", "ValidatingAdmissionPolicyBinding", n}}
	}
	cell := append(vap("bundles-spare-harness"), vap("bundles-app-limits")...)
	cases := []struct {
		role     string
		projects []string
		black    []entry
		dests    map[string][]string
	}{
		{"cell", []string{"cell", "cell-app"}, cell, map[string][]string{"cell-app": {"apps-demo"}}},
		{"cp", []string{"cell"}, vap("bundles-spare-harness"), map[string][]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.role, func(t *testing.T) {
			out := mustRun(t, "", "projects", "--role", tc.role, "--root", repoRoot)
			if err := bundle.CheckCanonical([]byte(out)); err != nil {
				t.Fatalf("output is not canonical: %v", err)
			}
			objs, err := bundle.DecodeManifests([]byte(out), 10)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, o := range objs {
				meta := o["metadata"].(map[string]any)
				name := meta["name"].(string)
				got = append(got, name)
				if o["apiVersion"] != "argoproj.io/v1alpha1" || o["kind"] != "AppProject" || meta["namespace"] != "argocd" {
					t.Errorf("%s: header %v", name, o)
				}
				ann, _ := meta["annotations"].(map[string]any)
				if ann["poc.internal/allow-sha256"] != wantSHA {
					t.Errorf("%s: allow-sha256 = %v, want %s", name, ann["poc.internal/allow-sha256"], wantSHA)
				}
				spec, _ := o["spec"].(map[string]any)
				var black []entry
				for _, e := range spec["clusterResourceBlacklist"].([]any) {
					m := e.(map[string]any)
					black = append(black, entry{m["group"].(string), m["kind"].(string), m["name"].(string)})
				}
				slices.SortFunc(black, func(a, b entry) int { return strings.Compare(a.kind+a.name, b.kind+b.name) })
				want := slices.Clone(tc.black)
				slices.SortFunc(want, func(a, b entry) int { return strings.Compare(a.kind+a.name, b.kind+b.name) })
				if !reflect.DeepEqual(black, want) {
					t.Errorf("%s: blacklist = %v, want %v", name, black, want)
				}
				if d, ok := tc.dests[name]; ok {
					var ns []string
					for _, e := range spec["destinations"].([]any) {
						ns = append(ns, e.(map[string]any)["namespace"].(string))
					}
					if !slices.Equal(ns, d) {
						t.Errorf("%s: destinations = %v, want %v", name, ns, d)
					}
				}
				exp, err := bundle.ExpectedAppProjectSpec(tc.role, name, bundle.DefaultPolicy())
				if err != nil {
					t.Fatal(err)
				}
				a, _ := json.Marshal(exp)
				b, _ := json.Marshal(spec)
				var ea, eb any
				_ = json.Unmarshal(a, &ea)
				_ = json.Unmarshal(b, &eb)
				if !reflect.DeepEqual(canonicalSort(ea), canonicalSort(eb)) {
					t.Errorf("%s: spec differs from the policy:\n%s\n%s", name, a, b)
				}
			}
			if !slices.Equal(got, tc.projects) {
				t.Errorf("projects = %v, want %v", got, tc.projects)
			}
		})
	}

	t.Run("open", func(t *testing.T) {
		want, err := os.ReadFile(filepath.Join(repoRoot, "components", "argocd", "project.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		out := mustRun(t, "", "projects", "--role", "open", "--root", repoRoot)
		if out != string(want) {
			t.Fatalf("open project differs from the M7 file:\n%s", out)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		code, out := runCLI(t, "", "projects", "--role", "nope", "--root", repoRoot)
		if code != 1 {
			t.Fatalf("exit %d: %s", code, out)
		}
		errorLine(t, out)
	})
}

// canonicalSort puts every list of v in order of its JSON text, so that list order does not matter.
func canonicalSort(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = canonicalSort(e)
		}
		return x
	case []any:
		for i := range x {
			x[i] = canonicalSort(x[i])
		}
		slices.SortFunc(x, func(a, b any) int {
			ja, _ := json.Marshal(a)
			jb, _ := json.Marshal(b)
			return strings.Compare(string(ja), string(jb))
		})
		return x
	}
	return v
}

func TestPubkeyPEM(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	for name, in := range map[string]string{
		"ctl line":    `{"spec.pub":"` + b64 + `"}` + "\n",
		"bare base64": b64 + "\n",
	} {
		out := mustRun(t, in, "pubkey-pem")
		blk, rest := pem.Decode([]byte(out))
		if blk == nil || blk.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("%s: output %q is not one PUBLIC KEY block", name, out)
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, ok := k.(ed25519.PublicKey); !ok || !bytes.Equal(got, pub) {
			t.Fatalf("%s: key = %v", name, k)
		}
	}
	short := base64.StdEncoding.EncodeToString(pub[:31])
	for name, in := range map[string]string{
		"empty": "", "garbage": "!!!", "short key": short, "no spec.pub": `{"other":"x"}`,
		"two keys": b64 + "\n" + b64 + "\n", "long key": base64.StdEncoding.EncodeToString(append(slices.Clone(pub), 0)),
	} {
		code, out := runCLI(t, in, "pubkey-pem")
		if code != 1 {
			t.Errorf("%s: exit %d: %s", name, code, out)
			continue
		}
		if strings.Contains(out, "BEGIN") {
			t.Errorf("%s: a key block reached the output", name)
		}
		errorLine(t, out)
	}
}

func TestErrorLine(t *testing.T) {
	for _, args := range [][]string{
		nil, {"bogus"}, {"set"}, {"set", "--nope"}, {"set", "-h"}, {"push"}, {"compose"}, {"projects"}, {"attach"},
		{"push-root"}, {"bootstrap"}, {"pubkey-pem", "extra"},
	} {
		code, out := runCLI(t, "", args...)
		if code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
		errorLine(t, out)
	}
}

// A YAML 1.1 boolean such as y is read as a boolean by the readers. The error says so.
func TestPushNamesTheBooleanCause(t *testing.T) {
	cases := map[string]string{
		"key":   "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  y: v\n",
		"value": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: n\ndata:\n  k: v\n",
	}
	cases["value"] = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: y\n"
	for name, body := range cases {
		build := render(t, t.TempDir(), "t", map[string]string{"bad": body})
		code, out := runCLI(t, "", "set", "--target", "t", "--build", build, "--root", t.TempDir(), "bad:0:x")
		if code != 1 {
			t.Fatalf("%s: exit %d: %s", name, code, out)
		}
		if msg := errorLine(t, out); !strings.Contains(msg, "unquoted y, n, yes, no, on or off") {
			t.Errorf("%s: error %q does not name the cause", name, msg)
		}
	}
	// Two keys that read as the same boolean would merge silently. They are refused by name.
	build := render(t, t.TempDir(), "t", map[string]string{"bad": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  y: v\n  on: w\n"})
	code, out := runCLI(t, "", "set", "--target", "t", "--build", build, "--root", t.TempDir(), "bad:0:x")
	if msg := errorLine(t, out); code != 1 || !strings.Contains(msg, `key "on"`) {
		t.Errorf("merged keys: exit %d: %s", code, out)
	}
	// Text inside a block scalar is not a key.
	build = render(t, t.TempDir(), "t", map[string]string{"ok": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  f: |\n    on: yes\n    y: n\n  \"y\": quoted\n"})
	mustRun(t, "", "set", "--target", "t", "--build", build, "--root", t.TempDir(), "ok:0:x")
	// A render that is refused for another reason gets no such hint.
	build = render(t, t.TempDir(), "t", map[string]string{"bad": "apiVersion: v1\nkind: List\nitems: []\n"})
	_, out = runCLI(t, "", "set", "--target", "t", "--build", build, "--root", t.TempDir(), "bad:0:x")
	if msg := errorLine(t, out); strings.Contains(msg, "unquoted") {
		t.Errorf("hint for a list: %q", msg)
	}
}
