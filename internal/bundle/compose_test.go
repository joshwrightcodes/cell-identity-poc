package bundle_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"sigs.k8s.io/yaml"
)

const store = "127.0.0.1:5000"

func composeSet() bundle.Set {
	return bundle.Set{Version: bundle.Version{Epoch: 1, Counter: 1}, Components: []bundle.Component{
		{Name: "apps-sample", Wave: 5, Namespace: "apps-demo", Digest: hexDigest('1')},
		{Name: "argocd", Wave: -1, Namespace: "argocd", Digest: hexDigest('2')},
		{Name: "istiod", Wave: 3, Namespace: "istio-system", Digest: hexDigest('3'),
			IgnoreDifferences: json.RawMessage(`[{"group":"admissionregistration.k8s.io","kind":"ValidatingWebhookConfiguration","jqPathExpressions":[".webhooks[]?.failurePolicy",".webhooks[]?.clientConfig.caBundle"]},{"group":"admissionregistration.k8s.io","kind":"MutatingWebhookConfiguration","jqPathExpressions":[".webhooks[]?.clientConfig.caBundle"]}]`)},
		{Name: "namespaces", Wave: -2, Namespace: "default", Digest: hexDigest('4')},
	}}
}

func compose(t testing.TB, role string, s bundle.Set) bundle.Artifact {
	t.Helper()
	a, err := bundle.ComposeRoot(role, s, bundle.DefaultPolicy(), store)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func rootFiles(t testing.TB, a bundle.Artifact) map[string][]byte {
	t.Helper()
	files, err := bundle.Unpack(a.Layer, bundle.MaxUnpackedBytes)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// publishApp is the Application of scripts/publish.sh for one component, with the digest in place
// of $digest. The script then merges components/<c>/application.yaml with yq `. *+ load(file)`, which
// adds spec.ignoreDifferences.
func publishApp(t testing.TB, c bundle.Component, project string) map[string]any {
	t.Helper()
	text := `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ` + c.Name + `
  namespace: argocd
  annotations:
    argocd.argoproj.io/sync-wave: "` + itoa(c.Wave) + `"
spec:
  project: ` + project + `
  source:
    repoURL: oci://` + store + `/bundles/` + c.Name + `
    targetRevision: ` + c.Digest + `
    path: .
  destination:
    server: https://kubernetes.default.svc
    namespace: ` + c.Namespace + `
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - ServerSideApply=true
      - RespectIgnoreDifferences=true
`
	var m map[string]any
	if err := yaml.Unmarshal([]byte(text), &m); err != nil {
		t.Fatal(err)
	}
	if len(c.IgnoreDifferences) > 0 {
		var ig []any
		if err := json.Unmarshal(c.IgnoreDifferences, &ig); err != nil {
			t.Fatal(err)
		}
		m["spec"].(map[string]any)["ignoreDifferences"] = ig
	}
	return m
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestComposeRootMatchesPublish(t *testing.T) {
	s := composeSet()
	files := rootFiles(t, compose(t, "cell", s))
	if len(files) != len(s.Components) {
		t.Fatalf("%d files for %d components", len(files), len(s.Components))
	}
	for _, c := range s.Components {
		body, ok := files[c.Name+".yaml"]
		if !ok {
			t.Fatalf("no file for %s", c.Name)
		}
		var got map[string]any
		if err := yaml.Unmarshal(body, &got); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		project := "cell"
		if c.Name == "apps-sample" {
			project = "cell-app"
		}
		want := publishApp(t, c, project)
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		if string(gj) != string(wj) {
			t.Errorf("%s differs from publish.sh\n got %s\nwant %s", c.Name, gj, wj)
		}
	}
}

func TestComposeRootNoFinalizer(t *testing.T) {
	for role, s := range map[string]bundle.Set{"cell": composeSet(), "cp": {Version: bundle.Version{Epoch: 1, Counter: 2}, Components: composeSet().Components[1:]}} {
		for name, body := range rootFiles(t, compose(t, role, s)) {
			text := strings.ToLower(string(body))
			for _, bad := range []string{"finalizer", "epoch", "counter"} {
				if strings.Contains(text, bad) {
					t.Errorf("%s/%s mentions %q:\n%s", role, name, bad, body)
				}
			}
			var m struct {
				Metadata struct {
					Finalizers  []string          `json:"finalizers"`
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
			}
			if err := yaml.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			if len(m.Metadata.Finalizers) != 0 || len(m.Metadata.Annotations) != 1 {
				t.Errorf("%s/%s metadata %+v", role, name, m.Metadata)
			}
		}
	}
}

func TestComposeRootIgnoresVersion(t *testing.T) {
	a := composeSet()
	b := composeSet()
	b.Version = bundle.Version{Epoch: 9, Counter: 9}
	if compose(t, "cell", a).Digest != compose(t, "cell", b).Digest {
		t.Error("the version changed the root")
	}
}

func TestComposeRootProjectByClass(t *testing.T) {
	project := func(role, name string) string {
		s := composeSet()
		if role == "cp" {
			s.Components = s.Components[1:]
		}
		files := rootFiles(t, compose(t, role, s))
		var m struct {
			Spec struct {
				Project string `json:"project"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(files[name+".yaml"], &m); err != nil {
			t.Fatal(err)
		}
		return m.Spec.Project
	}
	if p := project("cell", "apps-sample"); p != "cell-app" {
		t.Errorf("cell/apps-sample project %q", p)
	}
	for _, c := range []string{"argocd", "istiod", "namespaces"} {
		if p := project("cell", c); p != "cell" {
			t.Errorf("cell/%s project %q", c, p)
		}
		if p := project("cp", c); p != "cell" {
			t.Errorf("cp/%s project %q", c, p)
		}
	}
}

func TestComposeRootRefuses(t *testing.T) {
	p := bundle.DefaultPolicy()
	cp := composeSet() // apps-sample is not a component of role cp
	if _, err := bundle.ComposeRoot("cp", cp, p, store); err == nil {
		t.Error("cp composed apps-sample")
	}
	if _, err := bundle.ComposeRoot("open", composeSet(), p, store); err == nil {
		t.Error("role open composed")
	}
	unknown := composeSet()
	unknown.Components = append(unknown.Components, bundle.Component{Name: "zzz", Namespace: "x", Digest: hexDigest('9')})
	if _, err := bundle.ComposeRoot("cell", unknown, p, store); err == nil {
		t.Error("an unknown component composed")
	}
	for _, u := range []string{"", "oci://127.0.0.1:5000", "127.0.0.1:5000/bundles", "a b"} {
		if _, err := bundle.ComposeRoot("cell", composeSet(), p, u); err == nil {
			t.Errorf("store URL %q accepted", u)
		}
	}
	bad := composeSet()
	bad.Components[0].Digest = "sha256:short"
	if _, err := bundle.ComposeRoot("cell", bad, p, store); err == nil {
		t.Error("a bad digest composed")
	}
}

func TestComposeRootDeterministic(t *testing.T) {
	a := compose(t, "cell", composeSet())
	time.Sleep(1100 * time.Millisecond)
	b := compose(t, "cell", composeSet())
	if a.Digest != b.Digest || string(a.Layer) != string(b.Layer) || string(a.Manifest) != string(b.Manifest) {
		t.Fatalf("two runs differ: %s %s", a.Digest, b.Digest)
	}
	other := composeSet()
	other.Components[0].Digest = hexDigest('7')
	if compose(t, "cell", other).Digest == a.Digest {
		t.Error("a component digest did not change the root")
	}
	other = composeSet()
	other.Components[0].Wave = 6
	if compose(t, "cell", other).Digest == a.Digest {
		t.Error("a wave did not change the root")
	}
}
