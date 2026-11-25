package bundle_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"sigs.k8s.io/yaml"
)

func composeSet() bundle.Set {
	return bundle.Set{Version: bundle.Version{Epoch: 1, Counter: 1}, Components: []bundle.Component{
		{Name: "apps-sample", Wave: 5, Namespace: "apps-sample", Digest: hexDigest('1')},
		{Name: "argocd", Wave: -1, Namespace: "argocd", Digest: hexDigest('2')},
		{Name: "istiod", Wave: 3, Namespace: "istio-system", Digest: hexDigest('3'),
			IgnoreDifferences: json.RawMessage(`[{"group":"admissionregistration.k8s.io","kind":"ValidatingWebhookConfiguration","jqPathExpressions":[".webhooks[]?.failurePolicy",".webhooks[]?.clientConfig.caBundle"]},{"group":"admissionregistration.k8s.io","kind":"MutatingWebhookConfiguration","jqPathExpressions":[".webhooks[]?.clientConfig.caBundle"]}]`)},
		{Name: "namespaces", Wave: -2, Namespace: "default", Digest: hexDigest('4')},
	}}
}

func compose(t testing.TB, role string, s bundle.Set) bundle.Artifact {
	t.Helper()
	a, err := bundle.ComposeRoot(role, s, bundle.DefaultPolicy())
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
    repoURL: oci://` + bundle.StoreHost + `/bundles/` + c.Name + `
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
      - FailOnSharedResource=true
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

// TestComposeRootFailsOnSharedResource checks that every Application of a root, of every class, refuses to
// sync an object that another Application already tracks, and keeps the other sync options.
func TestComposeRootFailsOnSharedResource(t *testing.T) {
	want := []string{"ServerSideApply=true", "RespectIgnoreDifferences=true", "FailOnSharedResource=true"}
	cp := bundle.Set{Version: bundle.Version{Epoch: 1, Counter: 2}, Components: composeSet().Components[1:]}
	for role, s := range map[string]bundle.Set{"cell": composeSet(), "cp": cp} {
		files := rootFiles(t, compose(t, role, s))
		if len(files) != len(s.Components) {
			t.Fatalf("%s: %d files for %d components", role, len(files), len(s.Components))
		}
		for name, body := range files {
			var app struct {
				Spec struct {
					SyncPolicy struct {
						SyncOptions []string `json:"syncOptions"`
					} `json:"syncPolicy"`
				} `json:"spec"`
			}
			if err := yaml.Unmarshal(body, &app); err != nil {
				t.Fatal(err)
			}
			if got := app.Spec.SyncPolicy.SyncOptions; !slices.Equal(got, want) {
				t.Errorf("%s/%s syncOptions %v, want %v", role, name, got, want)
			}
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
	withNS := func(i int, ns string) bundle.Set {
		s := composeSet()
		s.Components[i].Namespace = ns
		return s
	}
	for _, tc := range []struct {
		name         string
		role         string
		set          bundle.Set
		detail, comp string
	}{
		{"cp_apps_sample", "cp", composeSet(), "component_unknown", "apps-sample"},
		{"role_open", "open", composeSet(), "component_unknown", "apps-sample"},
		{"role_unknown", "nope", composeSet(), "component_unknown", "apps-sample"},
		{"unknown_component", "cell", bundle.Set{Components: append(composeSet().Components, bundle.Component{Name: "zzz", Namespace: "argocd", Digest: hexDigest('9')})}, "component_unknown", "zzz"},
		{"platform_namespace_outside", "cell", withNS(1, "kube-system"), "namespace", "argocd"},
		{"platform_harness_namespace", "cell", withNS(1, "cell-identity-system"), "namespace", "argocd"},
		{"app_namespace_outside", "cell", withNS(0, "argocd"), "namespace", "apps-sample"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, err := range map[string]error{
				"CheckSet":    bundle.CheckSet(tc.role, tc.set, p),
				"ComposeRoot": func() error { _, err := bundle.ComposeRoot(tc.role, tc.set, p); return err }(),
			} {
				var na *bundle.NotAllowed
				if !errors.Is(err, bundle.ErrComponentNotAllowed) || !errors.As(err, &na) || na.Detail != tc.detail || na.Component != tc.comp {
					t.Errorf("%s: got %v, want not allowed %s %s", name, err, tc.detail, tc.comp)
				}
			}
		})
	}
	// The cp class adds three namespaces that the cell class does not have.
	cp := bundle.Set{Components: []bundle.Component{{Name: "relay-system", Wave: 8, Namespace: "relay-system", Digest: hexDigest('5')}}}
	if err := bundle.CheckSet("cp", cp, p); err != nil {
		t.Errorf("cp relay-system: %v", err)
	}
	if err := bundle.CheckSet("cell", cp, p); !errors.Is(err, bundle.ErrComponentNotAllowed) {
		t.Errorf("cell relay-system: %v", err)
	}
	if err := bundle.CheckSet("cell", composeSet(), p); err != nil {
		t.Errorf("control: %v", err)
	}
	bad := composeSet()
	bad.Components[0].Digest = "sha256:short"
	if _, err := bundle.ComposeRoot("cell", bad, p); !errors.Is(err, record.ErrDecode) {
		t.Errorf("a bad digest composed: %v", err)
	}
}

func TestComposeRootStoreHost(t *testing.T) {
	if bundle.StoreHost != "127.0.0.1:5000" {
		t.Fatalf("StoreHost %q", bundle.StoreHost)
	}
	for _, body := range rootFiles(t, compose(t, "cell", composeSet())) {
		if !strings.Contains(string(body), "oci://127.0.0.1:5000/bundles/") {
			t.Errorf("Application without the store host:\n%s", body)
		}
	}
}

// The root digest must agree between mgmtd, the appliers and bundlectl. The golden file pins it, so
// a change of the YAML encoder, the tar encoder or the Application shape shows up as a failure.
func TestComposeRootGolden(t *testing.T) {
	a := compose(t, "cell", composeSet())
	checkGolden(t, "testdata/root.golden", a)
	b := compose(t, "cell", composeSet())
	if a.Digest != b.Digest || !bytes.Equal(a.Layer, b.Layer) || !bytes.Equal(a.Manifest, b.Manifest) {
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
