package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newRepairFixtureWith is newRepairFixture with the manifests of the argocd bundle chosen by the caller, so a test can give the good root a bundle that
// the policy refuses.
func newRepairFixtureWith(t *testing.T, r *bundleRoot, argocdManifests string) repairFixture {
	t.Helper()
	f := repairFixture{netpol: "sha256:" + strings.Repeat("7", 64)}
	f.argocd = packBundle(t, r, "argocd", map[string]string{"manifests.yaml": argocdManifests})
	f.cellSys = packBundle(t, r, "cell-system", map[string]string{"manifests.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: store-marker, namespace: cell-system}\n"})
	app := func(name, digest string) string {
		return "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata: {name: " + name + ", namespace: argocd}\nspec:\n  source:\n    targetRevision: " + digest + "\n"
	}
	f.root = packBundle(t, r, "root", map[string]string{"argocd.yaml": app("argocd", f.argocd), "cell-system.yaml": app("cell-system", f.cellSys), "network-policy.yaml": app("network-policy", f.netpol)})
	var err error
	if f.rootManifest, err = os.ReadFile(filepath.Join(r.dir, "bundles", "root.manifest.json")); err != nil {
		t.Fatal(err)
	}
	f.want = map[string]string{"argocd": f.argocd, "cell-system": f.cellSys, "network-policy": f.netpol, "root": f.root}
	hexOf := func(d string) string { return strings.TrimPrefix(d, "sha256:") }
	f.subjects = `{"root":"` + hexOf(f.root) + `","argocd":"` + hexOf(f.argocd) + `","cell-system":"` + hexOf(f.cellSys) + `","network-policy":"` + hexOf(f.netpol) + `"}`
	return f
}

// TestBundleRepairPolicy: a signature proves that mgmtd signed a root, and not that the engine ever accepted it. So repair runs conftest, with the bundle.rego
// and the allow.json of the checkout and the role and the component of each bundle, over the argocd and cell-system bundles that it will apply, after
// it verified the root and before it changes anything. A good root that passes is repaired as before. A bundle that the policy denies is refused with the
// denial printed, and repair neither tags, pins, applies, deletes nor refreshes.
func TestBundleRepairPolicy(t *testing.T) {
	t.Run("a clean good root passes the policy first", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		f := newRepairFixture(t, r)
		out, errOut, log, err := r.run("bundle.sh", f.env(), "repair", "--target", "dev-cell-1")
		if err != nil {
			t.Fatalf("repair failed: %v\n%s\n%s\n%s", err, out, errOut, log)
		}
		argocd, cellSys := callIndex(log, "x -- conftest test", "--namespace bundle.allow"), -1
		for i, l := range strings.Split(log, "\n") {
			if strings.Contains(l, "x -- conftest test") && strings.Contains(l, "cell-system") {
				cellSys = i
			}
		}
		tag := callIndex(log, "oras manifest push")
		if argocd < 0 || cellSys < 0 || tag < 0 || argocd > tag || cellSys > tag {
			t.Errorf("conftest runs for argocd at %d and cell-system at %d, the tag at %d, want both checks before the first change:\n%s", argocd, cellSys, tag, log)
		}
	})
	t.Run("a bundle that the policy denies is refused before any change", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		f := newRepairFixtureWith(t, r, "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: argocd-marker, namespace: kube-system}\n")
		out, errOut, log, err := r.run("bundle.sh", f.env(), "repair", "--target", "dev-cell-1")
		if err == nil {
			t.Fatalf("repair passed with a denied bundle:\n%s\n%s\n%s", out, errOut, log)
		}
		for _, want := range []string{"component_not_allowed:namespace", "argocd", "policy"} {
			if !strings.Contains(out+errOut, want) {
				t.Errorf("the refusal lacks %q:\n%s%s", want, out, errOut)
			}
		}
		for _, change := range []string{"oras manifest push", " apply ", " patch ", " annotate ", " delete ", " create "} {
			if strings.Contains(log, change) {
				t.Errorf("repair changed something (%q) before it refused:\n%s", change, log)
			}
		}
	})
}
