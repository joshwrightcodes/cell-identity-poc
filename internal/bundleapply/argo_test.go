package bundleapply

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func application(name string, status map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
		"metadata": map[string]any{"name": name, "namespace": "argocd"},
	}}
	if status != nil {
		u.Object["status"] = status
	}
	return u
}

func newDynamic(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{applicationGVR: "ApplicationList"}, objs...)
}

func TestListApps(t *testing.T) {
	dyn := newDynamic(
		application("root", map[string]any{
			"sync":   map[string]any{"status": "Synced", "revision": "sha256:aa"},
			"health": map[string]any{"status": "Healthy"},
		}),
		application("apps-sample", map[string]any{
			"sync":   map[string]any{"status": "OutOfSync"},
			"health": map[string]any{"status": "Progressing"},
		}),
		application("bare", nil),
	)
	got, err := listApps(t.Context(), dyn)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]appState{
		"root":        {Sync: "Synced", Health: "Healthy", Revision: "sha256:aa"},
		"apps-sample": {Sync: "OutOfSync", Health: "Progressing"},
		"bare":        {Sync: "Unknown", Health: "Unknown"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %+v, want %+v", k, got[k], w)
		}
	}
}

func TestRefreshApp(t *testing.T) {
	dyn := newDynamic(application("root", nil))
	if err := refreshApp(t.Context(), dyn, "root"); err != nil {
		t.Fatal(err)
	}
	u, err := dyn.Resource(applicationGVR).Namespace("argocd").Get(t.Context(), "root", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := u.GetAnnotations()["argocd.argoproj.io/refresh"]; got != "hard" {
		t.Fatalf("refresh annotation = %q", got)
	}
	if err := refreshApp(t.Context(), dyn, "missing"); err == nil {
		t.Fatal("refresh of a missing Application succeeded")
	}
}
