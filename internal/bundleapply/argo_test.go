package bundleapply

import (
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
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
	running := application("istiod", map[string]any{
		"sync":   map[string]any{"status": "OutOfSync", "revision": "sha256:cc"},
		"health": map[string]any{"status": "Degraded"},
		"operationState": map[string]any{
			"phase": "Running", "startedAt": "2026-11-18T20:09:10Z",
			"operation":  map[string]any{"sync": map[string]any{"revision": "sha256:cc"}},
			"syncResult": map[string]any{"revision": "sha256:cc"},
		},
	})
	running.Object["operation"] = map[string]any{"sync": map[string]any{"revision": "sha256:cc"}}
	running.SetResourceVersion("42")
	done := application("mesh-policy", map[string]any{
		"sync":   map[string]any{"status": "Synced", "revision": "sha256:dd"},
		"health": map[string]any{"status": "Healthy"},
		"operationState": map[string]any{
			"phase": "Succeeded", "startedAt": "2026-11-18T20:15:26Z",
			"operation":  map[string]any{"sync": map[string]any{"revision": "sha256:dd"}},
			"syncResult": map[string]any{"revision": "sha256:dd"},
		},
	})
	for _, u := range []*unstructured.Unstructured{running, done} {
		if _, err := dyn.Resource(applicationGVR).Namespace("argocd").Create(t.Context(), u, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := listApps(t.Context(), dyn)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]appState{
		"root":        {Sync: "Synced", Health: "Healthy", Revision: "sha256:aa"},
		"apps-sample": {Sync: "OutOfSync", Health: "Progressing"},
		"bare":        {Sync: "Unknown", Health: "Unknown"},
		"istiod": {Sync: "OutOfSync", Health: "Degraded", Revision: "sha256:cc", Operation: true, RV: "42",
			Op: opState{Phase: "Running", Revision: "sha256:cc", Target: "sha256:cc", StartedAt: time.Date(2026, 11, 18, 20, 9, 10, 0, time.UTC)}},
		"mesh-policy": {Sync: "Synced", Health: "Healthy", Revision: "sha256:dd",
			Op: opState{Phase: "Succeeded", Revision: "sha256:dd", Target: "sha256:dd", StartedAt: time.Date(2026, 11, 18, 20, 15, 26, 0, time.UTC)}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, w := range want {
		g := got[k]
		if k != "istiod" {
			g.RV = ""
		}
		if !g.Op.StartedAt.Equal(w.Op.StartedAt) {
			t.Errorf("%s started at %v, want %v", k, g.Op.StartedAt, w.Op.StartedAt)
		}
		g.Op.StartedAt, w.Op.StartedAt = time.Time{}, time.Time{}
		if g != w {
			t.Errorf("%s = %+v, want %+v", k, g, w)
		}
	}
}

// TestTerminateOp checks the patch that ends a running sync operation, the way the Argo CD API server
// does for argocd app terminate-op: a merge patch of status.operationState.phase to Terminating, with
// the resource version that the caller read as a precondition.
func TestTerminateOp(t *testing.T) {
	dyn := newDynamic(application("istiod", nil))
	if err := terminateOp(t.Context(), dyn, "istiod", "42"); err != nil {
		t.Fatal(err)
	}
	var patches []string
	for _, act := range dyn.Actions() {
		if p, ok := act.(k8stesting.PatchAction); ok {
			if p.GetPatchType() != types.MergePatchType || p.GetName() != "istiod" || p.GetNamespace() != "argocd" {
				t.Errorf("patch %s %s/%s, want a merge patch of argocd/istiod", p.GetPatchType(), p.GetNamespace(), p.GetName())
			}
			patches = append(patches, string(p.GetPatch()))
		}
	}
	want := `{"metadata":{"resourceVersion":"42"},"status":{"operationState":{"phase":"Terminating"}}}`
	if !slices.Equal(patches, []string{want}) {
		t.Fatalf("patches = %q, want %q", patches, want)
	}
	if err := terminateOp(t.Context(), dyn, "missing", "1"); err == nil {
		t.Fatal("terminate of a missing Application succeeded")
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
