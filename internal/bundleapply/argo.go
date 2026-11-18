package bundleapply

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

var applicationGVR = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}

const (
	argoNamespace  = "argocd"
	refreshKey     = "argocd.argoproj.io/refresh"
	unknownStatus  = "Unknown"
	statusSynced   = "Synced"
	statusHealthy  = "Healthy"
	statusDegraded = "Degraded"
)

// appState is what the health wait reads from one Application: the sync status, the health status
// and the revision that the last sync resolved.
type appState struct{ Sync, Health, Revision string }

func (s appState) String() string { return s.Sync + "/" + s.Health }

// listApps returns the state of every Application in the Argo CD namespace, by name. A missing
// status field reads as Unknown.
func listApps(ctx context.Context, dyn dynamic.Interface) (map[string]appState, error) {
	list, err := dyn.Resource(applicationGVR).Namespace(argoNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Applications: %w", err)
	}
	out := make(map[string]appState, len(list.Items))
	for _, u := range list.Items {
		out[u.GetName()] = readApp(u)
	}
	return out, nil
}

func readApp(u unstructured.Unstructured) appState {
	s := appState{Sync: unknownStatus, Health: unknownStatus}
	if v, ok, _ := unstructured.NestedString(u.Object, "status", "sync", "status"); ok && v != "" {
		s.Sync = v
	}
	if v, ok, _ := unstructured.NestedString(u.Object, "status", "health", "status"); ok && v != "" {
		s.Health = v
	}
	s.Revision, _, _ = unstructured.NestedString(u.Object, "status", "sync", "revision")
	return s
}

// refreshApp asks Argo CD for a hard refresh of one Application.
func refreshApp(ctx context.Context, dyn dynamic.Interface, name string) error {
	patch := []byte(`{"metadata":{"annotations":{"` + refreshKey + `":"hard"}}}`)
	_, err := dyn.Resource(applicationGVR).Namespace(argoNamespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("refresh Application %s: %w", name, err)
	}
	return nil
}
