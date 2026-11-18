package bundleapply

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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
	phaseRunning   = "Running"
	phaseSucceeded = "Succeeded"
	// phaseTerminating is the phase that asks the application controller to end an operation.
	phaseTerminating = "Terminating"
)

// opState is the last sync operation that an Application shows in status.operationState: its phase,
// the revision that it synced (syncResult.revision), the revision that it was started for
// (operation.sync.revision) and its start time.
type opState struct {
	Phase, Revision, Target string
	StartedAt               time.Time
}

// appState is what the health wait reads from one Application: the sync status, the health status,
// the revision that the last compare resolved, and the last sync operation. Operation is true while
// the Application holds an operation request (the field operation), which the application controller
// clears when the operation ends. RV is the resource version of the read.
type appState struct {
	Sync, Health, Revision string
	Op                     opState
	Operation              bool
	RV                     string
}

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
	s := appState{Sync: unknownStatus, Health: unknownStatus, RV: u.GetResourceVersion()}
	if v, ok, _ := unstructured.NestedString(u.Object, "status", "sync", "status"); ok && v != "" {
		s.Sync = v
	}
	if v, ok, _ := unstructured.NestedString(u.Object, "status", "health", "status"); ok && v != "" {
		s.Health = v
	}
	s.Revision, _, _ = unstructured.NestedString(u.Object, "status", "sync", "revision")
	op, _, _ := unstructured.NestedMap(u.Object, "status", "operationState")
	s.Op.Phase, _, _ = unstructured.NestedString(op, "phase")
	s.Op.Revision, _, _ = unstructured.NestedString(op, "syncResult", "revision")
	s.Op.Target, _, _ = unstructured.NestedString(op, "operation", "sync", "revision")
	if v, _, _ := unstructured.NestedString(op, "startedAt"); v != "" {
		s.Op.StartedAt, _ = time.Parse(time.RFC3339, v)
	}
	_, s.Operation, _ = unstructured.NestedFieldNoCopy(u.Object, "operation")
	return s
}

// terminateOp asks Argo CD to end the running sync operation of one Application, as the API server
// does for argocd app terminate-op: it sets status.operationState.phase to Terminating, and the
// application controller then terminates the sync and marks the operation Failed. The Application has
// no status subresource, so the patch goes to the Application itself. It carries the resource version
// rv as a precondition, so that it fails with a conflict when the operation changed after the read.
func terminateOp(ctx context.Context, dyn dynamic.Interface, name, rv string) error {
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"resourceVersion": rv},
		"status":   map[string]any{"operationState": map[string]any{"phase": phaseTerminating}},
	})
	if err != nil {
		return fmt.Errorf("encode the terminate patch of %s: %w", name, err)
	}
	if _, err := dyn.Resource(applicationGVR).Namespace(argoNamespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("terminate the operation of Application %s: %w", name, err)
	}
	return nil
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
