package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"sigs.k8s.io/yaml"
)

// StoreHost is the registry host and port that every Argo CD Application of a root names. Argo CD
// reaches the bundle store through the token client on this loopback address in every cluster. The
// pushes of the applier use another address and never appear in a root.
const StoreHost = "127.0.0.1:5000"

// ErrComponentNotAllowed is wrapped by the error of CheckSet. The applier reports it as the reason
// component_not_allowed, and NotAllowed holds the detail.
var ErrComponentNotAllowed = errors.New("component not allowed")

// NotAllowed is the error of CheckSet. Detail is component_unknown or namespace.
type NotAllowed struct {
	Detail    string
	Component string
}

func (e *NotAllowed) Error() string {
	return fmt.Sprintf("component not allowed: %s: %s", e.Detail, e.Component)
}

func (e *NotAllowed) Is(target error) bool { return target == ErrComponentNotAllowed }

// CheckSet checks that every component of s is a component of role and that its destination
// namespace is one that its class allows. The role and the component name fix the class.
func CheckSet(role string, s Set, p Policy) error {
	for _, c := range s.Components {
		class, ok := p.ClassOf(role, c.Name)
		if !ok {
			return &NotAllowed{Detail: "component_unknown", Component: c.Name}
		}
		if !slices.Contains(class.DestinationNamespaces, c.Namespace) {
			return &NotAllowed{Detail: "namespace", Component: c.Name}
		}
	}
	return nil
}

// ComposeRoot returns the root bundle of set s for role: one Argo CD Application for each
// component, in the file <component>.yaml. Each Application pins its bundle by digest at
// oci://StoreHost/bundles/<component>, carries the sync wave, syncs into the namespace of the
// component and takes its project from the class of the component in role. Each Application
// carries only the sync-wave annotation, so two sets with the same components give the same root.
// Each Application syncs with FailOnSharedResource=true, so that Argo CD refuses to sync an object
// that another Application already tracks, instead of letting the two take it in turns.
// It runs CheckSet first.
func ComposeRoot(role string, s Set, p Policy) (Artifact, error) {
	if err := validateComponents(slices.Clone(s.Components)); err != nil {
		return Artifact{}, err
	}
	if err := CheckSet(role, s, p); err != nil {
		return Artifact{}, err
	}
	files := make(map[string][]byte, len(s.Components))
	for _, c := range s.Components {
		class, _ := p.ClassOf(role, c.Name)
		app, err := application(c, class.Project, StoreHost)
		if err != nil {
			return Artifact{}, err
		}
		files[c.Name+".yaml"] = app
	}
	return Pack(files)
}

func application(c Component, project, storeURL string) ([]byte, error) {
	spec := map[string]any{
		"project": project,
		"source": map[string]any{
			"repoURL":        "oci://" + storeURL + "/bundles/" + c.Name,
			"targetRevision": c.Digest,
			"path":           ".",
		},
		"destination": map[string]any{
			"server":    "https://kubernetes.default.svc",
			"namespace": c.Namespace,
		},
		"syncPolicy": map[string]any{
			"automated":   map[string]any{"prune": true, "selfHeal": true},
			"syncOptions": []string{"ServerSideApply=true", "RespectIgnoreDifferences=true", "FailOnSharedResource=true"},
		},
	}
	if len(c.IgnoreDifferences) > 0 {
		var ignore []any
		if err := json.Unmarshal(c.IgnoreDifferences, &ignore); err != nil {
			return nil, fmt.Errorf("ignoreDifferences of %q: %w", c.Name, err)
		}
		spec["ignoreDifferences"] = ignore
	}
	out, err := yaml.Marshal(map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata": map[string]any{
			"name":        c.Name,
			"namespace":   "argocd",
			"annotations": map[string]any{"argocd.argoproj.io/sync-wave": strconv.Itoa(c.Wave)},
		},
		"spec": spec,
	})
	if err != nil {
		return nil, fmt.Errorf("encode Application %q: %w", c.Name, err)
	}
	return out, nil
}
