package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

// ComposeRoot returns the root bundle of set s for role: one Argo CD Application for each
// component, in the file <component>.yaml. Each Application pins its bundle by digest at
// oci://<storeURL>/bundles/<component>, carries the sync wave, syncs into the namespace of the
// component and takes its project from the class of the component in role. storeURL is the
// registry host and port, with no scheme and no path. Each Application carries only the sync-wave
// annotation, so two sets with the same components give the same root.
func ComposeRoot(role string, s Set, p Policy, storeURL string) (Artifact, error) {
	if storeURL == "" || strings.ContainsAny(storeURL, "/ ") {
		return Artifact{}, errors.New("store URL is not a host and port")
	}
	if err := validateComponents(slicesClone(s.Components)); err != nil {
		return Artifact{}, err
	}
	files := make(map[string][]byte, len(s.Components))
	for _, c := range s.Components {
		class, ok := p.ClassOf(role, c.Name)
		if !ok {
			return Artifact{}, fmt.Errorf("component %q has no class in role %q", c.Name, role)
		}
		app, err := application(c, class.Project, storeURL)
		if err != nil {
			return Artifact{}, err
		}
		files[c.Name+".yaml"] = app
	}
	return Pack(files)
}

func slicesClone(cs []Component) []Component { return append([]Component(nil), cs...) }

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
			"syncOptions": []string{"ServerSideApply=true", "RespectIgnoreDifferences=true"},
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
