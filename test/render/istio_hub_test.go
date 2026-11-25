package render

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// retiredIstioHubs are image sources that Istio tears down on 2026-12-16. Istio publishes its
// release images to docker.io/istio.
var retiredIstioHubs = []string{"registry.istio.io/release", "gcr.io/istio-release"}

// TestIstioImagesUseDockerHub checks that every render pulls Istio images from docker.io/istio.
// The sidecar injector and the egress gateway take the hub from the istiod values, so the check
// covers the injector ConfigMap too.
func TestIstioImagesUseDockerHub(t *testing.T) {
	t.Parallel()
	images := map[string]string{}
	for _, cr := range renderAll(t) {
		for _, c := range cr.components {
			for _, o := range c.objs {
				b, err := yaml.Marshal(o)
				if err != nil {
					t.Fatalf("%s/%s: %v", cr.name, c.name, err)
				}
				for _, hub := range retiredIstioHubs {
					if strings.Contains(string(b), hub) {
						t.Errorf("%s/%s: %s names the retired hub %s", cr.name, c.name, objName(o), hub)
					}
				}
				for _, img := range podImages(o) {
					images[c.name+" "+img] = cr.name
				}
			}
		}
	}
	for _, want := range []string{"istio-cni docker.io/istio/install-cni:", "istiod docker.io/istio/pilot:"} {
		found := false
		for k := range images {
			if strings.HasPrefix(k, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no render runs an image with the prefix %q", want)
		}
	}
}

// podImages returns the container images of a workload object.
func podImages(o object) []string {
	var spec any
	switch o["kind"] {
	case "Deployment", "DaemonSet", "StatefulSet":
		spec, _ = lookup(o, "spec", "template", "spec")
	default:
		return nil
	}
	m, _ := spec.(map[string]any)
	var out []string
	for _, key := range []string{"initContainers", "containers"} {
		list, _ := m[key].([]any)
		for _, c := range list {
			cm, _ := c.(map[string]any)
			if img, ok := cm["image"].(string); ok {
				out = append(out, img)
			}
		}
	}
	return out
}
