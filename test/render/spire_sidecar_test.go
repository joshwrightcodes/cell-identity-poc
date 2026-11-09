package render

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// goldenCelld holds the cell-identity render of M2, before the sidecar helper existed. The image
// digest of the stub registry is replaced by stubDigest, so the file does not depend on the gzip
// output of one Go version. UPDATE_GOLDEN=1 writes the file again from the current render.
const (
	goldenCelld = "testdata/celld-deployment.golden.yaml"
	stubDigest  = "sha256:stub"
)

// devEnvCA is a fixed CA certificate of dev.env.poc.internal. The golden render uses it as the
// trust bundle, so its config checksum is the same in every run. The key was discarded.
func devEnvCA(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("testdata/dev-env-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// sameObjects compares two renders object by object, with list order kept.
func sameObjects(t *testing.T, got, want map[string]object) {
	t.Helper()
	var keys []string
	for k := range want {
		keys = append(keys, k)
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		g, w := got[k], want[k]
		if !reflect.DeepEqual(g, w) {
			gy, _ := yaml.Marshal(g)
			wy, _ := yaml.Marshal(w)
			t.Errorf("%s differs from the golden render.\ngot:\n%s\nwant:\n%s", k, gy, wy)
		}
	}
}

// TestSpireSidecarClusterJWTMatchesCelld renders celld through the sidecar helper and compares
// every object with the M2 render, so the helper keeps the deployed celld pod as it is.
func TestSpireSidecarClusterJWTMatchesCelld(t *testing.T) {
	r := renderCellIdentity(t, "STUB_BUNDLE_FILE="+devEnvCA(t))
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	out := strings.ReplaceAll(r.stdout, r.digest, stubDigest)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(goldenCelld, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenCelld)
	if err != nil {
		t.Fatal(err)
	}
	sameObjects(t, docsIn(t, out, "cell-identity-system"), docsIn(t, string(want), "cell-identity-system"))
}
