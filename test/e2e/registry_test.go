//go:build e2e

package e2e

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TestM4RegistryMatchesManagementRecords: each ConfigMap cell-registry on management holds, for the
// cells of its component set, the records that mgmtd serves, and holds only the key of mgmtd in
// signers.pub.
func TestM4RegistryMatchesManagementRecords(t *testing.T) {
	var served map[string]json.RawMessage
	if err := json.Unmarshal([]byte(mgmtCtl(t, "records")), &served); err != nil {
		t.Fatalf("mgmtd ctl records is no object of records: %v", err)
	}
	pub := mgmtSigningPub(t)
	for _, tc := range []struct{ namespace, set string }{
		{"central-view-system", "argocd-agent"},
		{"observability-system", "otel-uplink"},
		{"mesh-view-system", "mesh-view"},
	} {
		t.Run(tc.namespace, func(t *testing.T) {
			out, err := kubectl(t, mgmtCluster, "", "-n", tc.namespace, "get", "configmap", "cell-registry", "-o", "json")
			if err != nil {
				t.Fatal(err)
			}
			var cm struct {
				Data map[string]string `json:"data"`
			}
			if err := json.Unmarshal([]byte(out), &cm); err != nil {
				t.Fatal(err)
			}
			if got := strings.Fields(cm.Data["signers.pub"]); !slices.Equal(got, []string{pub}) {
				t.Errorf("signers.pub holds %q, want only the key of mgmt-signing-pub %q", got, pub)
			}
			want := clustersWith(t, tc.set)
			var held []string
			for key, record := range cm.Data {
				cell, ok := strings.CutSuffix(key, ".dsse.json")
				if !ok {
					if key != "signers.pub" {
						t.Errorf("cell-registry holds the unexpected key %s", key)
					}
					continue
				}
				held = append(held, cell)
				raw, ok := served[cell]
				if !ok {
					t.Errorf("cell-registry holds a record of %s, and mgmtd serves none", cell)
					continue
				}
				if got, want := compactJSON(t, record), compactJSON(t, string(raw)); got != want {
					t.Errorf("the record of %s in cell-registry differs from the one that mgmtd serves", cell)
				}
			}
			slices.Sort(held)
			slices.Sort(want)
			if !slices.Equal(held, want) {
				t.Errorf("cell-registry holds the records of %v, and the clusters with the %s set are %v", held, tc.set, want)
			}
		})
	}
}
