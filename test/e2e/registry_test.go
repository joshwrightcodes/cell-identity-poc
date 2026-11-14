//go:build e2e

package e2e

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cmdrun"
)

// registryNamespaces are the view namespaces of management where mgmtd publishes ConfigMap cell-registry.
var registryNamespaces = []string{"central-view-system", "observability-system", "mesh-view-system"}

// registryWait bounds the wait for mgmtd to publish a changed record: it writes at once after a change, and checks the
// object again every minute.
const registryWait = 3 * time.Minute

// registryDiff returns why ConfigMap cell-registry of a namespace differs from the records and the key of mgmtd, or the
// empty string when it holds exactly them.
func registryDiff(t *testing.T, namespace string) string {
	t.Helper()
	res, err := cmdrun.Run(2*time.Minute, "", nil, "mise", "run", "mgmt", "--", "records")
	if err != nil || res.Code != 0 {
		return "mise run mgmt -- records failed"
	}
	var served map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &served); err != nil {
		return "mgmtd ctl records is no object of records: " + err.Error()
	}
	out, err := kubectl(t, mgmtCluster, "", "-n", namespace, "get", "configmap", "cell-registry", "-o", "json")
	if err != nil {
		return err.Error()
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &cm); err != nil {
		return err.Error()
	}
	var diffs []string
	if got := strings.Fields(cm.Data["signers.pub"]); !slices.Equal(got, []string{mgmtSigningPub(t)}) {
		diffs = append(diffs, "signers.pub holds "+strings.Join(got, " "))
	}
	for cell, raw := range served {
		if got, ok := cm.Data[cell+".dsse.json"]; !ok || compactJSON(t, got) != compactJSON(t, string(raw)) {
			diffs = append(diffs, "the record of "+cell+" differs from the one that mgmtd serves")
		}
	}
	for key := range cm.Data {
		if cell, ok := strings.CutSuffix(key, ".dsse.json"); ok && served[cell] == nil {
			diffs = append(diffs, "the registry holds the record of "+cell+", which mgmtd does not serve")
		}
	}
	slices.Sort(diffs)
	return strings.Join(diffs, "; ")
}

// waitRegistryAtCleanup makes the cleanup of the test wait until each ConfigMap cell-registry holds the records that
// mgmtd serves. mgmtd publishes them itself, so no render runs. A test that changes a cell record calls it before the
// step that changes it, so that it runs after the cleanups of that step, which settle the record.
func waitRegistryAtCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for _, ns := range registryNamespaces {
			deadline := time.Now().Add(registryWait)
			for {
				diff := registryDiff(t, ns)
				if diff == "" {
					break
				}
				if time.Now().After(deadline) {
					t.Errorf("cell-registry of %s did not follow the records of mgmtd within %s: %s. Run: mise run mgmt -- status", ns, registryWait, diff)
					break
				}
				time.Sleep(5 * time.Second)
			}
		}
	})
}

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
