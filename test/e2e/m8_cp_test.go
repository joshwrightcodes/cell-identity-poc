//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// m8CpHydrated is the hydrated render of the apps-demo bundle of dev-cp, which cell:up leaves in the build directory.
const m8CpHydrated = "../../build/dev-cp/bundles/apps-demo/manifests.yaml"

// TestM8CpSignedBundleReachesArgoCD, in dev-cp: a bundle apps-demo that holds the hydrated objects and the ConfigMap
// apps-demo/m8-marker with a random marker is pushed to the mirror, and mgmtd signs the last set of dev-cp with this entry. envd
// applies it: the outcome is applied, the ConfigMap holds the marker, the Application spire-server is Synced at the digest of
// its signed entry, the state holds the signed version, and root is at the root digest of the state.
func TestM8CpSignedBundleReachesArgoCD(t *testing.T) {
	const target = cpClusterName
	m8RestoreTarget(t, target)
	marker := randomHex(t, 8)
	hydrated, err := os.ReadFile(filepath.FromSlash(m8CpHydrated))
	if err != nil {
		t.Fatalf("read the hydrated bundle apps-demo of %s: %v. Run: CELL=%s mise run cell:hydrate", target, err, target)
	}
	manifests := fmt.Sprintf("%s\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: m8-marker\n  namespace: apps-demo\n  labels:\n    cell.poc.internal/e2e: \"true\"\ndata:\n  marker: %q\n", strings.TrimRight(string(hydrated), "\n"), marker)
	digest := m8PushBundle(t, target, "apps-demo", []byte(manifests))

	last := m8LastSet(t, target)
	if len(last.Components) == 0 {
		t.Fatalf("%s has no signed set yet. Run: mise run bundle -- publish --target %s --wait", target, target)
	}
	var comps []bundle.Component
	spireDigest := ""
	found := false
	for _, c := range last.Components {
		if c.Name == "apps-demo" {
			c.Digest = digest
			found = true
		}
		if c.Name == "spire-server" {
			spireDigest = c.Digest
		}
		comps = append(comps, c)
	}
	if !found || spireDigest == "" {
		t.Fatalf("the last set of %s holds the components %v, want apps-demo and spire-server among them", target, last.Components)
	}
	signed := m8Sign(t, target, comps, true)
	res := m8Wait(t, target, signed.OpID, 10*time.Minute)
	if res.Result.Outcome != op.OutcomeApplied {
		t.Fatalf("the outcome is %+v, want applied", *res.Result)
	}

	out, err := kubectl(t, target, "", "-n", "apps-demo", "get", "configmap", "m8-marker", "-o", "jsonpath={.data.marker}")
	if err != nil || out != marker {
		t.Errorf("ConfigMap m8-marker holds %q (%v), want %q", out, err, marker)
	}
	spire := m8Application(t, target, "spire-server")
	if got := m8Field(spire, "status", "sync", "status"); got != "Synced" {
		t.Errorf("spire-server is %s, want Synced", got)
	}
	if got := m8Field(spire, "status", "sync", "revision"); got != spireDigest {
		t.Errorf("spire-server is at %s, want the signed digest %s", got, spireDigest)
	}
	st := m8State(t, target)
	if st.Source != "signed" || st.State != "healthy" || st.Version != signed.Version {
		t.Errorf("the state is %s/%s at %+v, want signed/healthy at %+v", st.Source, st.State, st.Version, signed.Version)
	}
	if st.Root.Digest != signed.RootDigest {
		t.Errorf("the state holds the root %s, want the root subject %s", st.Root.Digest, signed.RootDigest)
	}
	if got := m8Field(m8Application(t, target, "root"), "status", "sync", "revision"); got != st.Root.Digest {
		t.Errorf("root is at %s, want the root of the state %s", got, st.Root.Digest)
	}
}

// planeCellAddresses returns the node addresses that the policy plane-cells of a namespace of dev-cp admits, or nil when the policy
// is absent.
func planeCellAddresses(t *testing.T, ns string) []string {
	t.Helper()
	out, err := kubectl(t, cpClusterName, "", "-n", ns, "get", "networkpolicy", "plane-cells", "--ignore-not-found",
		"-o", "jsonpath={.spec.ingress[*].from[*].ipBlock.cidr}")
	if err != nil {
		t.Fatalf("read plane-cells in %s: %v", ns, err)
	}
	return strings.Fields(out)
}

// TestM8CpAdmitStageSigned deletes dev-cell-2 with cell:down and recreates it through the portal. The re-render of dev-cp after the
// delete takes the node address out of both plane-cells policies. The admit stage renders dev-cp again, and on a signed cluster that
// means a signed publish and then the render of envd. The log of the admit stage names bundle.sh publish --target dev-cp, the version
// of dev-cp rises by at least 1, both plane-cells policies admit the node address that the new cluster has, and dev-cell-2 turns valid.
func TestM8CpAdmitStageSigned(t *testing.T) {
	if testing.Short() {
		t.Skip("the admit stage creates a step and takes several minutes")
	}
	const cell = "dev-cell-2"
	if st := m8State(t, cpClusterName); st.Source != "signed" {
		t.Fatalf("the bundle state of %s has the source %q, and the test needs signed", cpClusterName, st.Source)
	}
	oldIP := clusterFacts(t, cell).NodeIP
	if oldIP == "" {
		t.Fatalf("%s has no node address, and the test starts from a live cell", cell)
	}
	for _, ns := range []string{"spire-system", "relay-system"} {
		if !slices.Contains(planeCellAddresses(t, ns), oldIP+"/32") {
			t.Fatalf("%s/plane-cells does not admit %s/32 before the test", ns, oldIP)
		}
	}

	// A failure after the delete must not leave the harness without the cell: the cleanup recreates it when its cluster is absent.
	t.Cleanup(func() {
		if !slices.Contains(kindClusters(t), cell) {
			if _, err := portal(t, "recreate", "--cell", cell, "--wait"); err != nil {
				t.Logf("FAILED to restore %s: %v. Run: mise run portal -- recreate --cell %s --wait", cell, err, cell)
				return
			}
			waitValid(t, []string{cell}, 5*time.Minute)
		}
		// A recreated cell holds the bootstrap state until a signed set reaches it.
		if m8State(t, cell).Source != "signed" {
			m8PublishSigned(t, cell)
		}
	})

	// cell:down renders dev-cp again. The address of the deleted cell must leave both policies, so a later admit adds it back.
	if out, err := miseRun(t, cellDownWait, []string{"CELL=" + cell}, "cell:down"); err != nil {
		t.Fatalf("cell:down of %s: %v\n%s", cell, err, out)
	}
	for _, ns := range []string{"spire-system", "relay-system"} {
		if got := planeCellAddresses(t, ns); slices.Contains(got, oldIP+"/32") {
			t.Fatalf("%s/plane-cells still admits %s/32 after cell:down of %s: %v", ns, oldIP, cell, got)
		}
	}
	before := m8Get(t, cpClusterName).Version

	m, err := portal(t, "recreate", "--cell", cell, "--wait")
	if err != nil {
		t.Fatalf("recreate %s: %v", cell, err)
	}
	res := portalResult(t, m)
	var id string
	for _, s := range res.Steps {
		if s.Cell == cell {
			id = s.StepID
		}
	}
	if !isStepID(id) {
		t.Fatalf("the portal printed %v, want a step for %s", m, cell)
	}

	var admit []string
	for _, s := range lastAttempts(stepLogSections(t, id)) {
		if s.stage == "admitting" && s.cluster == cpClusterName {
			admit = s.lines
		}
	}
	if !strings.Contains(strings.Join(admit, "\n"), "bundle.sh publish --target dev-cp") {
		t.Errorf("the admitting section of the step %s does not name bundle.sh publish --target dev-cp:\n%s", id, strings.Join(admit, "\n"))
	}
	after := m8Get(t, cpClusterName).Version
	if after.Epoch != before.Epoch || after.Counter < before.Counter+1 {
		t.Errorf("the version of %s is %+v after the admit stage, want at least one above %+v", cpClusterName, after, before)
	}

	ip := clusterFacts(t, cell).NodeIP
	if ip == "" {
		t.Fatalf("%s has no node address after the admit stage", cell)
	}
	for _, ns := range []string{"spire-system", "relay-system"} {
		if got := planeCellAddresses(t, ns); !slices.Contains(got, ip+"/32") {
			t.Errorf("%s/plane-cells admits %v after the admit stage, want %s/32", ns, got, ip)
		}
	}
	waitValid(t, []string{cell}, 5*time.Minute)
	m8PublishSigned(t, cell)
}

// m8PublishSigned publishes the hydrated set to a target with a signed publish and waits for the outcome applied, so that the target
// leaves the bootstrap state. It records the target for gate:m8:repair, and logs a failure instead of failing.
func m8PublishSigned(t *testing.T, target string) {
	t.Helper()
	m8RecordTarget(t, target)
	res, err := m8PublishHydrated(t, target)
	if err != nil {
		t.Logf("FAILED to publish a signed set to %s: %v. Run: mise run bundle -- publish --target %s --wait", target, err, target)
		return
	}
	if res["outcome"] != op.OutcomeApplied && res["outcome"] != op.OutcomeAlreadyApplied {
		t.Logf("the signed set of %s ended %v, want applied", target, res)
	}
}
