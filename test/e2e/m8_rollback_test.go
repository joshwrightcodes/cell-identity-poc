//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// m8Cycle is a good set S1 that the target applies, and a bad set S2 that it rolls back.
type m8Cycle struct {
	goodSigned, badSigned mgmtapi.BundleSignResult
	goodComps, badComps   []bundle.Component
	goodDigest            string
	bad                   mgmtapi.TargetBundle
	badTook               time.Duration
}

// m8Compose returns the objects of base (which may be empty) and of the documents as one manifests text.
func m8Compose(t *testing.T, base []byte, docs ...string) []byte {
	t.Helper()
	var objs []map[string]any
	if len(base) > 0 {
		objs = append(objs, m8Objects(t, base)...)
	}
	objs = append(objs, m8Objects(t, m8Docs(docs...))...)
	return m8Render(t, objs)
}

// m8RollbackCycle applies a good set S1, whose bundle of the component holds base and a marker, and then serves a bad set S2, whose bundle
// holds base and the documents bad. It fails the test unless S1 ends applied, and returns S2 with its final result. The caller registers
// the restore of the target before it calls.
func m8RollbackCycle(t *testing.T, target, component string, wave int, namespace string, base []byte, bad ...string) m8Cycle {
	t.Helper()
	var c m8Cycle
	c.goodDigest = m8PushBundle(t, target, component, m8Compose(t, base, m8Marker("m8-marker", randomHex(t, 8))))
	c.goodComps = m8SetWithDigest(t, target, component, wave, namespace, c.goodDigest)
	var tb mgmtapi.TargetBundle
	c.goodSigned, tb = m8Offer(t, target, c.goodComps, m8SetWait)
	if tb.Result.Outcome != op.OutcomeApplied {
		t.Fatalf("the good set S1 of %s ended %+v, want applied", target, *tb.Result)
	}
	badDigest := m8PushBundle(t, target, component, m8Compose(t, base, bad...))
	c.badComps = m8SetWithDigest(t, target, component, wave, namespace, badDigest)
	start := time.Now()
	c.badSigned, c.bad = m8Offer(t, target, c.badComps, m8SetWait)
	c.badTook = time.Since(start)
	t.Logf("the bad set S2 of %s ended %s/%s/%s after %s", target, c.bad.Result.Outcome, c.bad.Result.Reason, c.bad.Result.Detail, c.badTook.Round(time.Second))
	return c
}

// m8CheckRolledBack checks what a rollback to the last good root leaves: S2 ended rolled_back with the reason unhealthy, the root and every
// child are at S1, the state keeps S1 as good[0] and holds the version of S2.
func m8CheckRolledBack(t *testing.T, target string, c m8Cycle, detail string) {
	t.Helper()
	m8WantResult(t, c.bad.Result, op.OutcomeRolledBack, op.ReasonUnhealthy, detail)
	rootS1 := m8Subject(t, c.goodSigned.Envelope, "bundles/"+target+"/root")
	if rootS1 != c.goodSigned.RootDigest {
		t.Errorf("mgmtd reports the root %s for S1, and the signed statement names %s", c.goodSigned.RootDigest, rootS1)
	}
	m8RequireAtSet(t, target, c.goodComps, rootS1)
	st := m8State(t, target)
	switch {
	case len(st.Good) == 0 || st.Good[0].Root.Digest != rootS1:
		t.Errorf("good[0] of the state is %+v, want the root %s of S1", st.Good, rootS1)
	case st.Good[0].Version != c.goodSigned.Version:
		t.Errorf("good[0] has the version %+v, want %+v of S1", st.Good[0].Version, c.goodSigned.Version)
	}
	if st.Root.Digest != rootS1 {
		t.Errorf("the state holds the root %s, want the root %s of S1", st.Root.Digest, rootS1)
	}
	if st.Version != c.badSigned.Version {
		t.Errorf("the state holds the version %+v, want %+v of S2", st.Version, c.badSigned.Version)
	}
	if st.State != "rolled_back" {
		t.Errorf("the state is %s, want rolled_back", st.State)
	}
}

// TestM8RollbackRestoresLastGoodRoot, in dev-cell-1: S1 is applied. S2 holds a Deployment that never becomes ready, and ends rolled_back
// with unhealthy and the detail apps-sample:Synced/Degraded. The root, every child and good[0] are those of S1, and the state keeps the
// version of S2. The test catches a rollback that goes to another root (good[1], the bootstrap root), prunes, or loses the version.
func TestM8RollbackRestoresLastGoodRoot(t *testing.T) {
	const cell = "dev-cell-1"
	m8RestoreTarget(t, cell)
	m8DeleteProbeDeployment(t, cell, "m8-rollback-probe")
	c := m8RollbackCycle(t, cell, "apps-sample", m8AppWave, "apps-demo", nil, m8FailingDeployment(t, "m8-rollback-probe", ""))
	m8CheckRolledBack(t, cell, c, "apps-sample:Synced/Degraded")
}

// TestM8NextVersionAfterRollback, in dev-cell-1: after a rollback, the next set that mgmtd signs has the counter of the rolled back set plus
// one, and the cell applies it. The cycle runs here again, because the restore of the test above signs a set of its own when that test
// ends. The test catches a rollback that makes a version of its own, or a cell that refuses the next version.
func TestM8NextVersionAfterRollback(t *testing.T) {
	const cell = "dev-cell-1"
	m8RestoreTarget(t, cell)
	m8DeleteProbeDeployment(t, cell, "m8-rollback-probe")
	c := m8RollbackCycle(t, cell, "apps-sample", m8AppWave, "apps-demo", nil, m8FailingDeployment(t, "m8-rollback-probe", ""))
	m8WantResult(t, c.bad.Result, op.OutcomeRolledBack, op.ReasonUnhealthy, "*")

	signed, tb := m8Offer(t, cell, c.goodComps, m8SetWait)
	m8WantResult(t, tb.Result, op.OutcomeApplied, "", "")
	if signed.Version.Epoch != c.badSigned.Version.Epoch || signed.Version.Counter != c.badSigned.Version.Counter+1 {
		t.Errorf("the next set has the version %+v, want the counter of S2 %+v plus 1", signed.Version, c.badSigned.Version)
	}
	st := m8State(t, cell)
	if st.Version != signed.Version || st.State != "healthy" {
		t.Errorf("the state is %s at %+v, want healthy at %+v", st.State, st.Version, signed.Version)
	}
	m8RequireAtSet(t, cell, c.goodComps, signed.RootDigest)
}

// TestM8CpRollbackRestoresLastGoodRoot, in dev-cp: the same cycle with the bundle apps-demo, which holds the hydrated objects. Both cells
// stay valid from the start of S2 to the end. The test catches the same defects as the cell test in envd, and a rollback of dev-cp that
// disturbs the cells.
func TestM8CpRollbackRestoresLastGoodRoot(t *testing.T) {
	t.Parallel()
	const target = cpClusterName
	m8RestoreTarget(t, target)
	m8DeleteProbeDeployment(t, target, "m8-rollback-probe")
	stop := m8WatchCells("dev-cell-1", "dev-cell-2")
	t.Cleanup(func() { stop() })
	c := m8RollbackCycle(t, target, "apps-demo", 5, "apps-demo", m8Hydrated(t, target, "apps-demo"), m8FailingDeployment(t, "m8-rollback-probe", ""))
	m8CheckRolledBack(t, target, c, "apps-demo:Synced/Degraded")
	waitValid(t, []string{"dev-cell-1", "dev-cell-2"}, 5*time.Minute)
	for _, p := range stop() {
		t.Errorf("a cell was not valid during the rollback of %s: %s", target, p)
	}
}

// TestM8RollbackPastStuckWave, in dev-cell-1 (review I-2): S2 holds two sync waves, and the Deployment of the first never becomes healthy,
// so the sync of apps-sample waits. The cell ends S2 with rolled_back and a detail that starts with timeout:apps-sample:. The root is at S1
// within the 5 min rollback wait, and apps-sample is Synced and Healthy at its digest of S1. The test logs the times for verify row 12.
// The test catches a rollback that stalls behind the running sync, and a sync timeout that does not end it.
func TestM8RollbackPastStuckWave(t *testing.T) {
	const cell = "dev-cell-1"
	m8RestoreTarget(t, cell)
	m8DeleteProbeDeployment(t, cell, "m8-stuck-probe")
	second := m8Marker("m8-stuck-marker", "second-wave")
	second = strings.Replace(second, "  labels:", "  annotations:\n    argocd.argoproj.io/sync-wave: \"1\"\n  labels:", 1)
	c := m8RollbackCycle(t, cell, "apps-sample", m8AppWave, "apps-demo", nil, m8FailingDeployment(t, "m8-stuck-probe", "0"), second)
	if r := c.bad.Result; r == nil || r.Outcome != op.OutcomeRolledBack || r.Reason != op.ReasonUnhealthy || !strings.HasPrefix(r.Detail, "timeout:apps-sample:") {
		t.Errorf("the result of S2 is %+v, want rolled_back, unhealthy and a detail that starts with timeout:apps-sample:", r)
	}
	rootS1 := m8Subject(t, c.goodSigned.Envelope, "bundles/"+cell+"/root")
	start := time.Now()
	waitFor(t, "the root and apps-sample of "+cell+" to be at S1", 5*time.Minute, func() (bool, string) {
		p := m8AtSetProblems(t, cell, c.goodComps, rootS1)
		return len(p) == 0, strings.Join(p, "; ")
	})
	t.Logf("verify row 12: S2 ended after %s, and root with apps-sample were at S1 %s later", c.badTook.Round(time.Second), time.Since(start).Round(time.Second))
	if st := m8State(t, cell); st.Root.Digest != rootS1 || st.State != "rolled_back" {
		t.Errorf("the state holds the root %s as %s, want the root %s of S1 as rolled_back", st.Root.Digest, st.State, rootS1)
	}
}

// m8GuardVAP is a ValidatingAdmissionPolicy with the name. It matches no resource that exists, and no binding names it.
func m8GuardVAP(name, run string) string {
	return fmt.Sprintf(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: %s
  annotations:
    cell.poc.internal/e2e-run: %q
  labels:
    cell.poc.internal/e2e: "true"
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["m8-never-exists"]
  validations:
    - expression: "true"
`, name, run)
}

// TestM8HarnessObjectSpared, in dev-cell-2: a bundle cannot take over an object of the harness. mgmt_root: a mesh-policy bundle that holds
// ConfigMap argocd/mgmt-root, which the harness owns with its label, is denied by the policy bundles-spare-harness when Argo CD applies it.
// The set ends rolled_back, and the ConfigMap keeps its resource version. guard_overwrite: an argocd bundle that holds the policy
// bundles-spare-harness is refused with harness_object. guard_through_project: an Application of the project cell that syncs that policy
// from the store is refused by the AppProject, and an Application that syncs another policy of the same kind is not (verify row 5). The
// test catches a guard that Argo CD can pass, an engine that lets a harness name through, and a blacklist that works by kind alone.
func TestM8HarnessObjectSpared(t *testing.T) {
	const cell = "dev-cell-2"
	m8RestoreTarget(t, cell)
	// The sets of the subtests start from the set that is live now. A rolled back set stays the last signed set, and its bundles are not
	// the live ones.
	live := m8LiveSet(t, cell)

	t.Run("mgmt_root", func(t *testing.T) {
		objs := m8Objects(t, m8LiveManifests(t, cell, "mesh-policy", m8LiveDigest(live, "mesh-policy")))
		probe := m8Objects(t, []byte(m8MarkerIn("argocd", "mgmt-root", "taken-"+randomHex(t, 4))))[0]
		// Argo CD must not prune or delete the object if the guard lets it take the object over.
		m8Annotate(probe, "argocd.argoproj.io/sync-options", "Prune=false,Delete=false")
		objs = append(objs, probe)
		digest := m8PushBundle(t, cell, "mesh-policy", m8Render(t, objs))
		comps := m8WithDigest(live, "mesh-policy", 0, "istio-system", digest)
		rv := m8ResourceVersion(t, cell, "argocd", "configmap", "mgmt-root")
		jsonpath := func(field string) string {
			out, err := kubectl(t, cell, "", "-n", "argocd", "get", "configmap", "mgmt-root", "-o", "jsonpath={.metadata."+field+"}")
			if err != nil {
				t.Fatal(err)
			}
			return strings.TrimSpace(out)
		}
		label := func() string { return jsonpath(`labels.cell\.poc\.internal/harness`) }
		tracking := func() string { return jsonpath(`annotations.argocd\.argoproj\.io/tracking-id`) }
		if rv == "" || label() == "" {
			t.Fatalf("ConfigMap argocd/mgmt-root of %s has the resource version %q and the harness label %q, want both", cell, rv, label())
		}
		// A restore after a guard that failed must not prune the trust root of the agent, so the tracking annotation of Argo CD goes first.
		t.Cleanup(func() {
			if tracking() == "" {
				return
			}
			t.Errorf("Argo CD took over ConfigMap argocd/mgmt-root of %s", cell)
			if _, err := kubectl(t, cell, "", "-n", "argocd", "annotate", "configmap", "mgmt-root", "argocd.argoproj.io/tracking-id-"); err != nil {
				t.Errorf("remove the tracking annotation of argocd/mgmt-root: %v", err)
			}
		})
		signed := m8Sign(t, cell, comps, true)
		seen := false
		tb := m8WaitEach(t, cell, signed.OpID, m8SetWait, func() {
			if !seen && strings.Contains(m8ApplicationText(t, cell, "mesh-policy"), "bundles-spare-harness") {
				seen = true
			}
		})
		m8WantResult(t, tb.Result, op.OutcomeRolledBack, op.ReasonUnhealthy, "*")
		if tb.Result != nil && !strings.HasPrefix(tb.Result.Detail, "timeout:mesh-policy:") {
			t.Errorf("the detail of the rollback is %q, want one that starts with timeout:mesh-policy: (a failed sync does not turn the Application Degraded)", tb.Result.Detail)
		}
		if !seen {
			t.Errorf("Argo CD never reported a sync error that names bundles-spare-harness for mesh-policy")
		}
		if got := m8ResourceVersion(t, cell, "argocd", "configmap", "mgmt-root"); got != rv {
			t.Errorf("ConfigMap argocd/mgmt-root has the resource version %s, want %s. Apply the harness again: CELL=%s mise run cell:up", got, rv, cell)
		}
		if got := label(); got == "" {
			t.Error("ConfigMap argocd/mgmt-root lost its harness label")
		}
		m8RequireAtSet(t, cell, live, "")
	})

	t.Run("guard_overwrite", func(t *testing.T) {
		const guard = "validatingadmissionpolicy"
		rv := m8ClusterResourceVersion(t, cell, guard, "bundles-spare-harness")
		if rv == "" {
			t.Fatalf("%s has no ValidatingAdmissionPolicy bundles-spare-harness", cell)
		}
		vap := m8Objects(t, []byte(m8GuardVAP("bundles-spare-harness", randomHex(t, 8))))
		digest := m8PushBundle(t, cell, "argocd", m8Render(t, append(m8Objects(t, m8LiveManifests(t, cell, "argocd", m8LiveDigest(live, "argocd"))), vap...)))
		before := m8Snapshot(t, cell)
		_, tb := m8Offer(t, cell, m8WithDigest(live, "argocd", 0, "argocd", digest), m8RefusalWait)
		m8WantResult(t, tb.Result, op.OutcomeRefused, op.ReasonComponentNotAllowed, "harness_object")
		m8RequireSame(t, before, m8Snapshot(t, cell))
		if got := m8ClusterResourceVersion(t, cell, guard, "bundles-spare-harness"); got != rv {
			t.Errorf("the policy bundles-spare-harness has the resource version %s, want %s", got, rv)
		}
	})

	t.Run("guard_through_project", func(t *testing.T) {
		const guard = "validatingadmissionpolicy"
		rv := m8ClusterResourceVersion(t, cell, guard, "bundles-spare-harness")
		if rv == "" {
			t.Fatalf("%s has no ValidatingAdmissionPolicy bundles-spare-harness", cell)
		}
		_, store := m8ForwardStore(t, cell)
		run := randomHex(t, 8)
		guarded := m8PushTo(t, store, "bundles/m8-guard-probe", []byte(m8GuardVAP("bundles-spare-harness", run)))
		control := m8PushTo(t, store, "bundles/m8-guard-control", []byte(m8GuardVAP("m8-guard-control", run)))
		// The Applications have no finalizer, so the deletes remove no object. This policy is the only one that the probe makes.
		t.Cleanup(func() {
			if _, err := kubectl(t, cell, "", "delete", "validatingadmissionpolicy", "m8-guard-control", "--ignore-not-found"); err != nil {
				t.Errorf("delete the control policy of %s: %v", cell, err)
			}
			if got := m8ClusterResourceVersion(t, cell, guard, "bundles-spare-harness"); got != rv {
				t.Errorf("the policy bundles-spare-harness of %s has the resource version %s, want %s. Apply the harness again: CELL=%s mise run cell:up", cell, got, rv, cell)
			}
		})
		m8CreateApplication(t, cell, "m8-guard-control", "cell", "m8-guard-control", control, "default")
		m8CreateApplication(t, cell, "m8-guard-probe", "cell", "m8-guard-probe", guarded, "default")
		m8WaitApplicationText(t, cell, "m8-guard-probe", "not permitted in project", 3*time.Minute)
		var conditions any
		_ = json.Unmarshal([]byte(strings.TrimSpace(m8jsonpath(t, cell, "m8-guard-probe", "{.status.conditions}"))), &conditions)
		t.Logf("verify row 5: Argo CD reports %v for the guard policy", conditions)
		waitFor(t, "the Application m8-guard-control of "+cell+" to be Synced", 3*time.Minute, func() (bool, string) {
			app := m8Application(t, cell, "m8-guard-control")
			return m8Field(app, "status", "sync", "status") == "Synced", m8ApplicationText(t, cell, "m8-guard-control")
		})
		if text := m8ApplicationText(t, cell, "m8-guard-control"); strings.Contains(text, "not permitted in project") {
			t.Errorf("the control Application of another policy name is refused by the project: %s", text)
		}
		if got := m8ClusterResourceVersion(t, cell, guard, "bundles-spare-harness"); got != rv {
			t.Errorf("the policy bundles-spare-harness has the resource version %s, want %s", got, rv)
		}
	})
}

// m8jsonpath returns a jsonpath of an Application.
func m8jsonpath(t *testing.T, cluster, app, path string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "application", app, "-o", "jsonpath="+path)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// m8BadStoreTokenBundle returns the manifests of the argocd bundle with the upstream of the container store-token of the repo server on
// port 5999, where nothing listens. The repo server then cannot read the store.
func m8BadStoreTokenBundle(t *testing.T, cluster string, manifests []byte) []byte {
	t.Helper()
	objs := m8Objects(t, manifests)
	found := false
	for _, o := range objs {
		meta, _ := o["metadata"].(map[string]any)
		if o["kind"] != "Deployment" || meta["name"] != "argocd-repo-server" {
			continue
		}
		spec, _ := o["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		podSpec, _ := tmpl["spec"].(map[string]any)
		containers, _ := podSpec["containers"].([]any)
		for _, ci := range containers {
			c, _ := ci.(map[string]any)
			if c["name"] != "store-token" {
				continue
			}
			args, _ := c["args"].([]any)
			for i, a := range args {
				if s, ok := a.(string); ok && strings.HasPrefix(s, "--upstream=") {
					args[i] = s[:strings.LastIndex(s, ":")] + ":5999"
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("the hydrated argocd bundle of %s has no container store-token with the flag --upstream on argocd-repo-server", cluster)
	}
	return m8Render(t, objs)
}

// m8MiseOutput runs mise with the arguments, and returns the standard output and the standard error together with the exit code. A command
// that cannot start, or that ends after the limit, gives code -1.
func m8MiseOutput(limit time.Duration, args ...string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	out, err := exec.CommandContext(ctx, "mise", args...).CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	}
	return string(out) + err.Error(), -1
}

// TestM8BadArgocdSetNeedsRepair, in dev-cell-2, after the test above (review C-2): a set whose argocd bundle points the store token client of
// the repo server at port 5999 ends rolled_back with rollback_unhealthy, because Argo CD cannot read the store to restore the good root.
// mise run harness:status then exits 1 and names the command bundle -- repair --target dev-cell-2. The repair puts every Application back at
// the digests of good[0] within 15 min, and the hydrated set that follows ends applied. The test catches a rollback that cannot see its own
// failure, a status that hides the need for the repair, and a repair that does not restore the Applications.
func TestM8BadArgocdSetNeedsRepair(t *testing.T) {
	const cell = "dev-cell-2"
	m8RestoreTarget(t, cell)
	m8DeleteProbeDeployment(t, cell, "m8-repair-probe")
	var hydratedRoot string
	// The cleanup handles both outcomes of the bad set, and never leaves the cell on the bad root. A set that the cell rolled back is
	// repaired with the command under test. A set that the cell applied by mistake has the bad root as good[0], so the hydrated argocd
	// bundle goes back by hand, and the restore publish that follows finds a repo server that can read the store.
	t.Cleanup(func() {
		if hydratedRoot == "" || !m8RepoServerBroken(t, cell) {
			return
		}
		if st := m8State(t, cell); len(st.Good) > 0 && st.Good[0].Root.Digest == hydratedRoot {
			if out, err := m8Command(t, 25*time.Minute, "", "run", "bundle", "--", "repair", "--target", cell); err != nil {
				t.Errorf("repair %s after a failure: %v\n%s", cell, err, out)
			}
			return
		}
		applyArgs := []string{"apply", "--server-side", "--force-conflicts", "-f", "-"}
		if _, err := kubectl(t, cell, string(m8Hydrated(t, cell, "argocd")), applyArgs...); err != nil {
			t.Errorf("apply the hydrated argocd bundle of %s: %v", cell, err)
			return
		}
		if _, err := kubectl(t, cell, "", "-n", "argocd", "rollout", "status", "deployment/argocd-repo-server", "--timeout=300s"); err != nil {
			t.Errorf("the repo server of %s did not roll out after the hydrated bundle: %v", cell, err)
		}
	})

	if res, err := m8PublishHydrated(t, cell); err != nil || res["outcome"] != op.OutcomeApplied {
		t.Fatalf("the hydrated set of %s ended %v (%v), want applied before the bad set", cell, res, err)
	}
	st := m8State(t, cell)
	if len(st.Good) == 0 || st.Good[0].Root.Digest != st.Root.Digest {
		t.Fatalf("good[0] of %s is %+v after the publish, want the root %s", cell, st.Good, st.Root.Digest)
	}
	hydratedRoot = st.Root.Digest
	// Repair trusts only a root that cosign verifies against the key of mgmtd. The publish attached the Sigstore bundle of this root.
	if out, err := m8Command(t, 5*time.Minute, "", "run", "bundle", "--", "verify", "--target", cell); err != nil {
		t.Fatalf("the root %s of %s does not verify, so repair could not trust it: %v\n%s", hydratedRoot, cell, err, out)
	}

	live := m8LiveSet(t, cell)
	badArgocd := m8PushBundle(t, cell, "argocd", m8BadStoreTokenBundle(t, cell, m8LiveManifests(t, cell, "argocd", m8LiveDigest(live, "argocd"))))
	// The cache of Argo CD can hide a broken repo server, so the set also holds a new bundle that never becomes healthy: the health wait
	// and the rollback must then read the store through the broken token client.
	probe := m8PushBundle(t, cell, "apps-sample", []byte(m8FailingDeployment(t, "m8-repair-probe", "")))
	comps := m8WithDigest(m8WithDigest(live, "argocd", 0, "argocd", badArgocd), "apps-sample", m8AppWave, "apps-demo", probe)
	start := time.Now()
	_, tb := m8Offer(t, cell, comps, 30*time.Minute)
	t.Logf("the bad argocd set of %s ended %v after %s", cell, *tb.Result, time.Since(start).Round(time.Second))
	if tb.Result.Outcome == op.OutcomeApplied {
		t.Fatalf("the bad argocd set of %s ended applied, so it did not fail health and the test has nothing to repair. The cleanup puts the hydrated argocd bundle back", cell)
	}
	m8WantResult(t, tb.Result, op.OutcomeRolledBack, op.ReasonUnhealthy, "rollback_unhealthy")
	good0 := m8State(t, cell).Good[0]
	if good0.Root.Digest != hydratedRoot {
		t.Fatalf("good[0] of %s holds the root %s, want the hydrated root %s", cell, good0.Root.Digest, hydratedRoot)
	}

	statusOut, code := m8MiseOutput(30*time.Minute, "run", "harness:status")
	if code != 1 {
		t.Errorf("mise run harness:status exited %d, want 1", code)
	}
	if want := "mise run bundle -- repair --target " + cell; !strings.Contains(statusOut, want) {
		t.Errorf("mise run harness:status does not name %q:\n%s", want, statusOut)
	}

	repaired := time.Now()
	out, err := m8Command(t, 25*time.Minute, "", "run", "bundle", "--", "repair", "--target", cell)
	if err != nil {
		t.Fatalf("repair %s: %v\n%s", cell, err, out)
	}
	var res struct {
		Target string `json:"target"`
		Root   string `json:"root"`
	}
	if err := json.Unmarshal([]byte(m8LastLine(out)), &res); err != nil || res.Target != cell || res.Root != good0.Root.Digest {
		t.Errorf("repair printed %q, want a line for %s with the root %s of good[0] (%v)", out, cell, good0.Root.Digest, err)
	}
	var good []bundle.Component
	for name, d := range good0.Components {
		good = append(good, bundle.Component{Name: name, Digest: d})
	}
	waitFor(t, "every Application of "+cell+" to be at good[0]", 15*time.Minute, func() (bool, string) {
		p := m8AtSetProblems(t, cell, good, good0.Root.Digest)
		return len(p) == 0, strings.Join(p, "; ")
	})
	t.Logf("the repair of %s took %s", cell, time.Since(repaired).Round(time.Second))

	res2, err := m8PublishHydrated(t, cell)
	if err != nil {
		t.Fatalf("the hydrated set of %s after the repair: %v", cell, err)
	}
	if res2["outcome"] != op.OutcomeApplied {
		t.Errorf("the hydrated set of %s ended %v after the repair, want applied", cell, res2)
	}
}

// m8RepoServerBroken reports whether the repo server of the cluster still points its store token client at port 5999.
func m8RepoServerBroken(t *testing.T, cluster string) bool {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "deployment", "argocd-repo-server", "-o",
		`jsonpath={.spec.template.spec.containers[?(@.name=="store-token")].args}`)
	if err != nil {
		t.Errorf("read the repo server of %s: %v", cluster, err)
		return false
	}
	return strings.Contains(out, ":5999")
}
