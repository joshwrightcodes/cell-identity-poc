package scripts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	// statusRootDigest is the root that the stub of kubectl records in the bundle state and in the Application root by default.
	statusRootDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	// statusAllowSHA is the allow-list digest that the AppProjects and the status of mgmtd hold by default.
	statusAllowSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherAllowSHA  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherRoot      = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// bundleState is the content of key state.json of ConfigMap bundle-state: a signed, healthy state at statusRootDigest. over replaces fields.
func bundleState(over map[string]any) string {
	st := map[string]any{"source": "signed", "version": map[string]any{"epoch": 1, "counter": 3}, "state": "healthy", "holder": "pod-0",
		"until": timeAgo(time.Hour), "root": map[string]any{"digest": statusRootDigest}, "checkedBy": "pod-0", "good": []any{}}
	for k, v := range over {
		st[k] = v
	}
	b, _ := json.Marshal(st)
	return string(b)
}

// stubVar names the variable of the stubs for a cluster: STUB_<kind>_<cluster with underscores>.
func stubVar(kind, cluster string) string {
	return "STUB_" + kind + "_" + strings.ReplaceAll(cluster, "-", "_")
}

// TestStatusBundles checks each bundle condition of harness:status: the exit status is 1, the problem sits in the object of the cluster that
// it names, and it ends with the command to run. A state that is only a wait, and an absent cell, leave the exit status at 0.
func TestStatusBundles(t *testing.T) {
	t.Parallel()
	const publish = "Run: mise run bundle -- publish --target %s --wait"
	pub := func(c string) string { return strings.Replace(publish, "%s", c, 1) }
	rolledBack := map[string]any{"state": "rolled_back", "result": map[string]any{"outcome": "rolled_back", "reason": "unhealthy", "detail": "argocd:Synced/Degraded"}}
	rollbackFailed := map[string]any{"state": "rolled_back", "result": map[string]any{"outcome": "rolled_back", "reason": "unhealthy", "detail": "rollback_unhealthy"}}
	planeOpen := func(issued time.Duration, extra map[string]any) string {
		return healthyPlane(func(m map[string]any) {
			tb := map[string]any{"opId": "0123456789abcdef0123456789abcdef", "served": true, "issuedAt": timeAgo(issued), "expiresAt": timeAgo(-time.Hour), "rootDigest": statusRootDigest}
			for k, v := range extra {
				tb[k] = v
			}
			m["planeBundle"] = tb
		})
	}
	type bundleCase struct {
		name    string
		cluster string // the object that carries the problem; empty when the run must pass
		env     func() []string
		want    []string // substrings of the problems
		deny    []string // substrings that no problem holds
	}
	// The table is built again for each case, because its times are ages from the moment of the build.
	build := func() []bundleCase {
		return []bundleCase{
			{name: "a healthy signed state in every cluster passes", env: func() []string { return nil }},
			{name: "rolled_back", cluster: "dev-cell-2",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cell-2") + "=" + bundleState(rolledBack)}
				},
				want: []string{"dev-cell-2", "rolled_back", pub("dev-cell-2")}, deny: []string{"bundle -- repair"}},
			{name: "rolled_back in dev-cp", cluster: "dev-cp",
				env:  func() []string { return []string{stubVar("BUNDLE_STATE", "dev-cp") + "=" + bundleState(rolledBack)} },
				want: []string{"dev-cp", "rolled_back", pub("dev-cp")}, deny: []string{"bundle -- repair"}},
			{name: "rolled_back with rollback_unhealthy", cluster: "dev-cell-2",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cell-2") + "=" + bundleState(rollbackFailed)}
				},
				want: []string{"dev-cell-2", "rollback_unhealthy", "Run: mise run bundle -- repair --target dev-cell-2"}, deny: []string{"bundle -- publish"}},
			{name: "applying with until 11 minutes ago", cluster: "dev-cell-1",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cell-1") + "=" + bundleState(map[string]any{"state": "applying", "until": timeAgo(11 * time.Minute)})}
				},
				want: []string{"dev-cell-1", "applying", "more than 10 minutes", pub("dev-cell-1")}},
			{name: "rolling_back with until 11 minutes ago", cluster: "dev-cell-1",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cell-1") + "=" + bundleState(map[string]any{"state": "rolling_back", "until": timeAgo(11 * time.Minute)})}
				},
				want: []string{"dev-cell-1", "rolling_back", "more than 10 minutes", pub("dev-cell-1")}},
			{name: "applying with until 5 minutes ago is a wait",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cell-1") + "=" + bundleState(map[string]any{"state": "applying", "until": timeAgo(5 * time.Minute)})}
				}},
			{name: "applying with until in the future is a wait",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cp") + "=" + bundleState(map[string]any{"state": "applying", "until": timeAgo(-time.Minute)})}
				}},
			{name: "healthy with until long ago is no problem",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cp") + "=" + bundleState(map[string]any{"until": timeAgo(3 * time.Hour)})}
				}},
			{name: "the Application root is at another root than the state", cluster: "dev-cell-1",
				env:  func() []string { return []string{stubVar("ROOT_REV", "dev-cell-1") + "=" + otherRoot} },
				want: []string{"dev-cell-1", "Application root", otherRoot, statusRootDigest, pub("dev-cell-1")}},
			{name: "the Application root of dev-cp is at another root than the state", cluster: "dev-cp",
				env:  func() []string { return []string{stubVar("ROOT_REV", "dev-cp") + "=" + otherRoot} },
				want: []string{"dev-cp", "Application root", otherRoot, pub("dev-cp")}},
			{name: "the root differs while the state is applying is a wait",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cell-1") + "=" + bundleState(map[string]any{"state": "applying", "until": timeAgo(-time.Minute)}),
						stubVar("ROOT_REV", "dev-cell-1") + "=" + otherRoot}
				}},
			{name: "a live cell with no bundle state", cluster: "dev-cell-2",
				env:  func() []string { return []string{stubVar("BUNDLE_STATE", "dev-cell-2") + "="} },
				want: []string{"dev-cell-2", "no signed bundle state", pub("dev-cell-2")}},
			{name: "a live cell with a bootstrap state", cluster: "dev-cell-1",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cell-1") + "=" + bundleState(map[string]any{"source": "bootstrap"})}
				},
				want: []string{"dev-cell-1", "no signed bundle state", "bootstrap", pub("dev-cell-1")}},
			{name: "dev-cp with no bundle state", cluster: "dev-cp",
				env:  func() []string { return []string{stubVar("BUNDLE_STATE", "dev-cp") + "="} },
				want: []string{"dev-cp", "no signed bundle state", pub("dev-cp")}},
			{name: "a cell with no cluster has no bundle state to read", cluster: "dev-cell-2",
				env: func() []string {
					return []string{"STUB_KIND=management dev-cp dev-cell-1 rogue", stubVar("BUNDLE_STATE", "dev-cell-2") + "="}
				},
				want: []string{"has no cluster"}, deny: []string{"bundle state", "bundle --"}},
			{name: "an envd plane result that mgmtd has not closed for 6 minutes", cluster: "dev-cp",
				env:  func() []string { return []string{"STUB_MGMT_STATUS=" + planeOpen(6*time.Minute, nil)} },
				want: []string{"dev-cp", "0123456789abcdef0123456789abcdef", "more than 5 minutes", "expires at", "Run: mise run bundle -- get --target dev-cp"}, deny: []string{"cell:verify"}},
			{name: "an envd plane result open for 4 minutes is a wait",
				env: func() []string { return []string{"STUB_MGMT_STATUS=" + planeOpen(4*time.Minute, nil)} }},
			{name: "an envd plane result that mgmtd closed",
				env: func() []string {
					return []string{"STUB_MGMT_STATUS=" + planeOpen(20*time.Minute, map[string]any{"result": map[string]any{"cell": "dev-cp", "outcome": "applied"}})}
				}},
			{name: "an envd plane set that was never served",
				env: func() []string {
					return []string{"STUB_MGMT_STATUS=" + planeOpen(20*time.Minute, map[string]any{"served": false})}
				}},
			{name: "an envd plane result while envd still applies the set",
				env: func() []string {
					return []string{"STUB_MGMT_STATUS=" + healthyPlane(func(m map[string]any) {
						m["planeBundle"] = map[string]any{"opId": "0123456789abcdef0123456789abcdef", "served": true, "issuedAt": timeAgo(20 * time.Minute), "expiresAt": timeAgo(-time.Hour)}
						m["planeBundleStatus"] = map[string]any{"state": "applying", "allowSHA256": statusAllowSHA}
					})}
				}},
			{name: "an AppProject with another allow-list digest", cluster: "dev-cell-1",
				env:  func() []string { return []string{stubVar("ALLOW_ANN", "dev-cell-1") + "=" + otherAllowSHA} },
				want: []string{"dev-cell-1", "allowSHA256", statusAllowSHA, otherAllowSHA, pub("dev-cell-1")}},
			{name: "an AppProject with no allow-list annotation", cluster: "dev-cp",
				env:  func() []string { return []string{stubVar("ALLOW_ANN", "dev-cp") + "="} },
				want: []string{"dev-cp", "allowSHA256", statusAllowSHA, pub("dev-cp")}},
			{name: "an applier that runs another allow list", cluster: "dev-cell-2",
				env: func() []string {
					return []string{"STUB_MGMT_STATUS=" + healthyPlane(func(m map[string]any) {
						m["cells"] = []any{planeCell("dev-cell-1", nil), planeCell("dev-cell-2", map[string]any{
							"bundleStatus": map[string]any{"state": "healthy", "rootDigest": statusRootDigest, "allowSHA256": otherAllowSHA}})}
					})}
				},
				want: []string{"dev-cell-2", "allowSHA256", otherAllowSHA, statusAllowSHA, pub("dev-cell-2")}},
			{name: "the Application root cannot be read", cluster: "dev-cell-1", env: func() []string { return []string{"STUB_ROOT_FAIL=dev-cell-1"} },
				want: []string{"dev-cell-1", "Application root", "cannot be read", "connection to the server was refused"}},
			{name: "the Application root of dev-cp cannot be read", cluster: "dev-cp", env: func() []string { return []string{"STUB_ROOT_FAIL=dev-cp"} },
				want: []string{"dev-cp", "Application root", "cannot be read"}},
			{name: "the AppProjects cannot be read", cluster: "dev-cell-2", env: func() []string { return []string{"STUB_PROJECTS_FAIL=dev-cell-2"} },
				want: []string{"dev-cell-2", "AppProjects", "cannot be read", "connection to the server was refused"}},
			{name: "the root of a rolled_back state is compared too", cluster: "dev-cell-1",
				env: func() []string {
					return []string{stubVar("BUNDLE_STATE", "dev-cell-1") + "=" + bundleState(rolledBack), stubVar("ROOT_REV", "dev-cell-1") + "=" + otherRoot}
				},
				want: []string{"dev-cell-1", "Application root", otherRoot, statusRootDigest}},
			{name: "a cell that reported no bundle status is no allow-list mismatch",
				env: func() []string {
					return []string{"STUB_MGMT_STATUS=" + healthyPlane(func(m map[string]any) {
						m["cells"] = []any{planeCell("dev-cell-1", map[string]any{"bundleStatus": nil}), planeCell("dev-cell-2", nil)}
					})}
				}},
		}
	}
	for i, tc := range build() {
		t.Run(tc.name, func(t *testing.T) {
			tc = build()[i]
			byName, _, _, code := runStatus(t, tc.env()...)
			if tc.cluster == "" {
				if code != 0 {
					t.Fatalf("exit %d, want 0 for %s:\n%v", code, tc.name, byName)
				}
				return
			}
			if code != 1 {
				t.Fatalf("exit %d, want 1 for %s", code, tc.name)
			}
			problems := problemsOf(byName[tc.cluster])
			for _, w := range tc.want {
				if !strings.Contains(problems, w) {
					t.Errorf("the problems of %s %q lack %q", tc.cluster, problems, w)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(problems, d) {
					t.Errorf("the problems of %s %q hold %q", tc.cluster, problems, d)
				}
			}
			for name, o := range byName {
				if name != tc.cluster && o["ok"] != true {
					t.Errorf("the object of %s is not ok: %v", name, o["problems"])
				}
			}
		})
	}
}

// TestStatusExpiredUnservedBundleOps: an expired bundle.apply operation that was never served (signed with --no-serve) is information in the management
// object (unservedExpiredOps) and no problem. An expired operation that was served, or that has no served field, stays a problem with the close command.
func TestStatusExpiredUnservedBundleOps(t *testing.T) {
	t.Parallel()
	const id = "0123456789abcdef0123456789abcdef"
	ops := func(extra map[string]any) string {
		o := map[string]any{"id": id, "cell": "dev-cell-1", "state": "expired", "kind": "bundle.apply", "expiredAt": timeAgo(5 * time.Minute)}
		for k, v := range extra {
			o[k] = v
		}
		b, _ := json.Marshal(map[string]any{"ops": []any{o}})
		return "STUB_MGMT_OPS=" + string(b)
	}
	byName, _, _, code := runStatus(t, ops(map[string]any{"served": false}))
	m := byName["management"]["management"].(map[string]any)
	if list, _ := m["unservedExpiredOps"].([]any); code != 0 || len(list) != 1 || len(m["expiredOps"].([]any)) != 0 {
		t.Errorf("an unserved expired op: exit %d, unservedExpiredOps %v, expiredOps %v; want exit 0, one information entry and no failure", code, m["unservedExpiredOps"], m["expiredOps"])
	}
	for name, extra := range map[string]map[string]any{"served": {"served": true}, "no served field": nil, "another kind": {"served": false, "kind": "step"}} {
		byName, _, _, code = runStatus(t, ops(extra))
		if code != 1 || !strings.Contains(problemsOf(byName["management"]), "mise run ops -- close "+id) {
			t.Errorf("%s: exit %d, problems %q; want exit 1 with the close command", name, code, problemsOf(byName["management"]))
		}
	}
}

// TestStatusBundleChecksNeedMgmtStatus: the allow-list comparison and the open-set check read mise run mgmt -- status. When it cannot be read, the object of
// management says that these checks did not run, and no cluster passes in silence.
func TestStatusBundleChecksNeedMgmtStatus(t *testing.T) {
	t.Parallel()
	byName, _, _, code := runStatus(t, "STUB_MGMT_RC=1")
	if code != 1 || !strings.Contains(problemsOf(byName["management"]), "bundle checks that read the status of mgmtd") {
		t.Errorf("exit %d, problems %q; want a problem that names the skipped bundle checks", code, problemsOf(byName["management"]))
	}
}
