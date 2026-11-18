//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// m8Refusal is one set that a cell must refuse. The bundle of the component holds the live objects of the component and the probe, and
// the set is the live set of the target with that bundle in place of the live bundle. A component that the target does not run is added
// with the wave and the namespace, and its bundle holds the probe only. A set that the engine accepts by mistake then changes one object
// and prunes nothing.
type m8Refusal struct {
	name      string
	component string
	wave      int
	namespace string
	// manifests holds the probe objects that the bundle gets in addition to the live objects of the component. edit changes a live object
	// in place and returns it. Each object that a case adds or changes carries an annotation with a random value, so that the digest of the
	// bundle differs in every run.
	manifests []byte
	edit      func(t *testing.T, objs []map[string]any) map[string]any
	reason    string
	detail    string
}

// m8RunRefusals signs and serves each set in turn. Each must end refused with the reason and the detail, leave the bundle state and every
// Application as they were, and leave the digest of its bundle out of the store that Argo CD reads. storeAddr is the address of the
// loopback registry of the store of the target, which takes no token. Each set is the live set with one bundle replaced.
// The bundle holds the live objects of the component and the probe.
func m8RunRefusals(t *testing.T, target, storeAddr string, live []bundle.Component, cases []m8Refusal) {
	t.Helper()
	run := randomHex(t, 6)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			liveDigest := m8LiveDigest(live, c.component)
			var objs, changed []map[string]any
			if liveDigest != "" {
				objs = m8Objects(t, m8LiveManifests(t, target, c.component, liveDigest))
			}
			if c.edit != nil {
				changed = append(changed, c.edit(t, objs))
			}
			if len(c.manifests) > 0 {
				added := m8Objects(t, c.manifests)
				objs = append(objs, added...)
				changed = append(changed, added...)
			}
			for _, o := range changed {
				m8Annotate(o, "cell.poc.internal/e2e-run", run+"-"+c.name)
			}
			digest := m8PushBundle(t, target, c.component, m8Render(t, objs))
			comps := m8WithDigest(live, c.component, c.wave, c.namespace, digest)
			before := m8Snapshot(t, target)
			signed, tb := m8Offer(t, target, comps, m8RefusalWait)
			m8WantResult(t, tb.Result, op.OutcomeRefused, c.reason, c.detail)
			m8RequireSame(t, before, m8Snapshot(t, target))
			if got := m8StoreHead(t, storeAddr, "bundles/"+c.component, digest); got != 404 {
				t.Errorf("HEAD of %s in the store of %s gives %d, want 404, after the refusal of %s", digest, target, got, signed.OpID)
			}
			// A HEAD of the live digest must find it, or the 404 above could come from a wrong repository path.
			if liveDigest != "" {
				if got := m8StoreHead(t, storeAddr, "bundles/"+c.component, liveDigest); got != 200 {
					t.Errorf("HEAD of the live digest %s in the store of %s gives %d, want 200", liveDigest, target, got)
				}
			}
		})
	}
}

// TestM8BundleVersionOld, in dev-cell-1 (row 14): two sets are signed and not served, set A and then set B with the next version.
// The cell applies B, and then refuses A with version_old. The state and root stay at B. The test catches an applier that applies a
// version below the state, and a root that moves back.
func TestM8BundleVersionOld(t *testing.T) {
	const cell = "dev-cell-1"
	m8RestoreTarget(t, cell)
	digestA := m8PushBundle(t, cell, "apps-sample", []byte(m8Marker("m8-marker", "a-"+randomHex(t, 8))))
	digestB := m8PushBundle(t, cell, "apps-sample", []byte(m8Marker("m8-marker", "b-"+randomHex(t, 8))))
	a := m8Sign(t, cell, m8SetWithDigest(t, cell, "apps-sample", m8AppWave, "apps-demo", digestA), false)
	b := m8Sign(t, cell, m8SetWithDigest(t, cell, "apps-sample", m8AppWave, "apps-demo", digestB), false)
	if b.Version.Compare(a.Version) <= 0 {
		t.Fatalf("set B has the version %+v, want one above %+v of set A", b.Version, a.Version)
	}
	envA, envB := m8OperationEnvelope(t, a.OpID), m8OperationEnvelope(t, b.OpID)

	enqueueSigned(t, cell, envB, false)
	resB := m8WaitOp(t, b.OpID, m8SetWait)
	m8WantResult(t, resB.Result, op.OutcomeApplied, "", "")
	st := m8State(t, cell)
	rootB := m8Subject(t, b.Envelope, "bundles/"+cell+"/root")
	if st.Version != b.Version || st.Root.Digest != rootB {
		t.Fatalf("the state holds the version %+v and the root %s after B, want %+v and %s", st.Version, st.Root.Digest, b.Version, rootB)
	}
	before := m8Snapshot(t, cell)

	since := time.Now().Add(-logMargin)
	enqueueSigned(t, cell, envA, false)
	waitCelldSaw(t, cell, since, a.OpID, op.OutcomeRefused, op.ReasonVersionOld, m8RefusalWait)
	resA := m8WaitOp(t, a.OpID, m8RefusalWait)
	m8WantResult(t, resA.Result, op.OutcomeRefused, op.ReasonVersionOld, "")
	after := m8State(t, cell)
	if after.Root.Digest != rootB || after.Version != b.Version {
		t.Errorf("the state holds the root %s at %+v after A, want the root %s of B at %+v", after.Root.Digest, after.Version, rootB, b.Version)
	}
	if got := m8Field(m8Application(t, cell, "root"), "status", "sync", "revision"); got != rootB {
		t.Errorf("root is at %s after A, want the root %s of B", got, rootB)
	}
	m8RequireSame(t, before, m8Snapshot(t, cell))
}

// TestM8CpSetRefusedInCell (row 15): a set that mgmtd signed for dev-cp, and that a hand enqueues for dev-cell-1, is refused with
// wrong_target. The root of the cell stays. The test catches a cell that applies a set for another target.
func TestM8CpSetRefusedInCell(t *testing.T) {
	const cell = "dev-cell-1"
	m8RestoreOnFailure(t, cell)
	last := m8LastSet(t, cpClusterName)
	if len(last.Components) == 0 {
		t.Fatalf("%s has no signed set yet. Run: mise run bundle -- publish --target %s --wait", cpClusterName, cpClusterName)
	}
	signed := m8Sign(t, cpClusterName, last.Components, false)
	envelope := m8OperationEnvelope(t, signed.OpID)
	before := m8Snapshot(t, cell)
	seen := cellStatusOf(t, cell).ForgedSeen
	since := time.Now().Add(-logMargin)
	enqueueSigned(t, cell, envelope, true)
	waitCelldSaw(t, cell, since, signed.OpID, op.OutcomeRefused, op.ReasonWrongTarget, m8RefusalWait)
	waitForgedSeen(t, cell, seen, m8RefusalWait)
	requireOpOpen(t, signed.OpID)
	m8RequireSame(t, before, m8Snapshot(t, cell))
}

// m8AppCases are the sets of an app bundle that the policy refuses, each with the detail of its denial. The bundle is apps-sample.
func m8AppCases() []m8Refusal {
	app := func(name, manifests, detail string) m8Refusal {
		return m8Refusal{name: name, component: "apps-sample", wave: m8AppWave, namespace: "apps-demo", manifests: []byte(manifests),
			reason: op.ReasonComponentNotAllowed, detail: detail}
	}
	return []m8Refusal{
		app("kind_networkpolicy", `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: m8-probe
  namespace: apps-demo
  labels:
    cell.poc.internal/e2e: "true"
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
`, "kind"),
		app("kind_authorizationpolicy", `apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: m8-probe
  namespace: apps-demo
  labels:
    cell.poc.internal/e2e: "true"
spec:
  action: ALLOW
`, "kind"),
		app("namespace_argocd", m8MarkerIn("argocd", "m8-probe", "x"), "namespace"),
		app("service_nodeport", `apiVersion: v1
kind: Service
metadata:
  name: m8-probe
  namespace: apps-demo
  labels:
    cell.poc.internal/e2e: "true"
spec:
  type: NodePort
  selector:
    app: m8-probe
  ports:
    - port: 80
`, "service_type"),
		app("mesh_opt_out", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: m8-probe
  namespace: apps-demo
  labels:
    cell.poc.internal/e2e: "true"
spec:
  selector:
    matchLabels:
      app: m8-probe
  template:
    metadata:
      labels:
        app: m8-probe
        sidecar.istio.io/inject: "false"
    spec:
      containers:
        - name: probe
          image: registry.invalid/m8-probe
`, "mesh_opt_out"),
	}
}

// TestM8AppBundleOutsideAllowList, in dev-cell-1 (row 18, first layer): the engine refuses each app bundle that the class app does not
// allow, with component_not_allowed and the detail of the policy. The digest is never in the store, and no Application changes. The
// test catches a policy that lets one of the kinds, namespaces, Service types or opt-outs through.
func TestM8AppBundleOutsideAllowList(t *testing.T) {
	const cell = "dev-cell-1"
	m8RestoreOnFailure(t, cell)
	addr, _ := m8ForwardStore(t, cell)
	m8RunRefusals(t, cell, addr, m8LiveSet(t, cell), m8AppCases())
}

// TestM8CpBundleOutsideAllowList, in dev-cp (row 18): the engine of envd refuses a bundle that writes in a harness namespace. A set with a
// component that the role cp lacks never reaches the cell, because mgmtd refuses to compose its root.
func TestM8CpBundleOutsideAllowList(t *testing.T) {
	const target = cpClusterName
	m8RestoreOnFailure(t, target)
	addr, _ := m8ForwardStore(t, target)
	inNamespace := func(ns string) []byte { return []byte(m8MarkerIn(ns, "m8-probe", "x")) }
	live := m8LiveSet(t, target)
	m8RunRefusals(t, target, addr, live, []m8Refusal{
		{name: "spire_server_writes_envd_system", component: "spire-server", manifests: inNamespace("envd-system"),
			reason: op.ReasonComponentNotAllowed, detail: "harness_namespace"},
		{name: "relay_writes_gateway_system", component: "relay-system", manifests: inNamespace("gateway-system"),
			reason: op.ReasonComponentNotAllowed, detail: "harness_namespace"},
	})
	t.Run("apps_sample_in_cp", func(t *testing.T) {
		digest := m8PushBundle(t, target, "apps-sample", []byte(m8Marker("m8-probe", randomHex(t, 8))))
		comps := m8WithDigest(live, "apps-sample", m8AppWave, "apps-demo", digest)
		before := m8Snapshot(t, target)
		out, err := signRefused(t, target, comps)
		if err == nil || !payloadInvalidSet.MatchString(out+err.Error()) {
			t.Fatalf("signing a set with the component apps-sample for %s gave %v and %q, want the refusal payload_invalid with the detail set from mgmtd", target, err, out)
		}
		m8RequireSame(t, before, m8Snapshot(t, target))
		if got := m8StoreHead(t, addr, "bundles/apps-sample", digest); got != 404 {
			t.Errorf("HEAD of %s in the store of %s gives %d, want 404", digest, target, got)
		}
	})
}

var payloadInvalidSet = regexp.MustCompile(`payload_invalid\W+set\b`)

// signRefused asks mgmtd to sign the components, and returns the error of the call. The call must not change the target.
func signRefused(t *testing.T, target string, comps []bundle.Component) (string, error) {
	t.Helper()
	body, err := json.Marshal(comps)
	if err != nil {
		t.Fatal(err)
	}
	return m8Command(t, 2*time.Minute, string(body), "run", "mgmt", "--", "bundle", "sign", "--target", target)
}

// TestM8AppProjectRefusesKind, in dev-cell-1 (row 18, second layer): a NetworkPolicy bundle that a hand pushes into the store through the
// loopback port-forward, and that an Application in the project cell-app names, is refused by Argo CD with "not permitted in project".
// No NetworkPolicy of that name reaches apps-demo. The test catches an AppProject that lets a kind through.
func TestM8AppProjectRefusesKind(t *testing.T) {
	const cell = "dev-cell-1"
	_, store := m8ForwardStore(t, cell)
	name := "m8-probe-" + randomHex(t, 4)
	manifests := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: apps-demo
  labels:
    cell.poc.internal/e2e: "true"
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
`, name)
	digest := m8PushTo(t, store, "bundles/m8-project-probe", []byte(manifests))
	m8CreateApplication(t, cell, "m8-project-probe", "cell-app", "m8-project-probe", digest, "apps-demo")
	m8WaitApplicationText(t, cell, "m8-project-probe", "not permitted in project", 2*time.Minute)
	out, err := kubectl(t, cell, "", "-n", "apps-demo", "get", "networkpolicy", name, "--ignore-not-found", "-o", "name")
	if err != nil || strings.TrimSpace(out) != "" {
		t.Errorf("apps-demo holds the NetworkPolicy %s (%v): %q", name, err, out)
	}
}

// TestM8AppLimitsPolicy, in dev-cell-1 (row 18, third layer): a Service of type NodePort that a hand pushes into the store, and that an
// Application in the project cell-app syncs, is denied by the policy bundles-app-limits. The policy matches a tracking ID that starts with
// the name of an app component, and Argo CD builds the ID from the name of the Application, so the Application is named apps-sample.
// The cell has no such Application while no set carries the component. The test catches a missing or a loose policy.
func TestM8AppLimitsPolicy(t *testing.T) {
	const cell = "dev-cell-1"
	_, store := m8ForwardStore(t, cell)
	name := "m8-nodeport-" + randomHex(t, 4)
	manifests := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: apps-demo
  labels:
    cell.poc.internal/e2e: "true"
spec:
  type: NodePort
  selector:
    app: %s
  ports:
    - port: 80
`, name, name)
	digest := m8PushTo(t, store, "bundles/m8-app-limits", []byte(manifests))
	m8CreateApplication(t, cell, "apps-sample", "cell-app", "m8-app-limits", digest, "apps-demo")
	m8WaitApplicationText(t, cell, "apps-sample", "bundles-app-limits", 3*time.Minute)
	out, err := kubectl(t, cell, "", "-n", "apps-demo", "get", "service", name, "--ignore-not-found", "-o", "name")
	if err != nil || strings.TrimSpace(out) != "" {
		t.Errorf("apps-demo holds the Service %s (%v): %q", name, err, out)
	}
}

// TestM8PlatformBundleBlocksPlanes, in dev-cell-1 (row 19): a platform bundle that replaces a plane policy, or that turns the mesh on
// in a guarded namespace, is refused with policy_blocks_planes. The detail names the policy, or mesh_injection. The test catches a policy
// that lets a bundle replace a plane flow.
func TestM8PlatformBundleBlocksPlanes(t *testing.T) {
	const cell = "dev-cell-1"
	m8RestoreOnFailure(t, cell)
	addr, _ := m8ForwardStore(t, cell)
	policy := func(ns, name string) []byte {
		return []byte(fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: %s
  labels:
    cell.poc.internal/e2e: "true"
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
`, name, ns))
	}
	blocked := func(name, component, detail string, manifests []byte) m8Refusal {
		return m8Refusal{name: name, component: component, manifests: manifests, reason: op.ReasonPolicyBlocksPlanes, detail: detail}
	}
	m8RunRefusals(t, cell, addr, m8LiveSet(t, cell), []m8Refusal{
		blocked("agent_policy_replaced", "network-policy", "argocd/argocd-agent", policy("argocd", "argocd-agent")),
		blocked("store_policy_replaced", "network-policy", "cell-system/plane-celld-store", policy("cell-system", "plane-celld-store")),
		{name: "mesh_injection_argocd", component: "namespaces", reason: op.ReasonPolicyBlocksPlanes, detail: "mesh_injection",
			edit: func(t *testing.T, objs []map[string]any) map[string]any {
				for _, o := range objs {
					meta, _ := o["metadata"].(map[string]any)
					if o["kind"] == "Namespace" && meta["name"] == "argocd" {
						labels, _ := meta["labels"].(map[string]any)
						if labels == nil {
							labels = map[string]any{}
							meta["labels"] = labels
						}
						labels["istio-injection"] = "enabled"
						return o
					}
				}
				t.Fatal("the live bundle namespaces has no Namespace argocd")
				return nil
			}},
	})
}

// TestM8CpBundleBlocksPlanes, in dev-cp (row 19): a bundle that names a plane policy of spire-system or relay-system is refused with
// policy_blocks_planes. A spire-server bundle with no NetworkPolicy at all is applied, and both cells stay valid, so no policy of a bundle
// carries a plane flow. The test catches a policy that does not protect the plane policies of the role cp.
func TestM8CpBundleBlocksPlanes(t *testing.T) {
	const target = cpClusterName
	m8RestoreTarget(t, target)
	addr, _ := m8ForwardStore(t, target)
	policy := func(ns, name string) []byte {
		return []byte(fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: %s
  labels:
    cell.poc.internal/e2e: "true"
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
`, name, ns))
	}
	live := m8LiveSet(t, target)
	label, err := kubectl(t, target, "", "-n", "gateway-system", "get", "networkpolicy", "default-deny", "-o", `jsonpath={.metadata.labels.cell\.poc\.internal/harness}`)
	if err != nil || strings.TrimSpace(label) == "" {
		t.Fatalf("NetworkPolicy gateway-system/default-deny of %s has the harness label %q (%v), and the test needs it", target, label, err)
	}
	m8RunRefusals(t, target, addr, live, []m8Refusal{
		{name: "spire_names_plane_cells", component: "spire-server", manifests: policy("spire-system", "plane-cells"),
			reason: op.ReasonPolicyBlocksPlanes, detail: "spire-system/plane-cells"},
		{name: "relay_names_plane_upstream", component: "relay-system", manifests: policy("relay-system", "plane-upstream"),
			reason: op.ReasonPolicyBlocksPlanes, detail: "relay-system/plane-upstream"},
		// default-deny of gateway-system carries the harness label and no list names it, so only the match against the live harness
		// policies refuses it. Without that match the refusal is harness_namespace.
		{name: "harness_policy_not_listed", component: "network-policy", manifests: policy("gateway-system", "default-deny"),
			reason: op.ReasonPolicyBlocksPlanes, detail: "gateway-system/default-deny"},
	})
	t.Run("spire_drops_own_rules_passes", func(t *testing.T) {
		var kept []map[string]any
		for _, o := range m8Objects(t, m8LiveManifests(t, target, "spire-server", m8LiveDigest(live, "spire-server"))) {
			if o["kind"] != "NetworkPolicy" {
				kept = append(kept, o)
			}
		}
		digest := m8PushBundle(t, target, "spire-server", m8Render(t, kept))
		stop := m8WatchCells("dev-cell-1", "dev-cell-2")
		_, tb := m8Offer(t, target, m8WithDigest(live, "spire-server", 0, "spire-system", digest), m8SetWait)
		m8WantResult(t, tb.Result, op.OutcomeApplied, "", "")
		waitValid(t, []string{"dev-cell-1", "dev-cell-2"}, 5*time.Minute)
		for _, p := range stop() {
			t.Errorf("a cell was not valid while the set was applied: %s", p)
		}
		out, err := kubectl(t, target, "", "-n", "argocd", "get", "application", "spire-server", "-o",
			`jsonpath={.status.resources[?(@.kind=="NetworkPolicy")].name}`)
		if err != nil || strings.TrimSpace(out) != "" {
			t.Errorf("the Application spire-server of %s still holds the NetworkPolicies %q (%v)", target, out, err)
		}
	})
}

// m8Token returns a token of the service account for the audience, from the TokenRequest API of the cluster. It lives only in memory.
func m8Token(t *testing.T, cluster, ns, account, audience string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "create", "token", account, "--audience", audience, "--duration", "10m")
	if err != nil {
		t.Fatalf("create a token for %s/%s in %s: %v", ns, account, cluster, err)
	}
	return strings.TrimSpace(out)
}

var requestIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// m8DeniedLog waits for the line of store-proxy that names the request ID, and returns its reason and detail.
func m8DeniedLog(t *testing.T, cluster, id string) (reason, detail string) {
	t.Helper()
	waitFor(t, "store-proxy of "+cluster+" to log the denial "+id, time.Minute, func() (bool, string) {
		logs, err := kubectl(t, cluster, "", "-n", m8CellStoreNS, "logs", "bundle-store-0", "-c", "store-proxy", "--since=15m")
		if err != nil {
			return false, err.Error()
		}
		for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "request denied" && l.str("request_id") == id }) {
			reason, detail = l.str("reason"), l.str("detail")
			return true, ""
		}
		return false, lastLines(logs, 2)
	})
	return reason, detail
}

// TestM8StoreTokenChecks, in dev-cell-1 and in dev-cp (row 33): through a port-forward to the Service bundle-store, the store proxy admits
// the reader and the writer of the cluster only for their own methods. Each refusal is a 403 with a request ID, and the log of store-proxy
// names the same reason and detail under that ID. Tokens come from the TokenRequest API with the audience bundle-store and a lifetime of
// 10 minutes, and stay in memory. The test catches a proxy that lets a writer read, or lets any other identity, method or path through.
func TestM8StoreTokenChecks(t *testing.T) {
	for _, c := range []struct{ cluster, writerNS, writer string }{
		{"dev-cell-1", "cell-identity-system", "celld"},
		{cpClusterName, "envd-system", "envd"},
	} {
		t.Run(c.cluster, func(t *testing.T) {
			addr := portForward(t, c.cluster, m8CellStoreNS, "svc/bundle-store", m8StoreProxyPort)
			repoServer := m8Token(t, c.cluster, "argocd", "argocd-repo-server", "bundle-store")
			writer := m8Token(t, c.cluster, c.writerNS, c.writer, "bundle-store")
			// No other account of the cluster is an applier, so the controller of Argo CD stands for another identity that writes.
			other := m8Token(t, c.cluster, "argocd", "argocd-application-controller", "bundle-store")
			defaultSA := m8Token(t, c.cluster, "apps-demo", "default", "bundle-store")
			wrongAudience := m8Token(t, c.cluster, c.writerNS, c.writer, "other")
			const manifest = "/v2/bundles/root/manifests/current"
			const uploads = "/v2/bundles/m8-probe/blobs/uploads/"

			for _, d := range []struct {
				name, method, path, token string
				reasons, details          []string
			}{
				{"repo_server_write", "POST", uploads, repoServer, []string{"peer_not_allowed"}, []string{"subject"}},
				{"writer_read", "GET", manifest, writer, []string{"peer_not_allowed"}, []string{"subject"}},
				{"other_applier_write", "POST", uploads, other, []string{"peer_not_allowed"}, []string{"subject"}},
				{"no_token_read", "GET", manifest, "", []string{"peer_not_allowed"}, []string{"no_token"}},
				{"no_token_write", "POST", uploads, "", []string{"peer_not_allowed"}, []string{"no_token"}},
				{"wrong_audience", "GET", manifest, wrongAudience, []string{"peer_not_allowed"}, []string{"token_invalid", "audience"}},
				{"default_sa", "GET", manifest, defaultSA, []string{"peer_not_allowed"}, []string{"subject"}},
				{"writer_delete", "DELETE", manifest, writer, []string{"request_not_allowed"}, []string{"method"}},
				{"tags_list", "GET", "/v2/bundles/root/tags/list", repoServer, []string{"request_not_allowed"}, []string{"path"}},
			} {
				t.Run(d.name, func(t *testing.T) {
					status, id := m8StoreRequest(t, addr, d.method, d.path, d.token)
					if status != 403 {
						t.Fatalf("%s %s gave %d, want 403", d.method, d.path, status)
					}
					if !requestIDRE.MatchString(id) {
						t.Fatalf("X-Request-Id is %q, want 16 hex characters", id)
					}
					reason, detail := m8DeniedLog(t, c.cluster, id)
					if !containsString(d.reasons, reason) || !containsString(d.details, detail) {
						t.Errorf("store-proxy logged %s/%s for %s, want %v/%v", reason, detail, id, d.reasons, d.details)
					}
				})
			}
			t.Run("repo_server_read", func(t *testing.T) {
				if status, _ := m8StoreRequest(t, addr, "GET", manifest, repoServer); status != 200 {
					t.Errorf("GET %s with the repo server token gave %d, want 200", manifest, status)
				}
			})
		})
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
