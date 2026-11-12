//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cmdrun"
)

const (
	guardPolicy = "argocd-agent-read-only"
	// demoApp and demoNS name the Application and the namespace of the demo workloads.
	demoApp = "apps-demo"
	demoNS  = "apps-demo"
)

// jsonOf runs kubectl with -o json and decodes the object.
func jsonOf(t *testing.T, cluster string, args ...string) map[string]any {
	t.Helper()
	out, err := kubectl(t, cluster, "", append(args, "-o", "json")...)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatalf("decode %v: %v", args, err)
	}
	return obj
}

func field(obj map[string]any, path ...string) any {
	var cur any = obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func canonical(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// cellAppFacts is the part of an Application of a cell that the view must not change: the
// annotations, labels, owner references, operation and status, without status.reconciledAt, which
// the controller sets at its own pace.
func cellAppFacts(t *testing.T, cell string) map[string]string {
	t.Helper()
	app := jsonOf(t, cell, "-n", agentNamespace, "get", "application", demoApp)
	return map[string]string{
		"annotations":     canonical(field(app, "metadata", "annotations")),
		"labels":          canonical(field(app, "metadata", "labels")),
		"ownerReferences": canonical(field(app, "metadata", "ownerReferences")),
		"finalizers":      canonical(field(app, "metadata", "finalizers")),
		"spec":            canonical(field(app, "spec")),
		"operation":       canonical(field(app, "operation")),
		"operationState":  canonical(field(app, "status", "operationState")),
		"sync":            canonical(field(app, "status", "sync", "status")),
		"health":          canonical(field(app, "status", "health", "status")),
	}
}

func requireSameFacts(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s: the %s of the Application in the cell changed:\n  before %s\n  after  %s", what, k, v, after[k])
		}
	}
}

// mgmtPatch merge-patches the management copy of the Application of a cell and returns its new
// resource version. The principal sends the change to the agent as an event whose ID ends in
// _<resource version>, and the agent log names that ID.
func mgmtPatch(t *testing.T, agent, patch string) string {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", agent, "patch", "application", demoApp, "--type", "merge", "-p", patch,
		"-o", "jsonpath={.metadata.resourceVersion}")
	if err != nil {
		t.Fatalf("patch the management copy in %s with %s: %v", agent, patch, err)
	}
	rv := strings.TrimSpace(out)
	if rv == "" {
		t.Fatalf("the patch of the management copy in %s returned no resource version", agent)
	}
	t.Logf("patched the management copy in %s with %s: resource version %s", agent, patch, rv)
	return rv
}

// agentEventOutcome reads the agent log of a cell for the event of the management resource version
// rv. refused holds the lines with an error and an event ID that ends in _<rv>. applied holds the
// lines where the agent reports that it wrote the Application: an action line with the resource
// version rv and no error.
func agentEventOutcome(t *testing.T, cell, rv string) (refused, applied []string) {
	t.Helper()
	logs, err := kubectl(t, cell, "", "-n", agentNamespace, "logs", "deploy/"+agentDeployment, "-c", agentDeployment)
	if err != nil {
		return nil, nil
	}
	for l := range strings.SplitSeq(logs, "\n") {
		var rec struct {
			EventID         string `json:"event_id"`
			Error           string `json:"error"`
			Action          string `json:"action"`
			ResourceVersion string `json:"resourceVersion"`
		}
		if json.Unmarshal([]byte(l), &rec) != nil {
			continue
		}
		switch {
		case rec.Error != "" && strings.HasSuffix(rec.EventID, "_"+rv):
			refused = append(refused, l)
		case rec.Error == "" && rec.Action != "" && rec.ResourceVersion == rv:
			applied = append(applied, l)
		}
	}
	return refused, applied
}

// eventWait bounds the wait for the agent to handle one event of the principal.
const eventWait = 90 * time.Second

// awaitRefusal waits until the agent has handled the event of the management resource version rv.
// The agent must have refused it with a Forbidden error, and the log line proves that the event
// arrived. A log line that shows a write, or a change of the Application in the cell, is a failure
// of the test, and the wait ends at once.
func awaitRefusal(t *testing.T, cell, rv string, before map[string]string) {
	t.Helper()
	waitFor(t, "the agent of "+cell+" to handle the event of resource version "+rv, eventWait, func() (bool, string) {
		refused, applied := agentEventOutcome(t, cell, rv)
		if len(applied) > 0 {
			t.Errorf("the agent wrote the Application for the event %s: %s", rv, applied[0])
			return true, ""
		}
		if len(refused) > 0 {
			if !strings.Contains(strings.ToLower(refused[0]), "forbidden") {
				t.Errorf("the agent failed the event %s with an error that is not Forbidden: %s", rv, refused[0])
			}
			t.Logf("the agent refused the event %s: %s", rv, refused[0])
			return true, ""
		}
		after := cellAppFacts(t, cell)
		for k, v := range before {
			if after[k] != v {
				t.Errorf("the Application in the cell changed its %s, and the agent log shows no refusal of the event %s", k, rv)
				return true, ""
			}
		}
		return false, "no line of the agent for the event, and no change in the cell"
	})
}

// TestM3ViewWritesFail sends writes through the resource proxy, as the central view could. Each
// one fails with Forbidden, and the objects in the cell keep their resource versions.
func TestM3ViewWritesFail(t *testing.T) {
	for _, cell := range viewCells(t) {
		t.Run(cell, func(t *testing.T) {
			requireViewConnected(t, agentName(cell))
			cs, _ := viewClient(t, agentName(cell))
			rv := func() [3]string {
				return [3]string{
					field(jsonOf(t, cell, "-n", demoNS, "get", "deployment", "echo"), "metadata", "resourceVersion").(string),
					field(jsonOf(t, cell, "-n", demoNS, "get", "service", "echo"), "metadata", "resourceVersion").(string),
					fmt.Sprint(field(jsonOf(t, cell, "-n", demoNS, "get", "deployment", "echo"), "spec", "replicas")),
				}
			}
			before := rv()
			ctx, cancel := ctxTimeout()
			defer cancel()

			_, err := cs.CoreV1().ConfigMaps(demoNS).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "view-write-test"}}, metav1.CreateOptions{})
			requireForbidden(t, "create a ConfigMap", err)
			_, err = cs.AppsV1().Deployments(demoNS).Patch(ctx, "echo", types.MergePatchType, []byte(`{"spec":{"replicas":3}}`), metav1.PatchOptions{})
			requireForbidden(t, "patch the replicas of Deployment echo", err)
			err = cs.CoreV1().Services(demoNS).Delete(ctx, "echo", metav1.DeleteOptions{})
			requireForbidden(t, "delete Service echo", err)

			if _, err := kubectl(t, cell, "", "-n", demoNS, "get", "configmap", "view-write-test"); err == nil {
				t.Error("the ConfigMap view-write-test exists in the cell")
			}
			if after := rv(); after != before {
				t.Errorf("Deployment echo, Service echo and the replicas are %v, were %v", after, before)
			}
		})
	}
}

func requireForbidden(t *testing.T, what string, err error) {
	t.Helper()
	switch {
	case err == nil:
		t.Errorf("%s through the resource proxy succeeded", what)
	case !apierrors.IsForbidden(err):
		t.Errorf("%s through the resource proxy failed with %v, want Forbidden", what, err)
	default:
		t.Logf("%s: %v", what, err)
	}
}

// TestM3ViewAnnotationChangesFail changes the management copy of the Application of dev-cell-1 in
// two steps: a new annotation together with a bogus refresh value, and then a sync operation. After
// each step it waits until the agent log shows the refusal of that event, and then checks that the
// Application in the cell is as it was. The principal sends each change as an event, and the agent
// has no right to apply it. An agent that may patch the Application copies the refresh annotation and
// the operation, and no other annotation: UpdateOperation computes its patch from the difference
// in the refresh annotation only. So a cell without the new annotation proves nothing alone, and
// the refresh value and the operation are the changes that can reach the cell.
func TestM3ViewAnnotationChangesFail(t *testing.T) {
	cell, agent := "dev-cell-1", agentName("dev-cell-1")
	requireViewConnected(t, agent)
	before := cellAppFacts(t, cell)
	t.Cleanup(func() {
		_, _ = kubectl(t, mgmtCluster, "", "-n", agent, "patch", "application", demoApp, "--type", "merge",
			"-p", `{"metadata":{"annotations":{"poc.internal/test":null,"argocd.argoproj.io/refresh":null}},"operation":null}`)
	})
	for _, step := range []string{
		`{"metadata":{"annotations":{"poc.internal/test":"1","argocd.argoproj.io/refresh":"bogus"}}}`,
		`{"operation":{"sync":{"revision":"HEAD"}}}`,
	} {
		awaitRefusal(t, cell, mgmtPatch(t, agent, step), before)
	}
	after := cellAppFacts(t, cell)
	requireSameFacts(t, "after the two changes", before, after)
	for _, key := range []string{"poc.internal/test", "argocd.argoproj.io/refresh"} {
		if strings.Contains(after["annotations"], key) {
			t.Errorf("the Application in the cell has the annotation %s: %s", key, after["annotations"])
		}
	}
	if after["operation"] != "null" {
		t.Errorf("the Application in the cell has the operation %s, want none", after["operation"])
	}
}

// TestM3ViewStatusPatchFails patches status.operationState.phase of the management copy to
// Terminating. The principal sends a terminate-operation event, and the agent would patch the
// status of the Application in the cell. The test waits until the agent log shows the refusal, and
// then checks that the cell keeps its status. The Application in the cell has no owner reference
// patch to test: the autonomous agent applies an incoming update only to the annotations and the
// operation (internal/manager/application UpdateOperation), so no owner-reference case can fail.
func TestM3ViewStatusPatchFails(t *testing.T) {
	cell, agent := "dev-cell-1", agentName("dev-cell-1")
	requireViewConnected(t, agent)
	before := cellAppFacts(t, cell)
	rv := mgmtPatch(t, agent, `{"status":{"operationState":{"phase":"Terminating"}}}`)
	awaitRefusal(t, cell, rv, before)
	after := cellAppFacts(t, cell)
	if strings.Contains(after["operationState"], "Terminating") && !strings.Contains(before["operationState"], "Terminating") {
		t.Errorf("the operation state of the Application in the cell is %s", after["operationState"])
	}
	requireSameFacts(t, "after the status patch", before, after)
}

// TestM3ViewRefreshFails asks the central API for a refresh of the Application of dev-cell-1. The
// central argocd-server has no right to write in the agent namespace, so the call fails with 403
// and the message of the API server. The Application in the cell and the management copy never
// get a refresh annotation from it.
func TestM3ViewRefreshFails(t *testing.T) {
	cell, agent := "dev-cell-1", agentName("dev-cell-1")
	requireViewConnected(t, agent)
	addr := centralForward(t)
	for _, mode := range []string{"normal", "hard"} {
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Get("http://" + addr + "/api/v1/applications/" + demoApp + "?refresh=" + mode + "&appNamespace=" + agent)
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 4096)
		n, _ := resp.Body.Read(raw)
		resp.Body.Close()
		var body struct{ Error, Message string }
		_ = json.Unmarshal(raw[:n], &body)
		t.Logf("refresh=%s: HTTP %d: %s", mode, resp.StatusCode, strings.TrimSpace(body.Error))
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body.Error, `cannot patch resource "applications"`) {
			t.Errorf("refresh=%s: HTTP %d %q, want 403 with the refusal of the API server for the patch", mode, resp.StatusCode, body.Error)
		}
	}
	for what, annotations := range map[string]string{
		"the Application in the cell": mustKubectl(t, cell, "-n", agentNamespace, "get", "application", demoApp, "-o", "jsonpath={.metadata.annotations}"),
		"the management copy":         mustKubectl(t, mgmtCluster, "-n", agent, "get", "application", demoApp, "-o", "jsonpath={.metadata.annotations}"),
	} {
		if strings.Contains(annotations, "argocd.argoproj.io/refresh") {
			t.Errorf("%s has a refresh annotation: %s", what, annotations)
		}
	}
}

// TestM3ViewExecFails asks the resource proxy for an exec in pod echo, and logs the refusal. The
// pod has no such file, and the agent ServiceAccount has no right to exec by itself.
func TestM3ViewExecFails(t *testing.T) {
	cell := "dev-cell-1"
	requireViewConnected(t, agentName(cell))
	pod := strings.TrimSpace(mustKubectl(t, cell, "-n", demoNS, "get", "pods", "-l", "app=echo", "-o", "jsonpath={.items[0].metadata.name}"))
	t.Run("through the resource proxy", func(t *testing.T) {
		_, cfg := viewClient(t, agentName(cell))
		httpClient, err := rest.HTTPClientFor(cfg)
		if err != nil {
			t.Fatal(err)
		}
		url := cfg.Host + "/api/v1/namespaces/" + demoNS + "/pods/" + pod + "/exec?container=echo&command=touch&command=/tmp/view-exec&stdout=true"
		resp, err := httpClient.Post(url, "application/json", nil)
		if err != nil {
			t.Fatalf("POST %s: %v", url, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		t.Logf("exec through the resource proxy: HTTP %d, body %q", resp.StatusCode, strings.TrimSpace(string(body)))
		t.Logf("the refusal comes from the principal (principal/terminal.go), which allows a terminal only for a managed agent")
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "web terminal is only supported for managed agents") {
			t.Errorf("exec through the resource proxy answered HTTP %d %q, want 400 and the refusal of the principal", resp.StatusCode, strings.TrimSpace(string(body)))
		}
	})
	t.Run("nothing ran in the pod", func(t *testing.T) {
		out, err := kubectl(t, cell, "", "-n", demoNS, "exec", pod, "-c", "echo", "--", "ls", "/tmp/view-exec")
		if err == nil {
			t.Fatalf("the file /tmp/view-exec exists in the pod: %s", out)
		}
		if !strings.Contains(err.Error(), "No such file") {
			t.Fatalf("the admin exec failed for another reason than a missing file: %v", err)
		}
	})
	t.Run("as the agent ServiceAccount", func(t *testing.T) {
		_, err := kubectl(t, cell, "", "--as", agentAccount, "-n", demoNS, "exec", pod, "-c", "echo", "--", "true")
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "forbidden") {
			t.Fatalf("kubectl exec as the agent ServiceAccount: %v, want Forbidden", err)
		}
		t.Logf("%v", err)
	})
}

func mustKubectl(t *testing.T, cluster string, args ...string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestM3ViewSecretReadsFail reads Secrets through the resource proxy. Each get and each list fails
// with an error, and no list answers with an empty list. The canary Secret keeps its marker out of
// every object that the central view holds.
func TestM3ViewSecretReadsFail(t *testing.T) {
	cell := "dev-cell-1"
	agent := agentName(cell)
	requireViewConnected(t, agent)
	cs, _ := viewClient(t, agent)
	t.Run("a read of a managed object works", func(t *testing.T) {
		ctx, cancel := ctxTimeout()
		defer cancel()
		d, err := cs.AppsV1().Deployments(demoNS).Get(ctx, "echo", metav1.GetOptions{})
		if err != nil || d.Name != "echo" {
			t.Fatalf("get Deployment echo through the resource proxy: %v, so the refusals below prove nothing", err)
		}
	})
	for _, ns := range []string{"argocd", "istio-system", demoNS} {
		t.Run("get in "+ns, func(t *testing.T) {
			name := map[string]string{"argocd": "argocd-redis", "istio-system": "istio-ca-secret", demoNS: "view-canary"}[ns]
			if out := mustKubectl(t, cell, "-n", ns, "get", "secret", name, "-o", "name"); !strings.Contains(out, name) {
				t.Fatalf("the Secret %s/%s does not exist, so the get proves nothing: %q", ns, name, out)
			}
			ctx, cancel := ctxTimeout()
			defer cancel()
			s, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
			if err == nil {
				t.Fatalf("get Secret %s/%s through the resource proxy returned %d keys", ns, name, len(s.Data))
			}
			if !apierrors.IsForbidden(err) {
				t.Errorf("get Secret %s/%s through the resource proxy failed with %v, want Forbidden from the RBAC of the agent", ns, name, err)
			}
			t.Logf("get %s/%s: %v", ns, name, err)
		})
		t.Run("list in "+ns, func(t *testing.T) {
			ctx, cancel := ctxTimeout()
			defer cancel()
			l, err := cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
			if err == nil {
				t.Fatalf("list Secrets in %s through the resource proxy returned %d items, want an error", ns, len(l.Items))
			}
			t.Logf("list in %s: %v", ns, err)
		})
	}
	t.Run("the marker stays in the cell", func(t *testing.T) {
		raw := mustKubectl(t, cell, "-n", demoNS, "get", "secret", "view-canary", "-o", "jsonpath={.data.marker}")
		marker := decodeB64(t, raw)
		if len(marker) < 16 {
			t.Fatalf("the canary marker is %q", marker)
		}
		addr := centralForward(t)
		for _, path := range []string{
			"/api/v1/applications/" + demoApp + "/managed-resources?appNamespace=" + agent,
			"/api/v1/applications/" + demoApp + "/resource-tree?appNamespace=" + agent,
			"/api/v1/applications/" + demoApp + "?appNamespace=" + agent,
			"/api/v1/applications?appNamespace=" + agent,
		} {
			body := string(centralAPIAt(t, addr, path))
			if strings.Contains(body, marker) || strings.Contains(body, raw) {
				t.Errorf("%s holds the canary marker", path)
			}
			if path == "/api/v1/applications/"+demoApp+"/managed-resources?appNamespace="+agent && !strings.Contains(body, "view-canary") {
				t.Errorf("%s does not list the Secret view-canary, so the check proves nothing", path)
			}
		}
		// management runs the apps-demo bundle too, so its own Secret view-canary holds the marker.
		out, err := kubectl(t, mgmtCluster, "", "get", "secrets,configmaps,applications.argoproj.io", "-A", "-o", "json")
		if err != nil {
			t.Fatal(err)
		}
		var list struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			t.Fatal(err)
		}
		for _, item := range list.Items {
			var meta struct {
				Kind     string
				Metadata struct{ Namespace, Name string }
			}
			if err := json.Unmarshal(item, &meta); err != nil {
				t.Fatal(err)
			}
			if meta.Kind == "Secret" && meta.Metadata.Namespace == demoNS && meta.Metadata.Name == "view-canary" {
				continue
			}
			if strings.Contains(string(item), marker) || strings.Contains(string(item), raw) {
				t.Errorf("%s %s/%s in management holds the canary marker", meta.Kind, meta.Metadata.Namespace, meta.Metadata.Name)
			}
		}
	})
}

// TestM3AgentCannotReadOrEscalate asks the API server what the agent ServiceAccount may do in each
// cell. In argocd it may list and watch Secrets, which the agent needs to start. Every other answer
// is no.
func TestM3AgentCannotReadOrEscalate(t *testing.T) {
	type check struct {
		name, verb, resource, sub, ns string
		want                          bool
	}
	var checks []check
	for _, ns := range []string{"argocd", "istio-system", demoNS} {
		for _, verb := range []string{"get", "list", "watch"} {
			want := ns == "argocd" && verb != "get"
			checks = append(checks, check{fmt.Sprintf("%s secrets in %s", verb, ns), verb, "secrets", "", ns, want})
		}
	}
	for _, sub := range []string{"exec", "attach", "portforward"} {
		for _, ns := range []string{"argocd", demoNS} {
			checks = append(checks, check{fmt.Sprintf("create pods/%s in %s", sub, ns), "create", "pods", sub, ns, false})
		}
	}
	for _, r := range []string{"pods", "services"} {
		for _, ns := range []string{"argocd", demoNS} {
			checks = append(checks, check{fmt.Sprintf("get %s/proxy in %s", r, ns), "get", r, "proxy", ns, false})
		}
	}
	checks = append(checks,
		check{"get nodes/proxy", "get", "nodes", "proxy", "", false},
		check{"create serviceaccounts/token for default in argocd", "create", "serviceaccounts/default", "token", "argocd", false},
		check{"create serviceaccounts/token for default in apps-demo", "create", "serviceaccounts/default", "token", demoNS, false},
		check{"create serviceaccounts/token for echo in apps-demo", "create", "serviceaccounts/echo", "token", demoNS, false},
		check{"create serviceaccounts/token for argocd-agent in argocd", "create", "serviceaccounts/argocd-agent", "token", "argocd", true},
	)
	for _, verb := range []string{"update", "patch", "delete"} {
		checks = append(checks, check{fmt.Sprintf("%s applications in argocd", verb), verb, "applications.argoproj.io", "", "argocd", false})
	}
	for _, r := range []string{"users", "groups", "serviceaccounts"} {
		checks = append(checks, check{"impersonate " + r, "impersonate", r, "", "", false})
	}
	for _, r := range []string{"roles", "clusterroles"} {
		for _, verb := range []string{"escalate", "bind"} {
			checks = append(checks, check{fmt.Sprintf("%s %s", verb, r), verb, r + ".rbac.authorization.k8s.io", "", "", false})
		}
	}
	for _, r := range []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"} {
		for _, verb := range []string{"create", "update", "patch", "delete"} {
			checks = append(checks, check{fmt.Sprintf("%s %s", verb, r), verb, r + ".admissionregistration.k8s.io", "", "", false})
		}
	}
	for _, cell := range viewCells(t) {
		for _, c := range checks {
			t.Run(cell+"/"+c.name, func(t *testing.T) {
				args := []string{"auth", "can-i", c.verb, c.resource, "--as=" + agentAccount}
				if c.sub != "" {
					args = append(args, "--subresource="+c.sub)
				}
				if c.ns != "" {
					args = append(args, "-n", c.ns)
				}
				out, _ := kubectl(t, cell, "", args...)
				got := strings.TrimSpace(out)
				if got != map[bool]string{true: "yes", false: "no"}[c.want] {
					t.Errorf("can-i %s: %q, want %v", strings.Join(args[2:], " "), got, c.want)
				}
			})
		}
	}
}

// TestM3ViewTokenRequestFails sends token requests for the agent ServiceAccount through the
// resource proxy. The proxy forwards a POST to a subresource only when the parent object is managed
// by an Argo CD Application (agent/resource.go lines 581 to 602), and the ServiceAccount of the
// agent is not. Each request must fail with 403, and the agent log must name that refusal. The last
// case is the body that the guard admits: a SPIRE audience bound to the agent Pod. Only the managed
// check stops it, so a ServiceAccount that Argo CD manages would open it. cell:verify checks that.
func TestM3ViewTokenRequestFails(t *testing.T) {
	cell := "dev-cell-1"
	requireViewConnected(t, agentName(cell))
	cs, _ := viewClient(t, agentName(cell))
	podName, podUID := podFacts(t, cell, agentDeployment)
	secs := int64(600)
	for _, tc := range []struct {
		name string
		spec authenticationv1.TokenRequestSpec
	}{
		{"the audience of the API server", authenticationv1.TokenRequestSpec{Audiences: []string{"https://kubernetes.default.svc"}, ExpirationSeconds: &secs}},
		{"a SPIRE audience, no bound Pod", authenticationv1.TokenRequestSpec{Audiences: []string{"spire-" + pocEnv + "/x"}, ExpirationSeconds: &secs}},
		{"the body that the guard admits", authenticationv1.TokenRequestSpec{Audiences: []string{"spire-" + pocEnv + "/abc_DEF-123"}, ExpirationSeconds: &secs,
			BoundObjectRef: &authenticationv1.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: podName, UID: types.UID(podUID)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			since := time.Now().Add(-2 * time.Second)
			ctx, cancel := ctxTimeout()
			defer cancel()
			res := cs.CoreV1().RESTClient().Post().Namespace("argocd").Resource("serviceaccounts").Name("argocd-agent").SubResource("token").
				Body(&authenticationv1.TokenRequest{Spec: tc.spec}).Do(ctx)
			var code int
			res.StatusCode(&code)
			raw, err := res.Raw()
			t.Logf("HTTP %d, body %q, error %v", code, strings.TrimSpace(string(raw)), err)
			if err == nil || strings.Contains(string(raw), `"token"`) {
				t.Fatalf("the token request through the resource proxy answered HTTP %d with a token", code)
			}
			if code != http.StatusForbidden || err.Error() == "" {
				t.Errorf("the token request answered HTTP %d with the error %q, want 403 and a message", code, err)
			}
			waitFor(t, "the agent log to name the managed-object refusal", time.Minute, func() (bool, string) {
				logs, lerr := kubectl(t, cell, "", "-n", agentNamespace, "logs", "deploy/"+agentDeployment, "-c", agentDeployment, "--since-time="+since.UTC().Format(time.RFC3339))
				if lerr != nil {
					return false, lerr.Error()
				}
				for l := range strings.SplitSeq(logs, "\n") {
					if strings.Contains(l, "resource not managed by app") && strings.Contains(l, "argocd-agent") {
						t.Logf("refused by the managed-object check of the agent: %s", l)
						return true, ""
					}
				}
				return false, "no line with 'resource not managed by app' for argocd-agent"
			})
		})
	}
}

func decodeB64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// guardTestGroup is the group of the temporary grants. The test impersonates the agent
// ServiceAccount with this group, so the real agent never holds the grant, even when a run stops
// before its cleanups. Every temporary object has the label poc.internal/test=view-guard.
const guardTestGroup = "poc:guard-test"

// guardTestRole grants the test group every write that the guard must still deny, plus a token
// request with no name, a create of a Namespace and a write of the status of an Application. RBAC
// then allows each request below as the agent with that group, and only the policy can deny it.
// The Namespace view-guard-test holds a ServiceAccount argocd-agent, so a token request for it
// reaches the policy.
const guardTestRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: view-guard-test
  namespace: argocd
  labels: {poc.internal/test: view-guard}
rules:
  - apiGroups: [argoproj.io]
    resources: [applications]
    verbs: [get, create, update, patch, delete]
  - apiGroups: [apps]
    resources: [deployments, deployments/status]
    verbs: [get, update, patch]
  - apiGroups: [""]
    resources: [configmaps, serviceaccounts]
    verbs: [create, update, patch, delete]
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list]
  - apiGroups: [""]
    resources: [pods/exec]
    verbs: [create]
  - apiGroups: [""]
    resources: [serviceaccounts/token]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: view-guard-test
  namespace: argocd
  labels: {poc.internal/test: view-guard}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: view-guard-test
subjects:
  - kind: Group
    name: poc:guard-test
    apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: view-guard-test
  labels: {poc.internal/test: view-guard}
rules:
  - apiGroups: [""]
    resources: [namespaces]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: view-guard-test
  labels: {poc.internal/test: view-guard}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view-guard-test
subjects:
  - kind: Group
    name: poc:guard-test
    apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Namespace
metadata:
  name: view-guard-test
  labels: {poc.internal/test: view-guard}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-agent
  namespace: view-guard-test
  labels: {poc.internal/test: view-guard}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: view-guard-test
  namespace: view-guard-test
  labels: {poc.internal/test: view-guard}
rules:
  - apiGroups: [""]
    resources: [serviceaccounts/token]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: view-guard-test
  namespace: view-guard-test
  labels: {poc.internal/test: view-guard}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: view-guard-test
subjects:
  - kind: Group
    name: poc:guard-test
    apiGroup: rbac.authorization.k8s.io
`

// repairGuardObjects runs scripts/gate-m3-repair.sh for one cell, the same code as
// `mise run gate:m3:repair`. It deletes every object with the test label, waits until each one is
// gone, and fails when one stays.
func repairGuardObjects(t *testing.T, cell string) {
	t.Helper()
	res, err := cmdrun.Run(5*time.Minute, "", []string{"GATE_M3_CELLS=" + cell}, "bash", "../../scripts/gate-m3-repair.sh")
	if err != nil || res.Code != 0 {
		t.Errorf("gate-m3-repair.sh in %s: %v, exit %d\n%s%s", cell, err, res.Code, res.Stdout, res.Stderr)
	}
	if left, lerr := kubectl(t, cell, "", "get", "roles,rolebindings,clusterroles,clusterrolebindings,namespaces,serviceaccounts", "-A",
		"-l", "poc.internal/test", "-o", "name"); lerr != nil || strings.TrimSpace(left) != "" {
		t.Errorf("objects with the label poc.internal/test stay in %s: %q, %v", cell, left, lerr)
	}
	if out, _ := kubectl(t, cell, "", "auth", "can-i", "update", "applications.argoproj.io", "-n", "argocd", "--as="+agentAccount, "--as-group="+guardTestGroup); strings.TrimSpace(out) != "no" {
		t.Errorf("the test group can still update Applications in %s: %q", cell, strings.TrimSpace(out))
	}
}

// podFacts returns the name and UID of the first Pod in argocd with the label app.kubernetes.io/name=app.
func podFacts(t *testing.T, cell, app string) (name, uid string) {
	t.Helper()
	pod := jsonOf(t, cell, "-n", "argocd", "get", "pods", "-l", "app.kubernetes.io/name="+app)
	items, _ := pod["items"].([]any)
	if len(items) == 0 {
		t.Fatalf("no Pod %s in %s/argocd", app, cell)
	}
	first := items[0].(map[string]any)
	return field(first, "metadata", "name").(string), field(first, "metadata", "uid").(string)
}

// The messages of the three validations of the policy.
const (
	denyDeleteConnect = "cannot delete an object or connect to a Pod"
	denyUpdate        = "cannot update an object"
	denyCreate        = "creates only the bound token of its own SPIRE agent"
)

// requireDeniedBy fails unless err is a denial that names the policy and the message of one of its
// validations, so an error in an expression does not pass for a denial.
func requireDeniedBy(t *testing.T, what, message string, err error) {
	t.Helper()
	switch {
	case err == nil:
		t.Errorf("%s succeeded, want a denial by %s", what, guardPolicy)
	case !strings.Contains(err.Error(), guardPolicy) || !strings.Contains(err.Error(), message):
		t.Errorf("%s failed, but not with the denial %q of %s: %v", what, message, guardPolicy, err)
	default:
		t.Logf("%s: denied by %s: %s", what, guardPolicy, message)
	}
}

// TestM3GuardDeniesWithoutRBAC proves the policy argocd-agent-read-only on its own. It gives the
// test group a temporary Role with Application, ConfigMap and ServiceAccount writes, exec and token
// create, checks that RBAC allows them, and sends each request as the agent ServiceAccount with
// that group (kubectl --as and --as-group). The real agent never holds the grant. Server-side dry
// runs make no change. The cleanup runs before the apply, and it removes every object with the
// label poc.internal/test through scripts/gate-m3-repair.sh. Not covered: eviction and
// ephemeral container requests, which no render of this repository grants.
func TestM3GuardDeniesWithoutRBAC(t *testing.T) {
	for _, cell := range viewCells(t) {
		t.Run(cell, func(t *testing.T) {
			t.Cleanup(func() { repairGuardObjects(t, cell) })
			if _, err := kubectl(t, cell, guardTestRole, "apply", "-f", "-"); err != nil {
				t.Fatal(err)
			}
			asArgs := []string{"--as", agentAccount, "--as-group", guardTestGroup}
			waitFor(t, "RBAC allows the test group to update Applications", time.Minute, func() (bool, string) {
				out, _ := kubectl(t, cell, "", append([]string{"auth", "can-i", "update", "applications.argoproj.io", "-n", "argocd"}, asArgs...)...)
				return strings.TrimSpace(out) == "yes", strings.TrimSpace(out)
			})
			if out, _ := kubectl(t, cell, "", "auth", "can-i", "update", "applications.argoproj.io", "-n", "argocd", "--as="+agentAccount); strings.TrimSpace(out) != "no" {
				t.Fatalf("the agent ServiceAccount alone can update Applications in %s: %q, so the test would touch the real grant", cell, strings.TrimSpace(out))
			}
			as := func(args ...string) error {
				_, err := kubectl(t, cell, "", append(append([]string{}, asArgs...), append([]string{"-n", "argocd"}, args...)...)...)
				return err
			}
			agentPodName, agentPodUID := podFacts(t, cell, agentDeployment)
			otherPodName, otherPodUID := podFacts(t, cell, "argocd-redis")

			t.Run("update", func(t *testing.T) {
				requireDeniedBy(t, "annotate an Application", denyUpdate, as("annotate", "application", demoApp, "poc.internal/guard-test=1", "--overwrite", "--dry-run=server"))
				requireDeniedBy(t, "patch a ConfigMap", denyUpdate, as("patch", "configmap", "argocd-cm", "--type", "merge", "-p", `{"data":{"guard-test":"1"}}`, "--dry-run=server"))
			})
			t.Run("update of a status subresource", func(t *testing.T) {
				requireDeniedBy(t, "patch the status of a Deployment", denyUpdate, as("patch", "deployment", "argocd-repo-server", "--subresource=status", "--type", "merge",
					"-p", `{"status":{"replicas":9}}`, "--dry-run=server"))
			})
			t.Run("create", func(t *testing.T) {
				requireDeniedBy(t, "create a ConfigMap", denyCreate, as("create", "configmap", "guard-test", "--dry-run=server"))
				requireDeniedBy(t, "create a Namespace, a cluster-scoped object", denyCreate, as("create", "namespace", "guard-test-ns", "--dry-run=server"))
				// Without the subresource clause, this create reaches the audience clauses. A ServiceAccount has no
				// spec, so the expression ends in an error and the denial carries no message of the policy.
				requireDeniedBy(t, "create a ServiceAccount of the name argocd-agent", denyCreate, as("create", "serviceaccount", "argocd-agent", "--dry-run=server",
					"--as-user-extra=authentication.kubernetes.io/pod-name="+agentPodName, "--as-user-extra=authentication.kubernetes.io/pod-uid="+agentPodUID))
			})
			t.Run("delete", func(t *testing.T) {
				requireDeniedBy(t, "delete an Application", denyDeleteConnect, as("delete", "application", demoApp, "--dry-run=server"))
			})
			t.Run("connect", func(t *testing.T) {
				requireDeniedBy(t, "exec in the agent Pod", denyDeleteConnect, as("exec", agentPodName, "-c", "cell-proxy", "--", "true"))
			})

			// token creates a token of an account in argocd as the agent ServiceAccount, with the pod
			// name and UID of the agent Pod as the API server puts them in the user extras.
			token := func(account string, extra bool, args ...string) error {
				full := []string{"create", "token", account}
				if extra {
					full = append(full, "--as-user-extra=authentication.kubernetes.io/pod-name="+agentPodName,
						"--as-user-extra=authentication.kubernetes.io/pod-uid="+agentPodUID)
				}
				return as(append(full, args...)...)
			}
			bound := []string{"--bound-object-kind=Pod", "--bound-object-name=" + agentPodName, "--bound-object-uid=" + agentPodUID, "--duration=10m"}
			audience := func(a string) []string { return append([]string{"--audience=" + a}, bound...) }
			t.Run("token", func(t *testing.T) {
				if err := token("argocd-agent", true, audience("spire-"+pocEnv+"/abc_DEF-123")...); err != nil {
					t.Errorf("the bound token that the SPIRE agent asks for was refused: %v", err)
				}
				requireDeniedBy(t, "a token for the API server audience", denyCreate, token("argocd-agent", true, audience("https://kubernetes.default.svc")...))
				requireDeniedBy(t, "a token for another environment", denyCreate, token("argocd-agent", true, audience("spire-other/abc")...))
				requireDeniedBy(t, "a token with an empty nonce", denyCreate, token("argocd-agent", true, audience("spire-"+pocEnv+"/")...))
				requireDeniedBy(t, "a token with a nonce of 129 bytes", denyCreate, token("argocd-agent", true, audience("spire-"+pocEnv+"/"+strings.Repeat("a", 129))...))
				requireDeniedBy(t, "a token with a nonce outside base64url", denyCreate, token("argocd-agent", true, audience("spire-"+pocEnv+"/a.b")...))
				requireDeniedBy(t, "a token with two audiences", denyCreate, token("argocd-agent", true, append(audience("spire-"+pocEnv+"/abc"), "--audience=https://kubernetes.default.svc")...))
				requireDeniedBy(t, "a token with no bound object", denyCreate, token("argocd-agent", true, "--audience=spire-"+pocEnv+"/abc", "--duration=10m"))
				requireDeniedBy(t, "a token bound to a Secret", denyCreate, token("argocd-agent", true, "--audience=spire-"+pocEnv+"/abc", "--bound-object-kind=Secret", "--bound-object-name=argocd-redis", "--duration=10m"))
				requireDeniedBy(t, "a token bound to a Secret with the name and UID of the agent Pod", denyCreate, token("argocd-agent", true,
					"--audience=spire-"+pocEnv+"/abc", "--bound-object-kind=Secret", "--bound-object-name="+agentPodName, "--bound-object-uid="+agentPodUID, "--duration=10m"))
				requireDeniedBy(t, "a token with no pod extras", denyCreate, token("argocd-agent", false, audience("spire-"+pocEnv+"/abc")...))
				requireDeniedBy(t, "a token bound to another Pod", denyCreate, token("argocd-agent", true, "--audience=spire-"+pocEnv+"/abc",
					"--bound-object-kind=Pod", "--bound-object-name="+otherPodName, "--bound-object-uid="+otherPodUID, "--duration=10m"))
				requireDeniedBy(t, "a token bound to another Pod name", denyCreate, token("argocd-agent", true, "--audience=spire-"+pocEnv+"/abc",
					"--bound-object-kind=Pod", "--bound-object-name="+otherPodName, "--bound-object-uid="+agentPodUID, "--duration=10m"))
				requireDeniedBy(t, "a token bound to another Pod UID", denyCreate, token("argocd-agent", true, "--audience=spire-"+pocEnv+"/abc",
					"--bound-object-kind=Pod", "--bound-object-name="+agentPodName, "--bound-object-uid="+otherPodUID, "--duration=10m"))
				requireDeniedBy(t, "a token for the account of the same name in another namespace", denyCreate, as(append([]string{"-n", "view-guard-test", "create", "token", "argocd-agent",
					"--as-user-extra=authentication.kubernetes.io/pod-name=" + agentPodName, "--as-user-extra=authentication.kubernetes.io/pod-uid=" + agentPodUID}, audience("spire-"+pocEnv+"/abc")...)...))
				requireDeniedBy(t, "a token for another account", denyCreate, token("default", true, audience("spire-"+pocEnv+"/abc")...))
			})
		})
	}
}

// TestM3AgentReattestsUnderGuard deletes the agent Pod of dev-cell-1. The new Pod attests with a
// bound token that the guard admits: its SPIRE agent holds the identity of the cell within 2
// minutes, and the principal lists the stream again.
// logAgentRefusals logs each kind of error in the log of an agent Pod, with a count: the action
// that the agent tried and the answer of the API server or of the resource proxy. The gate tests
// make the agent try writes, so the log is the record of what it tried and which control refused.
func logAgentRefusals(t *testing.T, cell, pod string) {
	t.Helper()
	logs, err := kubectl(t, cell, "", "-n", agentNamespace, "logs", pod, "-c", agentDeployment)
	if err != nil {
		t.Logf("no log of %s: %v", pod, err)
		return
	}
	count := map[string]int{}
	for l := range strings.SplitSeq(logs, "\n") {
		var rec struct {
			Level, Action, Msg, Error, EventType string `json:"-"`
		}
		var raw map[string]any
		if json.Unmarshal([]byte(l), &raw) != nil || raw["level"] != "error" {
			continue
		}
		rec.Action, _ = raw["action"].(string)
		rec.EventType, _ = raw["event_type"].(string)
		rec.Msg, _ = raw["msg"].(string)
		rec.Error, _ = raw["error"].(string)
		text := rec.Error
		if text == "" {
			text = rec.Msg
		}
		if i := strings.Index(text, "cannot "); i >= 0 {
			text = text[i:]
		}
		if len(text) > 120 {
			text = text[:120]
		}
		method, _ := raw["http_method"].(string)
		count[fmt.Sprintf("action=%q event=%q http=%q: %s", rec.Action, rec.EventType, method, text)]++
	}
	for k, n := range count {
		t.Logf("agent log of %s, %d times: %s", pod, n, k)
	}
}

func TestM3AgentReattestsUnderGuard(t *testing.T) {
	cell := "dev-cell-1"
	requireViewConnected(t, agentName(cell))
	old := agentPod(t, cell)
	logAgentRefusals(t, cell, old)
	since := time.Now()
	if _, err := kubectl(t, cell, "", "-n", agentNamespace, "delete", "pod", old, "--wait=true"); err != nil {
		t.Fatal(err)
	}
	want := "spiffe://" + envTrustDomain + "/cell/" + cell + "/argocd-agent"
	waitFor(t, "a new agent Pod whose cell-proxy prints "+want, agentWait, func() (bool, string) {
		pods, err := kubectl(t, cell, "", "-n", agentNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+agentDeployment, "-o", "name")
		if err != nil || strings.Contains(pods, old) {
			return false, fmt.Sprintf("pods %q, err %v", pods, err)
		}
		out, err := kubectl(t, cell, "", "-n", agentNamespace, "exec", "deploy/"+agentDeployment, "-c", "cell-proxy", "--", "/ko-app/cell-proxy", "whoami")
		if err != nil {
			return false, err.Error()
		}
		return strings.Contains(out, want), out
	})
	waitFor(t, "the principal lists "+agentName(cell)+" with a new stream", agentWait, func() (bool, string) {
		return viewConnectedSince(t, agentName(cell), since)
	})
	requireViewConnected(t, agentName(cell))
}
