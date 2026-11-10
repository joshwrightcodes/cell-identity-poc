//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	guardPolicy = "argocd-agent-read-only"
	// demoApp and demoNS name the Application and the namespace of the demo workloads.
	demoApp = "apps-demo"
	demoNS  = "apps-demo"
	// settle is how long a test waits before it checks that a change did not reach a cell.
	settle = 60 * time.Second
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

// mgmtPatch merge-patches the management copy of the Application of a cell.
func mgmtPatch(t *testing.T, agent, patch string) {
	t.Helper()
	if out, err := kubectl(t, mgmtCluster, "", "-n", agent, "patch", "application", demoApp, "--type", "merge", "-p", patch); err != nil {
		t.Fatalf("patch the management copy in %s with %s: %v", agent, patch, err)
	} else {
		t.Logf("patched the management copy in %s with %s: %s", agent, patch, strings.TrimSpace(out))
	}
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

// TestM3ViewAnnotationChangesFail changes the management copy of the Application of dev-cell-1: a
// new annotation, a sync operation and a bogus refresh value. The cell keeps its Application as it
// was after 60 seconds. The principal sends each change as an event, and the agent has no right
// to apply it.
func TestM3ViewAnnotationChangesFail(t *testing.T) {
	cell, agent := "dev-cell-1", agentName("dev-cell-1")
	requireViewConnected(t, agent)
	before := cellAppFacts(t, cell)
	t.Cleanup(func() {
		_, _ = kubectl(t, mgmtCluster, "", "-n", agent, "patch", "application", demoApp, "--type", "merge",
			"-p", `{"metadata":{"annotations":{"poc.internal/test":null,"argocd.argoproj.io/refresh":null}},"operation":null}`)
	})
	mgmtPatch(t, agent, `{"metadata":{"annotations":{"poc.internal/test":"1"}}}`)
	mgmtPatch(t, agent, `{"operation":{"sync":{"revision":"HEAD"}}}`)
	mgmtPatch(t, agent, `{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"bogus"}}}`)
	time.Sleep(settle)
	after := cellAppFacts(t, cell)
	requireSameFacts(t, "after the three changes", before, after)
	for _, key := range []string{"poc.internal/test", "argocd.argoproj.io/refresh"} {
		if strings.Contains(after["annotations"], key) {
			t.Errorf("the Application in the cell has the annotation %s: %s", key, after["annotations"])
		}
	}
	if after["operation"] != before["operation"] || after["operation"] != "null" {
		t.Errorf("the Application in the cell has the operation %s, want none", after["operation"])
	}
}

// TestM3ViewStatusAndOwnerPatchFail patches the status and the owner references of the management
// copy. The cell keeps its status and has no owner reference after 60 seconds.
func TestM3ViewStatusAndOwnerPatchFail(t *testing.T) {
	cell, agent := "dev-cell-1", agentName("dev-cell-1")
	requireViewConnected(t, agent)
	before := cellAppFacts(t, cell)
	t.Cleanup(func() {
		_, _ = kubectl(t, mgmtCluster, "", "-n", agent, "patch", "application", demoApp, "--type", "merge", "-p", `{"metadata":{"ownerReferences":null}}`)
	})
	mgmtPatch(t, agent, `{"status":{"operationState":{"phase":"Terminating"}}}`)
	mgmtPatch(t, agent, `{"metadata":{"ownerReferences":[{"apiVersion":"v1","kind":"ConfigMap","name":"view-owner-test","uid":"00000000-0000-0000-0000-000000000001"}]}}`)
	time.Sleep(settle)
	after := cellAppFacts(t, cell)
	t.Run("status", func(t *testing.T) {
		if after["operationState"] != before["operationState"] || strings.Contains(after["operationState"], "Terminating") {
			t.Errorf("the operation state of the Application in the cell is %s, was %s", after["operationState"], before["operationState"])
		}
	})
	t.Run("owner", func(t *testing.T) {
		if after["ownerReferences"] != before["ownerReferences"] || strings.Contains(after["ownerReferences"], "view-owner-test") {
			t.Errorf("the owner references of the Application in the cell are %s, were %s", after["ownerReferences"], before["ownerReferences"])
		}
	})
	t.Run("other fields", func(t *testing.T) { requireSameFacts(t, "after the two patches", before, after) })
}

// reconciledAt returns status.reconciledAt of the Application of a cell.
func reconciledAt(t *testing.T, cell string) time.Time {
	t.Helper()
	s, _ := field(jsonOf(t, cell, "-n", agentNamespace, "get", "application", demoApp), "status", "reconciledAt").(string)
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("status.reconciledAt of %s in %s is %q", demoApp, cell, s)
	}
	return at
}

// TestM3ViewRefreshFails asks the central API for a refresh of the Application of dev-cell-1. The
// central argocd-server has no right to write in the agent namespace, so the call fails and the
// cell does not reconcile because of it. The controller reconciles every 3 minutes by itself, so
// the check starts when the last reconcile is recent.
func TestM3ViewRefreshFails(t *testing.T) {
	cell, agent := "dev-cell-1", agentName("dev-cell-1")
	requireViewConnected(t, agent)
	waitFor(t, "a reconcile of the Application in the cell less than 2 minutes ago", 5*time.Minute, func() (bool, string) {
		age := time.Since(reconciledAt(t, cell))
		return age < 2*time.Minute, fmt.Sprintf("the last reconcile was %s ago", age.Round(time.Second))
	})
	before := reconciledAt(t, cell)
	addr := centralForward(t)
	for _, mode := range []string{"normal", "hard"} {
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Get("http://" + addr + "/api/v1/applications/" + demoApp + "?refresh=" + mode + "&appNamespace=" + agent)
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, 512)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		t.Logf("refresh=%s: HTTP %d: %s", mode, resp.StatusCode, strings.TrimSpace(string(body[:n])))
		if resp.StatusCode == http.StatusOK {
			t.Errorf("the central API accepted refresh=%s", mode)
		}
	}
	time.Sleep(20 * time.Second)
	if after := reconciledAt(t, cell); !after.Equal(before) {
		t.Errorf("status.reconciledAt of the cell changed from %s to %s after the refresh calls", before, after)
	}
	if out, _ := kubectl(t, mgmtCluster, "", "-n", agent, "get", "application", demoApp, "-o", "jsonpath={.metadata.annotations}"); strings.Contains(out, "argocd.argoproj.io/refresh") {
		t.Errorf("the management copy holds a refresh annotation: %s", out)
	}
}

// TestM3ViewExecFails asks the resource proxy for an exec in pod echo. The proxy refuses, the pod
// has no such file, and the agent ServiceAccount has no right to exec by itself.
func TestM3ViewExecFails(t *testing.T) {
	cell := "dev-cell-1"
	requireViewConnected(t, agentName(cell))
	pod := strings.TrimSpace(mustKubectl(t, cell, "-n", demoNS, "get", "pods", "-l", "app=echo", "-o", "jsonpath={.items[0].metadata.name}"))
	t.Run("through the resource proxy", func(t *testing.T) {
		cs, _ := viewClient(t, agentName(cell))
		ctx, cancel := ctxTimeout()
		defer cancel()
		err := cs.CoreV1().RESTClient().Post().Namespace(demoNS).Resource("pods").Name(pod).SubResource("exec").
			Param("container", "echo").Param("command", "touch").Param("command", "/tmp/view-exec").Param("stdout", "true").
			Do(ctx).Error()
		if err == nil {
			t.Fatal("the exec through the resource proxy succeeded")
		}
		t.Logf("upstream refusal (agent/terminal.go starts a terminal only from the Argo CD web terminal, and agent/resource.go handles POST on the subresource of a managed object): %v", err)
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
	for _, ns := range []string{"argocd", "istio-system", demoNS} {
		t.Run("get in "+ns, func(t *testing.T) {
			name := "argocd-redis"
			if ns == demoNS {
				name = "view-canary"
			}
			ctx, cancel := ctxTimeout()
			defer cancel()
			s, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
			if err == nil {
				t.Fatalf("get Secret %s/%s through the resource proxy returned %d keys", ns, name, len(s.Data))
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
		out, err := kubectl(t, mgmtCluster, "", "get", "secrets,configmaps,applications.argoproj.io", "-A", "-o", "json")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, marker) || strings.Contains(out, raw) {
			t.Error("an object in management holds the canary marker")
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
		check{"create serviceaccounts/token for argocd-agent in argocd", "create", "serviceaccounts/argocd-agent", "token", "argocd", true},
	)
	for _, verb := range []string{"update", "patch", "delete"} {
		checks = append(checks, check{fmt.Sprintf("%s applications in argocd", verb), verb, "applications.argoproj.io", "", "argocd", false})
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

// TestM3ViewTokenRequestFails asks the resource proxy for a token of the agent ServiceAccount. A
// token with the audience of the API server fails, and so does a token for a SPIRE audience with
// no bound Pod.
func TestM3ViewTokenRequestFails(t *testing.T) {
	cell := "dev-cell-1"
	requireViewConnected(t, agentName(cell))
	cs, _ := viewClient(t, agentName(cell))
	for name, audience := range map[string]string{
		"the audience of the API server": "https://kubernetes.default.svc",
		"a SPIRE audience, no bound Pod": "spire-" + pocEnv + "/x",
	} {
		t.Run(name, func(t *testing.T) {
			secs := int64(600)
			req := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &secs}}
			ctx, cancel := ctxTimeout()
			defer cancel()
			out, err := cs.CoreV1().ServiceAccounts("argocd").CreateToken(ctx, "argocd-agent", req, metav1.CreateOptions{})
			if err == nil {
				t.Fatalf("the token request through the resource proxy returned a token of %d bytes", len(out.Status.Token))
			}
			t.Logf("%v", err)
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

// guardTestRole grants the agent ServiceAccount every write that the guard must still deny, plus a
// token request with no name. RBAC then allows each request below, and only the policy can deny it.
const guardTestRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: view-guard-test
  namespace: argocd
rules:
  - apiGroups: [argoproj.io]
    resources: [applications]
    verbs: [create, update, patch, delete]
  - apiGroups: [""]
    resources: [configmaps]
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
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: view-guard-test
subjects:
  - kind: ServiceAccount
    name: argocd-agent
    namespace: argocd
`

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
// agent ServiceAccount a temporary Role with every write verb, checks that RBAC allows them, and
// sends each request as that account with kubectl --as. Server-side dry runs make no change. The
// Role and its binding go away when the test ends.
func TestM3GuardDeniesWithoutRBAC(t *testing.T) {
	for _, cell := range viewCells(t) {
		t.Run(cell, func(t *testing.T) {
			if _, err := kubectl(t, cell, guardTestRole, "apply", "-f", "-"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = kubectl(t, cell, "", "-n", "argocd", "delete", "rolebinding/view-guard-test", "role/view-guard-test", "--ignore-not-found")
			})
			waitFor(t, "RBAC allows the agent ServiceAccount to update Applications", time.Minute, func() (bool, string) {
				out, _ := kubectl(t, cell, "", "auth", "can-i", "update", "applications.argoproj.io", "-n", "argocd", "--as="+agentAccount)
				return strings.TrimSpace(out) == "yes", strings.TrimSpace(out)
			})
			as := func(args ...string) error {
				_, err := kubectl(t, cell, "", append([]string{"--as", agentAccount, "-n", "argocd"}, args...)...)
				return err
			}
			agentPodName, agentPodUID := podFacts(t, cell, agentDeployment)
			otherPodName, otherPodUID := podFacts(t, cell, "argocd-redis")

			t.Run("update", func(t *testing.T) {
				requireDeniedBy(t, "annotate an Application", denyUpdate, as("annotate", "application", demoApp, "poc.internal/guard-test=1", "--overwrite", "--dry-run=server"))
				requireDeniedBy(t, "patch a ConfigMap", denyUpdate, as("patch", "configmap", "argocd-cm", "--type", "merge", "-p", `{"data":{"guard-test":"1"}}`, "--dry-run=server"))
			})
			t.Run("create", func(t *testing.T) {
				requireDeniedBy(t, "create a ConfigMap", denyCreate, as("create", "configmap", "guard-test", "--dry-run=server"))
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
				requireDeniedBy(t, "a token with no pod extras", denyCreate, token("argocd-agent", false, audience("spire-"+pocEnv+"/abc")...))
				requireDeniedBy(t, "a token bound to another Pod", denyCreate, token("argocd-agent", true, "--audience=spire-"+pocEnv+"/abc",
					"--bound-object-kind=Pod", "--bound-object-name="+otherPodName, "--bound-object-uid="+otherPodUID, "--duration=10m"))
				requireDeniedBy(t, "a token bound to another Pod UID", denyCreate, token("argocd-agent", true, "--audience=spire-"+pocEnv+"/abc",
					"--bound-object-kind=Pod", "--bound-object-name="+agentPodName, "--bound-object-uid="+otherPodUID, "--duration=10m"))
				requireDeniedBy(t, "a token for another account", denyCreate, token("default", true, audience("spire-"+pocEnv+"/abc")...))
			})
		})
	}
}

// TestM3AgentReattestsUnderGuard deletes the agent Pod of dev-cell-1. The new Pod attests with a
// bound token that the guard admits: its SPIRE agent holds the identity of the cell within 2
// minutes, and the principal lists the stream again.
func TestM3AgentReattestsUnderGuard(t *testing.T) {
	cell := "dev-cell-1"
	requireViewConnected(t, agentName(cell))
	old := agentPod(t, cell)
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
