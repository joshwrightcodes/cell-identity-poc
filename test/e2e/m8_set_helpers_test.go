//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	// m8SetWait bounds the wait for the final result of a set that the cell applies, or rolls back. The health wait takes 5 min and the
	// rollback wait takes 5 min more.
	m8SetWait = 15 * time.Minute
	// m8RefusalWait bounds the wait for the final result of a set that the engine must refuse. A refusal takes seconds. A set that is
	// accepted by mistake takes the health wait and the rollback wait, and the test must see its result before the next set.
	m8RefusalWait = m8SetWait
	// m8StoreRegistryPort is the port of the registry in the pod bundle-store-0. It listens on the loopback address of the pod and
	// takes no token. m8StoreProxyPort is the port of the store proxy, which the Service bundle-store exposes.
	m8StoreRegistryPort = 5001
	m8StoreProxyPort    = 5000
	// m8CellStoreNS is the namespace of the bundle store in each cluster with a bundle role.
	m8CellStoreNS = "cell-system"
)

// m8Hydrated returns the hydrated render of a component of a cluster, which cell:hydrate leaves in the build directory.
func m8Hydrated(t *testing.T, cluster, component string) []byte {
	t.Helper()
	path := filepath.FromSlash("../../build/" + cluster + "/bundles/" + component + "/manifests.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the hydrated bundle %s of %s: %v. Run: CELL=%s mise run cell:hydrate", component, cluster, err, cluster)
	}
	return b
}

// m8Objects decodes manifests into objects.
func m8Objects(t *testing.T, manifests []byte) []map[string]any {
	t.Helper()
	objs, err := bundle.DecodeManifests(manifests, bundle.MaxObjects)
	if err != nil {
		t.Fatalf("decode the manifests: %v", err)
	}
	return objs
}

// m8Render writes objects as one multi-document YAML text, which m8PushBundle reads again.
func m8Render(t *testing.T, objs []map[string]any) []byte {
	t.Helper()
	var docs []string
	for _, o := range objs {
		b, err := yaml.Marshal(o)
		if err != nil {
			t.Fatalf("encode an object: %v", err)
		}
		docs = append(docs, strings.TrimRight(string(b), "\n"))
	}
	return []byte(strings.Join(docs, "\n---\n") + "\n")
}

// m8Docs joins YAML documents into one manifests text.
func m8Docs(docs ...string) []byte {
	return []byte(strings.Join(docs, "---\n"))
}

// m8AppNS is the namespace of the app class. m8PlatformNS is the namespace of the platform workloads.
const (
	m8AppNS      = "apps-sample"
	m8PlatformNS = "apps-demo"
)

// m8Marker is a ConfigMap of apps-sample that holds a marker. A bundle that holds it differs from every other bundle.
func m8Marker(name, marker string) string { return m8MarkerIn(m8AppNS, name, marker) }

// m8MarkerIn is m8Marker in another namespace.
func m8MarkerIn(namespace, name, marker string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
  namespace: %s
  labels:
    cell.poc.internal/e2e: "true"
data:
  marker: %q
`, name, namespace, marker)
}

// m8FailingDeployment is a Deployment of the namespace ns that never becomes ready. Its readiness probe asks a closed port, and its
// progress deadline of 30 s makes Argo CD report it Degraded soon after the rollout starts. A wave other than "" sets the sync wave.
func m8FailingDeployment(t *testing.T, ns, name, wave string) string {
	t.Helper()
	needProbeImage(t)
	annotations := ""
	if wave != "" {
		annotations = fmt.Sprintf("  annotations:\n    argocd.argoproj.io/sync-wave: %q\n", wave)
	}
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[4]s
%[3]s  labels:
    cell.poc.internal/e2e: "true"
spec:
  replicas: 1
  progressDeadlineSeconds: 30
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: probe
          image: %[2]s
          args: ["serve", "--addr=:8080"]
          readinessProbe:
            tcpSocket:
              port: 9
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
`, name, probeImage, annotations, ns)
}

// m8EchoDeployment is a Deployment of the namespace ns that becomes ready. Its pods carry the label app: echo, the label that the selector
// of Service apps-demo/echo matches. It follows Pod Security restricted, as the Deployment of m8FailingDeployment does.
func m8EchoDeployment(t *testing.T, ns, name string) string {
	t.Helper()
	needProbeImage(t)
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[3]s
  labels:
    cell.poc.internal/e2e: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: probe
          image: %[2]s
          args: ["serve", "--addr=:8080"]
          readinessProbe:
            tcpSocket:
              port: 8080
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
`, name, probeImage, ns)
}

// m8DeleteProbeDeployment deletes a probe Deployment of apps-sample or apps-demo when the test ends. A rollback prunes it, and this covers a run
// that fails before the rollback.
func m8DeleteProbeDeployment(t *testing.T, cluster, name string) {
	t.Helper()
	t.Cleanup(func() {
		for _, ns := range []string{m8AppNS, m8PlatformNS} {
			if _, err := kubectl(t, cluster, "", "-n", ns, "delete", "deployment", name, "--ignore-not-found", "--wait=false"); err != nil {
				t.Errorf("delete the probe Deployment %s of %s in %s: %v", name, cluster, ns, err)
			}
		}
	})
}

// m8WaitNoOpen waits until the last served set of the target has a final result or is past its lifetime. mgmtd refuses to serve a set
// while one is open (bundle_open), and a set that the engine accepted by mistake takes the health wait and the rollback wait to end.
func m8WaitNoOpen(t *testing.T, target string) {
	t.Helper()
	end := time.Now().Add(35 * time.Minute)
	for {
		tb := m8Get(t, target)
		if tb.Result != nil || !tb.Served || time.Now().After(tb.ExpiresAt) {
			return
		}
		if time.Now().After(end) {
			t.Errorf("operation %s of %s is still open after 35 min", tb.OpID, target)
			return
		}
		time.Sleep(10 * time.Second)
	}
}

// m8DeleteProbeObjects deletes the ConfigMaps, Deployments and Services of apps-sample and apps-demo that M8 tests made. A root deletes the Application of
// a probe bundle and leaves its objects.
func m8DeleteProbeObjects(t *testing.T, cluster string) {
	t.Helper()
	for _, ns := range []string{m8AppNS, m8PlatformNS} {
		if _, err := kubectl(t, cluster, "", "-n", ns, "delete", "configmap,deployment,service,networkpolicy", "-l", m8Label, "--ignore-not-found", "--wait=false"); err != nil {
			t.Errorf("delete the probe objects of %s in %s: %v", ns, cluster, err)
		}
	}
}

// m8DeleteIfRun deletes a namespaced probe object when the test ends, and only when it carries the annotation e2e-run with this run's
// value. A harness object, or a probe of another run, is never deleted.
func m8DeleteIfRun(t *testing.T, cluster, ns, kind, name, run string) {
	t.Helper()
	t.Cleanup(func() {
		got, err := kubectl(t, cluster, "", "-n", ns, "get", kind, name, "--ignore-not-found", "-o", `jsonpath={.metadata.annotations.cell\.poc\.internal/e2e-run}`)
		if err != nil {
			t.Errorf("read the probe %s/%s of %s: %v", kind, name, cluster, err)
			return
		}
		if strings.TrimSpace(got) != run {
			return
		}
		if _, err := kubectl(t, cluster, "", "-n", ns, "delete", kind, name, "--ignore-not-found"); err != nil {
			t.Errorf("delete the probe %s/%s of %s: %v", kind, name, cluster, err)
		}
	})
}

// m8RestoreOnFailure records the target, and publishes its hydrated set again when the test, or one of its subtests, failed. A
// test that never lets a set reach the cell uses it, so that a failed run leaves the target healthy and a passing run costs no publish.
// The restore waits until no set is open.
func m8RestoreOnFailure(t *testing.T, target string) {
	t.Helper()
	m8RecordTarget(t, target)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		m8WaitNoOpen(t, target)
		res, err := m8PublishHydrated(t, target)
		if err != nil {
			t.Errorf("restore the hydrated set of %s: %v", target, err)
			return
		}
		if res["outcome"] != op.OutcomeApplied && res["outcome"] != op.OutcomeAlreadyApplied {
			t.Errorf("restore of %s ended %v", target, res)
		}
		m8DeleteProbeObjects(t, target)
	})
}

// m8LiveSet returns the components that the target runs now. The names, waves and namespaces come from the last signed set of mgmtd,
// and each digest comes from the bundle state of the cell, because a set that was refused or rolled back stays the last signed set and
// names bundles that never ran. A component that the state lacks is left out. A test that serves several sets takes this once and builds
// each set from it. It fails the test when nothing is live.
func m8LiveSet(t *testing.T, target string) []bundle.Component {
	t.Helper()
	last := m8LastSet(t, target)
	st := m8State(t, target)
	var comps []bundle.Component
	for _, c := range last.Components {
		if d, ok := st.Components[c.Name]; ok {
			c.Digest = d
			comps = append(comps, c)
		}
	}
	if len(comps) == 0 {
		t.Fatalf("%s runs no signed set yet. Run: mise run bundle -- publish --target %s --wait", target, target)
	}
	return comps
}

// m8LiveDigest returns the digest of the component in comps, or "".
func m8LiveDigest(comps []bundle.Component, name string) string {
	for _, c := range comps {
		if c.Name == name {
			return c.Digest
		}
	}
	return ""
}

// m8LiveManifests reads the manifests of a live bundle of the target from the mirror, where every signed set of the target is kept.
func m8LiveManifests(t *testing.T, target, component, digest string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	art, err := ocistore.Fetch(ctx, m8Mirror(t), "bundles/"+target+"/"+component, digest)
	if err != nil {
		t.Fatalf("read the live bundle %s@%s of %s from the mirror: %v", component, digest, target, err)
	}
	manifests, err := bundle.UnpackComponent(art.Layer, bundle.MaxUnpackedBytes)
	if err != nil {
		t.Fatalf("unpack the live bundle %s of %s: %v", component, target, err)
	}
	return manifests
}

// m8Annotate sets an annotation on an object, so that its bundle differs from every bundle of an earlier run.
func m8Annotate(obj map[string]any, key, value string) {
	meta, _ := obj["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		obj["metadata"] = meta
	}
	ann, _ := meta["annotations"].(map[string]any)
	if ann == nil {
		ann = map[string]any{}
		meta["annotations"] = ann
	}
	ann[key] = value
}

// m8WithDigest returns a copy of the components with the digest of the component name replaced. A component that the set lacks is added
// with the wave and the namespace.
func m8WithDigest(comps []bundle.Component, name string, wave int, namespace, digest string) []bundle.Component {
	out := slices.Clone(comps)
	for i := range out {
		if out[i].Name == name {
			out[i].Digest = digest
			return out
		}
	}
	return append(out, bundle.Component{Name: name, Wave: wave, Namespace: namespace, Digest: digest})
}

// m8SetWithDigest is m8WithDigest on the last signed set of the target.
func m8SetWithDigest(t *testing.T, target, name string, wave int, namespace, digest string) []bundle.Component {
	t.Helper()
	return m8WithDigest(m8LiveSet(t, target), name, wave, namespace, digest)
}

// m8Offer signs the components as the next set of the target, serves it, and waits for its final result.
func m8Offer(t *testing.T, target string, comps []bundle.Component, d time.Duration) (mgmtapi.BundleSignResult, mgmtapi.TargetBundle) {
	t.Helper()
	signed := m8Sign(t, target, comps, true)
	tb := m8Wait(t, target, signed.OpID, d)
	if tb.Result == nil {
		t.Fatalf("operation %s of %s has no result", signed.OpID, target)
	}
	return signed, tb
}

// m8AttachCosign attaches the Sigstore bundle of the root of the target to the mirror. bundle -- sign serves a set but attaches nothing, and a set with the
// same root as an older one then has no signed statement of its version, so the strict bundle -- verify and cell:verify fail after the test.
func m8AttachCosign(t *testing.T, target string) error {
	t.Helper()
	if out, err := m8Command(t, 5*time.Minute, "", "run", "bundle", "--", "cosign", "--target", target); err != nil {
		return fmt.Errorf("attach the Sigstore bundle of %s: %w\n%s", target, err, out)
	}
	return nil
}

// m8OfferCosigned is m8Offer with the Sigstore bundle attached after the set is signed and before the wait for its result.
func m8OfferCosigned(t *testing.T, target string, comps []bundle.Component, d time.Duration) (mgmtapi.BundleSignResult, mgmtapi.TargetBundle) {
	t.Helper()
	signed := m8Sign(t, target, comps, true)
	if err := m8AttachCosign(t, target); err != nil {
		t.Fatal(err)
	}
	tb := m8Wait(t, target, signed.OpID, d)
	if tb.Result == nil {
		t.Fatalf("operation %s of %s has no result", signed.OpID, target)
	}
	return signed, tb
}

// m8WantResult reports an error unless the result has the outcome, the reason and the detail. A detail of "*" accepts any.
func m8WantResult(t *testing.T, res *op.Result, outcome, reason, detail string) {
	t.Helper()
	if res == nil {
		t.Errorf("the operation has no result, want %s %s %s", outcome, reason, detail)
		return
	}
	if res.Outcome != outcome || res.Reason != reason || (detail != "*" && res.Detail != detail) {
		t.Errorf("the result is %s/%s/%s, want %s/%s/%s", res.Outcome, res.Reason, res.Detail, outcome, reason, detail)
	}
}

// m8WaitOp polls mgmtd until the operation has a final result, and returns it. It serves a set that was signed with --no-serve and
// enqueued by hand, which bundle get does not show.
func m8WaitOp(t *testing.T, id string, d time.Duration) mgmt.OpView {
	t.Helper()
	end := time.Now().Add(d)
	for {
		v := opGet(t, id)
		if v.Result != nil && v.Final != "" {
			return v
		}
		if time.Now().After(end) {
			t.Fatalf("operation %s has no final result after %s (state %s)", id, d, v.State)
		}
		time.Sleep(5 * time.Second)
	}
}

// m8OperationEnvelope returns the signed operation envelope of an operation that mgmtd holds. It is the envelope that a cell takes
// from its queue, and its args are the attestation.
func m8OperationEnvelope(t *testing.T, id string) []byte {
	t.Helper()
	v := opGet(t, id)
	if len(v.Envelope) == 0 {
		t.Fatalf("mgmtd holds no envelope for operation %s", id)
	}
	return []byte(v.Envelope)
}

// m8Snap is what a refused set must leave as it was: the root and the components of the bundle state, and the pinned and the synced
// revision of each Application that a set made.
type m8Snap struct {
	root       string
	components map[string]string
	apps       map[string]string
}

func m8Snapshot(t *testing.T, cluster string) m8Snap {
	t.Helper()
	st := m8State(t, cluster)
	out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "applications", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatal(err)
	}
	apps := map[string]string{}
	for _, app := range list.Items {
		name := m8Field(app, "metadata", "name")
		if strings.HasPrefix(name, "m8-") {
			continue
		}
		apps[name] = m8Field(app, "spec", "source", "targetRevision") + " " + m8Field(app, "status", "sync", "revision")
	}
	return m8Snap{root: st.Root.Digest, components: maps.Clone(st.Components), apps: apps}
}

// m8RequireSame reports an error for each difference between two snapshots.
func m8RequireSame(t *testing.T, before, after m8Snap) {
	t.Helper()
	if before.root != after.root {
		t.Errorf("the root of the bundle state changed from %s to %s", before.root, after.root)
	}
	if !maps.Equal(before.components, after.components) {
		t.Errorf("the components of the bundle state changed from %v to %v", before.components, after.components)
	}
	if !maps.Equal(before.apps, after.apps) {
		t.Errorf("the revisions of the Applications changed from %v to %v", before.apps, after.apps)
	}
}

// m8AtSetProblems lists each component whose Application is not Synced and Healthy at its digest, and a root Application that is not
// at the root digest. An empty root digest skips the root.
func m8AtSetProblems(t *testing.T, cluster string, comps []bundle.Component, rootDigest string) []string {
	t.Helper()
	var problems []string
	for _, c := range comps {
		app := m8Application(t, cluster, c.Name)
		if m8Field(app, "status", "sync", "status") != "Synced" || m8Field(app, "status", "health", "status") != "Healthy" ||
			m8Field(app, "status", "sync", "revision") != c.Digest {
			problems = append(problems, fmt.Sprintf("%s is %s/%s at %s, want Synced/Healthy at %s", c.Name, m8Field(app, "status", "sync", "status"),
				m8Field(app, "status", "health", "status"), m8Field(app, "status", "sync", "revision"), c.Digest))
		}
	}
	if rootDigest != "" {
		if got := m8Field(m8Application(t, cluster, "root"), "status", "sync", "revision"); got != rootDigest {
			problems = append(problems, fmt.Sprintf("root is at %s, want %s", got, rootDigest))
		}
	}
	return problems
}

// m8RequireAtSet reports an error for each problem of m8AtSetProblems.
func m8RequireAtSet(t *testing.T, cluster string, comps []bundle.Component, rootDigest string) {
	t.Helper()
	for _, p := range m8AtSetProblems(t, cluster, comps, rootDigest) {
		t.Errorf("in %s, %s", cluster, p)
	}
}

// m8WaitEach is m8Wait that also calls each before every look at the result, and once more when the result is there. A test uses it to
// watch an Application while a set is applied, because a rollback replaces what Argo CD reported.
func m8WaitEach(t *testing.T, target, opID string, d time.Duration, each func()) mgmtapi.TargetBundle {
	t.Helper()
	end := time.Now().Add(d)
	for {
		each()
		tb := m8Get(t, target)
		if tb.OpID != opID {
			t.Fatalf("the last set of %s is operation %s, want %s", target, tb.OpID, opID)
		}
		if tb.Result != nil {
			each()
			return tb
		}
		if time.Now().After(end) {
			t.Fatalf("operation %s of %s has no result after %s", opID, target, d)
		}
		time.Sleep(3 * time.Second)
	}
}

// m8WatchCells samples mgmtd every 15 s and records each sample in which one of the cells is not valid. The returned function stops
// the sampling, and returns the problems. The goroutine calls no method of t.
func m8WatchCells(cells ...string) (stop func() []string) {
	done := make(chan struct{})
	var mu sync.Mutex
	var problems []string
	var wg sync.WaitGroup
	var once sync.Once
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			out, err := mgmtCtlErr("status")
			var st mgmt.Status
			if err == nil {
				err = json.Unmarshal([]byte(out), &st)
			}
			mu.Lock()
			switch {
			case err != nil:
				problems = append(problems, "mgmtd status: "+err.Error())
			default:
				for _, c := range cells {
					valid := false
					for _, cs := range st.Cells {
						if cs.Name == c && cs.Valid {
							valid = true
						}
					}
					if !valid {
						problems = append(problems, fmt.Sprintf("%s is not valid at %s", c, time.Now().Format(time.TimeOnly)))
					}
				}
			}
			mu.Unlock()
			select {
			case <-done:
				return
			case <-time.After(15 * time.Second):
			}
		}
	}()
	return func() []string {
		once.Do(func() { close(done) })
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(problems)
	}
}

// m8ForwardStore starts a port-forward from this Mac to the loopback registry of the pod bundle-store-0 of the cluster, which takes no
// token, and returns the address and a client of it.
func m8ForwardStore(t *testing.T, cluster string) (string, *ocistore.Store) {
	t.Helper()
	addr := portForward(t, cluster, m8CellStoreNS, "pod/bundle-store-0", m8StoreRegistryPort)
	s, err := ocistore.New(ocistore.Client{Base: addr})
	if err != nil {
		t.Fatal(err)
	}
	return addr, s
}

// m8StoreHead returns the status of a HEAD request for a manifest of the registry at addr.
func m8StoreHead(t *testing.T, addr, repo, digest string) int {
	t.Helper()
	status, _ := m8StoreRequest(t, addr, http.MethodHead, "/v2/"+repo+"/manifests/"+digest, "")
	return status
}

// m8StoreRequest sends one request to a store, with the bearer token when it is not empty. It returns the status and the request ID that
// the store proxy puts in the header X-Request-Id of a refusal.
func m8StoreRequest(t *testing.T, addr, method, path, token string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://"+addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", bundle.MediaTypeManifest)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s on %s: %v", method, path, addr, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header.Get("X-Request-Id")
}

// m8CreateApplication applies an Application of the cluster that reads the bundle digest from the repository bundles/<repo> of the
// in-cluster store, and deletes it when the test ends. The Application has no finalizer and the delete orphans its objects, so that a
// probe that Argo CD applied by mistake over an object of the harness is never pruned with it. The Application syncs by itself.
func m8CreateApplication(t *testing.T, cluster, name, project, repo, digest, destNamespace string) {
	t.Helper()
	app := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata": map[string]any{
			"name": name, "namespace": "argocd",
			"labels": map[string]any{testNamespaceLabel: "true"},
		},
		"spec": map[string]any{
			"project": project,
			"source": map[string]any{
				"repoURL":        "oci://" + bundle.StoreHost + "/bundles/" + repo,
				"targetRevision": digest,
				"path":           ".",
			},
			"destination": map[string]any{"server": "https://kubernetes.default.svc", "namespace": destNamespace},
			"syncPolicy": map[string]any{
				"automated":   map[string]any{"prune": false, "selfHeal": false},
				"syncOptions": []any{"ServerSideApply=true"},
			},
		},
	}
	body, err := yaml.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "application", name, "--ignore-not-found", "-o", "name"); err != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("the Application %s exists in %s already (%v). The test needs the name for itself", name, cluster, err)
	}
	t.Cleanup(func() {
		if _, err := kubectl(t, cluster, "", "-n", "argocd", "delete", "application", name, "--cascade=orphan", "--ignore-not-found", "--wait=true", "--timeout=180s"); err != nil {
			t.Errorf("delete the Application %s of %s: %v", name, cluster, err)
		}
	})
	if _, err := kubectl(t, cluster, string(body), "apply", "-f", "-"); err != nil {
		t.Fatal(err)
	}
}

// m8ApplicationText returns the JSON of an Application as text, for a search of its conditions and its operation state.
func m8ApplicationText(t *testing.T, cluster, name string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "application", name, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// m8WaitApplicationText waits until the JSON of the Application holds the text, and returns the message that holds it.
func m8WaitApplicationText(t *testing.T, cluster, name, needle string, d time.Duration) {
	t.Helper()
	waitFor(t, fmt.Sprintf("the Application %s of %s to report %q", name, cluster, needle), d, func() (bool, string) {
		text := m8ApplicationText(t, cluster, name)
		if strings.Contains(text, needle) {
			return true, ""
		}
		var app map[string]any
		_ = json.Unmarshal([]byte(text), &app)
		status, _ := json.Marshal(app["status"])
		return false, string(status)
	})
}

// m8ResourceVersion returns the resource version of a namespaced object, or "" when it does not exist.
func m8ResourceVersion(t *testing.T, cluster, ns, kind, name string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", ns, "get", kind, name, "--ignore-not-found", "-o", "jsonpath={.metadata.resourceVersion}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// m8ClusterResourceVersion is m8ResourceVersion for an object with no namespace.
func m8ClusterResourceVersion(t *testing.T, cluster, kind, name string) string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "get", kind, name, "--ignore-not-found", "-o", "jsonpath={.metadata.resourceVersion}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}
