package render

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
)

// storeWriter is the --writer argument that each cluster gets: the account of the applier of its role.
// Role open (management) gets none, so the proxy refuses every write.
var storeWriter = map[string]string{
	"dev-cell-1": "--writer=system:serviceaccount:cell-identity-system:celld",
	"dev-cell-2": "--writer=system:serviceaccount:cell-identity-system:celld",
	"dev-cp":     "--writer=system:serviceaccount:envd-system:envd",
	"management": "",
}

// stubProxyImage is the cell-proxy reference that the stub build/images.env pins.
func stubProxyImage(t *testing.T, got string) {
	t.Helper()
	if !strings.HasPrefix(got, "localhost:5001/cell-proxy@sha256:") || strings.Contains(got, "@CELL_PROXY_IMAGE@") {
		t.Errorf("the image is %q, want the pinned cell-proxy reference from images.env", got)
	}
}

// proxyResources checks requests of 5m and 16Mi and a memory limit of 64Mi, and no CPU limit.
func proxyResources(t *testing.T, c map[string]any) {
	t.Helper()
	if got := fmt.Sprint(lookupOr(c, "resources")); got != "map[limits:map[memory:64Mi] requests:map[cpu:5m memory:16Mi]]" {
		t.Errorf("resources are %s, want requests 5m and 16Mi and limit 64Mi", got)
	}
}

// mountsOf lists the containers and init containers of a pod that mount the volume.
func mountsOf(pod map[string]any, volume string) []string {
	var out []string
	for _, key := range []string{"initContainers", "containers"} {
		list, _ := pod[key].([]any)
		for _, c := range list {
			m, _ := c.(map[string]any)
			mounts, _ := m["volumeMounts"].([]any)
			for _, v := range mounts {
				if v.(map[string]any)["name"] == volume {
					out = append(out, fmt.Sprint(m["name"]))
				}
			}
		}
	}
	return out
}

// wantToken checks that the pod has exactly one volume with a serviceAccountToken source (in a projected volume), that
// it is the named volume with exactly the expected token source, and that exactly the named container mounts it.
// A second token volume, or another mount of the first, would give a container a token that it must not have.
func wantToken(t *testing.T, pod map[string]any, volume, source, container string) {
	t.Helper()
	var tokenVolumes []string
	for _, v := range get[[]any](t, pod, "volumes") {
		m := v.(map[string]any)
		sources, _ := lookupOr(m, "projected", "sources").([]any)
		for _, src := range sources {
			if tok, ok := src.(map[string]any)["serviceAccountToken"]; ok {
				tokenVolumes = append(tokenVolumes, fmt.Sprint(m["name"]))
				if m["name"] == volume && fmt.Sprint(tok) != source {
					t.Errorf("volume %s token source is %v, want %s", volume, tok, source)
				}
			}
		}
	}
	if fmt.Sprint(tokenVolumes) != fmt.Sprint([]string{volume}) {
		t.Errorf("the pod has the token volumes %v, want only %s", tokenVolumes, volume)
	}
	if got := mountsOf(pod, volume); fmt.Sprint(got) != fmt.Sprint([]string{container}) {
		t.Errorf("volume %s is mounted by %v, want only %s", volume, got, container)
	}
}

// noSharedNamespaces checks that the pod shares no namespace with the host and no process namespace between its
// containers, so that no container reads the token of another through /proc or the host network.
func noSharedNamespaces(t *testing.T, pod map[string]any) {
	t.Helper()
	for _, field := range []string{"shareProcessNamespace", "hostNetwork", "hostPID", "hostIPC"} {
		if v, ok := pod[field]; ok {
			t.Errorf("the pod sets %s = %v, want it absent", field, v)
		}
	}
}

// TestBundleStoreTokenProxy checks the bundle store in every cluster: the registry listens on the loopback
// address of the pod only, the store proxy holds the exact arguments of its role, only the store proxy
// mounts an API token, the Service sends port 5000 to the store proxy, and the account may review tokens.
func TestBundleStoreTokenProxy(t *testing.T) {
	t.Parallel()
	for _, cr := range renderAll(t) {
		t.Run(cr.name, func(t *testing.T) {
			objs := clusterComponent(t, cr.name, "cell-system")
			sts := objs["StatefulSet cell-system/bundle-store"]
			if sts == nil {
				t.Fatal("no StatefulSet bundle-store")
			}
			pod := get[map[string]any](t, sts, "spec", "template", "spec")
			if got := lookupOr(pod, "automountServiceAccountToken"); got != false {
				t.Errorf("automountServiceAccountToken = %v, want false", got)
			}
			containers := get[[]any](t, pod, "containers")
			if len(containers) != 2 {
				t.Fatalf("the pod has %d containers, want the registry and store-proxy", len(containers))
			}
			reg := named(t, containers, "bundle-store")
			var addr string
			for _, e := range get[[]any](t, reg, "env") {
				if e.(map[string]any)["name"] == "REGISTRY_HTTP_ADDR" {
					addr, _ = e.(map[string]any)["value"].(string)
				}
			}
			if addr != "127.0.0.1:5001" {
				t.Errorf("REGISTRY_HTTP_ADDR = %q, want 127.0.0.1:5001", addr)
			}
			if ports, ok := lookup(reg, "ports"); ok {
				t.Errorf("the registry declares ports %v, want none", ports)
			}
			proxy := named(t, containers, "store-proxy")
			stubProxyImage(t, get[string](t, proxy, "image"))
			want := []string{"token", "--listen=:5000", "--upstream=127.0.0.1:5001", "--audience=bundle-store",
				"--reader=system:serviceaccount:argocd:argocd-repo-server"}
			if w := storeWriter[cr.name]; w != "" {
				want = append(want, w)
			}
			want = append(want, "--health=:8080")
			var args []string
			for _, a := range get[[]any](t, proxy, "args") {
				args = append(args, a.(string))
			}
			if fmt.Sprint(args) != fmt.Sprint(want) {
				t.Errorf("store-proxy args are %v, want %v", args, want)
			}
			proxyResources(t, proxy)
			// Readiness follows the registry through /healthz of the proxy, and the registry has no probe.
			if got := fmt.Sprint(lookupOr(proxy, "readinessProbe")); got != "map[httpGet:map[path:/healthz port:health] timeoutSeconds:3]" {
				t.Errorf("store-proxy readinessProbe = %s, want GET /healthz on the port health with timeoutSeconds 3", got)
			}
			// The probe waits longer than the registry check of the proxy, so a slow registry gives the 503 of the proxy.
			timeout, _ := lookupOr(proxy, "readinessProbe", "timeoutSeconds").(float64)
			if time.Duration(timeout*float64(time.Second)) <= cellproxy.StoreHealthTimeout {
				t.Errorf("the readiness probe timeoutSeconds is %v, want more than the %v of the registry check", timeout, cellproxy.StoreHealthTimeout)
			}
			var health any
			for _, p := range get[[]any](t, proxy, "ports") {
				if p.(map[string]any)["name"] == "health" {
					health = p.(map[string]any)["containerPort"]
				}
			}
			if fmt.Sprint(health) != "8080" {
				t.Errorf("store-proxy port health is %v, want 8080 as in --health", health)
			}
			for _, probe := range []string{"readinessProbe", "livenessProbe", "startupProbe"} {
				if p, ok := lookup(reg, probe); ok {
					t.Errorf("the registry container has %s %v, want none", probe, p)
				}
			}
			// The one serviceAccountToken volume of the pod is the API token, and only store-proxy mounts it.
			wantToken(t, pod, "api-token", "map[expirationSeconds:3600 path:token]", "store-proxy")
			noSharedNamespaces(t, pod)
			svc := objs["Service cell-system/bundle-store"]
			ports := get[[]any](t, svc, "spec", "ports")
			if len(ports) != 1 || fmt.Sprint(lookupOr(ports[0], "port")) != "5000" || lookupOr(ports[0], "targetPort") != "http" {
				t.Errorf("the Service ports are %v, want 5000 to targetPort http", ports)
			}
			var target any
			for _, p := range get[[]any](t, proxy, "ports") {
				if p.(map[string]any)["name"] == "http" {
					target = p.(map[string]any)["containerPort"]
				}
			}
			if fmt.Sprint(target) != "5000" {
				t.Errorf("store-proxy port http is %v, want 5000", target)
			}
			crb := objs["ClusterRoleBinding bundle-store-auth-delegator"]
			if crb == nil || fmt.Sprint(lookupOr(crb, "roleRef", "name")) != "system:auth-delegator" ||
				fmt.Sprint(lookupOr(crb, "subjects")) != "[map[kind:ServiceAccount name:bundle-store namespace:cell-system]]" {
				t.Errorf("ClusterRoleBinding bundle-store-auth-delegator is %v", crb)
			}
		})
	}
}

// TestRepoServerTokenSidecar checks, in every cluster, the token client in the repo server: its exact
// arguments, a projected token of 600 s with the audience bundle-store that only this container mounts,
// and the same resources.
func TestRepoServerTokenSidecar(t *testing.T) {
	t.Parallel()
	for _, cr := range renderAll(t) {
		t.Run(cr.name, func(t *testing.T) {
			dep := clusterComponent(t, cr.name, "argocd")["Deployment argocd/argocd-repo-server"]
			if dep == nil {
				t.Fatal("no Deployment argocd-repo-server")
			}
			pod := get[map[string]any](t, dep, "spec", "template", "spec")
			containers := get[[]any](t, pod, "containers")
			tok := named(t, containers, "store-token")
			stubProxyImage(t, get[string](t, tok, "image"))
			want := "[token-client --listen=127.0.0.1:5000 --upstream=bundle-store.cell-system.svc.cluster.local:5000 --token-file=/var/run/secrets/bundle-store/token --health=127.0.0.1:8085]"
			if got := fmt.Sprint(get[[]any](t, tok, "args")); got != want {
				t.Errorf("store-token args are %s, want %s", got, want)
			}
			proxyResources(t, tok)
			// The one serviceAccountToken volume of the pod is the bundle-store token, and only store-token mounts it.
			wantToken(t, pod, "bundle-store-token", "map[audience:bundle-store expirationSeconds:600 path:token]", "store-token")
			// The mount path of the token volume plus the file name is the --token-file argument of the same container.
			var mountPath any
			for _, v := range get[[]any](t, tok, "volumeMounts") {
				if v.(map[string]any)["name"] == "bundle-store-token" {
					mountPath = v.(map[string]any)["mountPath"]
				}
			}
			var tokenFile string
			for _, a := range get[[]any](t, tok, "args") {
				if f, ok := strings.CutPrefix(a.(string), "--token-file="); ok {
					tokenFile = f
				}
			}
			if fmt.Sprint(mountPath)+"/token" != tokenFile {
				t.Errorf("the token mounts at %v and --token-file is %q, want <mountPath>/token", mountPath, tokenFile)
			}
			if got := lookupOr(pod, "automountServiceAccountToken"); got != false {
				t.Errorf("the repo server pod has automountServiceAccountToken = %v, want false", got)
			}
			noSharedNamespaces(t, pod)
		})
	}
}

// TestArgocdSyncTimeout checks controller.sync.timeout.seconds in every cluster.
func TestArgocdSyncTimeout(t *testing.T) {
	t.Parallel()
	for _, cr := range renderAll(t) {
		t.Run(cr.name, func(t *testing.T) {
			cm := clusterComponent(t, cr.name, "argocd")["ConfigMap argocd/argocd-cmd-params-cm"]
			if got, _ := lookup(cm, "data", "controller.sync.timeout.seconds"); got != "240" {
				t.Errorf("controller.sync.timeout.seconds = %#v, want \"240\"", got)
			}
		})
	}
}

// TestRepoCredsAndRootUseTheTokenClient checks that Argo CD reads from the token client on the loopback
// address, in the repository credentials and in the root Application.
func TestRepoCredsAndRootUseTheTokenClient(t *testing.T) {
	t.Parallel()
	for _, cr := range renderAll(t) {
		t.Run(cr.name, func(t *testing.T) {
			secret := clusterComponent(t, cr.name, "argocd")["Secret argocd/bundle-store"]
			if got, _ := lookup(secret, "stringData", "url"); got != "oci://127.0.0.1:5000/bundles" {
				t.Errorf("repo creds url = %v, want oci://127.0.0.1:5000/bundles", got)
			}
			if got, _ := lookup(secret, "stringData", "insecureOCIForceHttp"); got != "true" {
				t.Errorf("insecureOCIForceHttp = %v, want \"true\"", got)
			}
		})
	}
	root := readObject(t, "../../bootstrap/root.yaml")
	if got, _ := lookup(root, "spec", "source", "repoURL"); got != "oci://127.0.0.1:5000/bundles/root" {
		t.Errorf("root repoURL = %v, want oci://127.0.0.1:5000/bundles/root", got)
	}
}
