package render

import (
	"fmt"
	"strings"
	"testing"
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

// TestBundleStoreTokenProxy checks the bundle store in every cluster: the registry listens on the loopback
// address of the pod only, the store proxy holds the exact arguments of its role, only the store proxy
// mounts an API token, the Service sends port 5000 to the store proxy, and the account may review tokens.
func TestBundleStoreTokenProxy(t *testing.T) {
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
			if got := fmt.Sprint(lookupOr(proxy, "readinessProbe")); got != "map[httpGet:map[path:/healthz port:health]]" {
				t.Errorf("store-proxy readinessProbe = %s, want GET /healthz on the port health", got)
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
			// Only store-proxy mounts the API token.
			for _, c := range containers {
				m := c.(map[string]any)
				has := false
				for _, v := range lookupOr(m, "volumeMounts").([]any) {
					if v.(map[string]any)["name"] == "api-token" {
						has = true
					}
				}
				if has != (m["name"] == "store-proxy") {
					t.Errorf("container %v mounts the API token = %v", m["name"], has)
				}
			}
			var vol map[string]any
			for _, v := range get[[]any](t, pod, "volumes") {
				if v.(map[string]any)["name"] == "api-token" {
					vol = v.(map[string]any)
				}
			}
			if vol == nil || fmt.Sprint(lookupOr(vol, "projected", "sources", 0, "serviceAccountToken")) != "map[expirationSeconds:3600 path:token]" {
				t.Errorf("the api-token volume is %v, want a projected token of 3600 s", vol)
			}
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
			var vol map[string]any
			for _, v := range get[[]any](t, pod, "volumes") {
				if v.(map[string]any)["name"] == "bundle-store-token" {
					vol = v.(map[string]any)
				}
			}
			if vol == nil {
				t.Fatal("no volume bundle-store-token")
			}
			if got := fmt.Sprint(lookupOr(vol, "projected")); got != "map[sources:[map[serviceAccountToken:map[audience:bundle-store expirationSeconds:600 path:token]]]]" {
				t.Errorf("the token volume is %s, want one token of 600 s with audience bundle-store", got)
			}
			for _, c := range containers {
				m := c.(map[string]any)
				mounts, _ := lookupOr(m, "volumeMounts").([]any)
				has := false
				for _, v := range mounts {
					if v.(map[string]any)["name"] == "bundle-store-token" {
						has = true
						if v.(map[string]any)["mountPath"] != "/var/run/secrets/bundle-store" {
							t.Errorf("the token mounts at %v", v)
						}
					}
				}
				if has != (m["name"] == "store-token") {
					t.Errorf("container %v mounts the bundle store token = %v", m["name"], has)
				}
			}
			for _, c := range get[[]any](t, pod, "initContainers") {
				for _, v := range lookupOr(c, "volumeMounts").([]any) {
					if v.(map[string]any)["name"] == "bundle-store-token" {
						t.Errorf("init container %v mounts the bundle store token", c.(map[string]any)["name"])
					}
				}
			}
		})
	}
}

// TestArgocdSyncTimeout checks controller.sync.timeout.seconds in every cluster.
func TestArgocdSyncTimeout(t *testing.T) {
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
