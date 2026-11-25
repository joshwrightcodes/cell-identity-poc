package render

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
)

const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// proofClients are the cell-proxy clients that prove their pod.
var proofClients = []struct{ component, ns, account string }{
	{"argocd-agent", "argocd", "argocd-agent"},
	{"otel-uplink", "observability-system", "otel-uplink"},
	{"mesh-view", "mesh-view-system", "mesh-view"},
}

// containerEnv returns the Downward API field of each variable that comes from a field reference.
func containerEnv(t *testing.T, ctr map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, e := range get[[]any](t, ctr, "env") {
		if p, ok := lookup(e, "valueFrom", "fieldRef", "fieldPath"); ok {
			out[get[string](t, e, "name")] = p.(string)
		}
	}
	return out
}

// TestCellProxyClientsProve checks the three cell-proxy clients in each cell. Each one runs with --proof and the
// four variables of the pod identity. It mounts a projected API token at the standard path, and no other container
// of the pod mounts that volume. The Role of the sidecar already lets the account create a token for itself. The
// uplink of dev-cp has an SVID of the cp path, so it sends no proof and mounts no token.
func TestCellProxyClientsProve(t *testing.T) {
	t.Parallel()
	for _, c := range proofClients {
		for _, cluster := range []string{"dev-cell-1", "dev-cell-2"} {
			t.Run(c.component+"/"+cluster, func(t *testing.T) {
				objs := clusterComponent(t, cluster, c.component)
				dep := objs["Deployment "+c.ns+"/"+c.account]
				if dep == nil {
					t.Fatalf("no Deployment %s/%s in %v", c.ns, c.account, keysOfObjects(objs))
				}
				spec := get[map[string]any](t, dep, "spec", "template", "spec")
				containers := get[[]any](t, spec, "containers")
				proxy := named(t, containers, "cell-proxy")
				if args := argsOf(t, proxy); !slices.Contains(args, "--proof") {
					t.Errorf("cell-proxy args %q lack --proof", args)
				}
				want := map[string]string{"POD_NAME": "metadata.name", "POD_UID": "metadata.uid", "POD_NAMESPACE": "metadata.namespace", "SERVICE_ACCOUNT": "spec.serviceAccountName"}
				if got := containerEnv(t, proxy); fmt.Sprint(got) != fmt.Sprint(want) {
					t.Errorf("cell-proxy pod variables %v, want %v", got, want)
				}
				volume := ""
				for _, m := range get[[]any](t, proxy, "volumeMounts") {
					if get[string](t, m, "mountPath") == tokenPath {
						volume = get[string](t, m, "name")
					}
				}
				if volume == "" {
					t.Fatalf("cell-proxy mounts no token at %s", tokenPath)
				}
				var sources []string
				for _, s := range get[[]any](t, named(t, get[[]any](t, spec, "volumes"), volume), "projected", "sources") {
					for k := range s.(map[string]any) {
						sources = append(sources, k)
					}
				}
				if !slices.Contains(sources, "serviceAccountToken") {
					t.Errorf("volume %s holds the sources %v, want a projected serviceAccountToken", volume, sources)
				}
				for _, other := range containers {
					name := get[string](t, other, "name")
					if name == "cell-proxy" {
						continue
					}
					for _, m := range get[[]any](t, other, "volumeMounts") {
						if get[string](t, m, "name") == volume {
							t.Errorf("container %s also mounts the token volume %s", name, volume)
						}
					}
				}
				if objs["Role "+c.ns+"/"+c.account+"-token"] == nil {
					t.Errorf("no Role %s-token for the token request of the account", c.account)
				}
			})
		}
	}
	t.Run("otel-uplink/dev-cp", func(t *testing.T) {
		objs := clusterComponent(t, "dev-cp", "otel-uplink")
		proxy := named(t, get[[]any](t, objs["Deployment observability-system/otel-uplink"], "spec", "template", "spec", "containers"), "cell-proxy")
		if slices.Contains(argsOf(t, proxy), "--proof") {
			t.Error("the uplink of dev-cp runs with --proof, and its SVID is not a cell SVID")
		}
		for _, m := range get[[]any](t, proxy, "volumeMounts") {
			if get[string](t, m, "mountPath") == tokenPath {
				t.Errorf("the uplink of dev-cp mounts a token: %v", m)
			}
		}
	})
}

// TestCellProxyServersRequireProof checks the three cell-proxy servers of management. Each one has exactly one
// --proof-subject, for its own role, reloads the registry every 10 s, and pins the signer in a ConfigMap whose key
// is the key of mgmt-signing-pub. It mounts the registry as a whole volume of the ConfigMap that mgmtd publishes:
// a mount with subPath never sees the update of a ConfigMap.
func TestCellProxyServersRequireProof(t *testing.T) {
	t.Parallel()
	// SPIRE_CELL_SUBJECTS of cells/dev-cp.env lists "<namespace>/<account>=<role>" for each attested role. A server expects "<role>=<namespace>/<account>".
	subjectOf := map[string]string{}
	for _, e := range strings.Fields(cellEnv(t, "dev-cp", "SPIRE_CELL_SUBJECTS")) {
		account, role, ok := strings.Cut(e, "=")
		if !ok {
			t.Fatalf("SPIRE_CELL_SUBJECTS entry %q has no role", e)
		}
		subjectOf[role] = role + "=" + account
	}
	for _, tc := range []struct{ component, ns, deployment, role string }{
		{"central-view", "central-view-system", "argocd-agent-principal", "argocd-agent"},
		{"telemetry-gateway", "observability-system", "telemetry-gateway", "otel"},
		{"mesh-view-hub", "mesh-view-system", "mesh-view-hub", "mesh-view"},
	} {
		wantSubject, found := subjectOf[tc.role]
		if !found {
			t.Fatalf("SPIRE_CELL_SUBJECTS lists no role %q: %v", tc.role, subjectOf)
		}
		t.Run(tc.component, func(t *testing.T) {
			objs := clusterComponent(t, "management", tc.component)
			spec := get[map[string]any](t, objs["Deployment "+tc.ns+"/"+tc.deployment], "spec", "template", "spec")
			proxy := named(t, get[[]any](t, spec, "containers"), "cell-proxy")
			args := argsOf(t, proxy)
			var subjects []string
			for _, a := range args {
				if v, ok := strings.CutPrefix(a, "--proof-subject="); ok {
					subjects = append(subjects, v)
				}
			}
			if !slices.Equal(subjects, []string{wantSubject}) {
				t.Errorf("--proof-subject values %q, want only %q from SPIRE_CELL_SUBJECTS", subjects, wantSubject)
			}
			for _, want := range []string{"--registry-reload=10s", "--registry-signer=/run/cell-proxy/registry-signer/signer.pub", "--registry-dir=/run/cell-proxy/registry"} {
				if !slices.Contains(args, want) {
					t.Errorf("args %q lack %s", args, want)
				}
			}
			mounts := map[string]string{}
			for _, m := range get[[]any](t, proxy, "volumeMounts") {
				if _, ok := lookup(m, "subPath"); ok {
					t.Errorf("mount %v uses subPath, and a subPath mount never sees an update of its ConfigMap", m)
				}
				mounts[get[string](t, m, "name")] = get[string](t, m, "mountPath")
			}
			volumes := get[[]any](t, spec, "volumes")
			if mounts["registry"] != "/run/cell-proxy/registry" || get[string](t, named(t, volumes, "registry"), "configMap", "name") != "cell-registry" {
				t.Errorf("the registry mount is %q from %v, want the whole ConfigMap cell-registry at /run/cell-proxy/registry", mounts["registry"], named(t, volumes, "registry"))
			}
			if mounts["registry-signer"] != "/run/cell-proxy/registry-signer" || get[string](t, named(t, volumes, "registry-signer"), "configMap", "name") != "registry-signer" {
				t.Errorf("the signer mount is %q, want ConfigMap registry-signer at /run/cell-proxy/registry-signer", mounts["registry-signer"])
			}
			signer := objs["ConfigMap "+tc.ns+"/registry-signer"]
			if signer == nil || strings.TrimSpace(get[string](t, signer, "data", "signer.pub")) != stubMgmtKey {
				t.Errorf("registry-signer is %v, want the key %s of mgmt-signing-pub", signer, stubMgmtKey)
			}
		})
	}
}

// TestGuardAllowsStreamAudience checks the CREATE exception of the two guards in a cell. The one audience of a
// TokenRequest may be the SPIRE audience, or mgmt-stream/<this cell>/<role>/<22 characters of binding>. The test
// runs the patterns of the CEL expression against audiences that the proof package builds.
func TestGuardAllowsStreamAudience(t *testing.T) {
	t.Parallel()
	binding := strings.Repeat("a", 21) + "_"
	for _, tc := range []struct{ component, policy, role string }{
		{"argocd-agent", "argocd-agent-read-only", "argocd-agent"},
		{"mesh-view", "mesh-view-read-only", "mesh-view"},
	} {
		t.Run(tc.component, func(t *testing.T) {
			objs := clusterComponent(t, "dev-cell-1", tc.component)
			policy := objs["ValidatingAdmissionPolicy "+tc.policy]
			if policy == nil {
				t.Fatalf("no policy %s", tc.policy)
			}
			validations := get[[]any](t, policy, "spec", "validations")
			expr := strings.ReplaceAll(get[string](t, validations[len(validations)-1], "expression"), "@CELL_NAME@", "dev-cell-1")
			var patterns []*regexp.Regexp
			for _, m := range regexp.MustCompile(`audiences\[0\]\.matches\('([^']+)'\)`).FindAllStringSubmatch(expr, -1) {
				patterns = append(patterns, regexp.MustCompile(m[1]))
			}
			if len(patterns) != 2 {
				t.Fatalf("the create validation holds %d audience patterns, want the SPIRE one and the stream one:\n%s", len(patterns), expr)
			}
			allowed := func(aud string) bool {
				for _, re := range patterns {
					if re.MatchString(aud) {
						return true
					}
				}
				return false
			}
			for aud, want := range map[string]bool{
				proof.StreamAudience("dev-cell-1", tc.role, binding):                  true,
				proof.StreamAudience("dev-cell-2", tc.role, binding):                  false,
				proof.StreamAudience("dev-cell-1", "otel", binding):                   false,
				proof.StreamAudience("dev-cell-1", tc.role, binding[1:]):              false,
				proof.StreamAudience("dev-cell-1", tc.role, binding+"a"):              false,
				proof.StreamAudience("dev-cell-1", tc.role, "aaaaaaaaaaaaaaaaaaaa/a"): false,
				proof.HelloAudience("dev-cell-1", binding):                            false,
				proof.StreamAudience("dev-cell-1", tc.role, binding) + "x":            false,
				"spire-" + commonEnv(t, "POC_ENV") + "/abc":                           true,
				"https://kubernetes.default.svc":                                      false,
			} {
				if got := allowed(aud); got != want {
					t.Errorf("audience %q allowed %v, want %v", aud, got, want)
				}
			}
			for _, clause := range []string{"object.spec.audiences.size() == 1", "object.spec.boundObjectRef.kind == 'Pod'",
				"request.userInfo.extra['authentication.kubernetes.io/pod-name'] == [object.spec.boundObjectRef.name]",
				"request.userInfo.extra['authentication.kubernetes.io/pod-uid'] == [object.spec.boundObjectRef.uid]"} {
				if !strings.Contains(expr, clause) {
					t.Errorf("the create validation lacks %q", clause)
				}
			}
			if strings.Contains(expr, "@") {
				t.Errorf("the create validation keeps a token:\n%s", expr)
			}
		})
	}
}
