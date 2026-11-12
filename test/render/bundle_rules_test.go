package render

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

// These tests render every component of every cluster, as scripts/hydrate.sh does, and check the
// rules that keep a clean harness:up working. The component sets and waves come from scripts/lib.sh.

// component is one entry of a component set: a bundle with its sync wave, a harness component or a
// link component.
type component struct {
	name, ns string
	wave     int
	// kind is "bundle", "harness" or "link".
	kind string
	objs []object
}

type clusterRender struct {
	name       string
	components []*component
	bootstrap  []string
}

// bundleFacts are stub cluster facts for every render.
var bundleFacts = []string{"POD_CIDR=10.11.0.0/16", "SERVICE_CIDR=10.111.0.0/16", "NODE_IPS=172.18.0.4",
	"API_SERVER_IPS=172.18.0.4", "API_SERVER_PORT=6443", "API_SERVICE_IP=10.111.0.1", "DNS_SERVICE_IP=10.111.0.10"}

// stubBinaries names the binary that the stub image must hold for each render that checks one.
var stubBinaries = map[string]string{"spire-server": "/ko-app/cluster-jwt-server", "cell-identity": "/ko-app/cluster-jwt-agent", "argocd-agent": "/ko-app/cluster-jwt-agent", "otel-uplink": "/ko-app/cluster-jwt-agent", "mesh-view": "/ko-app/cluster-jwt-agent"}

var (
	renderAllMu  sync.Mutex
	renderAllOut []*clusterRender
	kustomized   = map[string]string{}
)

// componentSets reads the component sets of a cluster from scripts/lib.sh.
func componentSets(t *testing.T, cluster string) (*clusterRender, error) {
	t.Helper()
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("bash", "-c", `source "$1"
for e in "${COMPONENTS[@]}"; do echo "bundle $e"; done
for e in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do echo "harness $e"; done
for e in ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do echo "link $e"; done
for e in "${BOOTSTRAP[@]}"; do echo "bootstrap $e"; done`, "_", lib)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=" + cluster, "POC_BUILD_ROOT=" + t.TempDir()}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read the component sets of %s: %v: %s", cluster, err, stderr.String())
	}
	cr := &clusterRender{name: cluster}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		kind, entry, _ := strings.Cut(line, " ")
		parts := strings.Split(entry, ":")
		switch {
		case kind == "bootstrap":
			cr.bootstrap = append(cr.bootstrap, entry)
		case kind == "bundle" && len(parts) == 3:
			wave, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("%s: bundle entry %q has no numeric wave", cluster, entry)
			}
			cr.components = append(cr.components, &component{name: parts[0], wave: wave, ns: parts[2], kind: kind})
		case (kind == "harness" || kind == "link") && len(parts) == 2:
			cr.components = append(cr.components, &component{name: parts[0], ns: parts[1], kind: kind})
		default:
			return nil, fmt.Errorf("%s: cannot read the component line %q", cluster, line)
		}
	}
	return cr, nil
}

// parseDocs parses a multi-document render into objects.
func parseDocs(out string) ([]object, error) {
	var objs []object
	for _, d := range regexp.MustCompile(`(?m)^---\s*$`).Split(out, -1) {
		var o object
		if err := yaml.Unmarshal([]byte(d), &o); err != nil {
			return nil, fmt.Errorf("document does not parse: %v", err)
		}
		if o != nil && o["kind"] != nil {
			objs = append(objs, o)
		}
	}
	return objs, nil
}

// renderComponent renders one component of a cluster as hydrate does.
func renderComponent(t *testing.T, cluster string, c *component) (string, error) {
	t.Helper()
	dir, err := filepath.Abs("../../components/" + c.name)
	if err != nil {
		return "", err
	}
	var out string
	if info, err := os.Stat(filepath.Join(dir, "render.sh")); err == nil && info.Mode()&0o111 != 0 {
		binary := stubBinaries[c.name]
		if binary == "" {
			binary = "/ko-app/stub"
		}
		r := runStubbed(t, binary, "", []string{filepath.Join(dir, "render.sh")}, append([]string{"STUB_CELL=" + cluster}, bundleFacts...)...)
		if r.err != nil {
			return "", fmt.Errorf("render %s for %s: %v\n%s", c.name, cluster, r.err, r.stderr)
		}
		out = r.stdout
	} else {
		cached, ok := kustomized[c.name]
		if !ok {
			cmd := exec.Command("kustomize", "build", "--enable-helm", "--load-restrictor", "LoadRestrictionsNone", dir)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			b, err := cmd.Output()
			if err != nil {
				return "", fmt.Errorf("kustomize build %s: %v\n%s", c.name, err, stderr.String())
			}
			cached = string(b)
			kustomized[c.name] = cached
		}
		out = cached
	}
	return strings.NewReplacer("@CELL_NAME@", cluster, "@CELL_MESH_TRUST_DOMAIN@", cluster+".mesh.poc.internal").Replace(out), nil
}

// renderAll renders every component of every cluster with components in harness/topology.yaml.
// The tests of this file share one render.
func renderAll(t *testing.T) []*clusterRender {
	t.Helper()
	testtool.Need(t, "yq", "jq", "helm", "kustomize", "bash", "tar", "go")
	renderAllMu.Lock()
	defer renderAllMu.Unlock()
	if renderAllOut != nil {
		return renderAllOut
	}
	topo, err := topology.Load("../../harness/topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var all []*clusterRender
	for _, cluster := range topo.WithComponents() {
		cr, err := componentSets(t, cluster)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cr.components {
			out, err := renderComponent(t, cluster, c)
			if err != nil {
				t.Fatal(err)
			}
			if c.objs, err = parseDocs(out); err != nil {
				t.Fatalf("%s/%s: %v", cluster, c.name, err)
			}
		}
		all = append(all, cr)
	}
	renderAllOut = all
	return all
}

// builtinGroups are the API groups that the API server serves without a CRD.
var builtinGroups = []string{"", "apps", "batch", "policy", "autoscaling", "networking.k8s.io", "rbac.authorization.k8s.io",
	"admissionregistration.k8s.io", "apiextensions.k8s.io", "storage.k8s.io", "coordination.k8s.io", "discovery.k8s.io",
	"scheduling.k8s.io", "certificates.k8s.io", "node.k8s.io", "apiregistration.k8s.io", "flowcontrol.apiserver.k8s.io"}

func groupOf(o object) string {
	apiVersion, _ := o["apiVersion"].(string)
	if group, _, ok := strings.Cut(apiVersion, "/"); ok {
		return group
	}
	return ""
}

func objName(o object) string {
	ns, _ := lookup(o, "metadata", "namespace")
	name, _ := lookup(o, "metadata", "name")
	if ns != nil {
		return fmt.Sprintf("%v %v/%v", o["kind"], ns, name)
	}
	return fmt.Sprintf("%v %v", o["kind"], name)
}

// podSpecs returns the pod specs of a workload object with the namespace of the workload.
func podSpecs(o object) []map[string]any {
	var path []any
	switch o["kind"] {
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		path = []any{"spec", "template", "spec"}
	case "CronJob":
		path = []any{"spec", "jobTemplate", "spec", "template", "spec"}
	case "Pod":
		path = []any{"spec"}
	default:
		return nil
	}
	if spec, ok := lookup(o, path...); ok {
		if m, ok := spec.(map[string]any); ok {
			return []map[string]any{m}
		}
	}
	return nil
}

func containersOf(spec map[string]any) []map[string]any {
	var out []map[string]any
	for _, key := range []string{"initContainers", "containers"} {
		list, _ := spec[key].([]any)
		for _, c := range list {
			if m, ok := c.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func (cr *clusterRender) waveOf(name string) (int, bool) {
	for _, c := range cr.components {
		if c.kind == "bundle" && c.name == name {
			return c.wave, true
		}
	}
	return 0, false
}

// TestRootBundleWaveOrder checks that no bundle depends on a later wave, a harness component or a
// link component, so a clean harness:up never waits for something that comes later.
func TestRootBundleWaveOrder(t *testing.T) {
	// The relay comes at wave 8 in dev-cp, after spire-server, and each cell runs the agent as a
	// harness component, so the loop below checks both.
	// The collector comes at wave 3 in every cluster. The uplink is a harness component in dev-cp (the
	// SPIRE server does not exist at the first hydrate) and in each cell.
	want := map[string][]string{
		"management": {"bundle observability-store 8 observability-system", "bundle observability-system 3 observability-system", "link mesh-view-hub 0 mesh-view-system", "link mgmt-api 0 mgmt-system"},
		"dev-cp":     {"bundle relay-system 8 relay-system", "bundle observability-system 3 observability-system", "harness otel-uplink 0 observability-system"},
		"dev-cell-1": {"harness argocd-agent 0 argocd", "bundle observability-system 3 observability-system", "harness otel-uplink 0 observability-system", "harness mesh-view 0 mesh-view-system"},
		"dev-cell-2": {"harness argocd-agent 0 argocd", "bundle observability-system 3 observability-system", "harness otel-uplink 0 observability-system", "harness mesh-view 0 mesh-view-system"},
	}
	for _, cr := range renderAll(t) {
		if ws, ok := want[cr.name]; ok {
			for _, w := range ws {
				found := false
				for _, c := range cr.components {
					found = found || fmt.Sprintf("%s %s %d %s", c.kind, c.name, c.wave, c.ns) == w
				}
				if !found {
					t.Errorf("%s has no component %q", cr.name, w)
				}
			}
			delete(want, cr.name)
		}
	}
	if len(want) > 0 {
		t.Errorf("the topology has no cluster %v", want)
	}
	for _, cr := range renderAll(t) {
		t.Run(cr.name, func(t *testing.T) {
			// Each CRD by group and kind, with the component that holds it.
			crds := map[string]*component{}
			for _, c := range cr.components {
				for _, o := range c.objs {
					if o["kind"] == "CustomResourceDefinition" {
						crds[get[string](t, o, "spec", "group")+"/"+get[string](t, o, "spec", "names", "kind")] = c
					}
				}
			}
			esoWave, hasESO := cr.waveOf("external-secrets")
			spireWave, hasSpire := cr.waveOf("spire-server")
			// ConfigMaps and Secrets that bundles make, and those that only harness and link components make.
			bundleMade, otherMade := map[string]bool{}, map[string]string{}
			for _, c := range cr.components {
				for _, o := range c.objs {
					if o["kind"] != "ConfigMap" && o["kind"] != "Secret" {
						continue
					}
					key := objName(o)
					if c.kind == "bundle" {
						bundleMade[key] = true
					} else {
						otherMade[key] = c.name
					}
				}
			}
			for _, c := range cr.components {
				if c.kind != "bundle" {
					continue
				}
				bootstrap := slices.Contains(cr.bootstrap, c.name)
				for _, o := range c.objs {
					group, kind := groupOf(o), o["kind"].(string)
					if !slices.Contains(builtinGroups, group) {
						def, ok := crds[group+"/"+kind]
						switch {
						case !ok:
							t.Errorf("%s in bundle %s has no CRD in any component of %s", objName(o), c.name, cr.name)
						case slices.Contains(cr.bootstrap, def.name):
						case def.kind != "bundle":
							t.Errorf("%s in bundle %s uses a CRD of the %s component %s", objName(o), c.name, def.kind, def.name)
						case !bootstrap && def.wave >= c.wave:
							t.Errorf("%s in bundle %s (wave %d) uses a CRD of bundle %s (wave %d), not of a lower wave or the bootstrap set",
								objName(o), c.name, c.wave, def.name, def.wave)
						}
					}
					if group == "external-secrets.io" && kind == "ExternalSecret" || group == "generators.external-secrets.io" {
						if !hasESO || c.wave <= esoWave {
							t.Errorf("%s in bundle %s (wave %d) is not above the external-secrets wave of %s", objName(o), c.name, c.wave, cr.name)
						}
					}
					ns, _ := lookup(o, "metadata", "namespace")
					for _, spec := range podSpecs(o) {
						for _, ctr := range containersOf(spec) {
							if image, _ := ctr["image"].(string); strings.HasPrefix(image, "ghcr.io/spiffe/spire-agent:") && (!hasSpire || c.wave <= spireWave) {
								t.Errorf("%s in bundle %s (wave %d) runs a SPIRE agent, and is not above the spire-server wave of %s", objName(o), c.name, c.wave, cr.name)
							}
						}
						for _, ref := range podRefs(spec) {
							key := fmt.Sprintf("%s %v/%s", ref[0], ns, ref[1])
							if owner, ok := otherMade[key]; ok && !bundleMade[key] {
								t.Errorf("%s in bundle %s uses %s, which only the component %s makes", objName(o), c.name, key, owner)
							}
						}
					}
				}
			}
		})
	}
}

// podRefs returns the ConfigMaps and Secrets that a pod spec mounts or reads, as [kind, name] pairs.
func podRefs(spec map[string]any) [][2]string {
	var refs [][2]string
	add := func(kind string, v any, path ...any) {
		if x, ok := lookup(v, path...); ok {
			if name, ok := x.(string); ok {
				refs = append(refs, [2]string{kind, name})
			}
		}
	}
	volumes, _ := spec["volumes"].([]any)
	for _, v := range volumes {
		add("ConfigMap", v, "configMap", "name")
		add("Secret", v, "secret", "secretName")
		sources, _ := lookup(v, "projected", "sources")
		list, _ := sources.([]any)
		for _, s := range list {
			add("ConfigMap", s, "configMap", "name")
			add("Secret", s, "secret", "name")
		}
	}
	for _, c := range containersOf(spec) {
		env, _ := c["env"].([]any)
		for _, e := range env {
			add("ConfigMap", e, "valueFrom", "configMapKeyRef", "name")
			add("Secret", e, "valueFrom", "secretKeyRef", "name")
		}
		envFrom, _ := c["envFrom"].([]any)
		for _, e := range envFrom {
			add("ConfigMap", e, "configMapRef", "name")
			add("Secret", e, "secretRef", "name")
		}
	}
	return refs
}

// The containers below came with M2 or earlier, from the vendored Argo CD manifest, the Istio charts
// and the demo workloads. Each key is "<component> <kind> <namespace>/<name> <container>". The test
// fails when a key no longer matches a rendered container, so a fixed container leaves the list.
var (
	// unpinnedBefore holds images by tag. The Istio gateway image "auto" is a placeholder that the
	// sidecar injector replaces.
	unpinnedBefore = map[string]bool{
		"argocd Deployment argocd/argocd-applicationset-controller argocd-applicationset-controller": true,
		"argocd Deployment argocd/argocd-redis redis":                                                true,
		"argocd Deployment argocd/argocd-redis secret-init":                                          true,
		"argocd Deployment argocd/argocd-repo-server argocd-repo-server":                             true,
		"argocd Deployment argocd/argocd-repo-server copyutil":                                       true,
		"argocd StatefulSet argocd/argocd-application-controller argocd-application-controller":      true,
		"istio-cni DaemonSet istio-system/istio-cni-node install-cni":                                true,
		"istio-egress Deployment istio-egress/istio-egressgateway istio-proxy":                       true,
		"istiod Deployment istio-system/istiod discovery":                                            true,
	}
	// unboundedBefore holds containers without CPU and memory requests or a memory limit.
	unboundedBefore = map[string]bool{
		"apps-demo Deployment apps-demo/client curl":                                                 true,
		"apps-demo Deployment apps-demo/echo echo":                                                   true,
		"apps-demo Deployment apps-demo/intruder curl":                                               true,
		"apps-demo Deployment apps-demo/plaintext curl":                                              true,
		"argocd Deployment argocd/argocd-applicationset-controller argocd-applicationset-controller": true,
		"argocd Deployment argocd/argocd-redis redis":                                                true,
		"argocd Deployment argocd/argocd-redis secret-init":                                          true,
		"argocd Deployment argocd/argocd-repo-server argocd-repo-server":                             true,
		"argocd Deployment argocd/argocd-repo-server copyutil":                                       true,
		"argocd StatefulSet argocd/argocd-application-controller argocd-application-controller":      true,
		"istio-cni DaemonSet istio-system/istio-cni-node install-cni":                                true,
		"istiod Deployment istio-system/istiod discovery":                                            true,
	}
)

// TestRenderedPodsPinnedAndBounded checks every container of every render: its image is pinned by
// digest, and it has CPU and memory requests and a memory limit.
func TestRenderedPodsPinnedAndBounded(t *testing.T) {
	seen := map[string]bool{}
	for _, cr := range renderAll(t) {
		for _, c := range cr.components {
			for _, o := range c.objs {
				for _, spec := range podSpecs(o) {
					for _, ctr := range containersOf(spec) {
						name := fmt.Sprintf("%s %s %s", c.name, objName(o), ctr["name"])
						seen[name] = true
						if image, _ := ctr["image"].(string); !unpinnedBefore[name] && !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(image) {
							t.Errorf("%s: %s image %q is not pinned by digest", cr.name, name, image)
						}
						if unboundedBefore[name] {
							continue
						}
						for _, path := range [][]any{{"requests", "cpu"}, {"requests", "memory"}, {"limits", "memory"}} {
							if _, ok := lookup(ctr, append([]any{"resources"}, path...)...); !ok {
								t.Errorf("%s: %s has no resources %v", cr.name, name, path)
							}
						}
					}
				}
			}
		}
	}
	for _, name := range []string{"relay-system Deployment relay-system/relay-view relay", "relay-system Deployment relay-system/relay-telemetry relay",
		"argocd-agent Deployment argocd/argocd-agent argocd-agent", "argocd-agent Deployment argocd/argocd-agent cell-proxy",
		"argocd-agent Deployment argocd/argocd-agent spire-agent", "argocd-agent Deployment argocd/argocd-agent install-agent-plugin",
		"observability-store StatefulSet observability-system/lgtm lgtm", "telemetry-gateway Deployment observability-system/telemetry-gateway cell-proxy",
		"observability-system StatefulSet observability-system/otel-collector otel-collector", "otel-uplink Deployment observability-system/otel-uplink cell-proxy",
		"otel-uplink Deployment observability-system/otel-uplink spire-agent", "otel-uplink Deployment observability-system/otel-uplink install-agent-plugin",
		"telemetry-gateway Deployment observability-system/telemetry-gateway spire-agent",
		"mesh-view-hub Deployment mesh-view-system/mesh-view-hub cell-proxy", "mesh-view-hub Deployment mesh-view-system/mesh-view-hub spire-agent",
		"mesh-view-hub Deployment mesh-view-system/kiali kiali", "mesh-view Deployment mesh-view-system/mesh-view cell-proxy",
		"mesh-view Deployment mesh-view-system/mesh-view spire-agent", "mesh-view Deployment mesh-view-system/mesh-view install-agent-plugin",
		"observability-store Deployment observability-system/prom-readonly cell-proxy",
		"mgmt-api StatefulSet mgmt-system/mgmtd mgmtd", "mgmt-api StatefulSet mgmt-system/mgmtd spire-agent"} {
		if !seen[name] {
			t.Errorf("no render holds the container %q", name)
		}
	}
	for _, list := range []map[string]bool{unpinnedBefore, unboundedBefore} {
		for name := range list {
			if !seen[name] {
				t.Errorf("the exception %q matches no rendered container. Remove it", name)
			}
		}
	}
}

// TestNoEmptyPeerList checks that every NetworkPolicy rule in every render names its peers. A rule
// with an empty or missing from or to list admits every peer.
func TestNoEmptyPeerList(t *testing.T) {
	// The collector policies and both forms of the uplink must be among the policies that the loop sees.
	seen := map[string]bool{}
	defer func() {
		for _, cluster := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
			if !seen[cluster+" collector"] || !seen[cluster+" collector-egress"] {
				t.Errorf("the loop saw no collector policy in %s", cluster)
			}
			if cluster != "management" && !seen[cluster+" otel-uplink"] {
				t.Errorf("the loop saw no uplink policy in %s", cluster)
			}
		}
		if !seen["management mgmtd"] {
			t.Error("the loop saw no mgmtd policy in management")
		}
	}()
	for _, cr := range renderAll(t) {
		for _, c := range cr.components {
			for _, o := range c.objs {
				if o["kind"] != "NetworkPolicy" {
					continue
				}
				seen[cr.name+" "+fmt.Sprint(lookupOr(o, "metadata", "name"))] = true
				for _, dir := range [][2]string{{"ingress", "from"}, {"egress", "to"}} {
					rules, _ := lookup(o, "spec", dir[0])
					list, _ := rules.([]any)
					for i, rule := range list {
						peers, _ := lookup(rule, dir[1])
						if l, ok := peers.([]any); !ok || len(l) == 0 {
							t.Errorf("%s: %s %s rule %d of %s has no %s peers", cr.name, c.name, dir[0], i, objName(o), dir[1])
						}
					}
				}
			}
		}
	}
}

// TestHarnessObjectsHaveOneOwner checks that no harness or link component renders an object with
// the kind, namespace and name of a bundle object of the same cluster. cell:up would take such an
// object from its Application, and Argo CD would take it back on each sync.
func TestHarnessObjectsHaveOneOwner(t *testing.T) {
	for _, cr := range renderAll(t) {
		bundleObjs := map[string]string{}
		for _, c := range cr.components {
			if c.kind == "bundle" {
				for _, o := range c.objs {
					bundleObjs[objName(o)] = c.name
				}
			}
		}
		for _, c := range cr.components {
			if c.kind == "bundle" {
				continue
			}
			for _, o := range c.objs {
				if owner, ok := bundleObjs[objName(o)]; ok {
					t.Errorf("%s: the %s component %s renders %s, which the bundle %s also renders", cr.name, c.kind, c.name, objName(o), owner)
				}
			}
		}
	}
}

// TestRendersRefuseEmptyAddressLists renders each component that builds a NetworkPolicy peer list
// from an address list of build/<cluster>/facts.env. A blank or malformed list must stop the
// render, because a rule with no peers admits every peer.
func TestRendersRefuseEmptyAddressLists(t *testing.T) {
	type render func(t *testing.T, env ...string) (string, string, error)
	script := func(component, cluster string) render {
		return func(t *testing.T, env ...string) (string, string, error) {
			r := renderScript(t, component, stubBinaries[component], append(append([]string{"STUB_CELL=" + cluster}, bundleFacts...), env...)...)
			return r.stdout, r.stderr, r.err
		}
	}
	eso := func(t *testing.T, env ...string) (string, string, error) {
		return renderExternalSecrets(t, append(slices.Clone(esoFacts), env...)...)
	}
	cases := []struct {
		name   string
		render render
		vars   []string
	}{
		{"spire-server of management", script("spire-server", "management"), []string{"API_SERVER_IPS"}},
		{"cell-identity", script("cell-identity", "dev-cell-1"), []string{"API_SERVER_IPS"}},
		{"external-secrets", eso, []string{"API_SERVER_IPS"}},
		{"network-policy", script("network-policy", "dev-cell-1"), []string{"API_SERVER_IPS", "NODE_IPS"}},
		{"relay-system", script("relay-system", "dev-cp"), []string{"NODE_IPS"}},
		{"argocd-agent", script("argocd-agent", "dev-cell-1"), []string{"API_SERVER_IPS"}},
		{"observability-system", script("observability-system", "dev-cell-1"), []string{"API_SERVER_IPS", "NODE_IPS"}},
		{"otel-uplink of a cell", script("otel-uplink", "dev-cell-1"), []string{"API_SERVER_IPS", "NODE_IPS"}},
		{"otel-uplink of dev-cp", script("otel-uplink", "dev-cp"), []string{"NODE_IPS"}},
		{"mgmt-api", script("mgmt-api", "management"), []string{"API_SERVER_IPS", "NODE_IPS"}},
	}
	for _, tc := range cases {
		for _, v := range tc.vars {
			for value, want := range map[string]string{" ": v + " holds no address", "172.18.0": "is not IPv4: 172.18.0"} {
				t.Run(fmt.Sprintf("%s %s=%q", tc.name, v, value), func(t *testing.T) {
					out, stderr, err := tc.render(t, v+"="+value)
					if err == nil || out != "" || !strings.Contains(stderr, want) {
						t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", err, len(out), stderr, want)
					}
				})
			}
		}
	}
}
