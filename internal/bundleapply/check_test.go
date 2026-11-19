package bundleapply

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	rNot   = op.ReasonComponentNotAllowed
	rPlane = op.ReasonPolicyBlocksPlanes
)

type want struct{ reason, detail string }

func pass() want { return want{} }

func not(detail string) want { return want{rNot, detail} }

func loadObject(t *testing.T, dir, name string) Object {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", dir, name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	objs, err := Decode(data, 10)
	if err != nil || len(objs) != 1 {
		t.Fatalf("decode %s/%s: %d objects, %v", dir, name, len(objs), err)
	}
	return objs[0]
}

func newTestChecker(t *testing.T, role string, h HarnessRefs) *Checker {
	t.Helper()
	c, err := NewChecker(role, bundle.DefaultPolicy(), h)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func expect(t *testing.T, err error, w want, object string) {
	t.Helper()
	if w == (want{}) {
		if err != nil {
			t.Fatalf("want pass, got %v", err)
		}
		return
	}
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("want refusal %s:%s, got %v", w.reason, w.detail, err)
	}
	if r.Reason != w.reason || r.Detail != w.detail {
		t.Fatalf("want %s:%s, got %s:%s", w.reason, w.detail, r.Reason, r.Detail)
	}
	if object != "" && !strings.Contains(r.Object, object) {
		t.Fatalf("refusal object %q does not name %q", r.Object, object)
	}
}

type tcase struct {
	name      string
	component string
	want      want
	with      []string // fixtures of the same directory that precede the object in the component
	cluster   []string // extra cluster scoped kinds, as group/Kind
	namespace []string // extra namespaced kinds, as group/Kind
}

func runCases(t *testing.T, role, dir, defComponent string, h HarnessRefs, cases []tcase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			comp := tc.component
			if comp == "" {
				comp = defComponent
			}
			c := newTestChecker(t, role, h)
			c.AddScopes(tc.cluster, tc.namespace)
			var objs []Object
			for _, w := range tc.with {
				objs = append(objs, loadObject(t, dir, w))
			}
			objs = append(objs, loadObject(t, dir, tc.name))
			expect(t, c.Check(context.Background(), comp, objs), tc.want, "")
		})
	}
}

func TestPolicyApp(t *testing.T) {
	runCases(t, "cell", "app", "apps-sample", HarnessRefs{}, []tcase{
		{name: "configmap"},
		{name: "deployment"},
		{name: "service_clusterip"},
		{name: "service_headless"},
		{name: "networkpolicy", want: not("kind")},
		{name: "authorizationpolicy", want: not("kind")},
		{name: "serviceentry", want: not("kind")},
		{name: "httproute", want: not("kind")},
		{name: "namespace_object", want: not("kind")},
		{name: "configmap_in_argocd", want: not("namespace")},
		{name: "configmap_in_apps_demo", want: not("namespace")},
		{name: "configmap_no_namespace", want: not("namespace_missing")},
		{name: "service_nodeport", want: not("service_type")},
		{name: "service_loadbalancer", want: not("service_type")},
		{name: "service_external_ips", want: not("service_type")},
		{name: "inject_false_label", want: not("mesh_opt_out")},
		{name: "inject_false_annotation", want: not("mesh_opt_out")},
		{name: "harness_label", want: not("harness_label")},
		{name: "deployment_template_metadata_string", want: not("layout")},
		{name: "deployment_template_labels_string", want: not("layout")},
		{name: "service_spec_string", want: not("layout")},
		{name: "application", want: not("kind")},
		{name: "unknown_kind", want: not("kind_unknown_scope")},
		{name: "unknown_kind", want: not("kind"), namespace: []string{"widgets.example.invalid/Widget"}},
		{name: "knative_service", want: not("kind_unknown_scope")},
		{name: "knative_service", want: not("kind"), namespace: []string{"serving.knative.dev/Service"}},
		{name: "secret_opaque"},
		{name: "secret_sa_token", want: not("service_account_token")},
		{name: "serviceaccount_client"},
		{name: "deployment_sa_default"},
		{name: "deployment_sa_client", want: not("foreign_service_account")},
		{name: "deployment_sa_client", with: []string{"serviceaccount_client"}},
		{name: "deployment_sa_legacy_field", want: not("foreign_service_account")},
		{name: "deployment_sa_legacy_field", with: []string{"serviceaccount_client"}},
		{name: "traffic_exclude_outbound", want: not("mesh_opt_out")},
		{name: "interception_mode", want: not("mesh_opt_out")},
		{name: "proxy_config", want: not("mesh_opt_out")},
		{name: "proxy_image", want: not("mesh_opt_out")},
		{name: "inject_templates", want: not("mesh_opt_out")},
		{name: "rev_label", want: not("mesh_opt_out")},
		{name: "configmap_kube_root_ca", want: not("reserved_object")},
		{name: "configmap_istio_ca_root_cert", want: not("reserved_object")},
		{name: "serviceaccount_default", want: not("reserved_object")},
	})
}

func TestPolicyPlatform(t *testing.T) {
	runCases(t, "cell", "platform", "namespaces", HarnessRefs{}, []tcase{
		{name: "crd"},
		{name: "clusterrole"},
		{name: "deployment_istio_system"},
		{name: "namespace_apps_demo"},
		{name: "namespace_apps_sample"},
		{name: "networkpolicy_apps_sample", component: "network-policy"},
		{name: "authorizationpolicy_apps_sample", component: "mesh-policy"},
		{name: "configmap_apps_sample", want: not("namespace")},
		{name: "deployment_apps_sample", component: "apps-demo", want: not("namespace")},
		{name: "extra_allow_all_policy", component: "network-policy"},
		{name: "configmap_cell_identity_system", want: not("harness_namespace")},
		{name: "namespace_cell_ops_system", want: not("harness_namespace")},
		{name: "configmap_spire_system", want: not("namespace")},
		{name: "persistentvolume", want: not("kind")},
		{name: "adminnetworkpolicy", want: not("kind")},
		{name: "adminnetworkpolicy_namespaced", want: not("kind")},
		{name: "crd_with_namespace", want: not("cluster_kind_namespaced")},
		{name: "persistentvolume_namespaced", want: not("kind")},
		{name: "apiservice_namespaced", want: not("kind")},
		{name: "mutatingadmissionpolicy_namespaced", want: not("kind")},
		{name: "storageclass", want: not("kind")},
		{name: "widget", want: not("kind_unknown_scope")},
		{name: "widget_cluster", want: not("kind_unknown_scope")},
		{name: "widget", with: []string{"widget_crd_namespaced"}},
		{name: "widget", with: []string{"widget_crd_cluster"}, want: not("kind")},
		{name: "widget_cluster", with: []string{"widget_crd_cluster"}, want: not("kind")},
		{name: "widget", namespace: []string{"widgets.example.invalid/Widget"}},
		{name: "widget", cluster: []string{"widgets.example.invalid/Widget"}, want: not("kind")},
		{name: "clusterrolebinding_foreign_group", want: not("kind_unknown_scope")},
		{name: "clusterrolebinding_foreign_group", cluster: []string{"evil.example.invalid/ClusterRoleBinding"}, want: not("kind")},
		{name: "crd_null_namespace"},
		{name: "namespace_argocd_no_label", want: want{rPlane, "mesh_injection"}},
		{name: "namespace_argocd_disabled"},
		{name: "namespace_kube_system", want: not("namespace")},
		{name: "deployment_argocd_inject_true", want: want{rPlane, "mesh_injection"}},
		{name: "deployment_argocd_rev_label", want: want{rPlane, "mesh_injection"}},
		{name: "cronjob_argocd_inject_true", want: want{rPlane, "mesh_injection"}},
		{name: "deployment_istio_system_inject_true", component: "istiod"},
		{name: "application", component: "argocd", want: not("kind")},
		{name: "applicationset", component: "argocd", want: not("kind")},
		{name: "application", component: "mesh-policy", want: not("kind")},
		{name: "appproject_cell", component: "argocd"},
		{name: "appproject_cell", component: "istiod", want: not("kind")},
		{name: "appproject_default", component: "argocd", want: not("appproject_spec")},
		{name: "appproject_other", component: "argocd", want: not("kind")},
		{name: "deployment_harness_label_template", want: not("harness_label")},
		{name: "unknown_component_object", component: "nope", want: not("component_unknown")},
		{name: "namespace_argocd_injection", want: want{rPlane, "mesh_injection"}},
		{name: "namespace_argocd_rev", want: want{rPlane, "mesh_injection"}},
		{name: "secret_sa_token", component: "argocd", want: not("service_account_token")},
		{name: "deployment_apps_demo_sa_client", component: "apps-demo"},
		{name: "serviceaccount_default_apps_demo", component: "apps-demo"},
	})
}

func TestPolicyCp(t *testing.T) {
	runCases(t, "cp", "cp", "spire-server", HarnessRefs{}, []tcase{
		{name: "spire_server_statefulset"},
		{name: "external_secret_spire_system", component: "external-secrets"},
		{name: "relay_deployment", component: "relay-system"},
		{name: "configmap_envd_system", want: not("harness_namespace")},
		{name: "namespace_gateway_system", component: "namespaces", want: not("harness_namespace")},
		{name: "role_cell_controller_system", want: not("harness_namespace")},
		{name: "configmap_apps_sample", component: "apps-sample", want: not("component_unknown")},
		{name: "namespace_apps_sample", component: "namespaces"},
		{name: "networkpolicy_apps_sample", component: "network-policy"},
		{name: "authorizationpolicy_apps_sample", component: "mesh-policy"},
		{name: "configmap_in_apps_sample", component: "relay-system", want: not("namespace")},
		{name: "clustergenerator", component: "external-secrets", want: not("kind")},
		{name: "clustergenerator_namespaced", component: "external-secrets", want: not("kind")},
		{name: "clusterpushsecret", component: "external-secrets", want: not("kind")},
		{name: "generator_password", component: "external-secrets"},
		{name: "namespace_spire_system_injection", component: "namespaces", want: want{rPlane, "mesh_injection"}},
		{name: "secret_sa_token_spire_system", want: not("service_account_token")},
	})
}

func TestPolicyHarnessObjects(t *testing.T) {
	cell := HarnessRefs{NetworkPolicies: []ObjectRef{
		{"cell-system", "plane-celld-store"}, {"argocd", "argocd-agent"},
	}}
	cp := HarnessRefs{NetworkPolicies: []ObjectRef{
		{"relay-system", "plane-cells"}, {"spire-system", "plane-cells"},
	}}
	runCases(t, "cell", "harness", "namespaces", cell, []tcase{
		{name: "vap", want: not("harness_object")},
		{name: "vap_binding", want: not("harness_object")},
		{name: "np_other", component: "network-policy"},
	})
	t.Run("cell np_argocd_agent", func(t *testing.T) {
		c := newTestChecker(t, "cell", cell)
		err := c.Check(context.Background(), "network-policy", []Object{loadObject(t, "harness", "np_argocd_agent")})
		expect(t, err, want{rPlane, "argocd/argocd-agent"}, "argocd-agent")
	})
	t.Run("cp np_plane_cells", func(t *testing.T) {
		c := newTestChecker(t, "cp", cp)
		err := c.Check(context.Background(), "spire-server", []Object{loadObject(t, "harness", "np_plane_cells")})
		expect(t, err, want{rPlane, "spire-system/plane-cells"}, "plane-cells")
	})
	t.Run("cp vap", func(t *testing.T) {
		c := newTestChecker(t, "cp", cp)
		err := c.Check(context.Background(), "namespaces", []Object{loadObject(t, "harness", "vap")})
		expect(t, err, not("harness_object"), "")
	})
	t.Run("cp without live cells refuses a reserved name", func(t *testing.T) {
		c := newTestChecker(t, "cp", HarnessRefs{})
		err := c.Check(context.Background(), "spire-server", []Object{loadObject(t, "harness", "np_plane_cells")})
		expect(t, err, want{rPlane, "spire-system/plane-cells"}, "")
	})
	t.Run("every reserved plane policy is refused with no live list", func(t *testing.T) {
		for role, r := range bundle.DefaultPolicy().Roles {
			for _, ref := range r.PlanePolicies {
				np := loadObject(t, "harness", "np_other")
				np.Namespace, np.Name = ref.Namespace, ref.Name
				m := np.Raw["metadata"].(map[string]any)
				m["namespace"], m["name"] = ref.Namespace, ref.Name
				err := newTestChecker(t, role, HarnessRefs{}).Check(context.Background(), "network-policy", []Object{np})
				var rf *Refusal
				if !errors.As(err, &rf) || rf.Reason != rPlane || rf.Detail != ref.Namespace+"/"+ref.Name {
					t.Errorf("%s %s/%s: %v", role, ref.Namespace, ref.Name, err)
				}
			}
		}
	})
	t.Run("bundles-app-limits belongs to role cell", func(t *testing.T) {
		vap := loadObject(t, "harness", "vap")
		vap.Raw["metadata"].(map[string]any)["name"] = "bundles-app-limits"
		vap.Name = "bundles-app-limits"
		expect(t, newTestChecker(t, "cell", cell).Check(context.Background(), "namespaces", []Object{vap}), not("harness_object"), "")
		expect(t, newTestChecker(t, "cp", cp).Check(context.Background(), "namespaces", []Object{vap}), pass(), "")
	})
}

// The last entry of each list must match: the F5 indexer defect of v1.22.0 hides rules that
// compare against a set literal with a reference.
func TestPolicyLastListEntryMatches(t *testing.T) {
	p := bundle.DefaultPolicy()
	for role, r := range p.Roles {
		if len(r.HarnessNamespaces) == 0 || len(r.MeshGuarded) == 0 {
			continue
		}
		c := newTestChecker(t, role, HarnessRefs{})
		comp := "namespaces"
		last := r.HarnessNamespaces[len(r.HarnessNamespaces)-1]
		o := loadObject(t, "cp", "configmap_envd_system")
		o.Raw["metadata"].(map[string]any)["namespace"] = last
		expect(t, c.Check(context.Background(), comp, []Object{o}), not("harness_namespace"), "")
		g := r.MeshGuarded[len(r.MeshGuarded)-1]
		ns := loadObject(t, "cp", "namespace_spire_system_injection")
		ns.Raw["metadata"].(map[string]any)["name"] = g
		expect(t, c.Check(context.Background(), comp, []Object{ns}), want{rPlane, "mesh_injection"}, "")
	}
}

func TestPolicyRoleOpenRefusesEveryComponent(t *testing.T) {
	c := newTestChecker(t, "open", HarnessRefs{})
	for _, comp := range []string{"namespaces", "argocd", "apps-sample", "spire-server"} {
		err := c.Check(context.Background(), comp, []Object{loadObject(t, "app", "configmap")})
		expect(t, err, not("component_unknown"), "")
	}
}

func TestCheckFirstRefusalInInputOrder(t *testing.T) {
	c := newTestChecker(t, "cell", HarnessRefs{})
	objs := []Object{
		loadObject(t, "app", "configmap"),
		loadObject(t, "app", "service_nodeport"),
		loadObject(t, "app", "networkpolicy"),
	}
	err := c.Check(context.Background(), "apps-sample", objs)
	expect(t, err, not("service_type"), "Service/apps-sample/demo")
	expect(t, c.Check(context.Background(), "apps-sample", objs[:1]), pass(), "")
	expect(t, c.Check(context.Background(), "nope", nil), not("component_unknown"), "")
	expect(t, c.Check(context.Background(), "apps-sample", nil), pass(), "")
	expect(t, c.Check(context.Background(), "apps-sample", []Object{}), pass(), "")
	expect(t, newTestChecker(t, "cell", HarnessRefs{}).Check(context.Background(), "argocd", nil), pass(), "")
}

func TestPolicyNoNetworkBuiltins(t *testing.T) {
	bad := map[string]string{
		"http.send":            `x := http.send({"method": "get", "url": "http://127.0.0.1"})`,
		"net.lookup_ip_addr":   `x := net.lookup_ip_addr("example.invalid")`,
		"net.cidr_contains":    `x := net.cidr_contains("10.0.0.0/8", "10.1.1.1")`,
		"opa.runtime":          `x := opa.runtime()`,
		"time.now_ns":          `x := time.now_ns()`,
		"rand.intn":            `x := rand.intn("a", 3)`,
		"uuid.rfc4122":         `x := uuid.rfc4122("a")`,
		"io.jwt.decode_verify": `x := io.jwt.decode_verify("a", {})`,
		"json.match_schema":    `x := json.match_schema({}, {"$ref": "file:///etc/passwd"})`,
		"json.verify_schema":   `x := json.verify_schema({"$ref": "http://127.0.0.1/s"})`,
		"sprintf":              `x := sprintf("%v", [1])`,
	}
	for name, rule := range bad {
		t.Run(name, func(t *testing.T) {
			module := policySource + "\nextra_deny contains d if {\n\t" + rule + "\n\td := x\n}\n"
			if _, err := newChecker("cell", bundle.DefaultPolicy(), HarnessRefs{}, module); err == nil {
				t.Fatalf("a policy that calls %s prepared", name)
			}
		})
	}
	t.Run("control", func(t *testing.T) {
		module := policySource + "\nextra_ok := count([1])\n"
		if _, err := newChecker("cell", bundle.DefaultPolicy(), HarnessRefs{}, module); err != nil {
			t.Fatalf("an allowed builtin failed to prepare: %v", err)
		}
	})
	t.Run("allow net is empty and not nil", func(t *testing.T) {
		caps := capabilities()
		if caps.AllowNet == nil || len(caps.AllowNet) != 0 {
			t.Fatalf("AllowNet = %#v", caps.AllowNet)
		}
		for _, b := range caps.Builtins {
			if !allowedBuiltins[b.Name] {
				t.Fatalf("builtin %s is not on the list", b.Name)
			}
		}
	})
}

// F5: OPA v1.22.0 never matches `x in {"a", input.y}`. The policy must not hold that shape.
func TestPolicyHasNoRefInSetLiteralMembership(t *testing.T) {
	if got := refInLiteralMembership(t, `package x
r if { input.a in {"a", input.y} }`); len(got) == 0 {
		t.Fatal("the scan does not detect the defective shape")
	}
	if got := refInLiteralMembership(t, `package x
r if { input.a in ["a", input.y] }`); len(got) == 0 {
		t.Fatal("the scan does not detect an array literal")
	}
	if got := refInLiteralMembership(t, `package x
r if { input.a in {"a", "b"} }`); len(got) != 0 {
		t.Fatalf("the scan flags constants: %v", got)
	}
	if got := refInLiteralMembership(t, policySource); len(got) != 0 {
		t.Fatalf("bundle.rego holds a membership test against a literal with references: %v", got)
	}
}

func refInLiteralMembership(t *testing.T, src string) []string {
	t.Helper()
	mod, err := ast.ParseModule("p.rego", src)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	ast.WalkExprs(mod, func(e *ast.Expr) bool {
		if !e.IsCall() {
			return false
		}
		if op := e.Operator().String(); op != "internal.member_2" && op != "internal.member_3" {
			return false
		}
		coll := e.Operand(len(e.Operands()) - 1)
		var elems []*ast.Term
		switch v := coll.Value.(type) {
		case ast.Set:
			elems = v.Slice()
		case *ast.Array:
			v.Foreach(func(t *ast.Term) { elems = append(elems, t) })
		}
		for _, el := range elems {
			switch el.Value.(type) {
			case ast.Ref, ast.Var, ast.Call:
				found = append(found, e.String())
			}
		}
		return false
	})
	return found
}

func TestDecodeLimits(t *testing.T) {
	doc := func(i int) string {
		return fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c%d\n  namespace: apps-demo\n", i)
	}
	build := func(n int) []byte {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			sb.WriteString("---\n")
			sb.WriteString(doc(i))
		}
		return []byte(sb.String())
	}
	objs, err := Decode(build(2000), 2000)
	if err != nil || len(objs) != 2000 {
		t.Fatalf("2000 objects: %d, %v", len(objs), err)
	}
	_, err = Decode(build(2001), 2000)
	var r *Refusal
	if !errors.As(err, &r) || r.Reason != rNot || r.Detail != "too_large" {
		t.Fatalf("2001 objects: %v", err)
	}
	_, err = Decode([]byte("apiVersion: v1\nkind: List\nitems: []\n"), 10)
	if !errors.As(err, &r) || r.Detail != "list" {
		t.Fatalf("list: %v", err)
	}
	for name, in := range map[string]string{
		"configmap with items": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: apps-demo}\n" +
			"items:\n- apiVersion: rbac.authorization.k8s.io/v1\n  kind: ClusterRoleBinding\n  metadata: {name: x}\n",
		"configmaplist":  "apiVersion: v1\nkind: ConfigMapList\nmetadata: {name: a}\nitems: []\n",
		"items null":     "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\nitems: null\n",
		"items scalar":   "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\nitems: 5\n",
		"items in later": doc(1) + "---\napiVersion: v1\nkind: Secret\nmetadata: {name: a}\nitems: []\n",
	} {
		if _, err := Decode([]byte(in), 10); !errors.As(err, &r) || r.Reason != rNot || r.Detail != "items_list" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := Decode([]byte("apiVersion: a/b/c\nkind: ConfigMap\nmetadata: {name: a}\n"), 10); !errors.As(err, &r) || r.Detail != "layout" {
		t.Fatalf("apiVersion with two slashes: %v", err)
	}
	objs, err = Decode([]byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: null}\n"), 10)
	if err != nil || len(objs) != 1 || objs[0].Namespace != "" {
		t.Fatalf("null namespace: %v %v", objs, err)
	}
	if _, has := objs[0].Raw["metadata"].(map[string]any)["namespace"]; has {
		t.Fatal("a null namespace stays in Raw")
	}
	for name, in := range map[string]string{
		"no kind":       "apiVersion: v1\nmetadata: {name: a}\n",
		"no name":       "apiVersion: v1\nkind: ConfigMap\nmetadata: {}\n",
		"scalar":        "just text\n",
		"bad labels":    "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, labels: {k: 1}}\n",
		"ns not string": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: 5}\n",
	} {
		if _, err := Decode([]byte(in), 10); !errors.As(err, &r) || r.Detail != "layout" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	objs, err = Decode([]byte("# comment\n---\n---\n"+doc(1)+"---\n"), 10)
	if err != nil || len(objs) != 1 || objs[0].Name != "c1" || objs[0].Namespace != "apps-demo" {
		t.Fatalf("empty documents: %v %v", objs, err)
	}
}

func TestPolicyOptOutValues(t *testing.T) {
	c := newTestChecker(t, "cell", HarnessRefs{})
	for v, refused := range map[string]bool{
		"false": true, "False": true, "FALSE": true, "n": true, "no": true, "No": true, "off": true, "OFF": true,
		"true": false, "": false, "maybe": false, "disabled": false,
	} {
		o := loadObject(t, "app", "deployment")
		tmpl := o.Raw["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)
		tmpl["annotations"] = map[string]any{"sidecar.istio.io/inject": v}
		err := c.Check(context.Background(), "apps-sample", []Object{o})
		if refused {
			expect(t, err, not("mesh_opt_out"), "")
		} else if err != nil {
			t.Errorf("value %q: %v", v, err)
		}
	}
}

func TestPolicyNullNamespaceIsAbsent(t *testing.T) {
	o := loadObject(t, "platform", "crd")
	o.Raw["metadata"].(map[string]any)["namespace"] = nil
	expect(t, newTestChecker(t, "cell", HarnessRefs{}).Check(context.Background(), "namespaces", []Object{o}), pass(), "")
}

func TestPolicyPlaneNameInHarnessNamespace(t *testing.T) {
	for role, r := range bundle.DefaultPolicy().Roles {
		for _, ref := range r.PlanePolicies {
			if !slices.Contains(r.HarnessNamespaces, ref.Namespace) {
				continue
			}
			np := loadObject(t, "harness", "np_other")
			np.Raw["metadata"].(map[string]any)["namespace"] = ref.Namespace
			np.Raw["metadata"].(map[string]any)["name"] = ref.Name
			err := newTestChecker(t, role, HarnessRefs{}).Check(context.Background(), "network-policy", []Object{np})
			expect(t, err, want{rPlane, ref.Namespace + "/" + ref.Name}, "")
		}
	}
}

func TestEveryDenyDetailHasARank(t *testing.T) {
	re := regexp.MustCompile(`entry\("(\w+)", "(\w+)"\)`)
	ms := re.FindAllStringSubmatch(policySource, -1)
	if len(ms) < 15 {
		t.Fatalf("found %d static denials", len(ms))
	}
	for _, m := range ms {
		if _, ok := detailRank[m[2]]; !ok {
			t.Errorf("detail %s has no rank", m[2])
		}
	}
	if _, ok := detailRank["planePolicy"]; !ok {
		t.Error("the plane policy rank is missing")
	}
	if got := rank(denial{reason: rNot, detail: "unranked"}); got != lastRank {
		t.Errorf("an unranked detail has rank %d", got)
	}
	if rank(denial{reason: rNot, detail: "component_unknown"}) >= rank(denial{reason: rNot, detail: "unranked"}) {
		t.Error("component_unknown does not rank before an unranked detail")
	}
}

func TestPolicyErrorsAreRefusals(t *testing.T) {
	// A runtime type error in a builtin is a refusal when strict builtin errors are on.
	module := policySource + "\ndeny contains entry(\"component_not_allowed\", \"zz\") if {\n\tx := object.get(input.kind, \"k\", 1)\n\tx == 1\n}\n"
	c, err := newChecker("cell", bundle.DefaultPolicy(), HarnessRefs{}, module)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Check(context.Background(), "apps-sample", []Object{loadObject(t, "app", "configmap")})
	expect(t, err, not("policy_error"), "ConfigMap/apps-sample/demo")

	// A query with no result is a refusal too.
	c, err = newChecker("cell", bundle.DefaultPolicy(), HarnessRefs{}, "package bundle.allow\n\nother := 1\n")
	if err != nil {
		t.Skipf("an empty module does not prepare: %v", err)
	}
	err = c.Check(context.Background(), "apps-sample", []Object{loadObject(t, "app", "configmap")})
	expect(t, err, not("policy_error"), "")
}

func TestPolicyCompilerIsStrict(t *testing.T) {
	module := policySource + "\nunused_var_rule if {\n\tx := 1\n\ttrue\n}\n"
	if _, err := newChecker("cell", bundle.DefaultPolicy(), HarnessRefs{}, module); err == nil {
		t.Fatal("a policy with an unused variable prepared")
	}
}

// generatedRender builds a manifest set that looks like the argocd render of M7: a few large CRDs,
// and workloads, services, roles and policies of the namespace argocd.
func generatedRender() []byte {
	var sb strings.Builder
	var fields strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&fields, "          f%d: {type: string, description: \"generated description of one field\"}\n", i)
	}
	big := fields.String()
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&sb, "---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: w%d.argoproj.io}\n"+
			"spec:\n  group: argoproj.io\n  scope: Namespaced\n  names: {kind: W%d, plural: w%ds}\n  versions:\n  - name: v1\n    schema:\n"+
			"      openAPIV3Schema:\n        type: object\n        properties:\n%s", i, i, i, big)
	}
	kinds := []struct{ api, kind string }{
		{"v1", "ConfigMap"}, {"v1", "Service"}, {"v1", "ServiceAccount"}, {"apps/v1", "Deployment"},
		{"rbac.authorization.k8s.io/v1", "Role"}, {"rbac.authorization.k8s.io/v1", "RoleBinding"},
		{"networking.k8s.io/v1", "NetworkPolicy"},
	}
	for i := 0; i < 33; i++ {
		k := kinds[i%len(kinds)]
		extra := ""
		switch k.kind {
		case "Deployment":
			extra = "spec:\n  selector: {matchLabels: {app: a}}\n  template:\n    metadata: {labels: {app: a}}\n    spec:\n      containers: [{name: a, image: \"registry.invalid/a:1\"}]\n"
		case "NetworkPolicy":
			extra = "spec: {podSelector: {}}\n"
		case "Service":
			extra = "spec: {ports: [{port: 80}]}\n"
		}
		fmt.Fprintf(&sb, "---\napiVersion: %s\nkind: %s\nmetadata: {name: o%d, namespace: argocd}\n%s", k.api, k.kind, i, extra)
	}
	sb.WriteString("---\napiVersion: argoproj.io/v1alpha1\nkind: AppProject\nmetadata: {name: cell, namespace: argocd}\nspec: {description: base}\n")
	return []byte(sb.String())
}

func measure(t *testing.T, label string, data []byte, component string, maxObjects int) {
	t.Helper()
	var peak uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak {
				peak = ms.HeapAlloc
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	start := time.Now()
	objs, err := Decode(data, maxObjects)
	if err != nil {
		t.Fatal(err)
	}
	err = newTestChecker(t, "cell", HarnessRefs{}).Check(context.Background(), component, objs)
	elapsed := time.Since(start)
	close(stop)
	<-done
	t.Logf("%s: %d bytes, %d objects, decode and check in %s, heap peak %d MiB", label, len(data), len(objs), elapsed, peak>>20)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("%s: check took %s", label, elapsed)
	}
}

func TestCheckArgocdSize(t *testing.T) {
	r := generatedRender()
	objs, err := Decode(r, 2000)
	if err != nil || len(objs) != 37 {
		t.Fatalf("generated render: %d objects, %v", len(objs), err)
	}
	if len(r) < 1<<20 {
		t.Fatalf("generated render has %d bytes", len(r))
	}
	measure(t, "argocd-like render", r, "argocd", 2000)

	var sb strings.Builder
	kinds := []string{"ConfigMap", "Secret", "ServiceAccount", "Service"}
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&sb, "---\napiVersion: v1\nkind: %s\nmetadata: {name: o%d, namespace: argocd}\n", kinds[i%len(kinds)], i)
	}
	measure(t, "2000 objects", []byte(sb.String()), "argocd", 2000)
}

// widenedAppPolicy is the default policy with every pod workload kind added to the class app, so that the
// service account rule shows for each kind and not only the kind rule.
func widenedAppPolicy() bundle.Policy {
	p := bundle.DefaultPolicy()
	p.Classes = maps.Clone(p.Classes)
	app := p.Classes["app"]
	app.NamespacedKinds = append(slices.Clone(app.NamespacedKinds),
		"Pod", "apps/StatefulSet", "apps/DaemonSet", "apps/ReplicaSet", "batch/Job", "batch/CronJob")
	p.Classes["app"] = app
	return p
}

// podObject returns an object of kind in apps-sample whose pod spec sets field to value. A nil value leaves
// the field out.
func podObject(t *testing.T, apiVersion, kind, field string, value any) Object {
	t.Helper()
	return podObjectIn(t, "apps-sample", apiVersion, kind, field, value)
}

// podObjectIn is podObject in the namespace ns.
func podObjectIn(t *testing.T, ns, apiVersion, kind, field string, value any) Object {
	t.Helper()
	spec := map[string]any{"containers": []any{map[string]any{"name": "a", "image": "registry.invalid/a:1"}}}
	if value != nil {
		spec[field] = value
	}
	template := map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "a"}}, "spec": spec}
	var body map[string]any
	switch kind {
	case "Pod":
		body = spec
	case "CronJob":
		body = map[string]any{"schedule": "0 * * * *", "jobTemplate": map[string]any{"spec": map[string]any{"template": template}}}
	default:
		body = map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "a"}}, "template": template}
	}
	o, ok := toObject(map[string]any{
		"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{"name": "w", "namespace": ns},
		"spec":     body,
	})
	if !ok {
		t.Fatalf("%s is not an object", kind)
	}
	return o
}

func serviceAccount(t *testing.T, apiVersion, namespace, name string) Object {
	t.Helper()
	o, ok := toObject(map[string]any{"apiVersion": apiVersion, "kind": "ServiceAccount",
		"metadata": map[string]any{"name": name, "namespace": namespace}})
	if !ok {
		t.Fatal("ServiceAccount is not an object")
	}
	return o
}

// TestPolicyAppPodServiceAccounts checks that a pod of an app component runs only as a ServiceAccount that
// the same component declares in the namespace of the pod, or as default, for every kind with a pod spec.
func TestPolicyAppPodServiceAccounts(t *testing.T) {
	c, err := NewChecker("cell", widenedAppPolicy(), HarnessRefs{})
	if err != nil {
		t.Fatal(err)
	}
	kinds := []struct{ apiVersion, kind string }{
		{"apps/v1", "Deployment"}, {"apps/v1", "StatefulSet"}, {"apps/v1", "DaemonSet"}, {"apps/v1", "ReplicaSet"},
		{"batch/v1", "Job"}, {"batch/v1", "CronJob"}, {"v1", "Pod"},
	}
	own := serviceAccount(t, "v1", "apps-sample", "client")
	for _, k := range kinds {
		for _, field := range []string{"serviceAccountName", "serviceAccount"} {
			t.Run(k.kind+"/"+field, func(t *testing.T) {
				check := func(value any, with ...Object) error {
					return c.Check(context.Background(), "apps-sample", append([]Object{podObject(t, k.apiVersion, k.kind, field, value)}, with...))
				}
				expect(t, check("client"), not("foreign_service_account"), k.kind+"/apps-sample/w")
				expect(t, check("client", own), pass(), "")
				expect(t, check(nil), pass(), "")
				expect(t, check("default"), pass(), "")
				expect(t, check(""), pass(), "")
				expect(t, check("other", own), not("foreign_service_account"), "")
				expect(t, check(map[string]any{"name": "client"}, own), not("foreign_service_account"), "")
				expect(t, check(7), not("foreign_service_account"), "")
				// A ServiceAccount of another namespace or of another API group is not the account of the pod.
				expect(t, check("client", serviceAccount(t, "v1", "argocd", "client")), not("foreign_service_account"), "")
				expect(t, check("client", serviceAccount(t, "example.invalid/v1", "apps-sample", "client")), not("foreign_service_account"), "")
			})
		}
	}
	t.Run("platform class names any account", func(t *testing.T) {
		for _, k := range kinds {
			expect(t, c.Check(context.Background(), "apps-demo", []Object{podObjectIn(t, "apps-demo", k.apiVersion, k.kind, "serviceAccountName", "client")}), pass(), "")
		}
	})
}

// TestPolicyServiceAccountsOfTheCheckedComponent checks that the declared accounts come from the objects of
// one Check call, in any order, and do not stay for the next call.
func TestPolicyServiceAccountsOfTheCheckedComponent(t *testing.T) {
	c := newTestChecker(t, "cell", HarnessRefs{})
	dep := loadObject(t, "app", "deployment_sa_client")
	sa := loadObject(t, "app", "serviceaccount_client")
	expect(t, c.Check(context.Background(), "apps-sample", []Object{dep, sa}), pass(), "")
	expect(t, c.Check(context.Background(), "apps-sample", []Object{sa}), pass(), "")
	expect(t, c.Check(context.Background(), "apps-sample", []Object{dep}), not("foreign_service_account"), "Deployment/apps-sample/thief")
}

// TestPolicyOptOutKeys checks that an app pod may carry no key that changes, moves traffic past, or removes
// its sidecar, in labels or annotations, whatever the value. The only mesh key it may carry is
// sidecar.istio.io/inject, whose opt-out values TestPolicyOptOutValues covers. A platform pod may carry any.
func TestPolicyOptOutKeys(t *testing.T) {
	app := newTestChecker(t, "cell", HarnessRefs{})
	for key, refused := range map[string]bool{
		"traffic.sidecar.istio.io/excludeOutboundIPRanges": true,
		"traffic.sidecar.istio.io/excludeInboundPorts":     true,
		"traffic.sidecar.istio.io/excludeOutboundPorts":    true,
		"traffic.sidecar.istio.io/includeOutboundIPRanges": true,
		"traffic.sidecar.istio.io/includeInboundPorts":     true,
		"traffic.sidecar.istio.io/kubevirtInterfaces":      true,
		"traffic.sidecar.istio.io/anyFutureKey":            true,
		"sidecar.istio.io/interceptionMode":                true,
		"sidecar.istio.io/interceptionmode":                true,
		"proxy.istio.io/config":                            true,
		"sidecar.istio.io/proxyCPU":                        true,
		"sidecar.istio.io/proxyImage":                      true,
		"sidecar.istio.io/bootstrapOverride":               true,
		"sidecar.istio.io/userVolume":                      true,
		"sidecar.istio.io/status":                          true,
		"inject.istio.io/templates":                        true,
		"istio.io/rev":                                     true,
		"Istio.io/Rev":                                     true,
		"sidecar.istio.io/inject":                          false,
		"example.invalid/traffic.sidecar.istio.io":         false,
		"traffic.sidecar.istio.io":                         false,
		"sidecar.istio.io":                                 false,
		"proxy.istio.io/other":                             false,
		"istio.io/other":                                   false,
		"security.istio.io/tlsMode":                        false,
	} {
		for _, field := range []string{"annotations", "labels"} {
			for _, value := range []string{"", "0.0.0.0/0", "NONE"} {
				o := loadObject(t, "app", "deployment")
				tmpl := o.Raw["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)
				tmpl[field] = map[string]any{"app": "demo", key: value}
				err := app.Check(context.Background(), "apps-sample", []Object{o})
				if refused {
					var r *Refusal
					if !errors.As(err, &r) || r.Reason != rNot || r.Detail != "mesh_opt_out" {
						t.Errorf("app %s %s=%q: %v, want mesh_opt_out", field, key, value, err)
					}
				} else if err != nil {
					t.Errorf("app %s %s=%q: %v", field, key, value, err)
				}
				o.Raw["metadata"].(map[string]any)["namespace"] = "istio-system"
				if err := app.Check(context.Background(), "istiod", []Object{o}); err != nil {
					t.Errorf("platform %s %s=%q: %v", field, key, value, err)
				}
			}
		}
	}
}
