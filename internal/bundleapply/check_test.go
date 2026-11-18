package bundleapply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
}

func runCases(t *testing.T, role, dir, defComponent string, h HarnessRefs, cases []tcase) {
	t.Helper()
	c := newTestChecker(t, role, h)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			comp := tc.component
			if comp == "" {
				comp = defComponent
			}
			err := c.Check(context.Background(), comp, []Object{loadObject(t, dir, tc.name)})
			expect(t, err, tc.want, "")
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
		{name: "configmap_no_namespace", want: not("namespace_missing")},
		{name: "service_nodeport", want: not("service_type")},
		{name: "service_loadbalancer", want: not("service_type")},
		{name: "service_external_ips", want: not("service_type")},
		{name: "inject_false_label", want: not("mesh_opt_out")},
		{name: "inject_false_annotation", want: not("mesh_opt_out")},
		{name: "harness_label", want: not("harness_label")},
	})
}

func TestPolicyPlatform(t *testing.T) {
	runCases(t, "cell", "platform", "namespaces", HarnessRefs{}, []tcase{
		{name: "crd"},
		{name: "clusterrole"},
		{name: "deployment_istio_system"},
		{name: "namespace_apps_demo"},
		{name: "extra_allow_all_policy", component: "network-policy"},
		{name: "configmap_cell_identity_system", want: not("harness_namespace")},
		{name: "namespace_cell_ops_system", want: not("harness_namespace")},
		{name: "configmap_spire_system", want: not("namespace")},
		{name: "persistentvolume", want: not("kind")},
		{name: "adminnetworkpolicy", want: not("kind")},
		{name: "adminnetworkpolicy_namespaced", want: not("kind")},
		{name: "crd_with_namespace", want: not("namespace")},
		{name: "unknown_component_object", component: "nope", want: not("component_unknown")},
		{name: "namespace_argocd_injection", want: want{rPlane, "mesh_injection"}},
		{name: "namespace_argocd_rev", want: want{rPlane, "mesh_injection"}},
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
		{name: "namespace_spire_system_injection", component: "namespaces", want: want{rPlane, "mesh_injection"}},
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
	t.Run("cp without live cells passes", func(t *testing.T) {
		c := newTestChecker(t, "cp", HarnessRefs{})
		err := c.Check(context.Background(), "spire-server", []Object{loadObject(t, "harness", "np_plane_cells")})
		expect(t, err, pass(), "")
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
	expect(t, err, not("service_type"), "Service/apps-demo/demo")
	expect(t, c.Check(context.Background(), "apps-sample", objs[:1]), pass(), "")
	expect(t, c.Check(context.Background(), "nope", nil), not("component_unknown"), "")
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

func findRender(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("M7_RENDER_ARGOCD"); p != "" {
		return p
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for d := dir; ; d = filepath.Dir(d) {
		p := filepath.Join(d, "build", "bundles", "argocd", "manifests.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		if d == filepath.Dir(d) {
			return ""
		}
	}
}

func TestCheckArgocdSize(t *testing.T) {
	path := findRender(t)
	if path == "" {
		t.Skip("no M7 render of argocd: run the hydrate, or set M7_RENDER_ARGOCD")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
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
	objs, err := Decode(data, 2000)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestChecker(t, "cell", HarnessRefs{})
	err = c.Check(context.Background(), "argocd", objs)
	elapsed := time.Since(start)
	close(stop)
	<-done
	t.Logf("argocd render: %d bytes, %d objects, decode and check in %s, heap peak %d MiB", len(data), len(objs), elapsed, peak>>20)
	if elapsed > 10*time.Second {
		t.Fatalf("check took %s", elapsed)
	}
	var r *Refusal
	if errors.As(err, &r) {
		t.Logf("first refusal of the render: %v", r)
	} else if err != nil {
		t.Fatal(err)
	}
}
