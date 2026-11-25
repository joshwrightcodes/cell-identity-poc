package render

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func renderGateway(t *testing.T, env ...string) result {
	t.Helper()
	return renderScript(t, "cell-gateway", "/ko-app/stub", append(append([]string{"STUB_CELL=dev-cp"}, bundleFacts...), env...)...)
}

// TestCellGatewayRender renders the cell gateway for dev-cp with cells/dev-cp.env. It checks the arguments, the image by digest,
// the bounds, the volumes, the three Services, the key ConfigMap with its checksum, and one NetworkPolicy rule for each of
// the flows N37 to N40, N8, N11 and N23.
func TestCellGatewayRender(t *testing.T) {
	t.Parallel()
	r := renderGateway(t)
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	objs := objectsIn(t, r.stdout)
	if left := regexp.MustCompile(`@[A-Z_]+@`).FindAllString(r.stdout, -1); len(left) > 0 {
		t.Fatalf("render left tokens %v", left)
	}
	for key, o := range objs {
		if v, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); v != "cell-gateway" {
			t.Errorf("%s has harness label %v, want cell-gateway", key, v)
		}
		if o["kind"] == "Secret" {
			t.Errorf("the render holds %s, and no Secret may exist in gateway-system", key)
		}
	}
	for _, want := range []string{"run hostsvc -- facts --cluster dev-cell-1", "run hostsvc -- facts --cluster dev-cell-2",
		"kubectl --context kind-dev-cp -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show"} {
		if !strings.Contains(r.log, want) {
			t.Errorf("render did not run %q; it ran:\n%s", want, r.log)
		}
	}
	if labels := get[map[string]any](t, objs["Namespace gateway-system"], "metadata", "labels"); labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["istio-injection"] != "disabled" {
		t.Errorf("namespace labels are %v", labels)
	}
	if sa := objs["ServiceAccount gateway-system/cell-gateway"]; sa == nil || sa["automountServiceAccountToken"] != false {
		t.Errorf("ServiceAccount cell-gateway is %v, want automountServiceAccountToken: false", sa)
	}
	for key := range objs {
		if strings.HasPrefix(key, "Role ") || strings.HasPrefix(key, "RoleBinding ") {
			t.Errorf("the render holds %s, and the gateway needs no API access", key)
		}
	}

	t.Run("statefulset", func(t *testing.T) {
		sts := objs["StatefulSet gateway-system/cell-gateway"]
		if sts == nil {
			t.Fatalf("no StatefulSet cell-gateway in %v", keysOfObjects(objs))
		}
		if get[float64](t, sts, "spec", "replicas") != 1 || get[string](t, sts, "spec", "serviceName") != "cell-gateway" {
			t.Errorf("replicas %v and serviceName %v, want 1 and cell-gateway", lookupOr(sts, "spec", "replicas"), lookupOr(sts, "spec", "serviceName"))
		}
		claim := get[[]any](t, sts, "spec", "volumeClaimTemplates")[0]
		if get[string](t, claim, "metadata", "name") != "store" || get[string](t, claim, "spec", "resources", "requests", "storage") != "256Mi" {
			t.Errorf("volume claim %v, want store with 256Mi, which makes PVC store-cell-gateway-0", claim)
		}
		pod := get[map[string]any](t, sts, "spec", "template", "spec")
		if pod["serviceAccountName"] != "cell-gateway" || pod["automountServiceAccountToken"] != false || pod["shareProcessNamespace"] != true {
			t.Errorf("pod spec is %v", pod)
		}
		sc := get[map[string]any](t, pod, "securityContext")
		if sc["runAsNonRoot"] != true || sc["runAsUser"] != float64(65532) || sc["fsGroup"] != float64(65532) {
			t.Errorf("pod securityContext is %v, want non-root 65532 with fsGroup 65532", sc)
		}
		labels := get[map[string]any](t, sts, "spec", "template", "metadata", "labels")
		if labels["app.kubernetes.io/name"] != "cell-gateway" || labels["cell.poc.internal/harness"] != "cell-gateway" {
			t.Errorf("pod labels are %v, want the app label that the SPIRE server policy selects, and the harness label", labels)
		}
		containers := get[[]any](t, pod, "containers")
		var names []string
		for _, c := range containers {
			names = append(names, get[string](t, c, "name"))
		}
		if !slices.Equal(names, []string{"spire-agent", "cellgw"}) {
			t.Fatalf("containers are %v, want spire-agent and cellgw", names)
		}
		ctr := named(t, containers, "cellgw")
		wantArgs := []string{"serve", "--env=dev", "--envd-id=spiffe://dev.env.poc.internal/envd", "--spec-key-file=/etc/cellgw/spec-key/spec.pub",
			"--data-dir=/var/lib/cellgw", "--stream-listen=:8450", "--bind-listen=:8451", "--envd-listen=:8452", "--health-listen=:8080",
			"--admin-socket=/run/cellgw/admin.sock", "--operator-key-file=/etc/cellgw/operator-key/keys.pub", "--cell-node=dev-cell-1=10.9.0.1", "--cell-node=dev-cell-2=10.9.0.2"}
		if got := fmt.Sprint(get[[]any](t, ctr, "args")); got != fmt.Sprint(wantArgs) {
			t.Errorf("cellgw args are %s, want %v", got, wantArgs)
		}
		if got := get[string](t, ctr, "image"); got != "localhost:5001/cellgw@"+r.digest {
			t.Errorf("cellgw image is %q, want the cellgw image by digest", got)
		}
		if get[string](t, ctr, "livenessProbe", "httpGet", "path") != "/livez" || get[string](t, ctr, "readinessProbe", "httpGet", "path") != "/healthz" {
			t.Error("cellgw probes must use /livez for liveness and /healthz for readiness")
		}
		for _, c := range containers {
			name := get[string](t, c, "name")
			if image := get[string](t, c, "image"); !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(image) {
				t.Errorf("%s image %q is not pinned by digest", name, image)
			}
			for _, path := range [][]any{{"requests", "cpu"}, {"requests", "memory"}, {"limits", "memory"}} {
				if _, ok := lookup(c, append([]any{"resources"}, path...)...); !ok {
					t.Errorf("%s has no resources %v", name, path)
				}
			}
			csc := get[map[string]any](t, c, "securityContext")
			if csc["allowPrivilegeEscalation"] != false || csc["readOnlyRootFilesystem"] != true || !slices.Equal(get[[]any](t, csc, "capabilities", "drop"), []any{"ALL"}) {
				t.Errorf("%s securityContext is %v", name, csc)
			}
			mounts := mountPaths(c.(map[string]any))
			// The admin socket directory and the data volume belong to cellgw alone. No container mounts a token.
			for _, only := range []string{"admin", "store", "spec-key"} {
				if _, ok := mounts[only]; ok != (name == "cellgw") {
					t.Errorf("container %s mounts %s: %v, want %v", name, only, ok, name == "cellgw")
				}
			}
			for vol, path := range mounts {
				if path == "/var/run/secrets/kubernetes.io/serviceaccount" {
					t.Errorf("container %s mounts the volume %s as a service account token", name, vol)
				}
			}
		}
		m := mountPaths(ctr)
		for vol, path := range map[string]string{"admin": "/run/cellgw", "store": "/var/lib/cellgw", "spec-key": "/etc/cellgw/spec-key", "spire-agent-socket": "/run/spire/agent"} {
			if m[vol] != path {
				t.Errorf("cellgw mounts %s at %q, want %q", vol, m[vol], path)
			}
		}
		for _, v := range get[[]any](t, pod, "volumes") {
			if _, ok := lookup(v, "hostPath"); ok {
				t.Errorf("volume %v uses a host path", v)
			}
			if _, ok := lookup(v, "secret"); ok {
				t.Errorf("volume %v is a Secret volume", lookupOr(v, "name"))
			}
		}
		ann := get[map[string]any](t, sts, "spec", "template", "metadata", "annotations")
		if ann["poc.internal/spec-key-sha256"] != sha256Hex(stubMgmtKey) {
			t.Errorf("spec-key annotation is %v, want the SHA-256 of the key", ann["poc.internal/spec-key-sha256"])
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fmt.Sprint(ann["cell.poc.internal/config-checksum"])) {
			t.Errorf("config checksum annotation is %v", ann["cell.poc.internal/config-checksum"])
		}
	})

	t.Run("key ConfigMap", func(t *testing.T) {
		cm := objs["ConfigMap gateway-system/mgmt-spec-key"]
		if get[string](t, cm, "data", "spec.pub") != stubMgmtKey || get[string](t, cm, "metadata", "annotations", "poc.internal/spec-key-sha256") != sha256Hex(stubMgmtKey) {
			t.Errorf("mgmt-spec-key is %v, want the key of mgmt-signing-pub with its checksum", cm)
		}
	})

	t.Run("services", func(t *testing.T) {
		for name, tc := range map[string]struct {
			typ      string
			port, np float64
		}{
			"cell-gateway-stream": {"NodePort", 8450, 30450},
			"cell-gateway-bind":   {"NodePort", 8451, 30451},
			"cell-gateway":        {"ClusterIP", 8452, 0},
		} {
			svc := objs["Service gateway-system/"+name]
			if svc == nil {
				t.Errorf("no Service %s", name)
				continue
			}
			p := get[[]any](t, svc, "spec", "ports")
			if get[string](t, svc, "spec", "type") != tc.typ || len(p) != 1 || get[float64](t, p[0], "port") != tc.port || get[float64](t, p[0], "targetPort") != tc.port {
				t.Errorf("Service %s is %v, want %s on %v", name, svc["spec"], tc.typ, tc.port)
			}
			if tc.np != 0 {
				if get[float64](t, p[0], "nodePort") != tc.np || get[string](t, svc, "spec", "externalTrafficPolicy") != "Local" {
					t.Errorf("Service %s is %v, want node port %v with the local traffic policy", name, svc["spec"], tc.np)
				}
			}
		}
	})

	t.Run("network policies", func(t *testing.T) {
		deny := objs["NetworkPolicy gateway-system/default-deny"]
		if deny == nil || len(get[map[string]any](t, deny, "spec", "podSelector")) != 0 || len(get[[]any](t, deny, "spec", "policyTypes")) != 2 {
			t.Fatalf("default-deny is %v", deny)
		}
		dns := objs["NetworkPolicy gateway-system/allow-dns"]
		if dns == nil || get[string](t, dns, "spec", "egress", 0, "to", 1, "ipBlock", "cidr") != "10.111.0.10/32" {
			t.Errorf("allow-dns is %v, want the DNS service peer", dns)
		}
		np := objs["NetworkPolicy gateway-system/cell-gateway"]
		var ingress, egress []string
		for _, rule := range get[[]any](t, np, "spec", "ingress") {
			ingress = append(ingress, fmt.Sprintf("%s %v", peerList(t, rule, "from"), portList(t, rule)))
		}
		wantIn := []string{"10.9.0.1/32,10.9.0.2/32 [8450]", "10.9.0.1/32,10.9.0.2/32 [8451]", "envd-system/envd [8452]", "172.18.0.4/32 [8080]"}
		if !slices.Equal(ingress, wantIn) {
			t.Errorf("ingress rules are %v, want %v", ingress, wantIn)
		}
		for _, rule := range get[[]any](t, np, "spec", "egress") {
			egress = append(egress, fmt.Sprintf("%s %v", peerList(t, rule, "to"), portList(t, rule)))
		}
		wantOut := []string{"spire-system/spire-server [8081]", "observability-system/otel-collector [4317]"}
		if !slices.Equal(egress, wantOut) {
			t.Errorf("egress rules are %v, want %v", egress, wantOut)
		}
	})
}

// TestCellGatewayRenderFailsClosed gives the render a missing or wrong input. Each stops it with no output.
func TestCellGatewayRenderFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, want string
		env        []string
		images     string
	}{
		{"no node addresses", "NODE_IPS holds no address", []string{"NODE_IPS= "}, ""},
		{"a trust domain other than the environment", "is not dev.env.poc.internal", []string{"SPIRE_TRUST_DOMAIN=mgmt.poc.internal"}, ""},
		{"no key", "mgmt-signing-pub", []string{"STUB_NO_MGMT_KEY=1"}, ""},
		{"no image record", "images.env", nil, "missing"},
		{"a stale image record", "older than", nil, "stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if tc.images != "" {
				env = append(env, "STUB_IMAGES="+tc.images)
			}
			r := renderGateway(t, env...)
			if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that says %q", r.err, len(r.stdout), r.stderr, tc.want)
			}
		})
	}
}

// TestCellGatewayRenderNoLiveCells: with no cell cluster the render succeeds, passes no --cell-node, reads no cell
// facts, and prints neither the N37 rule nor the N38 rule. The envd and kubelet rules stay.
func TestCellGatewayRenderNoLiveCells(t *testing.T) {
	t.Parallel()
	r := renderGateway(t, "STUB_KIND_CLUSTERS=management dev-cp rogue")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	if strings.Contains(r.stdout, "--cell-node") {
		t.Errorf("the render passes --cell-node with no live cell:\n%s", r.stdout)
	}
	if strings.Contains(r.log, "facts --cluster dev-cell") {
		t.Errorf("the render read the facts of a cell that has no cluster:\n%s", r.log)
	}
	objs := objectsIn(t, r.stdout)
	np := objs["NetworkPolicy gateway-system/cell-gateway"]
	var ingress []string
	for _, rule := range get[[]any](t, np, "spec", "ingress") {
		ingress = append(ingress, fmt.Sprintf("%s %v", peerList(t, rule, "from"), portList(t, rule)))
	}
	if want := []string{"envd-system/envd [8452]", "172.18.0.4/32 [8080]"}; !slices.Equal(ingress, want) {
		t.Errorf("ingress rules are %v, want %v", ingress, want)
	}
	sts := objs["StatefulSet gateway-system/cell-gateway"]
	ctr := named(t, get[[]any](t, sts, "spec", "template", "spec", "containers"), "cellgw")
	for _, a := range get[[]any](t, ctr, "args") {
		if a == "" {
			t.Errorf("the cellgw args hold an empty entry: %v", get[[]any](t, ctr, "args"))
		}
	}
}

// TestCellGatewayRenderOneLiveCell: one live cell gives one --cell-node and one address in the N37 and N38 rules.
func TestCellGatewayRenderOneLiveCell(t *testing.T) {
	t.Parallel()
	r := renderGateway(t, "STUB_KIND_CLUSTERS=management dev-cp rogue dev-cell-2")
	if r.err != nil {
		t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
	}
	if strings.Count(r.stdout, "--cell-node=") != 1 || !strings.Contains(r.stdout, "--cell-node=dev-cell-2=10.9.0.2") {
		t.Errorf("the render must pass --cell-node=dev-cell-2=10.9.0.2 only:\n%s", r.stdout)
	}
	np := objectsIn(t, r.stdout)["NetworkPolicy gateway-system/cell-gateway"]
	rules := get[[]any](t, np, "spec", "ingress")
	if len(rules) != 4 || peerList(t, rules[0], "from") != "10.9.0.2/32" || peerList(t, rules[1], "from") != "10.9.0.2/32" {
		t.Errorf("ingress rules %v, want the two cell rules to admit 10.9.0.2/32", rules)
	}
}

// TestCellGatewayRenderLiveCellWithoutFacts: a live cell whose facts fail stops the render, so a read error never
// removes a cell from the admit list.
func TestCellGatewayRenderLiveCellWithoutFacts(t *testing.T) {
	t.Parallel()
	r := renderGateway(t, "STUB_FACTS_FAIL=dev-cell-2")
	if r.err == nil || r.stdout != "" || !strings.Contains(r.stderr, "no host service facts for the live cell dev-cell-2") ||
		!strings.Contains(r.stderr, "mise run hostsvc -- facts --cluster dev-cell-2") {
		t.Fatalf("err %v, stdout %d bytes, stderr %q; want a stop that names the facts command", r.err, len(r.stdout), r.stderr)
	}
}

// TestCellGatewayOperatorPin: the gateway pins the keys of operator-pub as key keys.pub of ConfigMap
// gateway-system/operator-key, and only cellgw mounts it read-only and reads it through --operator-key-file. cellgw reads the
// file at start only, so the pod template carries the SHA-256 of the pin, and a rotation restarts the pod.
func TestCellGatewayOperatorPin(t *testing.T) {
	t.Parallel()
	sums := map[string]string{}
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"one key", nil, operatorKeysPub(stubOperatorKey)},
		{"a rotation", []string{"STUB_OPERATOR_NEXT=" + stubOperatorNext}, operatorKeysPub(stubOperatorKey, stubOperatorNext)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := renderGateway(t, tc.env...)
			if r.err != nil {
				t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
			}
			objs := objectsIn(t, r.stdout)
			cm := objs["ConfigMap gateway-system/operator-key"]
			if cm == nil {
				t.Fatalf("no ConfigMap gateway-system/operator-key in %v", keysOfObjects(objs))
			}
			if data := get[map[string]any](t, cm, "data"); len(data) != 1 || data["keys.pub"] != tc.want {
				t.Errorf("operator-key holds %q, want only keys.pub %q", data, tc.want)
			}
			sts := objs["StatefulSet gateway-system/cell-gateway"]
			pod := get[map[string]any](t, sts, "spec", "template", "spec")
			args := fmt.Sprint(get[[]any](t, named(t, get[[]any](t, pod, "containers"), "cellgw"), "args"))
			if strings.Count(args, "--operator-key-file=/etc/cellgw/operator-key/keys.pub") != 1 {
				t.Errorf("cellgw args %s do not hold --operator-key-file=/etc/cellgw/operator-key/keys.pub once", args)
			}
			if v := named(t, get[[]any](t, pod, "volumes"), "operator-key"); get[string](t, v, "configMap", "name") != "operator-key" {
				t.Errorf("volume operator-key is %v, want ConfigMap operator-key", v)
			}
			for _, c := range get[[]any](t, pod, "containers") {
				name := get[string](t, c, "name")
				var got []string
				for _, m := range mountList(t, c) {
					if strings.HasPrefix(m, "operator-key=") {
						got = append(got, m)
					}
				}
				if want := map[bool][]string{true: {"operator-key=/etc/cellgw/operator-key,true"}}[name == "cellgw"]; !slices.Equal(got, want) {
					t.Errorf("container %s mounts the pin as %v, want %v", name, got, want)
				}
			}
			sum := fmt.Sprint(lookupOr(sts, "spec", "template", "metadata", "annotations", "poc.internal/operator-key-sha256"))
			if sum != sha256Hex(tc.want) {
				t.Errorf("the pod annotation poc.internal/operator-key-sha256 is %s, want the SHA-256 of keys.pub %s", sum, sha256Hex(tc.want))
			}
			sums[tc.name] = sum
		})
	}
	if sums["one key"] == sums["a rotation"] {
		t.Error("a rotation leaves the pod annotation as it was, so cellgw would keep the old keys")
	}
}
