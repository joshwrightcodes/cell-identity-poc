package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// harnessOnlyRoot is a root for dev-cp with the sets spire-server and envd, and a stub render for each. The fake kubectl logs each call, and
// each apply and each pod deletion also log whether the lock of dev-cp is held.
func harnessOnlyRoot(t *testing.T) (root, calls string) {
	t.Helper()
	root, calls = harnessRoot(t)
	write := func(path, content string) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("harness/topology.yaml", "clusters:\n  - name: dev-cp\n    components: [spire-server, envd]\n")
	write("components/envd/render.sh", `#!/usr/bin/env bash
echo "render envd" >>"$STUB_LOG"
cat <<'EOF2'
apiVersion: apps/v1
kind: Deployment
metadata: {name: envd, namespace: envd-system}
EOF2
`)
	write("components/spire-server/render.sh", `#!/usr/bin/env bash
echo "render spire-server" >>"$STUB_LOG"
cat <<'EOF2'
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: spire-server, namespace: spire-system}
EOF2
`)
	write("scripts/facts.sh", "#!/usr/bin/env bash\nsource \"$(dirname \"$0\")/lib.sh\"\necho facts >>\"$STUB_LOG\"\nmkdir -p \"$BUILD\"\nprintf \"NODE_IPS='172.18.0.3'\\n\" >\"$FACTS\"\n")
	write("bin/mise", "#!/usr/bin/env bash\necho \"mise $*\" >>\"$STUB_LOG\"\nexit 0\n")
	write("bin/kubectl", `#!/usr/bin/env bash
args=" $* "
lock=free; [[ -d "$POC_BUILD_ROOT/locks/dev-cp.lock" ]] && lock=held
echo "kubectl $* | lock=$lock" >>"$STUB_LOG"
case "$args" in
  *" get -f "*) echo '{"kind":"List","items":[]}' ;;
  *" get deployments,statefulsets "*"harness=envd "*) echo deployment.apps/envd ;;
  *" get deployment.apps/envd -o json "*) echo '{"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"envd"}}}}' ;;
  *" get statefulset.apps/spire-server -o json "*) echo '{"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"spire-server"}}}}' ;;
  *" get pods -l "*" -o jsonpath"*) echo "old-uid" ;;
  *" get pods -l "*" -o json "*) echo '{"items":[{"metadata":{"uid":"new-uid"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  *" -A -l "*" -o json "*) echo '{"items":[]}' ;;
  *" get "*" -o json "*) echo '{"metadata":{}}' ;;
esac
exit 0
`)
	return root, calls
}

func runHarnessOnly(t *testing.T, root, calls, script string, env ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", script))
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cp", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + calls}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	b, _ := os.ReadFile(calls)
	return out.String(), string(b), err
}

// TestHarnessOnly: cell:up and cell:restart with HARNESS_ONLY=<component> act on that one harness component of an existing cluster.
func TestHarnessOnly(t *testing.T) {
	t.Parallel()
	t.Run("up renders, applies and waits for one component under the lock", func(t *testing.T) {
		root, calls := harnessOnlyRoot(t)
		out, log, err := runHarnessOnly(t, root, calls, "up.sh", "HARNESS_ONLY=envd")
		if err != nil {
			t.Fatalf("up.sh failed: %v\n%s\n%s", err, out, log)
		}
		if !strings.Contains(log, "render envd") || strings.Contains(log, "render spire-server") {
			t.Fatalf("calls:\n%s\nwant a render of envd only", log)
		}
		for _, bad := range []string{"hostsvc -- up", "publish", "bundle-store", "get applications", "root.yaml", "argocd"} {
			if strings.Contains(log, bad) {
				t.Errorf("HARNESS_ONLY ran %q:\n%s", bad, log)
			}
		}
		if n := strings.Count(log, "kubectl --context kind-dev-cp apply "); n != 1 {
			t.Errorf("%d applies, want the one of the component:\n%s", n, log)
		}
		if !strings.Contains(log, "apply --server-side --force-conflicts -f") || !strings.Contains(log, "| lock=held") {
			t.Errorf("the apply did not run under the lock:\n%s", log)
		}
		if !strings.Contains(log, "rollout status deployment.apps/envd") {
			t.Errorf("no wait for the rollout of envd:\n%s", log)
		}
		if !strings.Contains(log, "-A -l cell.poc.internal/harness=envd") {
			t.Errorf("no prune of the objects that left the bundle:\n%s", log)
		}
		if _, err := os.Stat(filepath.Join(root, "build", "locks", "dev-cp.lock")); err == nil {
			t.Error("the lock outlived up.sh")
		}
	})

	t.Run("up with an unknown name fails with the known names", func(t *testing.T) {
		root, calls := harnessOnlyRoot(t)
		out, log, err := runHarnessOnly(t, root, calls, "up.sh", "HARNESS_ONLY=nothing")
		if err == nil || !strings.Contains(out, "HARNESS_ONLY 'nothing' is not a harness component of dev-cp. Known: envd") || strings.Contains(log, "apply") {
			t.Fatalf("err %v, output %q, calls:\n%s", err, out, log)
		}
		// A component of a bundle is no harness component.
		if out, _, err = runHarnessOnly(t, root, calls, "up.sh", "HARNESS_ONLY=spire-server"); err == nil || !strings.Contains(out, "is not a harness component") {
			t.Fatalf("spire-server is a bundle: err %v, output %q", err, out)
		}
	})

	t.Run("up needs the cluster", func(t *testing.T) {
		root, calls := harnessOnlyRoot(t)
		out, log, err := runHarnessOnly(t, root, calls, "up.sh", "HARNESS_ONLY=envd", "STUB_KIND=management rogue")
		if err == nil || !strings.Contains(out, "HARNESS_ONLY needs the cluster dev-cp") || strings.Contains(log, "apply") || strings.Contains(log, "hostsvc") {
			t.Fatalf("err %v, output %q, calls:\n%s; want a stop that creates no cluster", err, out, log)
		}
	})

	t.Run("restart restarts one component and leaves the SPIRE server alone", func(t *testing.T) {
		root, calls := harnessOnlyRoot(t)
		if err := os.MkdirAll(filepath.Join(root, "build", "dev-cp", "bundles", "envd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "build", "dev-cp", "bundles", "envd", "manifests.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: envd, namespace: envd-system}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		out, log, err := runHarnessOnly(t, root, calls, "restart.sh", "HARNESS_ONLY=envd")
		if err != nil {
			t.Fatalf("restart.sh failed: %v\n%s\n%s", err, out, log)
		}
		if !strings.Contains(log, "-n envd-system delete pods -l app.kubernetes.io/name=envd") {
			t.Errorf("envd was not restarted:\n%s", log)
		}
		if strings.Contains(log, "spire-system") || strings.Contains(out, "SPIRE server") {
			t.Errorf("HARNESS_ONLY=envd touched the SPIRE server:\n%s\n%s", out, log)
		}
		// Without HARNESS_ONLY, the same run restarts the SPIRE server first.
		root, calls = harnessOnlyRoot(t)
		if err := os.MkdirAll(filepath.Join(root, "build", "dev-cp", "bundles", "envd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "build", "dev-cp", "bundles", "envd", "manifests.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: envd, namespace: envd-system}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, log, _ = runHarnessOnly(t, root, calls, "restart.sh"); !strings.Contains(log, "-n spire-system delete pods -l app.kubernetes.io/name=spire-server") {
			t.Errorf("a full restart skips the SPIRE server:\n%s", log)
		}
	})

	t.Run("restart with an unknown name fails", func(t *testing.T) {
		root, calls := harnessOnlyRoot(t)
		out, log, err := runHarnessOnly(t, root, calls, "restart.sh", "HARNESS_ONLY=nothing")
		if err == nil || !strings.Contains(out, "is not a harness component of dev-cp") || strings.Contains(log, "delete pods") {
			t.Fatalf("err %v, output %q, calls:\n%s", err, out, log)
		}
	})
}
