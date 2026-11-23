package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// stageRoot copies the scripts and cell settings, and gives management only the mesh-view-hub set.
// The render of the hub prints a hub Deployment and a Kiali Deployment that waits for the tunnels.
// The fake kubectl logs each call and prints the log of the hub from STUB_HUB_LOG.
func stageRoot(t *testing.T) (root, calls string) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	root = t.TempDir()
	calls = filepath.Join(root, "calls.log")
	write := func(path, content string, mode os.FileMode) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"scripts", "cells", "components/lib"} {
		files, _ := filepath.Glob(filepath.Join("../..", dir, "*"))
		for _, f := range files {
			if info, err := os.Stat(f); err == nil && !info.IsDir() {
				b, _ := os.ReadFile(f)
				write(filepath.Join(dir, filepath.Base(f)), string(b), info.Mode())
			}
		}
	}
	write("harness/topology.yaml", "clusters:\n  - name: management\n    components: [mesh-view-hub]\n  - name: dev-cell-1\n    components: [cell-identity]\n  - name: dev-cell-2\n    components: [cell-identity]\n", 0o644)
	writeLiveStubs(t, filepath.Join(root, "bin"))
	// harness_apply waits for the registry that mgmtd publishes, before it prunes.
	for _, f := range []string{"registry.sh", "mgmt-key.sh"} {
		b, err := os.ReadFile(filepath.Join("../../components/lib", f))
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join("components/lib", f), string(b), 0o644)
	}
	write("components/mesh-view-hub/render.sh", `#!/usr/bin/env bash
cat <<'EOF2'
apiVersion: apps/v1
kind: Deployment
metadata: {name: mesh-view-hub, namespace: mesh-view-system}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kiali
  namespace: mesh-view-system
  annotations: {poc.internal/link-stage: after-tunnels}
EOF2
`, 0o755)
	write("scripts/facts.sh", "#!/usr/bin/env bash\nsource \"$(dirname \"$0\")/lib.sh\"\nmkdir -p \"$BUILD\"\nprintf \"NODE_IPS='172.18.0.3'\\n\" >\"$FACTS\"\n", 0o755)
	write("bin/mise", "#!/usr/bin/env bash\nexit 0\n", 0o755)
	write("bin/kubectl", `#!/usr/bin/env bash
args=" $* "
case "$args" in
  *" apply "*) for a in "$@"; do f="$a"; done
    echo "apply $(yq -N '.metadata.name' "$f" | paste -sd, -)" >>"$STUB_LOG" ;;
  *" rollout status "*) echo "rollout ${*: -2:1}" >>"$STUB_LOG" ;;
  *" logs "*) echo "logs" >>"$STUB_LOG"; printf '%s\n' "${STUB_HUB_LOG:-}" ;;
  *" exec "*) [[ -n "${STUB_STATUS:-}" ]] || exit 1; printf '%s\n' "$STUB_STATUS" ;;
  *" get configmap cell-registry "*) echo '{"metadata":{"labels":{"poc.internal/made-by":"mgmtd"}},"data":{"signers.pub":"k\n","dev-cell-1.dsse.json":"{}","dev-cell-2.dsse.json":"{}"}}' ;;
  *" get pod spire-server-0 "*) echo Running ;;
  *" get -f "*) echo '{"kind":"List","items":[]}' ;;
  *" get deployments,statefulsets "*) printf 'deployment.apps/kiali\ndeployment.apps/mesh-view-hub\n' ;;
  *" get job "*) ;;
  *" get "*" -o json "*) echo '{"metadata":{}}' ;;
esac
exit 0
`, 0o755)
	return root, calls
}

func runStage(t *testing.T, root, calls string, env ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "link.sh"))
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"), "CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + calls,
		"LINK_TUNNEL_WAIT=2", "LINK_TUNNEL_POLL=1"}, env...)
	out, err := cmd.CombinedOutput()
	log, _ := os.ReadFile(calls)
	return string(out), string(log), err
}

const hubLogBoth = `{"msg":"tunnel_up","cell":"dev-cell-1","conn_id":1}
{"msg":"tunnel_up","cell":"dev-cell-2","conn_id":2}`

// The link phase applies the hub first, waits until the hub logs tunnel_up for each cell, and then
// applies Kiali.
func TestLinkAppliesKialiAfterTheTunnels(t *testing.T) {
	t.Parallel()
	root, calls := stageRoot(t)
	out, log, err := runStage(t, root, calls, "STUB_HUB_LOG="+hubLogBoth)
	if err != nil {
		t.Fatalf("link.sh failed: %v\n%s\ncalls:\n%s", err, out, log)
	}
	lines := strings.Split(strings.TrimSpace(log), "\n")
	var seq []string
	for _, l := range lines {
		if strings.HasPrefix(l, "apply ") || l == "logs" || strings.HasPrefix(l, "rollout ") {
			seq = append(seq, l)
		}
	}
	want := []string{"apply mesh-view-hub", "rollout deployment/mesh-view-hub", "logs", "logs", "apply mesh-view-hub,kiali"}
	if len(seq) < len(want) || strings.Join(seq[:len(want)], "|") != strings.Join(want, "|") {
		t.Fatalf("calls:\n%s\nwant the sequence %q first", log, want)
	}
}

// A cell with no tunnel fails the link phase after the wait, names that cell only, and applies no
// Kiali. A cell whose last line is tunnel_down counts as missing.
func TestLinkNamesTheCellsWithoutATunnel(t *testing.T) {
	t.Parallel()
	for name, hubLog := range map[string]string{
		"no line":     `{"msg":"tunnel_up","cell":"dev-cell-1","conn_id":1}`,
		"tunnel down": hubLogBoth + "\n" + `{"msg":"tunnel_down","cell":"dev-cell-2","conn_id":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			root, calls := stageRoot(t)
			out, log, err := runStage(t, root, calls, "STUB_HUB_LOG="+hubLog)
			if err == nil {
				t.Fatalf("link.sh passed with a missing tunnel:\n%s", out)
			}
			if !strings.Contains(out, "no tunnel from: dev-cell-2.") || strings.Contains(out, "dev-cell-1.") {
				t.Errorf("the failure names the wrong cells:\n%s", out)
			}
			if strings.Contains(log, "kiali") {
				t.Errorf("link.sh applied Kiali without a tunnel:\n%s", log)
			}
		})
	}
}

// The new tunnel of a cell logs tunnel_up before the replaced one logs tunnel_down, so the last line of the
// cell is a tunnel_down. The cell has an open tunnel all the same, and the link phase goes on.
func TestLinkCountsAReplacedTunnelAsUp(t *testing.T) {
	t.Parallel()
	root, calls := stageRoot(t)
	log := `{"msg":"tunnel_up","cell":"dev-cell-1","conn_id":1}
{"msg":"tunnel_up","cell":"dev-cell-2","conn_id":2}
{"msg":"tunnel_up","cell":"dev-cell-1","conn_id":3}
{"msg":"tunnel_down","cell":"dev-cell-1","conn_id":1,"replaced":true}`
	if out, got, err := runStage(t, root, calls, "STUB_HUB_LOG="+log); err != nil {
		t.Fatalf("link.sh failed: %v\n%s\ncalls:\n%s", err, out, got)
	}
}

// The link phase reads the state that the hub process serves, and the log is only the fallback. A hub
// that reports a cell down stops the link phase even when its log has a tunnel_up line for the cell.
func TestLinkReadsTheStateOfTheHub(t *testing.T) {
	t.Parallel()
	both := `{"side":"hub","up":true,"cells":{"dev-cell-1":{"up":true},"dev-cell-2":{"up":true}}}`
	root, calls := stageRoot(t)
	if out, got, err := runStage(t, root, calls, "STUB_STATUS="+both); err != nil {
		t.Fatalf("link.sh failed with both cells up in the status: %v\n%s\n%s", err, out, got)
	}
	root, calls = stageRoot(t)
	one := `{"side":"hub","up":false,"cells":{"dev-cell-1":{"up":true},"dev-cell-2":{"up":false,"down_seconds":90}}}`
	out, _, err := runStage(t, root, calls, "STUB_STATUS="+one, "STUB_HUB_LOG="+hubLogBoth)
	if err == nil || !strings.Contains(out, "no tunnel from: dev-cell-2.") || strings.Contains(out, "dev-cell-1.") {
		t.Fatalf("err %v, output:\n%s\nwant a stop that names dev-cell-2 only", err, out)
	}
}
