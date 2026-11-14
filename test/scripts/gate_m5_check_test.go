package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// TestGateM5ImageCheck: gate.sh m5 compares the images of mgmtd, envd, the gateway, the SPIRE server plugin, celld in each cell and the three
// cell-proxy servers of management with build/images.env. It stops before the tests on a stale image and names the
// command that brings the workload up to date. The cell-proxy clients are not in this check: a new image of the server
// changes the digest of every user of cell-proxy, and the M3 check covers the clients.
func TestGateM5ImageCheck(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, stale, want string
	}{
		{name: "healthy"},
		{name: "a stale cell-proxy in the principal", stale: "cell-proxy@central-view-system",
			want: "Run: mise run images -- cell-proxy, then CELL=management LINK_ONLY=central-view mise run cell:link"},
		{name: "a stale cell-proxy in the telemetry gateway", stale: "cell-proxy@observability-system",
			want: "Run: mise run images -- cell-proxy, then CELL=management LINK_ONLY=telemetry-gateway mise run cell:link"},
		{name: "a stale cell-proxy in the mesh hub", stale: "cell-proxy@mesh-view-system",
			want: "Run: mise run images -- cell-proxy, then CELL=management LINK_ONLY=mesh-view-hub mise run cell:link"},
		{name: "a stale SPIRE server plugin", stale: "cluster-jwt-server@dev-cp",
			want: "Run: mise run images -- cluster-jwt-server, then CELL=dev-cp mise run cell:up"},
		{name: "a stale celld", stale: "celld@dev-cell-1", want: "Run: mise run images -- celld cluster-jwt-agent, then CELL=dev-cell-1 mise run cell:up"},
		{name: "a stale cell-proxy client in a cell is left to the M3 check", stale: "cell-proxy@argocd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range []string{"scripts", "cells", "harness"} {
				copyFiles(t, root, d)
			}
			write := func(path, body string) {
				p := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			var env strings.Builder
			for _, n := range []string{"mgmtd", "envd", "cellgw", "celld", "cluster-jwt-agent", "cluster-jwt-server", "cell-proxy"} {
				fmt.Fprintf(&env, "IMAGE_%s=localhost:5001/%s@sha256:%s\n", strings.ToUpper(strings.ReplaceAll(n, "-", "_")), n, strings.Repeat("a", 64))
			}
			write("build/images.env", env.String())
			for _, cluster := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
				write("build/"+cluster+"/facts.env", "")
			}
			write("scripts/gate-m5-repair.sh", "#!/usr/bin/env bash\nexit 0\n")
			write("bin/go", "#!/usr/bin/env bash\necho \"go $*\" >>\"$STUB_LOG\"\n")
			// The fake answers "get <workload> -o json". Each workload runs the images that build/images.env records, except
			// the one that STUB_STALE names, as <image>@<namespace> or <image>@<cluster>.
			write("bin/kubectl", `#!/usr/bin/env bash
cluster="${2#kind-}"
ns=""
for i in "$@"; do [[ "$prev" == "-n" ]] && ns="$i"; prev="$i"; done
img() { # img <name> prints the reference that the workload runs
  local c=a
  [[ "$STUB_STALE" == "$1@$ns" || "$STUB_STALE" == "$1@$cluster" ]] && c=b
  printf 'localhost:5001/%s@sha256:%s' "$1" "$(printf "$c%.0s" $(seq 64))"
}
one() { printf '{"spec":{"template":{"spec":{"containers":[{"name":"%s","image":"%s"}]}}}}\n' "$1" "$(img "$2")"; }
case " $* " in
  *" get statefulset/mgmtd "*) one mgmtd mgmtd ;;
  *" get deployment/envd "*) one envd envd ;;
  *" get statefulset/cell-gateway "*) one cell-gateway cellgw ;;
  *" get statefulset/spire-server "*) printf '{"spec":{"template":{"spec":{"initContainers":[{"name":"install-plugin","image":"%s"}],"containers":[{"name":"spire-server","image":"ghcr.io/spiffe/spire-server:1"}]}}}}\n' "$(img cluster-jwt-server)" ;;
  *" get deployment/celld "*) printf '{"spec":{"template":{"spec":{"initContainers":[{"name":"install-agent-plugin","image":"%s"}],"containers":[{"name":"celld","image":"%s"}]}}}}\n' "$(img cluster-jwt-agent)" "$(img celld)" ;;
  *" get deployment/argocd-agent-principal "*|*" get deployment/telemetry-gateway "*|*" get deployment/mesh-view-hub "*) one cell-proxy cell-proxy ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`)
			cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), "m5")
			cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_STALE=" + tc.stale}
			out, err := cmd.CombinedOutput()
			calls, _ := os.ReadFile(filepath.Join(root, "calls"))
			ran := strings.Contains(string(calls), "-run M5")
			if tc.want == "" {
				if err != nil || !ran {
					t.Fatalf("err %v, ran %v, output %s\ncalls %s", err, ran, out, calls)
				}
				return
			}
			if err == nil || ran || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err %v, tests ran %v, output %s; want a stop before the tests that says %q", err, ran, out, tc.want)
			}
		})
	}
}
