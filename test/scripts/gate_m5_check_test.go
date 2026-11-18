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
			root := newM5GateRoot(t, tc.stale)
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

// newM5GateRoot copies the scripts of the checkout into a temporary root and stubs go, the repair script and kubectl, so that gate.sh m5 runs
// its checks against workloads that run the images of build/images.env, except the one that stale names, as <image>@<namespace> or
// <image>@<cluster>. The stub of go records its arguments in the file calls.
func newM5GateRoot(t *testing.T, stale string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
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
	for _, n := range []string{"mgmtd", "envd", "cell-controller", "cellgw", "celld", "cluster-jwt-agent", "cluster-jwt-server", "cell-proxy"} {
		fmt.Fprintf(&env, "IMAGE_%s=localhost:5001/%s@sha256:%s\n", strings.ToUpper(strings.ReplaceAll(n, "-", "_")), n, strings.Repeat("a", 64))
	}
	write("build/images.env", env.String())
	for _, cluster := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
		write("build/"+cluster+"/facts.env", "")
	}
	write("scripts/gate-m5-repair.sh", "#!/usr/bin/env bash\nexit 0\n")
	write("scripts/gate-token-scan.sh", "#!/usr/bin/env bash\nexit 0\n")
	write("bin/docker", "#!/usr/bin/env bash\n[[ \"$1\" == inspect ]] && { echo 172.18.0.9; exit 0; }\n[[ \"$*\" == \"exec dev-cp-control-plane date -u +%Y-%m-%dT%H:%M:%SZ\" ]] || exit 2\necho 2026-11-16T01:02:03Z\n")
	write("bin/kind", stubKind)
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
	  *" get deployment/cell-controller "*) one cell-controller cell-controller ;;
	  *" get statefulset/cell-gateway "*) one cell-gateway cellgw ;;
	  *" get statefulset/spire-server "*) printf '{"spec":{"template":{"spec":{"initContainers":[{"name":"install-plugin","image":"%s"}],"containers":[{"name":"spire-server","image":"ghcr.io/spiffe/spire-server:1"}]}}}}\n' "$(img cluster-jwt-server)" ;;
	  *" get deployment/celld "*) printf '{"spec":{"template":{"spec":{"initContainers":[{"name":"install-agent-plugin","image":"%s"}],"containers":[{"name":"celld","image":"%s"}]}}}}\n' "$(img cluster-jwt-agent)" "$(img celld)" ;;
	  *" get deployment/argocd-agent-principal "*|*" get deployment/telemetry-gateway "*|*" get deployment/mesh-view-hub "*) one cell-proxy cell-proxy ;;
	  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
	esac
	`)
	return root
}

// TestGateM5TokenScan: after the tests, gate.sh m5, m5-soak and m5-drill run gate-token-scan.sh with the start time of the run. A
// hit fails the gate with the lines of the scan, and a clean scan leaves the result of the tests. gate.sh m4 runs no scan.
func TestGateM5TokenScan(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		milestone string
		scan      bool
		hit       bool
		pattern   string
	}{
		{milestone: "m5", scan: true, pattern: "-run M5"},
		{milestone: "m5", scan: true, hit: true, pattern: "-run M5"},
		{milestone: "m5-soak", scan: true, hit: true, pattern: "-run ^TestStreamSoakHalfHour$"},
		{milestone: "m5-drill", scan: true, hit: true, pattern: "-run ^TestGatewayVolumeLostDrill$"},
		{milestone: "m4", scan: false, pattern: "-run M4"},
	} {
		name := tc.milestone
		if tc.hit {
			name += " with a token"
		}
		t.Run(name, func(t *testing.T) {
			root := newM5GateRoot(t, "")
			if err := os.WriteFile(filepath.Join(root, "scripts", "gate-token-scan.sh"), []byte(`#!/usr/bin/env bash
echo "scan $*" >>"$STUB_LOG"
[[ -z "$STUB_HIT" ]] || { echo "a token is in the log: dev-cp ns/pod container line 7"; exit 1; }
`), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "scripts", "gate-m4-repair.sh"), []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(filepath.Join(root, "scripts", "gate.sh"), tc.milestone)
			hit := ""
			if tc.hit {
				hit = "1"
			}
			cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + filepath.Join(root, "calls"), "STUB_STALE=", "STUB_HIT=" + hit}
			out, err := cmd.CombinedOutput()
			calls, _ := os.ReadFile(filepath.Join(root, "calls"))
			if !strings.Contains(string(calls), tc.pattern) {
				t.Fatalf("the tests did not run with %q: calls %s\noutput %s", tc.pattern, calls, out)
			}
			scanned := strings.Contains(string(calls), "scan 2026-11-16T01:02:03Z")
			if scanned != tc.scan {
				t.Errorf("scan ran %v, want %v; calls %s", scanned, tc.scan, calls)
			}
			if tc.hit && (err == nil || !strings.Contains(string(out), "a token is in the log: dev-cp ns/pod container line 7") || !strings.Contains(string(out), "FAIL")) {
				t.Errorf("err %v, output %s; want a failure that holds the line of the scan", err, out)
			}
			if !tc.hit && err != nil {
				t.Errorf("err %v, output %s; want a pass", err, out)
			}
		})
	}
}
