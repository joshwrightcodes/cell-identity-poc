package scripts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// libFunc runs a function of scripts/lib.sh in the cluster CELL and returns its standard output.
func libFunc(t *testing.T, cell, call string, env ...string) (string, string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeLiveStubs(t, bin)
	cmd := exec.Command("bash", "-c", `source "$1"; `+call, "_", lib)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=" + cell, "POC_BUILD_ROOT=" + t.TempDir()}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

// TestDependentsManagementRebuild: the rebuild order of management runs the first link of mgmt-api before dev-cp and before
// each cell. A new mgmtd has no request, so the portal asks again for each live cell and waits for it, and the full link comes
// last. A cell that has no cluster is neither requested nor waited for.
func TestDependentsManagementRebuild(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want []string
	}{
		{"both cells are live", nil, []string{
			"mise run hostsvc -- up --only management",
			"CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up",
			"CELL=management LINK_ONLY=mgmt-api mise run cell:link",
			"CELL=dev-cp mise run cell:up",
			"mise run portal -- request --cell dev-cell-1 --cell dev-cell-2",
			"mise run portal -- wait --cell dev-cell-1 --cell dev-cell-2",
			"CELL=management mise run cell:link",
		}},
		{"one cell is live", []string{"STUB_KIND=management dev-cp rogue dev-cell-2"}, []string{
			"mise run hostsvc -- up --only management",
			"CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up",
			"CELL=management LINK_ONLY=mgmt-api mise run cell:link",
			"CELL=dev-cp mise run cell:up",
			"mise run portal -- request --cell dev-cell-2",
			"mise run portal -- wait --cell dev-cell-2",
			"CELL=management mise run cell:link",
		}},
		{"no cell is live", []string{"STUB_KIND=management dev-cp rogue"}, []string{
			"mise run hostsvc -- up --only management",
			"CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up",
			"CELL=management LINK_ONLY=mgmt-api mise run cell:link",
			"CELL=dev-cp mise run cell:up",
			"CELL=management mise run cell:link",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, err := libFunc(t, "management", "dependents_of management", tc.env...)
			if err != nil {
				t.Fatalf("dependents_of management: %v\n%s", err, errOut)
			}
			if got := strings.Split(strings.TrimSpace(out), "\n"); !slices.Equal(got, tc.want) {
				t.Fatalf("order\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			link := slices.Index(lines, "CELL=management LINK_ONLY=mgmt-api mise run cell:link")
			if devcp := slices.Index(lines, "CELL=dev-cp mise run cell:up"); link < 0 || devcp < link {
				t.Errorf("the link of mgmt-api (%d) must come before the cell:up of dev-cp (%d)", link, devcp)
			}
			for _, l := range lines {
				if strings.Contains(l, "bound") || strings.Contains(l, "attest") || strings.Contains(l, "CELL=dev-cell-") {
					t.Errorf("step %q waits for a bind or runs cell:up of a cell: a cell exists only through its step", l)
				}
			}
		})
	}
}

// TestDependentsCellRebuild: a lost or rebuilt cell goes through cell:down (while its cluster exists), a portal recreate
// that waits, and the management link. A cell that must be created first goes through the portal too.
func TestDependentsCellRebuild(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"the cluster exists", nil, "CELL=dev-cell-1 mise run cell:down\nmise run portal -- recreate --cell dev-cell-1 --wait\nCELL=management mise run cell:link"},
		{"the cluster is gone", []string{"STUB_KIND=management dev-cp rogue dev-cell-2"}, "mise run portal -- recreate --cell dev-cell-1 --wait\nCELL=management mise run cell:link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, err := libFunc(t, "management", "dependents_of dev-cell-1", tc.env...)
			if err != nil || strings.TrimSpace(out) != tc.want {
				t.Fatalf("err %v, output %q, stderr %q; want %q", err, out, errOut, tc.want)
			}
		})
	}
}

// dependents_of dev-cp links mgmt-api again right after the cell:up of dev-cp and before the cells, because mgmtd
// admits envd by the dev-cp root and the node address. It names the live cells only.
func TestDependentsOfOtherChanges(t *testing.T) {
	for call, want := range map[string]string{
		"dependents_of hostsvc":       "mise run hostsvc:serve -- restart",
		"dependents_of gateway-nodes": "CELL=dev-cp mise run cell:up",
		"dependents_of gateway-store": "mise run gw:reset",
		"dependents_of dev-cp":        "CELL=dev-cp mise run cell:up\nCELL=management LINK_ONLY=mgmt-api mise run cell:link\nCELL=dev-cell-1 mise run cell:up\nCELL=dev-cell-2 mise run cell:up\nCELL=dev-cell-1 mise run cell:restart\nCELL=dev-cell-2 mise run cell:restart\nCELL=management mise run cell:link",
	} {
		out, errOut, err := libFunc(t, "management", call)
		if err != nil || strings.TrimSpace(out) != want {
			t.Errorf("%s: err %v, output %q, stderr %q; want %q", call, err, out, errOut, want)
		}
	}
	out, errOut, err := libFunc(t, "management", "dependents_of dev-cp", "STUB_KIND=management dev-cp rogue dev-cell-1")
	if want := "CELL=dev-cp mise run cell:up\nCELL=management LINK_ONLY=mgmt-api mise run cell:link\nCELL=dev-cell-1 mise run cell:up\nCELL=dev-cell-1 mise run cell:restart\nCELL=management mise run cell:link"; err != nil || strings.TrimSpace(out) != want {
		t.Errorf("dependents_of dev-cp with one live cell: err %v, output %q, stderr %q; want %q", err, out, errOut, want)
	}
	if _, errOut, err := libFunc(t, "management", "dependents_of rogue"); err == nil || !strings.Contains(errOut, "dependents_of knows") {
		t.Errorf("an unknown cluster: err %v, stderr %q", err, errOut)
	}
}

// harnessRoot copies the scripts, cell settings and topology, and puts a fake mise in front. The fake logs
// each call with the settings of the step, and fails the step that STUB_FAIL_AT names as
// <CELL>/<task>/<LINK_ONLY>.
func harnessRoot(t *testing.T) (root, calls string) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	root = t.TempDir()
	calls = filepath.Join(root, "calls.log")
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	writeLiveStubs(t, filepath.Join(root, "bin"))
	write := func(path, content string) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("bin/mise", `#!/usr/bin/env bash
echo "mise $* | CELL=${CELL:-} LINK_ONLY=${LINK_ONLY:-} SKIP=${CELL_UP_SKIP_LINK:-}" >>"$STUB_LOG"
[[ "${CELL:-}/$2/${LINK_ONLY:-}" != "${STUB_FAIL_AT:-none}" ]] || exit 1
`)
	write("bin/hostsvc-serve", "#!/usr/bin/env bash\necho \"hostsvc-serve $*\" >>\"$STUB_LOG\"\n")
	return root, calls
}

func runHarness(t *testing.T, root, calls, verb string, env ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "harness.sh"), verb)
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + calls, "HOSTSVC_SERVE=" + filepath.Join(root, "bin", "hostsvc-serve")}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	log, _ := os.ReadFile(calls)
	return string(log), errOut.String(), err
}

// harness:up follows the rebuild order: the first link of mgmt-api comes right after the cell:up of
// management, before dev-cp. The second comes right after the cell:up of dev-cp, with the dev-cp root.
// harness:down stops the host service last.
func TestHarnessUpOrderAndDown(t *testing.T) {
	root, calls := harnessRoot(t)
	log, errOut, err := runHarness(t, root, calls, "up")
	if err != nil {
		t.Fatalf("harness up failed: %v\n%s", err, errOut)
	}
	want := []string{
		"mise run hostsvc -- up | CELL=dev-cell-1 LINK_ONLY= SKIP=",
		"mise run images | CELL=dev-cell-1 LINK_ONLY= SKIP=",
		"mise run cell:up | CELL=management LINK_ONLY= SKIP=1",
		"mise run cell:link | CELL=management LINK_ONLY=mgmt-api SKIP=",
		"mise run cell:up | CELL=dev-cp LINK_ONLY= SKIP=",
		"mise run cell:link | CELL=management LINK_ONLY=mgmt-api SKIP=",
		"mise run cell:up | CELL=dev-cell-1 LINK_ONLY= SKIP=",
		"mise run cell:up | CELL=dev-cell-2 LINK_ONLY= SKIP=",
		"mise run cell:link | CELL=management LINK_ONLY= SKIP=",
	}
	if got := strings.Split(strings.TrimSpace(log), "\n"); !slices.Equal(got, want) {
		t.Fatalf("calls\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	root, calls = harnessRoot(t)
	log, errOut, err = runHarness(t, root, calls, "down")
	if err != nil {
		t.Fatalf("harness down failed: %v\n%s", err, errOut)
	}
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) != 2 || lines[0] != "hostsvc-serve stop" || !strings.HasPrefix(lines[1], "mise run hostsvc -- down") {
		t.Fatalf("down calls\n%s\nwant hostsvc-serve stop first, then hostsvc down", log)
	}
	// TestHarnessDownStopsHostFirst: the host service runs the steps that create and admit cells, so it stops before any
	// cluster goes, and a failed stop leaves the clusters alone.
	t.Run("TestHarnessDownStopsHostFirst", func(t *testing.T) {
		root, calls := harnessRoot(t)
		failing := filepath.Join(root, "bin", "hostsvc-serve-fails")
		if err := os.WriteFile(failing, []byte("#!/usr/bin/env bash\necho \"hostsvc-serve $*\" >>\"$STUB_LOG\"\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		log, _, err := runHarness(t, root, calls, "down", "HOSTSVC_SERVE="+failing)
		if err == nil || strings.Contains(log, "hostsvc -- down") || !strings.HasPrefix(log, "hostsvc-serve stop") {
			t.Fatalf("err %v, calls\n%s\nwant a stop that fails first, and no cluster deleted after it", err, log)
		}
	})
}

// TestHarnessUpHintListsAllSteps: a step that fails prints that step and every later one, the LINK_ONLY steps
// included.
func TestHarnessUpHintListsAllSteps(t *testing.T) {
	all := []string{
		"CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up",
		"CELL=management LINK_ONLY=mgmt-api mise run cell:link",
		"CELL=dev-cp mise run cell:up",
		"CELL=management LINK_ONLY=mgmt-api mise run cell:link",
		"CELL=dev-cell-1 mise run cell:up",
		"CELL=dev-cell-2 mise run cell:up",
		"CELL=management mise run cell:link",
	}
	for failAt, from := range map[string]int{"management/cell:up/": 0, "management/cell:link/mgmt-api": 1, "dev-cp/cell:up/": 2, "dev-cell-2/cell:up/": 5} {
		t.Run(failAt, func(t *testing.T) {
			root, calls := harnessRoot(t)
			_, errOut, err := runHarness(t, root, calls, "up", "STUB_FAIL_AT="+failAt)
			if err == nil {
				t.Fatal("harness up passed with a failing step")
			}
			_, hint, ok := strings.Cut(errOut, "Fix the cause, then run these commands in this order:\n")
			if !ok {
				t.Fatalf("no hint in\n%s", errOut)
			}
			var got []string
			for _, l := range strings.Split(strings.TrimSpace(hint), "\n") {
				got = append(got, strings.TrimSpace(l))
			}
			if !slices.Equal(got, all[from:]) {
				t.Fatalf("hint\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(all[from:], "\n"))
			}
		})
	}
}

// linkOnlyRoot gives management the sets mgmt-plane and central-view, with a stub render for each. The
// fake kubectl logs each apply and each rollout wait, and fails the apply of the bundle named in STUB_FAIL_APPLY.
func linkOnlyRoot(t *testing.T) (root, calls string) {
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
	write("harness/topology.yaml", "clusters:\n  - name: management\n    components: [mgmt-plane, central-view]\n")
	write("components/mgmt-api/render.sh", `#!/usr/bin/env bash
echo "render mgmt-api" >>"$STUB_LOG"
cat <<'EOF2'
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: mgmtd, namespace: mgmt-system}
EOF2
`)
	write("components/central-view/render.sh", `#!/usr/bin/env bash
echo "render central-view" >>"$STUB_LOG"
cat <<'EOF2'
apiVersion: apps/v1
kind: Deployment
metadata: {name: central-view, namespace: central-view-system}
EOF2
`)
	write("scripts/facts.sh", "#!/usr/bin/env bash\nsource \"$(dirname \"$0\")/lib.sh\"\nmkdir -p \"$BUILD\"\nprintf \"NODE_IPS='172.18.0.3'\\n\" >\"$FACTS\"\n")
	write("bin/mise", "#!/usr/bin/env bash\nexit 0\n")
	write("bin/kubectl", `#!/usr/bin/env bash
args=" $* "
echo "kubectl $*" >>"$STUB_LOG"
case "$args" in
  *" get pod spire-server-0 "*) echo Running ;;
  *" apply "*) for a in "$@"; do f="$a"; done
    [[ -z "${STUB_FAIL_APPLY:-}" ]] || ! grep -q "$STUB_FAIL_APPLY" "$f" || exit 1 ;;
  *" get -f "*) echo '{"kind":"List","items":[]}' ;;
  *" get deployments,statefulsets "*"harness=mgmt-api "*) echo statefulset.apps/mgmtd ;;
  *" get deployments,statefulsets "*"harness=central-view "*) echo deployment.apps/central-view ;;
  *" get job "*) ;;
  *" get "*" -o json "*) echo '{"metadata":{}}' ;;
esac
exit 0
`)
	return root, calls
}

func runLink(t *testing.T, root, calls string, env ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "link.sh"))
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + calls}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	log, _ := os.ReadFile(calls)
	return out.String(), string(log), err
}

// TestLinkOnly: LINK_ONLY=mgmt-api renders and applies that entry only, runs no check of the other clusters, and
// waits for the rollout of its StatefulSet. An unknown name fails. A full link that stops after mgmt-api prints
// the commands of the failed component and the later ones only.
func TestLinkOnly(t *testing.T) {
	t.Run("one component, no preflight, a StatefulSet wait", func(t *testing.T) {
		root, calls := linkOnlyRoot(t)
		// With no dev-cp server, the full link phase stops in link_preflight. LINK_ONLY=mgmt-api does not.
		out, log, err := runLink(t, root, calls, "LINK_ONLY=mgmt-api")
		if err != nil {
			t.Fatalf("link.sh failed: %v\n%s\n%s", err, out, log)
		}
		if strings.Contains(log, "render central-view") || !strings.Contains(log, "render mgmt-api") {
			t.Fatalf("calls:\n%s\nwant a render of mgmt-api only", log)
		}
		if !strings.Contains(log, "rollout status statefulset.apps/mgmtd") || strings.Contains(log, "central-view-system") {
			t.Fatalf("calls:\n%s\nwant the wait for statefulset.apps/mgmtd and nothing of central-view", log)
		}
		if strings.Contains(log, "spire-server-0") {
			t.Fatalf("calls:\n%s\nLINK_ONLY=mgmt-api must not check the SPIRE server of dev-cp", log)
		}
	})
	t.Run("an unknown name", func(t *testing.T) {
		root, calls := linkOnlyRoot(t)
		out, log, err := runLink(t, root, calls, "LINK_ONLY=nothing")
		if err == nil || !strings.Contains(out, "LINK_ONLY 'nothing' is not a link component of management. Known: mgmt-api central-view") || strings.Contains(log, "apply") {
			t.Fatalf("err %v, output %q, calls:\n%s", err, out, log)
		}
		root, calls = linkOnlyRoot(t)
		_, log, err = runLink(t, root, calls, "LINK_ONLY=nothing", "HYDRATE_ONLY=link")
		if err == nil || strings.Contains(log, "render") {
			t.Fatalf("link.sh rendered with an unknown LINK_ONLY: %v\n%s", err, log)
		}
	})
	t.Run("a failure after mgmt-api hints at the later components only", func(t *testing.T) {
		root, calls := linkOnlyRoot(t)
		out, log, err := runLink(t, root, calls, "STUB_FAIL_APPLY=central-view")
		if err == nil {
			t.Fatalf("link.sh passed though the apply of central-view fails:\n%s", log)
		}
		if !strings.Contains(log, "rollout status statefulset.apps/mgmtd") {
			t.Fatalf("mgmt-api did not finish before the failure:\n%s", log)
		}
		if !strings.Contains(out, "CELL=management LINK_ONLY=central-view mise run cell:link") || strings.Contains(out, "LINK_ONLY=mgmt-api") {
			t.Fatalf("output:\n%s\nwant a hint for central-view and none for mgmt-api", out)
		}
		root, calls = linkOnlyRoot(t)
		out, _, err = runLink(t, root, calls, "STUB_FAIL_APPLY=mgmtd")
		if err == nil || !strings.Contains(out, "LINK_ONLY=mgmt-api mise run cell:link") || !strings.Contains(out, "LINK_ONLY=central-view mise run cell:link") {
			t.Fatalf("err %v, output:\n%s\nwant a hint for mgmt-api and for central-view", err, out)
		}
	})
}

// TestLinkOnlyHydrate: HYDRATE_ONLY=link with LINK_ONLY renders only the named link component.
func TestLinkOnlyHydrate(t *testing.T) {
	root, calls := linkOnlyRoot(t)
	cmd := exec.Command(filepath.Join(root, "scripts", "hydrate.sh"))
	cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + calls, "HYDRATE_ONLY=link", "LINK_ONLY=mgmt-api"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hydrate failed: %v\n%s", err, out)
	}
	log, _ := os.ReadFile(calls)
	if strings.TrimSpace(string(log)) != "render mgmt-api" {
		t.Fatalf("calls %q, want a render of mgmt-api only", log)
	}
}

// TestRestartCoversTheStatefulSet: cell:restart of management restarts StatefulSet mgmtd, because mgmt-api
// is a link component and restart.sh restarts every workload of each link component. A new pod makes a new
// nonce key.
func TestRestartCoversTheStatefulSet(t *testing.T) {
	root, calls := linkOnlyRoot(t)
	// The harness, not the test, makes the objects of the bundle. The fake kubectl answers the label query and
	// the pod queries that restart.sh makes.
	if err := os.WriteFile(filepath.Join(root, "bin", "kubectl"), []byte(`#!/usr/bin/env bash
args=" $* "
echo "kubectl $*" >>"$STUB_LOG"
case "$args" in
  *" get deployments,statefulsets "*"harness=mgmt-api "*) echo statefulset.apps/mgmtd ;;
  *" get deployments,statefulsets "*"harness=central-view "*) echo deployment.apps/central-view ;;
  *" get statefulset.apps/mgmtd -o json "*|*" get deployment.apps/central-view -o json "*) echo '{"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"x"}}}}' ;;
  *" get pods -l "*" -o jsonpath"*) echo "old-uid" ;;
  *" get pods -l "*" -o json "*) echo '{"items":[{"metadata":{"uid":"new-uid"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
esac
exit 0
`), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; mkdir -p "$BUNDLES/mgmt-api" "$BUNDLES/central-view"
printf 'apiVersion: apps/v1\nkind: StatefulSet\nmetadata: {name: mgmtd, namespace: mgmt-system}\n' >"$BUNDLES/mgmt-api/manifests.yaml"
printf 'apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: central-view, namespace: central-view-system}\n' >"$BUNDLES/central-view/manifests.yaml"
exec "$1/scripts/restart.sh"`, "_", root)
	cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + calls}
	out, err := cmd.CombinedOutput()
	log, _ := os.ReadFile(calls)
	if err != nil {
		t.Fatalf("restart.sh failed: %v\n%s\n%s", err, out, log)
	}
	if !strings.Contains(string(log), "-n mgmt-system delete pods -l app.kubernetes.io/name=x") || !strings.Contains(string(out), "restarted statefulset.apps/mgmtd in mgmt-system") {
		t.Fatalf("output:\n%s\ncalls:\n%s\nwant the pods of statefulset mgmtd deleted and restarted", out, log)
	}
}

// fakeImagesKo prints a reference for each path that it gets, and logs the arguments.
const fakeImagesKo = `#!/usr/bin/env bash
echo "ko $*" >>"$STUB_LOG"
for a in "$@"; do
  case "$a" in
    ./cmd/*) n="${a#./cmd/}"; printf '%s/%s@sha256:%064d\n' "$KO_DOCKER_REPO" "$n" "${STUB_DIGEST:-1}" ;;
  esac
done
`

// TestImagesNamed: images.sh with names builds only those images and replaces only their lines of
// build/images.env. With no name, it builds every image.
func TestImagesNamed(t *testing.T) {
	testtool.Need(t, "bash", "git")
	root := t.TempDir()
	copyFiles(t, root, "scripts")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "ko"), []byte(fakeImagesKo), 0o755); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(root, "calls.log")
	run := func(digest string, args ...string) (string, error) {
		cmd := exec.Command(filepath.Join(root, "scripts", "images.sh"), args...)
		cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
			"KO_DOCKER_REPO=localhost:5001", "STUB_LOG=" + logFile, "STUB_DIGEST=" + digest}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// With no name, every image is built and recorded.
	if out, err := run("1"); err != nil {
		t.Fatalf("images.sh failed: %v\n%s", err, out)
	}
	envFile := filepath.Join(root, "build", "images.env")
	before, _ := os.ReadFile(envFile)
	log, _ := os.ReadFile(logFile)
	for _, name := range []string{"netprobe", "celld", "relay", "mgmtd", "envd", "cell-controller", "cellgw"} {
		if !strings.Contains(string(log), "./cmd/"+name) || !strings.Contains(string(before), "IMAGE_"+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))+"=localhost:5001/"+name+"@sha256:") {
			t.Fatalf("a full build lacks %s\ncalls: %s\nimages.env:\n%s", name, log, before)
		}
	}
	_ = os.Remove(logFile)
	// With a name, one image is built, and one line changes.
	if out, err := run("2", "mgmtd"); err != nil {
		t.Fatalf("images.sh mgmtd failed: %v\n%s", err, out)
	}
	log, _ = os.ReadFile(logFile)
	if strings.Count(string(log), "./cmd/") != 1 || !strings.Contains(string(log), "./cmd/mgmtd") {
		t.Fatalf("ko calls %q, want one image: mgmtd", log)
	}
	after, _ := os.ReadFile(envFile)
	var changed []string
	oldLines, newLines := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	if len(oldLines) != len(newLines) {
		t.Fatalf("the file has %d lines, was %d:\n%s", len(newLines), len(oldLines), after)
	}
	for i := range oldLines {
		if oldLines[i] != newLines[i] && !strings.HasPrefix(newLines[i], "# commit") {
			changed = append(changed, newLines[i])
		}
	}
	if len(changed) != 1 || !strings.HasPrefix(changed[0], "IMAGE_MGMTD=localhost:5001/mgmtd@sha256:0000") || !strings.HasSuffix(changed[0], "2") {
		t.Fatalf("changed lines %v, want only IMAGE_MGMTD with the new digest", changed)
	}
	// A partial build keeps the commit line of the file. A build of every image writes a new one.
	if err := os.WriteFile(envFile, []byte("# commit abc123\n"+string(after)[strings.Index(string(after), "\n")+1:]), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := run("5", "mgmtd", "celld"); err != nil {
		t.Fatalf("images.sh mgmtd celld failed: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(envFile); !strings.HasPrefix(string(got), "# commit abc123\n") {
		t.Fatalf("a partial build rewrote the commit line:\n%s", got)
	}
	allNames := strings.Fields("netprobe cluster-jwt-server cluster-jwt-agent celld attestprobe cell-proxy viewkeys relay mgmtd envd cell-controller cellgw")
	if out, err := run("6", allNames...); err != nil {
		t.Fatalf("images.sh with every name failed: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(envFile); strings.HasPrefix(string(got), "# commit abc123") {
		t.Fatalf("a build of every image kept the old commit line:\n%s", got)
	}
	after, _ = os.ReadFile(envFile)
	// An unknown name and a missing file fail, and the file stays as it is.
	if out, err := run("3", "nothing"); err == nil || !strings.Contains(out, "unknown image 'nothing'") {
		t.Fatalf("err %v, output %q", err, out)
	}
	if now, _ := os.ReadFile(envFile); string(now) != string(after) {
		t.Fatal("a failed run changed build/images.env")
	}
	if err := os.Remove(envFile); err != nil {
		t.Fatal(err)
	}
	if out, err := run("4", "mgmtd"); err == nil || !strings.Contains(out, "no ") {
		t.Fatalf("a named build with no images.env: err %v, output %q", err, out)
	}
}

// harnessAPI is a fake API server for one StatefulSet mgmtd in Namespace mgmt-system. It serves the discovery that
// kubectl needs, the object and its scale subresource, and the Namespace. A merge patch of the scale subresource
// changes spec.replicas only, takes the field from the field manager kubectl, and records the new manager as the
// API server does.
type harnessAPI struct {
	mu       sync.Mutex
	sts, ns  map[string]any
	requests []string
	ln       net.Listener
}

func newHarnessAPI(t *testing.T) *harnessAPI {
	t.Helper()
	labels := map[string]any{"cell.poc.internal/harness": "mgmt-api"}
	apply := func(fields map[string]any) map[string]any {
		return map[string]any{"manager": "kubectl", "operation": "Apply", "apiVersion": "apps/v1", "fieldsType": "FieldsV1", "fieldsV1": fields}
	}
	a := &harnessAPI{
		sts: map[string]any{
			"apiVersion": "apps/v1", "kind": "StatefulSet",
			"metadata": map[string]any{"name": "mgmtd", "namespace": "mgmt-system", "labels": labels, "managedFields": []any{
				apply(map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}, "f:selector": map[string]any{}, "f:template": map[string]any{}}})}},
			"spec": map[string]any{"replicas": 1, "selector": map[string]any{"matchLabels": map[string]any{"app.kubernetes.io/name": "mgmtd"}},
				"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app.kubernetes.io/name": "mgmtd"}},
					"spec": map[string]any{"containers": []any{map[string]any{"name": "mgmtd", "image": "x@sha256:1"}}}}},
		},
		ns: map[string]any{"apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]any{"name": "mgmt-system", "labels": labels, "managedFields": []any{apply(map[string]any{"f:metadata": map[string]any{}})}}},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a.ln = ln
	srv := &http.Server{Handler: http.HandlerFunc(a.serve)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return a
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (a *harnessAPI) scale() map[string]any {
	spec := a.sts["spec"].(map[string]any)
	return map[string]any{"apiVersion": "autoscaling/v1", "kind": "Scale",
		"metadata": map[string]any{"name": "mgmtd", "namespace": "mgmt-system"},
		"spec":     map[string]any{"replicas": spec["replicas"]}, "status": map[string]any{"replicas": spec["replicas"], "selector": "app.kubernetes.io/name=mgmtd"}}
}

func (a *harnessAPI) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, r.Method+" "+r.URL.RequestURI())
	const sts = "/apis/apps/v1/namespaces/mgmt-system/statefulsets"
	switch {
	case r.URL.Path == "/api":
		writeJSON(w, map[string]any{"kind": "APIVersions", "versions": []string{"v1"}})
	case r.URL.Path == "/apis":
		gv := map[string]any{"groupVersion": "apps/v1", "version": "v1"}
		writeJSON(w, map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{
			map[string]any{"name": "apps", "versions": []any{gv}, "preferredVersion": gv}}})
	case r.URL.Path == "/api/v1":
		writeJSON(w, map[string]any{"kind": "APIResourceList", "groupVersion": "v1", "resources": []any{
			map[string]any{"name": "namespaces", "singularName": "namespace", "namespaced": false, "kind": "Namespace", "verbs": []string{"get", "list"}}}})
	case r.URL.Path == "/apis/apps/v1":
		writeJSON(w, map[string]any{"kind": "APIResourceList", "groupVersion": "apps/v1", "resources": []any{
			map[string]any{"name": "statefulsets", "singularName": "statefulset", "namespaced": true, "kind": "StatefulSet", "verbs": []string{"get", "list", "patch"}},
			map[string]any{"name": "statefulsets/scale", "singularName": "", "namespaced": true, "group": "autoscaling", "version": "v1", "kind": "Scale", "verbs": []string{"get", "patch"}}}})
	case r.URL.Path == sts:
		writeJSON(w, map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSetList", "items": []any{a.sts}})
	case r.URL.Path == sts+"/mgmtd":
		writeJSON(w, a.sts)
	case r.URL.Path == sts+"/mgmtd/scale" && r.Method == http.MethodGet:
		writeJSON(w, a.scale())
	case r.URL.Path == sts+"/mgmtd/scale" && r.Method == http.MethodPatch:
		body, _ := io.ReadAll(r.Body)
		var patch struct {
			Spec map[string]any `json:"spec"`
		}
		if r.Header.Get("Content-Type") != "application/merge-patch+json" || r.URL.Query().Get("fieldManager") != "harness-replicas" ||
			json.Unmarshal(body, &patch) != nil || len(patch.Spec) != 1 || patch.Spec["replicas"] == nil {
			http.Error(w, fmt.Sprintf("unexpected patch %s %q %s", r.Header.Get("Content-Type"), r.URL.RawQuery, body), http.StatusBadRequest)
			return
		}
		a.sts["spec"].(map[string]any)["replicas"] = patch.Spec["replicas"]
		meta := a.sts["metadata"].(map[string]any)
		var kept []any
		for _, e := range meta["managedFields"].([]any) {
			m := e.(map[string]any)
			if m["manager"] == "harness-replicas" {
				continue
			}
			if m["manager"] == "kubectl" {
				delete(m["fieldsV1"].(map[string]any)["f:spec"].(map[string]any), "f:replicas")
			}
			kept = append(kept, m)
		}
		meta["managedFields"] = append(kept, map[string]any{"manager": "harness-replicas", "operation": "Update", "apiVersion": "autoscaling/v1",
			"subresource": "scale", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}})
		writeJSON(w, a.scale())
	case r.URL.Path == "/api/v1/namespaces":
		writeJSON(w, map[string]any{"apiVersion": "v1", "kind": "NamespaceList", "items": []any{a.ns}})
	case r.URL.Path == "/api/v1/namespaces/mgmt-system":
		writeJSON(w, a.ns)
	default:
		http.NotFound(w, r)
	}
}

func (a *harnessAPI) replicas() any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sts["spec"].(map[string]any)["replicas"]
}

// specField returns the JSON of one field under spec, read while the server is not writing.
func (a *harnessAPI) specField(name string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, _ := json.Marshal(a.sts["spec"].(map[string]any)[name])
	return string(b)
}

func (a *harnessAPI) requestLog() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.requests, "\n")
}

func (a *harnessAPI) managers() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.sts["metadata"].(map[string]any)["managedFields"].([]any) {
		m := e.(map[string]any)
		out = append(out, fmt.Sprintf("%s/%s/%v", m["manager"], m["operation"], m["subresource"]))
	}
	return out
}

const replicasBundle = `apiVersion: v1
kind: Namespace
metadata:
  name: mgmt-system
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mgmtd
  namespace: mgmt-system
`

// TestHarnessReplicasKeepsFields runs scripts/harness-replicas.sh with the real kubectl against a fake API
// server. After the replicas go to 0 and back to 1, the object keeps its selector and template, its managers are
// kubectl (Apply) and harness-replicas (Update, scale), and check_harness_objects passes. A harness-replicas entry
// that owns another field fails the check.
func TestHarnessReplicasKeepsFields(t *testing.T) {
	testtool.Need(t, "kubectl", "yq", "jq", "bash")
	api := newHarnessAPI(t)
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "kubeconfig")
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
  - name: fake
    cluster: {server: "http://%s"}
users:
  - name: fake
    user: {}
contexts:
  - name: kind-management
    context: {cluster: fake, user: fake}
current-context: kind-management
`, api.ln.Addr())
	if err := os.WriteFile(kubeconfig, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	bundleDir := filepath.Join(dir, "build", "management", "bundles", "mgmt-api")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "manifests.yaml"), []byte(replicasBundle), 0o644); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../scripts/harness-replicas.sh")
	if err != nil {
		t.Fatal(err)
	}
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "KUBECONFIG=" + kubeconfig, "KUBECACHEDIR=" + filepath.Join(dir, "cache"),
		"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(dir, "build")}
	scale := func(n string) {
		t.Helper()
		cmd := exec.Command(script, "management", "mgmt-system", "statefulset/mgmtd", n)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("harness-replicas.sh %s failed: %v\n%s\nrequests:\n%s", n, err, out, api.requestLog())
		}
	}
	check := func() (string, error) {
		cmd := exec.Command("bash", "-c", `source "$1"; check_harness_objects mgmt-api mgmt-system`, "_", lib)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	wantSpec, wantSelector := api.specField("template"), api.specField("selector")
	if out, err := check(); err != nil {
		t.Fatalf("the check fails before any change: %v\n%s", err, out)
	}
	for _, n := range []string{"0", "1"} {
		scale(n)
		if fmt.Sprint(api.replicas()) != n {
			t.Fatalf("replicas %v, want %s", api.replicas(), n)
		}
		tmpl, sel := api.specField("template"), api.specField("selector")
		if tmpl != wantSpec || sel != wantSelector {
			t.Fatalf("the object lost its template or selector:\n%s\n%s", tmpl, sel)
		}
		if got := api.managers(); !slices.Equal(got, []string{"kubectl/Apply/<nil>", "harness-replicas/Update/scale"}) {
			t.Fatalf("managers %v, want kubectl Apply and harness-replicas Update scale", got)
		}
		if out, err := check(); err != nil {
			t.Fatalf("check_harness_objects fails after replicas %s: %v\n%s", n, err, out)
		}
	}
	// An entry that owns more than spec.replicas, or another subresource, is a change by a person.
	for name, entry := range map[string]map[string]any{
		"another field": {"manager": "harness-replicas", "operation": "Update", "subresource": "scale",
			"fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}, "f:template": map[string]any{}}}},
		"no subresource": {"manager": "harness-replicas", "operation": "Update",
			"fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}},
		"an apply": {"manager": "harness-replicas", "operation": "Apply", "subresource": "scale",
			"fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}},
	} {
		api.mu.Lock()
		meta := api.sts["metadata"].(map[string]any)
		good := meta["managedFields"]
		meta["managedFields"] = []any{good.([]any)[0], entry}
		api.mu.Unlock()
		out, err := check()
		if err == nil || !strings.Contains(out, "has the field manager harness-replicas") {
			t.Errorf("%s: err %v, output %q; want a failure that names the manager", name, err, out)
		}
		api.mu.Lock()
		meta["managedFields"] = good
		api.mu.Unlock()
	}
	// The script stops on bad arguments.
	for _, args := range [][]string{{"management", "mgmt-system", "statefulset/mgmtd"}, {"management", "mgmt-system", "statefulset/mgmtd", "one"}, {"management", "mgmt-system", "mgmtd", "1"}} {
		cmd := exec.Command(script, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "harness-replicas:") {
			t.Errorf("harness-replicas.sh %v: err %v, output %q", args, err, out)
		}
	}
}

// signingKubectl serves ConfigMaps of mgmt-system. The bundle holds ConfigMap mgmt-intent. The fake lists
// mgmt-signing-pub as written by mgmtd, with the marker label when STUB_MARKER=1.
const signingKubectl = `#!/usr/bin/env bash
set -euo pipefail
args=" $* "
own='"labels":{"cell.poc.internal/harness":"mgmt-api"},"managedFields":[{"manager":"kubectl","operation":"Apply"}]'
case "$args" in
  *" -n mgmt-system get ConfigMap -o json --show-managed-fields "*)
    labels='"cell.poc.internal/harness":"mgmt-api"'
    [[ -z "${STUB_MARKER:-}" ]] || labels+=',"poc.internal/made-by":"mgmtd"'
    echo "{\"items\":[{\"metadata\":{\"name\":\"mgmt-intent\",$own}},{\"metadata\":{\"name\":\"mgmt-signing-pub\",\"labels\":{$labels},\"managedFields\":[{\"manager\":\"${STUB_MANAGER:-mgmtd}\",\"operation\":\"Update\"}]}},{\"metadata\":{\"name\":\"kube-root-ca.crt\",\"managedFields\":[{\"manager\":\"kube-controller-manager\",\"operation\":\"Update\"}]}}]}" ;;
  *" get Namespace -l cell.poc.internal/harness=mgmt-api -o json --show-managed-fields "*)
    echo "{\"items\":[{\"metadata\":{\"name\":\"mgmt-system\",$own}}]}" ;;
  *" get namespace mgmt-system -o json --show-managed-fields "*)
    echo "{\"metadata\":{\"name\":\"mgmt-system\",$own}}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

const signingBundle = `apiVersion: v1
kind: Namespace
metadata:
  name: mgmt-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mgmt-intent
  namespace: mgmt-system
`

// TestCheckHarnessObjectsAcceptsSigningPub: ConfigMap mgmt-system/mgmt-signing-pub passes check_harness_objects
// only with the marker label poc.internal/made-by=mgmtd and the field manager mgmtd.
func TestCheckHarnessObjectsAcceptsSigningPub(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	for _, tc := range []struct {
		name, marker, manager, want string
	}{
		{name: "with the marker", marker: "1"},
		{name: "without the marker", want: "'mgmt-intent mgmt-signing-pub'"},
		{name: "with the marker and another manager", marker: "1", manager: "kubectl-edit", want: "'mgmt-intent mgmt-signing-pub'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(signingKubectl), 0o755); err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(dir, "build", "management", "bundles", "mgmt-api")
			if err := os.MkdirAll(bundle, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bundle, "manifests.yaml"), []byte(signingBundle), 0o644); err != nil {
				t.Fatal(err)
			}
			lib, err := filepath.Abs("../../scripts/lib.sh")
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `source "$1"; check_harness_objects mgmt-api mgmt-system`, "_", lib)
			cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
				"CELL=management", "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_MARKER=" + tc.marker, "STUB_MANAGER=" + tc.manager}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err = cmd.Run()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("check failed: %v\n%s", err, out.String())
				}
				return
			}
			if err == nil || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("err %v, output %q; want a failure that names %s", err, out.String(), tc.want)
			}
		})
	}
}
