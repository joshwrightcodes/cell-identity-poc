package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// linkRoot copies the scripts, cell settings and topology of the repository into a temporary
// root. Every component of the topology renders through a stub render.sh that logs its name, and
// facts.sh, publish.sh and link.sh are stubs that log their call. The fake kubectl and mise answer
// what up.sh asks, and kubectl reports every Application Synced and Healthy at the published
// revision.
func linkRoot(t *testing.T) (root, logFile string) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	root = t.TempDir()
	logFile = filepath.Join(root, "calls.log")
	copyDir := func(src, dst string) {
		files, err := filepath.Glob(filepath.Join("../..", src, "*"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no files in %s: %v", src, err)
		}
		if err := os.MkdirAll(filepath.Join(root, dst), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if info, err := os.Stat(f); err != nil || info.IsDir() {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			info, _ := os.Stat(f)
			if err := os.WriteFile(filepath.Join(root, dst, filepath.Base(f)), b, info.Mode()); err != nil {
				t.Fatal(err)
			}
		}
	}
	copyDir("scripts", "scripts")
	copyDir("cells", "cells")
	copyDir("harness", "harness")
	write := func(path, content string) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	comps, err := os.ReadDir("../../components")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range comps {
		c := d.Name()
		write("components/"+c+"/render.sh", "#!/usr/bin/env bash\necho \"render "+c+"\" >>\"$STUB_LOG\"\nprintf 'apiVersion: v1\\nkind: ConfigMap\\nmetadata:\\n  name: "+c+"\\n'\n")
	}
	write("scripts/facts.sh", "#!/usr/bin/env bash\nsource \"$(dirname \"$0\")/lib.sh\"\nmkdir -p \"$BUILD\"\nprintf \"NODE_IPS='172.18.0.3'\\n\" >\"$FACTS\"\n")
	write("scripts/publish.sh", `#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
echo publish >>"$STUB_LOG"
{ echo root=sha256:1; for e in "${COMPONENTS[@]}"; do echo "${e%%:*}=sha256:1"; done; } >"$PUBLISHED"
`)
	write("scripts/link.sh", "#!/usr/bin/env bash\necho link >>\"$STUB_LOG\"\n")
	write("bin/mise", "#!/usr/bin/env bash\necho \"mise $*\" >>\"$STUB_LOG\"\n")
	write("bin/kubectl", `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
if [[ " $* " == *" get pod spire-server-0 "* ]]; then
  [[ -n "${STUB_NO_SPIRE:-}" ]] || echo Running
  exit 0
fi
if [[ " $* " == *" get applications -o json "* ]]; then
  want='. != "root"'
  [[ " $* " != *" -n argocd get "* ]] || want='. == "root"'
  cut -d= -f1 "$POC_BUILD_ROOT/management/published.env" | jq -Rn "{items: [inputs | select($want) | {metadata: {name: .},
    status: {sync: {status: \"Synced\", revision: \"sha256:1\"}, health: {status: \"Healthy\"}}}]}"
fi
exit 0
`)
	return root, logFile
}

func runLinkScript(t *testing.T, root, logFile, script string, env ...string) (string, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", script))
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"), "CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + logFile}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", script, err, out)
	}
	calls, _ := os.ReadFile(logFile)
	_ = os.Remove(logFile)
	return string(out), string(calls)
}

// With CELL_UP_SKIP_LINK=1, hydrate.sh renders no link component and up.sh does not run link.sh.
// Without it, hydrate.sh renders the link component, and up.sh runs the link phase last. up.sh
// always leaves the link components to link.sh, because their renders read live facts.
func TestLinkSkippedWhenAsked(t *testing.T) {
	root, logFile := linkRoot(t)

	_, calls := runLinkScript(t, root, logFile, "hydrate.sh", "CELL_UP_SKIP_LINK=1")
	if strings.Contains(calls, "render central-view") || !strings.Contains(calls, "render spire-server") {
		t.Fatalf("hydrate with CELL_UP_SKIP_LINK=1 calls:\n%s\nwant spire-server and no central-view", calls)
	}
	_, calls = runLinkScript(t, root, logFile, "hydrate.sh")
	if !strings.Contains(calls, "render central-view") {
		t.Fatalf("hydrate calls:\n%s\nwant central-view", calls)
	}
	_, calls = runLinkScript(t, root, logFile, "hydrate.sh", "HYDRATE_ONLY=link")
	if !strings.Contains(calls, "render central-view") || strings.Contains(calls, "render spire-server") {
		t.Fatalf("hydrate with HYDRATE_ONLY=link calls:\n%s\nwant central-view only", calls)
	}

	out, calls := runLinkScript(t, root, logFile, "up.sh", "CELL_UP_SKIP_LINK=1")
	if strings.Contains(calls, "link") || strings.Contains(calls, "render central-view") || !strings.Contains(out, "skipping the link phase") {
		t.Fatalf("up with CELL_UP_SKIP_LINK=1: output\n%s\ncalls:\n%s\nwant no link phase", out, calls)
	}
	_, calls = runLinkScript(t, root, logFile, "up.sh")
	lines := strings.Split(strings.TrimSpace(calls), "\n")
	if lines[len(lines)-1] != "link" || strings.Contains(calls, "render central-view") {
		t.Fatalf("up calls:\n%s\nwant link.sh as the last call, and no render of central-view in up.sh", calls)
	}
}

// Without CELL_UP_SKIP_LINK, cell:up and cell:link of management stop before any apply when the
// environment control plane has no running SPIRE server, and name the commands that go on.
func TestLinkPhaseNeedsTheOtherClusters(t *testing.T) {
	root, logFile := linkRoot(t)
	for _, script := range []string{"up.sh", "link.sh"} {
		t.Run(script, func(t *testing.T) {
			if script == "link.sh" {
				b, err := os.ReadFile("../../scripts/link.sh")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "scripts", "link.sh"), b, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(filepath.Join(root, "scripts", script))
			cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
				"HOME=" + os.Getenv("HOME"), "CELL=management", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + logFile, "STUB_NO_SPIRE=1"}
			out, err := cmd.CombinedOutput()
			calls, _ := os.ReadFile(logFile)
			_ = os.Remove(logFile)
			if err == nil || !strings.Contains(string(out), "the SPIRE server of dev-cp does not run. Run: CELL=dev-cp mise run cell:up") {
				t.Fatalf("err %v, output %s; want a stop that names dev-cp", err, out)
			}
			if script == "up.sh" && !strings.Contains(string(out), "CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up") {
				t.Fatalf("output %s does not name the command without the link phase", out)
			}
			if strings.Contains(string(calls), " apply ") || strings.Contains(string(calls), "hostsvc -- up") || strings.Contains(string(calls), "render ") {
				t.Fatalf("%s worked before the check:\n%s", script, calls)
			}
		})
	}
}
