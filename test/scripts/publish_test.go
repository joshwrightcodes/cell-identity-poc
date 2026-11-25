package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// publishStubs are the host commands of publish.sh. kubectl logs its call, and a port-forward sleeps. curl fails
// on its first call, as when no old port-forward holds the port, and then succeeds. mise answers
// "run bundlectl -- bootstrap" with a root digest and one digest for each entry, and logs the call. oras pushes
// and finds no tag.
var publishStubs = map[string]string{
	"kubectl": `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
if [[ " $* " == *" port-forward "* ]]; then exec sleep 30; fi
exit 0
`,
	"curl": `#!/usr/bin/env bash
echo "curl $*" >>"$STUB_LOG"
if [[ ! -e "$STUB_STATE/curl-seen" ]]; then touch "$STUB_STATE/curl-seen"; exit 22; fi
exit 0
`,
	"mise": `#!/usr/bin/env bash
echo "mise $*" >>"$STUB_LOG"
[[ "$1 $2 $3 $4" == "run bundlectl -- bootstrap" ]] || exit 2
names=()
for a in "$@"; do [[ "$a" == *:*:* ]] && names+=("${a%%:*}"); done
printf '%s\n' "${names[@]}" | jq -R . | jq -sc '{digest: "sha256:root", manifest: "bWFuaWZlc3Q=", components: (map({key: ., value: ("sha256:" + .)}) | from_entries)}'
`,
	"oras": `#!/usr/bin/env bash
echo "oras $*" >>"$STUB_LOG"
case "$1 $2" in
  "push --plain-http") echo '{"digest":"sha256:pushed"}' ;;
  "repo tags") ;;
esac
exit 0
`,
}

// runPublish runs publish.sh for a cluster in a temporary root. It returns the root, the log of the host
// commands and the entries of COMPONENTS.
func runPublish(t *testing.T, cell string) (root, log string, components []string) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	root = t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	bin, state := filepath.Join(root, "bin"), filepath.Join(root, "state")
	for _, d := range []string{bin, state} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range publishStubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logFile := filepath.Join(root, "calls.log")
	env := append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "CELL="+cell,
		"POC_BUILD_ROOT="+filepath.Join(root, "build"), "STUB_LOG="+logFile, "STUB_STATE="+state)
	list := exec.Command("bash", "-c", `source "$1"; printf '%s\n' "${COMPONENTS[@]}"`, "_", filepath.Join(root, "scripts", "lib.sh"))
	list.Env = env
	out, err := list.Output()
	if err != nil {
		t.Fatalf("read COMPONENTS of %s: %v", cell, err)
	}
	components = strings.Fields(string(out))
	for _, e := range components {
		dir := filepath.Join(root, "build", cell, "bundles", strings.SplitN(e, ":", 2)[0])
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifests.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x, namespace: default}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(filepath.Join(root, "scripts", "publish.sh"))
	cmd.Env = env
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("publish.sh for %s failed: %v\n%s", cell, err, combined)
	}
	b, _ := os.ReadFile(logFile)
	return root, string(b), components
}

// TestPublishForwardsLoopbackPort checks that publish.sh reaches the registry through a port-forward to port
// 5001 of pod bundle-store-0, which is the loopback address of the pod behind the token proxy, and that every
// registry address that it gives to a tool is the local end of that forward. It never forwards the Service.
func TestPublishForwardsLoopbackPort(t *testing.T) {
	t.Parallel()
	for _, cell := range []string{"dev-cell-1", "dev-cell-2", "dev-cp", "management"} {
		t.Run(cell, func(t *testing.T) {
			root, log, _ := runPublish(t, cell)
			envFile, _ := os.ReadFile(filepath.Join(root, "cells", cell+".env"))
			port := regexp.MustCompile(`(?m)^CELL_BUNDLE_STORE_PORT=(\d+)`).FindStringSubmatch(string(envFile))
			if port == nil {
				t.Fatalf("cells/%s.env has no CELL_BUNDLE_STORE_PORT", cell)
			}
			want := "kubectl --context kind-" + cell + " -n cell-system port-forward pod/bundle-store-0 " + port[1] + ":5001"
			if !strings.Contains(log, want+"\n") {
				t.Errorf("the log lacks %q:\n%s", want, log)
			}
			if strings.Contains(log, "svc/bundle-store") {
				t.Errorf("publish.sh forwards the Service, which the token proxy fronts:\n%s", log)
			}
			local := "127.0.0.1:" + port[1]
			for _, line := range strings.Split(log, "\n") {
				if strings.HasPrefix(line, "kubectl ") || strings.HasPrefix(line, "curl ") || line == "" {
					continue
				}
				if !strings.Contains(line, local) && (strings.Contains(line, "--registry") || strings.HasPrefix(line, "oras push") ||
					strings.HasPrefix(line, "oras repo") || strings.HasPrefix(line, "oras resolve")) {
					t.Errorf("the call %q does not use %s", line, local)
				}
			}
			if !strings.Contains(log, "curl -fsS http://"+local+"/v2/") {
				t.Errorf("publish.sh does not wait for the registry at %s:\n%s", local, log)
			}
		})
	}
}

// TestPublishWritesRootJSON checks that a cluster with role cell or cp gets its bundles and its root from
// bundlectl bootstrap with the role, the target, the loopback registry and the entries of COMPONENTS, and
// that the result lands in build/<cluster>/root.json and the digests in published.env. A cluster with role
// open gets no bootstrap call and no root.json, and its Applications read oci://127.0.0.1:5000.
func TestPublishWritesRootJSON(t *testing.T) {
	t.Parallel()
	roles := map[string]string{"dev-cell-1": "cell", "dev-cell-2": "cell", "dev-cp": "cp", "management": "open"}
	for cell, role := range roles {
		t.Run(cell, func(t *testing.T) {
			root, log, components := runPublish(t, cell)
			build := filepath.Join(root, "build", cell)
			published, err := os.ReadFile(filepath.Join(build, "published.env"))
			if err != nil {
				t.Fatal(err)
			}
			rootJSON, rootErr := os.ReadFile(filepath.Join(build, "root.json"))
			if role == "open" {
				if rootErr == nil {
					t.Error("management has a root.json")
				}
				if strings.Contains(log, "bundlectl") {
					t.Errorf("management runs bundlectl:\n%s", log)
				}
				app, err := os.ReadFile(filepath.Join(build, "root", "argocd.yaml"))
				if err != nil || !strings.Contains(string(app), "repoURL: oci://127.0.0.1:5000/bundles/argocd\n") {
					t.Errorf("the Application argocd is %q, %v, want repoURL oci://127.0.0.1:5000/bundles/argocd", app, err)
				}
				// Every Application that publish.sh writes must read a source that the project cell of
				// components/argocd/project.yaml allows.
				var project struct {
					Spec struct {
						SourceRepos []string `json:"sourceRepos"`
					} `json:"spec"`
				}
				raw, err := os.ReadFile("../../components/argocd/project.yaml")
				if err != nil || yaml.Unmarshal(raw, &project) != nil || len(project.Spec.SourceRepos) == 0 {
					t.Fatalf("read project.yaml: %v", err)
				}
				apps, _ := filepath.Glob(filepath.Join(build, "root", "*.yaml"))
				if len(apps) != len(components) {
					t.Fatalf("publish.sh wrote %d Application files for %d components", len(apps), len(components))
				}
				for _, f := range apps {
					data, _ := os.ReadFile(f)
					var app struct {
						Spec struct {
							Project string `json:"project"`
							Source  struct {
								RepoURL string `json:"repoURL"`
							} `json:"source"`
						} `json:"spec"`
					}
					if err := yaml.Unmarshal(data, &app); err != nil || app.Spec.Project != "cell" {
						t.Fatalf("%s: %v, project %q", f, err, app.Spec.Project)
					}
					allowed := false
					for _, g := range project.Spec.SourceRepos {
						if ok, _ := path.Match(g, app.Spec.Source.RepoURL); ok {
							allowed = true
						}
					}
					if !allowed {
						t.Errorf("%s reads %s, which project.yaml does not allow (%v)", filepath.Base(f), app.Spec.Source.RepoURL, project.Spec.SourceRepos)
					}
				}
				if !strings.Contains(string(published), "root=sha256:pushed\n") {
					t.Errorf("published.env is %q", published)
				}
				return
			}
			if rootErr != nil {
				t.Fatalf("no root.json: %v", rootErr)
			}
			var res struct {
				Digest, Manifest string
				Components       map[string]string
			}
			if err := json.Unmarshal(rootJSON, &res); err != nil || res.Digest != "sha256:root" || res.Manifest == "" || len(res.Components) != len(components) {
				t.Errorf("root.json is %q, %v, want the result of bundlectl bootstrap", rootJSON, err)
			}
			call := "mise run bundlectl -- bootstrap --role " + role + " --target " + cell + " --registry 127.0.0.1:"
			var line string
			for _, l := range strings.Split(log, "\n") {
				if strings.HasPrefix(l, call) {
					line = l
				}
			}
			if line == "" {
				t.Fatalf("no call that starts with %q:\n%s", call, log)
			}
			if !strings.HasSuffix(line, " "+strings.Join(components, " ")) {
				t.Errorf("the call %q does not end with the entries %v", line, components)
			}
			if !strings.Contains(string(published), "root=sha256:root\n") {
				t.Errorf("published.env is %q, want root=sha256:root", published)
			}
			for _, e := range components {
				c := strings.SplitN(e, ":", 2)[0]
				if !strings.Contains(string(published), c+"=sha256:"+c+"\n") {
					t.Errorf("published.env lacks %s=sha256:%s:\n%s", c, c, published)
				}
			}
			if strings.Contains(log, "oras push") {
				t.Errorf("a signed-role cluster pushes with oras:\n%s", log)
			}
		})
	}
}
