package scripts

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// appsKubectl serves the Applications of $STUB_APPS, a JSON list of {ns, name, sync, health, rev}.
// A call with -n answers for that namespace, and a call with -A for every namespace. It also
// answers the reads of AppProjects and Secrets from $STUB_PROJECTS, $STUB_SECRETS and
// $STUB_ADMIN_SECRET.
const appsKubectl = `#!/usr/bin/env bash
args=" $* "
echo "kubectl $*" >>"${STUB_LOG:-/dev/null}"
ns=""
if [[ "$args" == *" -n "* ]]; then ns="$(sed -E 's/.* -n ([^ ]+) .*/\1/' <<<"$args")"; fi
if [[ "$args" == *" get applications "* && "$args" == *" -o json "* ]]; then
  jq --arg ns "$ns" '{items: [.[] | select($ns == "" or .ns == $ns)
    | {metadata: {name: .name, namespace: .ns}, spec: {source: {targetRevision: (.pin // .rev)}},
       status: {sync: {status: .sync, revision: .rev}, health: {status: .health}}}]}' <<<"$STUB_APPS"
  exit 0
fi
if [[ "$args" == *" get application root "* ]]; then
  jq -e 'any(.[]; .ns == "argocd" and .name == "root")' <<<"$STUB_APPS" >/dev/null
  exit
fi
if [[ "$args" == *" get appprojects -o json "* ]]; then echo "$STUB_PROJECTS"; exit 0; fi
if [[ "$args" == *" get secret argocd-initial-admin-secret "* ]]; then [[ -n "${STUB_INITIAL_SECRET:-}" ]]; exit; fi
if [[ "$args" == *" get secret argocd-secret -o json "* ]]; then
  if [[ -n "${STUB_ARGOCD_SECRET:-}" ]]; then echo "$STUB_ARGOCD_SECRET"; else echo '{"data":{}}'; fi
  exit 0
fi
echo "unexpected kubectl call: $*" >&2
exit 2
`

type stubApp struct {
	NS     string `json:"ns"`
	Name   string `json:"name"`
	Sync   string `json:"sync"`
	Health string `json:"health"`
	Rev    string `json:"rev"`
}

func goodApps() []stubApp {
	return []stubApp{
		{"argocd", "root", "Synced", "Healthy", "sha256:r"},
		{"argocd-apps", "a", "Synced", "Healthy", "sha256:a"},
		{"argocd-apps", "b", "Synced", "Healthy", "sha256:b"},
	}
}

// runLib sources scripts/lib.sh as dev-cell-1 with the fake kubectl, then runs the snippet.
// published.env lists root, a and b.
func runLib(t *testing.T, apps []stubApp, snippet string, env ...string) (string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(appsKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(dir, "published.env")
	if err := os.WriteFile(published, []byte("a=sha256:a\nb=sha256:b\nroot=sha256:r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := json.Marshal(apps)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; PUBLISHED="$2"; `+snippet, "_", lib, published)
	cmd.Env = append([]string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_APPS=" + string(list)}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return out.String(), err
}

func with(apps []stubApp, edit func(a []stubApp) []stubApp) []stubApp {
	return edit(append([]stubApp(nil), apps...))
}

func TestAppsAtPublished(t *testing.T) {
	for _, tc := range []struct {
		name string
		apps []stubApp
		ok   bool
	}{
		{"root in argocd and children in argocd-apps", goodApps(), true},
		{"a child also in argocd", with(goodApps(), func(a []stubApp) []stubApp {
			return append(a, stubApp{"argocd", "a", "Synced", "Healthy", "sha256:a"})
		}), false},
		{"a child missing from argocd-apps", goodApps()[:2], false},
		{"a child at a stale revision", with(goodApps(), func(a []stubApp) []stubApp { a[2].Rev = "sha256:old"; return a }), false},
		{"a child that is not Healthy", with(goodApps(), func(a []stubApp) []stubApp { a[1].Health = "Progressing"; return a }), false},
		{"an unknown child without a revision", with(goodApps()[:2], func(a []stubApp) []stubApp {
			return append(a, stubApp{"argocd-apps", "zzz", "Synced", "Healthy", ""}, stubApp{"argocd-apps", "b", "Synced", "Healthy", "sha256:b"}, stubApp{"argocd-apps", "c", "Synced", "Healthy", "sha256:c"})
		}), false},
		{"the root in argocd-apps", []stubApp{{"argocd-apps", "root", "Synced", "Healthy", "sha256:r"}, goodApps()[1], goodApps()[2]}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runLib(t, tc.apps, `apps_at_published`)
			if (err == nil) != tc.ok {
				t.Fatalf("apps_at_published err %v, want success %v; output %q", err, tc.ok, out)
			}
		})
	}
}

func TestAppsBlockersNameTheReason(t *testing.T) {
	apps := with(goodApps(), func(a []stubApp) []stubApp {
		a[2].Health = "Progressing"
		return append(a, stubApp{"argocd", "a", "Synced", "Healthy", "sha256:a"})
	})
	out, err := runLib(t, apps, `apps_blockers`)
	if err != nil || !strings.Contains(out, "argocd holds Applications other than root: a") || !strings.Contains(out, "argocd-apps/b is Synced/Progressing") {
		t.Fatalf("err %v, output %q; want the stray Application and the unhealthy child", err, out)
	}
}

func TestCheckAppsNamespace(t *testing.T) {
	for _, tc := range []struct {
		name string
		apps []stubApp
		want string
	}{
		{"split correctly", goodApps(), ""},
		{"an Application in a third namespace", append(goodApps(), stubApp{"other", "x", "Synced", "Healthy", "sha256:x"}), "other/x"},
		{"a child left in argocd", append(goodApps(), stubApp{"argocd", "a", "Synced", "Healthy", "sha256:a"}), "argocd/a"},
		{"no root", goodApps()[1:], "argocd has no root Application"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runLib(t, tc.apps, `check_apps_namespace`)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("check_apps_namespace failed: %v\n%s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(out, tc.want) || !strings.Contains(out, "Run: CELL=dev-cell-1 mise run cell:up") {
				t.Fatalf("err %v, output %q; want a failure that names %q and the next command", err, out, tc.want)
			}
		})
	}
}

// applications_json merges the two namespaces for the repair and the trace check, and it keeps the
// errors of kubectl.
func TestApplicationsJSONMergesBothNamespaces(t *testing.T) {
	out, err := runLib(t, goodApps(), `applications_json kubectl | jq -c '[[.root[].metadata.name], [.children[].metadata.name], (.items | length)]'`)
	if err != nil || strings.TrimSpace(out) != `[["root"],["a","b"],3]` {
		t.Fatalf("err %v, output %q; want root, the two children and three items", err, out)
	}
	out, err = runLib(t, goodApps(), `failing() { echo boom-from-kubectl >&2; return 1; }; applications_json failing`)
	if err == nil || !strings.Contains(out, "boom-from-kubectl") {
		t.Fatalf("err %v, output %q; want the kubectl error on standard error", err, out)
	}
}

// bundle_traces reads root from argocd and spire-server from argocd-apps.
func TestBundleTracesReadBothNamespaces(t *testing.T) {
	snippet := `store_forward_start() { STORE_ADDR=x; }; store_forward_stop() { :; }
oras() { echo "$(sed -n "s/^$(basename "${@: -1}" | sed 's/:current//')=//p" "$BUILD_ROOT/dev-cp/published.env")"; }
published_digest() { sed -n "s/^$2=//p" "$BUILD_ROOT/$1/published.env"; }
kubectl() { if [[ " $* " == *" exec "* ]]; then echo '{"entries":[]}'; else command kubectl "$@"; fi; }
mkdir -p "$BUILD_ROOT/dev-cp"; cp "$PUBLISHED" "$BUILD_ROOT/dev-cp/published.env"
printf 'spire-server=sha256:s\n' >>"$BUILD_ROOT/dev-cp/published.env"
bundle_traces dev-cp`
	apps := []stubApp{
		{"argocd", "root", "Synced", "Healthy", "sha256:r"},
		{"argocd-apps", "spire-server", "Synced", "Healthy", "sha256:s"},
	}
	out, err := runLib(t, apps, snippet)
	if err != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("err %v, output %q; want no trace", err, out)
	}
	stale := []stubApp{apps[0], {"argocd-apps", "spire-server", "Synced", "Healthy", "sha256:old"}}
	out, _ = runLib(t, stale, snippet)
	if !strings.Contains(out, "Application spire-server pins sha256:old") {
		t.Fatalf("output %q; want the trace of the stale spire-server", out)
	}
	out, err = runLib(t, apps[:1], snippet)
	if err == nil || !strings.Contains(out, "no Application spire-server in argocd-apps") {
		t.Fatalf("err %v, output %q; want a stop that names the missing Application", err, out)
	}
}

func TestClusterChecksOfArgocd(t *testing.T) {
	locked := `{"items":[{"metadata":{"name":"cell"},"spec":{"sourceRepos":["oci://x"]}},{"metadata":{"name":"default"},"spec":{"sourceRepos":[],"destinations":[],"clusterResourceWhitelist":[]}}]}`
	open := `{"items":[{"metadata":{"name":"cell"},"spec":{}},{"metadata":{"name":"default"},"spec":{"sourceRepos":["*"],"destinations":[{"server":"*","namespace":"*"}],"clusterResourceWhitelist":[{"group":"*","kind":"*"}]}}]}`
	for _, tc := range []struct {
		name, projects string
		ok             bool
	}{{"locked default", locked, true}, {"permissive default", open, false},
		{"no default", `{"items":[{"metadata":{"name":"cell"},"spec":{}}]}`, false},
		{"a third project", strings.Replace(locked, `{"items":[`, `{"items":[{"metadata":{"name":"evil"},"spec":{}},`, 1), false}} {
		t.Run("projects/"+tc.name, func(t *testing.T) {
			out, err := runLib(t, nil, `check_argocd_projects`, "STUB_PROJECTS="+tc.projects)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want success %v; output %q", err, tc.ok, out)
			}
		})
	}
	for _, tc := range []struct {
		name string
		env  []string
		ok   bool
	}{{"no credential", nil, true},
		{"initial admin secret", []string{"STUB_INITIAL_SECRET=1"}, false},
		{"admin.password", []string{`STUB_ARGOCD_SECRET={"data":{"admin.password":"eA=="}}`}, false},
		{"only the signing key", []string{`STUB_ARGOCD_SECRET={"data":{"server.secretkey":"eA=="}}`}, true}} {
		t.Run("credentials/"+tc.name, func(t *testing.T) {
			out, err := runLib(t, nil, `check_no_admin_credentials`, tc.env...)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want success %v; output %q", err, tc.ok, out)
			}
		})
	}
}
