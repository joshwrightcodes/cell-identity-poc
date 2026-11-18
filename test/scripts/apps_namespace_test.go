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
// answers the reads of AppProjects and Secrets from $STUB_PROJECTS and $STUB_ARGOCD_SECRET, the
// Secret names of argocd from $STUB_SECRET_NAMES (default: the allowed three), the answer of
// can-i from $STUB_CAN_GET (default no), and the admission objects from $STUB_VAP and $STUB_VAPB.
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
if [[ "$args" == *" get secrets -o jsonpath="* ]]; then
  printf '%s\n' "${STUB_SECRET_NAMES-argocd-redis argocd-secret bundle-store}" | tr ' ' '\n'
  exit 0
fi
if [[ "$args" == *" auth can-i get secrets "* ]]; then echo "${STUB_CAN_GET:-no}"; [[ "${STUB_CAN_GET:-no}" == yes ]]; exit; fi
if [[ "$args" == *" auth can-i "*" secrets "* ]]; then verb="$(sed -E 's/.* auth can-i ([a-z]+) secrets.*/\1/' <<<"$args")"; echo "$([[ "$verb" == "${STUB_CAN_VERB:-}" ]] && echo yes || echo no)"; [[ "$verb" == "${STUB_CAN_VERB:-}" ]]; exit; fi
if [[ "$args" == *" get validatingadmissionpolicy argocd-secrets-allowed "* ]]; then echo "${STUB_VAP:-}"; [[ -n "${STUB_VAP:-}" ]]; exit; fi
if [[ "$args" == *" get validatingadmissionpolicybinding argocd-secrets-allowed "* ]]; then echo "${STUB_VAPB:-}"; [[ -n "${STUB_VAPB:-}" ]]; exit; fi
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
		{"argocd", "a", "Synced", "Healthy", "sha256:a"},
		{"argocd", "b", "Synced", "Healthy", "sha256:b"},
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
		{"the root and every child in argocd", goodApps(), true},
		{"a child missing from argocd", goodApps()[:2], false},
		{"a child at a stale revision", with(goodApps(), func(a []stubApp) []stubApp { a[2].Rev = "sha256:old"; return a }), false},
		{"a child that is not Healthy", with(goodApps(), func(a []stubApp) []stubApp { a[1].Health = "Progressing"; return a }), false},
		{"an unknown child without a revision", with(goodApps(), func(a []stubApp) []stubApp {
			return append(a, stubApp{"argocd", "zzz", "Synced", "Healthy", ""})
		}), false},
		{"no root", goodApps()[1:], false},
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
		return append(a, stubApp{"argocd", "zzz", "Synced", "Healthy", "sha256:z"})
	})
	out, err := runLib(t, apps, `apps_blockers`)
	if err != nil || !strings.Contains(out, "argocd holds Applications that were not published: zzz") || !strings.Contains(out, "argocd/b is Synced/Progressing") {
		t.Fatalf("err %v, output %q; want the unknown Application and the unhealthy child", err, out)
	}
	out, err = runLib(t, goodApps()[:2], `apps_blockers`)
	if err != nil || !strings.Contains(out, "argocd lacks b") {
		t.Fatalf("err %v, output %q; want the missing child", err, out)
	}
}

func TestCheckAppsNamespace(t *testing.T) {
	for _, tc := range []struct {
		name string
		apps []stubApp
		want string
	}{
		{"every Application in argocd", goodApps(), ""},
		{"an Application in a third namespace", append(goodApps(), stubApp{"other", "x", "Synced", "Healthy", "sha256:x"}), "other/x"},
		{"no root", goodApps()[1:], "argocd has no root Application"},
		{"a mirror outside management", append(goodApps(), stubApp{"dev-dev-cell-1", "a", "Synced", "Healthy", "sha256:a"}), "dev-dev-cell-1/a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runLib(t, tc.apps, `check_apps_namespace`, "CELL=dev-cell-1")
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

// In management, the principal mirrors the Applications of each cell of VIEW_CELLS into its agent
// namespace. Only those namespaces may hold mirrors.
func TestCheckAppsNamespaceAdmitsTheViewMirrors(t *testing.T) {
	mirrors := append(goodApps(), stubApp{"dev-dev-cell-1", "a", "Synced", "Healthy", "sha256:a"}, stubApp{"dev-dev-cell-2", "b", "Synced", "Healthy", "sha256:b"})
	if out, err := runLib(t, mirrors, `check_apps_namespace`, "CELL=management"); err != nil {
		t.Fatalf("check_apps_namespace failed in management: %v\n%s", err, out)
	}
	other := append(mirrors, stubApp{"dev-dev-cell-3", "c", "Synced", "Healthy", "sha256:c"})
	if out, err := runLib(t, other, `check_apps_namespace`, "CELL=management"); err == nil || !strings.Contains(out, "dev-dev-cell-3/c") {
		t.Fatalf("err %v, output %q; want a failure that names dev-dev-cell-3/c", err, out)
	}
}

// applications_json splits the Applications of argocd into the root and the children for the repair
// and the trace check, and it keeps the errors of kubectl.
func TestApplicationsJSONSplitsRootAndChildren(t *testing.T) {
	out, err := runLib(t, goodApps(), `applications_json kubectl | jq -c '[[.root[].metadata.name], [.children[].metadata.name], (.items | length)]'`)
	if err != nil || strings.TrimSpace(out) != `[["root"],["a","b"],3]` {
		t.Fatalf("err %v, output %q; want root, the two children and three items", err, out)
	}
	out, err = runLib(t, goodApps(), `failing() { echo boom-from-kubectl >&2; return 1; }; applications_json failing`)
	if err == nil || !strings.Contains(out, "boom-from-kubectl") {
		t.Fatalf("err %v, output %q; want the kubectl error on standard error", err, out)
	}
}

// bundle_traces reads root and spire-server from argocd.
func TestBundleTracesReadArgocd(t *testing.T) {
	snippet := `store_forward_start() { STORE_ADDR=x; }; store_forward_stop() { :; }
oras() { echo "$(sed -n "s/^$(basename "${@: -1}" | sed 's/:current//')=//p" "$BUILD_ROOT/dev-cp/published.env")"; }
published_digest() { sed -n "s/^$2=//p" "$BUILD_ROOT/$1/published.env"; }
kubectl() { if [[ " $* " == *" exec "* ]]; then echo '{"entries":[]}'; else command kubectl "$@"; fi; }
mkdir -p "$BUILD_ROOT/dev-cp"; cp "$PUBLISHED" "$BUILD_ROOT/dev-cp/published.env"
printf 'spire-server=sha256:s\n' >>"$BUILD_ROOT/dev-cp/published.env"
bundle_traces dev-cp`
	apps := []stubApp{
		{"argocd", "root", "Synced", "Healthy", "sha256:r"},
		{"argocd", "spire-server", "Synced", "Healthy", "sha256:s"},
	}
	out, err := runLib(t, apps, snippet)
	if err != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("err %v, output %q; want no trace", err, out)
	}
	stale := []stubApp{apps[0], {"argocd", "spire-server", "Synced", "Healthy", "sha256:old"}}
	out, _ = runLib(t, stale, snippet)
	if !strings.Contains(out, "Application spire-server pins sha256:old") {
		t.Fatalf("output %q; want the trace of the stale spire-server", out)
	}
	out, err = runLib(t, apps[:1], snippet)
	if err == nil || !strings.Contains(out, "no Application root or spire-server in argocd") {
		t.Fatalf("err %v, output %q; want a stop that names the missing Application", err, out)
	}
}

func TestClusterChecksOfArgocd(t *testing.T) {
	// The role of the cluster gives the projects: cell and cell-app in a cell, and cell in every other cluster.
	def := `{"metadata":{"name":"default"},"spec":{"sourceRepos":[],"destinations":[],"clusterResourceWhitelist":[]}}`
	cellProject := `{"metadata":{"name":"cell"},"spec":{"sourceRepos":["oci://x"]}}`
	appProject := `{"metadata":{"name":"cell-app"},"spec":{}}`
	list := func(items ...string) string { return `{"items":[` + strings.Join(items, ",") + `]}` }
	open := list(`{"metadata":{"name":"cell"},"spec":{}}`, `{"metadata":{"name":"default"},"spec":{"sourceRepos":["*"],"destinations":[{"server":"*","namespace":"*"}],"clusterResourceWhitelist":[{"group":"*","kind":"*"}]}}`)
	for _, tc := range []struct {
		name, cell, projects string
		ok                   bool
	}{
		{"locked default", "dev-cell-1", list(cellProject, appProject, def), true},
		{"permissive default", "dev-cell-1", strings.Replace(list(cellProject, appProject, def), def, open[strings.Index(open, `{"metadata":{"name":"default"`):len(open)-2], 1), false},
		{"no default", "dev-cell-1", list(cellProject, appProject), false},
		{"a cell without cell-app", "dev-cell-1", list(cellProject, def), false},
		{"a third project", "dev-cell-1", list(`{"metadata":{"name":"evil"},"spec":{}}`, cellProject, appProject, def), false},
		{"dev-cp with cell", "dev-cp", list(cellProject, def), true},
		{"dev-cp with cell-app", "dev-cp", list(cellProject, appProject, def), false},
		{"management with cell", "management", list(cellProject, def), true},
	} {
		t.Run("projects/"+tc.name, func(t *testing.T) {
			out, err := runLib(t, nil, `check_argocd_projects`, "STUB_PROJECTS="+tc.projects, "CELL="+tc.cell)
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

const (
	goodVAP = `{"spec":{"failurePolicy":"Fail","matchConstraints":{"resourceRules":[{"operations":["CREATE","UPDATE"]}]},
"validations":[{"expression":"object.metadata.name in ['argocd-redis', 'argocd-secret', 'bundle-store']"}]}}`
	goodVAPB = `{"spec":{"policyName":"argocd-secrets-allowed","validationActions":["Deny"],
"matchResources":{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"argocd"}}}}}`
)

func TestCheckArgocdSecrets(t *testing.T) {
	good := []string{"STUB_VAP=" + goodVAP, "STUB_VAPB=" + goodVAPB}
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"the allowed set", good, ""},
		{"a Secret outside the set", append([]string{"STUB_SECRET_NAMES=argocd-redis argocd-secret bundle-store repo-token"}, good...), "repo-token"},
		{"the agent can get a Secret", append([]string{"STUB_CAN_GET=yes"}, good...), "can get Secrets in argocd"},
		{"the agent can update a Secret", append([]string{"STUB_CAN_VERB=update"}, good...), "can update Secrets in argocd"},
		{"the agent can create a Secret", append([]string{"STUB_CAN_VERB=create"}, good...), "can create Secrets in argocd"},
		{"no policy", []string{"STUB_VAPB=" + goodVAPB}, "argocd-secrets-allowed is missing"},
		{"a wider policy", []string{"STUB_VAP=" + strings.Replace(goodVAP, "'bundle-store'", "'bundle-store', 'other'", 1), "STUB_VAPB=" + goodVAPB}, "does not allow exactly"},
		{"a policy that only warns", []string{"STUB_VAP=" + goodVAP, "STUB_VAPB=" + strings.Replace(goodVAPB, `"Deny"`, `"Warn"`, 1)}, "does not deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runLib(t, nil, `check_argocd_secrets`, tc.env...)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("check_argocd_secrets failed: %v\n%s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("err %v, output %q; want a failure that names %q", err, out, tc.want)
			}
		})
	}
}

// relayKubectl serves the live relay objects from files in $STUB_DIR: d-<name>.json and
// n-<name>.json.
const relayKubectl = `#!/usr/bin/env bash
args=" $* "
for kind in deployment networkpolicy; do
  for name in relay-view relay-telemetry; do
    if [[ "$args" == *" get $kind $name -o json "* ]]; then
      f="$STUB_DIR/${kind:0:1}-$name.json"; [[ -f "$f" ]] && cat "$f" && exit 0; exit 1
    fi
  done
done
echo "unexpected kubectl call: $*" >&2
exit 2
`

func relayFixture(t *testing.T, target string, cells ...string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(relayKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	var from []string
	for _, c := range cells {
		from = append(from, `{"ipBlock":{"cidr":"`+c+`/32"}}`)
	}
	for name, ports := range map[string][]string{"relay-view": {"8443=" + target + ":31443", "8445=" + target + ":31445"}, "relay-telemetry": {"8444=" + target + ":31444"}} {
		var args []string
		for _, p := range ports {
			args = append(args, `"--route"`, `"`+p+`"`)
		}
		deploy := `{"spec":{"template":{"spec":{"containers":[{"args":[` + strings.Join(args, ",") + `,"--health",":8080"]}]}}}}`
		var routePorts, targetPorts []string
		for _, p := range ports {
			container, rest, _ := strings.Cut(p, "=")
			routePorts = append(routePorts, `{"port":`+container+`}`)
			targetPorts = append(targetPorts, `{"port":`+rest[strings.LastIndex(rest, ":")+1:]+`}`)
		}
		np := `{"spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"172.18.0.4/32"}}],"ports":[{"port":8080}]},{"from":[` + strings.Join(from, ",") + `],"ports":[` + strings.Join(routePorts, ",") + `]}],` +
			`"egress":[{"to":[],"ports":[{"port":4317}]},{"to":[{"ipBlock":{"cidr":"` + target + `/32"}}],"ports":[` + strings.Join(targetPorts, ",") + `]}]}}`
		for f, data := range map[string]string{"d-" + name + ".json": deploy, "n-" + name + ".json": np} {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

// check_relay_current compares the routes and the policies of the relay with the node addresses
// that the host service reports now. The fixture holds management at 172.18.0.3 and the cells at
// 172.18.0.5 and 172.18.0.6.
func TestCheckRelayCurrent(t *testing.T) {
	for _, tc := range []struct {
		name, mgmt, cell2, want string
	}{
		{"current", "172.18.0.3", "172.18.0.6", ""},
		{"the management node moved", "172.18.0.9", "172.18.0.6", "relay-view routes to '172.18.0.3'"},
		{"a cell node moved", "172.18.0.3", "172.18.0.7", "the ingress policy of relay-view admits"},
		{"the telemetry relay is missing", "172.18.0.3", "172.18.0.6", "cannot read Deployment relay-system/relay-telemetry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := relayFixture(t, "172.18.0.3", "172.18.0.5", "172.18.0.6")
			writeLiveStubs(t, dir)
			if strings.Contains(tc.name, "telemetry relay") {
				_ = os.Remove(filepath.Join(dir, "d-relay-telemetry.json"))
			}
			snippet := `node_ip() { case "$1" in management) echo "$STUB_MGMT" ;; dev-cell-1) echo 172.18.0.5 ;; dev-cell-2) echo "$STUB_CELL2" ;; esac; }
RELAY_TARGET=management SPIRE_AGENT_CELLS="dev-cell-1 dev-cell-2" CELL_NAME=dev-cp
check_relay_current`
			out, err := runLib(t, nil, snippet, "STUB_DIR="+dir, "STUB_MGMT="+tc.mgmt, "STUB_CELL2="+tc.cell2,
				"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("check_relay_current failed: %v\n%s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(out, tc.want) || !strings.Contains(out, "Run: CELL=dev-cp mise run cell:up") {
				t.Fatalf("err %v, output %q; want a failure that names %q and the next command", err, out, tc.want)
			}
		})
	}
}
