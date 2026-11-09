package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// migrateKubectl plays a dev-cp that runs the cluster-scoped operator until the stub publish runs,
// and the namespaced store after the stub secrets:connect runs. Each call goes to kubectl.log.
//   STUB_MIGRATED        the cluster runs the scoped operator and the namespaced store already
//   STUB_ANNOTATE_LOST   the annotate does not reach the Namespace
//   STUB_NS_UID_CHANGES  the Namespace has a new UID after secrets:connect
const migrateKubectl = `#!/usr/bin/env bash
set -euo pipefail
echo "kubectl $*" >>"$STUB_DIR/kubectl.log"
published=0; connected=0
[[ -e "$STUB_DIR/published" || -n "${STUB_MIGRATED:-}" ]] && published=1
[[ -e "$STUB_DIR/connected" || -n "${STUB_MIGRATED:-}" ]] && connected=1
case " $* " in
  *" config get-contexts "*) echo kind-dev-cp ;;
  *" annotate namespace spire-system "*)
    [[ -n "${STUB_ANNOTATE_LOST:-}" ]] || echo "Prune=false,Delete=false" >"$STUB_DIR/annotation"
    echo annotated ;;
  *"sync-options}"*) cat "$STUB_DIR/annotation" 2>/dev/null || true ;;
  *"tracking-id}"*)
    if ((published)); then echo "external-secrets:/Namespace:spire-system/spire-system"
    else echo "spire-server:/Namespace:spire-system/spire-system"; fi ;;
  *" get namespace spire-system -o jsonpath={.metadata.uid} "*)
    if [[ -n "${STUB_NS_UID_CHANGES:-}" ]] && ((connected)); then echo uid-new; else echo uid-ns; fi ;;
  *" get pvc data-spire-server-0 "*) echo uid-pvc ;;
  *" get externalsecret spire-upstream -o json "*)
    kind=ClusterSecretStore; ((connected)) && kind=SecretStore
    echo "{\"spec\":{\"secretStoreRef\":{\"kind\":\"$kind\",\"name\":\"poc-secrets\"}},\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\"}]}}" ;;
  *" get deployment external-secrets -o json "*)
    arg=--enable-secret-store-reconciler=false; ((published)) && arg=--namespace=spire-system
    echo "{\"metadata\":{\"generation\":4},\"spec\":{\"replicas\":1,\"template\":{\"spec\":{\"containers\":[{\"args\":[\"$arg\"]}]}}},\"status\":{\"observedGeneration\":4,\"replicas\":1,\"updatedReplicas\":1,\"availableReplicas\":1}}" ;;
  *" get application external-secrets -o json "*)
    echo '{"status":{"sync":{"status":"Synced","revision":"sha256:new"},"health":{"status":"Healthy"}}}' ;;
  *" get applications -o json "*)
    jq -Rn '{items: [inputs | select(length > 0) | split("=") | {metadata: {name: .[0]},
      status: {sync: {status: "Synced", revision: .[1]}, health: {status: "Healthy"}}}]}' <"$POC_BUILD_ROOT/dev-cp/published.env" ;;
  *" get clusterroles,clusterrolebindings -o name "*)
    ((published)) || echo clusterrole.rbac.authorization.k8s.io/external-secrets-controller ;;
  *" auth can-i list secrets -A "*) if ((published)); then echo no; else echo yes; fi ;;
  *" auth can-i get secrets -n spire-system "*) echo yes ;;
  *" get pod spire-server-0 -o jsonpath={.status.phase} "*) echo Running ;;
  *" get crd clustersecretstores.external-secrets.io "*) [[ ! -e "$STUB_DIR/crd-deleted" ]] ;;
  *" delete crd clustersecretstores.external-secrets.io "*) touch "$STUB_DIR/crd-deleted"; echo deleted ;;
  *" delete "*) echo deleted ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// migrateScripts stand in for hydrate, publish and secrets:connect. publish writes published.env
// for every Application of dev-cp at sha256:new.
var migrateScripts = map[string]string{
	"hydrate.sh": `#!/usr/bin/env bash
echo "SCRIPT hydrate" >>"$STUB_DIR/kubectl.log"
`,
	"publish.sh": `#!/usr/bin/env bash
echo "SCRIPT publish" >>"$STUB_DIR/kubectl.log"
mkdir -p "$POC_BUILD_ROOT/dev-cp"
for c in root namespaces argocd cell-system network-policy istio-base istio-cni istiod observability-system \
    istio-egress mesh-policy apps-demo external-secrets spire-server; do
  echo "$c=sha256:new"
done >"$POC_BUILD_ROOT/dev-cp/published.env"
touch "$STUB_DIR/published"
`,
	"secrets-connect.sh": `#!/usr/bin/env bash
echo "SCRIPT secrets-connect" >>"$STUB_DIR/kubectl.log"
touch "$STUB_DIR/connected"
`,
}

func runMigrate(t *testing.T, env ...string) (string, []string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "git")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(migrateKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	scripts := filepath.Join(dir, "scripts")
	if err := os.Mkdir(scripts, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range migrateScripts {
		if err := os.WriteFile(filepath.Join(scripts, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script, err := filepath.Abs("../../scripts/eso-migrate.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script)
	cmd.Env = append([]string{
		"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"STUB_DIR=" + dir,
		"CELL=dev-cp",
		"POC_BUILD_ROOT=" + filepath.Join(dir, "build"),
		"POC_ENVRC_LOCAL=" + filepath.Join(dir, "no-envrc-local"),
		"ESO_MIGRATE_SCRIPTS=" + scripts,
		"POC_SECRET_TOKEN_CMD=printf %s " + token,
		"POC_SECRET_STORE_PROVIDER=" + provider,
	}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var calls []string
	if data, readErr := os.ReadFile(filepath.Join(dir, "kubectl.log")); readErr == nil {
		calls = strings.Split(strings.TrimSpace(string(data)), "\n")
	}
	return out.String(), calls, err
}

// index returns the position of the first call that contains want, or -1.
func index(calls []string, want string) int {
	for i, c := range calls {
		if strings.Contains(c, want) {
			return i
		}
	}
	return -1
}

func TestMigrateGuardsTheNamespaceFirst(t *testing.T) {
	out, calls, err := runMigrate(t)
	if err != nil {
		t.Fatalf("eso:migrate failed: %v\n%s", err, out)
	}
	order := []string{
		"annotate namespace spire-system argocd.argoproj.io/sync-options=Prune=false,Delete=false --overwrite",
		"sync-options}",
		"SCRIPT hydrate",
		"SCRIPT publish",
		"get deployment external-secrets -o json",
		"SCRIPT secrets-connect",
		"delete secret poc-secrets-token",
		"delete clustersecretstore poc-secrets",
		"delete crd clustersecretstores.external-secrets.io",
	}
	last := -1
	for _, want := range order {
		i := index(calls, want)
		if i <= last {
			t.Fatalf("call %q at %d, want it after the call before it at %d:\n%s", want, i, last, strings.Join(calls, "\n"))
		}
		last = i
	}
	if first := index(calls, "annotate"); calls[first] != calls[index(calls, "annotate namespace")] || first > index(calls, "SCRIPT") {
		t.Fatal("a change came before the annotate")
	}
	if !strings.Contains(out, "eso:migrate is complete") {
		t.Fatalf("output does not report completion:\n%s", out)
	}
}

func TestMigrateStopsWhenTheAnnotationDoesNotReadBack(t *testing.T) {
	out, calls, err := runMigrate(t, "STUB_ANNOTATE_LOST=1")
	if err == nil || !strings.Contains(out, "The migration stops before any other change") {
		t.Fatalf("err %v, output %q; want a stop after the read-back", err, out)
	}
	if i := index(calls, "SCRIPT"); i >= 0 {
		t.Fatalf("the migration ran %q after a failed read-back", calls[i])
	}
}

func TestMigrateOnAMigratedClusterOnlyChecks(t *testing.T) {
	out, calls, err := runMigrate(t, "STUB_MIGRATED=1")
	if err != nil {
		t.Fatalf("eso:migrate failed: %v\n%s", err, out)
	}
	for _, unwanted := range []string{"annotate", "SCRIPT"} {
		if i := index(calls, unwanted); i >= 0 {
			t.Fatalf("a migrated cluster got the call %q", calls[i])
		}
	}
	if index(calls, "delete crd clustersecretstores.external-secrets.io") < 0 {
		t.Fatal("the cleanup did not run")
	}
}

func TestMigrateFailsWithARollbackWhenTheNamespaceIsNew(t *testing.T) {
	out, calls, err := runMigrate(t, "STUB_NS_UID_CHANGES=1")
	if err == nil {
		t.Fatalf("eso:migrate succeeded:\n%s", out)
	}
	for _, want := range []string{"has the UID 'uid-new', not uid-ns", "To roll back", "worktree add --detach", "delete secretstore poc-secrets"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output does not contain %q:\n%s", want, out)
		}
	}
	if i := index(calls, "delete secret poc-secrets-token"); i >= 0 {
		t.Fatal("the cleanup ran after a failed check")
	}
}

func TestMigrateNeedsTheSecretsConnectSettings(t *testing.T) {
	out, calls, err := runMigrate(t, "POC_SECRET_TOKEN_CMD=")
	if err == nil || !strings.Contains(out, "POC_SECRET_TOKEN_CMD and POC_SECRET_STORE_PROVIDER must be set") || !strings.Contains(out, "changed nothing") {
		t.Fatalf("err %v, output %q; want a stop before any change", err, out)
	}
	if i := index(calls, "annotate"); i >= 0 {
		t.Fatal("the migration annotated without the settings")
	}
}
