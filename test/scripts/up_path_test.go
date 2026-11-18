package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// upKubectl is the kubectl of the up.sh tests. get configmap bundle-state prints STUB_STATE_JSON, or nothing when the ConfigMap is
// absent. create -f - keeps its standard input in STUB_CREATED. get applications reports each name of published.env as Synced and
// Healthy at sha256:1, and every list with a label selector is empty.
const upKubectl = `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
case " $* " in
  *" get configmap bundle-state "*) [[ -z "${STUB_STATE_JSON:-}" ]] || printf '%s' "$STUB_STATE_JSON"; exit 0 ;;
  *" create -f - "*) cat >"$STUB_CREATED"; exit 0 ;;
  *" get applications -o json "*)
    cut -d= -f1 "$POC_BUILD_ROOT/${CELL:-management}/published.env" | jq -Rn '{items: [inputs | {metadata: {name: ., namespace: "x"},
      status: {sync: {status: "Synced", revision: "sha256:1"}, health: {status: "Healthy"}}}]}'
    exit 0 ;;
  *" -A -l "*" -o json "*) echo '{"items":[]}'; exit 0 ;;
esac
exit 0
`

// upRoot makes a root for up.sh in the cell dev-cell-1: every render and facts.sh is a stub, publish.sh and bundle.sh log their call and
// write published.env, and publish.sh writes root.json, as the real scripts do.
func upRoot(t *testing.T) (root, logFile string) {
	t.Helper()
	root, logFile = linkRoot(t)
	write := func(path, content string) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("bin/kubectl", upKubectl)
	write("scripts/attest-wait.sh", "#!/usr/bin/env bash\ntrue\n")
	write("scripts/publish.sh", `#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
echo publish >>"$STUB_LOG"
{ for e in "${COMPONENTS[@]}"; do echo "${e%%:*}=sha256:1"; done; echo root=sha256:1; } >"$PUBLISHED"
jq -nc '{digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", manifest: "Ym9vdA==", components: {argocd: "sha256:1", "cell-system": "sha256:1"}}' >"$BUILD/root.json"
`)
	write("scripts/bundle.sh", `#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
echo "bundle.sh $*" >>"$STUB_LOG"
{ for e in "${COMPONENTS[@]}"; do echo "${e%%:*}=sha256:1"; done; echo root=sha256:1; } >"$PUBLISHED"
`)
	return root, logFile
}

// harnessApplyIndex returns the index of the call that applies the hydrated bundle of a component, or -1.
func harnessApplyIndex(calls, component string) int {
	return callIndex(calls, "apply --server-side --force-conflicts -f ", "/build/dev-cell-1/bundles/"+component+"/manifests.yaml")
}

func runUp(t *testing.T, root, logFile string, env ...string) (string, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "up.sh"))
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "CELL_UP_SKIP_LINK=1", "UP_WAIT=20", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + logFile,
		"STUB_CREATED=" + filepath.Join(root, "created.json")}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("up.sh failed: %v\n%s", err, out)
	}
	calls, _ := os.ReadFile(logFile)
	return string(out), string(calls)
}

// TestUpSignedPathSkipsBootstrapApply: in a cluster whose state has source signed, cell:up applies neither the bootstrap bundles
// (namespaces, argocd, cell-system) nor the root Application, and it does not run publish.sh, which would overwrite a signed root.
// It runs bundle.sh publish --target <cluster> --wait instead, and then applies the harness components. A bootstrap state, or no state,
// keeps the M6 order: the three applies, the root, publish.sh, and no bundle.sh.
func TestUpSignedPathSkipsBootstrapApply(t *testing.T) {
	applied := func(calls, component string) bool { return harnessApplyIndex(calls, component) >= 0 }
	t.Run("signed", func(t *testing.T) {
		root, logFile := upRoot(t)
		_, calls := runUp(t, root, logFile, `STUB_STATE_JSON={"source":"signed","state":"healthy"}`)
		for _, c := range []string{"namespaces", "argocd", "cell-system"} {
			if applied(calls, c) {
				t.Errorf("a signed cluster applies the bootstrap bundle %s:\n%s", c, calls)
			}
		}
		for _, bad := range []string{"bootstrap/root.yaml", "\npublish\n", " create -f -"} {
			if strings.Contains(calls, bad) {
				t.Errorf("a signed cluster ran %q:\n%s", bad, calls)
			}
		}
		pub := callIndex(calls, "bundle.sh publish --target dev-cell-1 --wait")
		harness := harnessApplyIndex(calls, "cell-identity")
		if pub < 0 || harness < 0 || pub > harness {
			t.Errorf("want bundle.sh publish before the harness apply (%d, %d):\n%s", pub, harness, calls)
		}
		if n := strings.Count(calls, "bundle.sh "); n != 1 {
			t.Errorf("bundle.sh ran %d times, want once", n)
		}
	})
	for name, env := range map[string][]string{"bootstrap state": {`STUB_STATE_JSON={"source":"bootstrap","state":"healthy"}`}, "no state": nil} {
		t.Run(name, func(t *testing.T) {
			root, logFile := upRoot(t)
			_, calls := runUp(t, root, logFile, env...)
			for _, c := range []string{"namespaces", "argocd", "cell-system"} {
				if !applied(calls, c) {
					t.Errorf("the bootstrap bundle %s is not applied:\n%s", c, calls)
				}
			}
			if !strings.Contains(calls, "bootstrap/root.yaml") || !strings.Contains(calls, "\npublish\n") || strings.Contains(calls, "bundle.sh") {
				t.Errorf("want the root, publish.sh and no bundle.sh:\n%s", calls)
			}
			ns, argo, cs, pub := harnessApplyIndex(calls, "namespaces"), harnessApplyIndex(calls, "argocd"), harnessApplyIndex(calls, "cell-system"), callIndex(calls, "publish")
			if !(ns < argo && argo < cs && cs < pub) {
				t.Errorf("the order of the bootstrap is wrong (%d %d %d %d):\n%s", ns, argo, cs, pub, calls)
			}
		})
	}
	t.Run("a state that cannot be read stops the run", func(t *testing.T) {
		root, logFile := upRoot(t)
		if err := os.WriteFile(filepath.Join(root, "bin", "kubectl"), []byte(`#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
if [[ " $* " == *" get configmap bundle-state "* ]]; then echo "error: connection refused" >&2; exit 1; fi
exit 0
`), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(root, "scripts", "up.sh"))
		cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"), "CELL=dev-cell-1", "CELL_UP_SKIP_LINK=1", "UP_WAIT=5",
			"POC_BUILD_ROOT="+filepath.Join(root, "build"), "STUB_LOG="+logFile)
		out, err := cmd.CombinedOutput()
		calls, _ := os.ReadFile(logFile)
		if err == nil || !strings.Contains(string(out), "state") || strings.Contains(string(calls), "apply --server-side") {
			t.Errorf("err %v, output %q, calls:\n%s", err, out, calls)
		}
	})
}

// TestUpBootstrapWritesState: after the harness apply, a cluster with a bundle role and no bundle-state gets the bootstrap state: the
// ConfigMap cell-ops-system/bundle-state with the marker poc.internal/made-by=bundle-bootstrap, written with kubectl create, so a
// state that celld wrote first is never replaced. It holds the root digest, the root manifest and the component digests of root.json,
// state healthy and no good root and no version. A cluster that has a state of any source, and a cluster of role open, get none.
func TestUpBootstrapWritesState(t *testing.T) {
	root, logFile := upRoot(t)
	_, calls := runUp(t, root, logFile)
	create := callIndex(calls, "kubectl --context kind-dev-cell-1 -n cell-ops-system create -f -")
	harness := harnessApplyIndex(calls, "cell-identity")
	if create < 0 || harness < 0 || create < harness {
		t.Fatalf("want one create of the state after the harness apply (%d, %d):\n%s", create, harness, calls)
	}
	if n := strings.Count(calls, " create -f -"); n != 1 {
		t.Errorf("%d creates, want 1", n)
	}
	if callIndex(calls, "-n cell-ops-system get configmap bundle-state") > create {
		t.Errorf("the state is read after the create:\n%s", calls)
	}
	raw, err := os.ReadFile(filepath.Join(root, "created.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		APIVersion, Kind string
		Metadata         struct {
			Name, Namespace string
			Labels          map[string]string
		}
		Data map[string]string
	}
	if err := json.Unmarshal(raw, &cm); err != nil {
		t.Fatalf("the created object is no JSON: %v\n%s", err, raw)
	}
	if cm.Kind != "ConfigMap" || cm.APIVersion != "v1" || cm.Metadata.Name != "bundle-state" || cm.Metadata.Namespace != "cell-ops-system" ||
		cm.Metadata.Labels["poc.internal/made-by"] != "bundle-bootstrap" || len(cm.Metadata.Labels) != 1 || len(cm.Data) != 1 {
		t.Fatalf("the created object is %s", raw)
	}
	var st bundleapply.State
	if err := record.DecodeStrict([]byte(cm.Data["state.json"]), &st); err != nil {
		t.Fatalf("the engine cannot read the state: %v\n%s", err, cm.Data["state.json"])
	}
	if st.Source != "bootstrap" || st.State != "healthy" || st.Root.Digest != "sha256:1111111111111111111111111111111111111111111111111111111111111111" ||
		string(st.Root.Manifest) != "boot" || st.Components["argocd"] != "sha256:1" || st.Components["cell-system"] != "sha256:1" || len(st.Components) != 2 ||
		st.Version.Epoch != 0 || st.Version.Counter != 0 || st.ContentSHA256 != "" || st.KeySHA256 != "" || st.OpID != "" || st.Holder != "" || len(st.Good) != 0 || st.Result != nil {
		t.Errorf("the bootstrap state is %+v", st)
	}

	for _, state := range []string{"bootstrap", "signed"} {
		t.Run("existing "+state+" state", func(t *testing.T) {
			root, logFile := upRoot(t)
			_, calls := runUp(t, root, logFile, `STUB_STATE_JSON={"source":"`+state+`","state":"healthy"}`)
			if strings.Contains(calls, " create -f -") {
				t.Errorf("a state exists, and up.sh created one:\n%s", calls)
			}
		})
	}
	t.Run("role open", func(t *testing.T) {
		root, logFile := upRoot(t)
		_, calls := runUp(t, root, logFile, "CELL=management")
		if strings.Contains(calls, "bundle-state") || strings.Contains(calls, " create -f -") {
			t.Errorf("management has no bundle state:\n%s", calls)
		}
	})
}
