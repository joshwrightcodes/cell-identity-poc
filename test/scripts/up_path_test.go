package scripts

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
  *" apply "*" -f - "*) n=$(($(cat "$STUB_APPLIED/count" 2>/dev/null || echo 0) + 1)); echo "$n" >"$STUB_APPLIED/count"; cat >"$STUB_APPLIED/applied-$n.yaml"; exit 0 ;;
  *" get statefulset bundle-store "*)
    # STUB_STS_SEQ (JSON documents separated by |) answers the successive reads, the last one for every later read, as the controller catches up.
    if [[ -n "${STUB_STS_SEQ:-}" ]]; then
      n=$(($(cat "$STUB_APPLIED/sts-reads" 2>/dev/null || echo 0) + 1)); echo "$n" >"$STUB_APPLIED/sts-reads"
      IFS='|' read -r -a seq <<<"$STUB_STS_SEQ"; i=$((n - 1)); ((i < ${#seq[@]})) || i=$((${#seq[@]} - 1)); printf '%s' "${seq[$i]}"; exit 0
    fi
    [[ -z "${STUB_STS_JSON:-}" ]] || printf '%s' "$STUB_STS_JSON"; exit 0 ;;
  *" get networkpolicy bundle-store "*) [[ -z "${STUB_NP_JSON:-}" ]] || printf '%s' "$STUB_NP_JSON"; exit 0 ;;
  *" get pod bundle-store-0 "*) [[ -z "${STUB_POD_JSON:-}" ]] || printf '%s' "$STUB_POD_JSON"; exit 0 ;;
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
	if err := os.MkdirAll(filepath.Join(root, "applied"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The renders of network-policy and cell-system hold the objects of the store, as the real bundles do.
	write("components/network-policy/render.sh", `#!/usr/bin/env bash
echo "render network-policy" >>"$STUB_LOG"
cat <<'EOF2'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: bundle-store, namespace: cell-system}
spec:
  podSelector: {matchLabels: {app.kubernetes.io/name: bundle-store}}
  policyTypes: [Egress]
  egress: [{ports: [{port: 4317}]}, {ports: [{port: 4318}]}, {ports: [{port: 443}]}]
EOF2
`)
	write("components/cell-system/render.sh", `#!/usr/bin/env bash
echo "render cell-system" >>"$STUB_LOG"
cat <<'EOF2'
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: bundle-store, namespace: cell-system}
spec:
  template:
    spec:
      containers:
        - {name: bundle-store, image: registry}
        - {name: store-proxy, image: proxy}
EOF2
`)
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
	return harnessApplyIndexIn(calls, "dev-cell-1", component)
}

func harnessApplyIndexIn(calls, cluster, component string) int {
	return callIndex(calls, "apply --server-side --force-conflicts -f ", "/build/"+cluster+"/bundles/"+component+"/manifests.yaml")
}

func runUp(t *testing.T, root, logFile string, env ...string) (string, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "up.sh"))
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "CELL_UP_SKIP_LINK=1", "UP_WAIT=20", "POC_BUILD_ROOT=" + filepath.Join(root, "build"), "STUB_LOG=" + logFile,
		"STUB_CREATED=" + filepath.Join(root, "created.json"), "STUB_APPLIED=" + filepath.Join(root, "applied")}, env...)
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
	t.Parallel()
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
	t.Parallel()
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

const (
	trackNP  = "cell-system:networking.k8s.io/NetworkPolicy:cell-system/bundle-store"
	trackSTS = "cell-system:apps/StatefulSet:cell-system/bundle-store"
)

func objJSON(kind, track, extra string) string {
	return `{"kind":"` + kind + `","metadata":{"name":"bundle-store","annotations":{"argocd.argoproj.io/tracking-id":"` + track + `"}}` + extra + `}`
}

const (
	staleSTS = `,"spec":{"template":{"spec":{"containers":[{"name":"bundle-store","readinessProbe":{"httpGet":{"path":"/v2/","port":"http"}},"ports":[{"name":"http","containerPort":5000}]},{"name":"store-proxy"}]}}}` + revSTS
	freshSTS = `,"spec":{"template":{"spec":{"containers":[{"name":"bundle-store"},{"name":"store-proxy","ports":[{"name":"http","containerPort":5000}]}]}}}` + revSTS
	podReady = `{"metadata":{"labels":{"controller-revision-hash":"bundle-store-rev2"}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}`
	// podStuck belongs to an earlier revision than the StatefulSet (rev2) and never became Ready. podStarting is a pod of the current revision.
	podStuck    = `{"metadata":{"labels":{"controller-revision-hash":"bundle-store-rev1"}},"status":{"conditions":[{"type":"Ready","status":"False"}]}}`
	podStarting = `{"metadata":{"labels":{"controller-revision-hash":"bundle-store-rev2"}},"status":{"conditions":[{"type":"Ready","status":"False"}]}}`
	revSTS      = `,"status":{"updateRevision":"bundle-store-rev2"}`
)

// storeApplies returns the objects that the store upgrade applied, by kind, with the call that applied each.
func storeApplies(t *testing.T, root, calls string) (map[string]string, []string) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(root, "applied", "applied-*.yaml"))
	out := map[string]string{}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, kind := range []string{"NetworkPolicy", "StatefulSet"} {
			if strings.Contains(string(b), "kind: "+kind) {
				out[kind] = string(b)
			}
		}
	}
	var lines []string
	for _, l := range strings.Split(calls, "\n") {
		if strings.Contains(l, "--field-manager=argocd-controller") {
			lines = append(lines, l)
		}
	}
	return out, lines
}

// TestUpStoreUpgrade: a cluster that moves from M7 to M8 keeps fields that Argo CD owned in the M7 store (the registry probe and port), and its
// store policy lacks the API egress, which only the Argo CD set carries, so the proxy cannot review a token and Argo CD cannot sync. After the
// bootstrap apply, up.sh applies the rendered NetworkPolicy and StatefulSet of the store with the field manager argocd-controller, keeps the
// tracking annotation, and deletes a store pod that never became Ready. A new cluster and an upgraded cluster get no StatefulSet apply and no
// pod delete.
func TestUpStoreUpgrade(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		env        []string
		wantNP     bool
		wantSTS    bool
		wantDelete bool
	}{
		{"M7 store with a stuck pod", []string{"STUB_NP_JSON=" + objJSON("NetworkPolicy", trackNP, ""), "STUB_STS_JSON=" + objJSON("StatefulSet", trackSTS, staleSTS), "STUB_POD_JSON=" + podStuck}, true, true, true},
		{"M7 store with a Ready pod", []string{"STUB_NP_JSON=" + objJSON("NetworkPolicy", trackNP, ""), "STUB_STS_JSON=" + objJSON("StatefulSet", trackSTS, staleSTS), "STUB_POD_JSON=" + podReady}, true, true, false},
		{"upgraded store", []string{"STUB_NP_JSON=" + objJSON("NetworkPolicy", trackNP, ""), "STUB_STS_JSON=" + objJSON("StatefulSet", trackSTS, freshSTS), "STUB_POD_JSON=" + podReady}, true, false, false},
		{"new cluster", nil, false, false, false},
		{"new cluster with a starting pod", []string{"STUB_STS_JSON=" + objJSON("StatefulSet", "", freshSTS), "STUB_POD_JSON=" + podStarting}, false, false, false},
		// A rerun after an interrupted upgrade: the template is fixed already, and the pod of the old revision never became Ready.
		{"fixed template and a stuck pod of the old revision", []string{"STUB_NP_JSON=" + objJSON("NetworkPolicy", trackNP, ""), "STUB_STS_JSON=" + objJSON("StatefulSet", trackSTS, freshSTS), "STUB_POD_JSON=" + podStuck}, true, false, true},
		{"a policy that Argo CD does not manage", []string{"STUB_NP_JSON=" + objJSON("NetworkPolicy", "", ""), "STUB_STS_JSON=" + objJSON("StatefulSet", trackSTS, freshSTS), "STUB_POD_JSON=" + podReady}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, logFile := upRoot(t)
			_, calls := runUp(t, root, logFile, tc.env...)
			objs, lines := storeApplies(t, root, calls)
			for kind, want := range map[string]bool{"NetworkPolicy": tc.wantNP, "StatefulSet": tc.wantSTS} {
				if _, got := objs[kind]; got != want {
					t.Errorf("applied %s = %v, want %v:\n%s", kind, got, want, calls)
				}
			}
			for _, l := range lines {
				if !strings.Contains(l, "apply --server-side --field-manager=argocd-controller --force-conflicts -f -") {
					t.Errorf("the apply call is %q", l)
				}
			}
			if tc.wantNP && !strings.Contains(objs["NetworkPolicy"], trackNP) {
				t.Errorf("the NetworkPolicy lost the tracking annotation:\n%s", objs["NetworkPolicy"])
			}
			if tc.wantSTS && (!strings.Contains(objs["StatefulSet"], trackSTS) || strings.Contains(objs["StatefulSet"], "readinessProbe")) {
				t.Errorf("the StatefulSet is %s, want the tracking annotation and no probe", objs["StatefulSet"])
			}
			del := callIndex(calls, "-n cell-system delete pod bundle-store-0")
			if (del >= 0) != tc.wantDelete {
				t.Errorf("delete of the store pod = %v, want %v:\n%s", del >= 0, tc.wantDelete, calls)
			}
			if tc.wantDelete {
				if wait := callIndex(calls, "rollout status statefulset/bundle-store"); !(del >= 0 && del < wait) {
					t.Errorf("the pod delete (%d) is not before the wait for the store (%d)", del, wait)
				}
			}
			// The upgrade runs after the bootstrap apply of cell-system and before the wait for the store.
			if tc.wantSTS {
				boot, up, wait := harnessApplyIndex(calls, "cell-system"), callIndex(calls, "--field-manager=argocd-controller"), callIndex(calls, "rollout status statefulset/bundle-store")
				if !(boot < up && up < wait) {
					t.Errorf("order: bootstrap apply %d, upgrade %d, rollout wait %d:\n%s", boot, up, wait, calls)
				}
				if tc.wantDelete && !(up < del && del < wait) {
					t.Errorf("the pod delete (%d) is not between the upgrade (%d) and the wait (%d)", del, up, wait)
				}
			}
		})
	}
	t.Run("the signed path runs no upgrade", func(t *testing.T) {
		root, logFile := upRoot(t)
		_, calls := runUp(t, root, logFile, `STUB_STATE_JSON={"source":"signed"}`, "STUB_STS_JSON="+objJSON("StatefulSet", trackSTS, staleSTS), "STUB_NP_JSON="+objJSON("NetworkPolicy", trackNP, ""))
		if strings.Contains(calls, "field-manager") {
			t.Errorf("the signed path upgraded the store:\n%s", calls)
		}
	})
}

// TestUpCpRerendersEnvdAfterPublish: in dev-cp, the signed path publishes a signed set, and then renders envd again and applies it, before the
// wait for the Applications. envd holds the harness plane policies of dev-cp (plane-cells for the live cells), and the signed set no longer
// carries those rules, so a cell:up of dev-cp that left envd as it was would leave the node address of a new cell out. up.sh logs the command
// of the publish. A cell renders nothing between the publish and the wait, and the bootstrap path of dev-cp has no signed publish.
func TestUpCpRerendersEnvdAfterPublish(t *testing.T) {
	t.Parallel()
	waitIndex := func(calls string, after int) int {
		lines := strings.Split(calls, "\n")
		for i := after + 1; i < len(lines); i++ {
			if strings.Contains(lines[i], "-n argocd get applications -o json") {
				return i
			}
		}
		return -1
	}
	t.Run("signed dev-cp", func(t *testing.T) {
		root, logFile := upRoot(t)
		out, calls := runUp(t, root, logFile, "CELL=dev-cp", `STUB_STATE_JSON={"source":"signed","state":"healthy"}`)
		if !strings.Contains(out, "bundle.sh publish --target dev-cp") {
			t.Errorf("up.sh does not log the publish command:\n%s", out)
		}
		pub := callIndex(calls, "bundle.sh publish --target dev-cp --wait")
		wait := waitIndex(calls, pub)
		render, apply := callIndex(calls, "render envd"), harnessApplyIndexIn(calls, "dev-cp", "envd")
		if pub < 0 || !(pub < render && render < apply && apply < wait) {
			t.Errorf("order: publish %d, render envd %d, apply envd %d, wait %d:\n%s", pub, render, apply, wait, calls)
		}
		if n := strings.Count(calls, "render spire-server"); n != 1 {
			t.Errorf("envd alone is rendered again, and spire-server was rendered %d times, want once", n)
		}
	})
	t.Run("a cell renders nothing between the publish and the wait", func(t *testing.T) {
		root, logFile := upRoot(t)
		_, calls := runUp(t, root, logFile, `STUB_STATE_JSON={"source":"signed","state":"healthy"}`)
		pub := callIndex(calls, "bundle.sh publish --target dev-cell-1 --wait")
		wait := waitIndex(calls, pub)
		lines := strings.Split(calls, "\n")
		for i := pub + 1; i < wait; i++ {
			if strings.HasPrefix(lines[i], "render ") || strings.Contains(lines[i], " apply ") {
				t.Errorf("a cell does %q between the publish and the wait", lines[i])
			}
		}
	})
	t.Run("the bootstrap path of dev-cp", func(t *testing.T) {
		root, logFile := upRoot(t)
		_, calls := runUp(t, root, logFile, "CELL=dev-cp")
		pub := slices.Index(strings.Split(calls, "\n"), "publish")
		if strings.Contains(calls, "bundle.sh") || pub < 0 {
			t.Fatalf("the bootstrap path ran bundle.sh or no publish.sh:\n%s", calls)
		}
		wait := waitIndex(calls, pub)
		lines := strings.Split(calls, "\n")
		for i := pub + 1; i < wait; i++ {
			if strings.HasPrefix(lines[i], "render ") {
				t.Errorf("the bootstrap path renders %q before the wait", lines[i])
			}
		}
	})
}

// TestUpCpBootstrapWritesState: dev-cp keeps its bundle state in envd-system. A cluster with no state gets the bootstrap state there, after the
// harness apply of envd, from build/dev-cp/root.json.
func TestUpCpBootstrapWritesState(t *testing.T) {
	t.Parallel()
	root, logFile := upRoot(t)
	_, calls := runUp(t, root, logFile, "CELL=dev-cp")
	create := callIndex(calls, "kubectl --context kind-dev-cp -n envd-system create -f -")
	apply := harnessApplyIndexIn(calls, "dev-cp", "envd")
	if create < 0 || apply < 0 || create < apply {
		t.Fatalf("want one create of the state in envd-system after the harness apply of envd (%d, %d):\n%s", create, apply, calls)
	}
	var cm struct {
		Metadata struct {
			Name, Namespace string
			Labels          map[string]string
		}
		Data map[string]string
	}
	raw, _ := os.ReadFile(filepath.Join(root, "created.json"))
	if err := json.Unmarshal(raw, &cm); err != nil || cm.Metadata.Namespace != "envd-system" || cm.Metadata.Name != "bundle-state" || cm.Metadata.Labels["poc.internal/made-by"] != "bundle-bootstrap" {
		t.Fatalf("the created object is %s (%v)", raw, err)
	}
	var st bundleapply.State
	if err := record.DecodeStrict([]byte(cm.Data["state.json"]), &st); err != nil || st.Source != "bootstrap" || st.State != "healthy" || st.Root.Digest == "" {
		t.Errorf("the bootstrap state is %+v (%v)", st, err)
	}
	for _, state := range []string{"bootstrap", "signed"} {
		root, logFile := upRoot(t)
		_, calls := runUp(t, root, logFile, "CELL=dev-cp", `STUB_STATE_JSON={"source":"`+state+`"}`)
		if strings.Contains(calls, " create -f -") {
			t.Errorf("a %s state exists, and up.sh created one", state)
		}
	}
}

// TestUpStoreUpgradeWaitsForTheController: after the StatefulSet apply, the controller needs a moment to move status.updateRevision. A pod of the
// bootstrap revision is "current" until then, so the upgrade waits until observedGeneration reaches the generation before it compares the pod
// with the update revision. With the old read, the stuck pod would stay and the store wait would time out.
func TestUpStoreUpgradeWaitsForTheController(t *testing.T) {
	t.Parallel()
	sts := func(generation, observed int, rev string) string {
		spec := strings.TrimSuffix(staleSTS, revSTS)
		return fmt.Sprintf(`{"kind":"StatefulSet","metadata":{"name":"bundle-store","generation":%d,"annotations":{"argocd.argoproj.io/tracking-id":%q}}%s,"status":{"observedGeneration":%d,"updateRevision":%q}}`,
			generation, trackSTS, spec, observed, rev)
	}
	root, logFile := upRoot(t)
	seq := strings.Join([]string{sts(1, 1, "bundle-store-rev1"), sts(2, 1, "bundle-store-rev1"), sts(2, 1, "bundle-store-rev1"), sts(2, 2, "bundle-store-rev2")}, "|")
	_, calls := runUp(t, root, logFile, "STUB_NP_JSON="+objJSON("NetworkPolicy", trackNP, ""), "STUB_STS_SEQ="+seq, "STUB_POD_JSON="+podStuck)
	if callIndex(calls, "-n cell-system delete pod bundle-store-0") < 0 {
		t.Errorf("the stuck pod of the bootstrap revision was not replaced after the controller caught up:\n%s", calls)
	}
}

// TestUpStoreUpgradeSaysWhenTheControllerLags: when the controller does not catch up within the wait, cell:up stops with the two generations, and
// does not compare the stuck pod with a stale update revision.
func TestUpStoreUpgradeSaysWhenTheControllerLags(t *testing.T) {
	t.Parallel()
	lag := fmt.Sprintf(`{"kind":"StatefulSet","metadata":{"name":"bundle-store","generation":4,"annotations":{"argocd.argoproj.io/tracking-id":%q}}%s,"status":{"observedGeneration":3,"updateRevision":"bundle-store-rev1"}}`, trackSTS, strings.TrimSuffix(staleSTS, revSTS))
	root, logFile := upRoot(t)
	cmd := exec.Command(filepath.Join(root, "scripts", "up.sh"))
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"), "CELL=dev-cell-1", "CELL_UP_SKIP_LINK=1", "UP_WAIT=5",
		"STORE_UPGRADE_WAIT=2", "POC_BUILD_ROOT="+filepath.Join(root, "build"), "STUB_LOG="+logFile, "STUB_CREATED="+filepath.Join(root, "created.json"), "STUB_APPLIED="+filepath.Join(root, "applied"),
		"STUB_NP_JSON="+objJSON("NetworkPolicy", trackNP, ""), "STUB_STS_JSON="+lag, "STUB_POD_JSON="+podStuck)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "generation 4") || !strings.Contains(string(out), "observed 3") {
		t.Errorf("err %v, output %q, want a failure that names generation 4 and observed 3", err, out)
	}
}
