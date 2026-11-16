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

// sourceLib runs a bash snippet after it sources scripts/lib.sh, which sources scripts/gate-traces.sh. The fake mise in dir answers
// mise run mgmt -- status with the content of dir/status, or fails when that file is absent.
func sourceLib(t *testing.T, dir, snippet string, args ...string) (string, error) {
	t.Helper()
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{"-c", `source "$1" && shift && ` + snippet, "bash", lib}, args...)...)
	cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cell-1"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return out.String(), err
}

// TestRecordKidsTrace: gate:m2:repair --check reports a record whose key IDs differ from the API server, with the key check command.
// It reports nothing for equal key IDs, and nothing when mgmtd does not answer.
func TestRecordKidsTrace(t *testing.T) {
	testtool.Need(t, "jq", "bash")
	dir := t.TempDir()
	mise := "#!/usr/bin/env bash\n[[ \"$*\" == 'run mgmt -- status' ]] || exit 2\ncat \"" + dir + "/status\" 2>/dev/null || exit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "mise"), []byte(mise), 0o755); err != nil {
		t.Fatal(err)
	}
	status := func(kids string) {
		body := `{"cells":[{"name":"dev-cell-2","kids":["other"]},{"name":"dev-cell-1","kids":` + kids + `}]}`
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	status(`["b","a"]`)
	if out, err := sourceLib(t, dir, `record_kids_trace dev-cell-1 "a b"`); err != nil || out != "" {
		t.Fatalf("equal key IDs: err %v, output %q, want nothing", err, out)
	}
	status(`["a","test"]`)
	out, err := sourceLib(t, dir, `record_kids_trace dev-cell-1 "a"`)
	want := "the record of dev-cell-1 lists the key IDs 'a test', and the API server publishes 'a'. Run: mise run mgmt -- keycheck --cell dev-cell-1"
	if err != nil || strings.TrimSpace(out) != want {
		t.Fatalf("different key IDs: err %v, output %q, want %q", err, out, want)
	}
	if err := os.Remove(filepath.Join(dir, "status")); err != nil {
		t.Fatal(err)
	}
	if out, err := sourceLib(t, dir, `record_kids_trace dev-cell-1 "a"`); err != nil || out != "" {
		t.Fatalf("mgmtd does not answer: err %v, output %q, want nothing", err, out)
	}
}

// TestRepairOrderPods: the pods of kindnet, kube-proxy and istio-cni-node come before coredns and every other pod, and only the pods with a stale UID
// are listed.
func TestRepairOrderPods(t *testing.T) {
	testtool.Need(t, "jq", "bash")
	pod := func(ns, name, uid, kind, owner string) string {
		return `{"metadata":{"namespace":"` + ns + `","name":"` + name + `","uid":"` + uid + `","ownerReferences":[{"kind":"` + kind + `","name":"` + owner + `"}]}}`
	}
	pods := `{"items":[` + strings.Join([]string{
		pod("kube-system", "coredns-1", "u1", "ReplicaSet", "coredns-559f"),
		pod("apps", "web-1", "u2", "ReplicaSet", "web-1a"),
		pod("kube-system", "kube-proxy-x", "u3", "DaemonSet", "kube-proxy"),
		pod("kube-system", "fresh", "u9", "ReplicaSet", "fresh-1"),
		pod("kube-system", "kindnet-y", "u4", "DaemonSet", "kindnet"),
		pod("local-path-storage", "provisioner", "u5", "ReplicaSet", "provisioner-1"),
		pod("istio-system", "istio-cni-node-z", "u6", "DaemonSet", "istio-cni-node"),
	}, ",") + `]}`
	dir := t.TempDir()
	out, err := sourceLib(t, dir, `printf '%s' "$2" | repair_order_pods "$1"`, `["u1","u2","u3","u4","u5","u6"]`, pods)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 6 {
		t.Fatalf("got %d pods %q, want the 6 with a stale UID", len(lines), lines)
	}
	first := map[string]bool{lines[0]: true, lines[1]: true, lines[2]: true}
	if !first["kube-system kube-proxy-x DaemonSet kube-proxy"] || !first["kube-system kindnet-y DaemonSet kindnet"] || !first["istio-system istio-cni-node-z DaemonSet istio-cni-node"] {
		t.Fatalf("the first three pods are %q, want kindnet, kube-proxy and istio-cni-node before coredns and the others", lines[:3])
	}
	for _, l := range lines[3:] {
		if strings.Contains(l, "fresh") {
			t.Errorf("the pod with a current UID is listed: %s", l)
		}
	}
}

// TestRepairOrderPodsIssuersBeforeApps: a pod that issues certificates or reviews tokens (istiod, the SPIRE server) comes after the
// node pods and before every app pod, also when the app pod sits in a namespace that sorts first. An app pod that waits for a certificate
// from an issuer that still holds a token of the old key would otherwise stall the repair. The match uses the label app.kubernetes.io/name.
func TestRepairOrderPodsIssuersBeforeApps(t *testing.T) {
	testtool.Need(t, "jq", "bash")
	pod := func(ns, name, uid, kind, owner, app string) string {
		return `{"metadata":{"namespace":"` + ns + `","name":"` + name + `","uid":"` + uid + `","labels":{"app.kubernetes.io/name":"` + app + `"},"ownerReferences":[{"kind":"` + kind + `","name":"` + owner + `"}]}}`
	}
	pods := `{"items":[` + strings.Join([]string{
		pod("apps-demo", "client-1", "u1", "ReplicaSet", "client-667d", "client"),
		pod("istio-system", "istiod-7f", "u2", "ReplicaSet", "istiod-7f", "istiod"),
		pod("spire-system", "spire-server-0", "u3", "StatefulSet", "spire-server", "spire-server"),
		pod("istio-system", "istio-cni-node-z", "u4", "DaemonSet", "istio-cni-node", "istio-cni"),
		pod("cell-identity-system", "celld-1", "u5", "ReplicaSet", "celld-6b", "celld"),
	}, ",") + `]}`
	out, err := sourceLib(t, t.TempDir(), `printf '%s' "$2" | repair_order_pods "$1"`, `["u1","u2","u3","u4","u5"]`, pods)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	pos := map[string]int{}
	for i, l := range lines {
		pos[strings.Fields(l)[1]] = i
	}
	if len(lines) != 5 || pos["istio-cni-node-z"] != 0 {
		t.Fatalf("order %q, want istio-cni-node first", lines)
	}
	for _, app := range []string{"client-1", "celld-1"} {
		for _, issuer := range []string{"istiod-7f", "spire-server-0"} {
			if pos[issuer] >= pos[app] {
				t.Errorf("order %q puts %s before %s, want the issuer first", lines, app, issuer)
			}
		}
	}
}

// controlPlaneStubs defines k and on_node for the step 3 checks of gate-m2-repair.sh. k prints a Lease from $D/lease-<name>.json and a mirror pod from
// $D/pod-<name>.json. on_node answers crictl ps with $D/id-<name> and crictl inspect with $D/inspect-<id>.json.
const controlPlaneStubs = `
k() {
  case "$*" in
    "-n kube-system get lease "*) cat "$D/lease-${5}.json" ;;
    "-n kube-system get pod "*) n="${5%-dev-cell-1-control-plane}"; cat "$D/pod-$n.json" ;;
    *) echo "unexpected k call: $*" >&2; return 2 ;;
  esac
}
on_node() {
  case "$1 $2" in
    "crictl ps") name="${4#^}"; name="${name%\$}"; cat "$D/id-$name" 2>/dev/null ;;
    "crictl inspect") cat "$D/inspect-$3.json" ;;
    *) echo "unexpected on_node call: $*" >&2; return 2 ;;
  esac
}
`

func writeStubs(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestContainerStarted: the start of a container comes from the container runtime, in epoch seconds, and a missing container fails.
func TestContainerStarted(t *testing.T) {
	testtool.Need(t, "jq", "bash")
	dir := t.TempDir()
	writeStubs(t, dir, map[string]string{"id-kube-apiserver": "abc\n", "inspect-abc.json": `{"status":{"state":"CONTAINER_RUNNING","startedAt":"2026-11-16T03:20:58.438809979Z"}}`})
	out, err := sourceLib(t, dir, "D="+dir+"\n"+controlPlaneStubs+`container_started kube-apiserver`)
	if err != nil || strings.TrimSpace(out) != "1794799258" {
		t.Fatalf("started %q (%v), want 1794799258", out, err)
	}
	if out, err := sourceLib(t, dir, "D="+dir+"\n"+controlPlaneStubs+`container_started kube-scheduler`); err == nil {
		t.Fatalf("a container that does not run gave %q, want a failure", out)
	}
}

// TestControlPlaneCurrent: step 3 passes only when both Leases name the node as holder and show an acquire or a renew time at or after the
// start of the API server. A stale mirror pod, which shows the old manager as started after the old API server, must not pass it, and neither
// must a Lease that was renewed before the API server start.
func TestControlPlaneCurrent(t *testing.T) {
	testtool.Need(t, "jq", "bash")
	const apiStart = "1794799258" // 2026-11-16T03:20:58Z
	lease := func(holder, acquire, renew string) string {
		return `{"spec":{"holderIdentity":"` + holder + `","acquireTime":"` + acquire + `","renewTime":"` + renew + `"}}`
	}
	node := "dev-cell-1-control-plane"
	// The mirror pods show a manager that started 5 s after the old API server, which is stale: the status was not updated yet.
	stalePod := `{"status":{"containerStatuses":[{"ready":true,"state":{"running":{"startedAt":"2026-11-16T03:00:05Z"}}}]}}`
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"both leases renewed after the API start", map[string]string{
			"lease-kube-controller-manager.json": lease(node+"_u1", "2026-11-16T03:10:00.100000Z", "2026-11-16T03:25:38.569171Z"),
			"lease-kube-scheduler.json":          lease(node+"_u2", "2026-11-16T03:10:00.100000Z", "2026-11-16T03:25:40.000000Z")}, true},
		{"a stale mirror status and a lease renewed before the API start", map[string]string{
			"pod-kube-apiserver.json":            stalePod,
			"pod-kube-controller-manager.json":   stalePod,
			"lease-kube-controller-manager.json": lease(node+"_u1", "2026-11-16T03:00:06.000000Z", "2026-11-16T03:20:33.000000Z"),
			"lease-kube-scheduler.json":          lease(node+"_u2", "2026-11-16T03:10:00.100000Z", "2026-11-16T03:25:40.000000Z")}, false},
		{"the scheduler lease is old", map[string]string{
			"lease-kube-controller-manager.json": lease(node+"_u1", "2026-11-16T03:25:49.000000Z", "2026-11-16T03:25:50.000000Z"),
			"lease-kube-scheduler.json":          lease(node+"_u2", "2026-11-16T03:00:00.000000Z", "2026-11-16T03:20:00.000000Z")}, false},
		{"another node holds the lease", map[string]string{
			"lease-kube-controller-manager.json": lease("other-node_u1", "2026-11-16T03:25:49.000000Z", "2026-11-16T03:25:50.000000Z"),
			"lease-kube-scheduler.json":          lease(node+"_u2", "2026-11-16T03:25:49.000000Z", "2026-11-16T03:25:50.000000Z")}, false},
		{"a lease with no holder", map[string]string{
			"lease-kube-controller-manager.json": `{"spec":{"renewTime":"2026-11-16T03:25:50.000000Z"}}`,
			"lease-kube-scheduler.json":          lease(node+"_u2", "2026-11-16T03:25:49.000000Z", "2026-11-16T03:25:50.000000Z")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeStubs(t, dir, tc.files)
			out, err := sourceLib(t, dir, "D="+dir+"\n"+controlPlaneStubs+`control_plane_current "$1" "$2"`, node, apiStart)
			if (err == nil) != tc.want {
				t.Fatalf("control_plane_current passed %v (%v: %s), want %v", err == nil, err, out, tc.want)
			}
		})
	}
}
