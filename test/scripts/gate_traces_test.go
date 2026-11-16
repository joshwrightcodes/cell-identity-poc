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

// TestRepairOrderPodsIssuersBeforeApps: istiod comes after the node pods and before every app pod, also when the app pod sits in a namespace that
// sorts first. An app pod that waits for a certificate from an istiod with a token of the old key would otherwise stall the repair. The match uses
// the label app.kubernetes.io/name. A SPIRE server pod gets no rank of its own.
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
		for _, issuer := range []string{"istiod-7f"} {
			if pos[issuer] >= pos[app] {
				t.Errorf("order %q puts %s before %s, want the issuer first", lines, app, issuer)
			}
		}
	}
}

// controlPlaneStubs defines k and on_node for the step 3 checks of gate-m2-repair.sh. k prints a Lease from $D/lease-<name>.json. on_node answers
// date +%s with $D/now, crictl ps with $D/id-<name>, and crictl inspect with $D/inspect-<id>.json. The file $D/crictl-fails makes every crictl call fail.
const controlPlaneStubs = `
stopped() { [ -e "$D/stopped-$(cat "$D/id-$1" 2>/dev/null)" ]; }
k() {
  case "$*" in
    "-n kube-system get lease "*)
      if [ -e "$D/lease-${5}-before.json" ] && ! stopped "${5}"; then cat "$D/lease-${5}-before.json"; else cat "$D/lease-${5}.json"; fi ;;
    *) echo "unexpected k call: $*" >&2; return 2 ;;
  esac
}
on_node() {
  case "$1 $2" in
    "date +%s") cat "$D/now" ;;
    "crictl ps") [ -e "$D/crictl-fails" ] && return 1; name="${4#^}"; name="${name%\$}"
      if stopped "$name" && [ -e "$D/id-$name-after" ]; then cat "$D/id-$name-after"; else cat "$D/id-$name" 2>/dev/null; fi; return 0 ;;
    "crictl inspect") [ -e "$D/crictl-fails" ] && return 1; cat "$D/inspect-$3.json" ;;
    "crictl stop") [ -e "$D/stop-fails" ] && return 1; : >"$D/stopped-$3"; echo "$3" >>"$D/stop-log" ;;
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

// TestContainerStarted: the start of a container comes from the container runtime, in epoch seconds. A container that does not run gives status 1, and a failed runtime
// call gives status 2, so that the repair can stop with an error and not treat the failure as "no container".
func TestContainerStarted(t *testing.T) {
	testtool.Need(t, "jq", "bash")
	dir := t.TempDir()
	writeStubs(t, dir, map[string]string{"id-kube-apiserver": "abc\n", "inspect-abc.json": `{"status":{"state":"CONTAINER_RUNNING","startedAt":"2026-11-16T03:20:58.438809979Z"}}`})
	out, err := sourceLib(t, dir, "D="+dir+"\n"+controlPlaneStubs+`container_started kube-apiserver`)
	if err != nil || strings.TrimSpace(out) != "1794799258" {
		t.Fatalf("started %q (%v), want 1794799258", out, err)
	}
	out, err = sourceLib(t, dir, "D="+dir+"\n"+controlPlaneStubs+`container_started kube-scheduler || echo "status $?"`)
	if !strings.Contains(out, "status 1") {
		t.Fatalf("a container that does not run gave %q (%v), want status 1", out, err)
	}
	writeStubs(t, dir, map[string]string{"crictl-fails": ""})
	out, _ = sourceLib(t, dir, "D="+dir+"\n"+controlPlaneStubs+`container_started kube-apiserver || echo "status $?"`)
	if !strings.Contains(out, "status 2") {
		t.Fatalf("a failed runtime call gave %q, want status 2", out)
	}
}

// TestControlPlaneCurrent: step 3 passes only when each of kube-controller-manager and kube-scheduler runs a container that started at or after the API
// server, and holds a live Lease with the node as holder. For a container that the repair stopped, the Lease needs a new holder or an acquire
// time at or after the stop: the old process renewed its Lease against the new API server before the stop, so a late renew time alone is no proof.
func TestControlPlaneCurrent(t *testing.T) {
	testtool.Need(t, "jq", "bash")
	const apiStart = "1794799258" // 2026-11-16T03:20:58Z
	node := "dev-cell-1-control-plane"
	lease := func(holder, acquire, renew string) string {
		return `{"spec":{"holderIdentity":"` + holder + `","acquireTime":"` + acquire + `","renewTime":"` + renew + `","leaseDurationSeconds":15}}`
	}
	inspect := func(started string) string { return `{"status":{"startedAt":"` + started + `"}}` }
	// base is a control plane that is current: both containers started 03:25:30, after the API server, and both Leases were renewed at 03:25:38.
	base := func(over map[string]string) map[string]string {
		m := map[string]string{
			"now":                        "1794799550", // 03:25:50
			"id-kube-controller-manager": "m1\n", "inspect-m1.json": inspect("2026-11-16T03:25:30.1Z"),
			"id-kube-scheduler": "s1\n", "inspect-s1.json": inspect("2026-11-16T03:25:31.1Z"),
			"lease-kube-controller-manager.json": lease(node+"_new", "2026-11-16T03:25:35.000000Z", "2026-11-16T03:25:48.569171Z"),
			"lease-kube-scheduler.json":          lease(node+"_s", "2026-11-16T03:25:36.000000Z", "2026-11-16T03:25:48.000000Z")}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
		args  []string // the holder before the stop and the stop time of the manager, then of the scheduler
		want  bool
	}{
		{"both started after the API server and hold live Leases", base(nil), nil, true},
		{"a manager that started before the API server, with a stale mirror status", base(map[string]string{
			"inspect-m1.json": inspect("2026-11-16T03:00:05Z")}), nil, false},
		{"a Lease renewed before the API start and older than its duration", base(map[string]string{
			"lease-kube-controller-manager.json": lease(node+"_new", "2026-11-16T03:00:06.000000Z", "2026-11-16T03:20:33.000000Z")}), nil, false},
		{"the scheduler Lease is old", base(map[string]string{
			"lease-kube-scheduler.json": lease(node+"_s", "2026-11-16T03:00:00.000000Z", "2026-11-16T03:20:00.000000Z")}), nil, false},
		{"another node holds the Lease", base(map[string]string{
			"lease-kube-controller-manager.json": lease("other-node_new", "2026-11-16T03:25:35.000000Z", "2026-11-16T03:25:48.000000Z")}), nil, false},
		{"a Lease with no holder", base(map[string]string{
			"lease-kube-controller-manager.json": `{"spec":{"renewTime":"2026-11-16T03:25:48.000000Z"}}`}), nil, false},
		{"a stopped manager whose old process renewed the Lease after the API start", base(map[string]string{
			"lease-kube-controller-manager.json": lease(node+"_old", "2026-11-16T03:10:00.000000Z", "2026-11-16T03:25:48.000000Z")}),
			[]string{node + "_old", "1794799540"}, false},
		{"a stopped manager with a new holder", base(nil), []string{node + "_old", "1794799540"}, true},
		{"a stopped manager with the same holder and an acquire time after the stop", base(map[string]string{
			"lease-kube-controller-manager.json": lease(node+"_old", "2026-11-16T03:25:45.000000Z", "2026-11-16T03:25:48.000000Z")}),
			[]string{node + "_old", "1794799540"}, true},
		{"the runtime call fails", base(map[string]string{"crictl-fails": ""}), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeStubs(t, dir, tc.files)
			out, err := sourceLib(t, dir, "D="+dir+"\n"+controlPlaneStubs+`control_plane_current "$@"`, append([]string{node, apiStart}, tc.args...)...)
			if (err == nil) != tc.want {
				t.Fatalf("control_plane_current passed %v (%v: %s), want %v", err == nil, err, out, tc.want)
			}
		})
	}
}

// TestSettleControlPlane runs the real stop path of step 3 against a stateful stub of the container runtime and the Leases. A stub container that
// started before the API server is stopped, and the stub then shows a new container. The step reads the Lease holder before the stop, so
// the old process, which renewed its Lease after the API start, must not pass, and a Lease with a new holder or a later acquire time must.
func TestSettleControlPlane(t *testing.T) {
	testtool.Need(t, "jq", "bash")
	const apiStart = "1794799258" // 2026-11-16T03:20:58Z
	node := "dev-cell-1-control-plane"
	lease := func(holder, acquire, renew string) string {
		return `{"spec":{"holderIdentity":"` + holder + `","acquireTime":"` + acquire + `","renewTime":"` + renew + `","leaseDurationSeconds":15}}`
	}
	inspect := func(started string) string { return `{"status":{"startedAt":"` + started + `"}}` }
	// The stale manager (container m0) started at 03:00:05. After the stop, the container m1 shows. The scheduler (container s1) is current.
	// The node time is 03:25:50 (1794799550).
	base := func(over map[string]string) map[string]string {
		m := map[string]string{
			"now":                        "1794799550",
			"id-kube-controller-manager": "m0\n", "id-kube-controller-manager-after": "m1\n",
			"inspect-m0.json": inspect("2026-11-16T03:00:05Z"), "inspect-m1.json": inspect("2026-11-16T03:25:30.1Z"),
			"id-kube-scheduler": "s1\n", "inspect-s1.json": inspect("2026-11-16T03:25:31.1Z"),
			"lease-kube-controller-manager-before.json": lease(node+"_old", "2026-11-16T03:10:00.000000Z", "2026-11-16T03:25:40.000000Z"),
			"lease-kube-scheduler.json":                 lease(node+"_s", "2026-11-16T03:25:36.000000Z", "2026-11-16T03:25:48.000000Z")}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		name    string
		files   map[string]string
		wantOK  bool
		wantLog []string
		noLog   []string
	}{
		{"the old process renews its Lease after the stop", base(map[string]string{
			"lease-kube-controller-manager.json": lease(node+"_old", "2026-11-16T03:10:00.000000Z", "2026-11-16T03:25:48.000000Z")}), false,
			[]string{"stopped the kube-controller-manager container", "Lease holder before the stop '" + node + "_old', stop time 1794799550", "not current after 2s"},
			[]string{"let the wait pass"}},
		{"the new process holds the Lease with a new holder", base(map[string]string{
			"lease-kube-controller-manager.json": lease(node+"_new", "2026-11-16T03:25:45.000000Z", "2026-11-16T03:25:48.000000Z")}), true,
			[]string{"Lease holder before the stop '" + node + "_old', stop time 1794799550",
				"Lease of kube-controller-manager let the wait pass: holder " + node + "_new, acquireTime 2026-11-16T03:25:45.000000Z"}, nil},
		{"the same holder with an acquire time after the stop", base(map[string]string{
			"lease-kube-controller-manager.json": lease(node+"_old", "2026-11-16T03:25:50.000000Z", "2026-11-16T03:25:51.000000Z")}), true,
			[]string{"acquireTime 2026-11-16T03:25:50.000000Z"}, nil},
		{"no container started before the API server", base(map[string]string{
			"id-kube-controller-manager": "m1\n", "lease-kube-controller-manager.json": lease(node+"_new", "2026-11-16T03:25:45.000000Z", "2026-11-16T03:25:48.000000Z")}), true,
			nil, []string{"stopped the"}},
		{"the container runtime call fails", base(map[string]string{"crictl-fails": ""}), false,
			[]string{"the container runtime call failed"}, []string{"stopped the"}},
		{"the stop fails", base(map[string]string{"stop-fails": ""}), false,
			[]string{"cannot stop the container m0 of kube-controller-manager"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeStubs(t, dir, tc.files)
			out, err := sourceLib(t, dir, "D="+dir+"\nexport CONTROL_PLANE_POLL=1\n"+controlPlaneStubs+`settle_control_plane "$1" "$2" 2`, node, apiStart)
			if (err == nil) != tc.wantOK {
				t.Fatalf("settle_control_plane passed %v (%v), want %v\n%s", err == nil, err, tc.wantOK, out)
			}
			for _, w := range tc.wantLog {
				if !strings.Contains(out, w) {
					t.Errorf("the log lacks %q\n%s", w, out)
				}
			}
			for _, w := range tc.noLog {
				if strings.Contains(out, w) {
					t.Errorf("the log has %q\n%s", w, out)
				}
			}
		})
	}
}
