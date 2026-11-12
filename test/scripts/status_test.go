package scripts

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// logsKubectl stands in for kubectl in harness:logs. Each cluster has one pod. The log of a pod has two JSON
// lines, one of them with a field "cluster", a plain line and a JSON line that is no object. STUB_FAIL_CLUSTER
// names a cluster whose API does not answer.
const logsKubectl = `#!/usr/bin/env bash
ctx="$2"
if [[ "$ctx" == "kind-${STUB_FAIL_CLUSTER:-none}" ]]; then echo "the connection was refused" >&2; exit 1; fi
case " $* " in
  *" get pods -A -l "*) echo '{"items":[{"metadata":{"namespace":"ns","name":"pod-1"}}]}' ;;
  *" logs pod-1 "*)
    printf '%s\n' '{"level":"info","msg":"first"}' '{"msg":"second","cluster":"inner"}' 'a plain line' '123' ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

func runScript(t *testing.T, script string, stubs map[string]string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	bin := t.TempDir()
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path, err := filepath.Abs(filepath.Join("../../scripts", script))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{path}, args...)...)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"POC_BUILD_ROOT=" + filepath.Join(bin, "build")}, env...)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errBuf.String(), code
}

func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("a line of standard output is no JSON object: %q", l)
		}
		lines = append(lines, m)
	}
	return lines
}

// TestLogsMergesWithClusterField checks that every output line of harness:logs decodes as JSON with the field
// cluster. A plain line and a JSON line that is no object get the field raw, and a field cluster of a log
// line moves to source_cluster.
func TestLogsMergesWithClusterField(t *testing.T) {
	out, _, code := runScript(t, "logs.sh", map[string]string{"kubectl": logsKubectl}, nil, "all", "app=x")
	lines := jsonLines(t, out)
	if code != 0 || len(lines) != 16 {
		t.Fatalf("exit %d with %d lines, want exit 0 and 16 lines (4 clusters, 4 lines each):\n%s", code, len(lines), out)
	}
	seen := map[string]int{}
	for _, m := range lines {
		c, _ := m["cluster"].(string)
		seen[c]++
		switch {
		case m["msg"] == "second":
			if m["source_cluster"] != "inner" {
				t.Errorf("line %v, want the cluster of the log line in source_cluster", m)
			}
		case m["msg"] == nil && m["raw"] == nil:
			t.Errorf("line %v has neither msg nor raw", m)
		}
	}
	for _, c := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
		if seen[c] != 4 {
			t.Errorf("cluster %s has %d lines, want 4 (seen %v)", c, seen[c], seen)
		}
	}
	raws := 0
	for _, m := range lines {
		if m["raw"] == "a plain line" || m["raw"] == "123" {
			raws++
		}
	}
	if raws != 8 {
		t.Errorf("%d raw lines, want 8 (a plain line and 123 in each of 4 clusters)", raws)
	}
}

// TestLogsReportsAnUnreadableCluster checks that the other clusters stay readable, that the unreadable one
// gives one error line with its name, and that the exit status is 1. A wrong argument gives one JSON error.
func TestLogsReportsAnUnreadableCluster(t *testing.T) {
	out, _, code := runScript(t, "logs.sh", map[string]string{"kubectl": logsKubectl}, []string{"STUB_FAIL_CLUSTER=dev-cp"}, "all", "app=x")
	lines := jsonLines(t, out)
	errs := 0
	for _, m := range lines {
		if m["level"] == "ERROR" {
			errs++
			if m["cluster"] != "dev-cp" || !strings.Contains(m["error"].(string), "connection was refused") {
				t.Errorf("error line %v, want cluster dev-cp and the kubectl error", m)
			}
		}
	}
	if code != 1 || errs != 1 || len(lines) != 13 {
		t.Fatalf("exit %d, %d error lines, %d lines in all, want exit 1, 1 error line and 13 lines:\n%s", code, errs, len(lines), out)
	}
	for _, args := range [][]string{{"rogue", "app=x"}, {"all"}} {
		out, _, code = runScript(t, "logs.sh", map[string]string{"kubectl": logsKubectl}, nil, args...)
		if m := jsonLines(t, out); code != 1 || len(m) != 1 || m[0]["level"] != "ERROR" {
			t.Errorf("arguments %v: exit %d, output %q, want one JSON error line and exit 1", args, code, out)
		}
	}
}

// statusKubectlStub answers the reads of harness:status. The STUB_ variables set what each source reports.
const statusKubectlStub = `#!/usr/bin/env bash
ctx="$2"
args=" $* "
case "$args" in
  *" -n argocd get applications -o json "*)
    s=Synced; h=Healthy
    [[ "$ctx" == "kind-${STUB_APP_BAD:-none}" ]] && s=OutOfSync
    [[ "$ctx" == "kind-${STUB_APP_PROGRESSING:-none}" ]] && h=Progressing
    echo '{"items":[{"metadata":{"name":"root"},"status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"}}},{"metadata":{"name":"istiod"},"status":{"sync":{"status":"'$s'"},"health":{"status":"'$h'"}}}]}' ;;
  *" logs deploy/argocd-agent-principal "*) printf '%s\n' "${STUB_PRINCIPAL:-}" ;;
  *" exec lgtm-0 "*) printf '%s' "${STUB_SAMPLES:-}" ;;
  *" get deployment kiali "*) printf '%s' "${STUB_KIALI_READY-1}" ;;
  *" get --raw "*) printf '%s' "${STUB_KIALI_CONF:-}" ;;
  *" exec deploy/mesh-view-hub "*) printf '%s' "${STUB_HUB:-}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// statusMiseStub answers mise run cell:verify, obs:uplink-status and mesh:status.
const statusMiseStub = `#!/usr/bin/env bash
case "$*" in
  "run cell:verify")
    var="STUB_VERIFY_${CELL//-/_}"
    printf '%s' "${!var:-PASS  a check
}"
    [[ "${!var:-}" == *FAIL* ]] && exit 1
    exit 0 ;;
  "run obs:uplink-status "*)
    if [[ "$3" == "${STUB_UPLINK_BAD:-none}" ]]; then echo '{"cluster":"'$3'","verdict":"gateway or relay: no export"}'; exit 1; fi
    echo '{"cluster":"'$3'","verdict":"every hop is healthy"}' ;;
  "run mesh:status")
    printf 'hub    dev-cell-1: tunnel up\n'
    exit "${STUB_MESH_RC:-0}" ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

const (
	stubConnected = `{"client":"dev-dev-cell-1","msg":"An agent connected to the subscription stream"}
{"client":"dev-dev-cell-2","msg":"An agent connected to the subscription stream"}`
	stubSamples = `{"data":{"result":[{"metric":{"k8s_cluster_name":"management"},"value":[0,"5.2"]},{"metric":{"k8s_cluster_name":"dev-cp"},"value":[0,"4"]},
{"metric":{"k8s_cluster_name":"dev-cell-1"},"value":[0,"6"]},{"metric":{"k8s_cluster_name":"dev-cell-2"},"value":[0,"299.9"]},{"metric":{},"value":[0,"1"]}]}}`
	stubKialiConf = `{"clusters":{"dev-cell-1":{"accessible":true},"dev-cell-2":{"accessible":true},"management":{"accessible":true}}}`
	stubHubUp     = `{"cells":{"dev-cell-1":{"up":true},"dev-cell-2":{"up":true}}}`
)

// runStatus runs harness:status with healthy stubs, and the extra variables of the caller after them.
func runStatus(t *testing.T, extra ...string) (map[string]map[string]any, []map[string]any, string, int) {
	t.Helper()
	env := append([]string{"STUB_PRINCIPAL=" + stubConnected, "STUB_SAMPLES=" + stubSamples, "STUB_KIALI_CONF=" + stubKialiConf, "STUB_HUB=" + stubHubUp}, extra...)
	out, stderr, code := runScript(t, "status.sh", map[string]string{"kubectl": statusKubectlStub, "mise": statusMiseStub}, env)
	lines := jsonLines(t, out)
	byName := map[string]map[string]any{}
	for _, m := range lines {
		byName[m["cluster"].(string)] = m
	}
	return byName, lines, stderr, code
}

func keys(m map[string]any) []string {
	var k []string
	for name := range m {
		k = append(k, name)
	}
	slices.Sort(k)
	return k
}

func strs(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}

// TestStatusHealthyShape checks a healthy run: exit 0, one object for each cluster with components in
// topology order, the documented fields and nothing on standard output but JSON. Progress goes to standard error.
func TestStatusHealthyShape(t *testing.T) {
	byName, lines, stderr, code := runStatus(t)
	if code != 0 || len(lines) != 4 {
		t.Fatalf("exit %d with %d objects, want exit 0 and 4:\n%v", code, len(lines), lines)
	}
	for i, c := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
		if lines[i]["cluster"] != c || lines[i]["ok"] != true {
			t.Errorf("object %d is %v, want an ok object of %s", i, lines[i], c)
		}
	}
	common := []string{"applications", "cluster", "ok", "problems", "telemetry", "verify"}
	if got := keys(byName["dev-cell-1"]); !slices.Equal(got, common) {
		t.Errorf("fields of a cell object %v, want %v", got, common)
	}
	if got := keys(byName["management"]); !slices.Equal(got, []string{"agents", "applications", "cluster", "kiali", "mesh", "ok", "problems", "samples", "stale_samples", "telemetry", "verify"}) {
		t.Errorf("fields of the management object %v", got)
	}
	m := byName["management"]
	agents := m["agents"].(map[string]any)
	if !slices.Equal(strs(agents["connected"]), []string{"dev-dev-cell-1", "dev-dev-cell-2"}) || len(agents["missing"].([]any)) != 0 {
		t.Errorf("agents %v, want both connected", agents)
	}
	if s := m["samples"].(map[string]any); len(s) != 4 || s["management"] != float64(5) || s["dev-cell-2"] != float64(299) {
		t.Errorf("samples %v, want the age of each of the 4 clusters, floored, and no entry without a cluster name", s)
	}
	if k := m["kiali"].(map[string]any); k["ready"] != true || !slices.Equal(strs(k["accessible"]), []string{"dev-cell-1", "dev-cell-2", "management"}) || k["note"] != "" {
		t.Errorf("kiali %v, want ready with both cells and no note", k)
	}
	if !strings.Contains(stderr, "==> ") {
		t.Errorf("standard error %q holds no progress line", stderr)
	}
}

func TestStatusReportsEachBadValue(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     []string
		cluster string
		field   func(m map[string]any) any
		want    string // a substring of the JSON of the field
		problem string // a substring of one problem
	}{
		{"failed check", []string{"STUB_VERIFY_dev_cell_1=PASS  a\nFAIL  The agent holds a stream\n      detail\n"}, "dev-cell-1",
			func(m map[string]any) any { return m["verify"] }, `"failed":["The agent holds a stream"]`, "CELL=dev-cell-1 mise run cell:verify"},
		{"verify dies without a FAIL line", []string{"STUB_VERIFY_dev_cp=error: no cluster\nFAIL"}, "dev-cp",
			func(m map[string]any) any { return m["verify"] }, `"ok":false`, "cell:verify failed"},
		{"an Application out of sync", []string{"STUB_APP_BAD=dev-cell-2"}, "dev-cell-2",
			func(m map[string]any) any { return m["applications"] }, `istiod: OutOfSync and Healthy`, "Application istiod: OutOfSync"},
		{"an Application that is not Healthy", []string{"STUB_APP_PROGRESSING=dev-cell-1"}, "dev-cell-1",
			func(m map[string]any) any { return m["applications"] }, `istiod: Synced and Progressing`, "Application istiod: Synced and Progressing"},
		{"a failing telemetry hop", []string{"STUB_UPLINK_BAD=dev-cp"}, "dev-cp",
			func(m map[string]any) any { return m["telemetry"] }, `"ok":false`, "mise run obs:uplink-status dev-cp"},
		{"an agent without a stream", []string{"STUB_PRINCIPAL=" + stubConnected + "\n" + `{"client":"dev-dev-cell-2","msg":"Closing EventStream"}`}, "management",
			func(m map[string]any) any { return m["agents"] }, `"missing":["dev-dev-cell-2"]`, "no stream from dev-dev-cell-2"},
		{"an agent that never connected", []string{`STUB_PRINCIPAL={"client":"dev-dev-cell-1","msg":"An agent connected to the subscription stream"}`}, "management",
			func(m map[string]any) any { return m["agents"] }, `"missing":["dev-dev-cell-2"]`, "no stream from dev-dev-cell-2"},
		{"a cluster with no sample", []string{`STUB_SAMPLES={"data":{"result":[{"metric":{"k8s_cluster_name":"management"},"value":[0,"5"]}]}}`}, "management",
			func(m map[string]any) any { return m["stale_samples"] }, `["dev-cp","dev-cell-1","dev-cell-2"]`, "no recent Prometheus sample for dev-cp and dev-cell-1 and dev-cell-2"},
		{"a sample at the age limit", []string{`STUB_SAMPLES={"data":{"result":[{"metric":{"k8s_cluster_name":"management"},"value":[0,"5"]},{"metric":{"k8s_cluster_name":"dev-cp"},"value":[0,"300.1"]},{"metric":{"k8s_cluster_name":"dev-cell-1"},"value":[0,"1"]},{"metric":{"k8s_cluster_name":"dev-cell-2"},"value":[0,"1"]}]}}`}, "management",
			func(m map[string]any) any { return m["stale_samples"] }, `["dev-cp"]`, "dev-cp"},
		{"mesh:status fails", []string{"STUB_MESH_RC=1"}, "management",
			func(m map[string]any) any { return m["mesh"] }, `"ok":false`, "mise run mesh:status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			byName, lines, _, code := runStatus(t, tc.env...)
			bad := byName[tc.cluster]
			got, _ := json.Marshal(tc.field(bad))
			problems := strings.Join(strs(bad["problems"]), "\n")
			if code != 1 || bad["ok"] != false || !strings.Contains(string(got), tc.want) || !strings.Contains(problems, tc.problem) {
				t.Fatalf("exit %d, ok %v, field %s, problems %q; want exit 1, ok false, the field to hold %s and a problem with %q", code, bad["ok"], got, problems, tc.want, tc.problem)
			}
			for _, m := range lines {
				if m["cluster"] != tc.cluster && m["ok"] != true {
					t.Errorf("the object of %s is not ok, and only %s has a bad value: %v", m["cluster"], tc.cluster, m)
				}
			}
		})
	}
}

// TestStatusNamesTheAbsentCellWhenKialiIsDown checks the state that follows a cell that is down: Kiali does not
// start, so the object names the absent cell, the recovery time and the command.
func TestStatusNamesTheAbsentCellWhenKialiIsDown(t *testing.T) {
	byName, _, _, code := runStatus(t, "STUB_KIALI_READY=", "STUB_KIALI_CONF=",
		`STUB_HUB={"cells":{"dev-cell-1":{"up":true},"dev-cell-2":{"up":false,"down_seconds":40}}}`)
	m := byName["management"]
	k := m["kiali"].(map[string]any)
	note, _ := k["note"].(string)
	if code != 1 || m["ok"] != false || k["ready"] != false || !slices.Equal(strs(k["down_cells"]), []string{"dev-cell-2"}) ||
		!slices.Equal(strs(k["missing"]), []string{"dev-cell-1", "dev-cell-2"}) {
		t.Fatalf("exit %d, kiali %v, want Kiali not ready, dev-cell-2 down and both cells missing", code, k)
	}
	for _, want := range []string{"cannot start while a cell is down", "dev-cell-2", "about 5 minutes after the cell returns", "CELL=dev-cell-2 mise run cell:up"} {
		if !strings.Contains(note, want) {
			t.Errorf("kiali.note %q lacks %q", note, want)
		}
	}
	if !strings.Contains(strings.Join(strs(m["problems"]), "\n"), "Kiali: "+note) {
		t.Errorf("problems %v lack the Kiali note", m["problems"])
	}
	// With every tunnel up, a Kiali that is not ready is a wait and not an absent cell.
	byName, _, _, _ = runStatus(t, "STUB_KIALI_READY=", "STUB_KIALI_CONF=")
	k = byName["management"]["kiali"].(map[string]any)
	if n, _ := k["note"].(string); len(k["down_cells"].([]any)) != 0 || !strings.Contains(n, "every tunnel is up") {
		t.Errorf("kiali %v, want no down cell and a note that every tunnel is up", k)
	}
	// A cell that Kiali does not list, while Kiali is ready, is missing too.
	byName, _, _, code = runStatus(t, `STUB_KIALI_CONF={"clusters":{"dev-cell-1":{"accessible":true},"dev-cell-2":{"accessible":false}}}`)
	k = byName["management"]["kiali"].(map[string]any)
	if code != 1 || !slices.Equal(strs(k["missing"]), []string{"dev-cell-2"}) {
		t.Errorf("exit %d, kiali %v, want dev-cell-2 missing", code, k)
	}
}

// viewPodsKubectl serves the reads of check_view_pods_current. STUB_SECRETS_AT is the creation time of the
// newest view key Secret, STUB_PRINCIPAL_AT and STUB_SERVER_AT the start of the main container of each pod.
const viewPodsKubectl = `#!/usr/bin/env bash
args=" $* "
case "$args" in
  *" get secrets argocd-agent-ca "*)
    echo '{"items":[{"metadata":{"creationTimestamp":"2026-11-12T09:00:00Z"}},{"metadata":{"creationTimestamp":"'"$STUB_SECRETS_AT"'"}}]}' ;;
  *"-l app.kubernetes.io/name=argocd-agent-principal "*)
    echo '{"items":[{"metadata":{"name":"principal-1"},"status":{"containerStatuses":[{"name":"cell-proxy","state":{"running":{"startedAt":"2030-01-01T00:00:00Z"}}},{"name":"argocd-agent-principal","state":{"running":{"startedAt":"'"$STUB_PRINCIPAL_AT"'"}}}]}}]}' ;;
  *"-l app.kubernetes.io/name=argocd-server "*)
    echo '{"items":[{"metadata":{"name":"server-1"},"status":{"containerStatuses":[{"name":"argocd-server","state":{"running":{"startedAt":"'"$STUB_SERVER_AT"'"}}}]}}]}' ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestViewPodsMustStartAfterTheViewKeys checks the drift check for an interrupted link run: a pod that started
// before the newest view key Secret fails the check, and the output names the pod and the repair command.
func TestViewPodsMustStartAfterTheViewKeys(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	verify, err := filepath.Abs("../../scripts/verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, secrets, principal, server, want string
	}{
		{"both started after the keys", "2026-11-12T10:00:00Z", "2026-11-12T10:00:05Z", "2026-11-12T10:00:09Z", ""},
		{"both started in the same second", "2026-11-12T10:00:00Z", "2026-11-12T10:00:00Z", "2026-11-12T10:00:00Z", ""},
		{"the principal is older", "2026-11-12T10:00:00Z", "2026-11-12T09:59:59Z", "2026-11-12T10:00:09Z", "principal-1 started at 2026-11-12T09:59:59Z"},
		{"argocd-server is older", "2026-11-12T10:00:00Z", "2026-11-12T10:00:05Z", "2026-11-12T09:00:00Z", "server-1 started at 2026-11-12T09:00:00Z"},
		{"a container that does not run", "2026-11-12T10:00:00Z", "2026-11-12T10:00:05Z", "", "server-1 started at no time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(viewPodsKubectl), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `source "$1"; eval "$(sed -n '/^check_view_pods_current()/,/^}/p' "$2")"; check_view_pods_current`, "_", lib, verify)
			cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=management",
				"STUB_SECRETS_AT=" + tc.secrets, "STUB_PRINCIPAL_AT=" + tc.principal, "STUB_SERVER_AT=" + tc.server}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("check failed: %v\n%s", err, out.String())
			case tc.want != "" && (err == nil || !strings.Contains(out.String(), tc.want) || !strings.Contains(out.String(), "Run: mise run view:rotate-keys")):
				t.Fatalf("err %v, output %q; want a failure that says %q and the repair command", err, out.String(), tc.want)
			}
		})
	}
}
