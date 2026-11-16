package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
    [[ " $* " == *" --tail=${STUB_WANT_TAIL:-200} "* && " $* " == *" --prefix "* && " $* " == *" --request-timeout="* ]] || { echo "bad logs flags: $*" >&2; exit 2; }
    [[ -z "${STUB_WANT_SINCE:-}" || " $* " == *" --since=$STUB_WANT_SINCE "* ]] || { echo "no --since: $*" >&2; exit 2; }
    printf '%s\n' '[pod/pod-1/main] {"level":"info","msg":"first"}' '[pod/pod-1/side] {"msg":"second","cluster":"inner"}' '[pod/pod-1/main] a plain line' '[pod/pod-1/main] 123' ;;
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
		want := "main"
		if m["msg"] == "second" {
			want = "side"
		}
		if m["namespace"] != "ns" || m["pod"] != "pod-1" || m["container"] != want {
			t.Errorf("line %v, want namespace ns, pod pod-1 and container %s", m, want)
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

// TestLogsBoundsAndCluster checks that the call of kubectl logs carries the line bound and the age limit (the stub
// refuses a call without them), and that a pattern as the cluster argument is no cluster and expands to nothing.
func TestLogsBoundsAndCluster(t *testing.T) {
	stubs := map[string]string{"kubectl": logsKubectl}
	out, _, code := runScript(t, "logs.sh", stubs, []string{"STUB_WANT_TAIL=7", "STUB_WANT_SINCE=10m", "LOGS_TAIL=7", "LOGS_SINCE=10m"}, "dev-cp", "app=x")
	if lines := jsonLines(t, out); code != 0 || len(lines) != 4 {
		t.Errorf("exit %d with %d lines, want exit 0 and 4 lines for --tail=7 and --since=10m:\n%s", code, len(lines), out)
	}
	for _, arg := range []string{".*", "dev-c.", "dev-cp dev-cell-1", "*"} {
		out, _, code = runScript(t, "logs.sh", stubs, nil, arg, "app=x")
		if m := jsonLines(t, out); code != 1 || len(m) != 1 || m[0]["level"] != "ERROR" {
			t.Errorf("cluster argument %q: exit %d, output %q, want one JSON error line and exit 1", arg, code, out)
		}
	}
}

// statusKubectlStub answers the reads of harness:status. The STUB_ variables set what each source reports.
const statusKubectlStub = `#!/usr/bin/env bash
ctx=""; prev=""
for a in "$@"; do [[ "$prev" == --context ]] && ctx="$a"; prev="$a"; done
args=" $* "
case "$args" in
  *" -n argocd get applications -o json "*)
    [[ "$ctx" == "kind-${STUB_APPS_GARBAGE:-none}" ]] && { echo "not json"; exit 0; }
    s=Synced; h=Healthy
    [[ "$ctx" == "kind-${STUB_APP_BAD:-none}" ]] && s=OutOfSync
    [[ "$ctx" == "kind-${STUB_APP_PROGRESSING:-none}" ]] && h=Progressing
    echo '{"items":[{"metadata":{"name":"root"},"status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"}}},{"metadata":{"name":"istiod"},"status":{"sync":{"status":"'$s'"},"health":{"status":"'$h'"}}}]}' ;;
  *" logs deploy/argocd-agent-principal "*) printf '%s\n' "${STUB_PRINCIPAL:-}" ;;
  *" exec lgtm-0 "*) printf '%s' "${STUB_SAMPLES:-}" ;;
  *" get deployment kiali "*) printf '%s' "${STUB_KIALI_READY-1}" ;;
  *" get --raw /readyz "*) [[ " ${STUB_CELL_DOWN:-} " == *" ${ctx#kind-} "* ]] && { echo "no answer" >&2; exit 1; }; echo ok ;;
  *" get --raw "*) printf '%s' "${STUB_KIALI_CONF:-}" ;;
  *" exec deploy/mesh-view-hub "*) printf '%s' "${STUB_HUB:-}" ;;
  *" get configmap hostsvc-pin "*) printf '%s' "${STUB_CM_PIN:-$STUB_PIN_PEM}" ;;
  *" get pod mgmtd-0 "*) printf '%s' "${STUB_POD_PIN:-}" ;;
  *" exec spire-server-0 "*) printf '%s\n' "${STUB_ROOT_PEM:-}" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// statusMiseStub answers mise run cell:verify, obs:uplink-status and mesh:status.
const statusMiseStub = `#!/usr/bin/env bash
case "$*" in
  "run cell:verify")
    [[ "${CELL}" == "${STUB_VERIFY_HANG:-none}" ]] && exec sleep 30
    [[ "${CELL}" == "${STUB_VERIFY_DIES:-none}" ]] && { echo "==> checking cell $CELL" >&2; echo "error: cannot reach the API server of $CELL" >&2; exit 1; }
    var="STUB_VERIFY_${CELL//-/_}"
    printf '%s' "${!var:-PASS  a check
}"
    [[ "${!var:-}" == *FAIL* ]] && exit 1
    exit 0 ;;
  "run obs:uplink-status "*)
    if [[ "$3" == "${STUB_UPLINK_BAD:-none}" ]]; then echo '{"cluster":"'$3'","verdict":"gateway or relay: no export"}'; exit 1; fi
    if [[ "$3" == "${STUB_UPLINK_WAIT:-none}" ]]; then echo '{"cluster":"'$3'","verdict":"collector export: the exporter failed and retried 8 times in 5 minutes.","store":{"ok":true}}'; exit 1; fi
    echo '{"cluster":"'$3'","verdict":"every hop is healthy"}' ;;
  "run mgmt -- status")
    printf '%s\n' "${STUB_MGMT_STATUS:-}"
    exit "${STUB_MGMT_RC:-0}" ;;
  "run mgmt -- op list")
    if [[ -n "${STUB_MGMT_OPS:-}" ]]; then printf '%s\n' "$STUB_MGMT_OPS"; else echo '{"ops":[]}'; fi
    exit "${STUB_MGMT_OPS_RC:-0}" ;;
  "run gw -- status")
    printf '%s\n' "${STUB_GW_STATUS:-}"
    exit "${STUB_GW_RC:-0}" ;;
  "run pki -- trust-bundle "*) cat ;;
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

// statusServe stands in for hostsvc-serve.sh. status prints STUB_SERVE_STATUS, and pin prints STUB_PIN_PEM.
const statusServe = `#!/usr/bin/env bash
case "$1" in
  status)
    # STUB_COUNT names a file. With STUB_SERVE_STATUS_FAILS_LATER set, every call after the first fails with no output.
    if [[ -n "${STUB_COUNT:-}" ]]; then
      n="$(cat "$STUB_COUNT" 2>/dev/null || echo 0)"
      echo $((n + 1)) >"$STUB_COUNT"
      [[ -z "${STUB_SERVE_STATUS_FAILS_LATER:-}" || "$n" == 0 ]] || exit 1
    fi
    printf '%s\n' "$STUB_SERVE_STATUS" ;;
  pin) printf '%s\n' "$STUB_PIN_PEM" ;;
  *) exit 2 ;;
esac
`

// derSHA is the SHA-256 of the DER bytes of the first certificate in a PEM text.
func derSHA(t *testing.T, pemText string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		t.Fatalf("no PEM block in %q", pemText)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// nodeClockDocker stands in for docker. It answers `exec dev-cp-control-plane date` with the time of a node, which is STUB_CLOCK_SKEW
// seconds behind the clock of the Mac (default 0), in epoch seconds or in the form of date -u.
const nodeClockDocker = `#!/usr/bin/env bash
[[ "$1 $2" == "exec dev-cp-control-plane" && "$3" == date ]] || { echo "unexpected docker call: $*" >&2; exit 2; }
t=$(( $(date +%s) - ${STUB_CLOCK_SKEW:-0} ))
if [[ "$4" == +%s ]]; then echo "$t"; else date -u -d "@$t" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$t" +%Y-%m-%dT%H:%M:%SZ; fi
`

// timeAgo formats the time that is d before now, as mgmtd prints it.
func timeAgo(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339Nano) }

const zeroTime = "0001-01-01T00:00:00Z"

// planeCell is one cell of mise run mgmt -- status, with a status from 20 seconds ago and nothing unreported. over replaces fields.
func planeCell(name string, over map[string]any) map[string]any {
	c := map[string]any{"name": name, "bound": true, "lastCheck": "unchanged", "lastStatusAt": timeAgo(20 * time.Second), "unreported": 0,
		"oldestUnreportedAt": zeroTime, "records": 3, "openOps": 0, "expiredOps": 0, "forgedSeen": 0, "lastHintCheck": "unchanged"}
	maps.Copy(c, over)
	return c
}

// healthyGateway is what mise run gw -- status prints for a gateway that envd synced 10 seconds ago, with a stream
// for each cell and nothing queued. mutate changes the object.
func healthyGateway(mutate func(m map[string]any)) string {
	m := map[string]any{"epoch": 3, "syncedAt": timeAgo(10 * time.Second), "oldestOutboxAt": zeroTime, "epochChangedAt": timeAgo(time.Hour),
		"droppedAt": zeroTime, "recordOldAt": zeroTime, "outboxItems": 0, "dropped": 0, "recordOld": 0, "queued": map[string]any{},
		"streams": map[string]any{"dev-cell-1": 1, "dev-cell-2": 1}, "mostClaimed": map[string]any{}, "records": map[string]any{},
		"lastBindRefusal": map[string]any{}, "keyHints": []any{}, "storeError": ""}
	if mutate != nil {
		mutate(m)
	}
	out, _ := json.Marshal(m)
	return string(out)
}

// healthyPlane is what mise run mgmt -- status prints on a healthy plane: signed and applied at the same
// revision, a report from 10 seconds ago, and both cells bound and checked. mutate changes the object.
func healthyPlane(mutate func(m map[string]any)) string {
	at := func(ago time.Duration) string { return time.Now().Add(-ago).UTC().Format(time.RFC3339Nano) }
	rev := map[string]any{"epoch": 1, "counter": 4}
	cell := func(name string) map[string]any { return planeCell(name, nil) }
	m := map[string]any{"env": "dev", "signed": rev, "served": rev, "applied": rev, "restoreActive": false, "appliedAt": at(time.Hour),
		"lastReportAt": at(10 * time.Second), "pendingDrops": []string{}, "cells": []any{cell("dev-cell-1"), cell("dev-cell-2")}}
	if mutate != nil {
		mutate(m)
	}
	out, _ := json.Marshal(m)
	return string(out)
}

// fakeServeStatus is what hostsvc-serve.sh status prints for a running service with this certificate and root.
func fakeServeStatus(cert, root string, mutate func(m map[string]any)) string {
	m := map[string]any{"running": true, "pid": 4242, "cert_sha256": cert, "root_sha256": root, "expires_soon": false, "last_error": ""}
	if mutate != nil {
		mutate(m)
	}
	out, _ := json.Marshal(m)
	return string(out)
}

// runStatus runs harness:status with healthy stubs, and the extra variables of the caller after them. The
// variables of the caller come last, so they win. The management plane and the host service are healthy.
func runStatus(t *testing.T, extra ...string) (map[string]map[string]any, []map[string]any, string, int) {
	t.Helper()
	pin, root := caPEM(t, 10), caPEM(t, 1)
	serve := filepath.Join(t.TempDir(), "serve")
	if err := os.WriteFile(serve, []byte(statusServe), 0o755); err != nil {
		t.Fatal(err)
	}
	env := append([]string{"STUB_PRINCIPAL=" + stubConnected, "STUB_SAMPLES=" + stubSamples, "STUB_KIALI_CONF=" + stubKialiConf, "STUB_HUB=" + stubHubUp,
		"STUB_MGMT_STATUS=" + healthyPlane(nil), "STUB_GW_STATUS=" + healthyGateway(nil), "HOSTSVC_SERVE=" + serve, "STUB_PIN_PEM=" + pin, "STUB_ROOT_PEM=" + root, "STUB_POD_PIN=" + derSHA(t, pin),
		"STUB_SERVE_STATUS=" + fakeServeStatus(derSHA(t, pin), derSHA(t, root), nil)}, extra...)
	out, stderr, code := runScript(t, "status.sh", map[string]string{"kubectl": statusKubectlStub, "mise": statusMiseStub, "docker": nodeClockDocker}, env)
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
	if got := keys(byName["management"]); !slices.Equal(got, []string{"agents", "applications", "cluster", "kiali", "management", "mesh", "ok", "problems", "samples", "stale_samples", "telemetry", "verify"}) {
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

// TestStatusAgentsSurviveLogRotation checks the count of agent streams once the connect lines have left the log of the
// principal (the kubelet rotates the log after about 10 hours). An agent with no stream line counts as connected when the
// principal received an event from it in the last 5 minutes. A closing line that is newer than the connect line still wins.
func TestStatusAgentsSurviveLogRotation(t *testing.T) {
	event := func(client string, ago time.Duration) string {
		return fmt.Sprintf(`{"client":%q,"msg":"Event received: application spec-update","time":%q}`, client, time.Now().Add(-ago).UTC().Format("2006-01-02T15:04:05Z"))
	}
	for _, tc := range []struct {
		name        string
		principal   string
		wantMissing []string
	}{
		{"events from both agents and no stream line", event("dev-dev-cell-1", time.Minute) + "\n" + event("dev-dev-cell-2", 2*time.Minute), nil},
		{"an event 20 minutes ago is no sign of a stream", event("dev-dev-cell-1", time.Minute) + "\n" + event("dev-dev-cell-2", 20*time.Minute), []string{"dev-dev-cell-2"}},
		{"a closing line after a recent event wins", event("dev-dev-cell-1", time.Minute) + "\n" + event("dev-dev-cell-2", time.Minute) + "\n" +
			`{"client":"dev-dev-cell-2","msg":"Closing EventStream"}`, []string{"dev-dev-cell-2"}},
		{"no line at all", "", []string{"dev-dev-cell-1", "dev-dev-cell-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			byName, _, _, code := runStatus(t, "STUB_PRINCIPAL="+tc.principal)
			agents := byName["management"]["agents"].(map[string]any)
			got := []string{}
			if m, ok := agents["missing"].([]any); ok {
				got = strs(m)
			}
			if !slices.Equal(got, append([]string{}, tc.wantMissing...)) && !(len(got) == 0 && len(tc.wantMissing) == 0) {
				t.Errorf("missing %v, want %v", got, tc.wantMissing)
			}
			if (code == 0) != (len(tc.wantMissing) == 0) {
				t.Errorf("exit %d with missing %v", code, tc.wantMissing)
			}
		})
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
			func(m map[string]any) any { return m["agents"] }, `"missing":["dev-dev-cell-2"]`, "no stream from dev-dev-cell-2. Run: CELL=dev-cell-2 mise run cell:verify"},
		{"an agent that never connected", []string{`STUB_PRINCIPAL={"client":"dev-dev-cell-1","msg":"An agent connected to the subscription stream"}`}, "management",
			func(m map[string]any) any { return m["agents"] }, `"missing":["dev-dev-cell-2"]`, "no stream from dev-dev-cell-2"},
		{"a cluster with no sample", []string{`STUB_SAMPLES={"data":{"result":[{"metric":{"k8s_cluster_name":"management"},"value":[0,"5"]}]}}`}, "management",
			func(m map[string]any) any { return m["stale_samples"] }, `["dev-cp","dev-cell-1","dev-cell-2"]`, "no recent Prometheus sample for dev-cp and dev-cell-1 and dev-cell-2. Run: mise run obs:uplink-status dev-cp and mise run obs:uplink-status dev-cell-1 and mise run obs:uplink-status dev-cell-2"},
		{"a sample at the age limit", []string{`STUB_SAMPLES={"data":{"result":[{"metric":{"k8s_cluster_name":"management"},"value":[0,"5"]},{"metric":{"k8s_cluster_name":"dev-cp"},"value":[0,"300.1"]},{"metric":{"k8s_cluster_name":"dev-cell-1"},"value":[0,"1"]},{"metric":{"k8s_cluster_name":"dev-cell-2"},"value":[0,"1"]}]}}`}, "management",
			func(m map[string]any) any { return m["stale_samples"] }, `["dev-cp"]`, "dev-cp"},
		{"collector export that clears by itself", []string{"STUB_UPLINK_WAIT=dev-cp"}, "dev-cp",
			func(m map[string]any) any { return m["telemetry"] }, `"wait":true`, "Wait up to 5 minutes, then run: mise run harness:status"},
		{"cell:verify dies with an error line", []string{"STUB_VERIFY_DIES=dev-cp"}, "dev-cp",
			func(m map[string]any) any { return m["verify"] }, `error: cannot reach the API server of dev-cp`, "CELL=dev-cp mise run cell:verify"},
		{"cell:verify does not finish", []string{"STUB_VERIFY_HANG=dev-cell-2", "STATUS_VERIFY_TIMEOUT=1"}, "dev-cell-2",
			func(m map[string]any) any { return m["verify"] }, `did not finish in 1 s`, "CELL=dev-cell-2 mise run cell:verify"},
		{"the status script dies for a cluster", []string{"STUB_APPS_GARBAGE=dev-cp"}, "dev-cp",
			func(m map[string]any) any { return []any{m["applications"], m["verify"], m["telemetry"]} }, `"failed":["the status script could not read the cluster"]`, "CELL=dev-cp mise run cell:verify"},
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
			if strings.ContainsAny(problems, "<>") {
				t.Errorf("problems %q hold a placeholder, and each command must work as printed", problems)
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
	byName, _, _, code := runStatus(t, "STUB_KIALI_READY=", "STUB_KIALI_CONF=", "STUB_CELL_DOWN=dev-cell-2",
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
    [[ "$args" == *" -o jsonpath="* && "$args" != *" -o json "* ]] || { echo "the check must read metadata only: $*" >&2; exit 2; }
    printf '%s\n' 2026-11-12T09:00:00Z "$STUB_SECRETS_AT" ;;
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

// TestStatusKialiNoteFollowsTheCause checks I1: a cell is absent only when its own API does not answer. A tunnel
// that is down while the cell API answers does not blame the cell, and no cell command is offered for it.
func TestStatusKialiNoteFollowsTheCause(t *testing.T) {
	bothDown := `STUB_HUB={"cells":{"dev-cell-1":{"up":false},"dev-cell-2":{"up":false}}}`
	oneDown := `STUB_HUB={"cells":{"dev-cell-1":{"up":true},"dev-cell-2":{"up":false}}}`
	for _, tc := range []struct {
		name    string
		env     []string
		absent  []string
		want    []string
		refuses []string
	}{
		{"every tunnel down, cell APIs answer", []string{"STUB_KIALI_READY=", "STUB_KIALI_CONF=", bothDown}, nil,
			[]string{"dev-cell-1 and dev-cell-2 have no tunnel at the hub", "CELL=dev-cp mise run cell:verify", "mise run mesh:status"}, []string{"is absent", "are absent", "cell:up"}},
		{"one tunnel down, its API answers", []string{"STUB_KIALI_READY=", "STUB_KIALI_CONF=", oneDown}, nil,
			[]string{"dev-cell-2 has no tunnel at the hub", "mise run mesh:status"}, []string{"is absent", "are absent", "cell:up", "dev-cp mise run cell:verify"}},
		{"both cell APIs down", []string{"STUB_KIALI_READY=", "STUB_KIALI_CONF=", bothDown, "STUB_CELL_DOWN=dev-cell-1 dev-cell-2"}, []string{"dev-cell-1", "dev-cell-2"},
			[]string{"The cells dev-cell-1 and dev-cell-2 are absent", "about 5 minutes after the cell returns", "CELL=dev-cell-1 mise run cell:up and CELL=dev-cell-2 mise run cell:up"}, []string{"is absent"}},
		{"one cell API down, the other tunnel down too", []string{"STUB_KIALI_READY=", "STUB_KIALI_CONF=", bothDown, "STUB_CELL_DOWN=dev-cell-2"}, []string{"dev-cell-2"},
			[]string{"The cell dev-cell-2 is absent", "CELL=dev-cell-2 mise run cell:up", "dev-cell-1 has no tunnel at the hub"}, []string{"CELL=dev-cell-1 mise run cell:up"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			byName, _, _, code := runStatus(t, tc.env...)
			k := byName["management"]["kiali"].(map[string]any)
			note, _ := k["note"].(string)
			var absent []string
			if a, ok := k["absent_cells"].([]any); ok {
				absent = strs(a)
			}
			if code != 1 || !slices.Equal(absent, tc.absent) {
				t.Errorf("exit %d, absent_cells %v, want %v", code, k["absent_cells"], tc.absent)
			}
			for _, w := range tc.want {
				if !strings.Contains(note, w) {
					t.Errorf("note %q lacks %q", note, w)
				}
			}
			for _, r := range tc.refuses {
				if strings.Contains(note, r) {
					t.Errorf("note %q holds %q", note, r)
				}
			}
		})
	}
}

// TestViewPodsTwoStalePodsEachGetTheirOwnTime checks S-M4: with two stale pods, each line names its own pod and the
// newest key time.
func TestViewPodsTwoStalePodsEachGetTheirOwnTime(t *testing.T) {
	out, err := runVerifyFunctions(t, viewPodsKubectl, "check_view_pods_current", "management",
		"STUB_SECRETS_AT=2026-11-12T10:00:00Z", "STUB_PRINCIPAL_AT=2026-11-12T09:59:59Z", "STUB_SERVER_AT=2026-11-12T09:00:00Z")
	if err == nil {
		t.Fatalf("the check passed with two stale pods:\n%s", out)
	}
	for _, want := range []string{
		"principal-1 started at 2026-11-12T09:59:59Z, before the newest view key at 2026-11-12T10:00:00Z.",
		"server-1 started at 2026-11-12T09:00:00Z, before the newest view key at 2026-11-12T10:00:00Z.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks the line %q:\n%s", want, out)
		}
	}
}

// runVerifyFunctions runs functions of scripts/verify.sh and scripts/verify-lib.sh with a stub kubectl, and returns the output.
func runVerifyFunctions(t *testing.T, stub, call, cell string, env ...string) (string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	lib, _ := filepath.Abs("../../scripts/lib.sh")
	verify, _ := filepath.Abs("../../scripts/verify.sh")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `source "$1"; for f in pem_lines peer_root_pods_current check_mesh_view_peer_root check_view_pods_current; do eval "$(sed -n "/^$f()/,/^}/p" "$2" "$3")"; done; ` + call
	verifyLib, _ := filepath.Abs("../../scripts/verify-lib.sh")
	cmd := exec.Command("bash", "-c", script, "_", lib, verify, verifyLib)
	cmd.Env = append([]string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=" + cell}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// peerRootKubectl serves check_mesh_view_peer_root in dev-cell-1. The live bundle and the ConfigMap hold STUB_PEM. The
// running pod carries STUB_POD_SUM, and STUB_GONE_SUM on a second pod that is already deleted.
const peerRootKubectl = `#!/usr/bin/env bash
args=" $* "
case "$args" in
  *" exec spire-server-0 "*) printf '%s\n' "$STUB_PEM" ;;
  *" get configmap mgmt-root "*) printf '%s' "$STUB_PEM" ;;
  *" get pods -l app.kubernetes.io/name=mesh-view "*)
    echo '{"items":[{"metadata":{"name":"mesh-view-new","annotations":{"poc.internal/peer-root-sha256":"'"$STUB_POD_SUM"'"}}},{"metadata":{"name":"mesh-view-old","deletionTimestamp":"2026-11-12T10:00:00Z","annotations":{"poc.internal/peer-root-sha256":"'"${STUB_GONE_SUM:-x}"'"}}}]}' ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestPeerRootCheckComparesThePodDigest checks S-M3: a ConfigMap that holds the live root is not enough. The running
// pod must carry the digest of that ConfigMap, because it reads the file once at start.
func TestPeerRootCheckComparesThePodDigest(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(pem)))
	old := fmt.Sprintf("%x", sha256.Sum256([]byte("an older root")))
	for _, tc := range []struct {
		name, podSum, goneSum, want string
	}{
		{"the pod carries the digest of the ConfigMap", sum, old, ""},
		{"the ConfigMap is right and the pod annotation is old", old, "", "mesh-view-new carries the root digest " + old},
		{"the pod has no annotation", "", "", "mesh-view-new carries the root digest none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runVerifyFunctions(t, peerRootKubectl, "check_mesh_view_peer_root", "dev-cell-1",
				"STUB_PEM="+pem, "STUB_POD_SUM="+tc.podSum, "STUB_GONE_SUM="+tc.goneSum)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("check failed: %v\n%s", err, out)
			case tc.want != "" && (err == nil || !strings.Contains(out, tc.want) || !strings.Contains(out, "Run: CELL=dev-cell-1 mise run cell:up")):
				t.Fatalf("err %v, output %q; want a failure that says %q and the repair command", err, out, tc.want)
			}
		})
	}
}

// meshKubectlStub answers the reads of mesh:status. STUB_CELL_DOWN names the clusters whose API does not answer.
const meshKubectlStub = `#!/usr/bin/env bash
ctx=""; prev=""
for a in "$@"; do [[ "$prev" == --context ]] && ctx="$a"; prev="$a"; done
case " $* " in
  *" get --raw /readyz "*) [[ " ${STUB_CELL_DOWN:-} " == *" ${ctx#kind-} "* ]] && { echo "no answer" >&2; exit 1; }; echo ok ;;
  *" logs deploy/mesh-view-hub "*) ;;
  *" exec deploy/mesh-view-hub "*) printf '%s' "${STUB_HUB:-}" ;;
  *" exec deploy/mesh-view "*) ;;
  *" get deployment "*) printf '%s' 1 ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestMeshStatusNamesCellUpOnlyForAnAbsentCell checks the same rule as harness:status: a cell is absent only when its own API
// does not answer. A tunnel that is down while the API answers has another cause, and cell:up of that cell does not fix it.
func TestMeshStatusNamesCellUpOnlyForAnAbsentCell(t *testing.T) {
	hub := `{"cells":{"dev-cell-1":{"up":false,"down_seconds":12},"dev-cell-2":{"up":true,"conn_id":1,"age_seconds":5}}}`
	run := func(down string) string {
		out, stderr, code := runScript(t, "mesh-status.sh", map[string]string{"kubectl": meshKubectlStub},
			[]string{"CELL=management", "STUB_HUB=" + hub, "STUB_CELL_DOWN=" + down})
		if code != 1 {
			t.Fatalf("exit %d, want 1 for a tunnel that is down:\n%s\n%s", code, out, stderr)
		}
		return out
	}
	var line string
	pick := func(out string) {
		line = ""
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "hub    dev-cell-1: no open tunnel") {
				line = l
			}
		}
		if line == "" {
			t.Fatalf("no hub line for dev-cell-1 in:\n%s", out)
		}
	}
	pick(run(""))
	if !strings.Contains(line, "CELL=dev-cp mise run cell:verify") || strings.Contains(line, "cell:up") {
		t.Errorf("the API of the cell answers, so the line %q must name cell:verify of dev-cp and no cell:up", line)
	}
	pick(run("dev-cell-1"))
	if !strings.Contains(line, "CELL=dev-cell-1 mise run cell:up") {
		t.Errorf("the cell is absent, so the line %q must name cell:up", line)
	}
}

// TestStatusReportsTheManagementPlane checks that harness:status shows the signed and applied revisions, the
// report times, the cells and the host service in the field management of the management object. A healthy plane
// exits 0. Each bad condition exits 1 with a problem that holds the next command, and no other cluster turns bad.
func TestStatusReportsTheManagementPlane(t *testing.T) {
	byName, _, _, code := runStatus(t)
	if code != 0 {
		t.Fatalf("exit %d on a healthy plane, want 0: %v", code, byName["management"]["problems"])
	}
	m, _ := byName["management"]["management"].(map[string]any)
	if m == nil {
		t.Fatalf("the management object has no field management: %v", byName["management"])
	}
	for _, f := range []string{"signed", "applied", "lastReportAt", "restoreActive", "pendingDrops", "cells", "hostsvc"} {
		if _, ok := m[f]; !ok {
			t.Errorf("management %v has no field %s", keys(m), f)
		}
	}
	if h := m["hostsvc"].(map[string]any); h["running"] != true || h["check"] != "" {
		t.Errorf("hostsvc %v, want a running service and an empty check", h)
	}

	at := func(ago time.Duration) string { return time.Now().Add(-ago).UTC().Format(time.RFC3339Nano) }
	plane := func(mutate func(m map[string]any)) []string {
		return []string{"STUB_MGMT_STATUS=" + healthyPlane(mutate)}
	}
	cellCheck := func(name, result string) func(m map[string]any) {
		return func(m map[string]any) {
			m["cells"] = []any{planeCell("dev-cell-1", nil), planeCell(name, map[string]any{"lastCheck": result})}
		}
	}
	pin, root := caPEM(t, 10), caPEM(t, 1)
	otherPin, otherRoot := caPEM(t, 11), caPEM(t, 2)
	verifyCP := "CELL=dev-cp mise run cell:verify"
	restart := "mise run hostsvc:serve -- restart"
	for _, tc := range []struct {
		name string
		env  []string
		want []string // substrings of the problems, the next command last
	}{
		{"signed is above applied for more than 2 minutes", plane(func(m map[string]any) {
			m["signed"] = map[string]any{"epoch": 1, "counter": 6}
			m["lagSince"] = at(3 * time.Minute)
		}), []string{"signed revision 1.6", "applied 1.4", verifyCP}},
		{"a refusal is newer than the applied spec", plane(func(m map[string]any) {
			m["lastRefusal"] = map[string]any{"reason": "signature_invalid", "revision": map[string]any{"epoch": 1, "counter": 5}, "at": at(time.Minute)}
		}), []string{"refused a spec: signature_invalid", verifyCP}},
		{"envd reports a store error", plane(func(m map[string]any) { m["storeError"] = "conflict writing cell-records" }),
			[]string{"store error: conflict writing cell-records", verifyCP}},
		{"a restore is active", plane(func(m map[string]any) { m["restoreActive"] = true }),
			[]string{"restore is active", "mise run mgmt -- restore --revision latest"}},
		{"the last report is 90 seconds old", plane(func(m map[string]any) { m["lastReportAt"] = at(90 * time.Second) }),
			[]string{"no report from envd", verifyCP}},
		{"envd never reported", plane(func(m map[string]any) { delete(m, "lastReportAt") }),
			[]string{"no report from envd", verifyCP}},
		{"a cell has untrusted keys", plane(cellCheck("dev-cell-2", "keys_untrusted")),
			[]string{"dev-cell-2", "keys_untrusted", "CELL=dev-cell-2 mise run cell:restart"}},
		{"a cell has an untrusted issuer", plane(cellCheck("dev-cell-2", "issuer_untrusted")),
			[]string{"dev-cell-2", "issuer_untrusted", restart}},
		{"a cell has an unavailable issuer", plane(cellCheck("dev-cell-2", "issuer_unavailable")),
			[]string{"dev-cell-2", "issuer_unavailable", "mise run hostsvc:serve -- status"}},
		{"a cell with cell-identity is unbound", plane(func(m map[string]any) {
			m["cells"] = []any{planeCell("dev-cell-1", nil), planeCell("dev-cell-2", map[string]any{"bound": false, "lastCheck": ""})}
		}), []string{"dev-cell-2 is not bound", "CELL=dev-cell-2 mise run cell:up"}},
		{"a cell with cell-identity is not in the status", plane(func(m map[string]any) {
			m["cells"] = []any{planeCell("dev-cell-1", nil)}
		}), []string{"dev-cell-2 is not bound", "CELL=dev-cell-2 mise run cell:up"}},
		{"mgmtd does not answer", []string{"STUB_MGMT_RC=1", `STUB_MGMT_STATUS={"level":"ERROR","msg":"mgmt failed","error":"pod mgmtd-0 is absent or not Ready. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"}`},
			[]string{"mgmtd status failed", "pod mgmtd-0 is absent", "Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"}},
		{"the host service does not run", []string{"STUB_SERVE_STATUS=" + fakeServeStatus("", "", func(m map[string]any) { m["running"] = false; m["pid"] = nil })},
			[]string{"host service is not running", "mise run hostsvc:serve -- start"}},
		{"the pod pin differs from the certificate", []string{"STUB_POD_PIN=" + strings.Repeat("0", 64)},
			[]string{"carries the pin digest", restart}},
		{"the ConfigMap pin differs from the certificate", []string{"STUB_CM_PIN=" + otherPin}, []string{"holds another certificate", restart}},
		{"the host service trusts another root", []string{"STUB_ROOT_PEM=" + otherRoot}, []string{"trusts the management root", restart}},
		{"a host service check fails with no output", []string{"STUB_COUNT=" + filepath.Join(t.TempDir(), "n"), "STUB_SERVE_STATUS_FAILS_LATER=1"},
			[]string{"the host service check failed", "mise run hostsvc:serve -- status"}},
		{"a refusal time does not parse", plane(func(m map[string]any) {
			m["appliedAt"] = at(time.Minute)
			m["lastRefusal"] = map[string]any{"reason": "signature_invalid", "revision": map[string]any{"epoch": 1, "counter": 3}, "at": "not a time"}
		}), []string{"refused a spec: signature_invalid", verifyCP}},
		{"the certificate expires soon", []string{"STUB_SERVE_STATUS=" + fakeServeStatus(derSHA(t, pin), derSHA(t, root), func(m map[string]any) { m["expires_soon"] = true })},
			[]string{"certificate expires soon", restart}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			byName, lines, _, code := runStatus(t, tc.env...)
			bad := byName["management"]
			problems := strings.Join(strs(bad["problems"]), "\n")
			if code != 1 || bad["ok"] != false {
				t.Fatalf("exit %d, ok %v, problems %q; want exit 1 and ok false", code, bad["ok"], problems)
			}
			for _, w := range tc.want {
				if !strings.Contains(problems, w) {
					t.Errorf("problems %q lack %q", problems, w)
				}
			}
			if strings.ContainsAny(problems, "<>") {
				t.Errorf("problems %q hold a placeholder, and each command must work as printed", problems)
			}
			for _, m := range lines {
				if m["cluster"] != "management" && m["ok"] != true {
					t.Errorf("the object of %s is not ok, and only management has a bad value: %v", m["cluster"], m)
				}
			}
		})
	}

	t.Run("signed above applied for less than 2 minutes is a wait", func(t *testing.T) {
		_, _, _, code := runStatus(t, plane(func(m map[string]any) {
			m["signed"] = map[string]any{"epoch": 1, "counter": 6}
			m["lagSince"] = at(time.Minute)
		})...)
		if code != 0 {
			t.Errorf("exit %d, want 0 while the lag is under 2 minutes", code)
		}
	})
	t.Run("a refusal older than the applied spec is history", func(t *testing.T) {
		_, _, _, code := runStatus(t, plane(func(m map[string]any) {
			m["appliedAt"] = at(time.Minute)
			m["lastRefusal"] = map[string]any{"reason": "signature_invalid", "revision": map[string]any{"epoch": 1, "counter": 3}, "at": at(time.Hour)}
		})...)
		if code != 0 {
			t.Errorf("exit %d, want 0 for a refusal before the last apply", code)
		}
	})
}

// TestStatusReportsTheGatewayAndSignedWork checks each condition of the signed work: the gateway object of dev-cp, and the
// work fields of each cell of the management object. A healthy run has none of them. Each case changes one value and
// expects exit 1 with the problem on the object of the cluster that holds the value, and the command to run.
func TestStatusReportsTheGatewayAndSignedWork(t *testing.T) {
	healthy, _, _, code := runStatus(t)
	if code != 0 {
		t.Fatalf("exit %d on a healthy run: %v", code, healthy["dev-cp"]["problems"])
	}
	g, _ := healthy["dev-cp"]["gateway"].(map[string]any)
	for _, f := range []string{"epoch", "epochChangedAt", "syncedAt", "outboxItems", "oldestOutboxAt", "dropped", "droppedAt", "recordOld", "recordOldAt", "queued", "streams", "mostClaimed", "lastBindRefusal", "storeError"} {
		if _, ok := g[f]; !ok {
			t.Errorf("the gateway object %v has no field %s", keys(g), f)
		}
	}
	mc, _ := healthy["management"]["management"].(map[string]any)["cells"].([]any)
	// lastRefusal is empty until a refusal happened, so a healthy cell has none.
	for _, f := range []string{"lastStatusAt", "unreported", "oldestUnreportedAt", "records", "openOps", "expiredOps", "forgedSeen", "lastHintCheck"} {
		if c := mc[0].(map[string]any); c[f] == nil && f != "oldestUnreportedAt" {
			t.Errorf("a cell of management %v has no field %s", keys(c), f)
		}
	}
	gw := func(mutate func(m map[string]any)) []string {
		return []string{"STUB_GW_STATUS=" + healthyGateway(mutate)}
	}
	plane := func(mutate func(m map[string]any)) []string {
		return []string{"STUB_MGMT_STATUS=" + healthyPlane(mutate)}
	}
	cellOf := func(over map[string]any) func(m map[string]any) {
		return func(m map[string]any) {
			m["cells"] = []any{planeCell("dev-cell-1", nil), planeCell("dev-cell-2", over)}
		}
	}
	op := func(state, final string, expiredAgo time.Duration) []string {
		o := map[string]any{"id": "0123456789abcdef0123456789abcdef", "cell": "dev-cell-1", "state": state, "final": final}
		if expiredAgo > 0 {
			o["expiredAt"] = timeAgo(expiredAgo)
		}
		out, _ := json.Marshal(map[string]any{"ops": []any{o}})
		return []string{"STUB_MGMT_OPS=" + string(out)}
	}
	for _, tc := range []struct {
		name    string
		env     []string
		cluster string
		want    []string
	}{
		{"the gateway has a store error", gw(func(m map[string]any) { m["storeError"] = "database is locked" }), "dev-cp",
			[]string{"store error", "database is locked", "mise run gw:reset"}},
		{"envd synced the gateway 3 minutes ago", gw(func(m map[string]any) { m["syncedAt"] = timeAgo(3 * time.Minute) }), "dev-cp",
			[]string{"more than 2 minutes", "CELL=dev-cp mise run cell:up"}},
		{"envd never synced the gateway", gw(func(m map[string]any) { m["syncedAt"] = zeroTime }), "dev-cp",
			[]string{"synced with the gateway at", "CELL=dev-cp mise run cell:up"}},
		{"the oldest outbox item is 3 minutes old and mgmtd answers", gw(func(m map[string]any) { m["outboxItems"] = 2; m["oldestOutboxAt"] = timeAgo(3 * time.Minute) }), "dev-cp",
			[]string{"oldest outbox item", "mise run gw -- outbox"}},
		{"an item was dropped 5 minutes ago", gw(func(m map[string]any) { m["dropped"] = 1; m["droppedAt"] = timeAgo(5 * time.Minute) }), "dev-cp",
			[]string{"dropped", "mise run gw -- outbox"}},
		{"an old record was refused 5 minutes ago", gw(func(m map[string]any) { m["recordOld"] = 1; m["recordOldAt"] = timeAgo(5 * time.Minute) }), "dev-cp",
			[]string{"older record", "CELL=dev-cp mise run cell:up"}},
		{"a bound cell has no stream", gw(func(m map[string]any) { m["streams"] = map[string]any{"dev-cell-1": 1} }), "dev-cp",
			[]string{"no stream of dev-cell-2", "CELL=dev-cell-2 mise run cell:up"}},
		{"a cell claimed one operation 4 times", gw(func(m map[string]any) {
			m["mostClaimed"] = map[string]any{"dev-cell-1": map[string]any{"opId": "feedfacefeedfacefeedfacefeedface", "count": 4}}
		}), "dev-cp", []string{"dev-cell-1 claimed operation feedfacefeedfacefeedfacefeedface 4 times", "mise run ops -- trace feedfacefeedfacefeedfacefeedface"}},
		{"the gateway status fails", []string{"STUB_GW_RC=1", `STUB_GW_STATUS={"level":"ERROR","msg":"gw failed","error":"pod cell-gateway-0 is absent or not Ready. Run: CELL=dev-cp mise run cell:up"}`}, "dev-cp",
			[]string{"gateway status failed", "pod cell-gateway-0 is absent", "Run: CELL=dev-cp mise run cell:up"}},
		{"a cell sent no status for 3 minutes", plane(cellOf(map[string]any{"lastStatusAt": timeAgo(3 * time.Minute)})), "management",
			[]string{"dev-cell-2", "no status", "CELL=dev-cell-2 mise run cell:verify"}},
		{"a bound cell never sent a status", plane(cellOf(map[string]any{"lastStatusAt": zeroTime})), "management",
			[]string{"dev-cell-2", "no status", "CELL=dev-cell-2 mise run cell:verify"}},
		{"an unreported item is 6 minutes old", plane(cellOf(map[string]any{"unreported": 2, "oldestUnreportedAt": timeAgo(6 * time.Minute)})), "management",
			[]string{"dev-cell-2", "unreported", "CELL=dev-cell-2 mise run cell:verify"}},
		{"a cell holds 801 records", plane(cellOf(map[string]any{"records": 801})), "management",
			[]string{"dev-cell-2", "801 operation records", "CELL=dev-cell-2 mise run cell:verify"}},
		{"an operation expired 5 minutes ago with no result", append(plane(nil), op("expired", "", 5*time.Minute)...), "management",
			[]string{"0123456789abcdef0123456789abcdef", "expired", "mise run ops -- close 0123456789abcdef0123456789abcdef"}},
		{"a hint check says keys_untrusted", plane(cellOf(map[string]any{"lastHintCheck": "keys_untrusted"})), "management",
			[]string{"dev-cell-2", "hint check", "keys_untrusted", "CELL=dev-cell-2 mise run cell:restart"}},
		{"a hint check says issuer_untrusted", plane(cellOf(map[string]any{"lastHintCheck": "issuer_untrusted"})), "management",
			[]string{"dev-cell-2", "issuer_untrusted", "mise run hostsvc:serve -- restart"}},
		{"a hint check says issuer_unavailable", plane(cellOf(map[string]any{"lastHintCheck": "issuer_unavailable"})), "management",
			[]string{"dev-cell-2", "issuer_unavailable", "mise run hostsvc:serve -- status"}},
		{"the list of operations fails", []string{"STUB_MGMT_OPS_RC=1", `STUB_MGMT_OPS={"level":"ERROR","msg":"mgmt failed","error":"boom"}`}, "management",
			[]string{"list of operations failed", "expired operations are not checked", "mise run mgmt -- op list"}},
		{"a hint check says error", plane(cellOf(map[string]any{"lastHintCheck": "error"})), "management",
			[]string{"dev-cell-2", "hint check", "error", "mise run mgmt -- keycheck --cell dev-cell-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			byName, lines, _, code := runStatus(t, tc.env...)
			bad := byName[tc.cluster]
			problems := strings.Join(strs(bad["problems"]), "\n")
			if code != 1 || bad["ok"] != false {
				t.Fatalf("exit %d, ok %v, problems %q; want exit 1 and ok false", code, bad["ok"], problems)
			}
			for _, w := range tc.want {
				if !strings.Contains(problems, w) {
					t.Errorf("problems %q lack %q", problems, w)
				}
			}
			if strings.ContainsAny(problems, "<>") {
				t.Errorf("problems %q hold a placeholder, and each command must work as printed", problems)
			}
			for _, m := range lines {
				if m["cluster"] != tc.cluster && m["ok"] != true {
					t.Errorf("the object of %s is not ok, and only %s has a bad value: %v", m["cluster"], tc.cluster, m)
				}
			}
		})
	}

	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"envd synced 90 seconds ago is within 2 minutes", gw(func(m map[string]any) { m["syncedAt"] = timeAgo(90 * time.Second) })},
		{"an outbox item of 1 minute is a wait", gw(func(m map[string]any) { m["outboxItems"] = 1; m["oldestOutboxAt"] = timeAgo(time.Minute) })},
		{"a drop 20 minutes ago is history", gw(func(m map[string]any) { m["dropped"] = 1; m["droppedAt"] = timeAgo(20 * time.Minute) })},
		{"a refused old record 20 minutes ago is history", gw(func(m map[string]any) { m["recordOld"] = 1; m["recordOldAt"] = timeAgo(20 * time.Minute) })},
		{"three claims are no concern", gw(func(m map[string]any) {
			m["mostClaimed"] = map[string]any{"dev-cell-1": map[string]any{"opId": "feedfacefeedfacefeedfacefeedface", "count": 3}}
		})},
		{"800 records are within the limit", plane(cellOf(map[string]any{"records": 800}))},
		{"an unreported item of 4 minutes is a wait", plane(cellOf(map[string]any{"unreported": 1, "oldestUnreportedAt": timeAgo(4 * time.Minute)}))},
		{"an operation that expired 20 minutes ago is history", append(plane(nil), op("expired", "", 20*time.Minute)...)},
		{"an expired operation with a final result is closed", append(plane(nil), op("final", "refused", 5*time.Minute)...)},
		{"an open operation is fine", append(plane(nil), op("open", "", 0)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			byName, _, _, code := runStatus(t, tc.env...)
			if code != 0 {
				t.Errorf("exit %d, want 0: %v %v", code, byName["dev-cp"]["problems"], byName["management"]["problems"])
			}
		})
	}
	t.Run("an outbox item of 3 minutes is no concern when mgmtd does not answer", func(t *testing.T) {
		byName, _, _, _ := runStatus(t, append(gw(func(m map[string]any) { m["outboxItems"] = 2; m["oldestOutboxAt"] = timeAgo(3 * time.Minute) }),
			"STUB_MGMT_RC=1", `STUB_MGMT_STATUS={"error":"down"}`)...)
		if p := strings.Join(strs(byName["dev-cp"]["problems"]), "\n"); strings.Contains(p, "outbox") {
			t.Errorf("problems %q name the outbox while mgmtd is down", p)
		}
	})
}

// TestStatusAgesFollowTheNodeClock: the timestamps of mgmtd and the gateway come from the clock of the VM. With a VM clock 5 minutes behind the Mac, a
// sync from 10 seconds ago on the VM clock is no problem, and a sync from 3 minutes ago on that clock still is.
func TestStatusAgesFollowTheNodeClock(t *testing.T) {
	const skew = 5 * time.Minute
	vm := func(d time.Duration) string { return timeAgo(skew + d) }
	env := func(syncedAgo time.Duration) []string {
		return []string{"STUB_CLOCK_SKEW=300",
			"STUB_GW_STATUS=" + healthyGateway(func(m map[string]any) { m["syncedAt"] = vm(syncedAgo) }),
			"STUB_MGMT_STATUS=" + healthyPlane(func(m map[string]any) {
				m["lastReportAt"] = vm(10 * time.Second)
				m["cells"] = []any{planeCell("dev-cell-1", map[string]any{"lastStatusAt": vm(20 * time.Second)}), planeCell("dev-cell-2", map[string]any{"lastStatusAt": vm(20 * time.Second)})}
			})}
	}
	healthy, _, stderr, code := runStatus(t, env(10*time.Second)...)
	if code != 0 {
		t.Fatalf("exit %d with a VM clock that lags 5 minutes, want 0: dev-cp %v, management %v\n%s", code, healthy["dev-cp"]["problems"], healthy["management"]["problems"], stderr)
	}
	late, _, _, code := runStatus(t, env(3*time.Minute)...)
	if code == 0 || !strings.Contains(strings.Join(strs(late["dev-cp"]["problems"]), "\n"), "more than 2 minutes") {
		t.Errorf("a sync from 3 minutes ago on the VM clock gave exit %d and problems %v, want the late sync", code, late["dev-cp"]["problems"])
	}
}

// TestCheckGatewaySyncedUsesTheNodeClock: check_gateway_synced reads the present from a node. With a node clock 5 minutes behind the Mac, a sync from
// 10 seconds ago on the node clock passes, and one from 3 minutes ago fails.
func TestCheckGatewaySyncedUsesTheNodeClock(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	lib, _ := filepath.Abs("../../scripts/lib.sh")
	verifyLib, _ := filepath.Abs("../../scripts/verify-lib.sh")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(nodeClockDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(syncedAgo time.Duration) (string, error) {
		cmd := exec.Command("bash", "-c", `source "$1"; source "$2"; gateway_status() { echo "$STUB_GW"; }; check_gateway_synced`, "_", lib, verifyLib)
		cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cp", "STUB_CLOCK_SKEW=300",
			"STUB_GW=" + healthyGateway(func(m map[string]any) { m["syncedAt"] = timeAgo(5*time.Minute + syncedAgo) })}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	if out, err := run(10 * time.Second); err != nil {
		t.Errorf("a sync from 10 seconds ago on the node clock failed: %v\n%s", err, out)
	}
	if out, err := run(3 * time.Minute); err == nil || !strings.Contains(out, "more than 2 minutes ago") {
		t.Errorf("a sync from 3 minutes ago on the node clock gave %v and %q, want the late sync", err, out)
	}
}
