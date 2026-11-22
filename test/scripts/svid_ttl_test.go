package scripts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// m9Rig is a copy of the scripts, the cell settings, the topology and components/lib in a temporary root, with a stub for every external
// tool that the slow-tier scripts call: uname, caffeinate, pmset, docker, kubectl, mise, date, sleep, go and kind. The stubs keep their state
// in stub/ and append each call to stub/calls. The clock of the Mac and of the nodes is the number in stub/now: date +%s prints it, and
// sleep adds its argument to it, so a wait ends at once and still counts its time.
type m9Rig struct {
	t                      *testing.T
	root, bin, stub, build string
}

// m9Uname answers uname -s with STUB_UNAME (default Linux).
const m9Uname = `#!/usr/bin/env bash
echo "uname $*" >>"$STUB_DIR/calls"
[[ "$*" == -s ]] || { echo "unexpected uname call: $*" >&2; exit 2; }
echo "${STUB_UNAME:-Linux}"
`

// m9Caffeinate runs the command after its flags, as caffeinate -ims does.
const m9Caffeinate = `#!/usr/bin/env bash
echo "caffeinate $*" >>"$STUB_DIR/calls"
[[ "$1" == -ims ]] || { echo "unexpected caffeinate call: $*" >&2; exit 2; }
shift
exec "$@"
`

// m9Pmset answers pmset -g batt with the power source STUB_POWER (default AC Power).
const m9Pmset = `#!/usr/bin/env bash
echo "pmset $*" >>"$STUB_DIR/calls"
[[ "$*" == "-g batt" ]] || { echo "unexpected pmset call: $*" >&2; exit 2; }
printf "Now drawing from '%s'\n -InternalBattery-0 (id=4653155)\t81%%; charged; 0:00 remaining present: true\n" "${STUB_POWER:-AC Power}"
`

// m9Date prints stub/now for date +%s and runs the real date for any other form.
const m9Date = `#!/usr/bin/env bash
if [[ "$*" == +%s ]]; then cat "$STUB_DIR/now"; exit 0; fi
for d in /bin /usr/bin; do [[ -x "$d/date" ]] && exec "$d/date" "$@"; done
exit 2
`

// m9Sleep adds its argument, in whole seconds, to stub/now and returns at once.
const m9Sleep = `#!/usr/bin/env bash
echo "sleep $*" >>"$STUB_DIR/calls"
n="${1%%.*}"
[[ "$n" =~ ^[0-9]+$ ]] || n=0
echo $(($(cat "$STUB_DIR/now") + n)) >"$STUB_DIR/now"
`

// m9Docker answers the clock of the node dev-cp-control-plane from stub/now, the address of a node container on the network kind (none
// when stub/no-ip-<container> exists), and the trace check of the key rotation test on dev-cell-1-control-plane, which prints stub/keytest.
const m9Docker = `#!/usr/bin/env bash
echo "docker $*" >>"$STUB_DIR/calls"
d="$STUB_DIR"
now="$(cat "$d/now")"
case "$*" in
  "exec dev-cp-control-plane date +%s") echo "$now" ;;
  "exec dev-cp-control-plane date -u +%Y-%m-%dT%H:%M:%SZ") jq -nr --argjson n "$now" '$n | todate' ;;
  "exec dev-cell-1-control-plane sh -c "*) cat "$d/keytest" 2>/dev/null; exit 0 ;;
  "inspect -f "*)
    name="${*: -1}"
    [[ ! -e "$d/no-ip-$name" ]] || { echo; exit 0; }
    case "$name" in
      dev-cell-1-control-plane) echo 172.18.0.5 ;;
      dev-cell-2-control-plane) echo 172.18.0.6 ;;
      *) echo 172.18.0.9 ;;
    esac ;;
  *) echo "unexpected docker call: $*" >&2; exit 2 ;;
esac
`

// m9Kubectl stands in for kubectl against the clusters of the rig. The state:
//   - stub/live-ttl: agent_ttl of the live server config of dev-cp (default 1m); stub/conf-fail makes the read fail.
//   - stub/agents: the agents that the SPIRE server of dev-cp lists, one "<path> <lifetime seconds> <flag>" line each, with the paths of
//     the real server: /spire/agent/cluster_jwt/<cell>/<pod uid>/<hash> and /spire/agent/k8s_psat/<cluster>/pod/<pod uid>. The flag is
//     live, banned, expired or gone (the pod of the agent is gone, and its entry stays listed). An agent that is not expired expires
//     three quarters of its lifetime after stub/now. The pods of a cluster are the pod UIDs of its agents that are not gone.
//     stub/agents-fail makes the list fail.
//   - stub/held: the cells of the entries that envd holds, one each line, for the next stub/held-reads reads of cell-records (default all).
//   - stub/inputs: the input entry IDs of envd-system/local-revocations, one each line.
//   - stub/ns-<cluster>: the e2e namespaces of the cluster, as namespace/<name> lines. A delete removes the line.
//   - stub/store-notready: the number of reads of the pod bundle-store-0 that still say not Ready. stub/apps: the Applications of argocd as
//     "<name> <sync> <health>" lines (default root Synced Healthy); an annotate of an Application sets it Synced and Healthy unless
//     stub/refresh-stuck exists.
//   - stub/claim-ending: the number of reads of the claim data-bundle-store-0 that show a deletionTimestamp.
//   - stub/no-agent-ban: the StatefulSet spire-server of dev-cp has no container agent-ban. stub/stale: "<namespace> <workload> <cluster>" of
//     a workload that runs another image.
const m9Kubectl = `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_DIR/calls"
d="$STUB_DIR"
ctx="" ns="" prev=""
for a in "$@"; do
  [[ "$prev" == --context ]] && ctx="${a#kind-}"
  [[ "$prev" == -n ]] && ns="$a"
  prev="$a"
done
ref() { printf 'localhost:5001/%s@sha256:%s' "$1" "$(printf "$2%.0s" $(seq 64))"; }
case " $* " in
  *" get configmap spire-server "*)
    [[ ! -e "$d/conf-fail" ]] || { echo "error: the server could not find the requested resource" >&2; exit 1; }
    lag="$(cat "$d/conf-lag" 2>/dev/null || echo 0)"
    if ((lag > 0)); then
      echo $((lag - 1)) >"$d/conf-lag"
      printf 'server {\n  agent_ttl = "%s"\n}\n' "$(cat "$d/live-ttl-old")"
      exit 0
    fi
    printf 'server {\n  default_x509_svid_ttl = "%s"\n  agent_ttl = "%s"\n}\n' "$(cat "$d/live-ttl" 2>/dev/null || echo 1m)" "$(cat "$d/live-ttl" 2>/dev/null || echo 1m)" ;;
  *"spire-server agent list "*)
    [[ ! -e "$d/agents-fail" ]] || { echo "error: connection refused" >&2; exit 1; }
    touch "$d/agents"
    jq -Rn --argjson now "$(cat "$d/now")" '{agents: [inputs | select(length > 0) | split(" ") | {
      id: {trust_domain: "dev.env.poc.internal", path: .[0]},
      attestation_type: (if (.[0] | contains("/cluster_jwt/")) then "cluster_jwt" else "k8s_psat" end),
      x509svid_serial_number: "1",
      x509svid_expires_at: (if .[2] == "expired" then $now - 10 else $now + ((.[1] | tonumber) * 3 / 4 | floor) end | tostring),
      banned: (.[2] == "banned"), can_reattest: false}]}' "$d/agents" ;;
  *" get pods -A -o json "*)
    touch "$d/agents"
    jq -Rn --arg c "$ctx" '{items: [inputs | split(" ") | select(length == 3 and .[2] != "gone")
      | (.[0] | capture("^/spire/agent/(cluster_jwt/(?<cell>[^/]+)/(?<uid>[^/]+)/|k8s_psat/(?<pcell>[^/]+)/pod/(?<puid>[^/]+)$)"))
      | select((.cell // .pcell) == $c) | {metadata: {uid: (.uid // .puid)}}] | unique}' "$d/agents" ;;
  *" get configmap cell-records "*)
    cells=""
    if [[ -s "$d/held" ]]; then
      reads="$(cat "$d/held-reads" 2>/dev/null || echo 1000)"
      if ((reads > 0)); then cells="$(cat "$d/held")"; echo $((reads - 1)) >"$d/held-reads"; fi
    fi
    jq -Rn --arg cells "$cells" '{data: {"local-revocations.json": ([$cells | split("\n")[] | select(length > 0)
      | {payloadType: "application/vnd.poc.local-revocation+json", payload: ({cell: .} | tojson | @base64), signatures: []}] | tojson)}}' ;;
  *" get configmap local-revocations "*)
    [[ -s "$d/inputs" ]] || exit 0
    jq -Rn '{data: ([inputs | select(length > 0) | {key: "\(.).json", value: "{}"}] | from_entries)}' "$d/inputs" ;;
  *" get namespaces -l cell.poc.internal/e2e=true -o name "*) cat "$d/ns-$ctx" 2>/dev/null; exit 0 ;;
  *" delete namespace "*)
    for a in "$@"; do
      [[ "$a" == m9-* ]] || continue
      grep -vx "namespace/$a" "$d/ns-$ctx" >"$d/ns-$ctx.new" || true
      mv "$d/ns-$ctx.new" "$d/ns-$ctx"
    done ;;
  *" get pvc data-bundle-store-0 "*)
    n="$(cat "$d/claim-ending" 2>/dev/null || echo 0)"
    if ((n > 0)); then echo $((n - 1)) >"$d/claim-ending"; printf '2026-11-22T10:00:00Z'; fi ;;
  *" delete pod bundle-store-0 "*) ;;
  *" get pod bundle-store-0 "*)
    n="$(cat "$d/store-notready" 2>/dev/null || echo 0)"
    if ((n > 0)); then echo $((n - 1)) >"$d/store-notready"; printf False; else printf True; fi ;;
  *" get applications -o json "*)
    [[ -e "$d/apps" ]] || echo "root Synced Healthy" >"$d/apps"
    jq -Rn '{items: [inputs | select(length > 0) | split(" ") | {metadata: {name: .[0]}, status: {sync: {status: .[1]}, health: {status: .[2]}}}]}' "$d/apps" ;;
  *" annotate application "*)
    if [[ ! -e "$d/refresh-stuck" ]]; then awk '{ print $1, "Synced", "Healthy" }' "$d/apps" >"$d/apps.new" && mv "$d/apps.new" "$d/apps"; fi ;;
  *" get node "*) case "$ctx" in dev-cell-1) echo 172.18.0.5 ;; dev-cell-2) echo 172.18.0.6 ;; *) echo 172.18.0.9 ;; esac ;;
  *" get statefulset/"*" -o json "*|*" get deployment/"*" -o json "*)
    w=""
    for a in "$@"; do [[ "$a" == statefulset/* || "$a" == deployment/* ]] && w="$a"; done
    c=a
    [[ "$(cat "$d/stale" 2>/dev/null)" != "$ns $w $ctx" ]] || c=b
    if [[ "$w" == statefulset/spire-server ]]; then
      ban=",{\"name\":\"agent-ban\",\"image\":\"$(ref cluster-jwt-server "$c")\"}"
      [[ ! -e "$d/no-agent-ban" ]] || ban=""
      printf '{"spec":{"template":{"spec":{"initContainers":[{"name":"install-plugin","image":"%s"}],"containers":[{"name":"spire-server","image":"ghcr.io/spiffe/spire-server:1"}%s]}}}}\n' "$(ref cluster-jwt-server "$c")" "$ban"
    else
      printf '{"spec":{"template":{"spec":{"containers":[{"name":"main","image":"%s"}]}}}}\n' "$(ref cell-proxy "$c")"
    fi ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// m9Mise stands in for mise. The calls:
//   - run mgmt -- status: a connected status, with the newest report of envd at stub/now. While stub/mgmt-down holds a number above 0, the
//     call fails and the number goes down by one. run mgmt -- unrevoke --cell <c> prints a result, and fails for a cell in stub/unrevoke-fail.
//   - run cell:up (CELL=dev-cp): the render takes the lifetime of build/gate/m9-svid-ttl, else 1m, into stub/live-ttl. Each live agent with
//     a shorter lifetime renews at once to the new one; a longer one keeps its SVID, as an agent does until half its lifetime. The call log
//     names the marker that the render saw. stub/cellup-fail makes it fail. With STUB_CONF_LAG=<n>, the next n reads of the server
//     config still give the old lifetime, as the ConfigMap does before Argo CD syncs.
//   - run cell:restart (CELL=<c>): each live agent of the cluster gets a new pod, so a new agent ID, with the live lifetime, and its old
//     entry stays listed as gone, as the real server keeps it (use_pod_uid_for_agent_id for k8s_psat). stub/restart-keep-<c> keeps the
//     old SVIDs.
//   - run cell:hydrate (CELL=<c>) fails when stub/hydrate-fail exists. run bundle -- publish fails when stub/publish-fail exists, and prints
//     the content of that file and a mise trailer to stderr when the file is not empty.
//   - run harness:status fails when stub/status-fail exists, and for as many runs as stub/status-fails holds. run revoke -- clean empties stub/inputs. run gate:<n> fails for a gate in
//     STUB_FAIL_GATES and adds STUB_GATE_SECONDS to stub/now.
const m9Mise = `#!/usr/bin/env bash
d="$STUB_DIR"
marker="$POC_BUILD_ROOT/gate/m9-svid-ttl"
seen=none
[[ ! -e "$marker" ]] || seen="$(cat "$marker")"
echo "mise $* CELL=${CELL:-} marker=$seen" >>"$d/calls"
secs() { local n="${1%[smh]}"; case "$1" in *s) echo "$n" ;; *m) echo $((n * 60)) ;; *h) echo $((n * 3600)) ;; esac; }
touch "$d/agents"
case "$1 $2" in
  "run mgmt")
    case "$4" in
      status)
        down="$(cat "$d/mgmt-down" 2>/dev/null || echo 0)"
        if ((down > 0)); then echo $((down - 1)) >"$d/mgmt-down"; echo '{"error":"mgmtd-0 is not Ready"}'; exit 1; fi
        jq -nc --argjson n "$(cat "$d/now")" '{signed: {epoch: 1, counter: 7}, applied: {epoch: 1, counter: 7}, lastReportAt: ($n | todate), cells: []}' ;;
      unrevoke)
        if grep -qx -- "$6" "$d/unrevoke-fail" 2>/dev/null; then echo '{"error":"not_connected"}'; exit 1; fi
        jq -nc --arg c "$6" '{cell: $c, revoked: false}' ;;
      *) echo "unexpected mgmt call: $*" >&2; exit 2 ;;
    esac ;;
  "run cell:up")
    [[ "${CELL:-}" == dev-cp ]] || { echo "unexpected cell:up of ${CELL:-}" >&2; exit 2; }
    [[ ! -e "$d/cellup-fail" ]] || exit 1
    ttl=1m
    [[ ! -e "$marker" ]] || ttl="$(cat "$marker")"
    if [[ -n "${STUB_CONF_LAG:-}" ]]; then cat "$d/live-ttl" 2>/dev/null >"$d/live-ttl-old" || echo 1m >"$d/live-ttl-old"; echo "$STUB_CONF_LAG" >"$d/conf-lag"; fi
    echo "$ttl" >"$d/live-ttl"
    want="$(secs "$ttl")"
    awk -v w="$want" '$3 == "live" && $2 < w { $2 = w } { print }' "$d/agents" >"$d/agents.new" && mv "$d/agents.new" "$d/agents" ;;
  "run cell:restart")
    c="${CELL:-}"
    [[ ! -e "$d/restart-keep-$c" ]] || exit 0
    want="$(secs "$(cat "$d/live-ttl" 2>/dev/null || echo 1m)")"
    awk -v c="$c" -v w="$want" '
      $3 == "live" && index($1, "/spire/agent/cluster_jwt/" c "/") == 1 { print $1, $2, "gone"; n = split($1, p, "/"); print "/spire/agent/cluster_jwt/" c "/" p[6] "r/" p[7] "r", w, "live"; next }
      $3 == "live" && index($1, "/spire/agent/k8s_psat/" c "/pod/") == 1 { print $1, $2, "gone"; print $1 "r", w, "live"; next }
      { print }' "$d/agents" >"$d/agents.new" && mv "$d/agents.new" "$d/agents" ;;
  "run harness:status")
    fails="$(cat "$d/status-fails" 2>/dev/null || echo 0)"
    if [[ -e "$d/status-fail" ]] || ((fails > 0)); then echo $((fails - 1)) >"$d/status-fails"; echo '{"cluster":"dev-cp","ok":false}'; exit 1; fi
    echo '{"cluster":"dev-cp","ok":true}' ;;
  "run cell:hydrate")
    [[ ! -e "$d/hydrate-fail" ]] || { echo "error: the hydrate failed" >&2; exit 1; }
    echo '{"hydrated":true}' ;;
  "run bundle")
    if [[ -s "$d/publish-fail" ]]; then cat "$d/publish-fail" >&2; echo "[bundle] ERROR task failed" >&2; exit 1; fi
    [[ ! -e "$d/publish-fail" ]] || { echo '{"error":"publish failed"}'; exit 1; }
    echo '{"outcome":"applied"}' ;;
  "run revoke") [[ "$4" == clean ]] || exit 2; : >"$d/inputs" ;;
  "run gate:"*)
    echo $(($(cat "$d/now") + ${STUB_GATE_SECONDS:-0})) >"$d/now"
    [[ " ${STUB_FAIL_GATES:-} " != *" $2 "* ]] || exit 1 ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

// m9Go stands in for go. A build (no -json) passes. A test run logs its arguments, adds STUB_TEST_SECONDS to stub/now, prints the events of
// the test that its -run pattern names (-run <p> or -run=<p>), and fails for a test in STUB_FAIL_TESTS. With STUB_WRITE_MARKER=1 it writes
// the slow-tier marker, as a test that records a lifetime change does. For a test in STUB_INTERRUPT_TESTS it sends SIGINT to its process
// group, as Ctrl-C does, so the signal ends the stub, tee and jq, and reaches the gate.
const m9Go = `#!/usr/bin/env bash
echo "go $*" >>"$STUB_DIR/calls"
d="$STUB_DIR"
[[ " $* " == *" -json "* ]] || exit 0
pat="" prev=""
for a in "$@"; do
  [[ "$prev" != -run ]] || pat="$a"
  [[ "$a" != -run=* ]] || pat="${a#-run=}"
  prev="$a"
done
name="${pat#^}"
name="${name%\$}"
echo $(($(cat "$d/now") + ${STUB_TEST_SECONDS:-0})) >"$d/now"
printf '{"Action":"run","Test":"%s"}\n{"Action":"output","Test":"%s","Output":"=== RUN   %s\\n"}\n' "$name" "$name" "$name"
[[ "${STUB_WRITE_MARKER:-}" != 1 ]] || { mkdir -p "$POC_BUILD_ROOT/gate"; echo 1h >"$POC_BUILD_ROOT/gate/m9-svid-ttl"; }
if [[ " ${STUB_INTERRUPT_TESTS:-} " == *" $name "* ]]; then trap - INT; kill -INT 0; sleep 5; exit 3; fi
if [[ " ${STUB_FAIL_TESTS:-} " == *" $name "* ]]; then
  printf '{"Action":"output","Test":"%s","Output":"--- FAIL: %s\\n"}\n{"Action":"fail","Test":"%s","Elapsed":2}\n' "$name" "$name" "$name"
  exit 1
fi
printf '{"Action":"output","Test":"%s","Output":"--- PASS: %s\\n"}\n{"Action":"pass","Test":"%s","Elapsed":1}\n' "$name" "$name" "$name"
`

func newM9Rig(t *testing.T) *m9Rig {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "awk")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, root, d)
	}
	r := &m9Rig{t: t, root: root, bin: filepath.Join(root, "bin"), stub: filepath.Join(root, "stub"), build: filepath.Join(root, "build")}
	for name, body := range map[string]string{"uname": m9Uname, "caffeinate": m9Caffeinate, "pmset": m9Pmset, "date": m9Date, "sleep": m9Sleep,
		"docker": m9Docker, "kubectl": m9Kubectl, "mise": m9Mise, "go": m9Go, "kind": stubKind} {
		r.write("bin/"+name, body)
	}
	r.state("now", "1700000000\n")
	r.state("calls", "")
	var images strings.Builder
	for _, n := range []string{"mgmtd", "envd", "cell-controller", "cellgw", "celld", "cluster-jwt-agent", "cluster-jwt-server", "cell-proxy"} {
		fmt.Fprintf(&images, "IMAGE_%s=localhost:5001/%s@sha256:%s\n", strings.ToUpper(strings.ReplaceAll(n, "-", "_")), n, strings.Repeat("a", 64))
	}
	r.write("build/images.env", images.String())
	for _, c := range []string{"management", "dev-cp", "dev-cell-1", "dev-cell-2"} {
		r.write("build/"+c+"/facts.env", "")
	}
	return r
}

// write writes a file of the root, executable, and makes its directory.
func (r *m9Rig) write(rel, body string) {
	r.t.Helper()
	p := filepath.Join(r.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

// state writes a file of the stub state.
func (r *m9Rig) state(rel, body string) { r.t.Helper(); r.write("stub/"+rel, body) }

func (r *m9Rig) read(rel string) string {
	b, _ := os.ReadFile(filepath.Join(r.root, rel))
	return string(b)
}

func (r *m9Rig) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(r.root, rel))
	return err == nil
}

// calls returns the call log of the stubs.
func (r *m9Rig) calls() string { return r.read("stub/calls") }

// marker writes the slow-tier marker with a lifetime.
func (r *m9Rig) marker(ttl string) { r.t.Helper(); r.write("build/gate/m9-svid-ttl", ttl+"\n") }

// command builds a command with the stubs first on PATH, the build directory of the rig and the variables in env.
func (r *m9Rig) command(name string, env []string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = append([]string{"PATH=" + r.bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"POC_BUILD_ROOT=" + r.build, "STUB_DIR=" + r.stub, "KIND_CLUSTERS_PAUSE=0"}, env...)
	// Each run has its own process group, so a stub can send a signal to the group of the script, as Ctrl-C does, and not to the tests.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

// run runs a script of the root and returns standard output, standard error and the exit status.
func (r *m9Rig) run(script string, env []string, args ...string) (string, string, int) {
	r.t.Helper()
	return r.exec(r.command(filepath.Join(r.root, "scripts", script), env, args...))
}

// lib sources scripts/lib.sh of the root with CELL and runs the snippet with the arguments in "$@".
func (r *m9Rig) lib(cell string, env []string, snippet string, args ...string) (string, string, int) {
	r.t.Helper()
	return r.exec(r.command("bash", append([]string{"CELL=" + cell}, env...), append([]string{"-c", `source "$1/scripts/lib.sh"; shift; ` + snippet, "_", r.root}, args...)...))
}

func (r *m9Rig) exec(cmd *exec.Cmd) (string, string, int) {
	r.t.Helper()
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			r.t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errOut.String(), code
}

// agents writes the agent list of the SPIRE server of dev-cp: two agents in each cell and one k8s_psat agent of dev-cp, all with the
// lifetime in seconds.
func (r *m9Rig) agents(lifetime int) {
	r.t.Helper()
	r.state("agents", fmt.Sprintf(`/spire/agent/cluster_jwt/dev-cell-1/u11/h11 %[1]d live
/spire/agent/cluster_jwt/dev-cell-1/u12/h12 %[1]d live
/spire/agent/cluster_jwt/dev-cell-2/u21/h21 %[1]d live
/spire/agent/cluster_jwt/dev-cell-2/u22/h22 %[1]d live
/spire/agent/k8s_psat/dev-cp/pod/n1 %[1]d live
`, lifetime))
}

// callAt returns the index of the first call log line that holds every part, or -1.
func callAt(calls string, parts ...string) int {
	return callIndex(calls, parts...)
}

// lastCallAt returns the index of the last call log line that holds the part, or -1.
func lastCallAt(calls, part string) int {
	last := -1
	for i, l := range strings.Split(calls, "\n") {
		if strings.Contains(l, part) {
			last = i
		}
	}
	return last
}

// TestLibReadsSlowLifetimeForDevCpOnly: while build/gate/m9-svid-ttl exists, scripts/lib.sh sets SPIRE_SVID_TTL from it after it sources
// cells/dev-cp.env, for CELL=dev-cp only, and logs "slow-tier SVID lifetime <ttl>". Another cluster keeps the value of its own env file, and a
// marker that holds no lifetime stops the script.
func TestLibReadsSlowLifetimeForDevCpOnly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, cell, marker, want, log string
		fail                          bool
	}{
		{name: "dev-cp without the marker", cell: "dev-cp", want: "1m"},
		{name: "dev-cp with the marker", cell: "dev-cp", marker: "1h", want: "1h", log: "slow-tier SVID lifetime 1h"},
		{name: "dev-cp with another lifetime", cell: "dev-cp", marker: "30m", want: "30m", log: "slow-tier SVID lifetime 30m"},
		{name: "management keeps its own", cell: "management", marker: "2h", want: "1h"},
		{name: "a cell sets none", cell: "dev-cell-1", marker: "1h", want: ""},
		{name: "a marker with no lifetime", cell: "dev-cp", marker: "soon", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newM9Rig(t)
			if tc.marker != "" {
				r.marker(tc.marker)
			}
			out, errOut, code := r.lib(tc.cell, nil, `printf '%s\n' "${SPIRE_SVID_TTL:-}"; bash -c 'printf "%s\n" "${SPIRE_SVID_TTL:-}"'`)
			if tc.fail {
				if code == 0 || !strings.Contains(errOut, "build/gate/m9-svid-ttl") || !strings.Contains(errOut, "mise run svid-ttl -- restore") {
					t.Fatalf("exit %d, stderr %q; want a stop that names the marker and the restore", code, errOut)
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if want := tc.want + "\n" + tc.want + "\n"; out != want {
				t.Errorf("SPIRE_SVID_TTL in the script and in a child: %q, want %q", out, want)
			}
			if got := strings.Contains(errOut, "slow-tier SVID lifetime"); got != (tc.log != "") || (tc.log != "" && !strings.Contains(errOut, tc.log)) {
				t.Errorf("stderr %q, want the log %q", errOut, tc.log)
			}
		})
	}
}

// TestSvidTtlSettled: svid_ttl_settled <ttl> passes when every live, current agent of the SPIRE server of dev-cp has a remaining lifetime that
// fits the lifetime: between 0.4 and 1.1 times it, the renewal window of an agent (half its lifetime to all of it) with 10 percent of the
// lifetime as margin. A banned agent, an expired entry, the entry of a pod that is gone and an agent of a cluster that does not exist do not
// count, for both attestors. Among the entries of one pod, the one with the least time left counts, and a pod that exists with entries
// that are all expired is an agent that is down, which fails the check.
func TestSvidTtlSettled(t *testing.T) {
	t.Parallel()
	const live = `/spire/agent/cluster_jwt/dev-cell-1/u11/h11 3600 live
/spire/agent/cluster_jwt/dev-cell-2/u21/h21 3600 live
/spire/agent/k8s_psat/dev-cp/pod/n1 3600 live
`
	for _, tc := range []struct {
		name, ttl, agents, kind, want string
		files                         []string
		ok                            bool
	}{
		{name: "every agent at 1h", ttl: "1h", agents: live, ok: true},
		{name: "one agent at 1m", ttl: "1h", agents: live + "/spire/agent/cluster_jwt/dev-cell-2/u22/h22 60 live\n", want: "dev-cell-2/u22"},
		{name: "a k8s_psat agent at 1m", ttl: "1h", agents: strings.Replace(live, "n1 3600", "n1 60", 1), want: "k8s_psat/dev-cp/pod/n1"},
		{name: "the k8s_psat entry of a pod that is gone", ttl: "1m", agents: strings.ReplaceAll(live, "3600", "60") + "/spire/agent/k8s_psat/dev-cp/pod/n0 3600 gone\n", ok: true},
		{name: "every agent at 1m for 1m", ttl: "1m", agents: strings.ReplaceAll(live, "3600", "60"), ok: true},
		{name: "an agent at 1h for 1m", ttl: "1m", agents: strings.Replace(strings.ReplaceAll(live, "3600", "60"), "u11/h11 60", "u11/h11 3600", 1), want: "dev-cell-1/u11"},
		{name: "a banned agent at 1m", ttl: "1h", agents: live + "/spire/agent/cluster_jwt/dev-cell-2/u23/h23 60 banned\n", ok: true},
		{name: "an expired entry beside the live one", ttl: "1h", agents: live + "/spire/agent/cluster_jwt/dev-cell-2/u21/h20 60 expired\n", ok: true},
		{name: "an agent that is down", ttl: "1h", agents: live + "/spire/agent/cluster_jwt/dev-cell-2/u23/h23 60 expired\n", want: "dev-cell-2/u23"},
		{name: "a k8s_psat agent that is down", ttl: "1h", agents: live + "/spire/agent/k8s_psat/dev-cp/pod/n2 3600 expired\n", want: "k8s_psat/dev-cp/pod/n2"},
		{name: "the entry of a pod that is gone", ttl: "1m", agents: strings.ReplaceAll(live, "3600", "60") + "/spire/agent/cluster_jwt/dev-cell-1/u19/h19 3600 gone\n", ok: true},
		{name: "an older entry of the same pod", ttl: "1m", agents: strings.ReplaceAll(live, "3600", "60") + "/spire/agent/cluster_jwt/dev-cell-1/u11/h10 3600 live\n", ok: true},
		{name: "an agent of a cluster that does not exist", ttl: "1h", agents: live + "/spire/agent/cluster_jwt/dev-cell-2/u22/h22 60 live\n", kind: "management dev-cp dev-cell-1", ok: true},
		{name: "no agent", ttl: "1h", agents: "", want: "no live agent"},
		{name: "the list fails", ttl: "1h", agents: live, files: []string{"agents-fail"}, want: "could not list the agents"},
		{name: "no lifetime", ttl: "soon", agents: live, want: "soon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newM9Rig(t)
			r.state("agents", tc.agents)
			for _, f := range tc.files {
				r.state(f, "")
			}
			var env []string
			if tc.kind != "" {
				env = append(env, "STUB_KIND="+tc.kind)
			}
			_, errOut, code := r.lib("dev-cell-1", env, `svid_ttl_settled "$1"`, tc.ttl)
			if tc.ok {
				if code != 0 {
					t.Fatalf("exit %d, stderr %q; want settled", code, errOut)
				}
				return
			}
			if code == 0 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("exit %d, stderr %q; want not settled with %q", code, errOut, tc.want)
			}
		})
	}
}

// svidTTLLine decodes the one JSON line of svid-ttl.sh.
func svidTTLLine(t *testing.T, out string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
		t.Fatalf("standard output %q is not one JSON object: %v", out, err)
	}
	return m
}

// TestSvidTtlSetWritesMarkerAndRenders: svid-ttl.sh set <ttl> checks that dev-cp is connected, writes the marker, runs CELL=dev-cp mise run
// cell:up with the marker in place, waits until the live agent_ttl and every agent have the lifetime, and then waits one old lifetime, so
// that workload SVIDs renew too. It prints one JSON line. A lifetime equal to cells/dev-cp.env skips the switch. It refuses a lifetime below
// 1m, a marker of another lifetime and a disconnected environment before it writes anything.
func TestSvidTtlSetWritesMarkerAndRenders(t *testing.T) {
	t.Parallel()
	t.Run("set 1h", func(t *testing.T) {
		t.Parallel()
		r := newM9Rig(t)
		r.agents(60)
		out, errOut, code := r.run("svid-ttl.sh", nil, "set", "1h")
		if code != 0 {
			t.Fatalf("exit %d, stderr %s\ncalls %s", code, errOut, r.calls())
		}
		if got := r.read("build/gate/m9-svid-ttl"); got != "1h\n" {
			t.Errorf("marker %q, want 1h", got)
		}
		calls := r.calls()
		status, up, list, wait := callAt(calls, "mise run mgmt -- status"), callAt(calls, "mise run cell:up CELL=dev-cp marker=1h"),
			callAt(calls, "spire-server agent list"), callAt(calls, "sleep 60")
		if status < 0 || up < status || list < up || wait < list {
			t.Errorf("want the connected check, cell:up with the marker, the agent list and then one old lifetime (60 s) of wait (%d %d %d %d):\n%s", status, up, list, wait, calls)
		}
		m := svidTTLLine(t, out)
		if m["ttl"] != "1h" || m["from"] != "1m" || m["switched"] != true {
			t.Errorf("result %v, want ttl 1h from 1m, switched", m)
		}
		show, _, code := r.run("svid-ttl.sh", nil, "show")
		s := svidTTLLine(t, show)
		if code != 0 || s["file"] != "1m" || s["marker"] != "1h" || s["live"] != "1h" {
			t.Errorf("show: exit %d, %v; want file 1m, marker 1h and live 1h", code, s)
		}
	})
	t.Run("the server config lags", func(t *testing.T) {
		t.Parallel()
		r := newM9Rig(t)
		r.agents(60)
		_, errOut, code := r.run("svid-ttl.sh", []string{"STUB_CONF_LAG=3"}, "set", "1h")
		calls := r.calls()
		if code != 0 {
			t.Fatalf("exit %d, stderr %s", code, errOut)
		}
		if poll, wait := callAt(calls, "sleep 10"), callAt(calls, "sleep 60"); poll < 0 || wait < poll {
			t.Errorf("the agents renewed before the live agent_ttl did, and the wait did not read the config again before it ended:\n%s", calls)
		}
	})
	t.Run("an agent that does not renew", func(t *testing.T) {
		t.Parallel()
		r := newM9Rig(t)
		r.agents(60)
		r.state("agents", r.read("stub/agents")+"/spire/agent/cluster_jwt/dev-cell-2/u29/h29 60 frozen\n")
		_, errOut, code := r.run("svid-ttl.sh", []string{"SVID_TTL_WAIT=60", "SVID_TTL_POLL=10"}, "set", "1h")
		if code == 0 || !strings.Contains(errOut, "dev-cell-2/u29") || !strings.Contains(errOut, "mise run gate:m9:repair") {
			t.Fatalf("exit %d, stderr %q; want a failure after the bound that names the agent and the repair", code, errOut)
		}
		if !r.exists("build/gate/m9-svid-ttl") {
			t.Error("the marker is gone after a failed wait, so the repair cannot see the switch")
		}
	})
	for _, tc := range []struct {
		name, ttl, marker, want string
		files                   []string
	}{
		{name: "below 1m", ttl: "30s", want: "1m or more"},
		{name: "no lifetime", ttl: "1d", want: "1m or more"},
		{name: "another marker", ttl: "1h", marker: "2h", want: "mise run gate:m9:repair"},
		{name: "close to the old lifetime", ttl: "2m", want: "2.5 times"},
		{name: "not connected", ttl: "1h", files: []string{"mgmt-down"}, want: "connected"},
	} {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			t.Parallel()
			r := newM9Rig(t)
			r.agents(60)
			if tc.marker != "" {
				r.marker(tc.marker)
			}
			for _, f := range tc.files {
				r.state(f, "1\n")
			}
			_, errOut, code := r.run("svid-ttl.sh", nil, "set", tc.ttl)
			if code == 0 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("exit %d, stderr %q; want a refusal with %q", code, errOut, tc.want)
			}
			if strings.Contains(r.calls(), "cell:up") {
				t.Errorf("cell:up ran after a refusal:\n%s", r.calls())
			}
			if got := r.read("build/gate/m9-svid-ttl"); got != "" && got != tc.marker+"\n" {
				t.Errorf("the marker holds %q after a refusal", got)
			}
		})
	}
	t.Run("the lifetime of cells/dev-cp.env skips the switch", func(t *testing.T) {
		t.Parallel()
		r := newM9Rig(t)
		r.agents(60)
		out, errOut, code := r.run("svid-ttl.sh", nil, "set", "1m")
		if code != 0 || strings.Contains(r.calls(), "cell:up") || r.exists("build/gate/m9-svid-ttl") {
			t.Fatalf("exit %d, stderr %q, calls %s; want a skip with no cell:up and no marker", code, errOut, r.calls())
		}
		if m := svidTTLLine(t, out); m["switched"] != false {
			t.Errorf("result %v, want switched false", m)
		}
		r.state("live-ttl", "1h\n")
		if _, errOut, code := r.run("svid-ttl.sh", nil, "set", "1m"); code == 0 || !strings.Contains(errOut, "mise run gate:m9:repair") {
			t.Errorf("a live agent_ttl of 1h with no marker: exit %d, stderr %q; want a refusal that names the repair", code, errOut)
		}
	})
}

// TestSvidTtlRestoreRestartsAndWaits: svid-ttl.sh restore checks that dev-cp is connected, removes the marker, runs CELL=dev-cp mise run cell:up,
// then cell:restart of dev-cp and of each live cell, and waits until every agent has the lifetime of cells/dev-cp.env. A cell whose agents keep
// the old SVID fails the wait with the agent. A disconnected environment keeps the marker.
func TestSvidTtlRestoreRestartsAndWaits(t *testing.T) {
	t.Parallel()
	t.Run("restore", func(t *testing.T) {
		t.Parallel()
		r := newM9Rig(t)
		r.marker("1h")
		r.state("live-ttl", "1h\n")
		r.agents(3600)
		out, errOut, code := r.run("svid-ttl.sh", nil, "restore")
		if code != 0 {
			t.Fatalf("exit %d, stderr %s\ncalls %s", code, errOut, r.calls())
		}
		if r.exists("build/gate/m9-svid-ttl") {
			t.Error("the marker is still there")
		}
		calls := r.calls()
		status, up := callAt(calls, "mise run mgmt -- status"), callAt(calls, "mise run cell:up CELL=dev-cp marker=none")
		cp, c1, c2 := callAt(calls, "mise run cell:restart CELL=dev-cp"), callAt(calls, "mise run cell:restart CELL=dev-cell-1"), callAt(calls, "mise run cell:restart CELL=dev-cell-2")
		if status < 0 || up < status || cp < up || c1 < up || c2 < up || lastCallAt(calls, "spire-server agent list") < max(cp, c1, c2) {
			t.Errorf("want the connected check, cell:up with no marker, a restart of dev-cp and of each cell, then the agent list:\n%s", calls)
		}
		if strings.Contains(calls, "cell:up CELL=dev-cp marker=1h") {
			t.Errorf("cell:up ran with the marker in place:\n%s", calls)
		}
		if m := svidTTLLine(t, out); m["ttl"] != "1m" || m["from"] != "1h" || m["restored"] != true {
			t.Errorf("result %v, want ttl 1m from 1h, restored", m)
		}
		if r.exists("build/gate/m9-svid-ttl.restoring") {
			t.Error("a restore that settled left the stamp build/gate/m9-svid-ttl.restoring")
		}
	})
	t.Run("a cell keeps the old SVIDs", func(t *testing.T) {
		t.Parallel()
		r := newM9Rig(t)
		r.marker("1h")
		r.state("live-ttl", "1h\n")
		r.agents(3600)
		r.state("restart-keep-dev-cell-2", "")
		_, errOut, code := r.run("svid-ttl.sh", []string{"SVID_TTL_WAIT=60", "SVID_TTL_POLL=10"}, "restore")
		if code == 0 || !strings.Contains(errOut, "dev-cell-2/u2") {
			t.Fatalf("exit %d, stderr %q; want a failure that names an agent of dev-cell-2", code, errOut)
		}
		if !r.exists("build/gate/m9-svid-ttl.restoring") {
			t.Error("a restore that did not settle left no stamp build/gate/m9-svid-ttl.restoring, so no check can see it")
		}
	})
	t.Run("not connected", func(t *testing.T) {
		t.Parallel()
		r := newM9Rig(t)
		r.marker("1h")
		r.state("live-ttl", "1h\n")
		r.agents(3600)
		r.state("mgmt-down", "1\n")
		_, errOut, code := r.run("svid-ttl.sh", nil, "restore")
		if code == 0 || !strings.Contains(errOut, "connected") || !r.exists("build/gate/m9-svid-ttl") || strings.Contains(r.calls(), "cell:up") {
			t.Fatalf("exit %d, stderr %q, calls %s; want a refusal that keeps the marker and runs no cell:up", code, errOut, r.calls())
		}
	})
}

// TestBundleStaleCountsMarker: the slow-tier marker and the stamp that restore leaves are inputs of the stale-build rule of bundle.sh for
// dev-cp only, because the render of dev-cp reads the marker. A marker that is newer than the hydrated bundles of dev-cp stops a publish
// of dev-cp, and a publish of a cell goes on.
func TestBundleStaleCountsMarker(t *testing.T) {
	t.Parallel()
	for _, rel := range []string{"build/gate/m9-svid-ttl", "build/gate/m9-svid-ttl.restoring"} {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			t.Parallel()
			r := newBundleRoot(t, "dev-cp", "dev-cell-1")
			if err := os.MkdirAll(filepath.Join(r.dir, "build", "gate"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(r.dir, rel), []byte("1h\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			env := []string{"IMAGES_ENV=" + filepath.Join(r.dir, "build", "images.env")}
			out, errOut, log, err := r.run("bundle.sh", env, "publish", "--target", "dev-cp")
			if err == nil || out != "" || !strings.Contains(errOut, rel) || !strings.Contains(errOut, "CELL=dev-cp mise run cell:hydrate") {
				t.Fatalf("dev-cp: err %v, output %q, stderr %q; want a stop that names %s and the hydrate", err, out, errOut, rel)
			}
			if strings.Contains(log, "bundlectl") {
				t.Errorf("the publish went on:\n%s", log)
			}
			if _, errOut, log, err := r.run("bundle.sh", env, "publish", "--target", "dev-cell-1"); err != nil {
				t.Errorf("dev-cell-1 does not read the marker, and its publish failed: %v\n%s\n%s", err, errOut, log)
			}
		})
	}
}
