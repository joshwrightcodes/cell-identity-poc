package scripts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// partitionDocker stands in for docker and for the commands that the script runs in a node through docker exec. It keeps one rule list
// for each node and tool in $STUB_DIR/rules/<node>.<tool>, and models -I, -C, -D and -S of iptables and ip6tables on them, with
// the exit codes of the real tools. A rule that -I adds is the line "-A <chain> <spec>", as -S prints it. The stub answers the node clock
// with STUB_NOW. It writes each timer command of sh -c to $STUB_DIR/timers and does not run it. docker inspect reads the addresses from
// $STUB_DIR/addr/<container>.4 and .6, and fails for a container with neither file. A node with the file $STUB_DIR/down-<node> does
// not answer. Every call goes to $STUB_DIR/calls, in order.
const partitionDocker = `#!/usr/bin/env bash
set -uo pipefail
d="$STUB_DIR"
echo "docker $*" >>"$d/calls"
case "$1" in
  inspect)
    name="${*: -1}"
    [[ -e "$d/addr/$name.4" || -e "$d/addr/$name.6" ]] || { echo "Error: No such object: $name" >&2; exit 1; }
    fam=4; [[ "$*" == *GlobalIPv6Address* ]] && fam=6
    cat "$d/addr/$name.$fam" 2>/dev/null || echo
    exit 0 ;;
  exec) ;;
  *) echo "unexpected docker call: $*" >&2; exit 2 ;;
esac
node="$2"; shift 2
[[ ! -e "$d/down-$node" ]] || { echo "Error response from daemon: container $node is not running" >&2; exit 1; }
case "$1" in
  date) [[ "$*" == "date +%s" ]] || exit 2; echo "${STUB_NOW:-1700000000}"; exit 0 ;;
  sh) [[ "$2" == -c ]] || exit 2; echo "$node|$3" >>"$d/timers"; exit 0 ;;
  iptables | ip6tables) ;;
  *) echo "unexpected docker exec: $*" >&2; exit 2 ;;
esac
tool="$1"; op="$2"
mkdir -p "$d/rules"
f="$d/rules/$node.$tool"
touch "$f"
case "$op" in
  -S)
    chain="$3"
    echo "-P $chain ACCEPT"
    while IFS= read -r line; do
      [[ -z "$line" || "$line" != "-A $chain "* ]] || printf '%s\n' "$line"
    done <"$f" ;;
  -I)
    chain="$3"; pos="$4"
    [[ "$pos" == 1 ]] || { echo "the stub models only position 1, got $pos" >&2; exit 2; }
    { printf '%s\n' "-A $chain ${*:5}"; cat "$f"; } >"$f.new"; mv "$f.new" "$f" ;;
  -C)
    grep -Fxq -- "-A $3 ${*:4}" "$f" || { echo "$tool: Bad rule (does a matching rule exist in that chain?)." >&2; exit 1; } ;;
  -D)
    line="-A $3 ${*:4}"
    grep -Fxq -- "$line" "$f" || { echo "$tool: Bad rule (does a matching rule exist in that chain?)." >&2; exit 1; }
    awk -v l="$line" '$0 == l && !done { done = 1; next } { print }' "$f" >"$f.new"; mv "$f.new" "$f" ;;
  *) echo "unexpected $tool call: $*" >&2; exit 2 ;;
esac
`

// partitionEnv is a stubbed harness for the partition tool. addrs maps a container to its IPv4 and IPv6 address.
type partitionEnv struct {
	t    *testing.T
	dir  string
	bin  string
	stub string
	env  []string
}

func newPartitionEnv(t *testing.T, kind string, addrs map[string][2]string) *partitionEnv {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir := t.TempDir()
	e := &partitionEnv{t: t, dir: dir, bin: filepath.Join(dir, "bin"), stub: filepath.Join(dir, "stub")}
	for _, d := range []string{e.bin, filepath.Join(e.stub, "addr"), filepath.Join(e.stub, "rules")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"docker": partitionDocker, "kind": stubKind} {
		if err := os.WriteFile(filepath.Join(e.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for c, a := range addrs {
		for i, fam := range []string{"4", "6"} {
			if a[i] == "" && fam == "6" {
				continue
			}
			e.write("addr/"+c+"-control-plane."+fam, a[i]+"\n")
		}
	}
	e.env = []string{"STUB_KIND=" + kind}
	return e
}

func (e *partitionEnv) write(rel, body string) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.stub, rel), []byte(body), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *partitionEnv) read(rel string) string {
	b, _ := os.ReadFile(filepath.Join(e.stub, rel))
	return string(b)
}

// rules returns the rule lines that the stub holds for a node and a tool.
func (e *partitionEnv) rules(node, tool string) []string {
	var out []string
	for _, l := range strings.Split(e.read("rules/"+node+"-control-plane."+tool), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// run runs scripts/partition.sh with the stubs and returns standard output, standard error and the error.
func (e *partitionEnv) run(args ...string) (string, string, error) {
	e.t.Helper()
	script, _ := filepath.Abs("../../scripts/partition.sh")
	cmd := exec.Command(script, args...)
	cmd.Env = append([]string{"PATH=" + e.bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"POC_BUILD_ROOT=" + filepath.Join(e.dir, "build"), "STUB_DIR=" + e.stub, "KIND_CLUSTERS_PAUSE=0"}, e.env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return out.String(), errOut.String(), err
}

func (e *partitionEnv) mustRun(args ...string) string {
	e.t.Helper()
	out, errOut, err := e.run(args...)
	if err != nil {
		e.t.Fatalf("partition %v: %v\n%s%s", args, err, out, errOut)
	}
	return out
}

// partitionAddrs is dev-cp with both families, and the others with the addresses of the kind network.
var partitionAddrs = map[string][2]string{
	"management": {"172.18.0.2", "fc00:f853:ccd:e793::2"},
	"dev-cp":     {"172.18.0.3", "fc00:f853:ccd:e793::3"},
	"dev-cell-1": {"172.18.0.5", "fc00:f853:ccd:e793::5"},
	"dev-cell-2": {"172.18.0.6", "fc00:f853:ccd:e793::6"},
}

const allClusters = "management dev-cp dev-cell-1 dev-cell-2"

// cutLine is the rule line that -S prints for one rule of a cut.
func cutLine(chain, flag, addr, tag string) string {
	mask := "/32"
	if strings.Contains(addr, ":") {
		mask = "/128"
	}
	return fmt.Sprintf("-A %s %s %s%s -m comment --comment %s -j DROP", chain, flag, addr, mask, tag)
}

type cutResult struct {
	Tag       string   `json:"tag"`
	Node      string   `json:"node"`
	Peers     []string `json:"peers"`
	Direction string   `json:"direction"`
	IPv6      bool     `json:"ipv6"`
	Note      string   `json:"note"`
	Until     string   `json:"until"`
}

func parseCut(t *testing.T, out string) cutResult {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one JSON line, got:\n%s", out)
	}
	var r cutResult
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	return r
}

var tagForm = regexp.MustCompile(`^gate-m9-cut-[0-9a-f]{8}$`)

// timerRules returns the node and the rule line of each timer that the stub recorded, and fails when a timer is not of the form that the
// plan fixes: nohup sh -c 'sleep <s>; <tool> -C <rule> && <tool> -D <rule>' in the background.
func (e *partitionEnv) timers(seconds int) map[string]string {
	e.t.Helper()
	re := regexp.MustCompile(`^(\S+)\|nohup sh -c 'sleep (\d+); (ip6?tables) -C (\S+) (.+) && (ip6?tables) -D (\S+) (.+)' >/dev/null 2>&1 &$`)
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(e.read("timers")), "\n") {
		if l == "" {
			continue
		}
		m := re.FindStringSubmatch(l)
		if m == nil {
			e.t.Fatalf("a timer is not of the planned form: %s", l)
		}
		if m[2] != fmt.Sprint(seconds) || m[3] != m[6] || m[4] != m[7] || m[5] != m[8] {
			e.t.Fatalf("the timer sleeps %s s and checks %s %s %s, but deletes %s %s %s: %s", m[2], m[3], m[4], m[5], m[6], m[7], m[8], l)
		}
		got[m[3]+" "+"-A "+m[4]+" "+m[5]] = m[1]
	}
	return got
}

// order checks that every timer call comes before the first -I call in the log of the stub.
func (e *partitionEnv) timersBeforeRules() {
	e.t.Helper()
	lastTimer, firstInsert := -1, -1
	for i, l := range strings.Split(e.read("calls"), "\n") {
		switch {
		case strings.Contains(l, " sh -c "):
			lastTimer = i
		case strings.Contains(l, " -I ") && firstInsert < 0:
			firstInsert = i
		}
	}
	if lastTimer < 0 || firstInsert < 0 || lastTimer > firstInsert {
		e.t.Fatalf("every timer must be armed before the first rule goes in (last timer call %d, first insert call %d):\n%s", lastTimer, firstInsert, e.read("calls"))
	}
}

// TestPartitionCutBoth: a cut in both directions of a peer with an IPv4 address only puts four rules with the tag in iptables, in the chains
// FORWARD and OUTPUT with -d and FORWARD and INPUT with -s, each at position 1 (the last rule that goes in is the first of the list). The
// script arms four removal timers first, one for each rule, with a sleep of the hold plus 15 minutes. Each timer checks and deletes the
// rule that it names. ip6tables holds nothing, and the JSON line says that the cut is IPv4 only.
func TestPartitionCutBoth(t *testing.T) {
	t.Parallel()
	addrs := map[string][2]string{"dev-cell-2": {"172.18.0.6", "fc00::6"}, "dev-cp": {"172.18.0.3", ""}}
	e := newPartitionEnv(t, allClusters, addrs)
	res := parseCut(t, e.mustRun("cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", "5", "--tag", "gate-m9-cut-0a1b2c3d"))
	if res.Tag != "gate-m9-cut-0a1b2c3d" || res.Node != "dev-cell-2-control-plane" || res.Direction != "both" || res.IPv6 || res.Note == "" ||
		len(res.Peers) != 1 || res.Peers[0] != "172.18.0.3" || res.Until != "2023-11-14T22:18:20Z" {
		t.Errorf("JSON line: %+v", res)
	}
	tag := res.Tag
	// Inserts at position 1 in the order FORWARD -d, OUTPUT -d, FORWARD -s, INPUT -s leave the list in the reverse order.
	want := []string{
		cutLine("INPUT", "-s", "172.18.0.3", tag),
		cutLine("FORWARD", "-s", "172.18.0.3", tag),
		cutLine("OUTPUT", "-d", "172.18.0.3", tag),
		cutLine("FORWARD", "-d", "172.18.0.3", tag),
	}
	if got := e.rules("dev-cell-2", "iptables"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("iptables rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := e.rules("dev-cell-2", "ip6tables"); len(got) != 0 {
		t.Errorf("a peer with no IPv6 address got ip6tables rules: %v", got)
	}
	if got := e.rules("dev-cp", "iptables"); len(got) != 0 {
		t.Errorf("the peer node was changed: %v", got)
	}
	timers := e.timers((5 + 15) * 60)
	if len(timers) != 4 {
		t.Fatalf("want four timers, got %d: %v", len(timers), timers)
	}
	for _, w := range want {
		if timers["iptables "+w] != "dev-cell-2-control-plane" {
			t.Errorf("no timer in the node for the rule %q: %v", w, timers)
		}
	}
	e.timersBeforeRules()
}

// TestPartitionCutBothFamilies: the same four rules go in ip6tables for the IPv6 address of the peer with the mask /128, next to the four of
// iptables, so a flow that leaves by the IPv6 address does not escape. Each of the eight rules has its own timer.
func TestPartitionCutBothFamilies(t *testing.T) {
	t.Parallel()
	e := newPartitionEnv(t, allClusters, partitionAddrs)
	res := parseCut(t, e.mustRun("cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", "5"))
	if !tagForm.MatchString(res.Tag) {
		t.Fatalf("the generated tag %q is not gate-m9-cut-<8 hex>", res.Tag)
	}
	if !res.IPv6 || res.Note != "" || len(res.Peers) != 2 || res.Peers[1] != "fc00:f853:ccd:e793::3" {
		t.Errorf("JSON line: %+v", res)
	}
	v6 := "fc00:f853:ccd:e793::3"
	want := []string{
		cutLine("INPUT", "-s", v6, res.Tag),
		cutLine("FORWARD", "-s", v6, res.Tag),
		cutLine("OUTPUT", "-d", v6, res.Tag),
		cutLine("FORWARD", "-d", v6, res.Tag),
	}
	if got := e.rules("dev-cell-2", "ip6tables"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ip6tables rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := e.rules("dev-cell-2", "iptables"); len(got) != 4 || !strings.Contains(got[0], "172.18.0.3/32") {
		t.Errorf("iptables rules: %v", got)
	}
	timers := e.timers(20 * 60)
	if len(timers) != 8 {
		t.Fatalf("want eight timers, got %d: %v", len(timers), timers)
	}
	for _, w := range want {
		if timers["ip6tables "+w] == "" {
			t.Errorf("no timer for the ip6tables rule %q", w)
		}
	}
	e.timersBeforeRules()
}

// TestPartitionCutOut: direction out puts -d rules in FORWARD and OUTPUT, for both families, and nothing in INPUT.
func TestPartitionCutOut(t *testing.T) {
	t.Parallel()
	e := newPartitionEnv(t, allClusters, partitionAddrs)
	res := parseCut(t, e.mustRun("cut", "--from", "dev-cell-2", "--to", "dev-cp", "--direction", "out", "--hold", "3"))
	if res.Direction != "out" {
		t.Errorf("direction %q", res.Direction)
	}
	for tool, addr := range map[string]string{"iptables": "172.18.0.3", "ip6tables": "fc00:f853:ccd:e793::3"} {
		want := []string{cutLine("OUTPUT", "-d", addr, res.Tag), cutLine("FORWARD", "-d", addr, res.Tag)}
		if got := e.rules("dev-cell-2", tool); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s rules:\n%s\nwant:\n%s", tool, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	if n := len(e.timers(18 * 60)); n != 4 {
		t.Errorf("want one timer for each of the four rules, got %d", n)
	}
}

// TestPartitionCutIn: direction in puts -s rules in FORWARD and INPUT, for both families, and nothing in OUTPUT.
func TestPartitionCutIn(t *testing.T) {
	t.Parallel()
	e := newPartitionEnv(t, allClusters, partitionAddrs)
	res := parseCut(t, e.mustRun("cut", "--from", "dev-cp", "--to", "management", "--direction", "in", "--hold", "3"))
	if res.Direction != "in" || res.Node != "dev-cp-control-plane" {
		t.Errorf("JSON line: %+v", res)
	}
	for tool, addr := range map[string]string{"iptables": "172.18.0.2", "ip6tables": "fc00:f853:ccd:e793::2"} {
		want := []string{cutLine("INPUT", "-s", addr, res.Tag), cutLine("FORWARD", "-s", addr, res.Tag)}
		if got := e.rules("dev-cp", tool); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s rules:\n%s\nwant:\n%s", tool, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

// TestPartitionHealTag: heal --tag deletes the rules of that tag in both families on the node and leaves the rules of another tag. It finds
// the rules by their comment, so it also deletes a rule that a crash left with no cut around it, for an address that the peer no longer has.
func TestPartitionHealTag(t *testing.T) {
	t.Parallel()
	e := newPartitionEnv(t, allClusters, partitionAddrs)
	a := parseCut(t, e.mustRun("cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", "5", "--tag", "gate-m9-cut-aaaaaaaa"))
	b := parseCut(t, e.mustRun("cut", "--from", "dev-cell-2", "--to", "dev-cell-1", "--hold", "5", "--tag", "gate-m9-cut-bbbbbbbb"))
	stale := cutLine("FORWARD", "-d", "172.18.0.99", a.Tag)
	e.write("rules/dev-cell-2-control-plane.iptables", stale+"\n"+e.read("rules/dev-cell-2-control-plane.iptables"))
	out := e.mustRun("heal", "--tag", a.Tag)
	var res struct {
		Tag    string   `json:"tag"`
		Healed int      `json:"healed"`
		Nodes  []string `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil || res.Tag != a.Tag || res.Healed != 9 || len(res.Nodes) != 1 || res.Nodes[0] != "dev-cell-2-control-plane" {
		t.Errorf("heal output %q: %+v %v", out, res, err)
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, l := range e.rules("dev-cell-2", tool) {
			if strings.Contains(l, a.Tag) {
				t.Errorf("%s still holds %s", tool, l)
			}
		}
		if n := len(e.rules("dev-cell-2", tool)); n != 4 {
			t.Errorf("%s holds %d rules after the heal, want the 4 of %s", tool, n, b.Tag)
		}
	}
	// A heal of a tag with no rules is no error, because a timer can have removed them.
	e.mustRun("heal", "--tag", a.Tag)
	if _, _, err := e.run("heal", "--tag", "blackhole"); err == nil {
		t.Errorf("heal accepted a tag without the prefix")
	}
}

// TestPartitionHealAll: heal --all deletes every rule of the tool on every existing node in both families, in two nodes at once. A rule of
// gate-m3-blackhole- and a rule with another comment stay. The delete calls name no rule outside the prefix. A cluster that kind does not list
// (rogue here) is not touched. list shows the remaining rules before the heal and none after.
func TestPartitionHealAll(t *testing.T) {
	t.Parallel()
	e := newPartitionEnv(t, "management dev-cp dev-cell-1 dev-cell-2", partitionAddrs)
	e.mustRun("cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", "5", "--tag", "gate-m9-cut-aaaaaaaa")
	e.mustRun("cut", "--from", "dev-cp", "--to", "management", "--hold", "5", "--tag", "gate-m9-cut-bbbbbbbb", "--direction", "out")
	m3 := "-A FORWARD -d 172.18.0.2/32 -p tcp -m comment --comment gate-m3-blackhole-1234abcd -j DROP"
	other := "-A INPUT -s 10.0.0.1/32 -m comment --comment keep-me -j DROP"
	plain := "-A OUTPUT -d 10.0.0.2/32 -j DROP"
	for _, node := range []string{"dev-cp", "dev-cell-2"} {
		for _, tool := range []string{"iptables", "ip6tables"} {
			f := "rules/" + node + "-control-plane." + tool
			e.write(f, m3+"\n"+other+"\n"+plain+"\n"+e.read(f))
		}
	}
	e.write("rules/rogue-control-plane.iptables", cutLine("FORWARD", "-d", "172.18.0.9", "gate-m9-cut-cccccccc")+"\n")
	var listed int
	for _, l := range strings.Split(strings.TrimSpace(e.mustRun("list")), "\n") {
		var r struct{ Node, Tool, Chain, Tag, Rule string }
		if err := json.Unmarshal([]byte(l), &r); err != nil || !tagForm.MatchString(r.Tag) || !strings.Contains(r.Rule, r.Tag) || r.Tool == "" || r.Chain == "" {
			t.Fatalf("list line %q: %+v %v", l, r, err)
		}
		if strings.Contains(r.Rule, "m3-blackhole") || strings.Contains(r.Rule, "keep-me") {
			t.Errorf("list shows a rule outside the prefix: %s", l)
		}
		listed++
	}
	if listed != 8+4 {
		t.Errorf("list shows %d rules, want 12 (8 of the first cut and 4 of the second)", listed)
	}
	out := e.mustRun("heal", "--all")
	var res struct {
		Healed int      `json:"healed"`
		Nodes  []string `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil || res.Healed != 12 || len(res.Nodes) != 2 {
		t.Errorf("heal --all output %q: %+v %v", out, res, err)
	}
	for _, node := range []string{"dev-cp", "dev-cell-2"} {
		for _, tool := range []string{"iptables", "ip6tables"} {
			got := e.rules(node, tool)
			if len(got) != 3 || !strings.HasPrefix(got[0], "-A FORWARD") || got[0] != m3 || got[1] != other || got[2] != plain {
				t.Errorf("%s %s after heal --all: %v, want the three foreign rules unchanged", node, tool, got)
			}
		}
	}
	if got := e.rules("rogue", "iptables"); len(got) != 1 {
		t.Errorf("heal --all changed the node of a cluster that kind does not list: %v", got)
	}
	for _, l := range strings.Split(e.read("calls"), "\n") {
		if strings.Contains(l, " -D ") && !strings.Contains(l, "gate-m9-cut-") {
			t.Errorf("a delete call names a rule outside the prefix: %s", l)
		}
	}
	if strings.TrimSpace(e.mustRun("list")) != "" {
		t.Errorf("list is not empty after heal --all")
	}
}

// TestPartitionHealAllSkipsAbsentCluster: a cluster that kind does not list gets no docker call at all.
func TestPartitionHealAllSkipsAbsentCluster(t *testing.T) {
	t.Parallel()
	e := newPartitionEnv(t, "dev-cp", partitionAddrs)
	e.mustRun("heal", "--all")
	for _, l := range strings.Split(e.read("calls"), "\n") {
		if strings.Contains(l, "dev-cell-2") || strings.Contains(l, "management") {
			t.Errorf("a call reached a cluster that does not exist: %s", l)
		}
	}
}

// TestPartitionRefusesSameCluster: --from and --to of one cluster is an error before any docker call changes a node.
func TestPartitionRefusesSameCluster(t *testing.T) {
	t.Parallel()
	e := newPartitionEnv(t, allClusters, partitionAddrs)
	_, errOut, err := e.run("cut", "--from", "dev-cp", "--to", "dev-cp", "--hold", "5")
	if err == nil || !strings.Contains(errOut, "itself") {
		t.Fatalf("want a refusal that names the same cluster, got err %v, stderr %q", err, errOut)
	}
	if calls := e.read("calls"); calls != "" {
		t.Errorf("the refusal made docker calls:\n%s", calls)
	}
}

// TestPartitionHoldBounds: the hold is 1 to 600 minutes. Each bound passes, and 0, 601, a negative number, a fraction and text fail with
// no docker call. The sleep of the timers follows the hold.
func TestPartitionHoldBounds(t *testing.T) {
	t.Parallel()
	for _, hold := range []string{"0", "601", "-1", "1.5", "abc", "", "0010", "99999"} {
		e := newPartitionEnv(t, allClusters, partitionAddrs)
		_, errOut, err := e.run("cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", hold)
		if err == nil || !strings.Contains(errOut, "hold") {
			t.Errorf("hold %q: want a refusal that names the hold, got %v %q", hold, err, errOut)
		}
		if calls := e.read("calls"); calls != "" {
			t.Errorf("hold %q made docker calls:\n%s", hold, calls)
		}
	}
	for hold, secs := range map[string]int{"1": 16 * 60, "600": 615 * 60} {
		e := newPartitionEnv(t, allClusters, partitionAddrs)
		e.mustRun("cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", hold)
		if n := len(e.timers(secs)); n != 8 {
			t.Errorf("hold %s: want 8 timers that sleep %d s, got %d", hold, secs, n)
		}
	}
}

// TestPartitionRefusesBadInput: a bad direction, a tag that is not of the form, a missing peer and a node that does not answer change no rule.
// A cut whose insert fails midway deletes the rules that went in, so no rule stays that the caller does not know of.
func TestPartitionRefusesBadInput(t *testing.T) {
	t.Parallel()
	e := newPartitionEnv(t, allClusters, partitionAddrs)
	for name, args := range map[string][]string{
		"direction": {"cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", "5", "--direction", "up"},
		"tag":       {"cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", "5", "--tag", "gate-m3-blackhole-1"},
		"peer":      {"cut", "--from", "dev-cell-2", "--to", "nowhere", "--hold", "5"},
		"cluster":   {"cut", "--from", "dev-cell-2;x", "--to", "dev-cp", "--hold", "5"},
		"verb":      {"explode"},
	} {
		if _, _, err := e.run(args...); err == nil {
			t.Errorf("%s: the script accepted %v", name, args)
		}
	}
	e.write("down-dev-cell-2-control-plane", "")
	if _, _, err := e.run("cut", "--from", "dev-cell-2", "--to", "dev-cp", "--hold", "5"); err == nil {
		t.Errorf("a node that does not answer was accepted")
	}
	if strings.Contains(e.read("calls"), " -I ") || e.read("timers") != "" {
		t.Errorf("a refused cut changed a node:\n%s", e.read("calls"))
	}
	if _, _, err := e.run("heal", "--all"); err == nil {
		t.Errorf("heal --all reported success for a node that does not answer")
	}
}

// opDockerCut is used by TestVerifyNoPartition. It answers iptables -S and ip6tables -S of the node with a rule list from
// STUB_RULES_<tool> (one rule line for each line), and fails for the nodes in STUB_DOCKER_FAIL.
const verifyPartitionDocker = `#!/usr/bin/env bash
[[ "$1" == exec ]] || { echo "unexpected docker call: $*" >&2; exit 2; }
node="$2"; tool="$3"
[[ " ${STUB_DOCKER_FAIL:-} " != *" $node "* ]] || { echo "Error response from daemon: No such container: $node" >&2; exit 1; }
[[ "$4" == -S ]] || exit 2
echo "-P $5 ACCEPT"
case "$tool" in iptables) rules="${STUB_RULES_IPTABLES:-}" ;; ip6tables) rules="${STUB_RULES_IP6TABLES:-}" ;; *) exit 2 ;; esac
while IFS= read -r line; do
  [[ -z "$line" || "$line" != "-A $5 "* ]] || printf '%s\n' "$line"
done <<<"$rules"
`

// TestVerifyNoPartition runs check_no_partition of scripts/verify.sh against a node with a stub docker. A clean node passes, and so does a
// node that holds only a rule of gate-m3-blackhole-. A cut rule in iptables, or in ip6tables only, fails and prints the rule and the heal
// command. A node that does not answer fails.
func TestVerifyNoPartition(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	lib, _ := filepath.Abs("../../scripts/lib.sh")
	verify, _ := filepath.Abs("../../scripts/verify.sh")
	m3 := "-A FORWARD -m comment --comment gate-m3-blackhole-1 -j DROP"
	v4 := cutLine("FORWARD", "-d", "172.18.0.3", "gate-m9-cut-0a1b2c3d")
	v6 := cutLine("INPUT", "-s", "fc00::3", "gate-m9-cut-0a1b2c3d")
	for _, tc := range []struct {
		name, r4, r6, fail string
		want               string
		ok                 bool
	}{
		{name: "clean", ok: true},
		{name: "blackhole only", r4: m3, ok: true},
		{name: "iptables rule", r4: v4, want: "iptables -D FORWARD -d 172.18.0.3/32"},
		{name: "ip6tables rule only", r6: v6, want: "ip6tables -D INPUT -s fc00::3/128"},
		{name: "no answer", fail: "dev-cell-2-control-plane", want: "does not answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(verifyPartitionDocker), 0o755); err != nil {
				t.Fatal(err)
			}
			script := `source "$1"; eval "$(sed -n '/^check_no_partition()/,/^}/p' "$2")"; check_no_partition`
			cmd := exec.Command("bash", "-c", script, "_", lib, verify)
			cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cell-2",
				"STUB_RULES_IPTABLES=" + tc.r4, "STUB_RULES_IP6TABLES=" + tc.r6, "STUB_DOCKER_FAIL=" + tc.fail}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v:\n%s", err, tc.ok, out.String())
			}
			if tc.want != "" && !strings.Contains(out.String(), tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out.String())
			}
			if !tc.ok && tc.fail == "" && !strings.Contains(out.String(), "Run: mise run partition -- heal --all") {
				t.Errorf("output lacks the heal command:\n%s", out.String())
			}
		})
	}
}

// TestVerifyCallsCheckNoPartition: cell:verify runs check_no_partition for every cell, not only for a cell with a relay target.
func TestVerifyCallsCheckNoPartition(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../scripts/verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^check "[^"]*" check_no_partition$`)
	if !re.Match(b) {
		t.Errorf("verify.sh has no unconditional call of check_no_partition at the top level")
	}
}
