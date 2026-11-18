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

const portalDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// portalMise is the fake plane. It logs each call to $STUB_STATE/calls.
//   - run hostsvc -- bootstrap-digest prints a fixed digest.
//   - run mgmt -- portal <command> --cell <c>... answers like mgmtd: request signs a step for a cell that is not requested yet (state-<cell>
//     is absent) and lists the others as alreadyRequested; retry is accepted only in a state that the plane accepts it in (failed,
//     failed_final, refused, expired) and step_open otherwise; a cell outside the catalog is cell_unknown.
//   - run mgmt -- status prints the cells that have a seq-<cell> file. Each call takes the next line of the file, and the last line
//     stays. A line is <step id>|<state>|<validReason>, and the state valid makes the cell valid.
const portalMise = `#!/usr/bin/env bash
echo "$*" >>"$STUB_STATE/calls"
case "$1 $2 $3" in
  "run hostsvc -- ") ;;
esac
if [[ "$1 $2 $3 $4" == "run hostsvc -- bootstrap-digest" ]]; then
  printf '{"bootstrapSHA256":"%s","files":12}\n' "$STUB_DIGEST"
  exit 0
fi
refuse() { printf '{"time":"2026-11-17T00:00:00Z","level":"ERROR","msg":"mgmt failed","error":"%s","reason":"%s"}\n' "$1" "$2"; exit 1; }
if [[ "$1 $2 $3 $4" == "run mgmt -- portal" ]]; then
  cmd="$5"; shift 5
  cells=()
  while (($#)); do
    case "$1" in
      --cell) cells+=("$2"); shift 2 ;;
      --bootstrap-sha256) shift 2 ;;
      *) shift ;;
    esac
  done
  steps="" already=""
  for c in "${cells[@]}"; do
    [[ "$c" != rogue ]] || refuse "cell rogue is not in the catalog" cell_unknown
    state="$(cat "$STUB_STATE/state-$c" 2>/dev/null || true)"
    case "$cmd" in
      request)
        if [[ -n "$state" ]]; then already+="${already:+,}\"$c\""; else echo requested >"$STUB_STATE/state-$c"; steps+="${steps:+,}{\"cell\":\"$c\",\"stepID\":\"${STUB_NEW_STEP_ID:-$(printf 'n%.0s' $(seq 32))}\"}"; fi ;;
      retry | recreate)
        case "$state" in
          failed | failed_final | refused | expired) echo requested >"$STUB_STATE/state-$c"; steps+="${steps:+,}{\"cell\":\"$c\",\"stepID\":\"${STUB_NEW_STEP_ID:-$(printf 'n%.0s' $(seq 32))}\"}" ;;
          *) refuse "the step of $c is open" step_open ;;
        esac ;;
      cancel | withdraw) [[ -n "$state" ]] || refuse "no step for $c" no_step ;;
    esac
  done
  printf '{"requestId":"0123456789abcdef","revision":{"epoch":1,"counter":9},"steps":[%s],"alreadyRequested":[%s]}\n' "$steps" "$already"
  exit 0
fi
if [[ "$1 $2 $3 $4" == "run mgmt -- status" ]]; then
  out='{"cells":[]}'
  for f in "$STUB_STATE"/seq-*; do
    [[ -f "$f" ]] || continue
    c="${f##*/seq-}"
    n="$(cat "$f.n" 2>/dev/null || echo 1)"
    line="$(sed -n "${n}p" "$f")"
    [[ -n "$line" ]] || line="$(tail -n 1 "$f")" || true
    echo $((n + 1)) >"$f.n"
    IFS='|' read -r id state reason <<<"$line"
    out="$(jq -c --arg c "$c" --arg id "$id" --arg s "$state" --arg r "$reason" --arg exp "${STUB_EXPIRES:-2099-01-01T00:00:00Z}" '.cells += [{name: $c, valid: ($s == "valid"), validReason: $r,
      step: (if $id == "" then null else {id: $id, issuedAt: "2026-11-17T00:00:00Z", expiresAt: (if $s == "expired" then "2000-01-01T00:00:00Z" else $exp end),
        host: {id: $id, cell: $c, state: (if $s == "valid" or $s == "expired" then "bootstrapping" else $s end), detail: "d-" + $s, reason: ""}} end)}]' <<<"$out")"
  done
  printf '%s\n' "$out"
  exit 0
fi
echo "unexpected mise call: $*" >&2
exit 2
`

const portalServe = `#!/usr/bin/env bash
echo "hostsvc-serve $*" >>"$STUB_STATE/calls"
case "$1" in
  status) [[ -z "${STUB_SERVE_FAIL:-}" ]] || exit 1; echo '{"running":true}' ;;
  steps) [[ -z "${STUB_STEPS_FAIL:-}" ]] || exit 1
    if [[ -s "$STUB_STATE/steps.json" ]]; then cat "$STUB_STATE/steps.json"; else echo '{"steps":[],"corrupt":false}'; fi ;;
esac
`

// portalEnv is a root with the fake plane. state-<cell> and seq-<cell> files in its state directory set the plane.
type portalEnv struct{ root, state string }

func newPortalEnv(t *testing.T) *portalEnv {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	e := &portalEnv{root: t.TempDir()}
	e.state = filepath.Join(e.root, "state")
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, e.root, d)
	}
	if err := os.MkdirAll(e.state, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"bin/mise": portalMise, "bin/hostsvc-serve": portalServe} {
		p := filepath.Join(e.root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *portalEnv) set(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.state, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *portalEnv) calls() []string {
	b, _ := os.ReadFile(filepath.Join(e.state, "calls"))
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (e *portalEnv) run(t *testing.T, args []string, env ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(e.root, "scripts", "portal.sh"), args...)
	cmd.Env = append([]string{"PATH=" + filepath.Join(e.root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"POC_BUILD_ROOT=" + filepath.Join(e.root, "build"), "STUB_STATE=" + e.state, "STUB_DIGEST=" + portalDigest,
		"HOSTSVC_SERVE=" + filepath.Join(e.root, "bin", "hostsvc-serve"), "PORTAL_POLL_SECONDS=0.1", "PORTAL_WAIT_SECONDS=2"}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

func portalJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Fatalf("standard output holds more than one line:\n%s", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("standard output is no JSON object: %v\n%s", err, out)
	}
	return m
}

// TestPortalScript: the portal runs bootstrap-digest once and one mgmtd call for request, recreate and retry; retry refuses on a
// running stage unless --force; wait and --wait read the step by its ID; and each final state prints a hint that the plane accepts
// in that state.
func TestPortalScript(t *testing.T) {
	newStep := strings.Repeat("n", 32)
	oldStep := strings.Repeat("o", 32)

	t.Run("request runs bootstrap-digest once, then one portal call", func(t *testing.T) {
		e := newPortalEnv(t)
		out, errOut, err := e.run(t, []string{"request", "--cell", "dev-cell-1", "--cell", "dev-cell-2"})
		if err != nil {
			t.Fatalf("request failed: %v\n%s\n%s", err, out, errOut)
		}
		want := []string{"run hostsvc -- bootstrap-digest",
			"run mgmt -- portal request --cell dev-cell-1 --cell dev-cell-2 --bootstrap-sha256 " + portalDigest}
		if got := e.calls(); !slices.Equal(got, want) {
			t.Fatalf("calls\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		m := portalJSON(t, out)
		if steps, _ := m["steps"].([]any); len(steps) != 2 || m["wait"] != nil {
			t.Fatalf("answer %v, want the answer of mgmtd with two steps and no wait", m)
		}
	})

	t.Run("a request for a cell that is requested already is a success", func(t *testing.T) {
		e := newPortalEnv(t)
		e.set(t, "state-dev-cell-1", "requested")
		out, errOut, err := e.run(t, []string{"request", "--cell", "dev-cell-1"})
		m := portalJSON(t, out)
		if got, _ := m["alreadyRequested"].([]any); err != nil || len(got) != 1 {
			t.Fatalf("err %v, answer %v, stderr %s; want alreadyRequested with exit 0", err, m, errOut)
		}
	})

	t.Run("a refusal of mgmtd is one error line with the reason", func(t *testing.T) {
		e := newPortalEnv(t)
		out, _, err := e.run(t, []string{"request", "--cell", "rogue"})
		m := portalJSON(t, out)
		if err == nil || m["reason"] != "cell_unknown" || m["level"] != "ERROR" {
			t.Fatalf("err %v, answer %v; want exit 1 and the reason cell_unknown", err, m)
		}
	})

	t.Run("withdraw and cancel make no digest", func(t *testing.T) {
		e := newPortalEnv(t)
		e.set(t, "state-dev-cell-1", "requested")
		for _, args := range [][]string{{"withdraw", "--cell", "dev-cell-1"}, {"cancel", "--cell", "dev-cell-1"}} {
			if out, errOut, err := e.run(t, args); err != nil {
				t.Fatalf("%v failed: %v\n%s\n%s", args, err, out, errOut)
			}
		}
		for _, c := range e.calls() {
			if strings.Contains(c, "bootstrap") {
				t.Errorf("a call computed a digest: %s", c)
			}
		}
	})

	t.Run("usage errors", func(t *testing.T) {
		e := newPortalEnv(t)
		for _, args := range [][]string{nil, {"explode", "--cell", "x"}, {"request"}, {"retry", "--cell", "a", "--cell", "b"}, {"withdraw", "--cell", "a", "--force"},
			{"request", "--cell"}, {"wait", "--wait", "--cell", "a"}} {
			out, _, err := e.run(t, args)
			if err == nil || portalJSON(t, out)["level"] != "ERROR" {
				t.Errorf("%v: err %v, output %q; want one error line and exit 1", args, err, out)
			}
		}
		if _, err := os.Stat(filepath.Join(e.state, "calls")); err == nil {
			t.Errorf("a usage error called the plane: %v", e.calls())
		}
	})

	t.Run("retry refuses on a running stage unless --force", func(t *testing.T) {
		e := newPortalEnv(t)
		e.set(t, "state-dev-cell-1", "failed")
		e.set(t, "steps.json", `{"steps":[{"id":"`+oldStep+`","cell":"dev-cell-1","state":"bootstrapping"}],"corrupt":false}`)
		out, _, err := e.run(t, []string{"retry", "--cell", "dev-cell-1"})
		m := portalJSON(t, out)
		if err == nil || m["reason"] != "step_running" || !strings.Contains(m["error"].(string), "--force") {
			t.Fatalf("err %v, answer %v; want a refusal that names --force", err, m)
		}
		for _, c := range e.calls() {
			if strings.Contains(c, "portal retry") || strings.Contains(c, "bootstrap-digest") {
				t.Fatalf("the refused retry reached the plane: %s", c)
			}
		}
		if out, errOut, err := e.run(t, []string{"retry", "--cell", "dev-cell-1", "--force"}); err != nil {
			t.Fatalf("retry --force failed: %v\n%s\n%s", err, out, errOut)
		}
		if got := e.calls(); !slices.Contains(got, "run mgmt -- portal retry --cell dev-cell-1 --bootstrap-sha256 "+portalDigest) {
			t.Fatalf("calls %v; want the retry with the digest, and no force flag for mgmtd", got)
		}
		for _, c := range e.calls() {
			if strings.Contains(c, "--force") {
				t.Errorf("--force reached mgmtd, which refuses it: %s", c)
			}
		}
	})

	t.Run("a failed read of the host service refuses the retry", func(t *testing.T) {
		for _, env := range []string{"STUB_SERVE_FAIL=1", "STUB_STEPS_FAIL=1"} {
			e := newPortalEnv(t)
			e.set(t, "state-dev-cell-1", "failed")
			out, _, err := e.run(t, []string{"retry", "--cell", "dev-cell-1"}, env)
			m := portalJSON(t, out)
			if err == nil || m["reason"] != "stage_read_failed" || !strings.Contains(m["error"].(string), "mise run hostsvc:serve -- ") {
				t.Fatalf("%s: err %v, answer %v; want a refusal that names the read", env, err, m)
			}
			for _, c := range e.calls() {
				if strings.Contains(c, "portal retry") {
					t.Fatalf("%s: the retry reached the plane: %s", env, c)
				}
			}
		}
	})

	t.Run("a step in another state does not stop a retry", func(t *testing.T) {
		e := newPortalEnv(t)
		e.set(t, "state-dev-cell-1", "failed")
		e.set(t, "steps.json", `{"steps":[{"id":"`+oldStep+`","cell":"dev-cell-1","state":"failed"},{"id":"`+newStep+`","cell":"dev-cell-2","state":"creating"}],"corrupt":false}`)
		if out, errOut, err := e.run(t, []string{"retry", "--cell", "dev-cell-1"}); err != nil {
			t.Fatalf("retry failed: %v\n%s\n%s", err, out, errOut)
		}
	})

	t.Run("--wait polls until the cell is valid, and logs the step and its log", func(t *testing.T) {
		e := newPortalEnv(t)
		e.set(t, "seq-dev-cell-1", newStep+"|creating|no_status\n"+newStep+"|admitting|no_status\n"+newStep+"|bootstrapping|not_bound\n|valid|\n")
		out, errOut, err := e.run(t, []string{"request", "--cell", "dev-cell-1", "--wait"})
		if err != nil {
			t.Fatalf("request --wait failed: %v\n%s\n%s", err, out, errOut)
		}
		m := portalJSON(t, out)
		cells := m["wait"].(map[string]any)["cells"].([]any)
		if len(cells) != 1 || cells[0].(map[string]any)["outcome"] != "valid" {
			t.Fatalf("answer %v, want the cell valid", m)
		}
		for _, want := range []string{"step " + newStep + " creating", "step " + newStep + " admitting", "step " + newStep + " bootstrapping", "build/hostsvc/steps/" + newStep + ".log"} {
			if !strings.Contains(errOut, want) {
				t.Errorf("stderr lacks %q:\n%s", want, errOut)
			}
		}
		if n := strings.Count(errOut, "step "+newStep+" creating"); n != 1 {
			t.Errorf("the state creating is logged %d times, want one line for each change", n)
		}
		if n := strings.Count(strings.Join(e.calls(), "\n"), "bootstrap-digest"); n != 1 {
			t.Errorf("%d digests, want 1", n)
		}
	})

	t.Run("the wait reads the step by its ID, never the step of an older request", func(t *testing.T) {
		e := newPortalEnv(t)
		e.set(t, "state-dev-cell-1", "failed_final")
		// The first two reads still show the old step in its final state. Only the third shows the new one.
		e.set(t, "seq-dev-cell-1", oldStep+"|failed_final|keys_failed\n"+oldStep+"|failed_final|keys_failed\n"+newStep+"|creating|not_bound\n|valid|\n")
		out, errOut, err := e.run(t, []string{"retry", "--cell", "dev-cell-1", "--wait"})
		if err != nil {
			t.Fatalf("retry --wait stopped on the old step: %v\n%s\n%s", err, out, errOut)
		}
		if outcome := portalJSON(t, out)["wait"].(map[string]any)["cells"].([]any)[0].(map[string]any)["outcome"]; outcome != "valid" {
			t.Fatalf("outcome %v, want valid", outcome)
		}
	})

	// For each final state, the hint is a command that the plane accepts in that state: the test runs it against the same plane.
	for _, tc := range []struct {
		name, line, state, outcome, hint string
		env                              []string
	}{
		{"refused", newStep + "|refused|no_status", "refused", "refused", "mise run portal -- retry --cell dev-cell-1", nil},
		{"failed", newStep + "|failed|no_status", "failed", "failed", "mise run portal -- retry --cell dev-cell-1", nil},
		{"failed_final", newStep + "|failed_final|no_status", "failed_final", "failed_final", "mise run portal -- retry --cell dev-cell-1", nil},
		{"expired", newStep + "|expired|no_status", "expired", "expired", "mise run portal -- retry --cell dev-cell-1", nil},
		{"timeout with the step running", newStep + "|bootstrapping|not_bound", "running", "timeout", "mise run portal -- wait --cell dev-cell-1", []string{"PORTAL_WAIT_SECONDS=1"}},
		{"not requested", "|none|not_requested", "", "not_requested", "mise run portal -- request --cell dev-cell-1", nil},
	} {
		t.Run("final state "+tc.name, func(t *testing.T) {
			e := newPortalEnv(t)
			e.set(t, "seq-dev-cell-1", tc.line+"\n")
			if tc.state != "" && tc.state != "running" {
				e.set(t, "state-dev-cell-1", tc.state)
			} else if tc.state == "running" {
				e.set(t, "state-dev-cell-1", "requested")
			}
			out, errOut, err := e.run(t, []string{"wait", "--cell", "dev-cell-1"}, tc.env...)
			if err == nil {
				t.Fatalf("wait ended with exit 0 in the state %s:\n%s", tc.name, out)
			}
			cell := portalJSON(t, out)["wait"].(map[string]any)["cells"].([]any)[0].(map[string]any)
			if cell["outcome"] != tc.outcome || cell["next"] != tc.hint || !strings.Contains(errOut, "Run: "+tc.hint) {
				t.Fatalf("outcome %v, next %v, stderr %q; want %s with the hint %q", cell["outcome"], cell["next"], errOut, tc.outcome, tc.hint)
			}
			// The hint is a command that the plane accepts now.
			args := strings.Fields(strings.TrimPrefix(tc.hint, "mise run portal -- "))
			if tc.outcome == "timeout" || tc.outcome == "not_requested" {
				// A wait on a pending cell, and a request for a cell that has no request: both read or ask, with the plane as it is.
				e.set(t, "seq-dev-cell-1", "|valid|\n")
			}
			if hintOut, hintErr, err := e.run(t, args); err != nil {
				t.Fatalf("the plane refuses the hint %q in the state %s: %v\n%s\n%s", tc.hint, tc.name, err, hintOut, hintErr)
			}
		})
	}

	t.Run("a hint that the plane would refuse is no hint", func(t *testing.T) {
		// retry in the state running is refused by the plane, so the wait never prints it for a running step.
		e := newPortalEnv(t)
		e.set(t, "state-dev-cell-1", "requested")
		out, _, err := e.run(t, []string{"retry", "--cell", "dev-cell-1"})
		if err == nil || portalJSON(t, out)["reason"] != "step_open" {
			t.Fatalf("err %v, output %q; the fake plane must refuse retry in the state requested", err, out)
		}
	})
}
