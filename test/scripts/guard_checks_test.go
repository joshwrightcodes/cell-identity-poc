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

// guardKubectl answers the reads of the guard checks and of scripts/gate-m3-repair.sh.
//   - STUB_SA is the ServiceAccount argocd-agent, STUB_BINDINGS the list of RoleBindings and
//     ClusterRoleBindings, and STUB_LEFT the list of objects with the label poc.internal/test.
//   - A delete call goes to $STUB_LOG, and it empties the list of leftovers.
const guardKubectl = `#!/usr/bin/env bash
args=" $* "
empty='{"items":[]}'
bare='{"metadata":{}}'
echo "kubectl $*" >>"$STUB_LOG"
case "$args" in
  *" get serviceaccount argocd-agent -o json "*) echo "${STUB_SA:-$bare}" ;;
  *" get configmap argocd-cm "*) printf '%s' "${STUB_INSTANCE_KEY:-}" ;;
  *" get roles,rolebindings,clusterroles,clusterrolebindings,namespaces,serviceaccounts -A -l poc.internal/test -o json "*)
    if [[ -f "$STUB_LOG.deleted" ]]; then echo "$empty"; else echo "${STUB_LEFT:-$empty}"; fi ;;
  *" get rolebindings,clusterrolebindings -A -o json "*) echo "${STUB_BINDINGS:-$empty}" ;;
  *" delete "*) touch "$STUB_LOG.deleted" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

func runGuardScript(t *testing.T, snippet string, env ...string) (string, string, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(guardKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(dir, "kubectl.log")
	cmd := exec.Command("bash", "-c", `source "$1"; `+snippet, "_", lib)
	cmd.Env = append([]string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_LOG=" + logFile}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	calls, _ := os.ReadFile(logFile)
	return out.String(), string(calls), err
}

func TestAgentServiceAccountMustBeUnmanaged(t *testing.T) {
	for _, tc := range []struct {
		name, sa, key, want string
	}{
		{"no annotation, label or owner", `{"metadata":{"labels":{"cell.poc.internal/harness":"argocd-agent"}}}`, "", ""},
		{"a tracking-id annotation", `{"metadata":{"annotations":{"argocd.argoproj.io/tracking-id":"a:/ServiceAccount:argocd/argocd-agent"}}}`, "", "argocd.argoproj.io/tracking-id"},
		{"an owner reference", `{"metadata":{"ownerReferences":[{"kind":"Application","name":"x"}]}}`, "", "an owner reference"},
		{"the default instance label", `{"metadata":{"labels":{"app.kubernetes.io/instance":"x"}}}`, "", "the label app.kubernetes.io/instance"},
		{"the configured instance label", `{"metadata":{"labels":{"cell.poc.internal/harness":"argocd-agent"}}}`, "cell.poc.internal/harness", "the label cell.poc.internal/harness"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := runGuardScript(t, `check_agent_unmanaged`, "STUB_SA="+tc.sa, "STUB_INSTANCE_KEY="+tc.key)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("check failed: %v\n%s", err, out)
			case tc.want != "" && (err == nil || !strings.Contains(out, tc.want)):
				t.Fatalf("err %v, output %q; want a failure that says %q", err, out, tc.want)
			}
		})
	}
}

func TestAgentGrantsMustMatchTheRender(t *testing.T) {
	left := `{"items":[{"kind":"Role","metadata":{"name":"view-guard-test","namespace":"argocd"}},{"kind":"Namespace","metadata":{"name":"view-guard-test"}}]}`
	for _, tc := range []struct {
		name, left, bindings, want string
	}{
		{"nothing left, only the render", "", `{"items":[{"kind":"RoleBinding","metadata":{"name":"argocd-agent","namespace":"argocd","labels":{"cell.poc.internal/harness":"argocd-agent"}},"subjects":[{"kind":"ServiceAccount","name":"argocd-agent","namespace":"argocd"}]}]}`, ""},
		{"an object with the test label", left, "", "Role argocd/view-guard-test"},
		{"a binding for the agent that the render lacks", "", `{"items":[{"kind":"RoleBinding","metadata":{"name":"extra","namespace":"argocd"},"subjects":[{"kind":"ServiceAccount","name":"argocd-agent","namespace":"argocd"}]}]}`, "RoleBinding argocd/extra"},
		{"a binding for the test group", "", `{"items":[{"kind":"ClusterRoleBinding","metadata":{"name":"g"},"subjects":[{"kind":"Group","name":"poc:guard-test"}]}]}`, "ClusterRoleBinding -/g"},
		{"a binding for another account", "", `{"items":[{"kind":"RoleBinding","metadata":{"name":"o","namespace":"argocd"},"subjects":[{"kind":"ServiceAccount","name":"argocd-server","namespace":"argocd"}]}]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{"STUB_BINDINGS=" + tc.bindings}
			if tc.left != "" {
				env = append(env, "STUB_LEFT="+tc.left)
			}
			out, _, err := runGuardScript(t, `check_agent_grants`, env...)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("check failed: %v\n%s", err, out)
			case tc.want != "" && (err == nil || !strings.Contains(out, tc.want) || !strings.Contains(out, "mise run gate:m3:repair")):
				t.Fatalf("err %v, output %q; want a failure that says %q and the repair command", err, out, tc.want)
			}
		})
	}
}

func TestGateM3Repair(t *testing.T) {
	testtool.Need(t, "yq", "jq", "bash")
	left := `{"items":[{"kind":"Role","metadata":{"name":"view-guard-test","namespace":"argocd"}},{"kind":"Namespace","metadata":{"name":"view-guard-test"}}]}`
	script, err := filepath.Abs("../../scripts/gate-m3-repair.sh")
	if err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, leftover string, args ...string) (string, string, error) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(guardKubectl), 0o755); err != nil {
			t.Fatal(err)
		}
		logFile := filepath.Join(dir, "kubectl.log")
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
			"POC_BUILD_ROOT=" + filepath.Join(dir, "build"), "STUB_LOG=" + logFile, "GATE_M3_CELLS=dev-cell-1 dev-cell-2"}
		if leftover != "" {
			cmd.Env = append(cmd.Env, "STUB_LEFT="+leftover)
		}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		calls, _ := os.ReadFile(logFile)
		return out.String(), string(calls), err
	}
	t.Run("--check with leftovers", func(t *testing.T) {
		out, calls, err := run(t, left, "--check")
		if err == nil || !strings.Contains(out, "role argocd/view-guard-test") || strings.Contains(calls, " delete ") {
			t.Fatalf("err %v, output %q, calls %q; want a failure that lists the objects and deletes none", err, out, calls)
		}
	})
	t.Run("--check with no leftover", func(t *testing.T) {
		if out, _, err := run(t, "", "--check"); err != nil {
			t.Fatalf("check failed: %v\n%s", err, out)
		}
	})
	t.Run("repair deletes the objects", func(t *testing.T) {
		out, calls, err := run(t, left)
		if err != nil || !strings.Contains(calls, "-n argocd delete role view-guard-test") || !strings.Contains(calls, "delete namespace view-guard-test") {
			t.Fatalf("err %v, output %q, calls %q; want a delete of the Role and the Namespace", err, out, calls)
		}
	})
	t.Run("no leftover, no delete", func(t *testing.T) {
		_, calls, err := run(t, "")
		if err != nil || strings.Contains(calls, " delete ") {
			t.Fatalf("err %v, calls %q; want no delete", err, calls)
		}
	})
}
