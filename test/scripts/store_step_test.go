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

// storeKubectl answers the store checks of store_gaps in scripts/lib.sh. STUB_STORE_NOT_READY makes
// the SecretStore not Ready, and STUB_SECRET_MISSING removes the target Secret.
const storeKubectl = `#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *" get secretstore poc-secrets "*)
    if [[ -n "${STUB_STORE_NOT_READY:-}" ]]; then echo '{"status":{"conditions":[{"type":"Ready","status":"False"}]}}'
    else echo '{"status":{"conditions":[{"type":"Ready","status":"True"}]}}'; fi ;;
  *" get externalsecrets.external-secrets.io "*)
    echo '{"items":[{"metadata":{"name":"spire-upstream"},"spec":{"secretStoreRef":{"kind":"SecretStore","name":"poc-secrets"},"target":{"name":"spire-upstream"}}}]}' ;;
  *" get secret spire-upstream "*)
    [[ -z "${STUB_SECRET_MISSING:-}" ]] || exit 1
    echo found ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// runStoreStep runs connect_store_step of scripts/lib.sh once, with a stub secrets:connect that
// records each run. It returns the output and the number of runs.
func runStoreStep(t *testing.T, env ...string) (string, int, error) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(storeKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	connect := filepath.Join(dir, "connect")
	script := "#!/usr/bin/env bash\necho run >>\"" + filepath.Join(dir, "runs") + "\"\n[[ -z \"${STUB_CONNECT_FAIL:-}\" ]]\n"
	if err := os.WriteFile(connect, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; store_done=0; last_hint=-60; connect_store_step "$2"; echo "store_done=$store_done"`, "_", lib, connect)
	cmd.Env = append([]string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cp"}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	runs := 0
	if data, readErr := os.ReadFile(filepath.Join(dir, "runs")); readErr == nil {
		runs = strings.Count(string(data), "run")
	}
	return out.String(), runs, err
}

func TestStoreStepWithAConnectedStore(t *testing.T) {
	out, runs, err := runStoreStep(t, "POC_SECRET_TOKEN_CMD=true")
	if err != nil || runs != 0 || !strings.Contains(out, "store_done=1") || !strings.Contains(out, "is connected") {
		t.Fatalf("err %v, %d runs, output %q; want no run of secrets:connect and store_done=1", err, runs, out)
	}
}

func TestStoreStepRunsSecretsConnectWithTheTokenCommand(t *testing.T) {
	for _, gap := range []string{"STUB_SECRET_MISSING=1", "STUB_STORE_NOT_READY=1"} {
		t.Run(gap, func(t *testing.T) {
			out, runs, err := runStoreStep(t, gap, "POC_SECRET_TOKEN_CMD=true")
			if err != nil || runs != 1 || !strings.Contains(out, "store_done=1") || !strings.Contains(out, "running secrets:connect") {
				t.Fatalf("err %v, %d runs, output %q; want one run of secrets:connect", err, runs, out)
			}
		})
	}
}

func TestStoreStepAsksForASecondShellWithoutTheTokenCommand(t *testing.T) {
	out, runs, err := runStoreStep(t, "STUB_SECRET_MISSING=1")
	if err != nil || runs != 0 || !strings.Contains(out, "store_done=0") ||
		!strings.Contains(out, "Secret spire-system/spire-upstream is missing. Run in a second shell: CELL=dev-cp mise run secrets:connect") {
		t.Fatalf("err %v, %d runs, output %q; want the second-shell command and no run", err, runs, out)
	}
}

func TestStoreStepStopsWhenSecretsConnectFails(t *testing.T) {
	out, _, err := runStoreStep(t, "STUB_SECRET_MISSING=1", "POC_SECRET_TOKEN_CMD=true", "STUB_CONNECT_FAIL=1")
	if err == nil || !strings.Contains(out, "secrets:connect failed. Fix the cause, then run: CELL=dev-cp mise run secrets:connect") {
		t.Fatalf("err %v, output %q; want a failure that names secrets:connect", err, out)
	}
}
