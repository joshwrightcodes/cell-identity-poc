package scripts

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// obsKubectl stands in for kubectl and for Grafana in the lgtm pod. The Secret and Grafana each keep
// a password in a file of STUB_STATE. A curl config on standard input makes a request: a GET of
// /api/user answers 200 for the Grafana password and 401 otherwise, and a PUT of /api/user/password
// with the Grafana password as the old one sets the new one.
const obsKubectl = `#!/usr/bin/env bash
set -uo pipefail
state="$STUB_STATE"
echo "$*" >>"$state/argv.log"
args=" $* "
case "$args" in
  *" get secret grafana-admin -o jsonpath={.data.password} "*)
    [[ ! -e "$state/get-fail" ]] || { echo "Error from server (NotFound)" >&2; exit 1; }
    printf '%s' "$(cat "$state/secret")" | base64 ;;
  *" exec -i lgtm-0 -c lgtm -- curl -K - "*)
    cfg="$(cat)"
    user="$(sed -n 's/^user = "\(.*\)"$/\1/p' <<<"$cfg")"
    method="$(sed -n 's/^request = "\(.*\)"$/\1/p' <<<"$cfg")"
    url="$(sed -n 's/^url = "\(.*\)"$/\1/p' <<<"$cfg")"
    data="$(sed -n 's/^data = "\(.*\)"$/\1/p' <<<"$cfg" | sed 's/\\"/"/g')"
    ok=0; [[ "$user" == "admin:$(cat "$state/grafana")" ]] && ok=1
    case "$method $url" in
      "GET http://127.0.0.1:3000/api/user") ((ok)) && printf '{"login":"admin"}\n200' || printf '{"message":"Invalid username or password"}\n401' ;;
      "PUT http://127.0.0.1:3000/api/user/password")
        if ((ok)) && [[ "$(jq -r .oldPassword <<<"$data")" == "$(cat "$state/grafana")" ]]; then
          jq -r .newPassword <<<"$data" | tr -d '\n' >"$state/grafana"
          printf '{"message":"User password changed"}\n200'
        else printf '{"message":"Invalid"}\n401'; fi ;;
      *) echo "unexpected request $method $url" >&2; exit 2 ;;
    esac ;;
  *" patch secret grafana-admin --type merge --patch-file /dev/stdin "*)
    body="$(cat)"
    [[ ! -e "$state/apply-fail" ]] || { echo "patch failed" >&2; exit 1; }
    # The patch must drop the last-applied annotation, and it must set the password.
    [[ "$(jq -r '.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"] | tostring' <<<"$body")" == null ]] || exit 3
    jq -r .data.password <<<"$body" | base64 -d | tr -d '\n' >"$state/secret" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// obsRun runs one of the obs scripts with the stub kubectl. It returns standard output, standard
// error, the exit status and the directory of the stub state.
func obsRun(t *testing.T, state string, script string, env ...string) (string, string, int) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "base64")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(obsKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	// A jq wrapper records its argument list, because a password there is visible to every process of the user.
	realJQ, err := exec.LookPath("jq")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/usr/bin/env bash\necho \"jq $*\" >>\"$STUB_STATE/argv.log\"\nexec " + realJQ + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "jq"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.Abs("../../scripts/" + script)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", path)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=management", "STUB_STATE=" + state}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String(), code
}

func obsState(t *testing.T, secret, grafana string) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range map[string]string{"secret": secret, "grafana": grafana} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func oneJSONLine(t *testing.T, out string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &m) != nil {
		t.Fatalf("standard output is %q, want exactly one JSON line", out)
	}
	return m
}

// TestObsPasswordPrintsOnlyThePassword checks that obs:password prints the password and nothing else,
// and prints one JSON error line and nothing else when the Secret is missing.
func TestObsPasswordPrintsOnlyThePassword(t *testing.T) {
	t.Parallel()
	state := obsState(t, "S3cretPassw0rdS3cretPassw0rd1234", "unused")
	out, _, code := obsRun(t, state, "obs-password.sh")
	if code != 0 || out != "S3cretPassw0rdS3cretPassw0rd1234\n" {
		t.Fatalf("exit %d, output %q, want the password and a newline", code, out)
	}
	if err := os.WriteFile(filepath.Join(state, "get-fail"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code = obsRun(t, state, "obs-password.sh")
	m := oneJSONLine(t, out)
	if code == 0 || m["level"] != "ERROR" || !strings.Contains(m["error"].(string), "grafana-admin") || strings.Contains(out, "S3cretPassw0rd") {
		t.Fatalf("exit %d, output %q, want one JSON error line that names the Secret", code, out)
	}
}

// TestObsRotatePassword checks the rotation: the new password differs, has 32 alphanumeric
// characters, reaches the Secret and Grafana, the old one stops working, no argument list of kubectl
// holds a password, and the output holds neither password.
func TestObsRotatePassword(t *testing.T) {
	t.Parallel()
	const old = "OldPassw0rdOldPassw0rdOldPassw0r"
	state := obsState(t, old, old)
	out, errOut, code := obsRun(t, state, "obs-rotate-password.sh")
	if code != 0 {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, out, errOut)
	}
	if m := oneJSONLine(t, out); m["rotated"] != true {
		t.Fatalf("output %v, want rotated true", m)
	}
	secret, _ := os.ReadFile(filepath.Join(state, "secret"))
	grafana, _ := os.ReadFile(filepath.Join(state, "grafana"))
	fresh := string(secret)
	if fresh == old || string(grafana) != fresh || len(fresh) != 32 || strings.Trim(fresh, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != "" {
		t.Fatalf("Secret %q, Grafana %q, old %q: want one new password of 32 alphanumeric characters", fresh, grafana, old)
	}
	argv, _ := os.ReadFile(filepath.Join(state, "argv.log"))
	for _, p := range []string{old, fresh} {
		if strings.Contains(string(argv)+out+errOut, p) {
			t.Errorf("a password appears in an argument list of kubectl or jq, or in the output: %.20s", p)
		}
	}
	if strings.Contains(string(argv), " apply ") || strings.Contains(string(argv), "apply -f") {
		t.Errorf("the script used kubectl apply, which writes the password into last-applied-configuration:\n%s", argv)
	}
}

// TestObsRotatePasswordFailureNamesTheRepair checks that a failed Secret update after the API call
// prints one JSON error line with the command that makes Grafana use the Secret again, and that the
// line holds no password.
func TestObsRotatePasswordFailureNamesTheRepair(t *testing.T) {
	t.Parallel()
	const old = "OldPassw0rdOldPassw0rdOldPassw0r"
	state := obsState(t, old, old)
	if err := os.WriteFile(filepath.Join(state, "apply-fail"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code := obsRun(t, state, "obs-rotate-password.sh")
	m := oneJSONLine(t, out)
	restore, _ := m["restore"].(string)
	if code == 0 || !strings.Contains(restore, "reset-admin-password") || !strings.Contains(restore, "obs:password") || strings.Contains(out, old) {
		t.Fatalf("exit %d, output %q, want one JSON error line with the restore command", code, out)
	}
	grafana, _ := os.ReadFile(filepath.Join(state, "grafana"))
	if strings.Contains(out, string(grafana)) {
		t.Errorf("the error line holds the new password")
	}
}

// TestObsRotatePasswordRefusesAnOutOfSyncSecret checks that the rotation changes nothing when
// Grafana does not accept the password of the Secret.
func TestObsRotatePasswordRefusesAnOutOfSyncSecret(t *testing.T) {
	t.Parallel()
	state := obsState(t, "SecretPassw0rdSecretPassw0rd1234", "GrafanaPassw0rdGrafanaPassw0rd12")
	out, _, code := obsRun(t, state, "obs-rotate-password.sh")
	m := oneJSONLine(t, out)
	if code == 0 || m["restore"] == nil {
		t.Fatalf("exit %d, output %q, want one JSON error line with a restore command", code, out)
	}
	if g, _ := os.ReadFile(filepath.Join(state, "grafana")); string(g) != "GrafanaPassw0rdGrafanaPassw0rd12" {
		t.Errorf("Grafana password changed to %q", g)
	}
}

// TestObsUIBusyPort checks that obs:ui prints one JSON line and fails when the port has a listener.
func TestObsUIBusyPort(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "lsof")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	out, _, code := obsRun(t, obsState(t, "x", "x"), "obs-ui.sh", "OBS_UI_PORT="+port)
	m := oneJSONLine(t, out)
	if code == 0 || m["port"] != port || !strings.Contains(m["error"].(string), "already has a listener") {
		t.Fatalf("exit %d, output %q, want one JSON error line for port %s", code, out, port)
	}
	out, _, code = obsRun(t, obsState(t, "x", "x"), "obs-ui.sh", "OBS_UI_PORT=abc")
	if m := oneJSONLine(t, out); code == 0 || !strings.Contains(m["error"].(string), "not a port number") {
		t.Fatalf("exit %d, output %q, want one JSON error line for a bad port", code, out)
	}
}

// TestNoLastAppliedSecretCheck checks the cell:verify row: a Secret in observability-system with the
// annotation last-applied-configuration fails it and names the Secret, and Secrets without it pass.
func TestNoLastAppliedSecretCheck(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "yq", "jq", "bash")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, items, want string }{
		{"clean", `{"metadata":{"name":"grafana-admin","annotations":{"reconcile.external-secrets.io/data-hash":"x"}}},{"metadata":{"name":"other"}}`, ""},
		{"annotated", `{"metadata":{"name":"grafana-admin","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"}}}`, "grafana-admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stub := "#!/usr/bin/env bash\necho '{\"items\":[" + tc.items + "]}'\n"
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `source "$1"; check_no_last_applied_secret`, "_", lib)
			cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=management"}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(out.String(), tc.want) || !strings.Contains(out.String(), "obs:rotate-password")) {
				t.Fatalf("err %v, output %q, want %q", err, out.String(), tc.want)
			}
		})
	}
}
