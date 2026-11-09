// Package scripts tests the shell scripts behind the mise tasks with stub host commands.
package scripts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const (
	token    = "stub-token-0f9e8d7c6b5a"
	provider = `{"stubProvider":{"store":"poc","auth":{"secretRef":{"name":"poc-secrets-token","key":"token","namespace":"external-secrets"}}}}`
)

// stubKubectl logs each call, answers the install checks and saves each applied manifest.
// STUB_NO_ESO makes the install checks fail. STUB_APPLY_FAIL makes apply fail and echo its input,
// the way a server error can quote a request. Two ExternalSecrets exist in spire-system: one uses
// the store poc-secrets, and one uses another store. STUB_NO_ES lists none. The ExternalSecret
// reports Ready with a refresh time of now. STUB_NO_TARGET makes it fail to sync and the target
// Secret missing, and STUB_STALE_REFRESH gives it a refresh time from before the force sync.
const stubKubectl = `#!/usr/bin/env bash
set -euo pipefail
echo "$*" >>"$STUB_DIR/kubectl.log"
case " $* " in
  *" apply "*)
    n=$(ls "$STUB_DIR" | grep -c '^applied-' || true)
    input="$(cat)"
    if [[ -n "${STUB_APPLY_FAIL:-}" ]]; then
      printf 'error: could not apply %s\n' "$input" >&2
      printf '%s\n' "$input"
      exit 1
    fi
    printf '%s' "$input" >"$STUB_DIR/applied-$n"
    echo "applied" ;;
  *" wait "*)
    [[ -z "${STUB_NOT_READY:-}" ]] || { echo 'error: timed out waiting for the condition' >&2; exit 1; }
    echo "condition met" ;;
  *" get clustersecretstore "*)
    echo "unable to access the vault" ;;
  *" -n external-secrets get deployment external-secrets -o json "*)
    [[ -z "${STUB_NO_ESO:-}" ]] || { echo 'Error from server (NotFound): not found' >&2; exit 1; }
    echo '{"status":{"availableReplicas":1}}' ;;
  *" get externalsecrets.external-secrets.io -o json "*)
    [[ -z "${STUB_NO_ES:-}" ]] || { echo '{"items":[]}'; exit 0; }
    echo '{"items":[
      {"metadata":{"name":"spire-upstream"},"spec":{"secretStoreRef":{"kind":"ClusterSecretStore","name":"poc-secrets"},"target":{"name":"spire-upstream"}}},
      {"metadata":{"name":"other"},"spec":{"secretStoreRef":{"kind":"ClusterSecretStore","name":"other-store"}}}]}' ;;
  *" annotate "*)
    echo "annotated" ;;
  *" get externalsecret "*)
    if [[ -n "${STUB_NO_TARGET:-}" ]]; then
      echo '{"status":{"refreshTime":"2000-01-01T00:00:00Z","conditions":[{"type":"Ready","status":"False","message":"could not get secret data from provider"}]}}'
    elif [[ -n "${STUB_STALE_REFRESH:-}" ]]; then
      echo '{"status":{"refreshTime":"2000-01-01T00:00:00Z","conditions":[{"type":"Ready","status":"True","message":"secret synced"}]}}'
    else
      echo "{\"status\":{\"refreshTime\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\",\"message\":\"secret synced\"}]}}"
    fi ;;
  *" get secret "*)
    [[ -z "${STUB_NO_TARGET:-}" ]] || { echo 'Error from server (NotFound): secrets not found' >&2; exit 1; }
    echo "found" ;;
  *" get "*)
    [[ -z "${STUB_NO_ESO:-}" ]] || { echo 'Error from server (NotFound): not found' >&2; exit 1; }
    echo "found" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

type result struct {
	stdout, stderr string
	err            error
	calls          []string
	applied        []map[string]any
}

func run(t *testing.T, env ...string) result {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "base64")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(stubKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../scripts/secrets-connect.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script)
	cmd.Env = []string{
		"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"STUB_DIR=" + dir,
		"CELL=dev-cp",
	}
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()

	r := result{stdout: stdout.String(), stderr: stderr.String(), err: err}
	if log, readErr := os.ReadFile(filepath.Join(dir, "kubectl.log")); readErr == nil {
		r.calls = strings.Split(strings.TrimSpace(string(log)), "\n")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "applied-*"))
	sort.Strings(files)
	for _, f := range files {
		data, readErr := os.ReadFile(f)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var obj map[string]any
		if err := yaml.Unmarshal(data, &obj); err != nil {
			t.Fatalf("applied manifest is not valid YAML: %v\n%s", err, data)
		}
		r.applied = append(r.applied, obj)
	}
	return r
}

func both() []string {
	return []string{"POC_SECRET_TOKEN_CMD=printf %s " + token, "POC_SECRET_STORE_PROVIDER=" + provider}
}

func get(t *testing.T, v any, path ...string) any {
	t.Helper()
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("no object at %v", path)
		}
		if v, ok = m[p]; !ok {
			t.Fatalf("no value at %v", path)
		}
	}
	return v
}

// assertNoToken fails when the token appears in the output or in a kubectl argument, in clear or in base64.
func assertNoToken(t *testing.T, r result) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(token))
	for name, text := range map[string]string{"stdout": r.stdout, "stderr": r.stderr, "kubectl arguments": strings.Join(r.calls, "\n")} {
		if strings.Contains(text, token) || strings.Contains(text, encoded) {
			t.Fatalf("%s contains the token:\n%s", name, text)
		}
	}
}

func applies(r result) int {
	n := 0
	for _, c := range r.calls {
		if strings.Contains(" "+c+" ", " apply ") {
			n++
		}
	}
	return n
}

func TestSecretsConnect(t *testing.T) {
	r := run(t, both()...)
	if r.err != nil {
		t.Fatalf("secrets-connect failed: %v\n%s", r.err, r.stderr)
	}
	assertNoToken(t, r)

	for _, c := range r.calls {
		if !strings.HasPrefix(c, "--context kind-dev-cp ") {
			t.Fatalf("kubectl call %q does not target kind-dev-cp", c)
		}
		if strings.Contains(" "+c+" ", " apply ") && (!strings.Contains(c, "--server-side") || !strings.HasSuffix(c, "-f -")) {
			t.Fatalf("apply call %q is not a server-side apply from standard input", c)
		}
	}
	if len(r.applied) != 2 {
		t.Fatalf("got %d applied manifests, want the token Secret and the store", len(r.applied))
	}
	waitAt, annotateAt, secretAt := -1, -1, -1
	for i, c := range r.calls {
		switch {
		case strings.Contains(c, " wait ") && strings.Contains(c, "clustersecretstore/poc-secrets"):
			waitAt = i
		case strings.Contains(c, " annotate "):
			if !strings.Contains(c, "-n spire-system annotate externalsecret spire-upstream force-sync=") || !strings.HasSuffix(c, " --overwrite") {
				t.Fatalf("annotate call %q, want a force sync of spire-upstream in spire-system only", c)
			}
			annotateAt = i
		case strings.Contains(c, "-n spire-system get secret spire-upstream"):
			secretAt = i
		}
	}
	if waitAt < 0 || annotateAt < waitAt || secretAt < annotateAt {
		t.Fatalf("calls %v: want the store wait, then the force sync, then the check for Secret spire-upstream", r.calls)
	}

	t.Run("token secret comes first and holds the command output", func(t *testing.T) {
		s := r.applied[0]
		if get(t, s, "kind") != "Secret" || get(t, s, "metadata", "name") != "poc-secrets-token" ||
			get(t, s, "metadata", "namespace") != "external-secrets" {
			t.Fatalf("first manifest is %v", s["metadata"])
		}
		data := get(t, s, "data").(map[string]any)
		if len(data) != 1 {
			t.Fatalf("Secret has keys %v, want only token", data)
		}
		got, err := base64.StdEncoding.DecodeString(data["token"].(string))
		if err != nil || string(got) != token {
			t.Fatalf("Secret token decodes to %q (%v)", got, err)
		}
		if _, ok := s["stringData"]; ok {
			t.Fatal("Secret uses stringData")
		}
	})

	t.Run("store has the name and the provider block from the variable", func(t *testing.T) {
		s := r.applied[1]
		if get(t, s, "apiVersion") != "external-secrets.io/v1" || get(t, s, "kind") != "ClusterSecretStore" ||
			get(t, s, "metadata", "name") != "poc-secrets" {
			t.Fatalf("second manifest is %v %v", s["kind"], s["metadata"])
		}
		var want any
		if err := json.Unmarshal([]byte(provider), &want); err != nil {
			t.Fatal(err)
		}
		if got := get(t, s, "spec", "provider"); !reflect.DeepEqual(got, want) {
			t.Fatalf("provider is %v, want %v", got, want)
		}
		conditions := get(t, s, "spec", "conditions").([]any)
		if len(conditions) != 1 || !reflect.DeepEqual(get(t, conditions[0], "namespaces"), []any{"spire-system"}) {
			t.Fatalf("conditions are %v, want only the namespaces from cells/dev-cp.env", conditions)
		}
		if at, ok := get(t, s, "metadata", "annotations").(map[string]any)["cell.poc.internal/connected-at"].(string); !ok || at == "" {
			t.Fatal("store has no connected-at annotation, so a new token would not reach a cached provider client")
		}
	})
}

func TestSecretsConnectWithoutExternalSecrets(t *testing.T) {
	r := run(t, append(both(), "STUB_NO_ES=1")...)
	if r.err != nil {
		t.Fatalf("secrets-connect failed: %v\n%s", r.err, r.stderr)
	}
	if !strings.Contains(r.stderr, "no ExternalSecret in spire-system uses ClusterSecretStore poc-secrets") {
		t.Fatalf("stderr %q does not say that no ExternalSecret uses the store", r.stderr)
	}
}

func TestSecretsConnectFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"no token command", []string{"POC_SECRET_STORE_PROVIDER=" + provider}, "POC_SECRET_TOKEN_CMD"},
		{"no provider", []string{"POC_SECRET_TOKEN_CMD=printf %s " + token}, "POC_SECRET_STORE_PROVIDER"},
		{"provider is not JSON", []string{"POC_SECRET_TOKEN_CMD=printf %s " + token, "POC_SECRET_STORE_PROVIDER=vault: x"}, "POC_SECRET_STORE_PROVIDER"},
		{"provider has two blocks", []string{"POC_SECRET_TOKEN_CMD=printf %s " + token,
			`POC_SECRET_STORE_PROVIDER={"a":{"ref":{"name":"poc-secrets-token","key":"token","namespace":"external-secrets"}},"b":{}}`}, "one provider"},
		{"provider does not use the token secret", []string{"POC_SECRET_TOKEN_CMD=printf %s " + token,
			`POC_SECRET_STORE_PROVIDER={"a":{"ref":{"name":"other","key":"token","namespace":"external-secrets"}}}`}, "poc-secrets-token"},
		{"operator not installed", append(both(), "STUB_NO_ESO=1", "SECRETS_CONNECT_ESO_WAIT=1"), "Run CELL=dev-cp mise run secrets:connect again when it is Healthy"},
		{"token command fails", []string{"POC_SECRET_TOKEN_CMD=echo partial; exit 3", "POC_SECRET_STORE_PROVIDER=" + provider}, "POC_SECRET_TOKEN_CMD"},
		{"token command prints nothing", []string{"POC_SECRET_TOKEN_CMD=true", "POC_SECRET_STORE_PROVIDER=" + provider}, "no token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, tc.env...)
			if r.err == nil {
				t.Fatal("secrets-connect succeeded")
			}
			if !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("stderr %q does not contain %q", r.stderr, tc.want)
			}
			if n := applies(r); n != 0 {
				t.Fatalf("secrets-connect ran %d applies before it failed", n)
			}
			assertNoToken(t, r)
		})
	}

	t.Run("target secret does not appear", func(t *testing.T) {
		r := run(t, append(both(), "STUB_NO_TARGET=1", "SECRETS_CONNECT_SYNC_WAIT=1")...)
		if r.err == nil {
			t.Fatal("secrets-connect succeeded")
		}
		if !strings.Contains(r.stderr, "Secret spire-system/spire-upstream") || !strings.Contains(r.stderr, "could not get secret data from provider") {
			t.Fatalf("stderr %q does not name the missing Secret and the ExternalSecret condition", r.stderr)
		}
		assertNoToken(t, r)
	})

	t.Run("refresh from before the force sync", func(t *testing.T) {
		r := run(t, append(both(), "STUB_STALE_REFRESH=1", "SECRETS_CONNECT_SYNC_WAIT=1")...)
		if r.err == nil {
			t.Fatal("secrets-connect succeeded with a refresh time from before the force sync")
		}
		if !strings.Contains(r.stderr, "did not sync") {
			t.Fatalf("stderr %q does not say that the ExternalSecret did not sync", r.stderr)
		}
	})

	t.Run("store does not become ready", func(t *testing.T) {
		r := run(t, append(both(), "STUB_NOT_READY=1")...)
		if r.err == nil {
			t.Fatal("secrets-connect succeeded")
		}
		if !strings.Contains(r.stderr, "not Ready") || !strings.Contains(r.stderr, "unable to access the vault") {
			t.Fatalf("stderr %q does not give the store condition", r.stderr)
		}
		assertNoToken(t, r)
	})

	t.Run("apply error that quotes the request", func(t *testing.T) {
		r := run(t, append(both(), "STUB_APPLY_FAIL=1")...)
		if r.err == nil {
			t.Fatal("secrets-connect succeeded")
		}
		if !strings.Contains(r.stderr, "poc-secrets-token") {
			t.Fatalf("stderr %q does not name the Secret", r.stderr)
		}
		if n := applies(r); n != 1 {
			t.Fatalf("secrets-connect ran %d applies, want it to stop after the failed Secret", n)
		}
		assertNoToken(t, r)
	})
}
