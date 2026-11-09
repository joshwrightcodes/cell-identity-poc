package scripts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

var (
	pkigenOnce sync.Once
	pkigenPath string
	pkigenErr  error
)

// pkigen builds cmd/pkigen once for the package.
func pkigen(t *testing.T) string {
	t.Helper()
	pkigenOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pkigen")
		if err != nil {
			pkigenErr = err
			return
		}
		pkigenPath = filepath.Join(dir, "pkigen")
		out, err := exec.Command("go", "build", "-o", pkigenPath, "../../cmd/pkigen").CombinedOutput()
		if err != nil {
			pkigenErr = err
			t.Logf("go build: %s", out)
		}
	})
	if pkigenErr != nil {
		t.Fatal(pkigenErr)
	}
	return pkigenPath
}

// rotateMise answers "mise run pki -- <args>" with the real pkigen.
const rotateMise = `#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2 $3" == "run pki --" ]] || { echo "unexpected mise call: $*" >&2; exit 2; }
shift 3
exec "$STUB_PKIGEN" "$@"
`

// rotateKubectl plays the cluster for secrets:connect, cell:restart and the authority check. The
// active authority names the subject key ID of the intermediate certificate that the write command
// stored, unless STUB_OLD_AUTHORITY is set.
const rotateKubectl = `#!/usr/bin/env bash
set -euo pipefail
echo "$*" >>"$STUB_DIR/kubectl.log"
case " $* " in
  *" config get-contexts "*) echo kind-dev-cp ;;
  *" localauthority x509 show "*)
    ski=old
    if [[ -z "${STUB_OLD_AUTHORITY:-}" ]]; then
      ski="$("$STUB_PKIGEN" info <"$STUB_DIR/written-dev-cp_spire-server_intermediate-cert" | jq -r .subject_key_id)"
    fi
    echo "{\"active\":{\"authority_id\":\"x\",\"upstream_authority_subject_key_id\":\"$ski\"}}" ;;
  *" apply "*) cat >/dev/null; echo applied ;;
  *" wait "*) echo "condition met" ;;
  *" -n external-secrets get deployment external-secrets -o json "*) echo '{"status":{"availableReplicas":1}}' ;;
  *" get externalsecrets.external-secrets.io -o json "*)
    echo '{"items":[{"metadata":{"name":"spire-upstream"},"spec":{"secretStoreRef":{"kind":"SecretStore","name":"poc-secrets"},"target":{"name":"spire-upstream"}}}]}' ;;
  *" annotate "*) echo annotated ;;
  *" get externalsecret spire-upstream -o json "*)
    echo "{\"status\":{\"refreshTime\":\"$(date -u -v+5S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+5 seconds' +%Y-%m-%dT%H:%M:%SZ)\",\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\"}]}}" ;;
  *" get pods -l app.kubernetes.io/name=spire-server -o jsonpath="*) echo old-uid ;;
  *" delete pods "*) echo deleted ;;
  *" get pods -l app.kubernetes.io/name=spire-server -o json "*)
    echo '{"items":[{"metadata":{"uid":"new-uid"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  *" get "*) echo found ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

type rotateResult struct {
	out     string
	err     error
	dir     string
	rootPEM string
}

func runRotate(t *testing.T, env ...string) rotateResult {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "go")
	dir := t.TempDir()
	for name, content := range map[string]string{"mise": rotateMise, "kubectl": rotateKubectl} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root, err := exec.Command(pkigen(t), "root").Output()
	if err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root-bundle")
	if err := os.WriteFile(rootFile, root, 0o600); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../scripts/pki-rotate-intermediate.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script)
	cmd.Env = append([]string{
		"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"STUB_DIR=" + dir,
		"STUB_PKIGEN=" + pkigen(t),
		"CELL=dev-cp",
		"POC_ENVRC_LOCAL=" + filepath.Join(dir, "no-envrc-local"),
		// The read command prints the root bundle for the one remote key that the test expects.
		`POC_SECRET_READ_CMD=[[ "$1" == vault/root-ca ]] && cat "` + rootFile + `"`,
		`POC_SECRET_WRITE_CMD=cat >"$STUB_DIR/written-$(printf %s "$1" | tr / _)"`,
		"POC_ROOT_CA_BUNDLE=vault/root-ca",
		"POC_SECRET_TOKEN_CMD=printf %s " + token,
		"POC_SECRET_STORE_PROVIDER=" + provider,
		"PKI_ROTATE_CHECK_WAIT=1",
	}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return rotateResult{out: out.String(), err: err, dir: dir, rootPEM: string(root)}
}

func readPEM(t *testing.T, path, blockType string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, rest := pem.Decode(data)
	if b == nil || b.Type != blockType || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("%s holds no single %s block", path, blockType)
	}
	return b.Bytes
}

func TestRotateIntermediate(t *testing.T) {
	r := runRotate(t)
	if r.err != nil {
		t.Fatalf("rotation failed: %v\n%s", r.err, r.out)
	}
	if strings.Contains(r.out, "PRIVATE KEY") {
		t.Fatalf("the output holds key material:\n%s", r.out)
	}
	if !strings.Contains(r.out, "chains to the new intermediate") {
		t.Fatalf("the output does not report the check:\n%s", r.out)
	}
	key, err := x509.ParseECPrivateKey(readPEM(t, filepath.Join(r.dir, "written-dev-cp_spire-server_intermediate-key"), "EC PRIVATE KEY"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(readPEM(t, filepath.Join(r.dir, "written-dev-cp_spire-server_intermediate-cert"), "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(cert.PublicKey.(*ecdsa.PublicKey)) {
		t.Fatal("the written key does not match the written certificate")
	}
	rootBlock, _ := pem.Decode([]byte(r.rootPEM[strings.Index(r.rootPEM, "-----BEGIN CERTIFICATE-----"):]))
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the new intermediate is not signed by the root from the read command: %v", err)
	}
	log, err := os.ReadFile(filepath.Join(r.dir, "kubectl.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"annotate externalsecret spire-upstream force-sync=", "delete pods -l app.kubernetes.io/name=spire-server", "localauthority x509 show"} {
		if !strings.Contains(string(log), want) {
			t.Fatalf("kubectl calls lack %q:\n%s", want, log)
		}
	}
	if i, j := strings.Index(string(log), "force-sync="), strings.Index(string(log), "delete pods"); i > j {
		t.Fatal("the server restarted before secrets:connect synced the Secret")
	}
}

func TestRotateIntermediateFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"server still on the old intermediate", []string{"STUB_OLD_AUTHORITY=1"}, "has the upstream authority 'old'"},
		{"no write command", []string{"POC_SECRET_WRITE_CMD="}, "POC_SECRET_WRITE_CMD is not set"},
		{"no SPIRE server in the cluster", []string{"CELL=dev-cell-1"}, "CELL=dev-cp mise run pki:rotate-intermediate"},
		{"root read fails", []string{"POC_ROOT_CA_BUNDLE=vault/other"}, "POC_SECRET_READ_CMD failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runRotate(t, tc.env...)
			if r.err == nil {
				t.Fatalf("rotation succeeded:\n%s", r.out)
			}
			if !strings.Contains(r.out, tc.want) {
				t.Fatalf("output does not contain %q:\n%s", tc.want, r.out)
			}
			if strings.Contains(r.out, "PRIVATE KEY") {
				t.Fatalf("the output holds key material:\n%s", r.out)
			}
		})
	}
}
