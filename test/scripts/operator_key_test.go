package scripts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

var (
	operatorctlOnce sync.Once
	operatorctlPath string
	operatorctlErr  error
)

// operatorctlBinary builds cmd/operatorctl once for the package.
func operatorctlBinary(t *testing.T) string {
	t.Helper()
	operatorctlOnce.Do(func() {
		dir, err := os.MkdirTemp("", "operatorctl")
		if err != nil {
			operatorctlErr = err
			return
		}
		operatorctlPath = filepath.Join(dir, "operatorctl")
		if out, err := exec.Command("go", "build", "-o", operatorctlPath, "../../cmd/operatorctl").CombinedOutput(); err != nil {
			operatorctlErr = fmt.Errorf("go build cmd/operatorctl: %v: %s", err, out)
		}
	})
	if operatorctlErr != nil {
		t.Fatal(operatorctlErr)
	}
	return operatorctlPath
}

// opSecretWrite stands in for the write command of the secret manager. It stores its standard input at the remote key "$1", in
// $STUB_DIR/secrets, and records its arguments. Like a CLI that prints a receipt, it echoes the stored value on standard output, so a
// script that lets that output through leaks the seed. STUB_WRITE_FAIL makes it read its input and fail.
const opSecretWrite = `#!/usr/bin/env bash
set -euo pipefail
echo "secret-write $*" >>"$STUB_DIR/calls"
(($# == 1)) || { echo "secret-write takes one remote key" >&2; exit 2; }
if [[ -n "${STUB_WRITE_FAIL:-}" ]]; then cat >/dev/null; echo "the write was refused" >&2; exit 1; fi
mkdir -p "$STUB_DIR/secrets"
f="$STUB_DIR/secrets/$(printf '%s' "$1" | tr / _)"
cat >"$f"
printf '{"stored":"'; tr -d '\n' <"$f"; printf '"}\n'
`

// opSecretRead stands in for the read command of the secret manager. It prints the value of the remote key "$1" from
// $STUB_DIR/secrets and records its arguments. STUB_READ_FAIL makes it fail, and STUB_READ_OTHER makes it print another seed.
const opSecretRead = `#!/usr/bin/env bash
set -euo pipefail
echo "secret-read $*" >>"$STUB_DIR/calls"
(($# == 1)) || { echo "secret-read takes one remote key" >&2; exit 2; }
[[ -z "${STUB_READ_FAIL:-}" ]] || { echo "the read was refused" >&2; exit 1; }
if [[ -n "${STUB_READ_OTHER:-}" ]]; then cat "$STUB_DIR/secrets/other"; exit 0; fi
cat "$STUB_DIR/secrets/$(printf '%s' "$1" | tr / _)"
`

// opKubectl plays the ConfigMaps of management and dev-cp. Each one is the file $STUB_DIR/k/<context>/<namespace>/<name>.json. It
// answers get, create -f - and replace -f -, records each call, and records each write with its data. Each write raises
// metadata.resourceVersion, and a replace whose body names another resourceVersion fails with a conflict, as the API server does. A
// write with -o json prints the stored object. STUB_DOWN names the contexts whose API does not answer, and STUB_PIN_WRITE_FAIL fails
// every write.
const opKubectl = `#!/usr/bin/env bash
set -euo pipefail
echo "kubectl $*" >>"$STUB_DIR/calls"
[[ "${1:-}" == --context ]] || { echo "kubectl without --context first: $*" >&2; exit 2; }
ctx="$2"; shift 2
[[ " ${STUB_DOWN:-} " != *" $ctx "* ]] || { echo "The connection to the server was refused" >&2; exit 1; }
ns=""; rest=()
while (($#)); do
  case "$1" in
    -n) ns="$2"; shift 2 ;;
    *) rest+=("$1"); shift ;;
  esac
done
set -- "${rest[@]}"
case "$1" in
  get)
    [[ "$2" == configmap && " $* " == *" -o json "* ]] || { echo "unexpected kubectl get: $*" >&2; exit 2; }
    f="$STUB_DIR/k/$ctx/$ns/$3.json"
    if [[ -f "$f" ]]; then cat "$f"
    elif [[ " $* " == *" --ignore-not-found "* ]]; then :
    else echo "Error from server (NotFound): configmaps \"$3\" not found" >&2; exit 1; fi ;;
  create | replace)
    [[ " $* " == *" -f - "* && " $* " == *" --field-manager=operator "* ]] || { echo "unexpected kubectl $1: $*" >&2; exit 2; }
    body="$(cat)"
    bns="$(printf '%s' "$body" | jq -r .metadata.namespace)"
    name="$(printf '%s' "$body" | jq -r .metadata.name)"
    f="$STUB_DIR/k/$ctx/$bns/$name.json"
    [[ "$1" != create || ! -f "$f" ]] || { echo "Error from server (AlreadyExists): configmaps \"$name\" already exists" >&2; exit 1; }
    [[ "$1" != replace || -f "$f" ]] || { echo "Error from server (NotFound): configmaps \"$name\" not found" >&2; exit 1; }
    [[ -z "${STUB_PIN_WRITE_FAIL:-}" ]] || { echo "Error from server (Forbidden)" >&2; exit 1; }
    rv=0
    [[ "$1" != replace ]] || rv="$(jq -r '.metadata.resourceVersion // "1"' "$f")"
    want="$(printf '%s' "$body" | jq -r '.metadata.resourceVersion // ""')"
    [[ -z "$want" || "$want" == "$rv" ]] \
      || { echo "Error from server (Conflict): the object has been modified; please apply your changes to the latest version" >&2; exit 1; }
    mkdir -p "$(dirname "$f")"
    printf '%s' "$body" | jq -c --arg rv "$((rv + 1))" '.metadata.resourceVersion = $rv' >"$f"
    echo "wrote $ctx $bns/$name $(printf '%s' "$body" | jq -c .data)" >>"$STUB_DIR/calls"
    [[ " $* " != *" -o json "* ]] || cat "$f" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// opDocker answers the clock of a node and the rule lists of iptables and ip6tables. STUB_CUT names <node>:<tool> pairs whose list
// holds a cut rule of the partition tool, and STUB_DOCKER_FAIL names nodes that do not answer.
const opDocker = `#!/usr/bin/env bash
set -euo pipefail
echo "docker $*" >>"$STUB_DIR/calls"
[[ "${1:-}" == exec ]] || { echo "unexpected docker call: $*" >&2; exit 2; }
node="$2"; shift 2
[[ " ${STUB_DOCKER_FAIL:-} " != *" $node "* ]] || { echo "Error response from daemon: No such container: $node" >&2; exit 1; }
case "$*" in
  "date +%s") date +%s ;;
  "iptables -S" | "ip6tables -S")
    printf '%s\n' "-P INPUT ACCEPT" "-P FORWARD ACCEPT" "-P OUTPUT ACCEPT" "-A FORWARD -m comment --comment gate-m3-blackhole-1 -j DROP"
    [[ " ${STUB_CUT:-} " != *" $node:$1 "* ]] || echo "-A FORWARD -d 172.18.0.3/32 -m comment --comment gate-m9-cut-0a1b2c3d -j DROP" ;;
  *) echo "unexpected docker exec: $*" >&2; exit 2 ;;
esac
`

// opMise stands in for mise. operatorctl runs the real binary. mgmt -- status prints $STUB_DIR/mgmt-status.json, or an error line
// under STUB_MGMT_DOWN. cell:up of dev-cp runs the pin helper of components/lib/operator-key.sh, as the renders do, and writes its
// key lines into the three pins of dev-cp. cell:link and cell:verify record their call, and cell:verify records the pin of envd.
// STUB_VERIFY_FAIL names the clusters whose verify fails. STUB_TAMPER makes the first verify of dev-cp raise the resourceVersion of
// operator-pub, as a writer during the rotation does.
const opMise = `#!/usr/bin/env bash
set -euo pipefail
echo "mise $* CELL=${CELL:-} LINK_ONLY=${LINK_ONLY:-} ACCEPT=${OPERATOR_KEY_ACCEPT_CHANGE:-}" >>"$STUB_DIR/calls"
[[ "${1:-}" == run ]] || { echo "unexpected mise call: $*" >&2; exit 2; }
task="$2"; shift 2
[[ "${1:-}" != -- ]] || shift
kput() {
  mkdir -p "$STUB_DIR/k/$1/$2"
  jq -nc --arg ns "$2" --arg n "$3" --argjson d "$4" '{apiVersion: "v1", kind: "ConfigMap", metadata: {namespace: $ns, name: $n}, data: $d}' >"$STUB_DIR/k/$1/$2/$3.json"
}
case "$task" in
  operatorctl) exec "$STUB_OPERATORCTL" "$@" ;;
  mgmt)
    [[ "$*" == status ]] || { echo "unexpected mgmt call: $*" >&2; exit 2; }
    if [[ -n "${STUB_MGMT_DOWN:-}" ]]; then echo '{"level":"ERROR","msg":"mgmt failed","error":"pod mgmtd-0 is absent or not Ready"}'; exit 1; fi
    cat "$STUB_DIR/mgmt-status.json" ;;
  cell:up)
    [[ "$CELL" == dev-cp ]] || { echo "unexpected cell:up of $CELL" >&2; exit 2; }
    source "$STUB_REPO/components/lib/operator-key.sh"
    keys="$(operator_pub_keys dev-cp)" || exit 1
    lines="$(printf '%s\n' "$keys")"
    kput kind-dev-cp envd-system operator-key "$(jq -nc --arg k "$lines" '{"keys.pub": ($k + "\n")}')"
    kput kind-dev-cp gateway-system operator-key "$(jq -nc --arg k "$lines" '{"keys.pub": ($k + "\n")}')"
    list="$(printf '%s\n' "$keys" | jq -Rr '"\"" + . + "\""' | paste -sd, - | sed 's/,/, /g')"
    kput kind-dev-cp spire-system spire-server "$(jq -nc --arg l "$list" '{"server.conf": ("plugins {\n  NodeAttestor \"cluster_jwt\" {\n    plugin_data {\n      operator_public_keys = [" + $l + "]\n    }\n  }\n}\n")}')"
    echo "render dev-cp pins=$(printf '%s\n' "$keys" | paste -sd, -)" >>"$STUB_DIR/calls" ;;
  cell:link) [[ "$CELL $LINK_ONLY" == "management mgmt-api" ]] || { echo "unexpected cell:link: $CELL $LINK_ONLY" >&2; exit 2; } ;;
  cell:verify)
    pins="$(jq -r '.data["keys.pub"]' "$STUB_DIR/k/kind-dev-cp/envd-system/operator-key.json" | paste -sd, -)"
    echo "verify $CELL pins=$pins" >>"$STUB_DIR/calls"
    if [[ -n "${STUB_TAMPER:-}" && "$CELL" == dev-cp && ! -e "$STUB_DIR/tampered" ]]; then
      : >"$STUB_DIR/tampered"
      f="$STUB_DIR/k/kind-management/mgmt-system/operator-pub.json"
      jq -c '.metadata.resourceVersion = ((.metadata.resourceVersion // "1" | tonumber) + 1 | tostring)' "$f" >"$f.new" && mv "$f.new" "$f"
    fi
    [[ " ${STUB_VERIFY_FAIL:-} " != *" $CELL "* ]] || { echo "cell:verify of $CELL failed" >&2; exit 1; } ;;
  *) echo "unexpected mise task: $task" >&2; exit 2 ;;
esac
`

// opRig is one hermetic run directory of scripts/operator-key.sh: the stubs, the stub state, the build root and TMPDIR.
type opRig struct {
	t                    *testing.T
	root, bin, stub, tmp string
	build                string
}

func newOpRig(t *testing.T) *opRig {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	root := t.TempDir()
	r := &opRig{t: t, root: root, bin: filepath.Join(root, "bin"), stub: filepath.Join(root, "stub"), tmp: filepath.Join(root, "tmp"),
		build: filepath.Join(root, "build")}
	for _, d := range []string{r.bin, r.stub, r.tmp, filepath.Join(r.stub, "secrets")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"kubectl": opKubectl, "docker": opDocker, "mise": opMise, "kind": stubKind,
		"secret-read": opSecretRead, "secret-write": opSecretWrite} {
		if err := os.WriteFile(filepath.Join(r.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r.setConnected(true)
	r.put("kind-dev-cp", "spire-system", "cell-records", map[string]string{"local-revocations.json": "[]"})
	if err := os.WriteFile(filepath.Join(r.stub, "secrets", "other"), []byte(revoke.FormatSeed(opNewKey(t))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

func opNewKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func opPub(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

func opSHA(k ed25519.PrivateKey) string { return revoke.KeySHA256(k.Public().(ed25519.PublicKey)) }

// setConnected writes the status of mgmtd: a report of envd 10 s ago with applied equal to signed, or a report of 10 minutes ago.
func (r *opRig) setConnected(ok bool) {
	age := 10 * time.Second
	if !ok {
		age = 10 * time.Minute
	}
	r.setReportAge(age)
}

// setReportAge writes the status of mgmtd with applied equal to signed and the newest report of envd age ago.
func (r *opRig) setReportAge(age time.Duration) {
	at := time.Now().UTC().Add(-age)
	r.writeStub("mgmt-status.json", fmt.Sprintf(`{"env":"dev","signed":{"epoch":2,"counter":9},"applied":{"epoch":2,"counter":9},"lastReportAt":%q}`,
		at.Format("2006-01-02T15:04:05.123456789Z07:00")))
}

func (r *opRig) writeStub(name, body string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.stub, name), []byte(body), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// put writes a ConfigMap of the stub cluster.
func (r *opRig) put(ctx, ns, name string, data map[string]string) {
	r.t.Helper()
	b, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]string{"namespace": ns, "name": name, "resourceVersion": "1"}, "data": data})
	if err != nil {
		r.t.Fatal(err)
	}
	dir := filepath.Join(r.stub, "k", ctx, ns)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// data returns the data of a ConfigMap of the stub cluster, or nil when it is absent.
func (r *opRig) data(ctx, ns, name string) map[string]string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.stub, "k", ctx, ns, name+".json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		r.t.Fatal(err)
	}
	var cm struct{ Data map[string]string }
	if err := json.Unmarshal(b, &cm); err != nil {
		r.t.Fatal(err)
	}
	return cm.Data
}

// pinDevCP writes the three pins of dev-cp with the given keys.
func (r *opRig) pinDevCP(keys ...string) {
	lines := strings.Join(keys, "\n") + "\n"
	r.put("kind-dev-cp", "envd-system", "operator-key", map[string]string{"keys.pub": lines})
	r.put("kind-dev-cp", "gateway-system", "operator-key", map[string]string{"keys.pub": lines})
	r.put("kind-dev-cp", "spire-system", "spire-server", map[string]string{"server.conf": "plugins {\n  NodeAttestor \"cluster_jwt\" {\n    plugin_data {\n      operator_public_keys = [\"" +
		strings.Join(keys, "\", \"") + "\"]\n    }\n  }\n}\n"})
}

// installKey sets up a key that create made: the seed in the secret manager at name, operator-pub, key.env and the pins of dev-cp.
func (r *opRig) installKey(k ed25519.PrivateKey, name string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.stub, "secrets", strings.ReplaceAll(name, "/", "_")), []byte(revoke.FormatSeed(k)+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
	r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": opPub(k), "spec.name": name})
	if err := os.MkdirAll(filepath.Join(r.build, "operator"), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.build, "operator", "key.env"), []byte("OPERATOR_KEY_NAME="+name+"\nOPERATOR_KEY_SHA256="+opSHA(k)+"\n"), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.pinDevCP(opPub(k))
}

func (r *opRig) env(extra ...string) []string {
	repo, err := filepath.Abs("../..")
	if err != nil {
		r.t.Fatal(err)
	}
	return append([]string{"PATH=" + r.bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"POC_BUILD_ROOT=" + r.build, "TMPDIR=" + r.tmp, "POC_ENVRC_LOCAL=/dev/null", "STUB_DIR=" + r.stub, "STUB_REPO=" + repo,
		"STUB_OPERATORCTL=" + operatorctlBinary(r.t), "KIND_CLUSTERS_TRIES=1",
		`POC_SECRET_READ_CMD=secret-read "$1"`, `POC_SECRET_WRITE_CMD=secret-write "$1"`, "POC_OPERATOR_KEY=poc/operator"}, extra...)
}

// run runs scripts/operator-key.sh with the arguments and checks that no seed of the secret manager leaked.
func (r *opRig) run(env []string, args ...string) (stdout, stderr string, code int) {
	r.t.Helper()
	path, err := filepath.Abs("../../scripts/operator-key.sh")
	if err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{path}, args...)...)
	cmd.Env = r.env(env...)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			r.t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	r.assertNoSeed(out.String(), errBuf.String())
	return out.String(), errBuf.String(), code
}

// seeds returns the base64 body of each seed in the stub secret manager.
func (r *opRig) seeds() []string {
	r.t.Helper()
	entries, err := os.ReadDir(filepath.Join(r.stub, "secrets"))
	if err != nil {
		r.t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(r.stub, "secrets", e.Name()))
		if err != nil {
			r.t.Fatal(err)
		}
		if body := strings.TrimPrefix(strings.TrimSpace(string(b)), revoke.SeedPrefix); body != "" {
			out = append(out, body)
		}
	}
	return out
}

// assertNoSeed fails when a seed of the secret manager, or the seed prefix, is in an output, in the call log (the arguments of
// every stub), or in any file under the run directory other than the stub secret manager: the build root, TMPDIR and the stub state.
func (r *opRig) assertNoSeed(outputs ...string) {
	r.t.Helper()
	bad := append(r.seeds(), revoke.SeedPrefix)
	for i, o := range outputs {
		for _, s := range bad {
			if strings.Contains(o, s) {
				r.t.Fatalf("output %d holds the seed or its prefix %q", i, s)
			}
		}
	}
	secrets := filepath.Join(r.stub, "secrets")
	err := filepath.WalkDir(r.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p == secrets {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, s := range bad {
			if bytes.Contains(b, []byte(s)) {
				r.t.Fatalf("the file %s holds the seed or its prefix", p)
			}
		}
		return nil
	})
	if err != nil {
		r.t.Fatal(err)
	}
}

func (r *opRig) calls() []string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.stub, "calls"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		r.t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// opCallAt returns the index of the first call at or after from that starts with prefix, or -1.
func opCallAt(calls []string, from int, prefix string) int {
	for i := from; i < len(calls); i++ {
		if strings.HasPrefix(calls[i], prefix) {
			return i
		}
	}
	return -1
}

func (r *opRig) keyEnv() string {
	b, err := os.ReadFile(filepath.Join(r.build, "operator", "key.env"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func oneJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one line on standard output, got %q", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("standard output %q is no JSON object: %v", out, err)
	}
	return m
}

// noSecretAccess fails when the run read or wrote the secret manager, or ran keygen.
func noSecretAccess(t *testing.T, calls []string) {
	t.Helper()
	for _, c := range calls {
		if strings.HasPrefix(c, "secret-read") || strings.HasPrefix(c, "secret-write") || strings.HasPrefix(c, "mise run operatorctl") {
			t.Fatalf("the run reached the secret manager or keygen: %q", c)
		}
	}
}

var keyNameRE = regexp.MustCompile(`^poc/operator/[0-9]{8}T[0-9]{6}Z$`)

// TestCreateWritesSecretThroughPipe: create pipes the seed from keygen into the write command, reads it back into operatorctl pub,
// and only after the match writes operator-pub and key.env. It prints one JSON line with the key name and keySHA256, and names the
// next commands.
func TestCreateWritesSecretThroughPipe(t *testing.T) {
	t.Parallel()
	r := newOpRig(t)
	out, errOut, code := r.run(nil, "create")
	if code != 0 {
		t.Fatalf("create: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
	res := oneJSON(t, out)
	name, _ := res["keyName"].(string)
	if !keyNameRE.MatchString(name) || res["created"] != true {
		t.Fatalf("create printed %v, want created true and a key name poc/operator/<UTC time>", res)
	}
	b, err := os.ReadFile(filepath.Join(r.stub, "secrets", strings.ReplaceAll(name, "/", "_")))
	if err != nil {
		t.Fatalf("the secret manager holds no key at %s: %v", name, err)
	}
	k, err := revoke.ParseSeed(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("the secret manager holds no seed line at %s: %v", name, err)
	}
	if res["keySHA256"] != opSHA(k) {
		t.Fatalf("keySHA256 %v, want %s", res["keySHA256"], opSHA(k))
	}
	pub := r.data("kind-management", "mgmt-system", "operator-pub")
	if pub["spec.pub"] != opPub(k) || pub["spec.name"] != name || len(pub) != 2 {
		t.Fatalf("operator-pub holds %v, want spec.pub %s and spec.name %s only", pub, opPub(k), name)
	}
	if want := "OPERATOR_KEY_NAME=" + name + "\nOPERATOR_KEY_SHA256=" + opSHA(k) + "\n"; r.keyEnv() != want {
		t.Fatalf("key.env holds %q, want %q", r.keyEnv(), want)
	}
	entries, _ := os.ReadDir(filepath.Join(r.build, "operator"))
	if len(entries) != 1 {
		t.Fatalf("build/operator holds %d files, want key.env only", len(entries))
	}
	next, _ := res["next"].([]any)
	if len(next) == 0 || !strings.Contains(fmt.Sprint(next), "CELL=dev-cp mise run cell:up") || !strings.Contains(fmt.Sprint(next), "mise run operator:check-key") ||
		!strings.Contains(errOut, "mise run operator:check-key") {
		t.Fatalf("create named the next commands %v and stderr %q, want the render of dev-cp and operator:check-key", next, errOut)
	}
	calls := r.calls()
	keygen := opCallAt(calls, 0, "mise run operatorctl -- keygen --public-file ")
	write := opCallAt(calls, 0, "secret-write "+name)
	read := opCallAt(calls, 0, "secret-read "+name)
	derive := opCallAt(calls, 0, "mise run operatorctl -- pub")
	pin := opCallAt(calls, 0, "wrote kind-management mgmt-system/operator-pub")
	if keygen < 0 || write < 0 || read < 0 || derive < 0 || pin < 0 || read < write || pin < read || pin < derive {
		t.Fatalf("calls %q: want keygen into the write command, then the read into pub, then the pin", calls)
	}
	if opCallAt(calls, 0, "kubectl --context kind-management -n mgmt-system create --field-manager=operator -f -") < 0 {
		t.Fatalf("calls %q: want operator-pub written with kubectl create, so that a second writer fails", calls)
	}
}

// TestCreateNoPinOnFailedWrite: a write or a read-back that fails, or a read-back of another key, leaves no operator-pub and no
// key.env. A second run starts again with a new key.
func TestCreateNoPinOnFailedWrite(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, knob, want string }{
		{"write_fails", "STUB_WRITE_FAIL=1", "POC_SECRET_WRITE_CMD"},
		{"read_fails", "STUB_READ_FAIL=1", "read back"},
		{"read_other_key", "STUB_READ_OTHER=1", "differs"},
		{"pin_write_fails", "STUB_PIN_WRITE_FAIL=1", "operator-pub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newOpRig(t)
			out, errOut, code := r.run([]string{tc.knob}, "create")
			if code == 0 {
				t.Fatalf("create: exit 0, want a failure\nstdout %s\nstderr %s", out, errOut)
			}
			res := oneJSON(t, out)
			if res["level"] != "ERROR" || !strings.Contains(fmt.Sprint(res["error"]), tc.want) {
				t.Fatalf("error line %v, want an error that names %q", res, tc.want)
			}
			if tc.name != "pin_write_fails" && r.data("kind-management", "mgmt-system", "operator-pub") != nil {
				t.Fatal("operator-pub exists after a failed write or read-back")
			}
			if r.keyEnv() != "" {
				t.Fatalf("key.env holds %q after a failure", r.keyEnv())
			}
			if entries, _ := os.ReadDir(filepath.Join(r.build, "operator")); len(entries) != 0 {
				t.Fatalf("build/operator holds %d files after a failure", len(entries))
			}
			if tc.name == "write_fails" && opCallAt(r.calls(), 0, "secret-read") >= 0 {
				t.Fatalf("calls %q: a failed write must stop before the read-back", r.calls())
			}
			if tc.name == "pin_write_fails" {
				return
			}
			out, errOut, code = r.run(nil, "create")
			if code != 0 {
				t.Fatalf("the second create: exit %d\nstdout %s\nstderr %s", code, out, errOut)
			}
			name, _ := oneJSON(t, out)["keyName"].(string)
			if k := newRotatedKey(t, r, name); r.data("kind-management", "mgmt-system", "operator-pub")["spec.pub"] != opPub(k) {
				t.Fatalf("after the second create, operator-pub does not hold the key at %s", name)
			}
		})
	}
}

// TestCreateRefusesSecondKey: create refuses when key.env or operator-pub exists, or when it cannot read operator-pub, before it
// runs keygen or reaches the secret manager.
func TestCreateRefusesSecondKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		setup func(r *opRig)
		env   []string
		want  string
	}{
		{"key_env", func(r *opRig) {
			os.MkdirAll(filepath.Join(r.build, "operator"), 0o755)
			os.WriteFile(filepath.Join(r.build, "operator", "key.env"), []byte("OPERATOR_KEY_NAME=poc/operator/x\n"), 0o644)
		}, nil, "key.env"},
		{"operator_pub", func(r *opRig) {
			r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": opPub(opNewKey(r.t)), "spec.name": "poc/operator/x"})
		}, nil, "operator-pub"},
		{"management_down", func(*opRig) {}, []string{"STUB_DOWN=kind-management"}, "operator-pub"},
		{"no_prefix", func(*opRig) {}, []string{"POC_OPERATOR_KEY="}, "POC_OPERATOR_KEY"},
		{"no_write_command", func(*opRig) {}, []string{"POC_SECRET_WRITE_CMD="}, "POC_SECRET_WRITE_CMD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newOpRig(t)
			tc.setup(r)
			before := r.data("kind-management", "mgmt-system", "operator-pub")
			out, errOut, code := r.run(tc.env, "create")
			if code == 0 {
				t.Fatalf("create: exit 0, want a refusal\nstdout %s\nstderr %s", out, errOut)
			}
			res := oneJSON(t, out)
			if !strings.Contains(fmt.Sprint(res["error"]), tc.want) {
				t.Fatalf("error line %v, want an error that names %q", res, tc.want)
			}
			noSecretAccess(t, r.calls())
			if fmt.Sprint(r.data("kind-management", "mgmt-system", "operator-pub")) != fmt.Sprint(before) {
				t.Fatal("create changed operator-pub")
			}
		})
	}
}

// TestCheckMatches: check reads the seed through the read command into operatorctl pub and compares the key with operator-pub, the
// three pins of dev-cp and key.env. Without key.env it reads the key name from spec.name of operator-pub.
func TestCheckMatches(t *testing.T) {
	t.Parallel()
	for _, withEnv := range []bool{true, false} {
		t.Run(fmt.Sprintf("key_env_%v", withEnv), func(t *testing.T) {
			t.Parallel()
			r := newOpRig(t)
			k := opNewKey(t)
			r.installKey(k, "poc/operator/20261120T093000Z")
			if !withEnv {
				os.Remove(filepath.Join(r.build, "operator", "key.env"))
			}
			out, errOut, code := r.run(nil, "check")
			if code != 0 {
				t.Fatalf("check: exit %d\nstdout %s\nstderr %s", code, out, errOut)
			}
			res := oneJSON(t, out)
			if res["match"] != true || res["keySHA256"] != opSHA(k) || res["keyName"] != "poc/operator/20261120T093000Z" ||
				res["operatorPub"] != true || res["envd"] != true || res["gateway"] != true || res["serverConf"] != true {
				t.Fatalf("check printed %v, want match true with every pin true", res)
			}
			if withEnv && res["keyEnv"] != true {
				t.Fatalf("check printed %v, want keyEnv true", res)
			}
			if !withEnv && res["keyEnv"] != nil {
				t.Fatalf("check printed %v with no key.env, want no keyEnv field", res)
			}
			if opCallAt(r.calls(), 0, "secret-read poc/operator/20261120T093000Z") < 0 {
				t.Fatalf("calls %q: want a read of the key name", r.calls())
			}
			noWrites(t, r.calls())
		})
	}
}

func noWrites(t *testing.T, calls []string) {
	t.Helper()
	for _, c := range calls {
		if strings.HasPrefix(c, "wrote ") || strings.HasPrefix(c, "secret-write") {
			t.Fatalf("the run wrote %q", c)
		}
	}
}

// TestCheckFindsSwappedPin: a pin that holds another key gives match false, the field of that pin false, and its name in mismatch.
func TestCheckFindsSwappedPin(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, field, pin string
		swap             func(r *opRig, other string)
	}{
		{"envd", "envd", "dev-cp envd-system/operator-key", func(r *opRig, o string) {
			r.put("kind-dev-cp", "envd-system", "operator-key", map[string]string{"keys.pub": o + "\n"})
		}},
		{"gateway", "gateway", "dev-cp gateway-system/operator-key", func(r *opRig, o string) {
			r.put("kind-dev-cp", "gateway-system", "operator-key", map[string]string{"keys.pub": o + "\n"})
		}},
		{"gateway_added_key", "gateway", "dev-cp gateway-system/operator-key", func(r *opRig, o string) {
			d := r.data("kind-dev-cp", "envd-system", "operator-key")
			r.put("kind-dev-cp", "gateway-system", "operator-key", map[string]string{"keys.pub": d["keys.pub"] + o + "\n"})
		}},
		{"gateway_absent", "gateway", "dev-cp gateway-system/operator-key", func(r *opRig, _ string) {
			os.Remove(filepath.Join(r.stub, "k", "kind-dev-cp", "gateway-system", "operator-key.json"))
		}},
		{"server_conf", "serverConf", "dev-cp spire-system/spire-server operator_public_keys", func(r *opRig, o string) {
			r.put("kind-dev-cp", "spire-system", "spire-server", map[string]string{"server.conf": "plugins {\n  NodeAttestor \"cluster_jwt\" {\n    plugin_data {\n      operator_public_keys = [\"" + o + "\"]\n    }\n  }\n}\n"})
		}},
		{"operator_pub", "operatorPub", "management mgmt-system/operator-pub", func(r *opRig, o string) {
			d := r.data("kind-management", "mgmt-system", "operator-pub")
			d["spec.pub"] = o
			r.put("kind-management", "mgmt-system", "operator-pub", d)
		}},
		{"operator_pub_next_added", "operatorPub", "management mgmt-system/operator-pub", func(r *opRig, o string) { r.setNext(o) }},
		{"key_env_name", "keyEnv", "build/operator/key.env", func(r *opRig, _ string) {
			// The same seed sits at another remote key, and key.env names that key with the right SHA-256.
			b, err := os.ReadFile(filepath.Join(r.stub, "secrets", "poc_operator_20261120T093000Z"))
			if err != nil {
				r.t.Fatal(err)
			}
			os.WriteFile(filepath.Join(r.stub, "secrets", "poc_operator_other"), b, 0o600)
			raw, _ := base64.StdEncoding.DecodeString(r.data("kind-management", "mgmt-system", "operator-pub")["spec.pub"])
			os.WriteFile(filepath.Join(r.build, "operator", "key.env"), []byte("OPERATOR_KEY_NAME=poc/operator/other\nOPERATOR_KEY_SHA256="+revoke.KeySHA256(raw)+"\n"), 0o644)
		}},
		{"key_env", "keyEnv", "build/operator/key.env", func(r *opRig, _ string) {
			os.WriteFile(filepath.Join(r.build, "operator", "key.env"), []byte("OPERATOR_KEY_NAME=poc/operator/20261120T093000Z\nOPERATOR_KEY_SHA256="+strings.Repeat("ab", 32)+"\n"), 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newOpRig(t)
			k := opNewKey(t)
			r.installKey(k, "poc/operator/20261120T093000Z")
			tc.swap(r, opPub(opNewKey(t)))
			out, errOut, code := r.run(nil, "check")
			if code == 0 {
				t.Fatalf("check: exit 0, want 1\nstdout %s\nstderr %s", out, errOut)
			}
			res := oneJSON(t, out)
			if res["match"] != false || res[tc.field] != false {
				t.Fatalf("check printed %v, want match false and %s false", res, tc.field)
			}
			for _, f := range []string{"operatorPub", "envd", "gateway", "serverConf", "keyEnv"} {
				if f != tc.field && res[f] != true {
					t.Errorf("check printed %v, want %s true", res, f)
				}
			}
			if mm, _ := res["mismatch"].([]any); len(mm) != 1 || mm[0] != tc.pin {
				t.Fatalf("mismatch %v, want [%s]", res["mismatch"], tc.pin)
			}
			if !strings.Contains(errOut, tc.pin) {
				t.Fatalf("stderr %q does not name %s", errOut, tc.pin)
			}
			noWrites(t, r.calls())
		})
	}
}

// operatorPubWrites returns the data of each write of operator-pub in the call log, with its index.
func operatorPubWrites(t *testing.T, calls []string) (idx []int, data []map[string]string) {
	t.Helper()
	const prefix = "wrote kind-management mgmt-system/operator-pub "
	for i, c := range calls {
		if rest, ok := strings.CutPrefix(c, prefix); ok {
			var d map[string]string
			if err := json.Unmarshal([]byte(rest), &d); err != nil {
				t.Fatalf("write %q: %v", c, err)
			}
			idx = append(idx, i)
			data = append(data, d)
		}
	}
	return idx, data
}

// rotateRig sets up a pinned key and returns the rig, the old key and its name.
func rotateRig(t *testing.T) (*opRig, ed25519.PrivateKey, string) {
	r := newOpRig(t)
	old := opNewKey(t)
	name := "poc/operator/20260101T000000Z"
	r.installKey(old, name)
	return r, old, name
}

// newRotatedKey returns the key that the rotation wrote to the secret manager under name.
func newRotatedKey(t *testing.T, r *opRig, name string) ed25519.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.stub, "secrets", strings.ReplaceAll(name, "/", "_")))
	if err != nil {
		t.Fatalf("the secret manager holds no key at %s: %v", name, err)
	}
	k, err := revoke.ParseSeed(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestRotateOverlapOrder: the default rotation writes the new key to the secret manager and reads it back, adds it as next.pub, renders
// both keys into dev-cp and management, and verifies them, all before the switch. The switch makes the new key spec.pub alone, renders
// and verifies again, and updates key.env.
func TestRotateOverlapOrder(t *testing.T) {
	t.Parallel()
	r, old, oldName := rotateRig(t)
	out, errOut, code := r.run(nil, "rotate")
	if code != 0 {
		t.Fatalf("rotate: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
	res := oneJSON(t, out)
	newName, _ := res["newKeyName"].(string)
	if !keyNameRE.MatchString(newName) || newName == oldName {
		t.Fatalf("rotate printed %v, want a new key name", res)
	}
	k := newRotatedKey(t, r, newName)
	if res["rotated"] != true || res["mode"] != "overlap" || res["oldKeySHA256"] != opSHA(old) || res["newKeySHA256"] != opSHA(k) || res["oldKeyName"] != oldName {
		t.Fatalf("rotate printed %v, want rotated true, mode overlap and both keys", res)
	}
	calls := r.calls()
	write := opCallAt(calls, 0, "secret-write "+newName)
	read := opCallAt(calls, 0, "secret-read "+newName)
	idx, data := operatorPubWrites(t, calls)
	if write < 0 || read < write || len(idx) != 2 || idx[0] < read {
		t.Fatalf("calls %q: want the write, the read-back, then two writes of operator-pub", calls)
	}
	if fmt.Sprint(data[0]) != fmt.Sprint(map[string]string{"spec.pub": opPub(old), "spec.name": oldName, "next.pub": opPub(k)}) {
		t.Fatalf("the first write of operator-pub holds %v, want the old key and next.pub", data[0])
	}
	if fmt.Sprint(data[1]) != fmt.Sprint(map[string]string{"spec.pub": opPub(k), "spec.name": newName}) {
		t.Fatalf("the switch holds %v, want the new key alone", data[1])
	}
	both := opPub(old) + "," + opPub(k)
	steps := []string{
		"mise run cell:up CELL=dev-cp LINK_ONLY= ACCEPT=1", "render dev-cp pins=" + both,
		"mise run cell:link CELL=management LINK_ONLY=mgmt-api ACCEPT=1",
		"verify dev-cp pins=" + both, "verify management pins=" + both,
	}
	at := idx[0]
	for _, s := range steps {
		if at = opCallAt(calls, at, s); at < 0 || at > idx[1] {
			t.Fatalf("calls %q: want %q between next.pub and the switch", calls, s)
		}
	}
	at = idx[1]
	for _, s := range []string{"mise run cell:up CELL=dev-cp LINK_ONLY= ACCEPT=1", "render dev-cp pins=" + opPub(k),
		"mise run cell:link CELL=management LINK_ONLY=mgmt-api ACCEPT=1", "verify dev-cp pins=" + opPub(k), "verify management pins=" + opPub(k)} {
		if at = opCallAt(calls, at, s); at < 0 {
			t.Fatalf("calls %q: want %q after the switch", calls, s)
		}
	}
	if want := "OPERATOR_KEY_NAME=" + newName + "\nOPERATOR_KEY_SHA256=" + opSHA(k) + "\n"; r.keyEnv() != want {
		t.Fatalf("key.env holds %q, want %q", r.keyEnv(), want)
	}
	if got := newRotatedKey(t, r, oldName); !got.Equal(old) {
		t.Fatal("the rotation changed the old key in the secret manager")
	}
}

// TestRotateEmergencySingleKey: --emergency makes the new key spec.pub alone at once, and no render ever pins both keys.
func TestRotateEmergencySingleKey(t *testing.T) {
	t.Parallel()
	r, old, _ := rotateRig(t)
	out, errOut, code := r.run(nil, "rotate", "--emergency")
	if code != 0 {
		t.Fatalf("rotate --emergency: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
	res := oneJSON(t, out)
	newName, _ := res["newKeyName"].(string)
	k := newRotatedKey(t, r, newName)
	if res["rotated"] != true || res["mode"] != "emergency" || res["newKeySHA256"] != opSHA(k) || res["oldKeySHA256"] != opSHA(old) {
		t.Fatalf("rotate printed %v, want rotated true, mode emergency and both keys", res)
	}
	calls := r.calls()
	idx, data := operatorPubWrites(t, calls)
	if len(idx) != 1 || fmt.Sprint(data[0]) != fmt.Sprint(map[string]string{"spec.pub": opPub(k), "spec.name": newName}) {
		t.Fatalf("operator-pub writes %v, want one write of the new key alone", data)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "render ") && c != "render dev-cp pins="+opPub(k) {
			t.Fatalf("calls %q: render %q, want the new key alone", calls, c)
		}
	}
	at := idx[0]
	for _, s := range []string{"mise run cell:up CELL=dev-cp LINK_ONLY= ACCEPT=1", "render dev-cp pins=" + opPub(k),
		"mise run cell:link CELL=management LINK_ONLY=mgmt-api ACCEPT=1", "verify dev-cp pins=" + opPub(k), "verify management pins=" + opPub(k)} {
		if at = opCallAt(calls, at, s); at < 0 {
			t.Fatalf("calls %q: want %q after the write", calls, s)
		}
	}
	if d := r.data("kind-dev-cp", "gateway-system", "operator-key"); d["keys.pub"] != opPub(k)+"\n" {
		t.Fatalf("the gateway pins %q, want the new key alone", d["keys.pub"])
	}
}

// rotateRefusals are the states in which rotate must refuse before it reads the secret manager.
var rotateRefusals = []struct {
	name  string
	setup func(r *opRig)
	env   []string
	want  string
}{
	{"report_old", func(r *opRig) { r.setConnected(false) }, nil, "not connected"},
	{"applied_behind", func(r *opRig) {
		r.writeStub("mgmt-status.json", fmt.Sprintf(`{"signed":{"epoch":2,"counter":10},"applied":{"epoch":2,"counter":9},"lastReportAt":%q}`, time.Now().UTC().Format(time.RFC3339Nano)))
	}, nil, "not connected"},
	{"mgmt_down", func(*opRig) {}, []string{"STUB_MGMT_DOWN=1"}, "not connected"},
	{"report_3m", func(r *opRig) { r.setReportAge(3 * time.Minute) }, nil, "not connected"},
	{"cut_v4", func(*opRig) {}, []string{"STUB_CUT=dev-cp-control-plane:iptables"}, "dev-cp-control-plane"},
	{"cut_v6", func(*opRig) {}, []string{"STUB_CUT=dev-cell-2-control-plane:ip6tables"}, "dev-cell-2-control-plane"},
	{"node_unreadable", func(*opRig) {}, []string{"STUB_DOCKER_FAIL=dev-cell-1-control-plane"}, "dev-cell-1-control-plane"},
	{"marker", func(r *opRig) {
		os.MkdirAll(filepath.Join(r.build, "gate"), 0o755)
		os.WriteFile(filepath.Join(r.build, "gate", "m9-svid-ttl"), []byte("1h\n"), 0o644)
	}, nil, "m9-svid-ttl"},
	{"held_entry", func(r *opRig) {
		r.put("kind-dev-cp", "spire-system", "cell-records", map[string]string{"local-revocations.json": `[{"payloadType":"application/vnd.poc.local-revocation+json","payload":"e30=","signatures":[{"sig":"AA=="}]}]`})
	}, nil, "held"},
	{"records_unreadable", func(r *opRig) {
		os.Remove(filepath.Join(r.stub, "k", "kind-dev-cp", "spire-system", "cell-records.json"))
	}, nil, "cell-records"},
	{"no_operator_pub", func(r *opRig) {
		os.Remove(filepath.Join(r.stub, "k", "kind-management", "mgmt-system", "operator-pub.json"))
	}, nil, "operator:create-key"},
	{"next_pending", func(r *opRig) {
		d := r.data("kind-management", "mgmt-system", "operator-pub")
		d["next.pub"] = opPub(opNewKey(r.t))
		r.put("kind-management", "mgmt-system", "operator-pub", d)
	}, nil, "--emergency"},
	// A writer of operator-pub swaps spec.pub for a key of its own. The pins in force and key.env keep the real key.
	{"spec_swapped", func(r *opRig) {
		d := r.data("kind-management", "mgmt-system", "operator-pub")
		d["spec.pub"] = opPub(opNewKey(r.t))
		r.put("kind-management", "mgmt-system", "operator-pub", d)
	}, nil, "operator:check-key"},
	{"pin_differs", func(r *opRig) {
		r.put("kind-dev-cp", "gateway-system", "operator-key", map[string]string{"keys.pub": opPub(opNewKey(r.t)) + "\n"})
	}, nil, "dev-cp gateway-system/operator-key"},
	{"pin_absent", func(r *opRig) {
		os.Remove(filepath.Join(r.stub, "k", "kind-dev-cp", "envd-system", "operator-key.json"))
	}, nil, "dev-cp envd-system/operator-key"},
	{"key_env_stale", func(r *opRig) {
		os.WriteFile(filepath.Join(r.build, "operator", "key.env"), []byte("OPERATOR_KEY_NAME=poc/operator/20260101T000000Z\nOPERATOR_KEY_SHA256="+strings.Repeat("ab", 32)+"\n"), 0o644)
	}, nil, "build/operator/key.env"},
}

// overlapOnly names the refusals of the default mode alone. A pending next.pub is the case that --emergency finishes. The other rows
// check the old key, which the overlap pins again and --emergency drops.
var overlapOnly = map[string]bool{"next_pending": true, "spec_swapped": true, "pin_differs": true, "pin_absent": true, "key_env_stale": true}

func runRotateRefusal(t *testing.T, name string, args ...string) {
	t.Helper()
	for _, tc := range rotateRefusals {
		if tc.name != name {
			continue
		}
		r, _, _ := rotateRig(t)
		tc.setup(r)
		pins := fmt.Sprint(r.data("kind-dev-cp", "envd-system", "operator-key"), r.data("kind-management", "mgmt-system", "operator-pub"))
		out, errOut, code := r.run(tc.env, append([]string{"rotate"}, args...)...)
		if code == 0 {
			t.Fatalf("rotate: exit 0, want a refusal\nstdout %s\nstderr %s", out, errOut)
		}
		res := oneJSON(t, out)
		if !strings.Contains(fmt.Sprint(res["error"]), tc.want) {
			t.Fatalf("error line %v, want an error that names %q", res, tc.want)
		}
		noSecretAccess(t, r.calls())
		noWrites(t, r.calls())
		if opCallAt(r.calls(), 0, "mise run cell:") >= 0 {
			t.Fatalf("calls %q: a refused rotation ran a cell task", r.calls())
		}
		if got := fmt.Sprint(r.data("kind-dev-cp", "envd-system", "operator-key"), r.data("kind-management", "mgmt-system", "operator-pub")); got != pins {
			t.Fatal("a refused rotation changed a pin")
		}
		return
	}
	t.Fatalf("no refusal %s", name)
}

// TestRotateRefusesNotConnected: rotate refuses while the newest report of envd at mgmtd is older than 2 minutes, while envd has not
// applied the signed revision, and while mgmtd does not answer.
func TestRotateRefusesNotConnected(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"report_old", "report_3m", "applied_behind", "mgmt_down"} {
		t.Run(name, func(t *testing.T) { t.Parallel(); runRotateRefusal(t, name) })
	}
}

// TestRotateRefusesCut: rotate refuses while a node holds a cut rule of the partition tool, in iptables or ip6tables, and while it
// cannot read the rules of a node.
func TestRotateRefusesCut(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"cut_v4", "cut_v6", "node_unreadable"} {
		t.Run(name, func(t *testing.T) { t.Parallel(); runRotateRefusal(t, name, "--emergency") })
	}
}

// TestRotateRefusesHeldEntry: rotate refuses while envd holds a local revocation entry, and while it cannot read the held overlay.
func TestRotateRefusesHeldEntry(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"held_entry", "records_unreadable"} {
		t.Run(name, func(t *testing.T) { t.Parallel(); runRotateRefusal(t, name) })
	}
}

// TestRotateRefusesSwappedPin: the overlap pins the old key again, so it refuses unless spec.pub of operator-pub is the only key of
// every pin in force in dev-cp and matches the SHA-256 in key.env. A writer of operator-pub who swaps spec.pub gets no render.
func TestRotateRefusesSwappedPin(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"spec_swapped", "pin_differs", "pin_absent", "key_env_stale"} {
		t.Run(name, func(t *testing.T) { t.Parallel(); runRotateRefusal(t, name) })
	}
}

// TestRotateEmergencyDropsSwappedKey: --emergency pins the new key alone, so it goes on when spec.pub was swapped, and never renders
// the swapped key.
func TestRotateEmergencyDropsSwappedKey(t *testing.T) {
	t.Parallel()
	r, _, _ := rotateRig(t)
	bad := opPub(opNewKey(t))
	d := r.data("kind-management", "mgmt-system", "operator-pub")
	d["spec.pub"] = bad
	r.put("kind-management", "mgmt-system", "operator-pub", d)
	out, errOut, code := r.run(nil, "rotate", "--emergency")
	if code != 0 {
		t.Fatalf("rotate --emergency: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
	k := newRotatedKey(t, r, oneJSON(t, out)["newKeyName"].(string))
	for _, c := range r.calls() {
		if strings.HasPrefix(c, "render ") && strings.Contains(c, bad) {
			t.Fatalf("calls %q: a render pinned the swapped key", r.calls())
		}
	}
	if got := r.data("kind-dev-cp", "envd-system", "operator-key")["keys.pub"]; got != opPub(k)+"\n" {
		t.Fatalf("envd pins %q, want the new key alone", got)
	}
}

// TestRotateKeepsResourceVersion: each write of operator-pub carries the resourceVersion of the write before it, from the first read
// on. A change of operator-pub during the rotation fails the switch, and the error line names the step and the way out.
func TestRotateKeepsResourceVersion(t *testing.T) {
	t.Parallel()
	r, old, oldName := rotateRig(t)
	out, errOut, code := r.run([]string{"STUB_TAMPER=1"}, "rotate")
	if code == 0 {
		t.Fatalf("rotate: exit 0 after a change of operator-pub during the rotation\nstdout %s\nstderr %s", out, errOut)
	}
	res := oneJSON(t, out)
	if res["step"] != "switch" || res["switched"] != false || !strings.Contains(fmt.Sprint(res["remaining"]), "--emergency") ||
		!strings.Contains(fmt.Sprint(res["error"]), "unused key at poc/operator/") {
		t.Fatalf("error line %v, want step switch, switched false, the unused remote key and --emergency", res)
	}
	d := r.data("kind-management", "mgmt-system", "operator-pub")
	if d["spec.pub"] != opPub(old) || d["spec.name"] != oldName {
		t.Fatalf("operator-pub holds %v, want the old key: the switch must not overwrite a change", d)
	}
}

// TestRotateRefusesBeforeSecretRead: every refusal of rotate, in both modes, comes before keygen and before any read or write of the
// secret manager, so a refused rotation never prompts.
func TestRotateRefusesBeforeSecretRead(t *testing.T) {
	t.Parallel()
	for _, tc := range rotateRefusals {
		for _, mode := range [][]string{nil, {"--emergency"}} {
			if overlapOnly[tc.name] && mode != nil {
				continue
			}
			t.Run(tc.name+strings.Join(mode, ""), func(t *testing.T) { t.Parallel(); runRotateRefusal(t, tc.name, mode...) })
		}
	}
}

// opGuard runs operator_pub_keys of components/lib/operator-key.sh with the stubs of the rig.
func (r *opRig) guard(env ...string) (stdout, stderr string, code int) {
	r.t.Helper()
	lib, err := filepath.Abs("../../components/lib/operator-key.sh")
	if err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `set -euo pipefail; source "$1"; operator_pub_keys dev-cp`, "_", lib)
	cmd.Env = r.env(env...)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			r.t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errBuf.String(), code
}

// TestPinGuardRefusesChange: operator_pub_keys prints spec.pub and next.pub of operator-pub for a render. When a pin of the cluster
// holds another key set, it refuses unless OPERATOR_KEY_ACCEPT_CHANGE=1, and it refuses any change while not connected.
func TestPinGuardRefusesChange(t *testing.T) {
	t.Parallel()
	a, b := opPub(opNewKey(t)), opPub(opNewKey(t))
	for _, tc := range []struct {
		name  string
		setup func(r *opRig)
		env   []string
		code  int
		want  string
	}{
		{"nothing_pinned", func(r *opRig) {}, nil, 0, a + "\n"},
		{"nothing_pinned_not_connected", func(r *opRig) { r.setConnected(false) }, nil, 0, a + "\n"},
		{"same_keys", func(r *opRig) { r.pinDevCP(a) }, nil, 0, a + "\n"},
		{"same_keys_not_connected", func(r *opRig) { r.pinDevCP(a); r.setConnected(false) }, nil, 0, a + "\n"},
		{"next_key", func(r *opRig) { r.setNext(b); r.pinDevCP(a, b) }, nil, 0, a + "\n" + b + "\n"},
		{"changed", func(r *opRig) { r.pinDevCP(b) }, nil, 1, "OPERATOR_KEY_ACCEPT_CHANGE"},
		{"changed_accepted", func(r *opRig) { r.pinDevCP(b) }, []string{"OPERATOR_KEY_ACCEPT_CHANGE=1"}, 0, a + "\n"},
		{"changed_accepted_not_connected", func(r *opRig) { r.pinDevCP(b); r.setConnected(false) }, []string{"OPERATOR_KEY_ACCEPT_CHANGE=1"}, 1, "not connected"},
		{"changed_accepted_report_90s", func(r *opRig) { r.pinDevCP(b); r.setReportAge(90 * time.Second) }, []string{"OPERATOR_KEY_ACCEPT_CHANGE=1"}, 0, a + "\n"},
		{"changed_accepted_report_3m", func(r *opRig) { r.pinDevCP(b); r.setReportAge(3 * time.Minute) }, []string{"OPERATOR_KEY_ACCEPT_CHANGE=1"}, 1, "not connected"},
		{"changed_accepted_mgmt_down", func(r *opRig) { r.pinDevCP(b) }, []string{"OPERATOR_KEY_ACCEPT_CHANGE=1", "STUB_MGMT_DOWN=1"}, 1, "not connected"},
		{"next_added", func(r *opRig) { r.setNext(b); r.pinDevCP(a) }, nil, 1, "envd-system/operator-key"},
		{"gateway_swapped", func(r *opRig) {
			r.pinDevCP(a)
			r.put("kind-dev-cp", "gateway-system", "operator-key", map[string]string{"keys.pub": b + "\n"})
		}, nil, 1, "gateway-system/operator-key"},
		{"server_conf_swapped", func(r *opRig) {
			r.pinDevCP(a)
			r.put("kind-dev-cp", "spire-system", "spire-server", map[string]string{"server.conf": "operator_public_keys = [\"" + b + "\"]\n"})
		}, nil, 1, "operator_public_keys"},
		{"no_operator_pub", func(r *opRig) {
			os.Remove(filepath.Join(r.stub, "k", "kind-management", "mgmt-system", "operator-pub.json"))
		}, nil, 1, "operator:create-key"},
		{"bad_spec_pub", func(r *opRig) {
			r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": "not-a-key", "spec.name": "poc/operator/x"})
		}, nil, 1, "spec.pub"},
		{"same_next", func(r *opRig) { r.setNext(a) }, nil, 1, "next.pub"},
		{"dev_cp_down", func(r *opRig) { r.pinDevCP(a) }, []string{"STUB_DOWN=kind-dev-cp"}, 1, "dev-cp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newOpRig(t)
			r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": a, "spec.name": "poc/operator/x"})
			tc.setup(r)
			out, errOut, code := r.guard(tc.env...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			if tc.code == 0 && out != tc.want {
				t.Fatalf("stdout %q, want %q", out, tc.want)
			}
			if tc.code != 0 && (out != "" || !strings.Contains(errOut, tc.want)) {
				t.Fatalf("stdout %q, stderr %q; want no key lines and an error that names %q", out, errOut, tc.want)
			}
		})
	}
}

func (r *opRig) setNext(k string) {
	d := r.data("kind-management", "mgmt-system", "operator-pub")
	d["next.pub"] = k
	r.put("kind-management", "mgmt-system", "operator-pub", d)
}

// TestOperatorScriptsKeepSeedInPipes: neither operator script has a here-string, a heredoc, mktemp, xtrace or a variable that holds
// the seed. Each read of the secret manager pipes straight into operatorctl, and keygen pipes straight into the write command. Under
// xtrace, which shows every assignment and command, a create, a check and a rotation print no seed on standard error, and leave no
// seed under the build root, TMPDIR or the stub state.
func TestOperatorScriptsKeepSeedInPipes(t *testing.T) {
	t.Parallel()
	readLine := regexp.MustCompile(`^\s*.*bash -c "\$POC_SECRET_READ_CMD" _ "\$[a-z_]+" \| mise run operatorctl -- (pub|sign)\b`)
	keygenLine := regexp.MustCompile(`^\s*(if ! )?mise run operatorctl -- keygen --public-file "\$[a-z_]+" \| bash -c "\$POC_SECRET_WRITE_CMD" _ "\$[a-z_]+"`)
	settingsLine := regexp.MustCompile(`^\s*(load_local_settings|need_settings) `)
	for _, f := range []string{"../../scripts/operator-key.sh", "../../components/lib/operator-key.sh"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, bad := range []*regexp.Regexp{regexp.MustCompile(`<<<`), regexp.MustCompile(`<<-?\s*['"]?[A-Za-z_]`), regexp.MustCompile(`\bmktemp\b`),
				regexp.MustCompile(`\bset\s+-[a-wyz]*x`), regexp.MustCompile(`xtrace`), regexp.MustCompile(`\bBASH_XTRACEFD\b`)} {
				if bad.MatchString(code) {
					t.Errorf("%s line %d has %q: %s", filepath.Base(f), i+1, bad, line)
				}
			}
			if (strings.Contains(code, "$POC_SECRET_READ_CMD") || strings.Contains(code, "{POC_SECRET_READ_CMD")) && !settingsLine.MatchString(code) && !strings.Contains(code, "${!name") &&
				!regexp.MustCompile(`^\s*for name in`).MatchString(code) && !readLine.MatchString(code) {
				t.Errorf("%s line %d uses the read command outside a pipe into operatorctl: %s", filepath.Base(f), i+1, line)
			}
			if strings.Contains(code, "operatorctl -- keygen") && !keygenLine.MatchString(code) {
				t.Errorf("%s line %d runs keygen outside a pipe into the write command: %s", filepath.Base(f), i+1, line)
			}
			if (strings.Contains(code, "$POC_SECRET_WRITE_CMD") || strings.Contains(code, "{POC_SECRET_WRITE_CMD")) && !settingsLine.MatchString(code) && !strings.Contains(code, "${!name") &&
				!regexp.MustCompile(`^\s*for name in`).MatchString(code) && !keygenLine.MatchString(code) {
				t.Errorf("%s line %d uses the write command outside the keygen pipe: %s", filepath.Base(f), i+1, line)
			}
		}
		if strings.Contains(f, "components") && strings.Contains(string(b), "POC_SECRET") {
			t.Errorf("%s reaches the secret manager; only scripts/operator-key.sh may", f)
		}
	}

	r := newOpRig(t)
	trace := "SHELLOPTS=xtrace"
	for _, args := range [][]string{{"create"}, {"check"}, {"rotate"}, {"rotate", "--emergency"}, {"check"}} {
		out, errOut, code := r.run([]string{trace}, args...)
		if code != 0 {
			t.Fatalf("%v under xtrace: exit %d\nstdout %s\nstderr %s", args, code, out, errOut)
		}
		if !strings.Contains(errOut, "+ ") {
			t.Fatalf("%v: stderr shows no xtrace lines, so the run did not trace", args)
		}
		if args[0] == "create" {
			r.pinDevCP(r.data("kind-management", "mgmt-system", "operator-pub")["spec.pub"])
		}
	}
	if n := len(r.seeds()); n != 4 {
		t.Fatalf("the secret manager holds %d values, want the other seed and three keys", n)
	}
}

// TestOperatorKeyOldBase64: on a macOS before 13, base64 decodes with -D only. check and the pin guard still work there.
func TestOperatorKeyOldBase64(t *testing.T) {
	t.Parallel()
	real, err := exec.LookPath("base64")
	if err != nil {
		t.Skip("no base64 on PATH")
	}
	r := newOpRig(t)
	stub := fmt.Sprintf("#!/usr/bin/env bash\ncase \"${1:-}\" in\n  -d) echo \"base64: invalid option -- d\" >&2; exit 64 ;;\n  -D) shift; exec %q -d \"$@\" ;;\n  *) exec %q \"$@\" ;;\nesac\n", real, real)
	if err := os.WriteFile(filepath.Join(r.bin, "base64"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	k := opNewKey(t)
	r.installKey(k, "poc/operator/20261120T093000Z")
	out, errOut, code := r.run(nil, "check")
	if code != 0 || oneJSON(t, out)["match"] != true || oneJSON(t, out)["keySHA256"] != opSHA(k) {
		t.Fatalf("check with base64 -D: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
	if out, errOut, code := r.guard(); code != 0 || out != opPub(k)+"\n" {
		t.Fatalf("guard with base64 -D: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
}
