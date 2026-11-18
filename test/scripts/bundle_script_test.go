package scripts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

const (
	stubOpID     = "cccccccccccccccccccccccccccccccc"
	stubRootSHA  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	stubArgocdD  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	stubCellSysD = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// bundleMise stands in for mise in the tests of bundle.sh. It logs each call with the CELL of the call and answers the calls that
// bundle.sh makes: the mirror facts, bundlectl push, push-root and attach, and mgmt bundle sign, get and cosign. STUB_SIGN_FAIL,
// STUB_PUSH_FAIL, STUB_ATTACH_FAIL and STUB_NO_MIRROR make the call fail with one JSON error line. STUB_MIRROR_HOST replaces the mirror host. STUB_ROOT_PUSHED replaces the digest
// that push-root answers. STUB_OUTCOMES lists what the successive calls of bundle get answer: open (no result), or an outcome. The last
// answer repeats. STUB_OTHER_OP makes bundle get answer another operation.
const bundleMise = `#!/usr/bin/env bash
echo "mise $* | CELL=${CELL:-} | locks=$(ls "$POC_BUILD_ROOT/locks" 2>/dev/null | tr '\n' ' ')" >>"$STUB_LOG"
fail() { echo "{\"level\":\"ERROR\",\"msg\":\"stub failed\",\"error\":\"$1\"}"; exit 1; }
root=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
opid=cccccccccccccccccccccccccccccccc
comps='[{"name":"argocd","wave":-1,"namespace":"argocd","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"name":"cell-system","wave":-1,"namespace":"cell-system","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]'
case "$*" in
  "run hostsvc -- facts --registry")
    [[ -z "${STUB_NO_MIRROR:-}" ]] || fail "registry-mirror has no address"
    printf '{"name":"registry-mirror","address":"172.18.0.7","port":5000,"host":"%s"}\n' "${STUB_MIRROR_HOST:-127.0.0.1:5001}" ;;
  "run mgmt -- pubkey")
    echo '{"spec.pub":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}' ;;
  "run bundlectl -- pubkey-pem")
    cat >/dev/null; printf -- '-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----\n' ;;
  "x -- cosign verify-attestation "*)
    # cosign runs with an empty DOCKER_CONFIG and the flags of the spike. STUB_COSIGN_FAIL fails it. STUB_COSIGN_SUBJECTS holds the hex digests that the statement names.
    [[ -d "${DOCKER_CONFIG:-}" && -z "$(ls -A "$DOCKER_CONFIG")" ]] || { echo "cosign needs an empty DOCKER_CONFIG" >&2; exit 3; }
    [[ "$*" == *" --insecure-ignore-tlog=true "* && "$*" == *" --allow-http-registry "* ]] || { echo "cosign flags" >&2; exit 4; }
    [[ -z "${STUB_COSIGN_FAIL:-}" ]] || { echo "Error: no matching signatures" >&2; exit 1; }
    # One envelope for each version of STUB_COSIGN_VERSIONS (a JSON array, oldest first), as cosign prints one for each attestation of the root. A null
    # version gives a statement with no version. The default is the single version 1/2.
    versions="${STUB_COSIGN_VERSIONS:-[${STUB_COSIGN_VERSION:-{\"epoch\":1,\"counter\":2\}}]}"
    for v in $(jq -c '.[]' <<<"$versions"); do
      payload="$(jq -nc --argjson s "${STUB_COSIGN_SUBJECTS:-{\}}" --argjson v "$v" '{_type: "https://in-toto.io/Statement/v1", subject: ($s | to_entries | map({name: ("bundles/dev-cell-1/" + .key), digest: {sha256: .value}})), predicate: (if $v == null then {} else {version: $v} end)}' | base64 | tr -d '\n')"
      printf '{"payloadType":"application/vnd.in-toto+json","payload":"%s","signatures":[{"sig":"x"}]}\n' "$payload"
    done ;;
  "run bundlectl -- push "*)
    [[ -z "${STUB_PUSH_FAIL:-}" ]] || fail "push failed"
    echo "$comps" ;;
  "run bundlectl -- push-root "*)
    cat >"$STUB_STATE/push-root.stdin"
    printf '{"digest":"%s","manifest":"bWFuaWZlc3Q="}\n' "${STUB_ROOT_PUSHED:-$root}" ;;
  "run bundlectl -- attach "*)
    [[ -z "${STUB_ATTACH_FAIL:-}" ]] || fail "attach failed"
    echo '{"root":"x","referrer":"y","repository":"z"}' ;;
  "run mgmt -- bundle sign "*)
    cat >"$STUB_STATE/sign.stdin"
    [[ -z "${STUB_SIGN_FAIL:-}" ]] || fail "bundle_open"
    jq -nc --arg op "$opid" --arg root "$root" '{opId: $op, version: {epoch: 1, counter: 3}, contentSHA256: "ee", rootDigest: $root,
      envelope: {payloadType: "application/vnd.in-toto+json", payload: "e30=", signatures: []},
      sigstoreBundle: {mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", dsseEnvelope: {payload: "e30="}, marker: "public"}}' ;;
  "run mgmt -- bundle cosign "*)
    jq -nc --arg op "$opid" --arg root "$root" '{opId: $op, version: {epoch: 1, counter: 3}, rootDigest: $root,
      envelope: {}, sigstoreBundle: {mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", marker: "rotated"}}' ;;
  "run mgmt -- bundle get "*)
    n=$(($(cat "$STUB_STATE/get-count" 2>/dev/null || echo 0) + 1)); echo "$n" >"$STUB_STATE/get-count"
    read -r -a seq <<<"${STUB_OUTCOMES:-applied}"
    i=$((n - 1)); ((i < ${#seq[@]})) || i=$((${#seq[@]} - 1))
    out="${seq[$i]}"; op="$opid"; [[ -z "${STUB_OTHER_OP:-}" ]] || op=dddddddddddddddddddddddddddddddd
    jq -nc --arg op "$op" --arg root "$root" --arg out "$out" --argjson comps "$comps" '{opId: $op, version: {epoch: 1, counter: 3},
      contentSHA256: "ee", rootDigest: $root, components: $comps, served: true}
      + (if $out == "open" then {} elif $out == "rolled_back" then {result: {opId: $op, outcome: $out, reason: "unhealthy", detail: "apps-demo:Synced/Degraded"}}
         else {result: {opId: $op, outcome: $out}} end)' ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

// bundleKubectl logs its call and answers what bundle.sh asks. get configmap bundle-state prints STUB_STATE_JSON, or nothing when
// the ConfigMap is absent, and STUB_STATE_FAIL makes the call fail. create -f - and apply -f - keep their standard input. A
// port-forward sleeps. get applications prints STUB_APPS_OLD_JSON for the first STUB_APPS_OLD_POLLS calls, and then STUB_APPS_JSON.
const bundleKubectl = `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
case " $* " in
  *" port-forward "*) exec sleep 30 ;;
  *" patch application "*) [[ -z "${STUB_PATCH_FAIL:-}" ]] || { echo "error: patch failed" >&2; exit 1; }; exit 0 ;;
  *" annotate application "*) [[ -z "${STUB_ANNOTATE_FAIL:-}" ]] || { echo "error: annotate failed" >&2; exit 1; }; exit 0 ;;
  *" create -f - "*) cat >"$STUB_STATE/created.json"; exit 0 ;;
  *" apply "*" -f - "*) n=$(($(cat "$STUB_STATE/apply-count" 2>/dev/null || echo 0) + 1)); echo "$n" >"$STUB_STATE/apply-count"; cat >"$STUB_STATE/applied-$n.yaml"; exit 0 ;;
  *" get configmap bundle-state "*)
    if [[ -n "${STUB_STATE_FAIL:-}" ]]; then echo "error: connection refused" >&2; exit 1; fi
    [[ -z "${STUB_STATE_JSON:-}" ]] || printf '%s' "$STUB_STATE_JSON"
    exit 0 ;;
  *" get applications -o json "*)
    n=$(($(cat "$STUB_STATE/apps-count" 2>/dev/null || echo 0) + 1)); echo "$n" >"$STUB_STATE/apps-count"
    if ((n <= ${STUB_APPS_OLD_POLLS:-0})); then printf '%s\n' "$STUB_APPS_OLD_JSON"; else printf '%s\n' "${STUB_APPS_JSON:-}"; fi
    exit 0 ;;
esac
exit 0
`

// bundleCurl fails on its first call, as when no old port-forward holds the port, and then succeeds.
const bundleCurl = `#!/usr/bin/env bash
echo "curl $*" >>"$STUB_LOG"
if [[ ! -e "$STUB_STATE/curl-seen" ]]; then touch "$STUB_STATE/curl-seen"; exit 22; fi
exit 0
`

// bundleOras serves the manifest and the layer of the bundle that the test names, and keeps what it pushes. STUB_ORAS_BAD makes the
// manifest differ from its digest.
const bundleOras = `#!/usr/bin/env bash
echo "oras $*" >>"$STUB_LOG"
args=("$@"); out=-
for ((i = 0; i < ${#args[@]}; i++)); do [[ "${args[i]}" == --output ]] && out="${args[i+1]}"; done
ref="${args[${#args[@]}-1]}"
case "${args[0]} ${args[1]}" in
  "manifest fetch")
    name="${ref##*/}"; name="${name%%@*}"
    cat "$STUB_BUNDLES/$name.manifest.json"
    [[ -z "${STUB_ORAS_BAD:-}" ]] || printf ' ' ;;
  "blob fetch") name="${ref##*/}"; name="${name%%@*}"; cat "$STUB_BUNDLES/$name.layer.tgz"
    [[ -z "${STUB_ORAS_BAD_LAYER:-}" ]] || printf ' ' ;;
  "manifest push") cat >"$STUB_STATE/tagged.json" ;;
  *) exit 2 ;;
esac
`

// bundleRoot makes a temporary root with the scripts, the cell settings and the stubs, and one hydrated bundle for each component of
// the cluster. It returns the root and the environment of a run.
type bundleRoot struct {
	t      *testing.T
	dir    string
	log    string
	state  string
	extras []string
}

func newBundleRoot(t *testing.T, clusters ...string) *bundleRoot {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "tar")
	r := &bundleRoot{t: t, dir: t.TempDir()}
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, r.dir, d)
	}
	r.log = filepath.Join(r.dir, "calls.log")
	r.state = filepath.Join(r.dir, "state")
	bin := filepath.Join(r.dir, "bin")
	for _, d := range []string{bin, r.state, filepath.Join(r.dir, "bundles")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"mise": bundleMise, "kubectl": bundleKubectl, "curl": bundleCurl, "oras": bundleOras} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range clusters {
		r.hydrate(c)
	}
	r.age()
	return r
}

// age gives the inputs of a render (scripts, cell settings, components) a time three hours back and the hydrated bundles a time one hour back,
// so a test makes a build stale by touching one input, and no test depends on the order of writes within one second.
func (r *bundleRoot) age() {
	r.t.Helper()
	set := func(root string, at time.Time, only string) {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && (only == "" || filepath.Base(path) == only) {
				_ = os.Chtimes(path, at, at)
			}
			return nil
		})
	}
	for _, d := range []string{"scripts", "cells", "harness", "components"} {
		set(filepath.Join(r.dir, d), time.Now().Add(-3*time.Hour), "")
	}
	set(filepath.Join(r.dir, "build"), time.Now().Add(-time.Hour), "manifests.yaml")
}

// touch makes a file of the root newer than the hydrated bundles, and makes it when it is absent. The content of an existing file stays.
func (r *bundleRoot) touch(rel string) {
	r.t.Helper()
	path := filepath.Join(r.dir, rel)
	if _, err := os.Stat(path); err == nil {
		now := time.Now()
		if err := os.Chtimes(path, now, now); err != nil {
			r.t.Fatal(err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed\n"), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// hydrate writes the hydrated bundles of a cluster, as scripts/hydrate.sh leaves them, and its root.json, as publish.sh leaves it.
func (r *bundleRoot) hydrate(cluster string) {
	r.t.Helper()
	list := exec.Command("bash", "-c", `source "$1"; printf '%s\n' "${COMPONENTS[@]}"`, "_", filepath.Join(r.dir, "scripts", "lib.sh"))
	list.Env = append(os.Environ(), "CELL="+cluster, "POC_BUILD_ROOT="+filepath.Join(r.dir, "build"))
	out, err := list.Output()
	if err != nil {
		r.t.Fatalf("read COMPONENTS of %s: %v", cluster, err)
	}
	for _, e := range strings.Fields(string(out)) {
		dir := filepath.Join(r.dir, "build", cluster, "bundles", strings.SplitN(e, ":", 2)[0])
		if err := os.MkdirAll(dir, 0o755); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifests.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x, namespace: default}\n"), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	root := `{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","manifest":"Ym9vdA==","components":{"argocd":"` + stubArgocdD + `","cell-system":"` + stubCellSysD + `"}}`
	if err := os.WriteFile(filepath.Join(r.dir, "build", cluster, "root.json"), []byte(root+"\n"), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// run runs a script of the root with the given variables and returns standard output, standard error, the log of the stub calls and
// the error.
func (r *bundleRoot) run(script string, env []string, args ...string) (string, string, string, error) {
	r.t.Helper()
	cmd := exec.Command(filepath.Join(r.dir, "scripts", script), args...)
	cmd.Env = append([]string{"PATH=" + filepath.Join(r.dir, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=dev-cell-1", "POC_BUILD_ROOT=" + filepath.Join(r.dir, "build"), "STUB_LOG=" + r.log, "STUB_STATE=" + r.state,
		"STUB_BUNDLES=" + filepath.Join(r.dir, "bundles"), "BUNDLE_WAIT_POLL=0.05", "BUNDLE_WAIT_SECONDS=20"}, append(r.extras, env...)...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	logData, _ := os.ReadFile(r.log)
	return out.String(), errOut.String(), string(logData), err
}

func (r *bundleRoot) file(path ...string) string {
	b, err := os.ReadFile(filepath.Join(append([]string{r.dir}, path...)...))
	if err != nil {
		return ""
	}
	return string(b)
}

// callIndex returns the index of the first line of the log that holds all of the parts, or -1.
func callIndex(log string, parts ...string) int {
	for i, l := range strings.Split(log, "\n") {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(l, p)
		}
		if ok {
			return i
		}
	}
	return -1
}

func calls(log, prefix string) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

// TestBundleAttachesSigstore: publish pushes the components to the mirror, signs the set with the components on standard input, writes
// the sigstoreBundle (public data) to build/<target>/sigstore-<counter>.json, pushes the root to the mirror, and attaches the file to
// the root with bundlectl attach, under the loopback mirror address. oras never attaches. A failure of the signature stops the publish
// before any root or attach, and a root that differs from the signed root stops it before the attach.
func TestBundleAttachesSigstore(t *testing.T) {
	r := newBundleRoot(t, "dev-cell-1")
	out, errOut, log, err := r.run("bundle.sh", nil, "publish", "--target", "dev-cell-1")
	if err != nil {
		t.Fatalf("publish failed: %v\n%s\n%s", err, errOut, log)
	}
	order := []int{
		callIndex(log, "run hostsvc -- facts --registry"),
		callIndex(log, "run bundlectl -- push --target dev-cell-1 --registry 127.0.0.1:5001"),
		callIndex(log, "run mgmt -- bundle sign --target dev-cell-1 | CELL=management"),
		callIndex(log, "run bundlectl -- push-root --role cell --target dev-cell-1", "--registry 127.0.0.1:5001"),
		callIndex(log, "run bundlectl -- attach --target dev-cell-1 --digest "+stubRootSHA, "--registry 127.0.0.1:5001"),
	}
	if !slices.IsSorted(order) || order[0] < 0 || slices.Contains(order, -1) {
		t.Fatalf("calls in the wrong order or missing (indexes %v):\n%s", order, log)
	}
	if strings.Contains(log, "oras") {
		t.Errorf("publish.sh called oras:\n%s", log)
	}
	file := filepath.Join("build", "dev-cell-1", "sigstore-3.json")
	want := `{"dsseEnvelope":{"payload":"e30="},"marker":"public","mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`
	var got, exp any
	if json.Unmarshal([]byte(r.file(file)), &got) != nil || json.Unmarshal([]byte(want), &exp) != nil || fmt.Sprint(got) != fmt.Sprint(exp) {
		t.Errorf("%s holds %q, want the sigstoreBundle %s", file, r.file(file), want)
	}
	if attach := calls(log, "mise run bundlectl -- attach")[0]; !strings.Contains(attach, "--bundle "+filepath.Join(r.dir, file)) {
		t.Errorf("attach call %q does not name the file %s", attach, file)
	}
	// The set that goes to mgmtd and to push-root is the answer of bundlectl push, on standard input.
	for _, f := range []string{"sign.stdin", "push-root.stdin"} {
		var comps []map[string]any
		if err := json.Unmarshal([]byte(r.file("state", f)), &comps); err != nil || len(comps) != 2 || comps[0]["name"] != "argocd" {
			t.Errorf("%s holds %q, want the components of bundlectl push", f, r.file("state", f))
		}
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &line); err != nil || line["opId"] != stubOpID || line["rootDigest"] != stubRootSHA || line["target"] != "dev-cell-1" {
		t.Errorf("publish printed %q, want one JSON line with the target, the opId and the rootDigest", out)
	}
	if strings.Contains(out, "dsseEnvelope") || strings.Contains(out, "payload") {
		t.Errorf("publish printed the envelope: %q", out)
	}

	t.Run("a refused signature stops before the root", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		_, errOut, log, err := r.run("bundle.sh", []string{"STUB_SIGN_FAIL=1"}, "publish", "--target", "dev-cell-1")
		if err == nil || !strings.Contains(errOut, "bundle_open") {
			t.Fatalf("err %v, stderr %q, want a failure that names the reason", err, errOut)
		}
		if strings.Contains(log, "push-root") || strings.Contains(log, "attach") {
			t.Errorf("a root or an attach after a failed signature:\n%s", log)
		}
	})
	t.Run("a root that differs from the signed root is not attached", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		_, errOut, log, err := r.run("bundle.sh", []string{"STUB_ROOT_PUSHED=sha256:" + strings.Repeat("9", 64)}, "publish", "--target", "dev-cell-1")
		if err == nil || !strings.Contains(errOut, "root") {
			t.Fatalf("err %v, stderr %q", err, errOut)
		}
		if strings.Contains(log, "attach") {
			t.Errorf("attach after a root mismatch:\n%s", log)
		}
	})
	t.Run("a failed push of the components stops before the signature", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		_, _, log, err := r.run("bundle.sh", []string{"STUB_PUSH_FAIL=1"}, "publish", "--target", "dev-cell-1")
		if err == nil || strings.Contains(log, "bundle sign") {
			t.Fatalf("err %v, calls:\n%s", err, log)
		}
	})
	t.Run("a missing mirror address stops the publish", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		_, _, log, err := r.run("bundle.sh", []string{"STUB_NO_MIRROR=1"}, "publish", "--target", "dev-cell-1")
		if err == nil || strings.Contains(log, "bundlectl") {
			t.Fatalf("err %v, calls:\n%s", err, log)
		}
	})
	t.Run("a mirror that is no loopback address stops the publish", func(t *testing.T) {
		for _, host := range []string{"10.0.0.5:5001", "evil.example:5001", "127.0.0.1"} {
			r := newBundleRoot(t, "dev-cell-1")
			_, errOut, log, err := r.run("bundle.sh", []string{"STUB_MIRROR_HOST=" + host}, "publish", "--target", "dev-cell-1")
			if err == nil || !strings.Contains(errOut, "loopback") || strings.Contains(log, "bundlectl") {
				t.Errorf("mirror %s: err %v, stderr %q, calls:\n%s", host, err, errOut, log)
			}
		}
	})
	t.Run("cosign attaches the bundle that mgmtd holds now, under the key of the plane", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		out, errOut, log, err := r.run("bundle.sh", nil, "cosign", "--target", "dev-cell-1")
		if err != nil {
			t.Fatalf("cosign failed: %v\n%s\n%s", err, errOut, log)
		}
		if !strings.Contains(r.file("build", "dev-cell-1", "sigstore-3.json"), `"marker":"rotated"`) {
			t.Errorf("sigstore-3.json is %q, want the bundle of mgmt bundle cosign", r.file("build", "dev-cell-1", "sigstore-3.json"))
		}
		if callIndex(log, "run mgmt -- bundle cosign --target dev-cell-1 | CELL=management") < 0 || callIndex(log, "run bundlectl -- attach --target dev-cell-1 --digest "+stubRootSHA) < 0 {
			t.Errorf("cosign calls:\n%s", log)
		}
		if strings.Contains(log, "bundle sign") || strings.Contains(log, "push-root") || !strings.Contains(out, stubRootSHA) {
			t.Errorf("cosign signed or pushed a root, or printed no digest: %q\n%s", out, log)
		}
	})
}

// TestBundleWaitOutcomes: with --wait, publish polls mgmt bundle get until the operation has a result. It exits 0 for applied and
// already_applied, and writes published.env (one name=digest line for each component, and root=<digest>). It exits 1 for rolled_back,
// refused and expired, for another operation, and for a deadline, and then it writes no published.env.
func TestBundleWaitOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		outcomes string
		env      []string
		ok       bool
		polls    int
		want     string
	}{
		{name: "applied at once", outcomes: "applied", ok: true, polls: 1},
		{name: "applied after two polls", outcomes: "open open applied", ok: true, polls: 3},
		{name: "already applied", outcomes: "already_applied", ok: true, polls: 1},
		{name: "rolled back", outcomes: "open rolled_back", polls: 2, want: "apps-demo:Synced/Degraded"},
		{name: "refused", outcomes: "refused", polls: 1, want: "refused"},
		{name: "expired", outcomes: "open expired", polls: 2, want: "expired"},
		{name: "superseded by another operation", outcomes: "applied", env: []string{"STUB_OTHER_OP=1"}, polls: 1, want: "another"},
		{name: "deadline", outcomes: "open", env: []string{"BUNDLE_WAIT_SECONDS=1"}, polls: -1, want: "timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newBundleRoot(t, "dev-cell-1")
			out, errOut, log, err := r.run("bundle.sh", append([]string{"STUB_OUTCOMES=" + tc.outcomes}, tc.env...), "publish", "--target", "dev-cell-1", "--wait")
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v\nstdout %s\nstderr %s", err, tc.ok, out, errOut)
			}
			if n := len(calls(log, "mise run mgmt -- bundle get")); tc.polls >= 0 && n != tc.polls || tc.polls < 0 && n < 2 {
				t.Errorf("%d polls, want %d\n%s", n, tc.polls, log)
			}
			published := r.file("build", "dev-cell-1", "published.env")
			if tc.ok {
				want := "argocd=" + stubArgocdD + "\ncell-system=" + stubCellSysD + "\nroot=" + stubRootSHA + "\n"
				if published != want {
					t.Errorf("published.env is %q, want %q", published, want)
				}
				if !strings.Contains(out, `"outcome":"`+strings.Fields(tc.outcomes)[len(strings.Fields(tc.outcomes))-1]+`"`) {
					t.Errorf("stdout lacks the outcome: %q", out)
				}
				return
			}
			if published != "" {
				t.Errorf("published.env exists after a failure: %q", published)
			}
			if !strings.Contains(out+errOut, tc.want) {
				t.Errorf("output %q lacks %q", out+errOut, tc.want)
			}
		})
	}

	// Two targets are signed first and waited for after, so the cells apply at the same time.
	t.Run("two targets", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1", "dev-cell-2")
		_, errOut, log, err := r.run("bundle.sh", nil, "publish", "--target", "dev-cell-1", "--target", "dev-cell-2", "--wait")
		if err != nil {
			t.Fatalf("publish failed: %v\n%s\n%s", err, errOut, log)
		}
		last := max(callIndex(log, "bundle sign --target dev-cell-1"), callIndex(log, "bundle sign --target dev-cell-2"))
		first := min(callIndex(log, "bundle get --target dev-cell-1"), callIndex(log, "bundle get --target dev-cell-2"))
		if last < 0 || first < 0 || first < last {
			t.Errorf("a wait starts before the last signature (%d, %d):\n%s", first, last, log)
		}
		for _, c := range []string{"dev-cell-1", "dev-cell-2"} {
			if r.file("build", c, "published.env") == "" {
				t.Errorf("no published.env for %s", c)
			}
		}
	})
}

// TestBundleRefusesOpenRole: management has role open, and keeps the harness publish. bundle.sh stops at once, names mise run
// cell:publish, and signs nothing. An unknown target stops too, and publish needs a target.
func TestBundleRefusesOpenRole(t *testing.T) {
	r := newBundleRoot(t, "dev-cell-1")
	for _, sub := range []string{"publish", "repair", "cosign"} {
		out, errOut, log, err := r.run("bundle.sh", nil, sub, "--target", "management")
		if err == nil || !strings.Contains(out+errOut, "cell:publish") || !strings.Contains(out+errOut, "role open") {
			t.Errorf("%s: err %v, output %q, want a refusal that names role open and cell:publish", sub, err, out+errOut)
		}
		if strings.Contains(log, "bundlectl") || strings.Contains(log, "bundle sign") || strings.Contains(log, "kubectl") {
			t.Errorf("%s ran a command:\n%s", sub, log)
		}
	}
	// Another target in the same call stops the whole call before the first signature.
	_, _, log, err := r.run("bundle.sh", nil, "publish", "--target", "dev-cell-1", "--target", "management")
	if err == nil || strings.Contains(log, "bundle sign") {
		t.Errorf("a call with management signed a set: err %v\n%s", err, log)
	}
	for _, args := range [][]string{{"publish"}, {"publish", "--target", "nope"}, {"nope", "--target", "dev-cell-1"}, {"get"}} {
		if _, _, log, err := r.run("bundle.sh", nil, args...); err == nil || strings.Contains(log, "bundle sign") {
			t.Errorf("bundle.sh %v: err %v\n%s", args, err, log)
		}
	}
	t.Run("get prints the answer of mgmtd for the target", func(t *testing.T) {
		out, _, log, err := r.run("bundle.sh", []string{"STUB_OUTCOMES=applied"}, "get", "--target", "dev-cell-1")
		if err != nil || !strings.Contains(out, `"outcome":"applied"`) || callIndex(log, "run mgmt -- bundle get --target dev-cell-1 | CELL=management") < 0 {
			t.Errorf("err %v, output %q, calls:\n%s", err, out, log)
		}
	})
}

// packBundle writes the manifest and the layer of a bundle (a gzip tar with the files at its root) into the stub directory and returns
// the digest of the manifest.
func packBundle(t *testing.T, r *bundleRoot, name string, files map[string]string) string {
	t.Helper()
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	tw := tar.NewWriter(gz)
	for _, f := range slices.Sorted(maps.Keys(files)) {
		if err := tw.WriteHeader(&tar.Header{Name: f, Mode: 0o644, Size: int64(len(files[f]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(files[f])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(layer.Bytes())
	manifest := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:` + hex.EncodeToString(sum[:]) + `","size":1}]}`
	msum := sha256.Sum256([]byte(manifest))
	for f, b := range map[string][]byte{name + ".manifest.json": []byte(manifest), name + ".layer.tgz": layer.Bytes()} {
		if err := os.WriteFile(filepath.Join(r.dir, "bundles", f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return "sha256:" + hex.EncodeToString(msum[:])
}

func appsJSON(revisions map[string]string, health string) string {
	var items []string
	for _, name := range []string{"argocd", "cell-system", "network-policy", "root"} {
		items = append(items, fmt.Sprintf(`{"metadata":{"name":%q},"status":{"sync":{"status":"Synced","revision":%q},"health":{"status":%q}}}`, name, revisions[name], health))
	}
	return `{"items":[` + strings.Join(items, ",") + `]}`
}

// repairFixture is a good root with two bundles that the repair applies, as the mirror (or the store) holds them.
type repairFixture struct {
	argocd, cellSys, netpol, root string
	rootManifest                  []byte
	want                          map[string]string
	subjects                      string
}

func newRepairFixture(t *testing.T, r *bundleRoot) repairFixture {
	t.Helper()
	f := repairFixture{netpol: "sha256:" + strings.Repeat("7", 64)}
	f.argocd = packBundle(t, r, "argocd", map[string]string{"manifests.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: argocd-marker, namespace: argocd}\n"})
	f.cellSys = packBundle(t, r, "cell-system", map[string]string{"manifests.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: store-marker, namespace: cell-system}\n"})
	app := func(name, digest string) string {
		return "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata: {name: " + name + ", namespace: argocd}\nspec:\n  source:\n    targetRevision: " + digest + "\n"
	}
	f.root = packBundle(t, r, "root", map[string]string{"argocd.yaml": app("argocd", f.argocd), "cell-system.yaml": app("cell-system", f.cellSys), "network-policy.yaml": app("network-policy", f.netpol)})
	var err error
	if f.rootManifest, err = os.ReadFile(filepath.Join(r.dir, "bundles", "root.manifest.json")); err != nil {
		t.Fatal(err)
	}
	f.want = map[string]string{"argocd": f.argocd, "cell-system": f.cellSys, "network-policy": f.netpol, "root": f.root}
	hexOf := func(d string) string { return strings.TrimPrefix(d, "sha256:") }
	f.subjects = fmt.Sprintf(`{"root":%q,"argocd":%q,"cell-system":%q,"network-policy":%q}`, hexOf(f.root), hexOf(f.argocd), hexOf(f.cellSys), hexOf(f.netpol))
	return f
}

// state returns a state ConfigMap whose good[0] names the root. Its component digests are wrong on purpose: the repair takes them from the root layer.
func (f repairFixture) state(goods ...any) string {
	if len(goods) == 0 {
		lie := "sha256:" + strings.Repeat("6", 64)
		goods = []any{map[string]any{"version": map[string]any{"epoch": 1, "counter": 2}, "contentSHA256": "aa", "at": "2026-11-18T00:00:00Z",
			"root":       map[string]any{"digest": f.root, "manifest": base64.StdEncoding.EncodeToString(f.rootManifest)},
			"components": map[string]string{"argocd": lie, "cell-system": lie, "network-policy": lie}}}
	}
	b, _ := json.Marshal(map[string]any{"source": "signed", "state": "rolled_back", "version": map[string]any{"epoch": 1, "counter": 3}, "good": goods})
	return string(b)
}

func (f repairFixture) env() []string {
	stale := map[string]string{"argocd": f.argocd, "cell-system": "sha256:" + strings.Repeat("6", 64), "network-policy": f.netpol, "root": "sha256:" + strings.Repeat("6", 64)}
	return []string{"STUB_STATE_JSON=" + f.state(), "STUB_COSIGN_SUBJECTS=" + f.subjects, "STUB_APPS_JSON=" + appsJSON(f.want, "Healthy"),
		"STUB_APPS_OLD_JSON=" + appsJSON(stale, "Healthy"), "STUB_APPS_OLD_POLLS=2"}
}

// TestBundleRepairOrder: repair trusts only what it verifies. A good root that a signed set made must verify offline with cosign against the
// current public key of mgmtd, and its subject must be the root digest. The digests of the bundles come from the root layer, and never from
// the state. Then the repair runs in this order: put the root back under the tag current through the loopback forward, pin the Application
// cell-system at its good digest, apply argocd and cell-system server side with --force-conflicts, delete the pod of the store, refresh root,
// and wait until every Application of the good root is Synced and Healthy at its digest.
func TestBundleRepairOrder(t *testing.T) {
	r := newBundleRoot(t, "dev-cell-1")
	f := newRepairFixture(t, r)
	out, errOut, log, err := r.run("bundle.sh", f.env(), "repair", "--target", "dev-cell-1")
	if err != nil {
		t.Fatalf("repair failed: %v\n%s\n%s\n%s", err, out, errOut, log)
	}
	idx := map[string]int{
		"state":   callIndex(log, "kubectl --context kind-dev-cell-1", "-n cell-ops-system get configmap bundle-state"),
		"pubkey":  callIndex(log, "run mgmt -- pubkey | CELL=management"),
		"cosign":  callIndex(log, "x -- cosign verify-attestation", "--key ", "--insecure-ignore-tlog=true", "--allow-http-registry", "--type https://cell.poc.internal/bundle-set/v1", "127.0.0.1:5001/bundles/dev-cell-1/root@"+f.root),
		"tag":     callIndex(log, "oras manifest push", "--plain-http", "127.0.0.1:", "/bundles/root:current"),
		"patch":   callIndex(log, "-n argocd patch application cell-system --type merge", `"targetRevision":"`+f.cellSys+`"`),
		"apply1":  callIndex(log, "kubectl --context kind-dev-cell-1 apply --server-side --force-conflicts -f -"),
		"delete":  callIndex(log, "-n cell-system delete pod bundle-store-0"),
		"refresh": callIndex(log, "-n argocd annotate application root argocd.argoproj.io/refresh=hard"),
		"wait":    callIndex(log, "-n argocd get applications -o json"),
	}
	lastApply := -1
	for i, l := range strings.Split(log, "\n") {
		if strings.Contains(l, " apply --server-side --force-conflicts -f -") {
			lastApply = i
		}
	}
	order := []int{idx["state"], idx["pubkey"], idx["cosign"], idx["tag"], idx["patch"], idx["apply1"], lastApply, idx["delete"], idx["refresh"], idx["wait"]}
	if slices.Contains(order, -1) || !slices.IsSorted(order) {
		t.Fatalf("the repair does not run read, verify, tag, pin, apply, delete pod, refresh, wait in this order (%v, last apply %d):\n%s", idx, lastApply, log)
	}
	if n := len(calls(log, "kubectl --context kind-dev-cell-1 -n argocd get applications")); n != 3 {
		t.Errorf("%d reads of the Applications, want 3 (two stale and one current)", n)
	}
	if applies := calls(log, "kubectl --context kind-dev-cell-1 apply "); len(applies) != 2 {
		t.Fatalf("%d applies, want one for argocd and one for cell-system:\n%s", len(applies), log)
	}
	if !strings.Contains(r.file("state", "applied-1.yaml"), "argocd-marker") || !strings.Contains(r.file("state", "applied-2.yaml"), "store-marker") {
		t.Errorf("the applies hold %q then %q, want argocd then cell-system", r.file("state", "applied-1.yaml"), r.file("state", "applied-2.yaml"))
	}
	// The state names other digests than the root layer. The fetches use the digests of the layer.
	for _, l := range calls(log, "oras manifest fetch") {
		if !strings.Contains(l, "127.0.0.1:5001/bundles/dev-cell-1/") {
			t.Errorf("a fetch outside the mirror repository of the target: %q", l)
		}
	}
	for _, want := range []string{"/argocd@" + f.argocd, "/cell-system@" + f.cellSys} {
		if callIndex(log, "oras manifest fetch", want) < 0 {
			t.Errorf("no fetch of %s:\n%s", want, log)
		}
	}
	if strings.Contains(log, strings.Repeat("6", 64)) && callIndex(log, "oras", strings.Repeat("6", 64)) >= 0 {
		t.Errorf("a fetch used a digest from the state:\n%s", log)
	}
	if got := r.file("state", "tagged.json"); got != string(f.rootManifest) {
		t.Errorf("the tag holds %q, want the verified root manifest %q", got, f.rootManifest)
	}
	pf := calls(log, "kubectl --context kind-dev-cell-1 -n cell-system port-forward pod/bundle-store-0 ")
	if len(pf) != 1 || !strings.HasSuffix(pf[0], ":5001") {
		t.Errorf("the tag does not go through the loopback forward of the pod: %v", pf)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &line); err != nil || strings.Count(strings.TrimSpace(out), "\n") != 0 || line["root"] != f.root || line["target"] != "dev-cell-1" {
		t.Errorf("repair printed %q, want one JSON line with the target and the root", out)
	}

	noChange := func(t *testing.T, log string) {
		t.Helper()
		for _, bad := range []string{" apply ", "oras manifest push", " patch application", " delete pod"} {
			if strings.Contains(log, bad) {
				t.Errorf("the repair changed the cluster (%q):\n%s", bad, log)
			}
		}
	}
	// Each case below fails one check. The mutation that removes the check makes the repair apply what it should refuse.
	for name, tc := range map[string]struct {
		env  func(f repairFixture) []string
		want string
	}{
		"a root that cosign does not verify": {func(f repairFixture) []string { return append(f.env(), "STUB_COSIGN_FAIL=1") }, "no matching signatures"},
		"a verified root older than the record of good[0]": {func(f repairFixture) []string {
			return append(f.env(), `STUB_COSIGN_VERSION={"epoch":1,"counter":1}`)
		}, "--allow-older"},
		"a verified root of an older epoch": {func(f repairFixture) []string { return append(f.env(), `STUB_COSIGN_VERSION={"epoch":0,"counter":9}`) }, "older"},
		"a verified root for another digest": {func(f repairFixture) []string {
			return append(f.env(), "STUB_COSIGN_SUBJECTS="+strings.Replace(f.subjects, strings.TrimPrefix(f.root, "sha256:"), strings.Repeat("9", 64), 1))
		}, "subject"},
		"a component that the signature does not name": {func(f repairFixture) []string {
			return append(f.env(), "STUB_COSIGN_SUBJECTS="+strings.Replace(f.subjects, strings.TrimPrefix(f.cellSys, "sha256:"), strings.Repeat("9", 64), 1))
		}, "cell-system"},
		"a root manifest that differs from its digest": {func(f repairFixture) []string { return append(f.env(), "STUB_ORAS_BAD=1") }, "digest"},
		"a layer that differs from its digest":         {func(f repairFixture) []string { return append(f.env(), "STUB_ORAS_BAD_LAYER=1") }, "digest"},
		"no good root": {func(f repairFixture) []string {
			return append(f.env(), `STUB_STATE_JSON={"source":"signed","good":[]}`)
		}, "good"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newBundleRoot(t, "dev-cell-1")
			f := newRepairFixture(t, r)
			out, errOut, log, err := r.run("bundle.sh", tc.env(f), "repair", "--target", "dev-cell-1")
			if err == nil || !strings.Contains(out+errOut, tc.want) {
				t.Errorf("err %v, output %q, want a failure that names %q", err, out+errOut, tc.want)
			}
			noChange(t, log)
		})
	}

	t.Run("a bootstrap root is checked against root.json and fetched from the store", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		f := newRepairFixture(t, r)
		rootJSON := `{"digest":"` + f.root + `","manifest":"x","components":{}}`
		if err := os.WriteFile(filepath.Join(r.dir, "build", "dev-cell-1", "root.json"), []byte(rootJSON), 0o644); err != nil {
			t.Fatal(err)
		}
		out, errOut, log, err := r.run("bundle.sh", append(f.env(), "STUB_COSIGN_FAIL=1"), "repair", "--target", "dev-cell-1")
		if err != nil {
			t.Fatalf("repair failed: %v\n%s\n%s\n%s", err, out, errOut, log)
		}
		if strings.Contains(log, "cosign") {
			t.Errorf("a bootstrap root went through cosign:\n%s", log)
		}
		for _, l := range calls(log, "oras manifest fetch") {
			if !strings.Contains(l, "127.0.0.1:5052/bundles/") || strings.Contains(l, "/dev-cell-1/") {
				t.Errorf("a bootstrap bundle is not read from the store through the forward: %q", l)
			}
		}
		if callIndex(log, "-n argocd patch application cell-system") < 0 || len(calls(log, "kubectl --context kind-dev-cell-1 apply ")) != 2 {
			t.Errorf("the bootstrap repair did not pin and apply:\n%s", log)
		}
	})
	t.Run("a root that is neither the bootstrap root nor signed", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		f := newRepairFixture(t, r)
		rootJSON := `{"digest":"sha256:` + strings.Repeat("1", 64) + `","manifest":"x","components":{}}`
		if err := os.WriteFile(filepath.Join(r.dir, "build", "dev-cell-1", "root.json"), []byte(rootJSON), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, log, err := r.run("bundle.sh", append(f.env(), "STUB_COSIGN_FAIL=1"), "repair", "--target", "dev-cell-1")
		if err == nil {
			t.Error("a root that matches no anchor was repaired")
		}
		noChange(t, log)
	})
	t.Run("an older root is applied with --allow-older, and a newer or equal one needs no flag", func(t *testing.T) {
		for _, tc := range []struct {
			version string
			args    []string
			ok      bool
		}{
			{`{"epoch":1,"counter":1}`, []string{"--allow-older"}, true},
			{`{"epoch":1,"counter":2}`, nil, true},
			{`{"epoch":1,"counter":5}`, nil, true},
			{`{"epoch":2,"counter":1}`, nil, true},
			{`{"epoch":1,"counter":1}`, nil, false},
		} {
			r := newBundleRoot(t, "dev-cell-1")
			f := newRepairFixture(t, r)
			out, errOut, log, err := r.run("bundle.sh", append(f.env(), "STUB_COSIGN_VERSION="+tc.version), append([]string{"repair", "--target", "dev-cell-1"}, tc.args...)...)
			if (err == nil) != tc.ok {
				t.Errorf("version %s args %v: err %v, want ok=%v\n%s%s", tc.version, tc.args, err, tc.ok, out, errOut)
			}
			if !tc.ok {
				noChange(t, log)
				if !strings.Contains(errOut, "older") || !strings.Contains(errOut, "1/2") {
					t.Errorf("the refusal does not say why: %q", errOut)
				}
			}
		}
		// The flag belongs to repair.
		r := newBundleRoot(t, "dev-cell-1")
		if _, _, _, err := r.run("bundle.sh", nil, "publish", "--target", "dev-cell-1", "--allow-older"); err == nil {
			t.Error("publish accepted --allow-older")
		}
	})
	// cosign prints one statement for each signed version of a root. Republishing the same content signs the same root again, so the root of good[0]
	// can carry several versions. The repair reads the one that equals the record, whatever the order cosign prints.
	t.Run("a root with several signed versions", func(t *testing.T) {
		v := func(c int) string { return fmt.Sprintf(`{"epoch":1,"counter":%d}`, c) }
		for _, tc := range []struct {
			name     string
			versions string
			record   int
			ok       bool
		}{
			{"oldest first, the record is the newest", "[" + v(5) + "," + v(6) + "]", 6, true},
			{"newest first, the record is the newest", "[" + v(6) + "," + v(5) + "]", 6, true},
			{"the record is in the middle", "[" + v(5) + "," + v(6) + "," + v(7) + "]", 6, true},
			{"every printed version is older", "[" + v(4) + "," + v(5) + "]", 6, false},
			{"a statement with no version", "[null]", 6, false},
		} {
			r := newBundleRoot(t, "dev-cell-1")
			f := newRepairFixture(t, r)
			record := map[string]any{"version": map[string]any{"epoch": 1, "counter": tc.record}, "contentSHA256": "aa",
				"root": map[string]any{"digest": f.root, "manifest": base64.StdEncoding.EncodeToString(f.rootManifest)}}
			env := append(f.env(), "STUB_STATE_JSON="+f.state(record), "STUB_COSIGN_VERSIONS="+tc.versions)
			out, errOut, log, err := r.run("bundle.sh", env, "repair", "--target", "dev-cell-1")
			if (err == nil) != tc.ok {
				t.Errorf("%s: err %v, want ok=%v\n%s%s", tc.name, err, tc.ok, out, errOut)
			}
			if !tc.ok {
				noChange(t, log)
			}
		}
	})
	t.Run("a failed pin stops the repair before the apply", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		f := newRepairFixture(t, r)
		_, errOut, log, err := r.run("bundle.sh", append(f.env(), "STUB_PATCH_FAIL=1"), "repair", "--target", "dev-cell-1")
		if err == nil || !strings.Contains(errOut, "pin") {
			t.Errorf("err %v, stderr %q, want a failure that names the pin", err, errOut)
		}
		if strings.Contains(log, " apply ") || strings.Contains(log, " delete pod") || strings.Contains(log, "refresh=hard") {
			t.Errorf("the repair went on after a failed pin:\n%s", log)
		}
	})
	t.Run("a failed refresh is reported", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		f := newRepairFixture(t, r)
		_, errOut, _, err := r.run("bundle.sh", append(f.env(), "STUB_ANNOTATE_FAIL=1"), "repair", "--target", "dev-cell-1")
		if err == nil || !strings.Contains(errOut, "refresh") {
			t.Errorf("err %v, stderr %q, want a failure that names the refresh", err, errOut)
		}
	})
	t.Run("an Application that stays off the digest fails the wait", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		f := newRepairFixture(t, r)
		bad := append(f.env(), "STUB_APPS_JSON="+appsJSON(f.want, "Degraded"), "STUB_APPS_OLD_POLLS=0", "BUNDLE_REPAIR_SECONDS=1")
		out, errOut, _, err := r.run("bundle.sh", bad, "repair", "--target", "dev-cell-1")
		if err == nil || !strings.Contains(out+errOut, "Degraded") {
			t.Errorf("err %v, output %q, want a failure that names the Application state", err, out+errOut)
		}
	})
}

// publishVariant runs publish.sh of a cluster in a temporary root, like runPublish, with the kubectl stub of bundle.sh in front. It
// returns the output, the log of the calls and the error.
func publishVariant(t *testing.T, cell string, env ...string) (string, string, error) {
	t.Helper()
	r := newBundleRoot(t, cell)
	// publish.sh stubs: bundlectl bootstrap answers with a root digest, oras pushes and finds no tag.
	if err := os.WriteFile(filepath.Join(r.dir, "bin", "mise"), []byte(publishStubs["mise"]), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "bin", "oras"), []byte(publishStubs["oras"]), 0o755); err != nil {
		t.Fatal(err)
	}
	out, errOut, log, err := r.run("publish.sh", append([]string{"CELL=" + cell}, env...))
	return out + errOut, log, err
}

// TestPublishRefusesSignedCluster: cell:publish stops in a cluster whose bundle state has source signed, because a harness publish
// would overwrite a signed root. It names mise run bundle and the break glass. A bootstrap state, no state, a cluster with role open,
// and a role that has no applier yet all go on. A state that cannot be read stops the publish too.
func TestPublishRefusesSignedCluster(t *testing.T) {
	for _, cell := range []string{"dev-cell-1", "dev-cell-2", "dev-cp"} {
		t.Run(cell, func(t *testing.T) {
			out, log, err := publishVariant(t, cell, `STUB_STATE_JSON={"source":"signed","state":"healthy"}`)
			if err == nil {
				t.Fatalf("publish.sh passed in a signed cluster:\n%s\n%s", out, log)
			}
			for _, want := range []string{"mise run bundle -- publish --target " + cell + " --wait", "BUNDLE_PUBLISH_UNSIGNED=1", "source: signed"} {
				if !strings.Contains(out, want) {
					t.Errorf("the refusal lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(log, "bundlectl") || strings.Contains(log, "port-forward") {
				t.Errorf("publish.sh changed the store before it refused:\n%s", log)
			}
			ns := map[string]string{"dev-cell-1": "cell-ops-system", "dev-cell-2": "cell-ops-system", "dev-cp": "envd-system"}[cell]
			if callIndex(log, "kubectl --context kind-"+cell+" -n "+ns+" get configmap bundle-state") < 0 {
				t.Errorf("publish.sh did not read the state in %s:\n%s", ns, log)
			}
		})
	}
	t.Run("bootstrap, absent and unreadable states", func(t *testing.T) {
		if out, log, err := publishVariant(t, "dev-cell-1", `STUB_STATE_JSON={"source":"bootstrap","state":"healthy"}`); err != nil || !strings.Contains(log, "bundlectl -- bootstrap") {
			t.Errorf("a bootstrap state: err %v\n%s\n%s", err, out, log)
		}
		if out, log, err := publishVariant(t, "dev-cell-1"); err != nil || !strings.Contains(log, "bundlectl -- bootstrap") {
			t.Errorf("no state: err %v\n%s\n%s", err, out, log)
		}
		out, log, err := publishVariant(t, "dev-cell-1", "STUB_STATE_FAIL=1")
		if err == nil || strings.Contains(log, "bundlectl") || !strings.Contains(out, "state") {
			t.Errorf("an unreadable state: err %v\n%s\n%s", err, out, log)
		}
	})
	t.Run("management has no state to read", func(t *testing.T) {
		out, log, err := publishVariant(t, "management", `STUB_STATE_JSON={"source":"signed"}`)
		if err != nil || strings.Contains(log, "get configmap bundle-state") {
			t.Errorf("err %v\n%s\n%s", err, out, log)
		}
	})
}

// TestPublishUnsignedBreakGlass: BUNDLE_PUBLISH_UNSIGNED=1 lets cell:publish go on in a signed cluster, and says in its output that the
// root is no longer signed, and which command signs it again.
func TestPublishUnsignedBreakGlass(t *testing.T) {
	out, log, err := publishVariant(t, "dev-cell-1", `STUB_STATE_JSON={"source":"signed","state":"healthy"}`, "BUNDLE_PUBLISH_UNSIGNED=1")
	if err != nil {
		t.Fatalf("publish.sh failed with the break glass: %v\n%s\n%s", err, out, log)
	}
	if !strings.Contains(log, "bundlectl -- bootstrap --role cell --target dev-cell-1") {
		t.Errorf("publish.sh did not publish:\n%s", log)
	}
	for _, want := range []string{"BUNDLE_PUBLISH_UNSIGNED", "mise run bundle -- publish --target dev-cell-1 --wait"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	// Any other value does not count.
	if _, _, err := publishVariant(t, "dev-cell-1", `STUB_STATE_JSON={"source":"signed"}`, "BUNDLE_PUBLISH_UNSIGNED=yes"); err == nil {
		t.Error("BUNDLE_PUBLISH_UNSIGNED=yes opened the break glass")
	}
}

// harnessUpPublish is the step that harness:up ends with: one publish for dev-cp and the cells, which waits until each applied the set.
const harnessUpPublish = "mise run bundle -- publish --target dev-cp --target dev-cell-1 --target dev-cell-2 --wait | CELL=dev-cell-1 LINK_ONLY= SKIP="

// TestHarnessUpPublishesTargets: harness:up ends with one signed publish that names dev-cp first and then each cell of the catalog, and waits for
// them, after the full link of management. The cells attest through the plane policies that envd holds in dev-cp, so dev-cp comes first. A failed
// publish prints itself in the hint list.
func TestHarnessUpPublishesTargets(t *testing.T) {
	root, calls := harnessRoot(t)
	log, errOut, err := runHarness(t, root, calls, "up")
	if err != nil {
		t.Fatalf("harness up failed: %v\n%s", err, errOut)
	}
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if n := len(lines); n < 2 || lines[n-1] != harnessUpPublish || lines[n-2] != "mise run cell:link | CELL=management LINK_ONLY= SKIP=" {
		t.Fatalf("calls\n%s\nwant the signed publish after the full link as the last call", log)
	}
	root, calls = harnessRoot(t)
	_, errOut, err = runHarness(t, root, calls, "up", "STUB_FAIL_ARGS=run bundle -- publish")
	if err == nil {
		t.Fatal("harness up passed with a failing publish")
	}
	hint := hintLines(t, errOut)
	if want := "mise run bundle -- publish --target dev-cp --target dev-cell-1 --target dev-cell-2 --wait"; hint[len(hint)-1] != want || len(hint) != 1 {
		t.Errorf("hint %v, want only %q", hint, want)
	}
}

// TestRestartStoreTokens: STORE_TOKENS=1 cell:restart also restarts the pods of bundle-store-0 and argocd-repo-server, which hold
// the projected store tokens, besides the harness workloads. Without the variable, it restarts only the harness workloads.
func TestRestartStoreTokens(t *testing.T) {
	setup := func(t *testing.T) (*bundleRoot, string) {
		r := newBundleRoot(t)
		dir := filepath.Join(r.dir, "build", "dev-cell-1", "bundles", "cell-identity")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifests.yaml"), []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: celld, namespace: cell-identity-system}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		kubectl := `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
case " $* " in
  *" get deployments,statefulsets "*"harness=cell-identity "*) echo deployment.apps/celld ;;
  *" get deployment.apps/celld -o json "*) echo '{"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"celld"}}}}' ;;
  *" get deployment.apps/argocd-repo-server -o json "*) echo '{"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"argocd-repo-server"}}}}' ;;
  *" get statefulset.apps/bundle-store -o json "*) echo '{"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"bundle-store"}}}}' ;;
  *" get pods -l "*" -o jsonpath"*) echo "old-uid" ;;
  *" get pods -l "*" -o json "*) echo '{"items":[{"metadata":{"uid":"new-uid"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
esac
exit 0
`
		if err := os.WriteFile(filepath.Join(r.dir, "bin", "kubectl"), []byte(kubectl), 0o755); err != nil {
			t.Fatal(err)
		}
		return r, "cell-identity"
	}
	t.Run("with STORE_TOKENS", func(t *testing.T) {
		r, only := setup(t)
		out, errOut, log, err := r.run("restart.sh", []string{"HARNESS_ONLY=" + only, "STORE_TOKENS=1"})
		if err != nil {
			t.Fatalf("restart.sh failed: %v\n%s\n%s\n%s", err, out, errOut, log)
		}
		for _, want := range []string{
			"-n cell-system delete pods -l app.kubernetes.io/name=bundle-store",
			"-n argocd delete pods -l app.kubernetes.io/name=argocd-repo-server",
			"-n cell-identity-system delete pods -l app.kubernetes.io/name=celld",
			"-n cell-system rollout status statefulset.apps/bundle-store",
			"-n argocd rollout status deployment.apps/argocd-repo-server",
		} {
			if callIndex(log, want) < 0 {
				t.Errorf("the log lacks %q:\n%s", want, log)
			}
		}
		if callIndex(log, "-n cell-system delete pods") > callIndex(log, "-n argocd delete pods") {
			t.Errorf("the store restarts after the repo server:\n%s", log)
		}
	})
	t.Run("without STORE_TOKENS", func(t *testing.T) {
		r, only := setup(t)
		_, _, log, err := r.run("restart.sh", []string{"HARNESS_ONLY=" + only})
		if err != nil || callIndex(log, "-n cell-identity-system delete pods") < 0 {
			t.Fatalf("err %v\n%s", err, log)
		}
		if strings.Contains(log, "bundle-store") || strings.Contains(log, "argocd-repo-server") {
			t.Errorf("a restart without STORE_TOKENS touched the store or the repo server:\n%s", log)
		}
	})
	t.Run("another value is no request", func(t *testing.T) {
		r, only := setup(t)
		_, _, log, _ := r.run("restart.sh", []string{"HARNESS_ONLY=" + only, "STORE_TOKENS=0"})
		if strings.Contains(log, "bundle-store") {
			t.Errorf("STORE_TOKENS=0 restarted the store:\n%s", log)
		}
	})
}

// TestMgmtBundleSignReadsStdin: mgmt -- bundle sign reads the components as JSON on standard input, so the script runs kubectl exec with -i,
// as it does for step sign. Any other command runs without it, because a stray -i would take the input of a shell loop.
func TestMgmtBundleSignReadsStdin(t *testing.T) {
	kubectl := `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
if [[ " $* " == *" get pod mgmtd-0 "* ]]; then printf True; exit 0; fi
echo '{}'
`
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"bundle", "sign", "--target", "dev-cell-1"}, true},
		{[]string{"step", "sign"}, true},
		{[]string{"bundle", "get", "--target", "dev-cell-1"}, false},
		{[]string{"status"}, false},
	} {
		logFile := filepath.Join(t.TempDir(), "log")
		_, errOut, code := runScript(t, "mgmt.sh", map[string]string{"kubectl": kubectl}, []string{"STUB_LOG=" + logFile}, tc.args...)
		if code != 0 {
			t.Fatalf("mgmt.sh %v: exit %d\n%s", tc.args, code, errOut)
		}
		b, _ := os.ReadFile(logFile)
		m := regexp.MustCompile(`(?m)^kubectl .* exec( -i)? mgmtd-0`).FindStringSubmatch(string(b))
		if m == nil || (m[1] == " -i") != tc.want {
			t.Errorf("mgmt.sh %v: the exec call is %q, want -i=%v", tc.args, m, tc.want)
		}
	}
}

// TestDependentsOfStoreChanges: a new address of the registry mirror needs the harness render of each live cell again, and new
// store tokens need a restart of each live cell with STORE_TOKENS=1.
func TestDependentsOfStoreChanges(t *testing.T) {
	for name, want := range map[string]string{
		"mirror":       "CELL=%s HARNESS_ONLY=cell-identity mise run cell:up",
		"store-tokens": "CELL=%s STORE_TOKENS=1 mise run cell:restart",
	} {
		t.Run(name, func(t *testing.T) {
			out, errOut, err := libFunc(t, "dev-cell-1", "dependents_of "+name)
			if err != nil {
				t.Fatalf("dependents_of %s: %v\n%s", name, err, errOut)
			}
			if got, exp := strings.TrimSpace(out), fmt.Sprintf(want, "dev-cell-1")+"\n"+fmt.Sprintf(want, "dev-cell-2"); got != exp {
				t.Errorf("dependents_of %s prints\n%s\nwant\n%s", name, got, exp)
			}
			out, _, err = libFunc(t, "dev-cell-1", "dependents_of "+name, "STUB_KIND=management dev-cp rogue dev-cell-2")
			if err != nil || strings.TrimSpace(out) != fmt.Sprintf(want, "dev-cell-2") {
				t.Errorf("with one live cell: err %v, output %q", err, out)
			}
		})
	}
}

// TestRuntimeObjectsBundleState: the bundle state in cell-ops-system is a runtime object that celld writes (marker celld) after
// the harness wrote it first with kubectl create (marker bundle-bootstrap), so check_harness_objects skips it in both forms.
func TestRuntimeObjectsBundleState(t *testing.T) {
	out, errOut, err := libFunc(t, "dev-cell-1", "runtime_objects cell-identity cell-ops-system ConfigMap")
	if err != nil {
		t.Fatalf("runtime_objects: %v\n%s", err, errOut)
	}
	var cases []struct {
		Names    string   `json:"names"`
		Managers []string `json:"managers"`
		Marker   struct{ Key, Value string }
	}
	if err := json.Unmarshal([]byte(out), &cases); err != nil {
		t.Fatalf("runtime_objects printed %q: %v", out, err)
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if c.Names == "^bundle-state$" {
			seen[c.Marker.Value] = true
			if c.Marker.Key != "poc.internal/made-by" {
				t.Errorf("marker key is %q", c.Marker.Key)
			}
			if len(c.Managers) == 0 || slices.Contains(c.Managers, "argocd-controller") {
				t.Errorf("managers %v", c.Managers)
			}
		}
	}
	if !seen["celld"] || !seen["bundle-bootstrap"] || len(seen) != 2 {
		t.Errorf("markers of bundle-state: %v, want celld and bundle-bootstrap\n%s", seen, out)
	}
	if !strings.Contains(out, "op-[0-9a-f]{32}") {
		t.Errorf("the operation records are no runtime objects any more: %s", out)
	}
}

// bundleHolder starts a process whose command line is bash <dir>/<script>, which the lock accepts as a harness script, and
// writes the lock directory of the cluster with its pid. It returns the pid. The process ends with the test.
func bundleHolder(t *testing.T, r *bundleRoot, script, cluster string) int {
	t.Helper()
	dir := filepath.Join(r.dir, "holder")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, script)
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\nsleep 120\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	lock := filepath.Join(r.dir, "build", "locks", cluster+".lock")
	if err := os.MkdirAll(lock, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

// TestBundleLocks: publish and repair take the cluster lock of each target before the first change, in sorted order, hold it until the
// last wait ends, and release it. A live holder (a harness script, bundle.sh included) stops them at once. A nested call that inherits
// POC_HELD_LOCKS (cell:up runs bundle.sh) passes. cosign and get change no cluster and take no lock.
func TestBundleLocks(t *testing.T) {
	both := "dev-cell-1.lock dev-cell-2.lock"
	t.Run("both locks are held from the first signature to the last wait", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1", "dev-cell-2")
		_, errOut, log, err := r.run("bundle.sh", nil, "publish", "--target", "dev-cell-2", "--target", "dev-cell-1", "--wait")
		if err != nil {
			t.Fatalf("publish failed: %v\n%s\n%s", err, errOut, log)
		}
		for _, l := range strings.Split(log, "\n") {
			if (strings.Contains(l, "bundle sign") || strings.Contains(l, "bundle get") || strings.Contains(l, "push-root")) && !strings.HasSuffix(strings.TrimSpace(l), "locks="+both) {
				t.Errorf("the call %q does not run under both locks (%s)", l, both)
			}
		}
		if left, _ := os.ReadDir(filepath.Join(r.dir, "build", "locks")); len(left) != 0 {
			t.Errorf("locks left after the run: %v", left)
		}
	})
	for _, script := range []string{"bundle.sh", "up.sh"} {
		t.Run("a live "+script+" holds dev-cell-1", func(t *testing.T) {
			r := newBundleRoot(t, "dev-cell-1", "dev-cell-2")
			pid := bundleHolder(t, r, script, "dev-cell-1")
			for _, args := range [][]string{{"publish", "--target", "dev-cell-1"}, {"publish", "--target", "dev-cell-2", "--target", "dev-cell-1"}, {"repair", "--target", "dev-cell-1"}} {
				out, errOut, log, err := r.run("bundle.sh", []string{"STUB_STATE_JSON={}"}, args...)
				if err == nil || !strings.Contains(errOut, fmt.Sprintf("process %d", pid)) {
					t.Errorf("%v: err %v, stderr %q, want a stop that names process %d", args, err, errOut, pid)
				}
				if strings.Contains(log, "bundle sign") || strings.Contains(log, "oras") || strings.Contains(log, " apply ") || out != "" {
					t.Errorf("%v changed something under a held lock:\n%s\n%s", args, out, log)
				}
				// The first target is not left locked.
				if _, err := os.Stat(filepath.Join(r.dir, "build", "locks", "dev-cell-2.lock")); err == nil {
					t.Errorf("%v left the lock of dev-cell-2", args)
				}
			}
		})
	}
	t.Run("a nested call under POC_HELD_LOCKS passes", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		bundleHolder(t, r, "up.sh", "dev-cell-1")
		_, errOut, log, err := r.run("bundle.sh", []string{"POC_HELD_LOCKS=dev-cell-1"}, "publish", "--target", "dev-cell-1", "--wait")
		if err != nil {
			t.Fatalf("the nested publish failed: %v\n%s\n%s", err, errOut, log)
		}
	})
	t.Run("cosign and get take no lock", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		bundleHolder(t, r, "up.sh", "dev-cell-1")
		for _, sub := range []string{"cosign", "get"} {
			_, errOut, log, err := r.run("bundle.sh", nil, sub, "--target", "dev-cell-1")
			if err != nil {
				t.Errorf("%s under a held lock: err %v\n%s\n%s", sub, err, errOut, log)
			}
		}
	})
}

// TestBundleWaitSharesOneDeadline: --wait has one bound for every target, so two targets that never settle fail after one bound and not two.
func TestBundleWaitSharesOneDeadline(t *testing.T) {
	r := newBundleRoot(t, "dev-cell-1", "dev-cell-2")
	start := time.Now()
	out, errOut, log, err := r.run("bundle.sh", []string{"STUB_OUTCOMES=open", "BUNDLE_WAIT_SECONDS=3", "BUNDLE_WAIT_POLL=0.2"}, "publish", "--target", "dev-cell-1", "--target", "dev-cell-2", "--wait")
	took := time.Since(start)
	if err == nil || !strings.Contains(out+errOut, "timeout") {
		t.Fatalf("err %v, output %q", err, out+errOut)
	}
	if took > 5500*time.Millisecond {
		t.Errorf("two targets waited %s with a bound of 3 s, so the bound is not shared", took)
	}
	if callIndex(log, "bundle get --target dev-cell-2") < 0 {
		t.Errorf("the second target was never polled:\n%s", log)
	}
}

// TestBundlePublishWritesBootstrapState: a publish to a cluster with no bundle state writes the bootstrap state before it pushes anything,
// and a cluster with a state gets none.
func TestBundlePublishWritesBootstrapState(t *testing.T) {
	r := newBundleRoot(t, "dev-cell-1")
	_, errOut, log, err := r.run("bundle.sh", nil, "publish", "--target", "dev-cell-1")
	if err != nil {
		t.Fatalf("publish failed: %v\n%s", err, errOut)
	}
	create, push := callIndex(log, "-n cell-ops-system create -f -"), callIndex(log, "run bundlectl -- push --target")
	if create < 0 || push < 0 || create > push {
		t.Errorf("want the bootstrap state before the first push (%d, %d):\n%s", create, push, log)
	}
	if !strings.Contains(r.file("state", "created.json"), `bundle-bootstrap`) {
		t.Errorf("the created object is %q", r.file("state", "created.json"))
	}
	r = newBundleRoot(t, "dev-cell-1")
	if _, errOut, log, err = r.run("bundle.sh", []string{`STUB_STATE_JSON={"source":"signed"}`}, "publish", "--target", "dev-cell-1"); err != nil || strings.Contains(log, " create -f -") {
		t.Errorf("a cluster with a state: err %v %s\n%s", err, errOut, log)
	}
}

// TestBundleVerifyArgs: verify reads the root digest of the state, converts the public key of mgmtd, and runs cosign verify-attestation
// offline with exactly these arguments: --key, --insecure-ignore-tlog=true, --allow-http-registry, --type of the set predicate, and the
// root on the mirror by digest. It gives cosign an empty Docker configuration, passes no --rekor-url and no --certificate-identity, and prints
// one JSON line with the signed version and the subjects. It changes no cluster and takes no lock. A state with no signed root, a root that
// cosign does not verify, and a statement with no subject for the root fail with no output.
func TestBundleVerifyArgs(t *testing.T) {
	r := newBundleRoot(t, "dev-cell-1")
	f := newRepairFixture(t, r)
	state := `{"source":"signed","state":"healthy","version":{"epoch":1,"counter":2},"root":{"digest":"` + f.root + `"},"good":[]}`
	env := []string{"STUB_STATE_JSON=" + state, "STUB_COSIGN_SUBJECTS=" + f.subjects}
	holder := bundleHolder(t, r, "up.sh", "dev-cell-1")
	out, errOut, log, err := r.run("bundle.sh", env, "verify", "--target", "dev-cell-1")
	if err != nil {
		t.Fatalf("verify failed under a held lock: %v\n%s\n%s\n%s", err, out, errOut, log)
	}
	_ = holder
	lines := calls(log, "mise x -- cosign")
	if len(lines) != 1 {
		t.Fatalf("%d cosign calls:\n%s", len(lines), log)
	}
	call := strings.TrimSpace(strings.SplitN(lines[0], " | CELL=", 2)[0])
	want := regexp.MustCompile(`^mise x -- cosign verify-attestation --key \S+ --insecure-ignore-tlog=true --allow-http-registry --type https://cell\.poc\.internal/bundle-set/v1 127\.0\.0\.1:5001/bundles/dev-cell-1/root@` + f.root + `$`)
	if !want.MatchString(call) {
		t.Errorf("the cosign call is %q", call)
	}
	for _, bad := range []string{"--rekor-url", "--certificate-identity", "--certificate-oidc-issuer", "--insecure-ignore-sct", "sign-blob"} {
		if strings.Contains(call, bad) {
			t.Errorf("the cosign call has %s", bad)
		}
	}
	if callIndex(log, "run mgmt -- pubkey | CELL=management") < 0 || callIndex(log, "run bundlectl -- pubkey-pem") < 0 {
		t.Errorf("the public key is not read from mgmtd:\n%s", log)
	}
	for _, bad := range []string{" apply ", " patch ", " delete ", "oras", "create -f"} {
		if strings.Contains(log, bad) {
			t.Errorf("verify changed something (%q):\n%s", bad, log)
		}
	}
	var res struct {
		Target   string
		Root     string
		Version  map[string]int
		Subjects []struct{ Name, Digest string }
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil || strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Fatalf("verify printed %q", out)
	}
	got := map[string]string{}
	for _, s := range res.Subjects {
		got[s.Name] = s.Digest
	}
	wantSubjects := map[string]string{"bundles/dev-cell-1/root": f.root, "bundles/dev-cell-1/argocd": f.argocd, "bundles/dev-cell-1/cell-system": f.cellSys, "bundles/dev-cell-1/network-policy": f.netpol}
	if res.Target != "dev-cell-1" || res.Root != f.root || res.Version["counter"] != 2 || !maps.Equal(got, wantSubjects) {
		t.Errorf("verify printed %+v, want the target, the root, the version and the subjects %v", res, wantSubjects)
	}

	for name, tc := range map[string]struct {
		env  []string
		want string
	}{
		"cosign does not verify":      {[]string{"STUB_COSIGN_FAIL=1"}, "no matching signatures"},
		"no subject for the root":     {[]string{"STUB_COSIGN_SUBJECTS=" + strings.Replace(f.subjects, strings.TrimPrefix(f.root, "sha256:"), strings.Repeat("9", 64), 1)}, "subject"},
		"a bootstrap state":           {[]string{`STUB_STATE_JSON={"source":"bootstrap","root":{"digest":"` + f.root + `"}}`}, "bootstrap"},
		"no state":                    {[]string{"STUB_STATE_JSON="}, "state"},
		"a state with no root digest": {[]string{`STUB_STATE_JSON={"source":"signed"}`}, "root digest"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newBundleRoot(t, "dev-cell-1")
			out, errOut, _, err := r.run("bundle.sh", append(slices.Clone(env), tc.env...), "verify", "--target", "dev-cell-1")
			if err == nil || out != "" || !strings.Contains(errOut, tc.want) {
				t.Errorf("err %v, stdout %q, stderr %q, want a failure with no output that names %q", err, out, errOut, tc.want)
			}
		})
	}
	t.Run("a root with several signed versions prints the version of the state", func(t *testing.T) {
		for _, versions := range []string{`[{"epoch":1,"counter":1},{"epoch":1,"counter":2}]`, `[{"epoch":1,"counter":2},{"epoch":1,"counter":1}]`} {
			r := newBundleRoot(t, "dev-cell-1")
			out, errOut, _, err := r.run("bundle.sh", append(slices.Clone(env), "STUB_COSIGN_VERSIONS="+versions), "verify", "--target", "dev-cell-1")
			var res struct{ Version map[string]int }
			if err != nil || json.Unmarshal([]byte(strings.TrimSpace(out)), &res) != nil || res.Version["counter"] != 2 {
				t.Errorf("versions %s: err %v, output %q %q, want the version 1/2 of the state", versions, err, out, errOut)
			}
		}
		// No printed statement has the version of the state: the root is not the set that the state says.
		r := newBundleRoot(t, "dev-cell-1")
		out, errOut, _, err := r.run("bundle.sh", append(slices.Clone(env), `STUB_COSIGN_VERSIONS=[{"epoch":1,"counter":1}]`), "verify", "--target", "dev-cell-1")
		if err == nil || out != "" || !strings.Contains(errOut, "1/2") {
			t.Errorf("err %v, stdout %q, stderr %q, want a failure that names the version 1/2", err, out, errOut)
		}
	})
	t.Run("role open and a second target", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		if _, errOut, _, err := r.run("bundle.sh", env, "verify", "--target", "management"); err == nil || !strings.Contains(errOut, "role open") {
			t.Errorf("management: err %v %q", err, errOut)
		}
		if _, _, _, err := r.run("bundle.sh", env, "verify", "--target", "dev-cell-1", "--target", "dev-cell-2"); err == nil {
			t.Error("verify took two targets")
		}
	})
}

// TestBundlePublishRefusesStaleBuild: publish packs build/<t>/bundles as it is, so a render change without a new hydrate would sign the old content.
// The rule is the one of ko_image for build/images.env: a hydrated manifests.yaml of any component of the cluster that is older than a render input
// stops the publish, and the message names the input and the command CELL=<t> mise run cell:hydrate. The inputs are the files of
// components/<component> and components/lib, cells/common.env, cells/<t>.env, internal/bundle/allow.json and build/images.env. A missing bundle stops
// it too. A fresh build, and a change outside these inputs, go on. Nothing is signed or pushed when it stops.
func TestBundlePublishRefusesStaleBuild(t *testing.T) {
	for _, tc := range []struct {
		name  string
		touch string
	}{
		{"a component render", "components/argocd/render.sh"},
		{"a shared render helper", "components/lib/addresses.sh"},
		{"the cell settings", "cells/dev-cell-1.env"},
		{"the common settings", "cells/common.env"},
		{"the allow-list", "internal/bundle/allow.json"},
		{"the images file", "build/images.env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newBundleRoot(t, "dev-cell-1")
			r.touch(tc.touch)
			env := []string{"IMAGES_ENV=" + filepath.Join(r.dir, "build", "images.env")}
			out, errOut, log, err := r.run("bundle.sh", env, "publish", "--target", "dev-cell-1")
			if err == nil || out != "" {
				t.Fatalf("a stale build was published: err %v, output %q", err, out)
			}
			for _, want := range []string{tc.touch, "CELL=dev-cell-1 mise run cell:hydrate"} {
				if !strings.Contains(errOut, want) {
					t.Errorf("stderr %q lacks %q", errOut, want)
				}
			}
			for _, bad := range []string{"bundlectl", "bundle sign", "create -f"} {
				if strings.Contains(log, bad) {
					t.Errorf("the publish went on (%q):\n%s", bad, log)
				}
			}
		})
	}
	t.Run("a fresh build and an unrelated change go on", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		r.touch("components/lib/../../README.md")
		r.touch("cells/dev-cell-2.env")
		r.touch("components/other-component/render.sh")
		if _, errOut, log, err := r.run("bundle.sh", []string{"IMAGES_ENV=" + filepath.Join(r.dir, "build", "images.env")}, "publish", "--target", "dev-cell-1"); err != nil {
			t.Fatalf("publish failed: %v\n%s\n%s", err, errOut, log)
		}
	})
	t.Run("a missing bundle", func(t *testing.T) {
		r := newBundleRoot(t, "dev-cell-1")
		if err := os.Remove(filepath.Join(r.dir, "build", "dev-cell-1", "bundles", "argocd", "manifests.yaml")); err != nil {
			t.Fatal(err)
		}
		_, errOut, _, err := r.run("bundle.sh", nil, "publish", "--target", "dev-cell-1")
		if err == nil || !strings.Contains(errOut, "argocd") || !strings.Contains(errOut, "CELL=dev-cell-1 mise run cell:hydrate") {
			t.Errorf("err %v, stderr %q", err, errOut)
		}
	})
}
