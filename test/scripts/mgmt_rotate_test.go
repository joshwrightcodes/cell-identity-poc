package scripts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// caRotateKubectl sends each exec into the server pod to the fake spire-server, and answers the
// ConfigMap lists of the copy search with no copy. With STUB_OWN_COPY, management holds the trust
// bundle of the principal sidecar, with the content of $STUB_STATE/own.pem.
const caRotateKubectl = `#!/usr/bin/env bash
set -euo pipefail
own() {
  jq -n --rawfile pem "$STUB_STATE/own.pem" '{kind: "ConfigMap", metadata: {namespace: "central-view-system",
    name: "spire-trust-bundle-argocd-agent-principal", labels: {"cell.poc.internal/harness": "central-view"}},
    data: {"bundle.crt": $pem}}'
}
case " $* " in
  *" exec spire-server-0 "*)
    while (($#)) && [[ "$1" != -- ]]; do shift; done
    shift 2
    exec "$STUB_DIR/spire-server" "$@" ;;
  *" --context kind-management get configmaps -A -o json "*)
    if [[ -n "${STUB_OWN_COPY:-}" ]]; then own | jq '{items: [.]}'; else echo '{"items":[]}'; fi ;;
  *" --context kind-management -n central-view-system get configmap spire-trust-bundle-argocd-agent-principal -o json "*) own ;;
  *" get configmaps -A -o json "*) echo '{"items":[]}' ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// fakeSpireServer keeps the authority slots and the bundle of a SPIRE server in $STUB_STATE, as
// SPIRE v1.15.5 does: prepare overwrites the next slot and adds the root to the bundle, activate
// takes only the prepared next slot and makes the active one old, taint takes only the old slot,
// and revoke takes only a tainted old authority and removes it from the bundle. A prepare takes
// the next ID of <kind>.pool. STUB_FAIL=<verb> makes that verb fail.
const fakeSpireServer = `#!/usr/bin/env bash
set -euo pipefail
st="$STUB_STATE"
id="" fmt="" pos=()
while (($#)); do
  case "$1" in
    -socketPath|-output) shift 2 ;;
    -format) fmt="$2"; shift 2 ;;
    -authorityID) id="$2"; shift 2 ;;
    *) pos+=("$1"); shift ;;
  esac
done
echo "${pos[*]} $id" >>"$STUB_LOG"
if [[ -n "${STUB_FAIL:-}" && "${pos[2]:-}" == "$STUB_FAIL" ]]; then echo "rpc error: injected failure" >&2; exit 1; fi
k="${pos[1]:-}"
case "${pos[*]}" in
  "bundle show")
    if [[ "$fmt" == pem ]]; then
      while read -r i t; do cat "$st/pem/$i"; done <"$st/x509.bundle"
    else
      x="$(while read -r i t; do printf '{"asn1":"%s","tainted":%s}\n' "$(cat "$st/der/$i")" "$t"; done <"$st/x509.bundle" | jq -s .)"
      j="$(while read -r i t; do printf '{"key_id":"%s","tainted":%s}\n' "$i" "$t"; done <"$st/jwt.bundle" | jq -s .)"
      jq -n --argjson x "$x" --argjson j "$j" '{x509_authorities: $x, jwt_authorities: $j}'
    fi ;;
  "localauthority $k show")
    jq -n --arg a "$(cat "$st/$k.active")" --arg n "$(cat "$st/$k.next")" --arg s "$(cat "$st/$k.status")" \
      '{active: {authority_id: $a}} + (if $s == "prepared" then {prepared: {authority_id: $n}} elif $s == "old" then {old: {authority_id: $n}} else {} end)' ;;
  "localauthority $k prepare")
    n="$(head -n 1 "$st/$k.pool")"
    sed -i.bak 1d "$st/$k.pool"
    echo "$n" >"$st/$k.next"; echo prepared >"$st/$k.status"; echo "$n false" >>"$st/$k.bundle"
    jq -n --arg n "$n" '{prepared_authority: {authority_id: $n}}' ;;
  "localauthority $k activate")
    [[ "$(cat "$st/$k.status")" == prepared && "$(cat "$st/$k.next")" == "$id" ]] || { echo "only the prepared authority can be activated" >&2; exit 1; }
    old="$(cat "$st/$k.active")"
    echo "$id" >"$st/$k.active"; echo "$old" >"$st/$k.next"; echo old >"$st/$k.status"
    echo '{}' ;;
  "localauthority $k taint")
    [[ "$(cat "$st/$k.status")" == old && "$(cat "$st/$k.next")" == "$id" ]] || { echo "only the old authority can be tainted" >&2; exit 1; }
    awk -v id="$id" '$1 == id { $2 = "true" } { print }' "$st/$k.bundle" >"$st/$k.tmp" && mv "$st/$k.tmp" "$st/$k.bundle"
    echo '{}' ;;
  "localauthority $k revoke")
    [[ "$(cat "$st/$k.status")" == old && "$(cat "$st/$k.next")" == "$id" ]] && grep -qx "$id true" "$st/$k.bundle" \
      || { echo "only a tainted old authority can be revoked" >&2; exit 1; }
    grep -vx "$id true" "$st/$k.bundle" >"$st/$k.tmp" || true
    mv "$st/$k.tmp" "$st/$k.bundle"
    echo '{}' ;;
  *) echo "unexpected spire-server call: ${pos[*]}" >&2; exit 2 ;;
esac
`

// fakeRotateHostsvc stands for hostsvc-serve.sh. restart logs the call and copies the bundle of the fake server
// into the host service root, as a restart of the real service does. STUB_HOSTSVC_STALE leaves the root alone.
const fakeRotateHostsvc = `#!/usr/bin/env bash
[[ "$1" == restart ]] || exit 2
echo "restart" >>"$STUB_STATE/hostsvc.log"
[[ -z "${STUB_HOSTSVC_STALE:-}" ]] || exit 0
mkdir -p "$POC_BUILD_ROOT/hostsvc"
while read -r i t; do cat "$STUB_STATE/pem/$i"; done <"$STUB_STATE/x509.bundle" >"$POC_BUILD_ROOT/hostsvc/mgmt-root.crt"
`

// rotateServer is a fake server: X.509 authorities A (active), then B and C to prepare, and JWT
// authorities j1 (active), then j2 and j3.
type rotateServer struct {
	dir, state string
	x509       []string
}

func newRotateServer(t *testing.T) *rotateServer {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "go")
	s := &rotateServer{dir: t.TempDir()}
	s.state = filepath.Join(s.dir, "state")
	for _, d := range []string{"pem", "der"} {
		if err := os.MkdirAll(filepath.Join(s.state, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(s.dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("kubectl", caRotateKubectl, 0o755)
	write("hostsvc-serve", fakeRotateHostsvc, 0o755)
	write("spire-server", fakeSpireServer, 0o755)
	for i := range 3 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		uri, _ := url.Parse("spiffe://mgmt.poc.internal")
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "test root"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, URIs: []*url.URL{uri}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		id := hex.EncodeToString(cert.SubjectKeyId)
		s.x509 = append(s.x509, id)
		write("state/pem/"+id, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
		write("state/der/"+id, base64.StdEncoding.EncodeToString(der), 0o644)
	}
	write("state/x509.active", s.x509[0]+"\n", 0o644)
	write("state/x509.pool", s.x509[1]+"\n"+s.x509[2]+"\n", 0o644)
	write("state/x509.bundle", s.x509[0]+" false\n", 0o644)
	write("state/jwt.active", "j1\n", 0o644)
	write("state/jwt.pool", "j2\nj3\n", 0o644)
	write("state/jwt.bundle", "j1 false\n", 0o644)
	for _, k := range []string{"x509", "jwt"} {
		write("state/"+k+".next", "\n", 0o644)
		write("state/"+k+".status", "\n", 0o644)
	}
	return s
}

// run runs mgmt:rotate-ca against the fake server. It returns the output, the spire-server calls
// of this run, and the error.
func (s *rotateServer) run(t *testing.T, env ...string) (string, string, error) {
	t.Helper()
	script, err := filepath.Abs("../../scripts/mgmt-rotate-ca.sh")
	if err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(s.dir, "calls")
	_ = os.Remove(logFile)
	cmd := exec.Command(script)
	cmd.Env = append([]string{"PATH=" + s.dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"CELL=management", "STUB_DIR=" + s.dir, "STUB_STATE=" + s.state, "STUB_LOG=" + logFile,
		"MGMT_ROTATE_TAINT_WAIT=0", "MGMT_ROTATE_WAIT=5", "POC_BUILD_ROOT=" + filepath.Join(s.dir, "build"),
		"HOSTSVC_SERVE=" + filepath.Join(s.dir, "hostsvc-serve")}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	calls, _ := os.ReadFile(logFile)
	return out.String(), string(calls), err
}

func (s *rotateServer) read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.state, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// rotated checks the end state of one complete rotation to X.509 authority x and JWT authority j:
// each is active, and the bundle holds only it.
func (s *rotateServer) rotated(t *testing.T, x, j string) {
	t.Helper()
	if got := s.read(t, "x509.active") + " | " + s.read(t, "x509.bundle") + " | " + s.read(t, "jwt.active") + " | " + s.read(t, "jwt.bundle"); got != x+" | "+x+" false | "+j+" | "+j+" false" {
		t.Fatalf("server state is %q, want %s active and alone in the bundle, and the JWT authority %s the same", got, x, j)
	}
}

func count(calls, verb string) int {
	n := 0
	for line := range strings.SplitSeq(calls, "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "localauthority" && f[2] == verb {
			n++
		}
	}
	return n
}

func TestRotateCARunsToTheEnd(t *testing.T) {
	s := newRotateServer(t)
	out, calls, err := s.run(t)
	if err != nil {
		t.Fatalf("rotation failed: %v\n%s", err, out)
	}
	s.rotated(t, s.x509[1], "j2")
	for verb, want := range map[string]int{"prepare": 2, "activate": 2, "taint": 2, "revoke": 2} {
		if got := count(calls, verb); got != want {
			t.Fatalf("%d %s calls, want %d:\n%s", got, verb, want, calls)
		}
	}
	// A second rotation finds the old authorities revoked, so it prepares again.
	if out, _, err := s.run(t); err != nil {
		t.Fatalf("second rotation failed: %v\n%s", err, out)
	}
	s.rotated(t, s.x509[2], "j3")
}

// A rotation that stopped goes on from the failed step when it runs again. It never prepares
// while an old authority still needs its taint or revoke, because a prepare overwrites that slot.
func TestRotateCAResumes(t *testing.T) {
	for _, tc := range []struct {
		fail, wantStop string
		// verbs that the second run must not call
		never []string
	}{
		{"activate", "could not activate the x509 authority B. Each copy holds its root. Run: mise x -- kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority x509 activate -socketPath /run/spire/sockets/api.sock -authorityID B",
			[]string{"prepare"}},
		{"taint", "could not taint the old x509 authority A. Run: mise x -- kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority x509 taint -socketPath /run/spire/sockets/api.sock -authorityID A, wait 0s, then run: mise x -- kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority x509 revoke -socketPath /run/spire/sockets/api.sock -authorityID A",
			[]string{"prepare", "activate"}},
		{"revoke", "could not revoke the old x509 authority A. Run: mise x -- kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority x509 revoke -socketPath /run/spire/sockets/api.sock -authorityID A",
			[]string{"prepare", "activate", "taint"}},
	} {
		t.Run(tc.fail, func(t *testing.T) {
			s := newRotateServer(t)
			want := strings.NewReplacer("authority B", "authority "+s.x509[1], "authorityID B", "authorityID "+s.x509[1],
				"authority A", "authority "+s.x509[0], "authorityID A", "authorityID "+s.x509[0]).Replace(tc.wantStop)
			out, _, err := s.run(t, "STUB_FAIL="+tc.fail)
			if err == nil || !strings.Contains(out, want) || !strings.Contains(out, "mise run mgmt:rotate-ca again") {
				t.Fatalf("first run: err %v, output:\n%s\nwant a stop that says %q and names the re-run", err, out, want)
			}
			out, calls, err := s.run(t)
			if err != nil {
				t.Fatalf("second run failed: %v\n%s", err, out)
			}
			for _, verb := range tc.never {
				if n := count(calls, verb); n > 0 {
					t.Fatalf("the second run called %s %d times:\n%s", verb, n, calls)
				}
			}
			s.rotated(t, s.x509[1], "j2")
		})
	}
}

// cell:up must apply each harness component through harness_apply, which refuses objects of
// other owners. A bare apply_bundle after the root sync would take them.
func TestUpAppliesHarnessThroughTheOwnerCheck(t *testing.T) {
	data, err := os.ReadFile("../../scripts/up.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	_, after, ok := strings.Cut(text, "until apps_at_published")
	if !ok {
		t.Fatal("scripts/up.sh has no wait for apps_at_published")
	}
	loop := `for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  harness_apply "${entry%%:*}"
done`
	if !strings.Contains(after, loop) {
		t.Fatalf("scripts/up.sh does not apply each harness component with harness_apply after the root sync; want:\n%s", loop)
	}
	if strings.Contains(after, "apply_bundle") {
		t.Fatal("scripts/up.sh calls apply_bundle after the root sync, which skips the owner check of harness_apply")
	}
}

// Both refresh steps restart the host service and wait until its root file equals the bundle. A service that
// keeps an old root stops the run before the activate.
func TestRotateCARestartsTheHostService(t *testing.T) {
	s := newRotateServer(t)
	out, _, err := s.run(t)
	if err != nil {
		t.Fatalf("rotation failed: %v\n%s", err, out)
	}
	if got := strings.Count(s.read(t, "hostsvc.log"), "restart"); got != 2 {
		t.Fatalf("the host service restarted %d times, want 2 (prepare and revoke)", got)
	}
	root, err := os.ReadFile(filepath.Join(s.dir, "build", "hostsvc", "mgmt-root.crt"))
	want, _ := os.ReadFile(filepath.Join(s.state, "pem", s.x509[1]))
	if err != nil || string(root) != string(want) {
		t.Fatalf("mgmt-root.crt holds %d bytes (%v), want only the new root", len(root), err)
	}

	s = newRotateServer(t)
	out, calls, err := s.run(t, "STUB_HOSTSVC_STALE=1")
	if err == nil || !strings.Contains(out, "still differs from the bundle of management") || count(calls, "activate") > 0 {
		t.Fatalf("err %v, calls:\n%s\noutput:\n%s\nwant a stop before the activate", err, calls, out)
	}
}
