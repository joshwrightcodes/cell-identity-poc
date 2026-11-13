package scripts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// fakeHostsvcSource is the source of the fake binary that go build makes. It is a compiled program, so its command
// line is exactly "<path> serve ...", as the real binary has. serve prints the serving line of the real binary (its
// certificate SHA-256 is new at each start, and root_sha256 comes from the map that the test filled from the Go code),
// says that it listens by writing its pid for the fake lsof, and runs until TERM. pin succeeds only for the certificate
// of the running process.
const fakeHostsvcSource = `package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func main() {
	st := os.Getenv("STUB_STATE")
	switch os.Args[1] {
	case "serve":
		listen, bundle := flagValue(os.Args, "--listen"), flagValue(os.Args, "--client-bundle")
		port := listen[strings.LastIndex(listen, ":")+1:]
		data, _ := os.ReadFile(bundle)
		sum := sha256.Sum256(data)
		root, err := os.ReadFile(filepath.Join(st, "map", hex.EncodeToString(sum[:])))
		if err != nil {
			root = []byte("unknown")
		}
		c := sha256.Sum256([]byte(fmt.Sprint(os.Getpid(), time.Now().UnixNano())))
		cert := hex.EncodeToString(c[:])
		_ = os.WriteFile(filepath.Join(st, "cert."+port), []byte(cert), 0o644)
		_ = os.WriteFile(filepath.Join(st, "listen."+port), []byte(fmt.Sprint(os.Getpid())), 0o644)
		f, _ := os.OpenFile(filepath.Join(st, "starts"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		fmt.Fprintln(f, bundle)
		f.Close()
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM)
		fmt.Printf("{\"time\":\"2026-11-13T00:00:00Z\",\"level\":\"INFO\",\"msg\":\"serving\",\"addr\":\"%s\",\"cert_sha256\":\"%s\",\"root_sha256\":\"%s\",\"pid\":%d}\n", listen, cert, root, os.Getpid())
		<-ch
		os.Remove(filepath.Join(st, "listen."+port))
		os.Remove(filepath.Join(st, "cert."+port))
	case "pin":
		addr, expect := flagValue(os.Args, "--addr"), flagValue(os.Args, "--expect-sha256")
		port := addr[strings.LastIndex(addr, ":")+1:]
		got, err := os.ReadFile(filepath.Join(st, "cert."+port))
		if err != nil || string(got) != expect {
			fmt.Println(` + "`" + `{"level":"ERROR","msg":"hostsvc failed","error":"no such server"}` + "`" + `)
			os.Exit(1)
		}
		pem, _ := os.ReadFile(filepath.Join(st, "pin.pem"))
		os.Stdout.Write(pem)
	}
}
`

var (
	fakeBinOnce sync.Once
	fakeBinPath string
	fakeBinErr  error
)

// fakeHostsvcBinary compiles the fake host service once for the package.
func fakeHostsvcBinary(t *testing.T) string {
	t.Helper()
	fakeBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-hostsvc")
		if err != nil {
			fakeBinErr = err
			return
		}
		src := filepath.Join(dir, "main.go")
		if err := os.WriteFile(src, []byte(fakeHostsvcSource), 0o644); err != nil {
			fakeBinErr = err
			return
		}
		fakeBinPath = filepath.Join(dir, "hostsvc")
		cmd := exec.Command("go", "build", "-o", fakeBinPath, src)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			fakeBinErr = fmt.Errorf("build the fake host service: %v: %s", err, out)
		}
	})
	if fakeBinErr != nil {
		t.Fatal(fakeBinErr)
	}
	return fakeBinPath
}

const fakeServeKubectl = `#!/usr/bin/env bash
case " $* " in
  *" exec spire-server-0 "*) cat "$STUB_STATE/live-root.pem" ;;
  *) echo "kubectl $*" >>"$STUB_STATE/kubectl.log" ;;
esac
`

const fakeServeMise = `#!/usr/bin/env bash
case "$1 $2 $3 $4" in
  "run pki -- trust-bundle") cat ;;
  "run pki -- info") printf '{"subject_key_id":"","not_after":"%s"}\n' "${STUB_NOT_AFTER:-2099-01-01T00:00:00Z}" ;;
  "run cell:link"*) echo "link CELL=$CELL LINK_ONLY=${LINK_ONLY:-}" >>"$STUB_STATE/link.log" ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

const fakeServeGo = `#!/usr/bin/env bash
[[ "$1 $2" == "build -o" && "$4" == ./cmd/hostsvc ]] || { echo "unexpected go call: $*" >&2; exit 2; }
echo "go build $3" >>"$STUB_STATE/go.log"
mkdir -p "$(dirname "$3")"
cp "$STUB_STATE/hostsvc" "$3"
chmod +x "$3"
`

const fakeLsof = `#!/usr/bin/env bash
for a in "$@"; do [[ "$a" == -iTCP:* ]] && port="${a#-iTCP:}"; done
[[ -f "$STUB_STATE/listen.$port" ]] && cat "$STUB_STATE/listen.$port"
exit 0
`

type serveEnv struct {
	root, state, build string
	rootA, rootB       string // PEM
	shaA, shaB         string // the root_sha256 of the Go code
}

// caPEM returns a self-signed CA of trust domain mgmt.poc.internal as PEM.
func caPEM(t *testing.T, serial int64) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://mgmt.poc.internal")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// goRootSHA is the root_sha256 that the real host service logs for a bundle file.
func goRootSHA(t *testing.T, pemText string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, []byte(pemText), 0o644); err != nil {
		t.Fatal(err)
	}
	roots, err := hostsvc.LoadClientRoots(path, spiffeid.RequireTrustDomainFromString("mgmt.poc.internal"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return roots.SHA256()
}

func newServeEnv(t *testing.T) *serveEnv {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash", "awk", "base64", "shasum")
	e := &serveEnv{root: t.TempDir()}
	e.state = filepath.Join(e.root, "state")
	e.build = filepath.Join(e.root, "build")
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
		copyFiles(t, e.root, d)
	}
	write := func(path, content string, mode os.FileMode) {
		p := filepath.Join(e.root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("bin/kubectl", fakeServeKubectl, 0o755)
	write("bin/mise", fakeServeMise, 0o755)
	write("bin/go", fakeServeGo, 0o755)
	write("bin/lsof", fakeLsof, 0o755)
	bin, err := os.ReadFile(fakeHostsvcBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	write("state/hostsvc", string(bin), 0o755)
	write("state/pin.pem", caPEM(t, 99), 0o644)
	e.rootA, e.rootB = caPEM(t, 1), caPEM(t, 2)
	e.shaA, e.shaB = goRootSHA(t, e.rootA), goRootSHA(t, e.rootB)
	for pemText, sha := range map[string]string{e.rootA: e.shaA, e.rootB: e.shaB} {
		sum := sha256.Sum256([]byte(pemText))
		write("state/map/"+hex.EncodeToString(sum[:]), sha, 0o644)
	}
	e.setRoot(t, e.rootA)
	t.Cleanup(func() {
		if b, err := os.ReadFile(filepath.Join(e.build, "hostsvc", "serve.pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	return e
}

func (e *serveEnv) setRoot(t *testing.T, pemText string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.state, "live-root.pem"), []byte(pemText), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *serveEnv) script(name string, args []string, env ...string) (stdout, stderr string, err error) {
	cmd := exec.Command(filepath.Join(e.root, "scripts", name), args...)
	cmd.Env = append([]string{"PATH=" + filepath.Join(e.root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"), "CELL=management", "STUB_STATE=" + e.state, "POC_BUILD_ROOT=" + e.build,
		"HOSTSVC_SERVE_WAIT=10"}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

func (e *serveEnv) serve(t *testing.T, verb string, env ...string) (string, string, error) {
	t.Helper()
	return e.script("hostsvc-serve.sh", []string{verb}, env...)
}

func (e *serveEnv) mustServe(t *testing.T, verb string, env ...string) string {
	t.Helper()
	out, errOut, err := e.serve(t, verb, env...)
	if err != nil {
		t.Fatalf("hostsvc-serve.sh %s failed: %v\nstdout: %s\nstderr: %s", verb, err, out, errOut)
	}
	return out + errOut
}

type serveStatus struct {
	Running     bool   `json:"running"`
	PID         *int   `json:"pid"`
	CertSHA256  string `json:"cert_sha256"`
	RootSHA256  string `json:"root_sha256"`
	ExpiresSoon bool   `json:"expires_soon"`
	LastError   string `json:"last_error"`
}

func (e *serveEnv) status(t *testing.T, env ...string) serveStatus {
	t.Helper()
	out, errOut, err := e.serve(t, "status", env...)
	if err != nil {
		t.Fatalf("status failed: %v\n%s\n%s", err, out, errOut)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Fatalf("status printed more than one line:\n%s", out)
	}
	var s serveStatus
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("status is no JSON object: %v\n%s", err, out)
	}
	return s
}

func (e *serveEnv) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(e.state, name))
	return string(b)
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// TestHostsvcServeLifecycle runs scripts/hostsvc-serve.sh against a fake binary, a fake lsof and a fake
// management server. The shell computes the root digest, and the fake binary logs the digest that the
// Go code gives, so a difference between the two makes start restart the service at each call.
func TestHostsvcServeLifecycle(t *testing.T) {
	t.Run("start twice gives one process", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		first := e.status(t)
		if !first.Running || first.PID == nil || first.CertSHA256 == "" || first.RootSHA256 != e.shaA {
			t.Fatalf("status after start: %+v, want a running service with root_sha256 %s", first, e.shaA)
		}
		if got := e.read("go.log"); strings.Count(got, "go build") != 1 {
			t.Fatalf("go build ran:\n%s", got)
		}
		root, err := os.ReadFile(filepath.Join(e.build, "hostsvc", "mgmt-root.crt"))
		if err != nil || string(root) != e.rootA {
			t.Fatalf("mgmt-root.crt is %q (%v), want the live root", root, err)
		}
		out := e.mustServe(t, "start")
		second := e.status(t)
		if !strings.Contains(out, "serves already") || *second.PID != *first.PID || second.CertSHA256 != first.CertSHA256 {
			t.Fatalf("second start: %s\nstatus %+v, want the same process %d", out, second, *first.PID)
		}
		if n := strings.Count(e.read("starts"), "\n"); n != 1 {
			t.Fatalf("%d processes started, want 1", n)
		}
	})

	t.Run("a changed root restarts the process", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		first := e.status(t)
		e.setRoot(t, e.rootB)
		e.mustServe(t, "start")
		second := e.status(t)
		if *second.PID == *first.PID || second.RootSHA256 != e.shaB || second.CertSHA256 == first.CertSHA256 {
			t.Fatalf("after a new root: %+v, want a new process with root_sha256 %s (before: %+v)", second, e.shaB, first)
		}
		for i := 0; i < 50 && alive(*first.PID); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if alive(*first.PID) {
			t.Fatalf("the old process %d still runs", *first.PID)
		}
		root, _ := os.ReadFile(filepath.Join(e.build, "hostsvc", "mgmt-root.crt"))
		if string(root) != e.rootB {
			t.Fatalf("mgmt-root.crt holds %q, want the new root", root)
		}
		if _, err := os.Stat(filepath.Join(e.build, "hostsvc", "serve.log.1")); err != nil {
			t.Fatalf("the log of the first run was not rotated: %v", err)
		}
	})

	t.Run("a held port fails start", func(t *testing.T) {
		e := newServeEnv(t)
		holder := exec.Command("sleep", "60")
		if err := holder.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = holder.Process.Kill(); _ = holder.Wait() })
		if err := os.WriteFile(filepath.Join(e.state, "listen.17443"), []byte(strconv.Itoa(holder.Process.Pid)), 0o644); err != nil {
			t.Fatal(err)
		}
		_, errOut, err := e.serve(t, "start")
		if err == nil || !strings.Contains(errOut, fmt.Sprintf("port 17443 is held by process %d", holder.Process.Pid)) {
			t.Fatalf("err %v, stderr %q; want a stop that names the holder", err, errOut)
		}
		if e.read("go.log") != "" || e.read("starts") != "" {
			t.Fatal("start built or ran the service though another process holds the port")
		}
	})

	t.Run("stop refuses a process with another command line", func(t *testing.T) {
		e := newServeEnv(t)
		other := exec.Command("sleep", "60")
		if err := other.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
		dir := filepath.Join(e.build, "hostsvc")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "serve.pid"), []byte(strconv.Itoa(other.Process.Pid)), 0o644); err != nil {
			t.Fatal(err)
		}
		_, errOut, err := e.serve(t, "stop")
		if err == nil || !strings.Contains(errOut, "is not the host service") || !alive(other.Process.Pid) {
			t.Fatalf("err %v, stderr %q, alive %v; want a refusal that leaves the process running", err, errOut, alive(other.Process.Pid))
		}
		if _, err := os.Stat(filepath.Join(dir, "serve.pid")); err != nil {
			t.Fatal("stop removed a pid file that does not name the host service")
		}
	})

	t.Run("stop refuses a wrapper that only names the binary", func(t *testing.T) {
		e := newServeEnv(t)
		bin := filepath.Join(e.build, "bin", "hostsvc")
		wrapper := exec.Command("sh", "-c", "sleep 60; true # "+bin+" serve")
		if err := wrapper.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = wrapper.Process.Kill(); _ = wrapper.Wait() })
		dir := filepath.Join(e.build, "hostsvc")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "serve.pid"), []byte(strconv.Itoa(wrapper.Process.Pid)), 0o644); err != nil {
			t.Fatal(err)
		}
		_, errOut, err := e.serve(t, "stop")
		if err == nil || !strings.Contains(errOut, "is not the host service") || !alive(wrapper.Process.Pid) {
			t.Fatalf("err %v, stderr %q; want a refusal that leaves the wrapper running", err, errOut)
		}
	})

	t.Run("a second listener on the port fails start", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		pid := *e.status(t).PID
		other := exec.Command("sleep", "60")
		if err := other.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
		listen := filepath.Join(e.state, "listen.17443")
		if err := os.WriteFile(listen, []byte(fmt.Sprintf("%d\n%d\n", pid, other.Process.Pid)), 0o644); err != nil {
			t.Fatal(err)
		}
		_, errOut, err := e.serve(t, "start")
		if err == nil || !strings.Contains(errOut, fmt.Sprintf("port 17443 is held by process %d %d", pid, other.Process.Pid)) {
			t.Fatalf("err %v, stderr %q; want a stop that names both holders", err, errOut)
		}
	})

	t.Run("the service runs in its own process group", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		pid := *e.status(t).PID
		pgid, err := syscall.Getpgid(pid)
		if err != nil || pgid == syscall.Getpgrp() || pgid != pid {
			t.Fatalf("process group of the service %d (%v), want its own group %d, not the group %d of the caller", pgid, err, pid, syscall.Getpgrp())
		}
	})

	t.Run("stop ends the service and runs again with no effect", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		pid := *e.status(t).PID
		e.mustServe(t, "stop")
		if alive(pid) {
			t.Fatalf("process %d still runs after stop", pid)
		}
		if s := e.status(t); s.Running || s.PID != nil {
			t.Fatalf("status after stop: %+v, want not running", s)
		}
		e.mustServe(t, "stop")
	})

	t.Run("status of a service that never ran", func(t *testing.T) {
		e := newServeEnv(t)
		s := e.status(t)
		if s.Running || s.PID != nil || s.CertSHA256 != "" || s.RootSHA256 != "" || s.ExpiresSoon {
			t.Fatalf("status %+v, want nothing", s)
		}
	})

	t.Run("a certificate that ends within 14 days restarts the service", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		first := e.status(t)
		if first.ExpiresSoon {
			t.Fatalf("a fresh certificate reports expires_soon")
		}
		soon := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
		if s := e.status(t, "STUB_NOT_AFTER="+soon); !s.ExpiresSoon {
			t.Fatalf("status %+v, want expires_soon for a certificate that ends in 10 days", s)
		}
		e.mustServe(t, "start", "STUB_NOT_AFTER="+soon)
		if second := e.status(t); *second.PID == *first.PID {
			t.Fatal("start kept the process whose certificate ends in 10 days")
		}
	})

	t.Run("restart links mgmt-api", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		first := e.status(t)
		e.mustServe(t, "restart")
		second := e.status(t)
		if *second.PID == *first.PID {
			t.Fatal("restart kept the process")
		}
		if got := e.read("link.log"); got != "link CELL=management LINK_ONLY=mgmt-api\n" {
			t.Fatalf("link calls %q, want one link of mgmt-api", got)
		}
	})

	t.Run("pin prints the certificate of the running service", func(t *testing.T) {
		e := newServeEnv(t)
		if _, _, err := e.serve(t, "pin"); err == nil {
			t.Fatal("pin succeeded with no running service")
		}
		e.mustServe(t, "start")
		out, _, err := e.serve(t, "pin")
		if err != nil || out != e.read("pin.pem") {
			t.Fatalf("pin printed %q (%v), want the certificate", out, err)
		}
	})
}

// fakeSigningKubectl serves the ConfigMap and the pod that mgmt_signing_pub reads.
const fakeSigningKubectl = `#!/usr/bin/env bash
case " $* " in
  *" get configmap mgmt-signing-pub "*)
    [[ -z "${STUB_NO_CM:-}" ]] || { echo 'Error from server (NotFound)' >&2; exit 1; }
    printf '{"data":{"spec.pub":"%s"}}\n' "$STUB_CM_PUB" ;;
  *" get configmap mgmt-spec-key "*) [[ -z "${STUB_PIN_ERR:-}" ]] || exit 1; printf '%s' "${STUB_PINNED:-}" ;;
  *" get pod mgmtd-0 "*) printf '%s' "${STUB_READY:-True}" ;;
  *) exit 2 ;;
esac
`

const fakeMgmtMise = `#!/usr/bin/env bash
[[ "$*" == "run mgmt -- pubkey" ]] || { echo "unexpected mise call: $*" >&2; exit 2; }
printf '{"spec.pub":"%s"}\n' "$STUB_LIVE_PUB"
`

// TestMgmtSigningPub: mgmt_signing_pub reads spec.pub from the live ConfigMap and checks that it is the
// base64 of 32 bytes. Whenever mgmtd-0 is Ready, the value must equal `mise run mgmt -- pubkey`. An absent
// ConfigMap fails with the link command.
func TestMgmtSigningPub(t *testing.T) {
	testtool.Need(t, "jq", "bash", "base64")
	dir := t.TempDir()
	for name, body := range map[string]string{"kubectl": fakeSigningKubectl, "mise": fakeMgmtMise} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	lib, err := filepath.Abs("../../components/lib/mgmt-key.sh")
	if err != nil {
		t.Fatal(err)
	}
	good := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	other := "/wECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	for _, tc := range []struct {
		name, want string
		env        []string
		fail       string
	}{
		{"ready and equal", good, []string{"STUB_CM_PUB=" + good, "STUB_LIVE_PUB=" + good}, ""},
		{"ready and different", "", []string{"STUB_CM_PUB=" + good, "STUB_LIVE_PUB=" + other}, "mgmtd-0 signs with " + other},
		{"not ready skips the comparison", good, []string{"STUB_CM_PUB=" + good, "STUB_LIVE_PUB=" + other, "STUB_READY=False"}, ""},
		{"not ready and pinned equal", good, []string{"STUB_CM_PUB=" + good, "STUB_READY=False", "STUB_PINNED=" + good}, ""},
		{"not ready and nothing pinned", good, []string{"STUB_CM_PUB=" + good, "STUB_READY=False"}, ""},
		{"not ready and pinned different", "", []string{"STUB_CM_PUB=" + good, "STUB_READY=False", "STUB_PINNED=" + other},
			"Start mgmtd with: CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
		{"not ready and pin unreadable", "", []string{"STUB_CM_PUB=" + good, "STUB_READY=False", "STUB_PIN_ERR=1"}, "MGMT_KEY_ACCEPT_CHANGE=1"},
		{"not ready and pinned different with the override", good, []string{"STUB_CM_PUB=" + good, "STUB_READY=False", "STUB_PINNED=" + other, "MGMT_KEY_ACCEPT_CHANGE=1"}, ""},
		{"ready and pinned different is not checked", good, []string{"STUB_CM_PUB=" + good, "STUB_LIVE_PUB=" + good, "STUB_PINNED=" + other}, ""},
		{"the ConfigMap is absent", "", []string{"STUB_NO_CM=1"}, "Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"},
		{"31 bytes", "", []string{"STUB_CM_PUB=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==", "STUB_READY=False"}, "not the base64 of 32 bytes"},
		{"not base64", "", []string{"STUB_CM_PUB=not-a-key", "STUB_READY=False"}, "not the base64 of 32 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `source "$1"; mgmt_signing_pub`, "_", lib)
			cmd.Env = append([]string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}, tc.env...)
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if tc.fail != "" {
				if err == nil || stdout.String() != "" || !strings.Contains(stderr.String(), tc.fail) {
					t.Fatalf("err %v, stdout %q, stderr %q; want a failure that says %q", err, stdout.String(), stderr.String(), tc.fail)
				}
				return
			}
			if err != nil || strings.TrimSpace(stdout.String()) != tc.want {
				t.Fatalf("err %v, stdout %q, stderr %q; want %s", err, stdout.String(), stderr.String(), tc.want)
			}
		})
	}
}

// TestMgmtTaskNamesTheLinkCommand: mise run mgmt prints one JSON error line that names the link command when
// mgmtd-0 is absent or not Ready, and runs mgmtd ctl in the pod otherwise.
func TestMgmtTaskNamesTheLinkCommand(t *testing.T) {
	testtool.Need(t, "jq", "yq", "bash")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness"} {
		copyFiles(t, root, d)
	}
	kubectl := `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_LOG"
case " $* " in
  *" get pod mgmtd-0 "*) printf '%s' "${STUB_READY:-}" ;;
  *" exec mgmtd-0 "*) echo '{"spec.pub":"x"}' ;;
esac
`
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "kubectl"), []byte(kubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(env ...string) (string, error) {
		cmd := exec.Command(filepath.Join(root, "scripts", "mgmt.sh"), "pubkey")
		cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
			"HOME=" + os.Getenv("HOME"), "CELL=management", "STUB_LOG=" + filepath.Join(root, "calls")}, env...)
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		return out.String(), err
	}
	for _, ready := range []string{"", "False"} {
		out, err := run("STUB_READY=" + ready)
		var line struct{ Level, Msg, Error string }
		if jsonErr := json.Unmarshal([]byte(out), &line); err == nil || jsonErr != nil || strings.Count(strings.TrimSpace(out), "\n") != 0 ||
			line.Level != "ERROR" || !strings.Contains(line.Error, "CELL=management LINK_ONLY=mgmt-api mise run cell:link") {
			t.Fatalf("ready %q: err %v, output %q; want one JSON error line that names the link command", ready, err, out)
		}
	}
	out, err := run("STUB_READY=True")
	calls, _ := os.ReadFile(filepath.Join(root, "calls"))
	if err != nil || strings.TrimSpace(out) != `{"spec.pub":"x"}` || !strings.Contains(string(calls), "-n mgmt-system exec mgmtd-0 -c mgmtd -- /ko-app/mgmtd ctl pubkey") {
		t.Fatalf("err %v, output %q, calls:\n%s; want mgmtd ctl pubkey in mgmtd-0", err, out, calls)
	}
}
