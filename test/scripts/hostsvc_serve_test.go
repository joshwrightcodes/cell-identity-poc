package scripts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func appendLine(path, line string) {
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	fmt.Fprintln(f, line)
	f.Close()
}

func main() {
	st := os.Getenv("STUB_STATE")
	if st == "" {
		// The service runs under env -i, so the state directory comes from the place of the binary: <root>/build/bin/hostsvc.
		self, _ := filepath.Abs(os.Args[0])
		st = filepath.Join(filepath.Dir(self), "..", "..", "state")
	}
	switch os.Args[1] {
	case "ctl":
		appendLine(filepath.Join(st, "ctl.log"), strings.Join(os.Args[2:], " "))
		switch os.Args[2] {
		case "steps":
			if _, err := os.Stat(filepath.Join(st, "ctl-fail")); err == nil {
				fmt.Println("{\"level\":\"ERROR\",\"msg\":\"hostsvc failed\",\"error\":\"admin socket: connection refused\"}")
				os.Exit(1)
			}
			data, err := os.ReadFile(filepath.Join(st, "steps.json"))
			if err != nil {
				data = []byte("{\"steps\":[],\"corrupt\":false}\n")
			}
			os.Stdout.Write(data)
		case "cancel":
			if mode, err := os.ReadFile(filepath.Join(st, "cancel-mode")); err == nil {
				fmt.Printf("{\"level\":\"ERROR\",\"msg\":\"hostsvc failed\",\"error\":\"%s\"}\n", strings.TrimSpace(string(mode)))
				os.Exit(1)
			}
			fmt.Println("{\"cancelled\":true}")
		case "reset-journal":
			fmt.Println("{\"reset\":true}")
		case "log":
			fmt.Println("the log of the step")
		}
	case "serve":
		wd, _ := os.Getwd()
		_ = os.WriteFile(filepath.Join(st, "cwd"), []byte(wd), 0o644)
		_ = os.WriteFile(filepath.Join(st, "args"), []byte(strings.Join(os.Args[2:], "\n")+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(st, "env"), []byte(strings.Join(os.Environ(), "\n")+"\n"), 0o644)
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
		fmt.Printf("{\"time\":\"2026-11-13T00:00:00Z\",\"level\":\"INFO\",\"msg\":\"serving\",\"addr\":\"%s\",\"cert_sha256\":\"%s\",\"root_sha256\":\"%s\",\"binary_sha256\":\"%s\",\"pid\":%d}\n", listen, cert, root, strings.Repeat("b", 64), os.Getpid())
		if _, err := os.Stat(filepath.Join(st, "ignore-term")); err == nil {
			signal.Ignore(syscall.SIGTERM)
			for {
				time.Sleep(time.Second)
			}
		}
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

// fakeServeKubectl answers the live roots of management and dev-cp, the state of mgmtd-0 (STUB_READY, empty by default,
// so mgmtd is not Ready), and the ConfigMaps that the key helpers read.
const fakeServeKubectl = `#!/usr/bin/env bash
case " $* " in
  *" exec spire-server-0 "*)
    if [[ " $* " == *"kind-dev-cp"* ]]; then cat "$STUB_STATE/dev-root.pem"; else cat "$STUB_STATE/live-root.pem"; fi ;;
  *" get pod mgmtd-0 "*) printf '%s' "${STUB_READY:-}" ;;
  *" get configmap mgmt-signing-pub "*)
    if [[ -n "${STUB_CM_NEXT:-}" ]]; then printf '{"data":{"spec.pub":"%s","next.pub":"%s"}}\n' "$STUB_CM_PUB" "$STUB_CM_NEXT"
    else printf '{"data":{"spec.pub":"%s"}}\n' "$STUB_CM_PUB"; fi ;;
  *" get configmap mgmt-spec-key "*) printf '%s' "${STUB_PINNED:-}" ;;
  *) echo "kubectl $*" >>"$STUB_STATE/kubectl.log" ;;
esac
`

// fakeServeMise answers the certificate helpers, the link, and the two reads of mgmtd that the key cross-check makes.
const fakeServeMise = `#!/usr/bin/env bash
case "$1 $2 $3 $4" in
  "run pki -- trust-bundle") cat ;;
  "run pki -- info") printf '{"subject_key_id":"","not_after":"%s"}\n' "${STUB_NOT_AFTER:-2099-01-01T00:00:00Z}" ;;
  "run mgmt -- pubkey") printf '{"spec.pub":"%s"}\n' "$STUB_LIVE_PUB" ;;
  "run mgmt -- status")
    staged="${STUB_STAGED_KEY:-}"
    if [[ -z "$staged" && -n "${STUB_NEXT_PUB:-}" ]]; then staged="$(printf '%s' "$STUB_NEXT_PUB" | base64 -d | shasum -a 256 | cut -d' ' -f1)"; fi
    printf '{"signed":{"epoch":1,"counter":7},"stagedKey":"%s"}\n' "$staged" ;;
  "run cell:link"*) echo "link CELL=$CELL LINK_ONLY=${LINK_ONLY:-}" >>"$STUB_STATE/link.log" ;;
  "run cell:up"*)
    echo "up CELL=$CELL HARNESS_ONLY=${HARNESS_ONLY:-}" >>"$STUB_STATE/link.log"
    [[ -z "${STUB_UP_FAIL:-}" ]] || { echo "cell:up failed" >&2; exit 1; } ;;
  *) echo "unexpected mise call: $*" >&2; exit 2 ;;
esac
`

// fakeKind lists the clusters that exist: STUB_KIND, or management and dev-cp. STUB_KIND_FAIL makes the listing fail.
const fakeKind = `#!/usr/bin/env bash
[[ "$*" == "get clusters" ]] || exit 2
[[ -z "${STUB_KIND_FAIL:-}" ]] || exit 1
printf '%s\n' ${STUB_KIND:-management dev-cp}
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

const (
	keyGood  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	keyOther = "/wECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	keyNext  = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
)

type serveEnv struct {
	root, state, build string
	rootA, rootB       string // PEM
	devPEM             string // the live root of dev-cp
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
	write("bin/kind", fakeKind, 0o755)
	bin, err := os.ReadFile(fakeHostsvcBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	write("state/hostsvc", string(bin), 0o755)
	write("state/pin.pem", caPEM(t, 99), 0o644)
	e.devPEM = caPEM(t, 77)
	write("state/dev-root.pem", e.devPEM, 0o644)
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

// mustRun runs scripts/hostsvc-serve.sh with several arguments, and fails when it fails.
func (e *serveEnv) mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, errOut, err := e.script("hostsvc-serve.sh", args)
	if err != nil {
		t.Fatalf("hostsvc-serve.sh %v failed: %v\nstdout: %s\nstderr: %s", args, err, out, errOut)
	}
	return out + errOut
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
	Running       bool            `json:"running"`
	PID           *int            `json:"pid"`
	CertSHA256    string          `json:"cert_sha256"`
	RootSHA256    string          `json:"root_sha256"`
	ExpiresSoon   bool            `json:"expires_soon"`
	LastError     string          `json:"last_error"`
	DevRootSHA256 string          `json:"dev_root_sha256"`
	Keys          []string        `json:"keys"`
	SpecRevision  json.RawMessage `json:"spec_revision"`
	BinarySHA256  string          `json:"binary_sha256"`
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
	t.Parallel()
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
		want := "link CELL=management LINK_ONLY=mgmt-api\nup CELL=dev-cp HARNESS_ONLY=cell-controller\n"
		if got := e.read("link.log"); got != want {
			t.Fatalf("calls %q, want the link of mgmt-api and then the render of the cell controller: %q", got, want)
		}
	})

	// The new pin of the host service reaches the cell controller through its render, so restart renders it when dev-cp exists.
	t.Run("restart without dev-cp links mgmt-api only", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		e.mustServe(t, "restart", "STUB_KIND=management")
		if got := e.read("link.log"); got != "link CELL=management LINK_ONLY=mgmt-api\n" {
			t.Fatalf("calls %q, want the link of mgmt-api and no render", got)
		}
	})

	// One failed call of kind does not keep the old pin in the cell controller.
	t.Run("restart retries kind", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		env := append(writeFlakyKind(t, filepath.Join(e.root, "bin")), "STUB_KIND_FAILS=1")
		e.mustServe(t, "restart", env...)
		if got := e.read("link.log"); got != "link CELL=management LINK_ONLY=mgmt-api\nup CELL=dev-cp HARNESS_ONLY=cell-controller\n" || kindCalls(t, env) != "2" {
			t.Fatalf("calls %q, kind calls %s; want the render of the cell controller after a second call of kind", got, kindCalls(t, env))
		}
	})

	t.Run("restart fails when the render of the cell controller fails", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		if _, _, err := e.serve(t, "restart", "STUB_UP_FAIL=1"); err == nil {
			t.Fatal("restart succeeded although the render of the cell controller failed")
		}
	})

	t.Run("restart fails when kind does not answer", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		_, errOut, err := e.serve(t, "restart", "STUB_KIND_FAIL=1", "KIND_CLUSTERS_PAUSE=0")
		if err == nil || strings.Contains(e.read("link.log"), "up CELL=dev-cp") {
			t.Fatalf("err %v, stderr %q, calls %q; want a failure and no render", err, errOut, e.read("link.log"))
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
	t.Run("start_without_mgmtd", func(t *testing.T) {
		// The mgmt-api render starts the service before mgmtd exists on a clean harness. The start keeps the files and serves.
		e := newServeEnv(t)
		out := e.mustServe(t, "start")
		if !strings.Contains(out, "mgmtd-0 is not Ready") || !e.status(t).Running {
			t.Fatalf("start output %q, status %+v; want a running service and the hint", out, e.status(t))
		}
		if entries, _ := os.ReadDir(filepath.Join(e.build, "hostsvc", "mgmt-keys")); len(entries) != 0 {
			t.Fatalf("start wrote %d key files while mgmtd was down", len(entries))
		}
		if _, err := os.Stat(filepath.Join(e.build, "hostsvc", "dev-root.crt")); err == nil {
			t.Fatal("start wrote dev-root.crt while mgmtd was down")
		}
		if _, _, err := e.serve(t, "sync"); err == nil {
			t.Fatal("sync succeeded while mgmtd was down")
		}
	})

	t.Run("start passes the step flags and runs in the repository root", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		args := strings.Split(strings.TrimSpace(e.read("args")), "\n")
		for flag, want := range map[string]string{"--repo-root": e.root, "--journal-dir": "build/hostsvc/steps", "--step-keys-dir": "build/hostsvc/mgmt-keys",
			"--step-client-bundle": "build/hostsvc/dev-root.crt", "--admin-socket": "build/hostsvc/admin.sock"} {
			i := slices.Index(args, flag)
			if i < 0 || i+1 >= len(args) || args[i+1] != want {
				t.Errorf("serve flag %s is %v, want %q (args %v)", flag, args[min(i+1, len(args)-1)], want, args)
			}
		}
		wantWD, _ := filepath.EvalSymlinks(e.root)
		if got := e.read("cwd"); got != wantWD {
			t.Errorf("the service runs in %q, want the repository root %q, which each stage child inherits", got, wantWD)
		}
	})

	t.Run("env_cleared", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start", "POC_SECRET_TOKEN_CMD=print-a-secret", "SOME_TOKEN=abc", "OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318",
			"DOCKER_HOST=unix:///tmp/docker.sock", "POC_ENVRC_LOCAL=/tmp/x")
		got := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(e.read("env")), "\n") {
			k, v, _ := strings.Cut(line, "=")
			got[k] = v
		}
		for k := range got {
			if !slices.Contains([]string{"HOME", "PATH", "USER", "TMPDIR", "DOCKER_HOST"}, k) && !strings.HasPrefix(k, "OTEL_") {
				t.Errorf("the service holds the variable %s, and env -i allows only HOME, PATH, USER, TMPDIR, DOCKER_HOST and OTEL_*", k)
			}
		}
		if got["OTEL_EXPORTER_OTLP_ENDPOINT"] != "http://collector:4318" || got["DOCKER_HOST"] != "unix:///tmp/docker.sock" || got["PATH"] == "" || got["HOME"] == "" {
			t.Errorf("the service lacks an allowed variable: %v", got)
		}
	})

	stageJournal := func(t *testing.T, e *serveEnv, state string) {
		t.Helper()
		dir := filepath.Join(e.build, "hostsvc", "steps")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		doc := `{"entries":[{"status":{"id":"` + strings.Repeat("a", 32) + `","cell":"dev-cell-1","state":"` + state + `"}}]}`
		if err := os.WriteFile(filepath.Join(dir, "journal.json"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stageSteps := func(t *testing.T, e *serveEnv, state string) {
		t.Helper()
		doc := `{"steps":[{"id":"` + strings.Repeat("a", 32) + `","cell":"dev-cell-1","state":"` + state + `"}],"corrupt":false}`
		if err := os.WriteFile(filepath.Join(e.state, "steps.json"), []byte(doc+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// stages is what rotate-signing-key reads: one line for each step that runs a stage, from the service or from journal.json.
	t.Run("stages lists the steps that run a stage", func(t *testing.T) {
		line := func(state string) string { return strings.Repeat("a", 32) + " dev-cell-1 " + state + "\n" }
		for _, state := range []string{"creating", "admitting", "bootstrapping"} {
			e := newServeEnv(t)
			stageJournal(t, e, state)
			if out, errOut, err := e.serve(t, "stages"); err != nil || out != line(state) {
				t.Fatalf("journal file, %s: err %v, stdout %q, stderr %q; want %q", state, err, out, errOut, line(state))
			}
			e = newServeEnv(t)
			e.mustServe(t, "start")
			stageSteps(t, e, state)
			if out, errOut, err := e.serve(t, "stages"); err != nil || out != line(state) {
				t.Fatalf("running service, %s: err %v, stdout %q, stderr %q; want %q", state, err, out, errOut, line(state))
			}
		}
		for _, state := range []string{"queued", "done", "failed_final"} {
			e := newServeEnv(t)
			stageJournal(t, e, state)
			if out, _, err := e.serve(t, "stages"); err != nil || out != "" {
				t.Fatalf("%s: err %v, stdout %q; want no line", state, err, out)
			}
		}
		e := newServeEnv(t)
		if out, _, err := e.serve(t, "stages"); err != nil || out != "" {
			t.Fatalf("no journal: err %v, stdout %q; want no line", err, out)
		}
		e = newServeEnv(t)
		e.mustServe(t, "start")
		if err := os.WriteFile(filepath.Join(e.state, "ctl-fail"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, errOut, err := e.serve(t, "stages"); err == nil || !strings.Contains(errOut, "could not read the steps") {
			t.Fatalf("a failed read: err %v, stderr %q; want a failure", err, errOut)
		}
	})

	t.Run("start_refuses_during_stage", func(t *testing.T) {
		for _, state := range []string{"creating", "admitting", "bootstrapping"} {
			e := newServeEnv(t)
			stageJournal(t, e, state)
			_, errOut, err := e.serve(t, "start")
			if err == nil || !strings.Contains(errOut, "a step runs a stage") || !strings.Contains(errOut, state) || e.read("starts") != "" {
				t.Fatalf("%s: err %v, stderr %q, starts %q; want a refusal before any start", state, err, errOut, e.read("starts"))
			}
			e.mustRun(t, "start", "--force")
			if !e.status(t).Running {
				t.Fatalf("%s: start --force did not start the service", state)
			}
		}
		// A step that ended, or waits, is no stage.
		e := newServeEnv(t)
		stageJournal(t, e, "queued")
		e.mustServe(t, "start")

		// While the service runs, the state comes from the service, and restart refuses too.
		e = newServeEnv(t)
		e.mustServe(t, "start")
		first := e.status(t)
		e.setRoot(t, e.rootB)
		stageSteps(t, e, "bootstrapping")
		for _, verb := range []string{"start", "restart"} {
			_, errOut, err := e.serve(t, verb)
			if err == nil || !strings.Contains(errOut, "a step runs a stage") || *e.status(t).PID != *first.PID {
				t.Fatalf("%s: err %v, stderr %q; want a refusal that leaves the process %d", verb, err, errOut, *first.PID)
			}
		}
		if got := e.read("link.log"); got != "" {
			t.Fatalf("a refused restart linked mgmt-api: %q", got)
		}
		e.mustRun(t, "restart", "--force")
		if second := e.status(t); *second.PID == *first.PID || second.RootSHA256 != e.shaB {
			t.Fatalf("restart --force: %+v, want a new process with the new root", second)
		}
	})

	t.Run("a failed read of the steps refuses start and restart", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		first := e.status(t)
		e.setRoot(t, e.rootB)
		if err := os.WriteFile(filepath.Join(e.state, "ctl-fail"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"start", "restart"} {
			_, errOut, err := e.serve(t, verb)
			if err == nil || !strings.Contains(errOut, "cannot tell whether a step runs a stage") || !strings.Contains(errOut, "--force") || *e.status(t).PID != *first.PID {
				t.Fatalf("%s: err %v, stderr %q; want a refusal that leaves process %d", verb, err, errOut, *first.PID)
			}
		}
		// A journal file that does not parse refuses too, while the service does not run.
		e = newServeEnv(t)
		dir := filepath.Join(e.build, "hostsvc", "steps")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "journal.json"), []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, errOut, err := e.serve(t, "start"); err == nil || !strings.Contains(errOut, "cannot tell whether a step runs a stage") || e.read("starts") != "" {
			t.Fatalf("a corrupt journal: err %v, stderr %q", err, errOut)
		}
	})

	t.Run("step_context_no_restart", func(t *testing.T) {
		id := strings.Repeat("c", 32)
		e := newServeEnv(t)
		e.mustServe(t, "start")
		first := e.status(t)
		// A current service: the step runs sync only.
		out := e.mustServe(t, "start", "POC_STEP_ID="+id, "STUB_READY=True", "STUB_CM_PUB="+keyGood, "STUB_LIVE_PUB="+keyGood)
		if !strings.Contains(out, "serves already") || *e.status(t).PID != *first.PID {
			t.Fatalf("step start: %q, status %+v; want the same process", out, e.status(t))
		}
		if b, err := os.ReadFile(filepath.Join(e.build, "hostsvc", "mgmt-keys", "spec.pub")); err != nil || strings.TrimSpace(string(b)) != keyGood {
			t.Fatalf("the step start did not run sync: spec.pub %q (%v)", b, err)
		}
		// A service that needs a restart: the step fails and leaves the process, with no build.
		e.setRoot(t, e.rootB)
		_, errOut, err := e.serve(t, "start", "POC_STEP_ID="+id)
		want := "run mise run hostsvc:serve -- restart after step " + id
		if err == nil || !strings.Contains(errOut, want) {
			t.Fatalf("err %v, stderr %q; want %q", err, errOut, want)
		}
		if second := e.status(t); *second.PID != *first.PID {
			t.Fatal("the step start restarted the service")
		}
		if n := strings.Count(e.read("go.log"), "go build"); n != 1 {
			t.Fatalf("%d builds, want the one of the first start", n)
		}
		if n := strings.Count(e.read("starts"), "\n"); n != 1 {
			t.Fatalf("%d processes started, want 1", n)
		}
		// With no service at all, a step start builds nothing and starts nothing.
		e = newServeEnv(t)
		_, errOut, err = e.serve(t, "start", "POC_STEP_ID="+id)
		if err == nil || !strings.Contains(errOut, want) || e.read("go.log") != "" || e.read("starts") != "" {
			t.Fatalf("no service: err %v, stderr %q, builds %q; want the restart hint and no build", err, errOut, e.read("go.log"))
		}
		// restart is no step command.
		e = newServeEnv(t)
		if _, errOut, err = e.serve(t, "restart", "POC_STEP_ID="+id); err == nil || !strings.Contains(errOut, "would end the host service that runs step "+id) {
			t.Fatalf("restart in a step: err %v, stderr %q", err, errOut)
		}
	})

	t.Run("stop sends KILL after the wait", func(t *testing.T) {
		e := newServeEnv(t)
		if err := os.WriteFile(filepath.Join(e.state, "ignore-term"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		e.mustServe(t, "start")
		pid := *e.status(t).PID
		begin := time.Now()
		_, errOut, err := e.serve(t, "stop", "HOSTSVC_STOP_WAIT=1")
		if err != nil || !strings.Contains(errOut, "did not stop within 1s, so it gets KILL") {
			t.Fatalf("err %v, stderr %q; want a KILL after the wait", err, errOut)
		}
		if d := time.Since(begin); d < 500*time.Millisecond || d > 15*time.Second {
			t.Fatalf("stop took %s, want the wait of 1s and then the KILL", d)
		}
		for i := 0; i < 50 && alive(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if alive(pid) {
			t.Fatalf("process %d still runs after the KILL", pid)
		}
	})

	t.Run("steps, log and cancel run hostsvc ctl on the admin socket", func(t *testing.T) {
		e := newServeEnv(t)
		e.mustServe(t, "start")
		stageSteps(t, e, "done")
		if out := e.mustServe(t, "steps"); !strings.Contains(out, `"corrupt":false`) {
			t.Fatalf("steps printed %q", out)
		}
		e.mustRun(t, "steps", "--reset")
		cmd := func(args ...string) (string, string, error) { return e.script("hostsvc-serve.sh", args) }
		if out, _, err := cmd("log", "--step", strings.Repeat("a", 32), "--follow"); err != nil || !strings.Contains(out, "the log of the step") {
			t.Fatalf("log: %q (%v)", out, err)
		}
		if out, _, err := cmd("cancel", "--cell", "dev-cell-1"); err != nil || !strings.Contains(out, `"cancelled":true`) {
			t.Fatalf("cancel: %q (%v)", out, err)
		}
		calls := e.read("ctl.log")
		for _, want := range []string{"steps --admin-socket build/hostsvc/admin.sock", "reset-journal --admin-socket build/hostsvc/admin.sock",
			"log --admin-socket build/hostsvc/admin.sock --step " + strings.Repeat("a", 32) + " --follow", "cancel --admin-socket build/hostsvc/admin.sock --cell dev-cell-1"} {
			if !strings.Contains(calls, want) {
				t.Errorf("ctl calls\n%s\nlack %q", calls, want)
			}
		}
		// A cancel with no open step is no failure, so cell:down can go on. Any other refusal is one.
		if err := os.WriteFile(filepath.Join(e.state, "cancel-mode"), []byte("no open step matches\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, errOut, err := cmd("cancel", "--cell", "dev-cell-2"); err != nil || !strings.Contains(errOut, "nothing to cancel") {
			t.Fatalf("cancel with no open step: err %v, stderr %q; want exit 0 and a log line", err, errOut)
		}
		if err := os.WriteFile(filepath.Join(e.state, "cancel-mode"), []byte("socket is gone\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, _, err := cmd("cancel", "--cell", "dev-cell-2"); err == nil || !strings.Contains(out, "socket is gone") {
			t.Fatalf("cancel with another error: %q (%v); want exit 1", out, err)
		}
	})

	t.Run("sync writes the roots and the keys after the cross-check", func(t *testing.T) {
		e := newServeEnv(t)
		env := []string{"STUB_READY=True", "STUB_CM_PUB=" + keyGood, "STUB_LIVE_PUB=" + keyGood, "STUB_CM_NEXT=" + keyNext, "STUB_NEXT_PUB=" + keyNext}
		e.mustServe(t, "start", env...)
		out, errOut, err := e.serve(t, "sync", env...)
		if err != nil {
			t.Fatalf("sync: %v\n%s\n%s", err, out, errOut)
		}
		hostFile := func(name string) string {
			b, _ := os.ReadFile(filepath.Join(e.build, "hostsvc", name))
			return strings.TrimSpace(string(b))
		}
		if hostFile("mgmt-keys/spec.pub") != keyGood || hostFile("mgmt-keys/next.pub") != keyNext || hostFile("dev-root.crt") != strings.TrimSpace(e.devPEM) {
			t.Fatalf("files: spec.pub %q, next.pub %q, dev-root.crt %q", hostFile("mgmt-keys/spec.pub"), hostFile("mgmt-keys/next.pub"), hostFile("dev-root.crt"))
		}
		for _, f := range []string{"mgmt-keys/spec.pub", "mgmt-keys/next.pub", "dev-root.crt"} {
			if fi, _ := os.Stat(filepath.Join(e.build, "hostsvc", f)); fi == nil || fi.Mode().Perm() != 0o644 {
				t.Errorf("%s is not a file of mode 0644: %v", f, fi)
			}
		}
		// status reads three values from the files, and binary_sha256 from the serving line.
		stepsDir := filepath.Join(e.build, "hostsvc", "steps")
		if err := os.MkdirAll(stepsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		payload := base64.StdEncoding.EncodeToString([]byte(`{"revision":{"epoch":1,"counter":7}}`))
		envelope, _ := json.Marshal(map[string]string{"payload": payload})
		specJSON, _ := json.Marshal(map[string]string{"envelope": string(envelope)})
		if err := os.WriteFile(filepath.Join(stepsDir, "spec.json"), specJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		st := e.status(t)
		block, _ := pem.Decode([]byte(e.devPEM))
		der := sha256.Sum256(block.Bytes)
		raw := func(b64 string) string {
			b, _ := base64.StdEncoding.DecodeString(b64)
			sum := sha256.Sum256(b)
			return hex.EncodeToString(sum[:])
		}
		wantKeys := []string{raw(keyGood), raw(keyNext)}
		slices.Sort(wantKeys)
		if st.DevRootSHA256 != hex.EncodeToString(der[:]) || !slices.Equal(st.Keys, wantKeys) || string(st.SpecRevision) != `{"epoch":1,"counter":7}` || st.BinarySHA256 != strings.Repeat("b", 64) {
			t.Fatalf("status %+v, want dev_root_sha256 %x, keys %v, spec_revision {epoch 1, counter 7}, binary_sha256 of the serving line", st, der, wantKeys)
		}
		// A staged key that mgmtd no longer shows leaves with the next sync.
		env = []string{"STUB_READY=True", "STUB_CM_PUB=" + keyGood, "STUB_LIVE_PUB=" + keyGood}
		e.mustServe(t, "sync", env...)
		if _, err := os.Stat(filepath.Join(e.build, "hostsvc", "mgmt-keys", "next.pub")); err == nil {
			t.Fatal("sync kept next.pub though no key is staged")
		}
		if st := e.status(t); len(st.Keys) != 1 {
			t.Fatalf("keys %v, want only spec.pub", st.Keys)
		}
	})

	// The refusals write nothing: each starts from an empty directory and ends with one, or with the files that it had.
	hostFiles := func(e *serveEnv) []string {
		var out []string
		root := filepath.Join(e.build, "hostsvc")
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && (strings.HasSuffix(path, ".pub") || strings.HasSuffix(path, "dev-root.crt")) {
				b, _ := os.ReadFile(path)
				out = append(out, strings.TrimPrefix(path, root)+"="+strings.TrimSpace(string(b)))
			}
			return nil
		})
		slices.Sort(out)
		return out
	}

	t.Run("next_pub_not_staged", func(t *testing.T) {
		for name, env := range map[string][]string{
			"mgmtd shows no staged key": {"STUB_CM_NEXT=" + keyNext, "STUB_STAGED_KEY=none-staged"},
			"another staged key":        {"STUB_CM_NEXT=" + keyNext, "STUB_NEXT_PUB=" + keyOther},
			"a next.pub that is no key": {"STUB_CM_NEXT=not-a-key", "STUB_STAGED_KEY=abc"},
		} {
			e := newServeEnv(t)
			all := append([]string{"STUB_READY=True", "STUB_CM_PUB=" + keyGood, "STUB_LIVE_PUB=" + keyGood}, env...)
			_, errOut, err := e.serve(t, "sync", all...)
			if err == nil || !strings.Contains(errOut, "next.pub") {
				t.Fatalf("%s: err %v, stderr %q; want a refusal that names next.pub", name, err, errOut)
			}
			if files := hostFiles(e); len(files) != 0 {
				t.Fatalf("%s: sync wrote %v, want no file", name, files)
			}
		}
	})

	t.Run("mgmtd_down_keeps_keys", func(t *testing.T) {
		e := newServeEnv(t)
		up := []string{"STUB_READY=True", "STUB_CM_PUB=" + keyGood, "STUB_LIVE_PUB=" + keyGood}
		e.mustServe(t, "sync", up...)
		before := hostFiles(e)
		if len(before) != 2 {
			t.Fatalf("files after the first sync: %v", before)
		}
		_, errOut, err := e.serve(t, "sync", "STUB_READY=False", "STUB_CM_PUB="+keyOther, "STUB_LIVE_PUB="+keyOther)
		if err == nil || !strings.Contains(errOut, "CELL=management LINK_ONLY=mgmt-api mise run cell:link") {
			t.Fatalf("err %v, stderr %q; want exit 1 with the link hint", err, errOut)
		}
		if after := hostFiles(e); !slices.Equal(after, before) {
			t.Fatalf("files changed while mgmtd was down: %v, was %v", after, before)
		}
	})

	t.Run("kind_down_keeps_files", func(t *testing.T) {
		e := newServeEnv(t)
		up := []string{"STUB_READY=True", "STUB_CM_PUB=" + keyGood, "STUB_LIVE_PUB=" + keyGood}
		e.mustServe(t, "sync", up...)
		before := hostFiles(e)
		if len(before) != 2 {
			t.Fatalf("files after the first sync: %v", before)
		}
		_, errOut, err := e.serve(t, "sync", append(up, "STUB_KIND_FAIL=1", "KIND_CLUSTERS_PAUSE=0")...)
		if err == nil || !strings.Contains(errOut, "kind get clusters failed") || strings.Contains(errOut, "dev-cp does not exist") {
			t.Fatalf("err %v, stderr %q; want exit 1 that names kind, never an absent dev-cp", err, errOut)
		}
		if after := hostFiles(e); !slices.Equal(after, before) {
			t.Fatalf("files changed while kind did not answer: %v, was %v", after, before)
		}
	})

	t.Run("spec_pub_differs", func(t *testing.T) {
		e := newServeEnv(t)
		_, errOut, err := e.serve(t, "sync", "STUB_READY=True", "STUB_CM_PUB="+keyGood, "STUB_LIVE_PUB="+keyOther)
		if err == nil || !strings.Contains(errOut, "mgmtd-0 signs with "+keyOther) {
			t.Fatalf("err %v, stderr %q; want a refusal that names the live key", err, errOut)
		}
		if files := hostFiles(e); len(files) != 0 {
			t.Fatalf("sync wrote %v with a spec.pub that mgmtd does not hold", files)
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
	t.Parallel()
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
	t.Parallel()
	testtool.Need(t, "jq", "yq", "bash")
	root := t.TempDir()
	for _, d := range []string{"scripts", "cells", "harness", "components/lib"} {
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
