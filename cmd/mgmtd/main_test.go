package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func jsonLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(w, nil)) }

const (
	envdID = "spiffe://dev.env.poc.internal/envd"
	mgmtID = "spiffe://mgmt.poc.internal/api"
)

type fixture struct {
	dir, sockDir      string
	devCA, mgmtCA     *spiffetest.CA
	kube              *fake.Clientset
	args              map[string]string
	telemetryCalls    atomic.Int32
	telemetryRealCall bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir(), devCA: spiffetest.NewCA(t, "dev.env.poc.internal"), mgmtCA: spiffetest.NewCA(t, "mgmt.poc.internal"), kube: fake.NewClientset()}
	intent := filepath.Join(f.dir, "intent.json")
	must(t, os.WriteFile(intent, []byte(`{"env":"dev","bindSubject":{"namespace":"cell-identity-system","serviceAccount":"celld"},"cells":[{"name":"dev-cell-1","subjects":[{"namespace":"cell-identity-system","serviceAccount":"celld"}]}]}`), 0o600))
	bundle := filepath.Join(f.dir, "peer-root.pem")
	pemBytes, err := f.devCA.Bundle().Marshal()
	must(t, err)
	must(t, os.WriteFile(bundle, pemBytes, 0o600))
	cert, err := hostsvc.SelfSignedCert("host.docker.internal", time.Now())
	must(t, err)
	pin := filepath.Join(f.dir, "hostsvc.crt")
	must(t, os.WriteFile(pin, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600))
	must(t, os.MkdirAll(filepath.Join(f.dir, "data"), 0o700))
	f.sockDir, err = os.MkdirTemp("", "mg")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(f.sockDir) })
	f.args = map[string]string{
		"intent": intent, "data-dir": filepath.Join(f.dir, "data"),
		"api-listen": "127.0.0.1:0", "bind-listen": "127.0.0.1:0", "health-listen": "127.0.0.1:0",
		"admin-socket": filepath.Join(f.sockDir, "a.sock"), "peer-bundle": bundle,
		"peer-trust-domain": "dev.env.poc.internal", "allow-id": envdID,
		"hostsvc-addr": "127.0.0.1:1", "hostsvc-server-name": "host.docker.internal", "hostsvc-pin": pin,
		"hostsvc-timeout": "2s", "public-configmap": "mgmt-system/mgmt-signing-pub",
	}
	return f
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) argv(skip ...string) []string {
	out := []string{"serve"}
	for k, v := range f.args {
		if !contains(skip, k) {
			out = append(out, "--"+k, v)
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (f *fixture) deps() deps {
	return deps{
		telemetry: func(ctx context.Context, w io.Writer) (*telemetry.T, error) {
			f.telemetryCalls.Add(1)
			if f.telemetryRealCall {
				return telemetry.Start(ctx, "mgmtd", w)
			}
			return &telemetry.T{Log: jsonLogger(w), Shutdown: func(context.Context) error { return nil }}, nil
		},
		kube: func() (kubernetes.Interface, error) { return f.kube, nil },
		svids: func(context.Context) (x509svid.Source, func(), error) {
			return f.mgmtCA.Source(nil2t(), mgmtID), func() {}, nil
		},
		nofile: func() (uint64, error) { return 1 << 20, nil },
	}
}

// nil2t returns a testing.TB for helpers that need one outside a test body.
func nil2t() testing.TB { return currentT }

var currentT testing.TB

type running struct {
	out    *lockedBuffer
	cancel context.CancelFunc
	done   chan int
	addrs  map[string]string
	once   sync.Once
	code   int
}

// stop ends the command and returns its exit code. It is safe to call twice.
func (r *running) stop(t testing.TB) int {
	r.once.Do(func() {
		r.cancel()
		select {
		case r.code = <-r.done:
		case <-time.After(10 * time.Second):
			t.Error("mgmtd did not stop")
			r.code = -1
		}
	})
	return r.code
}

func (f *fixture) start(t *testing.T) *running {
	t.Helper()
	currentT = t
	ctx, cancel := context.WithCancel(t.Context())
	r := &running{out: &lockedBuffer{}, cancel: cancel, done: make(chan int, 1)}
	go func() { r.done <- execute(ctx, f.argv(), r.out, f.deps()) }()
	t.Cleanup(func() { r.stop(t) })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(r.out.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "listening" {
				r.addrs = map[string]string{}
				for _, k := range []string{"api", "bind", "health", "admin"} {
					r.addrs[k], _ = m[k].(string)
				}
				return r
			}
		}
		select {
		case code := <-r.done:
			t.Fatalf("mgmtd exited with %d: %s", code, r.out.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("mgmtd did not start: %s", r.out.String())
	return nil
}

func jsonLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a JSON line: %q", l)
		}
		out = append(out, m)
	}
	return out
}

func TestServeRequiresFlags(t *testing.T) {
	f := newFixture(t)
	currentT = t
	for _, missing := range []string{"intent", "peer-bundle", "peer-trust-domain", "allow-id", "hostsvc-addr", "hostsvc-server-name", "hostsvc-pin", "public-configmap"} {
		var out bytes.Buffer
		if code := execute(t.Context(), f.argv(missing), &out, f.deps()); code != 2 {
			t.Errorf("without --%s: exit %d, want 2", missing, code)
		}
		lines := jsonLines(t, out.String())
		if len(lines) != 1 || lines[0]["level"] != "ERROR" || !strings.Contains(lines[0]["error"].(string), missing) {
			t.Errorf("without --%s: output %q", missing, out.String())
		}
	}
	for name, args := range map[string][]string{"none": nil, "unknown_command": {"nope"}, "unknown_flag": {"serve", "--nope", "x"}} {
		var out bytes.Buffer
		if code := execute(t.Context(), args, &out, f.deps()); code != 2 || len(jsonLines(t, out.String())) != 1 {
			t.Errorf("%s: exit %d output %q", name, code, out.String())
		}
	}
}

func TestServeEndToEnd(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)

	// Health is 200 once the plane has loaded.
	resp, err := http.Get("http://" + r.addrs["health"] + "/healthz")
	must(t, err)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}

	// envd reads the spec over mTLS.
	auth := tlsconfig.AuthorizeID(mustSPIFFE(t, mgmtID))
	cfg := tlsconfig.MTLSClientConfig(f.devCA.Source(t, envdID), f.mgmtCA.Bundle(), auth)
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	resp, err = (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + r.addrs["api"] + mgmtapi.SpecPath("dev"))
	must(t, err)
	var bundle mgmtapi.SpecBundle
	must(t, json.NewDecoder(resp.Body).Decode(&bundle))
	resp.Body.Close()
	if resp.StatusCode != 200 || len(bundle.Spec) == 0 {
		t.Fatalf("spec: %d", resp.StatusCode)
	}

	// The bind listener answers a cell with server-only TLS and the SVID of mgmtd.
	bcfg := tlsconfig.TLSClientConfig(f.mgmtCA.Bundle(), auth)
	btr := &http.Transport{TLSClientConfig: bcfg, ForceAttemptHTTP2: true}
	defer btr.CloseIdleConnections()
	resp, err = (&http.Client{Transport: btr, Timeout: 5 * time.Second}).Post("https://"+r.addrs["bind"]+mgmtapi.NoncePath("dev-cell-1"), "application/json", nil)
	must(t, err)
	var nonce mgmtapi.NonceResponse
	must(t, json.NewDecoder(resp.Body).Decode(&nonce))
	resp.Body.Close()
	if resp.StatusCode != 200 || nonce.Bound {
		t.Fatalf("nonce: %d %+v", resp.StatusCode, nonce)
	}

	// The admin socket has mode 0600, and ctl reads the public key through it.
	info, err := os.Stat(f.args["admin-socket"])
	must(t, err)
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("admin socket mode %v", info.Mode())
	}
	var pubOut bytes.Buffer
	if code := execute(t.Context(), []string{"ctl", "--socket", f.args["admin-socket"], "pubkey"}, &pubOut, f.deps()); code != 0 {
		t.Fatalf("ctl pubkey: %d %s", code, pubOut.String())
	}
	var pk map[string]string
	must(t, json.Unmarshal(pubOut.Bytes(), &pk))

	// The public key reaches the ConfigMap, with no restart and no private key.
	deadline := time.Now().Add(5 * time.Second)
	for {
		cm, err := f.kube.CoreV1().ConfigMaps("mgmt-system").Get(t.Context(), "mgmt-signing-pub", metav1.GetOptions{})
		if err == nil && cm.Data["spec.pub"] == pk["spec.pub"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ConfigMap not published: %v %v", cm, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	keyPEM, err := os.ReadFile(filepath.Join(f.args["data-dir"], "ed25519.key"))
	must(t, err)
	if info, _ := os.Stat(filepath.Join(f.args["data-dir"], "ed25519.key")); info.Mode().Perm() != 0o400 {
		t.Fatalf("key mode %v", info.Mode())
	}

	if code := r.stop(t); code != 0 {
		t.Fatalf("exit %d: %s", code, r.out.String())
	}
	// Every line on stdout is JSON, and none holds key material.
	lines := jsonLines(t, r.out.String())
	if len(lines) == 0 {
		t.Fatal("no log lines")
	}
	block, _ := pem.Decode(keyPEM)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	must(t, err)
	priv := parsed.(ed25519.PrivateKey)
	for _, raw := range [][]byte{block.Bytes, priv, priv.Seed()} {
		for name, form := range map[string]string{
			"bytes": string(raw), "hex": hex.EncodeToString(raw), "std64": base64.StdEncoding.EncodeToString(raw),
			"raw64": base64.RawStdEncoding.EncodeToString(raw), "url64": base64.URLEncoding.EncodeToString(raw),
			"rawurl64": base64.RawURLEncoding.EncodeToString(raw),
		} {
			if strings.Contains(r.out.String(), form) {
				t.Fatalf("the logs hold the private key in the form %s", name)
			}
		}
	}
	if strings.Contains(r.out.String(), "PRIVATE KEY") {
		t.Fatal("the logs hold a key block")
	}
	if !strings.Contains(r.out.String(), "signing_key_created") {
		t.Fatalf("no signing_key_created line: %s", r.out.String())
	}
}

func mustSPIFFE(t testing.TB, s string) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromString(s)
	must(t, err)
	return id
}

// Every line on stdout is JSON, and nothing reaches the standard logger, which writes to stderr.
// A refused handshake on each listener produces a line on stdout.
func TestLogsAreJSON(t *testing.T) {
	var stderr lockedBuffer
	log.SetOutput(&stderr)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f := newFixture(t)
	r := f.start(t)
	c, err := net.Dial("tcp", r.addrs["api"])
	must(t, err)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	_ = c.Close()
	bc, err := net.Dial("tcp", r.addrs["bind"])
	must(t, err)
	_, _ = bc.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	_, _ = io.Copy(io.Discard, bc)
	_ = bc.Close()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(r.out.String(), `"msg":"server_error"`) || !strings.Contains(r.out.String(), `"msg":"handshake_refused"`) {
		if time.Now().After(deadline) {
			t.Fatalf("no server_error and handshake_refused lines: %s", r.out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.stop(t)
	if len(jsonLines(t, r.out.String())) < 4 {
		t.Fatalf("too few lines: %s", r.out.String())
	}
	if stderr.String() != "" {
		t.Fatalf("the standard logger wrote: %q", stderr.String())
	}
}

// Liveness answers while the process waits for its first SVID. Readiness is 503 until the plane has
// loaded.
func TestLivenessBeforeSVIDAndReadinessAfterPlane(t *testing.T) {
	f := newFixture(t)
	currentT = t
	d := f.deps()
	releaseSVID, releasePlane := make(chan struct{}), make(chan struct{})
	inner := d.svids
	d.svids = func(ctx context.Context) (x509svid.Source, func(), error) {
		<-releaseSVID
		return inner(ctx)
	}
	d.beforePlane = func() { <-releasePlane }
	ctx, cancel := context.WithCancel(t.Context())
	out := &lockedBuffer{}
	done := make(chan int, 1)
	go func() { done <- execute(ctx, f.argv(), out, d) }()
	// release closes a gate once, and ignores a second close.
	release := func(c chan struct{}) { defer func() { _ = recover() }(); close(c) }
	defer func() {
		release(releaseSVID)
		release(releasePlane)
		cancel()
		<-done
	}()
	addr := waitField(t, out, "health_listening", "addr")
	status := func(path string) int {
		resp, err := http.Get("http://" + addr + path)
		must(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	if status("/livez") != 200 || status("/healthz") != 503 {
		t.Fatal("while the SVID is missing, /livez must be 200 and /healthz 503")
	}
	release(releaseSVID)
	time.Sleep(100 * time.Millisecond)
	if status("/healthz") != 503 {
		t.Fatal("/healthz was not 503 while the plane loads")
	}
	release(releasePlane)
	deadline := time.Now().Add(5 * time.Second)
	for status("/healthz") != 200 {
		if time.Now().After(deadline) {
			t.Fatal("/healthz never became 200")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitField(t *testing.T, out *lockedBuffer, msg, field string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(out.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == msg {
				v, _ := m[field].(string)
				return v
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q line: %s", msg, out.String())
	return ""
}

// Readiness does not depend on the key publish: every write fails and /healthz stays 200.
func TestHealthzStaysUpWhilePublishFails(t *testing.T) {
	f := newFixture(t)
	for _, verb := range []string{"get", "create", "update"} {
		f.kube.PrependReactor(verb, "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("forbidden")
		})
	}
	r := f.start(t)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(r.out.String(), "public_key_publish_failed") {
		if time.Now().After(deadline) {
			t.Fatalf("no publish failure line: %s", r.out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp, err := http.Get("http://" + r.addrs["health"] + "/healthz")
	must(t, err)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/healthz %d while the publish fails", resp.StatusCode)
	}
}

func TestShutdownBudgetStaysBelowTheGracePeriod(t *testing.T) {
	if serverStopTimeout+flushTimeout >= 25*time.Second {
		t.Fatalf("shutdown budget %s", serverStopTimeout+flushTimeout)
	}
}

func TestServeRefusesNonPositiveIntervals(t *testing.T) {
	f := newFixture(t)
	currentT = t
	for _, tc := range [][]string{{"--hostsvc-timeout", "0s"}, {"--check-every", "0s"}, {"--check-every", "-1m"}} {
		var out bytes.Buffer
		argv := append(f.argv("hostsvc-timeout"), tc...)
		if code := execute(t.Context(), argv, &out, f.deps()); code != 2 {
			t.Errorf("%v: exit %d, want 2", tc, code)
		}
	}
}

func TestServeStateInvalid(t *testing.T) {
	f := newFixture(t)
	must(t, os.WriteFile(filepath.Join(f.args["data-dir"], "state.json"), []byte(`{"version":99,"history":[]}`), 0o600))
	currentT = t
	var out bytes.Buffer
	code := execute(t.Context(), f.argv(), &out, f.deps())
	lines := jsonLines(t, out.String())
	last := lines[len(lines)-1]
	msg, _ := last["error"].(string)
	if code == 0 || !strings.Contains(msg, "state_invalid") || !strings.Contains(msg, "Recover lost management state") || strings.Contains(msg, "mgmtd ctl") {
		t.Fatalf("exit %d, last line %v", code, last)
	}
}

type countingListener struct {
	net.Listener
	n atomic.Int32
}

func (c *countingListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}

func countingEndpoint(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	cl := &countingListener{Listener: ln}
	go func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return cl
}

// Without OTEL_EXPORTER_OTLP_ENDPOINT the command starts no exporter. The per-signal endpoints point
// at a counting listener, so a started exporter would connect there.
func TestServeNoExporterWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	cl := countingEndpoint(t)
	for _, sig := range []string{"TRACES", "METRICS", "LOGS"} {
		t.Setenv("OTEL_EXPORTER_OTLP_"+sig+"_ENDPOINT", "http://"+cl.Addr().String())
	}
	f := newFixture(t)
	f.telemetryRealCall = true
	r := f.start(t)
	r.stop(t)
	if f.telemetryCalls.Load() != 0 || cl.n.Load() != 0 {
		t.Fatalf("telemetry started %d times, %d connections", f.telemetryCalls.Load(), cl.n.Load())
	}
}

func TestServeStartsTelemetryWithEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	f := newFixture(t)
	r := f.start(t)
	r.stop(t)
	if f.telemetryCalls.Load() != 1 {
		t.Fatalf("telemetry started %d times, want 1", f.telemetryCalls.Load())
	}
}

var _ = x509.NewCertPool
