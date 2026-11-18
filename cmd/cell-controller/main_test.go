package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/metric/noop"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellctl"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// deadHost answers every call as an unreachable host service.
type deadHost struct{}

func (deadHost) Put(context.Context, string, []byte) (mgmtapi.StepStatus, error) {
	return mgmtapi.StepStatus{}, &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}
}

func (deadHost) Get(context.Context, string) (mgmtapi.StepStatus, error) {
	return mgmtapi.StepStatus{}, &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}
}

func fakeDeps(t *testing.T, kube kubernetes.Interface, started *int) deps {
	return deps{
		telemetry: func(_ context.Context, stdout io.Writer) (*telemetry.T, error) {
			*started++
			return &telemetry.T{Log: slog.New(slog.NewJSONHandler(stdout, nil)), Meter: noop.NewMeterProvider().Meter("t"),
				Shutdown: func(context.Context) error { return nil }}, nil
		},
		kube: func() (kubernetes.Interface, error) { return kube, nil },
		svids: func(context.Context) (x509svid.Source, func(), error) {
			ca := spiffetest.NewCA(t, "dev.env.poc.internal")
			return ca.Source(t, "spiffe://dev.env.poc.internal/cp/cell-controller"), func() {}, nil
		},
		host: func(runConfig, x509svid.Source) (cellctl.HostClient, error) { return deadHost{}, nil },
	}
}

// files holds the arguments that point at real files.
type files struct{ keyDir, pin string }

func newFiles(t *testing.T) files {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o755); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "spec.pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return files{keyDir: keys, pin: writeCert(t, dir)}
}

func writeCert(t *testing.T, dir string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "host.docker.internal"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"host.docker.internal"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "hostsvc.crt")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f files) args(extra ...string) []string {
	return append([]string{"run", "--env", "dev", "--steps-configmap", "cell-controller-system/cell-steps",
		"--status-configmap", "cell-controller-system/step-status", "--spec-key-dir", f.keyDir,
		"--hostsvc-addr", "192.0.2.1:17443", "--hostsvc-server-name", "host.docker.internal", "--hostsvc-pin", f.pin}, extra...)
}

func oneLine(t *testing.T, out string) map[string]any {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("output is not one line: %q", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output is not JSON: %q", out)
	}
	return m
}

func TestCellControllerRequiresFlags(t *testing.T) {
	f := newFiles(t)
	without := func(flag string) []string {
		a := f.args()
		for i, s := range a {
			if s == flag {
				return append(append([]string{}, a[:i]...), a[i+2:]...)
			}
		}
		t.Fatalf("no flag %s", flag)
		return nil
	}
	replace := func(flag, value string) []string {
		a := f.args()
		for i, s := range a {
			if s == flag {
				a[i+1] = value
			}
		}
		return a
	}
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"no_mode", nil, []string{"usage"}},
		{"unknown_mode", []string{"serve"}, []string{"unknown mode"}},
		{"run_bare", []string{"run"}, []string{"--env", "--hostsvc-addr", "--hostsvc-pin", "--hostsvc-server-name", "--spec-key-dir", "--status-configmap", "--steps-configmap"}},
		{"no_env", without("--env"), []string{"--env"}},
		{"no_steps", without("--steps-configmap"), []string{"--steps-configmap"}},
		{"no_status", without("--status-configmap"), []string{"--status-configmap"}},
		{"no_key_dir", without("--spec-key-dir"), []string{"--spec-key-dir"}},
		{"no_addr", without("--hostsvc-addr"), []string{"--hostsvc-addr"}},
		{"no_server_name", without("--hostsvc-server-name"), []string{"--hostsvc-server-name"}},
		{"no_pin", without("--hostsvc-pin"), []string{"--hostsvc-pin"}},
		{"extra_argument", append(f.args(), "x"), []string{"unexpected argument"}},
		{"bad_steps_ref", replace("--steps-configmap", "cell-steps"), []string{"--steps-configmap must be"}},
		{"two_namespaces", replace("--status-configmap", "other/step-status"), []string{"one namespace"}},
		{"key_dir_missing", replace("--spec-key-dir", filepath.Join(f.keyDir, "none")), []string{"--spec-key-dir"}},
		{"addr_no_port", replace("--hostsvc-addr", "192.0.2.1"), []string{"--hostsvc-addr"}},
		{"pin_not_pem", replace("--hostsvc-pin", filepath.Join(f.keyDir, "spec.pub")), []string{"--hostsvc-pin"}},
		{"bad_interval", f.args("--interval", "0s"), []string{"--interval"}},
		{"bad_env", replace("--env", "Dev"), []string{"--env"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			started := 0
			code := execute(t.Context(), tc.args, &out, fakeDeps(t, fake.NewClientset(), &started))
			if code != exitConfig {
				t.Fatalf("exit %d", code)
			}
			msg, _ := oneLine(t, out.String())["error"].(string)
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q lacks %q", msg, w)
				}
			}
			if started != 0 {
				t.Error("telemetry started")
			}
		})
	}
}

func TestParseRunTakesTheDocumentedFlags(t *testing.T) {
	f := newFiles(t)
	cfg, err := parseRun(f.args("--health-listen", "127.0.0.1:0", "--interval", "3s")[1:])
	if err != nil {
		t.Fatal(err)
	}
	if cfg.env != "dev" || cfg.namespace != "cell-controller-system" || cfg.stepsName != "cell-steps" || cfg.statusName != "step-status" ||
		cfg.hostAddr != "192.0.2.1:17443" || cfg.hostServerName != "host.docker.internal" || len(cfg.pin) != 32 ||
		cfg.interval != 3*time.Second || cfg.healthListen != "127.0.0.1:0" {
		t.Errorf("%+v", cfg)
	}
	cfg, err = parseRun(f.args()[1:])
	if err != nil || cfg.healthListen != ":8080" || cfg.interval != 10*time.Second {
		t.Errorf("defaults %+v, %v", cfg, err)
	}
}

func TestLogsAreJSON(t *testing.T) {
	f := newFiles(t)
	kube := fake.NewClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cell-steps", Namespace: "cell-controller-system"},
		Data:       map[string]string{cellctl.SpecKey: "not an envelope"},
	})
	started := 0
	d := fakeDeps(t, kube, &started)
	var out syncBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, f.args("--interval", "50ms", "--health-listen", "127.0.0.1:0"), &out, d)
	}()

	var health string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !(health != "" && strings.Contains(out.String(), `"msg":"spec refused"`)) {
		for _, l := range strings.Split(out.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "cell-controller started" {
				health, _ = m["health"].(string)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if health == "" || !strings.Contains(out.String(), `"msg":"spec refused"`) {
		t.Fatalf("the controller did not start or log a refusal: %q", out.String())
	}
	var status int
	for time.Now().Before(deadline) && status != http.StatusOK {
		if resp, err := http.Get("http://" + health + "/healthz"); err == nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status != http.StatusOK {
		t.Errorf("healthz %d while the host service is unreachable", status)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Errorf("not a JSON line: %q", l)
		}
		if m["msg"] == nil || m["level"] == nil || m["time"] == nil {
			t.Errorf("line lacks time, level or msg: %q", l)
		}
	}
	if !strings.Contains(lines[len(lines)-1], `"msg":"stopped"`) {
		t.Errorf("last line %q", lines[len(lines)-1])
	}
}

func TestHealthIsNotReadyBeforeTheFirstRead(t *testing.T) {
	c, err := cellctl.New(cellctl.Config{Env: "dev", Namespace: "n", StepsName: "a", StatusName: "b", Client: fake.NewClientset(),
		Keys: func() []ed25519.PublicKey { return nil }, Host: deadHost{}})
	if err != nil {
		t.Fatal(err)
	}
	rec := &respRecorder{}
	healthHandler(c).ServeHTTP(rec, nil)
	if rec.code != http.StatusServiceUnavailable {
		t.Errorf("status %d", rec.code)
	}
}

type respRecorder struct {
	code int
	h    http.Header
}

func (r *respRecorder) Header() http.Header {
	if r.h == nil {
		r.h = http.Header{}
	}
	return r.h
}
func (r *respRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (r *respRecorder) WriteHeader(c int)           { r.code = c }

func TestHealthServerLimits(t *testing.T) {
	s := newHealthServer(http.NewServeMux())
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 {
		t.Errorf("a phase has no limit: %+v", s)
	}
}

func TestRealHostClientIsBuiltFromTheFlags(t *testing.T) {
	f := newFiles(t)
	cfg, err := parseRun(f.args()[1:])
	if err != nil {
		t.Fatal(err)
	}
	ca := spiffetest.NewCA(t, "dev.env.poc.internal")
	c, err := realDeps().host(cfg, ca.Source(t, "spiffe://dev.env.poc.internal/cp/cell-controller"))
	if err != nil || c == nil {
		t.Fatalf("%v, %v", c, err)
	}
	// A Put refuses an envelope that has no step ID before it makes a call. TestHostClientAgainstTheStepRoute makes real calls.
	if _, err := c.Put(t.Context(), "x", []byte("not an envelope")); err == nil {
		t.Error("a bad envelope was sent")
	}
}
