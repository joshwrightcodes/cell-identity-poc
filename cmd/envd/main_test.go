package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/envd"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
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

type signer struct {
	t    *testing.T
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	jwks json.RawMessage
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cp, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, err := (&jose.JSONWebKey{Key: cp, KeyID: "k", Algorithm: "EdDSA", Use: "sig"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []json.RawMessage{raw}})
	return &signer{t: t, pub: pub, priv: priv, jwks: jwks}
}

func (s *signer) keyFile() string {
	p := filepath.Join(s.t.TempDir(), "spec.pub")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(s.pub)+"\n"), 0o600); err != nil {
		s.t.Fatal(err)
	}
	return p
}

// bundle signs a spec of one cell "a" at the revision counter c.
func (s *signer) bundle(c uint64) mgmtapi.SpecBundle {
	s.t.Helper()
	rec, err := record.Sign(record.Cell{Name: "a", Env: "dev", Issuer: "https://a.example", JWKS: s.jwks,
		Subjects: []record.Subject{{Namespace: "n", ServiceAccount: "s"}}, Epoch: 1, Counter: c}, s.priv)
	if err != nil {
		s.t.Fatal(err)
	}
	_, payload, err := record.VerifyWithPayload(rec, []ed25519.PublicKey{s.pub})
	if err != nil {
		s.t.Fatal(err)
	}
	raw, err := spec.Sign(spec.Spec{Env: "dev", Revision: spec.Revision{Epoch: 1, Counter: c}, Cells: []spec.Entry{
		{Name: "a", Revision: spec.Revision{Epoch: 1, Counter: c}, RecordSHA256: spec.RecordDigest(payload)}}}, s.priv)
	if err != nil {
		s.t.Fatal(err)
	}
	return mgmtapi.SpecBundle{Spec: raw, Records: map[string]json.RawMessage{"a": rec}}
}

func (s *signer) stdin(b mgmtapi.SpecBundle) io.Reader {
	raw, _ := json.Marshal(b)
	return bytes.NewReader(raw)
}

// bundleSource is what the Workload API source gives: SVIDs and trust bundles.
type bundleSource struct {
	svids   x509svid.Source
	bundles x509bundle.Source
}

func (b bundleSource) GetX509SVID() (*x509svid.SVID, error) { return b.svids.GetX509SVID() }

func (b bundleSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return b.bundles.GetX509BundleForTrustDomain(td)
}

// workloadSource returns a svids dependency that serves the SVID of envd and the bundle of ca.
func workloadSource(t *testing.T, ca *spiffetest.CA) func(context.Context) (x509svid.Source, func(), error) {
	return func(context.Context) (x509svid.Source, func(), error) {
		return bundleSource{ca.Source(t, "spiffe://dev.env.poc.internal/envd"), ca.Bundle()}, func() {}, nil
	}
}

// gatewayFlags are the flags that run requires besides the M4 ones.
func gatewayFlags() []string {
	return append([]string{"--gateway", "https://cell-gateway.gateway-system.svc:8452",
		"--gateway-id", "spiffe://dev.env.poc.internal/cp/gateway", "--hints-configmap", "spire-system/attest-hints"}, stepFlags()...)
}

// stepFlags are the flags that run requires for the provisioning steps.
func stepFlags() []string {
	return []string{"--steps-configmap", "cell-controller-system/cell-steps",
		"--step-status-configmap", "cell-controller-system/step-status"}
}

func fakeDeps(kube kubernetes.Interface, started *int) deps {
	return deps{
		telemetry: func(_ context.Context, stdout io.Writer) (*telemetry.T, error) {
			*started++
			return &telemetry.T{Log: slog.New(slog.NewJSONHandler(stdout, nil)), Meter: noop.NewMeterProvider().Meter("t"),
				Shutdown: func(context.Context) error { return nil }}, nil
		},
		kube: func() (kubernetes.Interface, error) { return kube, nil },
	}
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

func TestCheckModePrintsOneLine(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	keyFile := s.keyFile()
	client := fake.NewClientset()
	store := envd.NewConfigMapStore(client, "spire-system", "cell-records", "dev", []ed25519.PublicKey{s.pub}, slog.New(slog.DiscardHandler))
	cur, _, err := envd.Accept(envd.Empty(), s.bundle(5), "dev", []ed25519.PublicKey{s.pub})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(t.Context(), cur); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()

	args := []string{"check", "--spec-key-file", keyFile, "--env", "dev", "--current-configmap", "spire-system/cell-records"}
	for _, tc := range []struct {
		name  string
		in    mgmtapi.SpecBundle
		code  int
		check func(t *testing.T, m map[string]any)
	}{
		{"accepted", s.bundle(6), 0, func(t *testing.T, m map[string]any) {
			if m["result"] != "accepted" || m["revision"].(map[string]any)["counter"] != float64(6) {
				t.Errorf("got %v", m)
			}
		}},
		{"unchanged", s.bundle(5), 0, func(t *testing.T, m map[string]any) {
			if m["result"] != "unchanged" || m["revision"].(map[string]any)["counter"] != float64(5) {
				t.Errorf("got %v", m)
			}
		}},
		{"older", s.bundle(4), 1, func(t *testing.T, m map[string]any) {
			if m["result"] != "refused" || m["reason"] != "revision_old" || len(m) != 2 {
				t.Errorf("got %v", m)
			}
		}},
		{"foreign_key", other.bundle(6), 1, func(t *testing.T, m map[string]any) {
			if m["result"] != "refused" || m["reason"] != "signature_invalid" {
				t.Errorf("got %v", m)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			started := 0
			code := execute(t.Context(), args, s.stdin(tc.in), &out, fakeDeps(client, &started))
			if code != tc.code {
				t.Fatalf("exit %d, want %d, output %q", code, tc.code, out.String())
			}
			tc.check(t, oneLine(t, out.String()))
			if started != 0 {
				t.Error("check started telemetry")
			}
			for _, a := range client.Actions() {
				if a.GetVerb() != "get" {
					t.Errorf("check made a %s call", a.GetVerb())
				}
			}
		})
	}

	t.Run("bad_input_is_an_error_line", func(t *testing.T) {
		var out bytes.Buffer
		started := 0
		code := execute(t.Context(), args, strings.NewReader("not json"), &out, fakeDeps(client, &started))
		m := oneLine(t, out.String())
		if code != 1 || m["msg"] != "envd failed" || m["level"] != "ERROR" {
			t.Fatalf("exit %d, line %v", code, m)
		}
	})
}

func TestEnvdRequiresFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"no_mode", nil, []string{"usage"}},
		{"unknown_mode", []string{"serve"}, []string{"unknown mode"}},
		{"run", []string{"run"}, []string{"--env", "--expect-id", "--output-configmap", "--peer-bundle", "--peer-trust-domain", "--spec-key-file", "--upstream"}},
		{"check", []string{"check"}, []string{"--current-configmap", "--env", "--spec-key-file"}},
		{"extra_argument", []string{"check", "--env", "dev", "x"}, []string{"unexpected argument"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			started := 0
			code := execute(t.Context(), tc.args, strings.NewReader(""), &out, fakeDeps(fake.NewClientset(), &started))
			if code != exitConfig {
				t.Fatalf("exit %d", code)
			}
			m := oneLine(t, out.String())
			msg, _ := m["error"].(string)
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

func TestLogsAreJSON(t *testing.T) {
	s := newSigner(t)
	td := spiffetest.NewCA(t, "mgmt.poc.internal")
	dir := t.TempDir()
	bundlePEM, err := td.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(dir, "peer.pem")
	if err := os.WriteFile(peer, bundlePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset()
	started := 0
	d := fakeDeps(client, &started)
	envCA := spiffetest.NewCA(t, "dev.env.poc.internal")
	d.svids = workloadSource(t, envCA)
	args := append([]string{"run", "--upstream", "127.0.0.1:1", "--expect-id", "spiffe://mgmt.poc.internal/api",
		"--peer-bundle", peer, "--peer-trust-domain", "mgmt.poc.internal", "--spec-key-file", s.keyFile(),
		"--env", "dev", "--output-configmap", "spire-system/cell-records", "--interval", "50ms", "--health-listen", "127.0.0.1:0"},
		gatewayFlags()...)

	var out syncBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() { done <- execute(ctx, args, strings.NewReader(""), &out, d) }()

	var health string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(out.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "envd started" {
				health, _ = m["health"].(string)
			}
		}
		if health != "" && strings.Contains(out.String(), "pull failed") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if health == "" {
		t.Fatalf("envd did not start: %q", out.String())
	}
	var status int
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + health + "/healthz")
		if err == nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
		}
		if status == http.StatusOK {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status != http.StatusOK {
		t.Errorf("healthz %d while management is unreachable", status)
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

func TestRunRefusesExpectIDOutsideTrustDomain(t *testing.T) {
	s := newSigner(t)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	pem, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(t.TempDir(), "peer.pem")
	if err := os.WriteFile(peer, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	args := func(id string) []string {
		return append([]string{"--upstream", "x:1", "--expect-id", id, "--peer-bundle", peer, "--peer-trust-domain", "mgmt.poc.internal",
			"--spec-key-file", s.keyFile(), "--env", "dev", "--output-configmap", "a/b",
			"--gateway", "https://cell-gateway.gateway-system.svc:8452", "--gateway-id", "spiffe://dev.env.poc.internal/cp/gateway",
			"--hints-configmap", "spire-system/attest-hints"}, stepFlags()...)
	}
	if _, err := parseRun(args("spiffe://mgmt.poc.internal/api")); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := parseRun(args("spiffe://other.poc.internal/api")); err == nil || !strings.Contains(err.Error(), "--expect-id") {
		t.Fatalf("expect-id outside the trust domain: %v", err)
	}
}

func TestHealthServerLimits(t *testing.T) {
	srv := newHealthServer(http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("limits %v %v %v %v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}

func TestEnvdRequiresGatewayFlags(t *testing.T) {
	s := newSigner(t)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	pem, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(t.TempDir(), "peer.pem")
	if err := os.WriteFile(peer, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--upstream", "x:1", "--expect-id", "spiffe://mgmt.poc.internal/api", "--peer-bundle", peer,
		"--peer-trust-domain", "mgmt.poc.internal", "--spec-key-file", s.keyFile(), "--env", "dev", "--output-configmap", "a/b"}
	if _, err := parseRun(append(slices.Clone(base), gatewayFlags()...)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, flag := range []string{"--gateway", "--gateway-id", "--hints-configmap"} {
		var rest []string
		g := gatewayFlags()
		for i := 0; i < len(g); i += 2 {
			if g[i] != flag {
				rest = append(rest, g[i], g[i+1])
			}
		}
		_, err := parseRun(append(slices.Clone(base), rest...))
		if err == nil || !slices.Contains(strings.Split(strings.TrimSuffix(err.Error(), " required"), ", "), flag) {
			t.Errorf("without %s: %v", flag, err)
		}
	}
	var out bytes.Buffer
	started := 0
	code := execute(t.Context(), append([]string{"run"}, base...), strings.NewReader(""), &out, fakeDeps(fake.NewClientset(), &started))
	m := oneLine(t, out.String())
	msg, _ := m["error"].(string)
	if code != exitConfig || started != 0 || !strings.Contains(msg, "--gateway") || !strings.Contains(msg, "--hints-configmap") {
		t.Fatalf("exit %d, started %d, error %q", code, started, msg)
	}
	for name, val := range map[string]string{"http_scheme": "http://cell-gateway:8452", "query": "https://g:1?x=y", "empty_query": "https://g:1?", "fragment": "https://g:1#f", "user": "https://u@g:1", "no_host": "https://", "with_path": "https://g:1/x", "not_a_url": "::"} {
		args := append(slices.Clone(base), "--gateway", val, "--gateway-id", "spiffe://dev.env.poc.internal/cp/gateway", "--hints-configmap", "a/b")
		args = append(args, stepFlags()...)
		if _, err := parseRun(args); err == nil {
			t.Errorf("%s: --gateway %q accepted", name, val)
		}
	}
	bad := append(slices.Clone(base), "--gateway", "https://g:1", "--gateway-id", "not an id", "--hints-configmap", "a/b")
	bad = append(bad, stepFlags()...)
	if _, err := parseRun(bad); err == nil || !strings.Contains(err.Error(), "--gateway-id") {
		t.Errorf("bad gateway id: %v", err)
	}
}

func TestEnvdRequiresStepFlags(t *testing.T) {
	s := newSigner(t)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	pem, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(t.TempDir(), "peer.pem")
	if err := os.WriteFile(peer, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	key := s.keyFile()
	base := []string{"--upstream", "x:1", "--expect-id", "spiffe://mgmt.poc.internal/api", "--peer-bundle", peer,
		"--peer-trust-domain", "mgmt.poc.internal", "--spec-key-file", key, "--env", "dev", "--output-configmap", "a/b"}
	full := append(append(slices.Clone(base), gatewayFlags()[:6]...), stepFlags()...)
	cfg, err := parseRun(full)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if cfg.stepsNS != "cell-controller-system" || cfg.stepsName != "cell-steps" ||
		cfg.statusNS != "cell-controller-system" || cfg.statusName != "step-status" {
		t.Fatalf("parsed %+v", cfg)
	}
	for _, flag := range []string{"--steps-configmap", "--step-status-configmap"} {
		t.Run("missing"+flag, func(t *testing.T) {
			var args []string
			for i := 0; i < len(full); i++ {
				if full[i] == flag {
					i++
					continue
				}
				args = append(args, full[i])
			}
			_, err := parseRun(args)
			if err == nil || !slices.Contains(strings.Split(strings.TrimSuffix(err.Error(), " required"), ", "), flag) {
				t.Fatalf("without %s: %v", flag, err)
			}
			var out bytes.Buffer
			started := 0
			code := execute(t.Context(), append([]string{"run"}, args...), strings.NewReader(""), &out, fakeDeps(fake.NewClientset(), &started))
			msg, _ := oneLine(t, out.String())["error"].(string)
			if code != exitConfig || started != 0 || !strings.Contains(msg, flag) {
				t.Fatalf("exit %d, started %d, error %q", code, started, msg)
			}
		})
	}
	for name, v := range map[string]string{"no_slash": "cell-steps", "empty_name": "ns/", "empty_ns": "/n", "extra_slash": "a/b/c"} {
		for _, flag := range []string{"--steps-configmap", "--step-status-configmap"} {
			args := slices.Clone(full)
			i := slices.Index(args, flag)
			args[i+1] = v
			if _, err := parseRun(args); err == nil || !strings.Contains(err.Error(), flag) {
				t.Errorf("%s %s=%q: %v", name, flag, v, err)
			}
		}
	}
	t.Run("check_needs_neither", func(t *testing.T) {
		var out bytes.Buffer
		started := 0
		code := execute(t.Context(), []string{"check", "--env", "dev", "--spec-key-file", key, "--current-configmap", "a/b"},
			s.stdin(s.bundle(1)), &out, fakeDeps(fake.NewClientset(), &started))
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out.String())
		}
		if m := oneLine(t, out.String()); m["result"] != "accepted" {
			t.Fatalf("result %v", m)
		}
	})
}

// A log line of envd carries trace_id when the round runs under a span.
func TestRunLogLinesCarryTraceID(t *testing.T) {
	s := newSigner(t)
	td := spiffetest.NewCA(t, "mgmt.poc.internal")
	pem, err := td.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(t.TempDir(), "peer.pem")
	if err := os.WriteFile(peer, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	d := fakeDeps(fake.NewClientset(), new(int))
	d.telemetry = func(_ context.Context, stdout io.Writer) (*telemetry.T, error) {
		return &telemetry.T{Log: telemetry.NewLogger(stdout, slog.DiscardHandler), Meter: noop.NewMeterProvider().Meter("t"),
			Tracer: sdktrace.NewTracerProvider().Tracer("t"), Shutdown: func(context.Context) error { return nil }}, nil
	}
	d.svids = workloadSource(t, spiffetest.NewCA(t, "dev.env.poc.internal"))
	args := append([]string{"run", "--upstream", "127.0.0.1:1", "--expect-id", "spiffe://mgmt.poc.internal/api",
		"--peer-bundle", peer, "--peer-trust-domain", "mgmt.poc.internal", "--spec-key-file", s.keyFile(),
		"--env", "dev", "--output-configmap", "spire-system/cell-records", "--interval", "50ms", "--health-listen", "127.0.0.1:0"},
		gatewayFlags()...)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() { done <- execute(ctx, args, strings.NewReader(""), &out, d) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), "pull failed") {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	var found bool
	for _, l := range strings.Split(out.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "pull failed" {
			found = true
			if id, _ := m["trace_id"].(string); len(id) != 32 {
				t.Errorf("line %q has no trace_id", l)
			}
		}
	}
	if !found {
		t.Fatalf("no pull failure line in %q", out.String())
	}
}

// The clients of envd add the traceparent of the span of the request.
func TestTracedClientAddsTraceparent(t *testing.T) {
	var got http.Header
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	ctx, span := sdktrace.NewTracerProvider().Tracer("t").Start(t.Context(), "round")
	defer span.End()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := tracedClient(&tls.Config{RootCAs: pool}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if tp := got.Get("Traceparent"); !strings.Contains(tp, span.SpanContext().TraceID().String()) {
		t.Fatalf("traceparent %q", tp)
	}
}

// The gateway client of serve authorizes --gateway-id and no other ID, trusts the bundle of the envd
// trust domain, and adds the traceparent header.
func TestNewClientsBuildsGatewayClient(t *testing.T) {
	envCA := spiffetest.NewCA(t, "dev.env.poc.internal")
	mgmtCA := spiffetest.NewCA(t, "mgmt.poc.internal")
	const gwID = "spiffe://dev.env.poc.internal/cp/gateway"
	var mu sync.Mutex
	var headers []http.Header
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		headers = append(headers, r.Header.Clone())
		mu.Unlock()
		_, _ = io.WriteString(w, `{"items":[],"status":{}}`)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: tlsconfig.MTLSServerConfig(envCA.Source(t, gwID), envCA.Bundle(), tlsconfig.AuthorizeAny())}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	cfg := runConfig{expect: spiffeid.RequireFromString("spiffe://mgmt.poc.internal/api"), peer: mgmtCA.Bundle(),
		gateway: "https://" + ln.Addr().String(), gatewayID: spiffeid.RequireFromString(gwID)}
	src := workloadSource(t, envCA)
	svids, closeFn, _ := src(t.Context())
	defer closeFn()
	mgmt, gw, err := newClients(svids, cfg)
	if err != nil || mgmt == nil {
		t.Fatalf("newClients: %v", err)
	}
	ctx, span := sdktrace.NewTracerProvider().Tracer("t").Start(t.Context(), "round")
	defer span.End()
	if _, err := gw.Sync(ctx, gwapi.SyncRequest{}); err != nil {
		t.Fatalf("sync with the gateway ID that --gateway-id names: %v", err)
	}
	mu.Lock()
	if len(headers) != 1 || !strings.Contains(headers[0].Get("Traceparent"), span.SpanContext().TraceID().String()) {
		t.Errorf("gateway request headers %v carry no traceparent of the round", headers)
	}
	mu.Unlock()

	// Another workload ID in the same trust domain is refused.
	cfg.gatewayID = spiffeid.RequireFromString("spiffe://dev.env.poc.internal/cp/other")
	_, other, err := newClients(svids, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Sync(ctx, gwapi.SyncRequest{}); err == nil {
		t.Error("a gateway with another ID was accepted")
	}

	// --gateway-id outside the trust domain of the SVID is a configuration error.
	cfg.gatewayID = spiffeid.RequireFromString("spiffe://other.poc.internal/cp/gateway")
	if _, _, err := newClients(svids, cfg); err == nil || !strings.Contains(err.Error(), "--gateway-id") {
		t.Errorf("gateway ID in another trust domain: %v", err)
	}
	// A source with no bundles is a configuration error too.
	cfg.gatewayID = spiffeid.RequireFromString(gwID)
	if _, _, err := newClients(envCA.Source(t, "spiffe://dev.env.poc.internal/envd"), cfg); err == nil {
		t.Error("a source with no bundles was accepted")
	}
}

// pullerConfig wires the step store and the step status to the ConfigMaps of the flags.
func TestPullerConfigWiresStepConfigMaps(t *testing.T) {
	s := newSigner(t)
	cfg := runConfig{upstream: "x:1", env: "dev", key: s.pub, namespace: "spire-system", configMap: "cell-records",
		hintsNS: "spire-system", hintsName: "hints", stepsNS: "steps-ns", stepsName: "steps-name",
		statusNS: "status-ns", statusName: "status-name", interval: time.Second}
	kube := fake.NewClientset()
	tel := &telemetry.T{Log: slog.New(slog.DiscardHandler), Meter: noop.NewMeterProvider().Meter("t")}
	pc := pullerConfig(cfg, kube, &http.Client{}, nil, tel)
	if pc.Steps == nil || pc.StepStatus == nil || pc.Env != "dev" || pc.BaseURL != "https://x:1" {
		t.Fatalf("config %+v", pc)
	}

	// The step store writes the ConfigMap of --steps-configmap.
	b := s.bundle(1)
	var sp spec.Spec
	sp.Env, sp.Revision = "dev", spec.Revision{Epoch: 1, Counter: 2}
	_, payload, _ := record.VerifyWithPayload(b.Records["a"], []ed25519.PublicKey{s.pub})
	sp.Cells = []spec.Entry{{Name: "a", Revision: spec.Revision{Epoch: 1, Counter: 1}, RecordSHA256: spec.RecordDigest(payload)}}
	raw, err := spec.Sign(sp, s.priv)
	if err != nil {
		t.Fatal(err)
	}
	st, _, err := envd.Accept(envd.Empty(), mgmtapi.SpecBundle{Spec: raw, Records: b.Records}, "dev", []ed25519.PublicKey{s.pub})
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.Steps.Save(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().ConfigMaps("steps-ns").Get(t.Context(), "steps-name", metav1.GetOptions{}); err != nil {
		t.Fatalf("steps ConfigMap: %v", err)
	}

	// The step status is read from the ConfigMap of --step-status-configmap.
	body := `{"at":"2026-11-12T09:00:00Z","steps":[{"id":"` + strings.Repeat("ab", 16) + `","cell":"d","state":"done"}]}`
	if _, err := kube.CoreV1().ConfigMaps("status-ns").Create(t.Context(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "status-name", Namespace: "status-ns"}, Data: map[string]string{"status.json": body}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	got, _, err := pc.StepStatus.Read(t.Context())
	if err != nil || len(got) != 1 || got[0].Cell != "d" {
		t.Fatalf("step status %v %v", got, err)
	}
}

// planeBase returns the flags of a complete run command.
func planeBase(t *testing.T) []string {
	t.Helper()
	s := newSigner(t)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	pem, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(t.TempDir(), "peer.pem")
	if err := os.WriteFile(peer, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--upstream", "x:1", "--expect-id", "spiffe://mgmt.poc.internal/api", "--peer-bundle", peer,
		"--peer-trust-domain", "mgmt.poc.internal", "--spec-key-file", s.keyFile(), "--env", "dev", "--output-configmap", "a/b"}
	return append(base, gatewayFlags()...)
}

func planeFlags() []string {
	return []string{"--cluster", "dev-cp", "--bundle-mirror", "10.0.0.5:5000", "--bundle-store", "bundle-store.cell-system.svc:5000",
		"--bundle-store-token", "/var/run/secrets/store/token", "--bundle-state-configmap", "envd-system/bundle-state"}
}

func TestEnvdPlaneFlags(t *testing.T) {
	base := planeBase(t)
	plain, err := parseRun(base)
	if err != nil {
		t.Fatalf("without the plane flags: %v", err)
	}
	if plain.bundleMirror != "" || plain.cluster != "" {
		t.Fatalf("plane is on without flags: %+v", plain)
	}
	cfg, err := parseRun(append(slices.Clone(base), planeFlags()...))
	if err != nil {
		t.Fatalf("full plane flags: %v", err)
	}
	if cfg.cluster != "dev-cp" || cfg.bundleMirror != "10.0.0.5:5000" || cfg.bundleStore != "bundle-store.cell-system.svc:5000" ||
		cfg.bundleStoreToken != "/var/run/secrets/store/token" || cfg.bundleNS != "envd-system" || cfg.bundleName != "bundle-state" ||
		cfg.bundleHealthTimeout != 5*time.Minute {
		t.Fatalf("parsed %+v", cfg)
	}
	if cfg2, err := parseRun(append(slices.Clone(base), "--cluster", "dev-cp")); err != nil || cfg2.cluster != "dev-cp" || cfg2.bundleMirror != "" {
		t.Fatalf("cluster alone: %+v %v", cfg2, err)
	}
	if cfg3, err := parseRun(append(append(slices.Clone(base), planeFlags()...), "--bundle-health-timeout", "90s")); err != nil || cfg3.bundleHealthTimeout != 90*time.Second {
		t.Fatalf("health timeout: %+v %v", cfg3, err)
	}
	drop := func(args []string, flag string) []string {
		var out []string
		for i := 0; i < len(args); i++ {
			if args[i] == flag {
				i++
				continue
			}
			out = append(out, args[i])
		}
		return out
	}
	for _, flag := range []string{"--cluster", "--bundle-store", "--bundle-store-token", "--bundle-state-configmap"} {
		t.Run("missing"+flag, func(t *testing.T) {
			_, err := parseRun(append(slices.Clone(base), drop(planeFlags(), flag)...))
			if err == nil || !strings.Contains(err.Error(), flag) {
				t.Fatalf("without %s: %v", flag, err)
			}
		})
	}
	for _, flag := range []string{"--bundle-store", "--bundle-store-token", "--bundle-state-configmap", "--bundle-health-timeout"} {
		t.Run("needs_mirror"+flag, func(t *testing.T) {
			v := "x/y"
			if flag == "--bundle-health-timeout" {
				v = "1m"
			}
			if _, err := parseRun(append(slices.Clone(base), flag, v)); err == nil || !strings.Contains(err.Error(), "--bundle-mirror") {
				t.Fatalf("%s without the mirror: %v", flag, err)
			}
		})
	}
	for name, extra := range map[string][]string{
		"timeout zero":        {"--bundle-health-timeout", "0s"},
		"bad state":           {"--bundle-state-configmap", "nostate"},
		"cluster not a label": {"--cluster", "Dev_CP"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRun(append(append(slices.Clone(base), planeFlags()...), extra...)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPullerConfigWiresCluster(t *testing.T) {
	s := newSigner(t)
	cfg := runConfig{upstream: "x:1", env: "dev", key: s.pub, cluster: "dev-cp", namespace: "n", configMap: "c",
		hintsNS: "n", hintsName: "h", stepsNS: "n", stepsName: "s", statusNS: "n", statusName: "t", interval: time.Second}
	tel := &telemetry.T{Log: slog.New(slog.DiscardHandler), Meter: noop.NewMeterProvider().Meter("t")}
	if pc := pullerConfig(cfg, fake.NewClientset(), &http.Client{}, nil, tel); pc.Cluster != "dev-cp" {
		t.Fatalf("cluster = %q", pc.Cluster)
	}
}

func TestPlaneKeysReadTheFileEachCall(t *testing.T) {
	a, b := newSigner(t), newSigner(t)
	path := filepath.Join(t.TempDir(), "key")
	write := func(s *signer) {
		t.Helper()
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(s.pub)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(a)
	keys := planeKeys(path, a.pub, slog.New(slog.DiscardHandler))
	if got := keys(); len(got) != 1 || !got[0].(ed25519.PublicKey).Equal(a.pub) {
		t.Fatalf("first read %v", got)
	}
	write(b)
	if got := keys(); len(got) != 1 || !got[0].(ed25519.PublicKey).Equal(b.pub) {
		t.Fatalf("second read %v", got)
	}
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := keys(); len(got) != 1 || !got[0].(ed25519.PublicKey).Equal(b.pub) {
		t.Fatalf("after a failed read %v", got)
	}
}

func TestStoreTokenReadsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	read := tokenFromFile(path)
	if got, err := read(); err != nil || got != "tok-1" {
		t.Fatalf("token %q %v", got, err)
	}
	if err := os.WriteFile(path, []byte("tok-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(); got != "tok-2" {
		t.Fatalf("rotated token %q", got)
	}
	if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := read(); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestPlaneKeysStartWithTheStartupKey(t *testing.T) {
	a := newSigner(t)
	keys := planeKeys(filepath.Join(t.TempDir(), "missing"), a.pub, slog.New(slog.DiscardHandler))
	if got := keys(); len(got) != 1 || !got[0].(ed25519.PublicKey).Equal(a.pub) {
		t.Fatalf("keys after a failed first read: %v", got)
	}
}

// TestEngineKeysReadFailureIsAnError checks that the engine gets an error, not the startup key, when
// the key file cannot be read, so that the engine records no signature refusal with a stale key.
func TestEngineKeysReadFailureIsAnError(t *testing.T) {
	b := newSigner(t)
	path := filepath.Join(t.TempDir(), "key")
	keys := engineKeys(path)
	if got, err := keys(); err == nil || len(got) != 0 {
		t.Fatalf("missing file: %v, err %v; want an error and no keys", got, err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(b.pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := keys(); err != nil || len(got) != 1 || !got[0].(ed25519.PublicKey).Equal(b.pub) {
		t.Fatalf("after the file appears: %v, err %v", got, err)
	}
}

// capture holds the engine Config that newPlane built.
type capture struct{ cfg bundleapply.Config }

func (c *capture) build(cfg bundleapply.Config) envd.BundleApplier {
	c.cfg = cfg
	return bundleapply.New(cfg)
}

func TestNewPlaneBuildsTheEngine(t *testing.T) {
	var mirrorHits, storeHits atomic.Int32
	var storeAuth atomic.Value
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mirrorHits.Add(1); http.NotFound(w, r) }))
	defer mirror.Close()
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storeHits.Add(1)
		storeAuth.Store(r.Header.Get("Authorization"))
		if r.URL.Path == "/v2/" {
			return
		}
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer store.Close()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("tok-9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newSigner(t)
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(s.pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := runConfig{env: "dev", cluster: "dev-cp", key: s.pub, keyFile: keyPath, bundleMirror: strings.TrimPrefix(mirror.URL, "http://"),
		bundleStore: strings.TrimPrefix(store.URL, "http://"), bundleStoreToken: tokenPath,
		bundleNS: "envd-system", bundleName: "bundle-state", bundleHealthTimeout: 90 * time.Second}
	tel := &telemetry.T{Log: slog.New(slog.DiscardHandler), Meter: noop.NewMeterProvider().Meter("t")}
	kube := fake.NewClientset()
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	var c capture
	p, err := newPlane(cfg, kube, dyn, tel, c.build)
	if err != nil || p == nil {
		t.Fatalf("newPlane: %v %v", p, err)
	}
	got := c.cfg
	t.Run("role", func(t *testing.T) {
		if got.Role != "cp" {
			t.Errorf("role %q", got.Role)
		}
	})
	t.Run("env and target", func(t *testing.T) {
		if got.Env != "dev" || got.Target != "dev-cp" {
			t.Errorf("env %q target %q", got.Env, got.Target)
		}
	})
	t.Run("health timeout", func(t *testing.T) {
		if got.HealthTimeout != 90*time.Second {
			t.Errorf("health timeout %v", got.HealthTimeout)
		}
	})
	t.Run("holder", func(t *testing.T) {
		if got.Holder == "" {
			t.Error("no holder")
		}
	})
	t.Run("state", func(t *testing.T) {
		st, ok := got.State.(*bundleapply.ConfigMapStore)
		if !ok || st.Namespace != "envd-system" || st.Name != "bundle-state" || st.MadeBy != "envd" || st.Client != kube {
			t.Errorf("state %+v", got.State)
		}
	})
	t.Run("clients", func(t *testing.T) {
		if got.Client != kube || got.Dynamic != dyn {
			t.Errorf("kube or dynamic client missing: %v %v", got.Client, got.Dynamic)
		}
	})
	t.Run("keys", func(t *testing.T) {
		if got.Keys == nil {
			t.Fatal("no keys")
		}
		if ks, err := got.Keys(); err != nil || len(ks) != 1 || !ks[0].(ed25519.PublicKey).Equal(s.pub) {
			t.Errorf("keys %v, err %v", ks, err)
		}
	})
	t.Run("policy", func(t *testing.T) {
		if len(got.Policy.Roles) == 0 {
			t.Error("empty policy")
		}
	})
	t.Run("mirror host", func(t *testing.T) {
		_, _ = got.Mirror.Resolve(t.Context(), "bundles/root", "current")
		if mirrorHits.Load() == 0 || storeHits.Load() != 0 {
			t.Errorf("mirror %d, store %d", mirrorHits.Load(), storeHits.Load())
		}
	})
	t.Run("store host and token", func(t *testing.T) {
		before := mirrorHits.Load()
		_ = got.Store.PushBlob(t.Context(), "bundles/root", fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("x"))), []byte("x"))
		if storeHits.Load() == 0 || mirrorHits.Load() != before {
			t.Errorf("store %d, mirror %d", storeHits.Load(), mirrorHits.Load())
		}
		if a, _ := storeAuth.Load().(string); a != "Bearer tok-9" {
			t.Errorf("authorization %q", a)
		}
	})
	t.Run("store is write only", func(t *testing.T) {
		if err := got.Store.Ping(t.Context()); err == nil {
			t.Error("the store client can read")
		}
	})
	cfg.bundleMirror = "not an address"
	if _, err := newPlane(cfg, fake.NewClientset(), dyn, tel, c.build); err == nil {
		t.Fatal("a bad mirror address was accepted")
	}
}

// operatorKeyFile writes the pin of the operator keys: one standard base64 key on each line.
func operatorKeyFile(t *testing.T, keys ...ed25519.PublicKey) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keys.pub")
	writeOperatorKeys(t, p, keys...)
	return p
}

func writeOperatorKeys(t *testing.T, path string, keys ...ed25519.PublicKey) {
	t.Helper()
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(base64.StdEncoding.EncodeToString(k) + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestEnvdRevocationFlags: --operator-key-file and --revocations-configmap go together. They wire
// the operator keys, read again on each call, the input ConfigMap and the overlay of the store.
func TestEnvdRevocationFlags(t *testing.T) {
	base := planeBase(t)
	a, b := newSigner(t), newSigner(t)
	keyFile := operatorKeyFile(t, a.pub)
	flags := []string{"--operator-key-file", keyFile, "--revocations-configmap", "envd-system/local-revocations"}

	plain, err := parseRun(base)
	if err != nil || plain.operatorKeyFile != "" {
		t.Fatalf("without the flags: %+v %v", plain, err)
	}
	tel := &telemetry.T{Log: slog.New(slog.DiscardHandler), Meter: noop.NewMeterProvider().Meter("t")}
	if pc := pullerConfig(plain, fake.NewClientset(), &http.Client{}, nil, tel); pc.OperatorKeys != nil || pc.Revocations != nil {
		t.Fatalf("overlay on without flags: %+v", pc)
	}

	cfg, err := parseRun(append(slices.Clone(base), flags...))
	if err != nil {
		t.Fatalf("with the flags: %v", err)
	}
	if cfg.operatorKeyFile != keyFile || cfg.revocationsNS != "envd-system" || cfg.revocationsName != "local-revocations" {
		t.Fatalf("parsed %+v", cfg)
	}
	kube := fake.NewClientset()
	pc := pullerConfig(cfg, kube, &http.Client{}, nil, tel)
	src, ok := pc.Revocations.(envd.ConfigMapRevocations)
	if !ok || src.Client != kube || src.Namespace != "envd-system" || src.Name != "local-revocations" {
		t.Fatalf("revocation source %#v", pc.Revocations)
	}
	if got := pc.OperatorKeys(); len(got) != 1 || !got[0].Equal(a.pub) {
		t.Fatalf("operator keys %v", got)
	}
	writeOperatorKeys(t, keyFile, a.pub, b.pub)
	if got := pc.OperatorKeys(); len(got) != 2 || !got[1].Equal(b.pub) {
		t.Fatalf("operator keys after a rotation %v", got)
	}
	if err := os.WriteFile(keyFile, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := pc.OperatorKeys(); len(got) != 2 {
		t.Fatalf("operator keys after a failed read %v, want the last keys that loaded", got)
	}

	// The store of the puller keeps the overlay key of its ConfigMap.
	st, _, err := envd.Accept(envd.Empty(), a.bundle(1), "dev", []ed25519.PublicKey{a.pub})
	if err != nil {
		t.Fatal(err)
	}
	writeOperatorKeys(t, keyFile, a.pub)
	cfg.key = a.pub
	pc = pullerConfig(cfg, kube, &http.Client{}, nil, tel)
	if err := pc.Store.Save(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	cm, err := kube.CoreV1().ConfigMaps(cfg.namespace).Get(t.Context(), cfg.configMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data[envd.RevocationsKey] = "[]"
	if _, err := kube.CoreV1().ConfigMaps(cfg.namespace).Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, clean, err := pc.Store.Peek(t.Context()); err != nil || clean {
		t.Fatalf("an empty overlay key: clean %v, err %v, want not clean", clean, err)
	}

	for name, extra := range map[string][]string{
		"key file alone":      {"--operator-key-file", keyFile},
		"configmap alone":     {"--revocations-configmap", "envd-system/local-revocations"},
		"missing key file":    {"--operator-key-file", filepath.Join(t.TempDir(), "absent"), "--revocations-configmap", "envd-system/local-revocations"},
		"bad key file":        {"--operator-key-file", a.keyFile() + ".bad", "--revocations-configmap", "envd-system/local-revocations"},
		"bad configmap":       {"--operator-key-file", keyFile, "--revocations-configmap", "local-revocations"},
		"three keys in a pin": {"--operator-key-file", operatorKeyFile(t, a.pub, b.pub, newSigner(t).pub), "--revocations-configmap", "a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "bad key file" {
				if err := os.WriteFile(extra[1], []byte("not a key\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := parseRun(append(slices.Clone(base), extra...)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
