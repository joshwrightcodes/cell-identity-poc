package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

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
	return []string{"--gateway", "https://cell-gateway.gateway-system.svc:8452",
		"--gateway-id", "spiffe://dev.env.poc.internal/cp/gateway", "--hints-configmap", "spire-system/attest-hints"}
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
		return []string{"--upstream", "x:1", "--expect-id", id, "--peer-bundle", peer, "--peer-trust-domain", "mgmt.poc.internal",
			"--spec-key-file", s.keyFile(), "--env", "dev", "--output-configmap", "a/b",
			"--gateway", "https://cell-gateway.gateway-system.svc:8452", "--gateway-id", "spiffe://dev.env.poc.internal/cp/gateway",
			"--hints-configmap", "spire-system/attest-hints"}
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
		if _, err := parseRun(args); err == nil {
			t.Errorf("%s: --gateway %q accepted", name, val)
		}
	}
	bad := append(slices.Clone(base), "--gateway", "https://g:1", "--gateway-id", "not an id", "--hints-configmap", "a/b")
	if _, err := parseRun(bad); err == nil || !strings.Contains(err.Error(), "--gateway-id") {
		t.Errorf("bad gateway id: %v", err)
	}
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
