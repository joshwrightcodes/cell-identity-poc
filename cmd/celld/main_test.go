package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bind"
	"github.com/joshwrightcodes/cell-identity-poc/internal/executor"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

const testID = "spiffe://dev.env.poc.internal/cell/dev-cell-1/celld"

// syncBuffer is a bytes.Buffer that the test can read while celld writes to it.
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

// recordHandler keeps the messages of the records that reach the OTLP side of the logger.
type recordHandler struct {
	mu   *sync.Mutex
	msgs *[]string
}

func (h recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.msgs = append(*h.msgs, r.Message)
	return nil
}
func (h recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h recordHandler) WithGroup(string) slog.Handler      { return h }

// testTelemetry exports nothing. Spans are sampled, so their IDs reach the log lines.
func testTelemetry(otlp slog.Handler) telemetryStarter {
	return func(_ context.Context, stdout io.Writer) (*telemetry.T, error) {
		tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
		return &telemetry.T{
			Log:      telemetry.NewLogger(stdout, otlp),
			Tracer:   tp.Tracer("test"),
			Meter:    noop.NewMeterProvider().Meter("test"),
			Shutdown: tp.Shutdown,
		}, nil
	}
}

func discard() slog.Handler { return slog.DiscardHandler }

func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		var m map[string]any
		if err := json.Unmarshal(s.Bytes(), &m); err != nil {
			t.Fatalf("output line is not JSON: %q", s.Text())
		}
		lines = append(lines, m)
	}
	return lines
}

// blockingBind stands in for bind.Run: it returns when ctx ends.
func blockingBind(ctx context.Context, _ bind.Config) error {
	<-ctx.Done()
	return ctx.Err()
}

func fakeKubeClient() (kubernetes.Interface, error) {
	return fake.NewClientset(), nil
}

// blockingStream stands in for executor.RunStream: it returns when ctx ends.
func blockingStream(ctx context.Context, _ executor.StreamConfig) error {
	<-ctx.Done()
	return ctx.Err()
}

const (
	gwTD   = "dev.env.poc.internal"
	gwID   = "spiffe://dev.env.poc.internal/cp/gateway"
	gwAddr = "127.0.0.1:1"
)

// opKeyDir returns a directory with the key files that a ConfigMap mount holds.
func opKeyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"op.pub", "op.next.pub"} {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testEnv(name string) (string, bool) {
	v, ok := map[string]string{"POD_NAME": "celld-abc", "POD_UID": "uid-1", "POD_NAMESPACE": "cell-identity-system", "SERVICE_ACCOUNT": "celld"}[name]
	return v, ok
}

func testDeps(start telemetryStarter) deps {
	return deps{start: start, lookupEnv: testEnv, kubeClient: fakeKubeClient, bindRun: blockingBind, streamRun: blockingStream}
}

func bundleFile(t *testing.T) string {
	t.Helper()
	pem, err := spiffetest.NewCA(t, gwTD).Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validArgs(t *testing.T) []string {
	t.Helper()
	return gatewayArgs(gwAddr, "127.0.0.1:2", gwID, bundleFile(t), opKeyDir(t))
}

func gatewayArgs(stream, bindAddr, id, bundle, keys string) []string {
	return []string{
		"--cell", "dev-cell-1", "--env", "dev", "--gateway", stream, "--gateway-bind", bindAddr, "--gateway-id", id,
		"--trust-bundle", bundle, "--op-key-dir", keys, "--ops-namespace", "cell-ops-system",
	}
}

func TestCelldRequiresGatewayFlags(t *testing.T) {
	base := validArgs(t)
	without := func(flag string) []string {
		var out []string
		for i := 0; i < len(base); i += 2 {
			if base[i] != flag {
				out = append(out, base[i], base[i+1])
			}
		}
		return out
	}
	empty := t.TempDir()
	badKey := t.TempDir()
	if err := os.WriteFile(filepath.Join(badKey, "op.pub"), []byte("not base64 of a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no arguments":    nil,
		"positional":      append(slices.Clone(base), "serve"),
		"unknown flag":    append(slices.Clone(base), "--verbose"),
		"retired flag":    append(slices.Clone(base), "--bind-upstream", "h:1"),
		"id not spiffe":   gatewayArgs("h:1", "h:2", "https://x/gw", base[11], base[13]),
		"no key files":    gatewayArgs("h:1", "h:2", gwID, base[11], empty),
		"key not a key":   gatewayArgs("h:1", "h:2", gwID, base[11], badKey),
		"key dir missing": gatewayArgs("h:1", "h:2", gwID, base[11], "/nonexistent/keys"),
	}
	for _, flag := range []string{"--cell", "--env", "--gateway", "--gateway-bind", "--gateway-id", "--trust-bundle", "--op-key-dir", "--ops-namespace"} {
		cases["missing "+flag] = without(flag)
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := execute(t.Context(), args, &out, testDeps(testTelemetry(discard()))); code != 1 {
				t.Fatalf("exit code %d, want 1", code)
			}
			lines := jsonLines(t, out.String())
			if len(lines) != 1 || lines[0]["level"] != "ERROR" || lines[0]["error"] == nil {
				t.Fatalf("output is %v, want one JSON error line", lines)
			}
		})
	}
	for _, name := range []string{"POD_NAME", "POD_UID", "POD_NAMESPACE", "SERVICE_ACCOUNT"} {
		t.Run("env "+name, func(t *testing.T) {
			d := testDeps(testTelemetry(discard()))
			d.lookupEnv = func(n string) (string, bool) {
				if n == name {
					return "", false
				}
				return testEnv(n)
			}
			var out bytes.Buffer
			if code := execute(t.Context(), base, &out, d); code != 1 {
				t.Fatalf("exit code %d, want 1", code)
			}
			if lines := jsonLines(t, out.String()); len(lines) != 1 || !strings.Contains(lines[0]["error"].(string), name) {
				t.Fatalf("output is %v, want one error line that names %s", lines, name)
			}
		})
	}
}

func TestLoadOpKeysReadsEveryPubFile(t *testing.T) {
	keys, err := loadOpKeys(opKeyDir(t))
	if err != nil || len(keys) != 2 {
		t.Fatalf("%d keys, %v, want the two *.pub files", len(keys), err)
	}
}

func TestCelldPassesTheGatewayConfig(t *testing.T) {
	var gotBind bind.Config
	var gotStream executor.StreamConfig
	var mu sync.Mutex
	d := testDeps(testTelemetry(discard()))
	d.bindRun = func(ctx context.Context, cfg bind.Config) error {
		mu.Lock()
		gotBind = cfg
		mu.Unlock()
		return blockingBind(ctx, cfg)
	}
	d.streamRun = func(ctx context.Context, cfg executor.StreamConfig) error {
		mu.Lock()
		gotStream = cfg
		mu.Unlock()
		return blockingStream(ctx, cfg)
	}
	_, addr := serveWorkloadAPI(t)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", addr)
	ctx, cancel := context.WithCancel(t.Context())
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- execute(ctx, validArgs(t), out, d) }()
	waitForLines(t, out, "watching the workload api", 1)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if gotBind.Cell != "dev-cell-1" || gotBind.Upstream != "127.0.0.1:2" || gotBind.TLS == nil || gotBind.Tokens == nil || gotBind.Log == nil || gotBind.Observe == nil {
		t.Fatalf("bind config %+v", gotBind)
	}
	if gotStream.Cell != "dev-cell-1" || gotStream.Upstream != gwAddr || gotStream.TLS == nil || gotStream.SVIDUpdates == nil ||
		gotStream.Tokens == nil || gotStream.Exec == nil || gotStream.Status == nil || gotStream.Tracer == nil {
		t.Fatalf("stream config %+v", gotStream)
	}
	st := gotStream.Status()
	if st.Cell != "dev-cell-1" || st.Pod != "celld-abc" || st.PodUID != "uid-1" || st.Version == "" {
		t.Fatalf("status %+v", st)
	}
}

// The SVID watcher is the SVID source of the stream. It signals a new SVID once, and gives the stream
// the SVID and its expiry.
func TestSVIDWatcherFeedsTheStream(t *testing.T) {
	ca := newCA(t)
	var parse = func(serial int64) *x509svid.SVID {
		resp := ca.svid(t, serial).Svids[0]
		svid, err := x509svid.ParseRaw(resp.X509Svid, resp.X509SvidKey)
		if err != nil {
			t.Fatal(err)
		}
		return svid
	}
	first, second := parse(1), parse(2)
	tel, err := testTelemetry(discard())(t.Context(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	w, err := newSVIDWatcher(tel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.GetX509SVID(); err == nil {
		t.Fatal("GetX509SVID gave an SVID before the Workload API sent one")
	}
	if !w.expiry().IsZero() {
		t.Fatal("expiry is not zero before the first SVID")
	}
	w.OnX509ContextUpdate(&workloadapi.X509Context{SVIDs: []*x509svid.SVID{first}})
	w.OnX509ContextUpdate(&workloadapi.X509Context{SVIDs: []*x509svid.SVID{first}})
	if got, err := w.GetX509SVID(); err != nil || got != first {
		t.Fatalf("GetX509SVID = %v, %v", got, err)
	}
	if !w.expiry().Equal(first.Certificates[0].NotAfter) {
		t.Fatalf("expiry %v", w.expiry())
	}
	if len(w.signal) != 1 {
		t.Fatalf("%d signals after a new SVID and a repeat, want 1", len(w.signal))
	}
	<-w.signal
	w.OnX509ContextUpdate(&workloadapi.X509Context{SVIDs: []*x509svid.SVID{second}})
	select {
	case <-w.signal:
	default:
		t.Fatal("no signal for the rotated SVID")
	}
}

// TestCelldServesSVIDWhileGatewayDown runs the real bind loop and the real stream against a closed
// port. The SVID watch keeps running, the bind loop logs each failure, the stream logs each end, and
// the attempt counter counts the bind failures.
func TestCelldServesSVIDWhileGatewayDown(t *testing.T) {
	fake, addr := serveWorkloadAPI(t)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", addr)
	reader := sdkmetric.NewManualReader()
	start := func(ctx context.Context, w io.Writer) (*telemetry.T, error) {
		tel, err := testTelemetry(discard())(ctx, w)
		if err == nil {
			tel.Meter = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
		}
		return tel, err
	}
	d := testDeps(start)
	var bindReturned atomic.Bool
	d.streamRun = func(ctx context.Context, cfg executor.StreamConfig) error {
		cfg.Sleep = fastSleep
		return executor.RunStream(ctx, cfg)
	}
	d.bindRun = func(ctx context.Context, cfg bind.Config) error {
		defer func() {
			time.Sleep(100 * time.Millisecond)
			bindReturned.Store(true)
		}()
		cfg.Sleep = func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Millisecond):
				return nil
			}
		}
		return bind.Run(ctx, cfg)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- execute(ctx, validArgs(t), out, d) }()

	fake.responses <- newCA(t).svid(t, 21)
	waitForLines(t, out, "x509 svid updated", 1)
	failed := waitForLines(t, out, "bind failed", 3)
	if failed[0]["cell"] != "dev-cell-1" || failed[0]["result"] != "error" {
		t.Fatalf("bind failed line is %v", failed[0])
	}
	ended := waitForLines(t, out, "stream ended", 3)
	if ended[0]["cell"] != "dev-cell-1" || ended[0]["error"] == nil {
		t.Fatalf("stream ended line is %v", ended[0])
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit code %d, want 0\n%s", code, out.String())
	}
	if !bindReturned.Load() {
		t.Fatal("execute returned before the bind goroutine did")
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	var errs int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == "celld.bind.attempts" {
				for _, dp := range sum.DataPoints {
					if v, _ := dp.Attributes.Value("result"); v.AsString() == "error" {
						errs += dp.Value
					}
				}
			}
		}
	}
	if errs < 3 {
		t.Fatalf("celld.bind.attempts with result=error is %d, want at least 3", errs)
	}
}

// bindServer is a TLS HTTP/2 server that plays the bind listener of the gateway and records what
// reaches it.
type bindServer struct {
	addr     string
	mu       sync.Mutex
	requests int
	bound    atomic.Bool
	binds    []mgmtapi.BindRequest
}

const bindResultID = "0123456789abcdef0123456789abcdef"

func newBindServer(t *testing.T, ca *spiffetest.CA, serverID string) *bindServer {
	t.Helper()
	s := &bindServer{}
	cfg := tlsconfig.TLSServerConfig(ca.Source(t, serverID))
	cfg.MinVersion, cfg.NextProtos = tls.VersionTLS13, []string{"h2"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+mgmtapi.NoncePattern, func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests++
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(mgmtapi.NonceResponse{Nonce: "nonce1", Audience: mgmtapi.BindAudience(r.PathValue("cell"), "nonce1"), Bound: s.bound.Load()})
	})
	mux.HandleFunc("POST "+mgmtapi.BindPattern, func(w http.ResponseWriter, r *http.Request) {
		var req mgmtapi.BindRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		s.requests++
		s.binds = append(s.binds, req)
		s.mu.Unlock()
		s.bound.Store(true)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(gwapi.BindAccepted{ID: bindResultID})
	})
	mux.HandleFunc("GET "+gwapi.BindResultPattern, func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests++
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(gwapi.BindResult{Status: mgmtapi.StatusBound})
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	srv := &http.Server{Handler: mux, Protocols: protos}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	s.addr = ln.Addr().String()
	return s
}

func (s *bindServer) seen() (int, []mgmtapi.BindRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, append([]mgmtapi.BindRequest(nil), s.binds...)
}

func caBundleFile(t *testing.T, ca *spiffetest.CA) string {
	t.Helper()
	pem, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// tokenRecorder is a fake kube client that answers each TokenRequest with a token and records it.
type tokenRecorder struct {
	mu   sync.Mutex
	reqs []tokenCall
}

type tokenCall struct {
	namespace, serviceAccount string
	req                       *authenticationv1.TokenRequest
}

func (r *tokenRecorder) client() func() (kubernetes.Interface, error) {
	return func() (kubernetes.Interface, error) {
		cs := fake.NewClientset()
		cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(k8stesting.CreateActionImpl)
			if !ok || a.GetSubresource() != "token" {
				return false, nil, nil
			}
			req := ca.GetObject().(*authenticationv1.TokenRequest)
			r.mu.Lock()
			r.reqs = append(r.reqs, tokenCall{ca.GetNamespace(), ca.Name, req.DeepCopy()})
			r.mu.Unlock()
			out := req.DeepCopy()
			out.Status.Token = "pod-token"
			return true, out, nil
		})
		return cs, nil
	}
}

func (r *tokenRecorder) calls() []tokenCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]tokenCall(nil), r.reqs...)
}

func fastSleep(ctx context.Context, _ time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Millisecond):
		return nil
	}
}

func fastBind(ctx context.Context, cfg bind.Config) error {
	cfg.Sleep = fastSleep
	cfg.PollEvery = 5 * time.Millisecond
	return bind.Run(ctx, cfg)
}

func runCelld(t *testing.T, args []string, d deps) (*syncBuffer, func() int) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- execute(ctx, args, out, d) }()
	return out, func() int {
		cancel()
		return <-done
	}
}

func bindArgs(t *testing.T, addr, id, bundle string) []string {
	t.Helper()
	return gatewayArgs(gwAddr, addr, id, bundle, opKeyDir(t))
}

// TestCelldRefusesAWrongGateway runs the real flag wiring and the real bind loop. A server with
// another SPIFFE ID, and a server whose certificate is outside the peer bundle, get no request and
// no token.
func TestCelldRefusesAWrongGateway(t *testing.T) {
	mgmtCA := spiffetest.NewCA(t, gwTD)
	otherCA := spiffetest.NewCA(t, gwTD)
	for name, tc := range map[string]struct {
		ca *spiffetest.CA
		id string
	}{
		"other id same ca":              {mgmtCA, "spiffe://dev.env.poc.internal/cp/other"},
		"certificate not in the bundle": {otherCA, gwID},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newBindServer(t, tc.ca, tc.id)
			rec := &tokenRecorder{}
			d := testDeps(testTelemetry(discard()))
			d.kubeClient, d.bindRun = rec.client(), fastBind
			_, addr := serveWorkloadAPI(t)
			t.Setenv("SPIFFE_ENDPOINT_SOCKET", addr)
			out, stop := runCelld(t, bindArgs(t, srv.addr, gwID, caBundleFile(t, mgmtCA)), d)
			waitForLines(t, out, "bind failed", 3)
			if code := stop(); code != 0 {
				t.Fatalf("exit code %d", code)
			}
			if n, _ := srv.seen(); n != 0 {
				t.Fatalf("%d requests reached the wrong server", n)
			}
			if n := len(rec.calls()); n != 0 {
				t.Fatalf("%d tokens were minted", n)
			}
			if strings.Contains(out.String(), `"msg":"bound"`) {
				t.Fatal("celld logged bound")
			}
		})
	}
}

// TestCelldBindsAsThePod runs the same wiring against the right server and checks the token request.
func TestCelldBindsAsThePod(t *testing.T) {
	mgmtCA := spiffetest.NewCA(t, gwTD)
	srv := newBindServer(t, mgmtCA, gwID)
	rec := &tokenRecorder{}
	d := testDeps(testTelemetry(discard()))
	d.kubeClient, d.bindRun = rec.client(), fastBind
	_, addr := serveWorkloadAPI(t)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", addr)
	out, stop := runCelld(t, bindArgs(t, srv.addr, gwID, caBundleFile(t, mgmtCA)), d)
	bound := waitForLines(t, out, "bound", 1)
	if bound[0]["status"] != mgmtapi.StatusBound || bound[0]["cell"] != "dev-cell-1" {
		t.Fatalf("bound line %v", bound[0])
	}
	if code := stop(); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	calls := rec.calls()
	if len(calls) != 1 {
		t.Fatalf("%d token requests, want 1", len(calls))
	}
	c := calls[0]
	ref := c.req.Spec.BoundObjectRef
	if c.namespace != "cell-identity-system" || c.serviceAccount != "celld" ||
		len(c.req.Spec.Audiences) != 1 || c.req.Spec.Audiences[0] != mgmtapi.BindAudience("dev-cell-1", "nonce1") ||
		ref == nil || ref.Kind != "Pod" || ref.Name != "celld-abc" || string(ref.UID) != "uid-1" {
		t.Fatalf("token request %+v in %s/%s", c.req.Spec, c.namespace, c.serviceAccount)
	}
	if _, binds := srv.seen(); len(binds) != 1 || binds[0].Token != "pod-token" || binds[0].Nonce != "nonce1" {
		t.Fatalf("bind requests %+v", binds)
	}
}

// A bundle file that is missing or unreadable stops the bind only. The SVID watch runs.
func TestCelldServesSVIDWithAMissingBundle(t *testing.T) {
	fake, addr := serveWorkloadAPI(t)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", addr)
	d := testDeps(testTelemetry(discard()))
	d.bindRun = fastBind
	srv := newBindServer(t, spiffetest.NewCA(t, gwTD), gwID)
	out, stop := runCelld(t, bindArgs(t, srv.addr, gwID, "/nonexistent/bundle.pem"), d)
	fake.responses <- newCA(t).svid(t, 31)
	waitForLines(t, out, "x509 svid updated", 1)
	failed := waitForLines(t, out, "bind failed", 2)
	if !strings.Contains(failed[0]["error"].(string), "bundle") {
		t.Fatalf("bind failed line %v", failed[0])
	}
	if code := stop(); code != 0 {
		t.Fatalf("exit code %d", code)
	}
}

func TestFailsWithoutWorkloadAPISocket(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	var out bytes.Buffer
	if code := execute(t.Context(), validArgs(t), &out, testDeps(testTelemetry(discard()))); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	lines := jsonLines(t, out.String())
	last := lines[len(lines)-1]
	if last["level"] != "ERROR" || !strings.Contains(last["error"].(string), "watch the workload api") {
		t.Fatalf("last line is %v, want the watch error", last)
	}
}

// fakeWorkloadAPI streams the responses on its channel to the one FetchX509SVID caller.
type fakeWorkloadAPI struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer
	responses chan *workloadpb.X509SVIDResponse
}

func (f *fakeWorkloadAPI) FetchX509SVID(_ *workloadpb.X509SVIDRequest, stream grpc.ServerStreamingServer[workloadpb.X509SVIDResponse]) error {
	for {
		select {
		case r := <-f.responses:
			if err := stream.Send(r); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	td, _ := url.Parse("spiffe://dev.env.poc.internal")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, URIs: []*url.URL{td},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert, key}
}

// svid returns a Workload API response with one SVID for testID and the given serial number.
func (ca testCA) svid(t *testing.T, serial int64) *workloadpb.X509SVIDResponse {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := url.Parse(testID)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{id},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &workloadpb.X509SVIDResponse{Svids: []*workloadpb.X509SVID{{
		SpiffeId: testID, X509Svid: der, X509SvidKey: pkcs8, Bundle: ca.cert.Raw,
	}}}
}

func serveWorkloadAPI(t *testing.T) (*fakeWorkloadAPI, string) {
	t.Helper()
	// A unix socket path must be short, so the socket does not live in t.TempDir.
	dir, err := os.MkdirTemp("", "celld")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "api.sock")
	lis, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeWorkloadAPI{responses: make(chan *workloadpb.X509SVIDResponse, 4)}
	srv := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return fake, "unix://" + path
}

func waitForLines(t *testing.T, out *syncBuffer, msg string, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var match []map[string]any
		for _, l := range jsonLines(t, out.String()) {
			if l["msg"] == msg {
				match = append(match, l)
			}
		}
		if len(match) >= n {
			return match
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d %q lines, output:\n%s", n, msg, out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLogsEachNewSVIDOnce(t *testing.T) {
	fake, addr := serveWorkloadAPI(t)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", addr)
	ca := newCA(t)
	first := ca.svid(t, 10)

	var mu sync.Mutex
	var exported []string
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, validArgs(t), out, testDeps(testTelemetry(recordHandler{&mu, &exported})))
	}()

	fake.responses <- first
	waitForLines(t, out, "x509 svid updated", 1)
	// The same SVID again, as after a bundle change, then a rotated SVID.
	fake.responses <- first
	fake.responses <- ca.svid(t, 11)
	lines := waitForLines(t, out, "x509 svid updated", 2)

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d after cancel, want 0\n%s", code, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("celld did not stop after cancel")
	}

	lines = waitForLines(t, out, "x509 svid updated", 2)
	if len(lines) != 2 {
		t.Fatalf("got %d update lines, want 2 (one for each new SVID):\n%s", len(lines), out.String())
	}
	for i, wantSerial := range []string{"a", "b"} {
		l := lines[i]
		if l["spiffe_id"] != testID || l["serial"] != wantSerial || l["trace_id"] == nil || l["span_id"] == nil || l["not_after"] == nil {
			t.Fatalf("update line %d is %v", i, l)
		}
	}
	if lines[0]["trace_id"] == lines[1]["trace_id"] {
		t.Fatal("both updates share one trace")
	}
	mu.Lock()
	defer mu.Unlock()
	if n := strings.Count(strings.Join(exported, "\n"), "x509 svid updated"); n != 2 {
		t.Fatalf("OTLP handler got %d update records, want 2: %v", n, exported)
	}
}

// TestSVIDAgainAfterAGap logs the same SVID again after a gap, as held and not as new. Only a new
// SVID adds to the counter, so celld.svid.updates counts new SVIDs.
func TestSVIDAgainAfterAGap(t *testing.T) {
	ca := newCA(t)
	resp := ca.svid(t, 8).Svids[0]
	svid, err := x509svid.ParseRaw(resp.X509Svid, resp.X509SvidKey)
	if err != nil {
		t.Fatal(err)
	}
	rotated := ca.svid(t, 9).Svids[0]
	next, err := x509svid.ParseRaw(rotated.X509Svid, rotated.X509SvidKey)
	if err != nil {
		t.Fatal(err)
	}
	gaps := map[string]func(w *svidWatcher){
		"watch error": func(w *svidWatcher) {
			w.OnX509ContextWatchError(errors.New("rpc error: code = PermissionDenied desc = no identity issued"))
		},
		"empty update": func(w *svidWatcher) { w.OnX509ContextUpdate(&workloadapi.X509Context{}) },
	}
	for name, gap := range gaps {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			reader := sdkmetric.NewManualReader()
			tel, err := testTelemetry(discard())(t.Context(), &out)
			if err != nil {
				t.Fatal(err)
			}
			tel.Meter = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
			w, err := newSVIDWatcher(tel)
			if err != nil {
				t.Fatal(err)
			}
			w.OnX509ContextUpdate(&workloadapi.X509Context{SVIDs: []*x509svid.SVID{svid}})
			gap(w)
			w.OnX509ContextUpdate(&workloadapi.X509Context{SVIDs: []*x509svid.SVID{svid}})
			w.OnX509ContextUpdate(&workloadapi.X509Context{SVIDs: []*x509svid.SVID{svid}})
			w.OnX509ContextUpdate(&workloadapi.X509Context{SVIDs: []*x509svid.SVID{next}})
			var msgs []string
			for _, l := range jsonLines(t, out.String()) {
				msgs = append(msgs, l["msg"].(string))
			}
			gapMsg := map[string]string{"watch error": "workload api watch failed", "empty update": "workload api update without an svid"}[name]
			want := []string{"x509 svid updated", gapMsg, "x509 svid held", "x509 svid updated"}
			if !slices.Equal(msgs, want) {
				t.Fatalf("messages are %v, want %v", msgs, want)
			}
			var rm metricdata.ResourceMetrics
			if err := reader.Collect(t.Context(), &rm); err != nil {
				t.Fatal(err)
			}
			var total int64
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					if sum, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == "celld.svid.updates" {
						for _, dp := range sum.DataPoints {
							total += dp.Value
						}
					}
				}
			}
			if total != 2 {
				t.Fatalf("celld.svid.updates is %d, want 2: one for each new SVID", total)
			}
		})
	}
}
