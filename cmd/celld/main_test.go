package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"

	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
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

func TestRejectsArguments(t *testing.T) {
	var out bytes.Buffer
	if code := execute(t.Context(), []string{"serve"}, &out, testTelemetry(discard())); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	lines := jsonLines(t, out.String())
	if len(lines) != 1 || lines[0]["level"] != "ERROR" || lines[0]["error"] != "celld takes no arguments" {
		t.Fatalf("output is %v, want one JSON error line", lines)
	}
}

func TestFailsWithoutWorkloadAPISocket(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	var out bytes.Buffer
	if code := execute(t.Context(), nil, &out, testTelemetry(discard())); code != 1 {
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
	go func() { done <- execute(ctx, nil, out, testTelemetry(recordHandler{&mu, &exported})) }()

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
