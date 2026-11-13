package hostsvc

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

func TestFileLimit(t *testing.T) {
	if got := FilesNeeded(); got != 1024+16+64 {
		t.Fatalf("FilesNeeded = %d, want 1104", got)
	}
	if err := CheckFileLimit(1104); err != nil {
		t.Errorf("limit of 1104: %v", err)
	}
	err := CheckFileLimit(256)
	if err == nil || !strings.Contains(err.Error(), "RLIMIT_NOFILE") || !strings.Contains(err.Error(), "256") || !strings.Contains(err.Error(), "1104") {
		t.Errorf("limit of 256: %v, want an error that names the limit and the need", err)
	}
	if err := CheckFileLimit(1103); err == nil {
		t.Error("limit of 1103: want an error")
	}
}

// ServeKeys gives the cap of pending handshakes to the listener, and refuses connections past it.
func TestServeKeysRefusesPastPendingCap(t *testing.T) {
	old := maxPending
	maxPending = 3
	t.Cleanup(func() { maxPending = old })
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	addr, _ := keyServer(t, ca.Bundle(), &lookups{})
	var held []net.Conn
	for range 3 {
		held = append(held, dialPending(t, addr))
	}
	time.Sleep(100 * time.Millisecond)
	for range 3 {
		if !closedWithin(dialPending(t, addr), 2*time.Second) {
			t.Fatal("a connection past the pending cap was not refused")
		}
	}
	for i, c := range held {
		if closedWithin(c, 50*time.Millisecond) {
			t.Errorf("pending connection %d was dropped", i)
		}
	}
}

func refusals(t *testing.T, reader *sdkmetric.ManualReader, reason string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	return sumFor(t, rm, "hostsvc.key.handshake.refusals", "reason", reason)
}

func TestServeKeysCountsRefusalsByReason(t *testing.T) {
	oldPending, oldFirst := maxPending, firstByteTimeout
	maxPending, firstByteTimeout = 2, 100*time.Millisecond
	t.Cleanup(func() { maxPending, firstByteTimeout = oldPending, oldFirst })
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	addr, _ := keyServerMeter(t, ca.Bundle(), &lookups{}, mp.Meter("m"))

	// Two silent sockets fill the pool and then time out. A third and fourth arrive while it is full.
	dialPending(t, addr)
	dialPending(t, addr)
	time.Sleep(20 * time.Millisecond)
	dialPending(t, addr)
	waitFor(t, "pool_full refusals", func() bool { return refusals(t, reader, refusedPoolFull) >= 1 })
	waitFor(t, "handshake_timeout refusals", func() bool { return refusals(t, reader, refusedTimeout) >= 2 })

	// A client with no certificate fails the handshake.
	time.Sleep(200 * time.Millisecond)
	bad := &http.Client{Timeout: 2 * time.Second, Transport: newNoCertTransport()}
	if resp, err := bad.Get("https://" + addr + "/none"); err == nil {
		resp.Body.Close()
	}
	waitFor(t, "handshake_failed refusals", func() bool { return refusals(t, reader, refusedFailed) >= 1 })
}

// A handler reads the verified peer from the request context. Request.TLS is nil.
func TestHandlerReadsPeerFromContext(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	cert, err := SelfSignedCert(KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := PeerID(r.Context())
		got <- id.String() + "|" + boolString(ok) + "|" + boolString(r.TLS == nil)
	})
	log := newDiscardLogger()
	srv := NewKeyServer(h, ServerTLS(cert, ca.Bundle(), spiffeid.RequireFromString(mgmtdID)), log)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ServeKeys(ctx, srv, ln, log, nil) }()
	defer func() { cancel(); <-done }()
	client := newMgmtClient(t, ca)
	resp, err := client.Get("https://" + ln.Addr().String() + "/x")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if v := <-got; v != mgmtdID+"|true|true" {
		t.Errorf("peer, found, TLS is nil = %q, want %q", v, mgmtdID+"|true|true")
	}
	if _, ok := PeerID(context.Background()); ok {
		t.Error("PeerID found a peer in an empty context")
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// A lookup whose probe panics fails, and the service stays usable.
type panicProber struct{}

func (panicProber) Probe(context.Context, string) (Observed, error) { panic("probe exploded") }

func TestFactsRecoversPanic(t *testing.T) {
	rt := &fakeRuntime{clusters: map[string]bool{"rogue": true}}
	s := newTestService(rt, matchingObs())
	s.Prober = panicProber{}
	for range 3 {
		_, err := s.Facts(context.Background(), "rogue")
		if err == nil || !strings.Contains(err.Error(), "panicked") {
			t.Fatalf("Facts error = %v, want a panic error", err)
		}
	}
	s.Prober = fakeProber{obs: matchingObs()}
	if _, err := s.Facts(context.Background(), "rogue"); err != nil {
		t.Fatalf("Facts after the panics: %v", err)
	}
}

// The worker checks the context before it starts the next runtime call.
func TestFactsStopsBeforeKubeconfigWhenContextEnds(t *testing.T) {
	s, rt := stuckService("List")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := s.Facts(ctx, "rogue"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Facts error = %v", err)
	}
	close(rt.release)
	waitFor(t, "the worker to finish", func() bool { return len(s.lookups) == 0 })
	if n := rt.kubeconfigs.Load(); n != 0 {
		t.Errorf("Kubeconfig was called %d times after the context ended, want 0", n)
	}
}

// Down and Up return when the context ends, even while docker hangs.
func TestUpAndDownReturnOnCancelWhileDockerHangs(t *testing.T) {
	for name, call := range map[string]func(*Service, context.Context) error{
		"Down": func(s *Service, ctx context.Context) error { return s.Down(ctx, "rogue") },
		"Up":   func(s *Service, ctx context.Context) error { _, err := s.Up(ctx, "rogue"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			s, rt := stuckService("List")
			defer close(rt.release)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			err := returnsWithin(t, 2*time.Second, func() error { return call(s, ctx) })
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("error = %v, want deadline exceeded", err)
			}
		})
	}
}
