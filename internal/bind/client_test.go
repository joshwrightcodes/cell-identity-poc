package bind

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

const (
	mgmtTD  = "mgmt.poc.internal"
	apiID   = "spiffe://mgmt.poc.internal/api"
	testCel = "dev-cell-1"
)

// fakeServer plays the bind listener of mgmtd. It records requests and answers through handlers.
type fakeServer struct {
	addr       string
	ca         *spiffetest.CA
	handshakes atomic.Int64
	peerCerts  atomic.Int64
	mu         sync.Mutex
	nonceBody  []string
	nonce      func(w http.ResponseWriter, r *http.Request, n int)
	bind       func(w http.ResponseWriter, r *http.Request, req mgmtapi.BindRequest, n int)
	nonceCalls int
	bindCalls  int
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func okNonce(bound bool) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, r *http.Request, n int) {
		nonce := "nonce" + string(rune('a'+n))
		writeJSON(w, 200, mgmtapi.NonceResponse{Nonce: nonce, Audience: mgmtapi.BindAudience(testCel, nonce), Bound: bound})
	}
}

func okBind(w http.ResponseWriter, _ *http.Request, _ mgmtapi.BindRequest, _ int) {
	writeJSON(w, 200, mgmtapi.BindResponse{Status: mgmtapi.StatusBound, Record: spec.Revision{Epoch: 1, Counter: 2}})
}

func denied(w http.ResponseWriter) {
	writeJSON(w, 403, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: "0123456789abcdef"})
}

func newServer(t *testing.T, serverID string) *fakeServer {
	t.Helper()
	f := &fakeServer{ca: spiffetest.NewCA(t, mgmtTD), nonce: okNonce(false), bind: okBind}
	cfg := tlsconfig.TLSServerConfig(f.ca.Source(t, serverID))
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos = []string{"h2"}
	cfg.ClientAuth = tls.RequestClientCert
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		f.handshakes.Add(1)
		f.peerCerts.Add(int64(len(cs.PeerCertificates)))
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc(mgmtapi.NoncePattern, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.nonceBody = append(f.nonceBody, string(body))
		n := f.nonceCalls
		f.nonceCalls++
		h := f.nonce
		f.mu.Unlock()
		h(w, r, n)
	})
	mux.HandleFunc(mgmtapi.BindPattern, func(w http.ResponseWriter, r *http.Request) {
		var req mgmtapi.BindRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		n := f.bindCalls
		f.bindCalls++
		h := f.bind
		f.mu.Unlock()
		h(w, r, req, n)
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
	f.addr = ln.Addr().String()
	return f
}

func (f *fakeServer) counts() (nonce, bind int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nonceCalls, f.bindCalls
}

func (f *fakeServer) config(t *testing.T, expect string) Config {
	t.Helper()
	id := spiffeid.RequireFromString(expect)
	return Config{
		Cell: testCel, Upstream: f.addr, TLS: ClientTLS(f.ca.Bundle(), id),
		Tokens: func(_ context.Context, aud string) (string, error) { return "tok:" + aud, nil },
		Log:    slog.New(slog.DiscardHandler),
	}
}

func TestOnceBinds(t *testing.T) {
	f := newServer(t, apiID)
	var gotReq mgmtapi.BindRequest
	f.bind = func(w http.ResponseWriter, r *http.Request, req mgmtapi.BindRequest, n int) {
		gotReq = req
		okBind(w, r, req, n)
	}
	resp, err := Once(t.Context(), f.config(t, apiID))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != mgmtapi.StatusBound || resp.Record != (spec.Revision{Epoch: 1, Counter: 2}) {
		t.Fatalf("response %+v", resp)
	}
	if gotReq.Nonce != "noncea" || gotReq.Token != "tok:"+mgmtapi.BindAudience(testCel, "noncea") {
		t.Fatalf("bind request %+v", gotReq)
	}
	if b := f.nonceBody[0]; b != "" && b != "{}" {
		t.Fatalf("nonce request body %q, want empty or {}", b)
	}
}

func TestOnceRefusesAudienceMismatch(t *testing.T) {
	f := newServer(t, apiID)
	f.nonce = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, 200, mgmtapi.NonceResponse{Nonce: "n1", Audience: mgmtapi.BindAudience("other-cell", "n1")})
	}
	cfg := f.config(t, apiID)
	called := false
	cfg.Tokens = func(context.Context, string) (string, error) { called = true; return "t", nil }
	if _, err := Once(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("err = %v, want an audience error", err)
	}
	if called {
		t.Fatal("a token was minted for a mismatched audience")
	}
	if _, b := f.counts(); b != 0 {
		t.Fatalf("%d bind requests, want 0", b)
	}
}

func TestClientRefusesWrongServerID(t *testing.T) {
	f := newServer(t, "spiffe://mgmt.poc.internal/other")
	if _, err := Once(t.Context(), f.config(t, apiID)); err == nil {
		t.Fatal("Once accepted a server with another SPIFFE ID of the same trust domain")
	}
	if n, b := f.counts(); n+b != 0 {
		t.Fatalf("%d requests reached the wrong server", n+b)
	}
}

func TestClientSendsNoCertificate(t *testing.T) {
	f := newServer(t, apiID)
	if _, err := Once(t.Context(), f.config(t, apiID)); err != nil {
		t.Fatal(err)
	}
	if f.handshakes.Load() == 0 {
		t.Fatal("no handshake seen")
	}
	if n := f.peerCerts.Load(); n != 0 {
		t.Fatalf("the client sent %d certificates", n)
	}
}

func TestClientTLSSettings(t *testing.T) {
	cfg := ClientTLS(spiffetest.NewCA(t, mgmtTD).Bundle(), spiffeid.RequireFromString(apiID))
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("versions %x to %x, want TLS 1.3 only", cfg.MinVersion, cfg.MaxVersion)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h2" {
		t.Fatalf("NextProtos %v", cfg.NextProtos)
	}
	if len(cfg.Certificates) != 0 || cfg.GetClientCertificate != nil {
		t.Fatal("ClientTLS must not hold a client certificate")
	}
}

func TestOnceUsesFreshConnectionForBind(t *testing.T) {
	f := newServer(t, apiID)
	f.nonce = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Connection", "close")
		okNonce(false)(w, r, n)
	}
	if _, err := Once(t.Context(), f.config(t, apiID)); err != nil {
		t.Fatal(err)
	}
	if got := f.handshakes.Load(); got != 2 {
		t.Fatalf("%d handshakes, want 2: nonce and bind each use their own connection", got)
	}
}

func TestOnceErrorKinds(t *testing.T) {
	f := newServer(t, apiID)
	f.bind = func(w http.ResponseWriter, _ *http.Request, _ mgmtapi.BindRequest, _ int) { denied(w) }
	_, err := Once(t.Context(), f.config(t, apiID))
	var ref *Refused
	if !errors.As(err, &ref) || ref.RequestID != "0123456789abcdef" {
		t.Fatalf("err = %v, want Refused with the request ID", err)
	}
	f.bind = func(w http.ResponseWriter, _ *http.Request, _ mgmtapi.BindRequest, _ int) {
		writeJSON(w, 503, map[string]string{"error": "busy"})
	}
	_, err = Once(t.Context(), f.config(t, apiID))
	if err == nil || errors.As(err, &ref) {
		t.Fatalf("err = %v, want a transient error", err)
	}
}

// pipeListener hands out the server end of in-memory connections.
type pipeListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestOnceAttemptTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca := spiffetest.NewCA(t, mgmtTD)
		scfg := tlsconfig.TLSServerConfig(ca.Source(t, apiID))
		scfg.NextProtos = []string{"h2"}
		pl := &pipeListener{ch: make(chan net.Conn), done: make(chan struct{})}
		release := make(chan struct{})
		protos := new(http.Protocols)
		protos.SetHTTP2(true)
		srv := &http.Server{Protocols: protos, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release })}
		go func() { _ = srv.Serve(tls.NewListener(pl, scfg)) }()

		cfg := Config{
			Cell: testCel, Upstream: "mgmt.test:443", TLS: ClientTLS(ca.Bundle(), spiffeid.RequireFromString(apiID)),
			Tokens: func(context.Context, string) (string, error) { return "t", nil },
			Log:    slog.New(slog.DiscardHandler),
			dial: func(context.Context, string, string) (net.Conn, error) {
				c, s := net.Pipe()
				pl.ch <- s
				return c, nil
			},
		}
		start := time.Now()
		_, err := Once(t.Context(), cfg)
		elapsed := time.Since(start)
		close(release)
		_ = srv.Close()
		_ = pl.Close()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want deadline exceeded", err)
		}
		if elapsed != 30*time.Second {
			t.Fatalf("attempt ended after %v, want 30s of fake time", elapsed)
		}
	})
}

// sleepRecorder replaces Config.Sleep. It records each wait and calls stop for the wait that stop
// accepts.
type sleepRecorder struct {
	mu     sync.Mutex
	waits  []time.Duration
	cancel context.CancelFunc
	stopAt func(n int, d time.Duration) bool
}

func (s *sleepRecorder) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.waits = append(s.waits, d)
	n := len(s.waits)
	stop := s.stopAt != nil && s.stopAt(n, d)
	s.mu.Unlock()
	if stop {
		s.cancel()
	}
	return ctx.Err()
}

func runCfg(t *testing.T, f *fakeServer, rec *sleepRecorder) (Config, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	rec.cancel = cancel
	cfg := f.config(t, apiID)
	cfg.Sleep = rec.sleep
	cfg.MinBackoff, cfg.MaxBackoff, cfg.RefusedBackoff, cfg.AttemptTimeout, cfg.RecheckEvery = time.Second, 30*time.Second, 60*time.Second, 30*time.Second, 5*time.Minute
	return cfg, ctx
}

func TestRunRetriesForever(t *testing.T) {
	f := newServer(t, apiID)
	f.nonce = func(w http.ResponseWriter, r *http.Request, n int) {
		if n < 50 {
			writeJSON(w, 503, map[string]string{"error": "busy"})
			return
		}
		okNonce(false)(w, r, n)
	}
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n > 50 }}
	cfg, ctx := runCfg(t, f, rec)
	err := Run(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context canceled", err)
	}
	if len(rec.waits) != 51 {
		t.Fatalf("%d waits, want 50 backoffs and one recheck", len(rec.waits))
	}
	for i, d := range rec.waits[:50] {
		if d < time.Second || d > 30*time.Second {
			t.Fatalf("backoff %d is %v, want between 1s and 30s", i, d)
		}
	}
	if rec.waits[49] < 15*time.Second {
		t.Fatalf("backoff did not grow: %v", rec.waits[49])
	}
	if _, b := f.counts(); b != 1 {
		t.Fatalf("%d binds, want 1", b)
	}
	if d := rec.waits[50]; d < 4*time.Minute || d > 6*time.Minute {
		t.Fatalf("recheck wait %v, want about 5 min", d)
	}
}

func TestRunRefusedUsesLongBackoff(t *testing.T) {
	for _, tc := range []struct {
		name     string
		respond  func(w http.ResponseWriter)
		min, max time.Duration
	}{
		{"refused", denied, 60 * time.Second, 120 * time.Second},
		{"busy", func(w http.ResponseWriter) { writeJSON(w, 503, map[string]string{"error": "busy"}) }, time.Second, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServer(t, apiID)
			f.bind = func(w http.ResponseWriter, r *http.Request, req mgmtapi.BindRequest, n int) {
				if n == 0 {
					tc.respond(w)
					return
				}
				okBind(w, r, req, n)
			}
			rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 2 }}
			cfg, ctx := runCfg(t, f, rec)
			_ = Run(ctx, cfg)
			if d := rec.waits[0]; d < tc.min || d > tc.max {
				t.Fatalf("first wait %v, want between %v and %v", d, tc.min, tc.max)
			}
			if _, b := f.counts(); b != 2 {
				t.Fatalf("%d binds, want 2", b)
			}
		})
	}
}

func TestRunRebindsWhenUnbound(t *testing.T) {
	f := newServer(t, apiID)
	// Calls 0 and 1 answer bound:false: the first starts the bind, and the second is the recheck
	// after a restore. Call 2 starts the second bind. Later calls answer bound:true.
	f.nonce = func(w http.ResponseWriter, r *http.Request, n int) {
		nonce := "nonce" + string(rune('a'+n))
		writeJSON(w, 200, mgmtapi.NonceResponse{Nonce: nonce, Audience: mgmtapi.BindAudience(testCel, nonce), Bound: n >= 3})
	}
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 3 }}
	cfg, ctx := runCfg(t, f, rec)
	_ = Run(ctx, cfg)
	n, b := f.counts()
	if b != 2 || n != 4 {
		t.Fatalf("%d nonce and %d bind requests, want 4 and 2", n, b)
	}
	if len(rec.waits) != 3 {
		t.Fatalf("waits %v, want three recheck waits", rec.waits)
	}
}

func TestRunLogsBoundAndObserves(t *testing.T) {
	f := newServer(t, apiID)
	var out bytes.Buffer
	var results []string
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 1 }}
	cfg, ctx := runCfg(t, f, rec)
	cfg.Log = slog.New(slog.NewJSONHandler(&out, nil))
	cfg.Observe = func(_ context.Context, result string) { results = append(results, result) }
	_ = Run(ctx, cfg)
	if !strings.Contains(out.String(), `"msg":"bound"`) || !strings.Contains(out.String(), `"status":"bound"`) {
		t.Fatalf("log %s", out.String())
	}
	if len(results) != 1 || results[0] != mgmtapi.StatusBound {
		t.Fatalf("results %v", results)
	}
}
