package bind

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

const (
	mgmtTD  = "dev.env.poc.internal"
	apiID   = "spiffe://dev.env.poc.internal/cp/gateway"
	testCel = "dev-cell-1"
)

const fakeBindID = "0123456789abcdef0123456789abcdef"

// fakeServer plays the bind listener of the cell gateway. It records requests and answers through handlers.
type fakeServer struct {
	addr       string
	ca         *spiffetest.CA
	handshakes atomic.Int64
	peerCerts  atomic.Int64
	mu         sync.Mutex
	nonceBody  []string
	nonce      func(w http.ResponseWriter, r *http.Request, n int)
	bind       func(w http.ResponseWriter, r *http.Request, req mgmtapi.BindRequest, n int)
	result     func(w http.ResponseWriter, r *http.Request, n int)
	nonceCalls int
	bindCalls  int
	resultCall int
	methods    []string
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func okNonce(bound bool) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, r *http.Request, n int) {
		nonce := fmt.Sprintf("nonce%d", n)
		writeJSON(w, 200, mgmtapi.NonceResponse{Nonce: nonce, Audience: mgmtapi.BindAudience(testCel, nonce), Bound: bound})
	}
}

func okBind(w http.ResponseWriter, _ *http.Request, _ mgmtapi.BindRequest, _ int) {
	writeJSON(w, http.StatusAccepted, gwapi.BindAccepted{ID: fakeBindID})
}

func boundNow(w http.ResponseWriter, _ *http.Request, _ int) {
	writeJSON(w, 200, gwapi.BindResult{Status: mgmtapi.StatusBound})
}

// pendingThenBound answers pending to the first poll and bound to every later one.
func pendingThenBound(w http.ResponseWriter, _ *http.Request, n int) {
	if n == 0 {
		writeJSON(w, 200, gwapi.BindResult{Status: gwapi.BindPending})
		return
	}
	writeJSON(w, 200, gwapi.BindResult{Status: mgmtapi.StatusBound})
}

func denied(w http.ResponseWriter) {
	writeJSON(w, 403, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: "0123456789abcdef"})
}

func newServer(t *testing.T, serverID string) *fakeServer {
	t.Helper()
	f := &fakeServer{ca: spiffetest.NewCA(t, mgmtTD), nonce: okNonce(false), bind: okBind, result: boundNow}
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
	mux.HandleFunc("GET "+gwapi.NoncePattern, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.methods = append(f.methods, r.Method+" "+r.URL.Path)
		f.nonceBody = append(f.nonceBody, string(body))
		n := f.nonceCalls
		f.nonceCalls++
		h := f.nonce
		f.mu.Unlock()
		h(w, r, n)
	})
	mux.HandleFunc("GET "+gwapi.BindResultPattern, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.methods = append(f.methods, r.Method+" "+r.URL.Path)
		n := f.resultCall
		f.resultCall++
		h := f.result
		f.mu.Unlock()
		if r.PathValue("id") != fakeBindID {
			writeJSON(w, 404, map[string]string{"error": "unknown"})
			return
		}
		h(w, r, n)
	})
	mux.HandleFunc("POST "+gwapi.BindPattern, func(w http.ResponseWriter, r *http.Request) {
		var req mgmtapi.BindRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.methods = append(f.methods, r.Method+" "+r.URL.Path)
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
		Log:    slog.New(slog.DiscardHandler), PollEvery: 5 * time.Millisecond,
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
	if resp.Status != mgmtapi.StatusBound {
		t.Fatalf("response %+v", resp)
	}
	if gotReq.Nonce != "nonce0" || gotReq.Token != "tok:"+mgmtapi.BindAudience(testCel, "nonce0") {
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

func TestBindRefusesWrongGatewayID(t *testing.T) {
	f := newServer(t, "spiffe://dev.env.poc.internal/cp/other")
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

// The fake keeps each connection open. A client that reuses one handshakes fewer times than it
// sends requests.
func TestOnceUsesFreshConnectionForEachRequest(t *testing.T) {
	f := newServer(t, apiID)
	f.result = pendingThenBound
	if _, err := Once(t.Context(), f.config(t, apiID)); err != nil {
		t.Fatal(err)
	}
	n, b := f.counts()
	if got, want := int(f.handshakes.Load()), n+b+f.resultCall; got != want || f.resultCall != 2 {
		t.Fatalf("%d handshakes for %d requests, want one each", got, want)
	}
}

// TestBindThroughGatewayPolls checks the gateway flow: GET for the nonce, POST for the bind, then
// a poll of the result path until it is final.
func TestBindThroughGatewayPolls(t *testing.T) {
	f := newServer(t, apiID)
	f.result = func(w http.ResponseWriter, _ *http.Request, n int) {
		if n < 3 {
			writeJSON(w, 200, gwapi.BindResult{Status: gwapi.BindPending})
			return
		}
		writeJSON(w, 200, gwapi.BindResult{Status: mgmtapi.StatusKeysUpdated})
	}
	resp, err := Once(t.Context(), f.config(t, apiID))
	if err != nil || resp.Status != mgmtapi.StatusKeysUpdated {
		t.Fatalf("Once = %+v, %v", resp, err)
	}
	want := []string{
		"GET " + gwapi.NoncePath(testCel), "POST " + gwapi.BindPath(testCel),
		"GET " + gwapi.BindResultPath(testCel, fakeBindID), "GET " + gwapi.BindResultPath(testCel, fakeBindID),
		"GET " + gwapi.BindResultPath(testCel, fakeBindID), "GET " + gwapi.BindResultPath(testCel, fakeBindID),
	}
	if !slices.Equal(f.methods, want) {
		t.Fatalf("requests %v, want %v", f.methods, want)
	}
}

// A failed poll does not end the attempt: the bind went in, so a new nonce could be refused.
func TestBindPollSurvivesAFailedPoll(t *testing.T) {
	f := newServer(t, apiID)
	f.result = func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 0 {
			writeJSON(w, 503, map[string]string{"error": "busy"})
			return
		}
		pendingThenBound(w, r, n-1)
	}
	if resp, err := Once(t.Context(), f.config(t, apiID)); err != nil || resp.Status != mgmtapi.StatusBound {
		t.Fatalf("Once = %+v, %v", resp, err)
	}
	if n, b := f.counts(); n != 1 || b != 1 {
		t.Fatalf("%d nonce and %d bind requests, want 1 and 1", n, b)
	}
}

func TestBindDeniedResultIsRefused(t *testing.T) {
	f := newServer(t, apiID)
	f.result = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, 200, gwapi.BindResult{Status: gwapi.BindDenied, RequestID: "abc123"})
	}
	_, err := Once(t.Context(), f.config(t, apiID))
	var ref *Refused
	if !errors.As(err, &ref) || ref.RequestID != "abc123" {
		t.Fatalf("err = %v, want Refused abc123", err)
	}
}

// TestBindDeniedUsesLongBackoff: a denied result waits the refused backoff, and the next attempt
// binds with a new nonce.
func TestBindDeniedUsesLongBackoff(t *testing.T) {
	f := newServer(t, apiID)
	f.result = func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 0 {
			writeJSON(w, 200, gwapi.BindResult{Status: gwapi.BindDenied, RequestID: "abc123"})
			return
		}
		pendingThenBound(w, r, n)
	}
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 2 }}
	cfg, ctx := runCfg(t, f, rec)
	_ = Run(ctx, cfg)
	if d := rec.waits[0]; d < 60*time.Second || d > 120*time.Second {
		t.Fatalf("first wait %v, want between 60s and 120s", d)
	}
	if _, b := f.counts(); b != 2 {
		t.Fatalf("%d binds, want 2", b)
	}
}

// A denial of a cell that the nonce answer calls bound, as a key_update_gap denial is, still waits
// the refused backoff and then binds again with a fresh nonce.
func TestRunBindsAgainAfterDenialOfBoundCell(t *testing.T) {
	f := newServer(t, apiID)
	f.nonce = okNonce(true)
	f.result = func(w http.ResponseWriter, _ *http.Request, n int) {
		if n == 0 {
			writeJSON(w, 200, gwapi.BindResult{Status: gwapi.BindDenied, RequestID: "abc123"})
			return
		}
		writeJSON(w, 200, gwapi.BindResult{Status: mgmtapi.StatusKeysUpdated})
	}
	var results []string
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 2 }}
	cfg, ctx := runCfg(t, f, rec)
	cfg.Observe = func(_ context.Context, r string) { results = append(results, r) }
	_ = Run(ctx, cfg)
	if _, b := f.counts(); b != 2 {
		t.Fatalf("%d binds, want 2", b)
	}
	if d := rec.waits[0]; d < 60*time.Second || d > 120*time.Second {
		t.Fatalf("first wait %v, want the refused backoff", d)
	}
	if len(results) < 2 || results[0] != "refused" || results[1] != mgmtapi.StatusKeysUpdated {
		t.Fatalf("results %v, want refused then keys_updated", results)
	}
}

func TestBindPollWaitsThroughConfigSleep(t *testing.T) {
	f := newServer(t, apiID)
	f.result = pendingThenBound
	var waits []time.Duration
	cfg := f.config(t, apiID)
	cfg.PollEvery = 2 * time.Second
	cfg.Sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	if _, err := Once(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 1 || waits[0] != 2*time.Second {
		t.Fatalf("poll waits %v, want one wait of 2s through Config.Sleep", waits)
	}
}

func TestBindAcceptsOnly202(t *testing.T) {
	f := newServer(t, apiID)
	f.bind = func(w http.ResponseWriter, _ *http.Request, _ mgmtapi.BindRequest, _ int) {
		writeJSON(w, 200, gwapi.BindAccepted{ID: fakeBindID})
	}
	var se *StatusError
	if _, err := Once(t.Context(), f.config(t, apiID)); !errors.As(err, &se) || se.Code != 200 {
		t.Fatalf("err = %v, want a StatusError 200", err)
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

// TestOnceAttemptTimeout stalls each stage in turn. The whole attempt ends after 60 s of fake time.
func TestOnceAttemptTimeout(t *testing.T) {
	for _, stage := range []string{"nonce", "token", "bind", "poll"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ca := spiffetest.NewCA(t, mgmtTD)
				scfg := tlsconfig.TLSServerConfig(ca.Source(t, apiID))
				scfg.NextProtos = []string{"h2"}
				pl := &pipeListener{ch: make(chan net.Conn), done: make(chan struct{})}
				release := make(chan struct{})
				mux := http.NewServeMux()
				mux.HandleFunc("GET "+gwapi.NoncePattern, func(w http.ResponseWriter, _ *http.Request) {
					if stage == "nonce" {
						<-release
					}
					okNonce(false)(w, nil, 0)
				})
				mux.HandleFunc("POST "+gwapi.BindPattern, func(w http.ResponseWriter, r *http.Request) {
					if stage == "bind" {
						<-release
					}
					okBind(w, r, mgmtapi.BindRequest{}, 0)
				})
				mux.HandleFunc("GET "+gwapi.BindResultPattern, func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, 200, gwapi.BindResult{Status: gwapi.BindPending})
				})
				protos := new(http.Protocols)
				protos.SetHTTP2(true)
				srv := &http.Server{Protocols: protos, Handler: mux}
				go func() { _ = srv.Serve(tls.NewListener(pl, scfg)) }()

				cfg := Config{
					Cell: testCel, Upstream: "mgmt.test:443", TLS: ClientTLS(ca.Bundle(), spiffeid.RequireFromString(apiID)),
					Tokens: func(ctx context.Context, _ string) (string, error) {
						if stage == "token" {
							<-ctx.Done()
							return "", ctx.Err()
						}
						return "t", nil
					},
					Log: slog.New(slog.DiscardHandler),
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
				if elapsed != 60*time.Second {
					t.Fatalf("attempt ended after %v, want 60s of fake time", elapsed)
				}
			})
		})
	}
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
	cfg.PollEvery = 5 * time.Millisecond
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
		nonce := fmt.Sprintf("nonce%d", n)
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

func TestOnceDoesNotFollowRedirects(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, stage := range []string{"nonce", "bind"} {
			t.Run(fmt.Sprintf("%d %s", code, stage), func(t *testing.T) {
				var sinkBytes atomic.Int64
				sink, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sink.Close() })
				go func() {
					for {
						c, err := sink.Accept()
						if err != nil {
							return
						}
						go func() {
							n, _ := io.Copy(io.Discard, c)
							sinkBytes.Add(n)
							_ = c.Close()
						}()
					}
				}()
				f := newServer(t, apiID)
				away := "http://" + sink.Addr().String() + "/steal"
				redirect := func(w http.ResponseWriter) {
					w.Header().Set("Location", away)
					w.WriteHeader(code)
				}
				if stage == "nonce" {
					f.nonce = func(w http.ResponseWriter, _ *http.Request, _ int) { redirect(w) }
				} else {
					f.bind = func(w http.ResponseWriter, _ *http.Request, _ mgmtapi.BindRequest, _ int) { redirect(w) }
				}
				cfg := f.config(t, apiID)
				cfg.AttemptTimeout = 2 * time.Second
				_, err = Once(t.Context(), cfg)
				var se *StatusError
				if !errors.As(err, &se) || se.Code != code {
					t.Fatalf("err = %v, want a transient StatusError %d", err, code)
				}
				time.Sleep(100 * time.Millisecond)
				if n := sinkBytes.Load(); n != 0 {
					t.Fatalf("the redirect target received %d bytes", n)
				}
			})
		}
	}
}

func TestOnceRedirectToSameServerSendsOneBind(t *testing.T) {
	f := newServer(t, apiID)
	f.bind = func(w http.ResponseWriter, _ *http.Request, _ mgmtapi.BindRequest, _ int) {
		w.Header().Set("Location", "/again")
		w.WriteHeader(http.StatusPermanentRedirect)
	}
	if _, err := Once(t.Context(), f.config(t, apiID)); err == nil {
		t.Fatal("a redirect counted as success")
	}
	if _, b := f.counts(); b != 1 {
		t.Fatalf("%d bind requests, want 1", b)
	}
}

func TestOnceRefusesBadNonceAnswers(t *testing.T) {
	long := strings.Repeat("a", 200)
	for name, n := range map[string]mgmtapi.NonceResponse{
		"empty nonce":     {Nonce: "", Audience: mgmtapi.BindAudience(testCel, "")},
		"attest audience": {Nonce: "abc", Audience: "spire-dev/abc"},
		"oversized nonce": {Nonce: long, Audience: mgmtapi.BindAudience(testCel, long)},
		"newline nonce":   {Nonce: "ab\ncd", Audience: mgmtapi.BindAudience(testCel, "ab\ncd")},
		"slash nonce":     {Nonce: "ab/cd", Audience: mgmtapi.BindAudience(testCel, "ab/cd")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newServer(t, apiID)
			f.nonce = func(w http.ResponseWriter, _ *http.Request, _ int) { writeJSON(w, 200, n) }
			cfg := f.config(t, apiID)
			cfg.Tokens = func(context.Context, string) (string, error) { t.Error("a token was minted"); return "t", nil }
			if _, err := Once(t.Context(), cfg); err == nil {
				t.Fatal("Once accepted the nonce answer")
			}
			if err := CheckNonce(testCel, n); err == nil {
				t.Fatal("CheckNonce accepted the nonce answer")
			}
			if _, b := f.counts(); b != 0 {
				t.Fatalf("%d binds", b)
			}
		})
	}
	if err := CheckNonce(testCel, mgmtapi.NonceResponse{Nonce: "abc", Audience: mgmtapi.BindAudience(testCel, "abc")}); err != nil {
		t.Fatalf("a good answer failed: %v", err)
	}
}

func TestOnceRefusesUnknownBindStatus(t *testing.T) {
	for _, status := range []string{"", "pwned", strings.Repeat("x", 100)} {
		f := newServer(t, apiID)
		f.result = func(w http.ResponseWriter, _ *http.Request, _ int) {
			writeJSON(w, 200, gwapi.BindResult{Status: status})
		}
		if _, err := Once(t.Context(), f.config(t, apiID)); err == nil {
			t.Fatalf("status %q counted as success", status)
		}
	}
	for _, status := range []string{mgmtapi.StatusBound, mgmtapi.StatusAlreadyBound, mgmtapi.StatusKeysUpdated} {
		f := newServer(t, apiID)
		f.result = func(w http.ResponseWriter, _ *http.Request, _ int) {
			writeJSON(w, 200, gwapi.BindResult{Status: status})
		}
		if resp, err := Once(t.Context(), f.config(t, apiID)); err != nil || resp.Status != status {
			t.Fatalf("status %q: %v", status, err)
		}
	}
	f := newServer(t, apiID)
	f.result = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
	}
	if _, err := Once(t.Context(), f.config(t, apiID)); err == nil {
		t.Fatal("a 200 with {} counted as success")
	}
}

func TestRefusedRequestIDIsClipped(t *testing.T) {
	f := newServer(t, apiID)
	f.bind = func(w http.ResponseWriter, _ *http.Request, _ mgmtapi.BindRequest, _ int) {
		writeJSON(w, 403, mgmtapi.Denied{Error: "denied", RequestID: "ab\nbound:bound" + strings.Repeat("z", 500)})
	}
	_, err := Once(t.Context(), f.config(t, apiID))
	var ref *Refused
	if !errors.As(err, &ref) {
		t.Fatalf("err = %v", err)
	}
	if len(ref.RequestID) > 32 || strings.ContainsAny(ref.RequestID, "\n\r :") {
		t.Fatalf("request ID %q", ref.RequestID)
	}
}

func TestOnceRefusesOversizedBody(t *testing.T) {
	f := newServer(t, apiID)
	f.nonce = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"pad":"`+strings.Repeat("p", 70<<10)+`","nonce":"abc","audience":"`+mgmtapi.BindAudience(testCel, "abc")+`"}`)
	}
	if _, err := Once(t.Context(), f.config(t, apiID)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v, want a size error", err)
	}
}

func TestRunRecheckWaits(t *testing.T) {
	f := newServer(t, apiID)
	// Call 0 starts the bind. Calls 1 to 4 are rechecks: bound, a 503, a 403, bound.
	f.nonce = func(w http.ResponseWriter, r *http.Request, n int) {
		switch n {
		case 2:
			writeJSON(w, 503, map[string]string{"error": "busy"})
		case 3:
			denied(w)
		default:
			okNonce(n >= 1)(w, r, n)
		}
	}
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 5 }}
	cfg, ctx := runCfg(t, f, rec)
	_ = Run(ctx, cfg)
	if len(rec.waits) != 5 {
		t.Fatalf("waits %v, want 5", rec.waits)
	}
	for i, r := range []struct{ min, max time.Duration }{
		{4*time.Minute + 30*time.Second, 5*time.Minute + 30*time.Second},
		{4*time.Minute + 30*time.Second, 5*time.Minute + 30*time.Second},
		{time.Second, 30 * time.Second},
		{60 * time.Second, 66 * time.Second},
		{4*time.Minute + 30*time.Second, 5*time.Minute + 30*time.Second},
	} {
		if d := rec.waits[i]; d < r.min || d > r.max {
			t.Errorf("wait %d is %v, want between %v and %v", i, d, r.min, r.max)
		}
	}
}

// bindFailedReason runs Run until it logs one "bind failed" line and returns the reason field.
func bindFailedReason(t *testing.T, ctx context.Context, cfg Config, rec *sleepRecorder, out *bytes.Buffer) (string, map[string]any) {
	t.Helper()
	cfg.Log = slog.New(slog.NewJSONHandler(out, nil))
	_ = Run(ctx, cfg)
	for _, l := range strings.Split(out.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "bind failed" {
			reason, _ := m["reason"].(string)
			return reason, m
		}
	}
	t.Fatalf("no bind failed line in %s", out.String())
	return "", nil
}

func TestBindRefusalReasonWrongID(t *testing.T) {
	f := newServer(t, "spiffe://dev.env.poc.internal/cp/other")
	var out bytes.Buffer
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 1 }}
	cfg, ctx := runCfg(t, f, rec)
	reason, line := bindFailedReason(t, ctx, cfg, rec, &out)
	if reason != "peer_not_allowed" {
		t.Fatalf("reason = %q in %v", reason, line)
	}
	for _, k := range []string{"cell", "result", "error", "retry_in"} {
		if _, ok := line[k]; !ok {
			t.Errorf("line lost the field %s: %v", k, line)
		}
	}
}

func TestBindRefusalReasonUntrusted(t *testing.T) {
	f := newServer(t, apiID)
	var out bytes.Buffer
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 1 }}
	cfg, ctx := runCfg(t, f, rec)
	// The client trusts another CA than the one that signed the gateway certificate.
	cfg.TLS = ClientTLS(spiffetest.NewCA(t, mgmtTD).Bundle(), spiffeid.RequireFromString(apiID))
	if reason, line := bindFailedReason(t, ctx, cfg, rec, &out); reason != "peer_untrusted" {
		t.Fatalf("reason = %q in %v", reason, line)
	}
}

// lineOf returns the first JSON log line with the message msg.
func lineOf(t *testing.T, out *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	for _, l := range strings.Split(out.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == msg {
			return m
		}
	}
	t.Fatalf("no %q line in %s", msg, out.String())
	return nil
}

// A non-TLS failure logs no reason field at all.
func TestBindFailedWithoutTLSFailureHasNoReason(t *testing.T) {
	f := newServer(t, apiID)
	f.nonce = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, 503, map[string]string{"error": "down"})
	}
	var out bytes.Buffer
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 1 }}
	cfg, ctx := runCfg(t, f, rec)
	if _, line := bindFailedReason(t, ctx, cfg, rec, &out); line["result"] != "error" {
		t.Fatalf("line %v", line)
	}
	if _, ok := lineOf(t, &out, "bind failed")["reason"]; ok {
		t.Fatalf("a non-TLS failure logged a reason: %s", out.String())
	}
}

// A gateway that offers another ALPN protocol ends the handshake with an alert from the peer.
func TestBindRefusalReasonALPNMismatch(t *testing.T) {
	ca := spiffetest.NewCA(t, mgmtTD)
	scfg := tlsconfig.TLSServerConfig(ca.Source(t, apiID))
	scfg.MinVersion, scfg.MaxVersion, scfg.NextProtos = tls.VersionTLS12, tls.VersionTLS13, []string{"http/1.1"}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", scfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	f := newServer(t, apiID)
	f.addr = ln.Addr().String()
	f.ca = ca
	var out bytes.Buffer
	rec := &sleepRecorder{stopAt: func(n int, _ time.Duration) bool { return n >= 1 }}
	cfg, ctx := runCfg(t, f, rec)
	if reason, line := bindFailedReason(t, ctx, cfg, rec, &out); reason != "handshake_failed" {
		t.Fatalf("reason = %q in %v", reason, line)
	}
}

// switchSource trusts the CA of good until flip, and the CA of other after it.
type switchSource struct {
	good, other x509bundle.Source
	flipped     atomic.Bool
}

func (s *switchSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if s.flipped.Load() {
		return s.other.GetX509BundleForTrustDomain(td)
	}
	return s.good.GetX509BundleForTrustDomain(td)
}

func TestBindRecheckFailedReason(t *testing.T) {
	f := newServer(t, apiID)
	src := &switchSource{good: f.ca.Bundle(), other: spiffetest.NewCA(t, mgmtTD).Bundle()}
	var out bytes.Buffer
	rec := &sleepRecorder{}
	rec.stopAt = func(n int, _ time.Duration) bool {
		if n == 1 {
			src.flipped.Store(true) // The first wait is the recheck wait, after a good bind.
		}
		return n >= 2
	}
	cfg, ctx := runCfg(t, f, rec)
	cfg.TLS = ClientTLS(src, spiffeid.RequireFromString(apiID))
	cfg.Log = slog.New(slog.NewJSONHandler(&out, nil))
	_ = Run(ctx, cfg)
	if got := lineOf(t, &out, "bind recheck failed")["reason"]; got != "peer_untrusted" {
		t.Fatalf("reason = %v in %s", got, out.String())
	}
}
