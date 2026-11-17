package envd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

// memStore keeps the state in memory and counts the calls.
type memStore struct {
	mu       sync.Mutex
	state    *State
	saved    []spec.Revision
	failSave int
	// commitThenFail makes Save store the state and still return an error.
	commitThenFail bool
	loadErr        error
	blockLoad      bool
	loads          int
}

func (m *memStore) Load(ctx context.Context) (*State, error) {
	m.mu.Lock()
	m.loads++
	block, loadErr := m.blockLoad, m.loadErr
	m.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if loadErr != nil {
		return nil, loadErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return Empty(), nil
	}
	return m.state, nil
}

func (m *memStore) Save(_ context.Context, s *State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saved = append(m.saved, s.Revision)
	if m.commitThenFail {
		m.state = s
		return errors.New("connection reset after the write")
	}
	if m.failSave > 0 {
		m.failSave--
		return errors.New("apiserver unavailable")
	}
	m.state = s
	return nil
}

func (m *memStore) Peek(context.Context) (*State, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return Empty(), true, nil
	}
	return m.state, true, nil
}

func (m *memStore) Replace(ctx context.Context, s *State) error { return m.Save(ctx, s) }

func (m *memStore) saves() []spec.Revision {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]spec.Revision(nil), m.saved...)
}

// upstream is a fake management plane.
type upstream struct {
	mu      sync.Mutex
	bundle  mgmtapi.SpecBundle
	reports []mgmtapi.StatusReport
	hits    atomic.Int32
	url     string
	client  *http.Client
	hs      atomic.Int32
	cert    *x509.Certificate
	failGet atomic.Bool
	delay   atomic.Int64
}

func newUpstream(t *testing.T, b mgmtapi.SpecBundle, tlsCfg *tls.Config) *upstream {
	t.Helper()
	u := &upstream{bundle: b}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+mgmtapi.SpecPattern, func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		time.Sleep(time.Duration(u.delay.Load()))
		if u.failGet.Load() {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		u.mu.Lock()
		defer u.mu.Unlock()
		_ = json.NewEncoder(w).Encode(u.bundle)
	})
	mux.HandleFunc("POST "+mgmtapi.StatusPattern, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(u.delay.Load()))
		var rep mgmtapi.StatusReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		u.mu.Lock()
		u.reports = append(u.reports, rep)
		u.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	counted := func(*tls.ClientHelloInfo) (*tls.Config, error) {
		u.hs.Add(1)
		return nil, nil
	}
	if tlsCfg != nil {
		tlsCfg.GetConfigForClient = counted
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: mux, TLSConfig: tlsCfg, ErrorLog: log.New(io.Discard, "", 0)}
		go func() { _ = srv.ServeTLS(ln, "", "") }()
		t.Cleanup(func() { _ = srv.Close() })
		u.url = "https://" + ln.Addr().String()
		return u
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{GetConfigForClient: counted}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u.url, u.client, u.cert = srv.URL, srv.Client(), srv.Certificate()
	return u
}

// shipped returns the client that cmd/envd uses, trusting only the certificate of u.
func (u *upstream) shipped() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(u.cert)
	return NewClient(&tls.Config{RootCAs: pool})
}

func (u *upstream) set(b mgmtapi.SpecBundle) {
	u.mu.Lock()
	u.bundle = b
	u.mu.Unlock()
}

func (u *upstream) got() []mgmtapi.StatusReport {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]mgmtapi.StatusReport(nil), u.reports...)
}

// runRounds runs p for n rounds on the fake clock.
func runRounds(t *testing.T, p *Puller, clk *clock) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	clk.cancel = cancel
	if err := p.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
}

type harness struct {
	f     *fx
	up    *upstream
	store *memStore
	clk   *clock
	logs  *syncBuffer
	read  *sdkmetric.ManualReader
	p     *Puller
}

// newHarnessWith creates the fixture first, so the bundle can be signed with its key.
func newHarnessWith(t *testing.T, rounds int, build func(f *fx) (mgmtapi.SpecBundle, *State), mut func(*PullerConfig)) *harness {
	t.Helper()
	f := newFx(t)
	b, st := build(f)
	h := &harness{f: f, store: &memStore{state: st}, clk: newClock(rounds), logs: &syncBuffer{}, read: sdkmetric.NewManualReader()}
	h.up = newUpstream(t, b, nil)
	cfg := PullerConfig{
		Client: h.up.client, BaseURL: h.up.url, Env: testEnv, Keys: f.keys(), Store: h.store,
		Log: newLog(h.logs), Meter: sdkmetric.NewMeterProvider(sdkmetric.WithReader(h.read)).Meter("test"),
		Now: h.clk.Now, Sleep: h.clk.Sleep,
	}
	if mut != nil {
		mut(&cfg)
	}
	h.p = NewPuller(cfg)
	return h
}

func (h *harness) metric(t *testing.T, name string) metricdata.Aggregation {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := h.read.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m.Data
			}
		}
	}
	return nil
}

func TestPullerAppliesAndReports(t *testing.T) {
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 4)), nil }, nil)
	if h.p.Ready() {
		t.Fatal("Ready before Run")
	}
	runRounds(t, h.p, h.clk)
	if !h.p.Ready() {
		t.Fatal("not Ready after Run")
	}
	if got := h.store.saves(); len(got) != 1 || got[0] != rev(1, 4) {
		t.Fatalf("saves %v", got)
	}
	reps := h.up.got()
	if len(reps) != 3 {
		t.Fatalf("reports %d", len(reps))
	}
	for i, r := range reps {
		if r.Applied != rev(1, 4) || r.LastRefusal != nil || r.StoreError != "" {
			t.Errorf("report %d = %+v", i, r)
		}
	}
	for _, d := range h.clk.slept() {
		if d != 10*time.Second {
			t.Errorf("slept %v between healthy rounds", d)
		}
	}
	g, ok := h.metric(t, "envd.spec.counter").(metricdata.Gauge[int64])
	if !ok || len(g.DataPoints) != 1 || g.DataPoints[0].Value != 4 {
		t.Errorf("gauge %+v", h.metric(t, "envd.spec.counter"))
	}
}

func TestPullerRefusalReported(t *testing.T) {
	var cur *State
	h := newHarnessWith(t, 12, func(f *fx) (mgmtapi.SpecBundle, *State) {
		cur, _ = f.base()
		return f.bundle(rev(1, 4), []item{f.item(f.cell("a", rev(1, 2), false))}, nil), cur
	}, func(c *PullerConfig) { c.Interval = 10 * time.Second })
	runRounds(t, h.p, h.clk)

	if saves := h.store.saves(); len(saves) != 0 {
		t.Fatalf("a refusal saved %v", saves)
	}
	for _, d := range h.clk.slept() {
		if d != 10*time.Second {
			t.Errorf("waited %v after a refusal, want the interval", d)
		}
	}
	reps := h.up.got()
	if len(reps) != 12 {
		t.Fatalf("reports %d", len(reps))
	}
	for i, r := range reps {
		if r.Applied != rev(1, 5) || r.LastRefusal == nil || r.LastRefusal.Reason != mgmtapi.ReasonRevisionOld || r.LastRefusal.Revision != rev(1, 4) {
			t.Fatalf("report %d = %+v", i, r)
		}
	}
	if n := h.logs.count("spec refused"); n != 1 {
		t.Errorf("refusal log lines over 12 rounds: %d, want 1", n)
	}
	sum, ok := h.metric(t, "envd.spec.refusals").(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 12 {
		t.Fatalf("refusal counter %+v", h.metric(t, "envd.spec.refusals"))
	}
	if v, _ := sum.DataPoints[0].Attributes.Value("reason"); v.AsString() != mgmtapi.ReasonRevisionOld {
		t.Errorf("reason attribute %v", v)
	}

	// After the window the same refusal logs again, with the count that it held back.
	h.clk.mu.Lock()
	h.clk.now = h.clk.now.Add(6 * time.Minute)
	h.clk.sleeps, h.clk.stop = nil, 1
	h.clk.mu.Unlock()
	runRounds(t, h.p, h.clk)
	if n := h.logs.count("spec refused"); n != 2 {
		t.Errorf("refusal log lines after the window: %d, want 2", n)
	}
}

func TestPullerRefusalLogsOnChange(t *testing.T) {
	h := newHarnessWith(t, 2, func(f *fx) (mgmtapi.SpecBundle, *State) {
		st, _ := f.base()
		return f.bundle(rev(1, 4), []item{f.item(f.cell("a", rev(1, 2), false))}, nil), st
	}, nil)
	runRounds(t, h.p, h.clk)
	h.up.set(func() mgmtapi.SpecBundle {
		b := h.up.bundle
		b.Spec = []byte(`{"payloadType":"x","payload":"","signatures":[]}`)
		return b
	}())
	h.clk.mu.Lock()
	h.clk.sleeps, h.clk.stop = nil, 2
	h.clk.mu.Unlock()
	runRounds(t, h.p, h.clk)
	if n := h.logs.count("spec refused"); n != 2 {
		t.Errorf("lines %d, want 2 (one for each reason)", n)
	}
}

func TestPullerIslandKeepsState(t *testing.T) {
	f := newFx(t)
	cur, _ := f.base()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	client, url := srv.Client(), srv.URL
	srv.Close()
	clk := newClock(4)
	store := &memStore{state: cur}
	p := NewPuller(PullerConfig{Client: client, BaseURL: url, Env: testEnv, Keys: f.keys(), Store: store,
		Log: newLog(io.Discard), Now: clk.Now, Sleep: clk.Sleep})
	runRounds(t, p, clk)
	if !p.Ready() {
		t.Fatal("not Ready while management is unreachable")
	}
	if len(store.saves()) != 0 {
		t.Fatal("island rounds saved")
	}
	prev := time.Duration(0)
	for i, d := range clk.slept() {
		want := time.Second << i
		if d < want || d > min(2*want, 30*time.Second) {
			t.Errorf("backoff %d = %v, want within [%v, %v]", i, d, want, min(2*want, 30*time.Second))
		}
		if d < prev/2 {
			t.Errorf("backoff shrank: %v after %v", d, prev)
		}
		prev = d
	}
	if got, _ := store.Load(t.Context()); got != cur {
		t.Error("state replaced")
	}
}

func TestPullerRefusesWrongServerID(t *testing.T) {
	f := newFx(t)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	clientCA := spiffetest.NewCA(t, "dev.env.poc.internal")
	client := clientCA.Source(t, "spiffe://dev.env.poc.internal/envd")
	want := spiffeid.RequireFromString("spiffe://mgmt.poc.internal/api")

	serve := func(id string) *upstream {
		cfg := tlsconfig.MTLSServerConfig(ca.Source(t, id), clientCA.Bundle(), tlsconfig.AuthorizeAny())
		return newUpstream(t, firstBundle(f, rev(1, 2)), cfg)
	}
	run := func(u *upstream) (*memStore, *syncBuffer) {
		clk := newClock(2)
		store := &memStore{}
		logs := &syncBuffer{}
		p := NewPuller(PullerConfig{
			Client: NewClient(cellproxy.ClientTLS(client, ca.Bundle(), want)), BaseURL: u.url,
			Env: testEnv, Keys: f.keys(), Store: store, Log: newLog(logs), Now: clk.Now, Sleep: clk.Sleep,
		})
		runRounds(t, p, clk)
		return store, logs
	}

	store, _ := run(serve("spiffe://mgmt.poc.internal/api"))
	if len(store.saves()) != 1 {
		t.Fatalf("control: saves %v", store.saves())
	}
	impostor := serve("spiffe://mgmt.poc.internal/other")
	store, logs := run(impostor)
	if len(store.saves()) != 0 || impostor.hits.Load() != 0 {
		t.Fatalf("impostor: saves %v, requests %d", store.saves(), impostor.hits.Load())
	}
	if logs.count("pull failed") != 1 {
		t.Error("no pull failure logged")
	}
}

func TestPullerBodyLimit(t *testing.T) {
	f := newFx(t)
	huge := mgmtapi.SpecBundle{Spec: []byte(`"` + strings.Repeat("x", MaxBodyBytes) + `"`), Records: map[string]json.RawMessage{}}
	u := newUpstream(t, huge, nil)
	clk := newClock(1)
	store := &memStore{}
	logs := &syncBuffer{}
	p := NewPuller(PullerConfig{Client: u.client, BaseURL: u.url, Env: testEnv, Keys: f.keys(), Store: store,
		Log: newLog(logs), Now: clk.Now, Sleep: clk.Sleep})
	runRounds(t, p, clk)
	if len(store.saves()) != 0 {
		t.Fatalf("saves %v", store.saves())
	}
	if reps := u.got(); len(reps) != 1 || reps[0].Applied != (spec.Revision{}) {
		t.Fatalf("a failed pull must still post the status: %+v", reps)
	}
	var found bool
	for _, l := range logs.lines() {
		if l["msg"] == "pull failed" && strings.Contains(l["error"].(string), "larger than") {
			found = true
		}
	}
	if !found {
		t.Errorf("no body limit error in %v", logs.lines())
	}
}

func TestPullerRetriesFailedSave(t *testing.T) {
	h := newHarnessWith(t, 2, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 4)), nil }, nil)
	h.store.failSave = 1
	runRounds(t, h.p, h.clk)

	if got := h.store.saves(); len(got) != 2 || got[0] != rev(1, 4) || got[1] != rev(1, 4) {
		t.Fatalf("saves %v", got)
	}
	reps := h.up.got()
	if len(reps) != 2 {
		t.Fatalf("reports %d", len(reps))
	}
	if reps[0].StoreError != mgmtapi.ReasonStoreFailed || reps[0].Applied != (spec.Revision{}) {
		t.Errorf("first report %+v", reps[0])
	}
	if reps[1].StoreError != "" || reps[1].Applied != rev(1, 4) {
		t.Errorf("second report %+v", reps[1])
	}
	if d := h.clk.slept()[0]; d >= 10*time.Second || d < time.Second {
		t.Errorf("wait after a failed save: %v", d)
	}
}

func TestPullerRoundDeadline(t *testing.T) {
	f := newFx(t)
	release := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() { close(release); srv.Close() })
	clk := newClock(1)
	store := &memStore{}
	logs := &syncBuffer{}
	p := NewPuller(PullerConfig{Client: srv.Client(), BaseURL: srv.URL, Env: testEnv, Keys: f.keys(), Store: store,
		RoundTimeout: 200 * time.Millisecond, Log: newLog(logs), Now: clk.Now, Sleep: clk.Sleep})
	start := time.Now()
	runRounds(t, p, clk)
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("round took %v", took)
	}
	var msg string
	for _, l := range logs.lines() {
		if l["msg"] == "pull failed" {
			msg, _ = l["error"].(string)
		}
	}
	if !strings.Contains(msg, "deadline exceeded") {
		t.Errorf("pull error %q", msg)
	}
	if len(store.saves()) != 0 {
		t.Error("saved after a timeout")
	}
}

func TestPullerNewHandshakeEachRound(t *testing.T) {
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) { return firstBundle(f, rev(1, 2)), nil },
		nil)
	h.p.cfg.Client = h.up.shipped()
	runRounds(t, h.p, h.clk)
	if n := h.up.hs.Load(); n != 3 {
		t.Fatalf("handshakes %d, want 3", n)
	}
	if n := h.up.hits.Load(); n != 3 {
		t.Fatalf("pulls %d, want 3", n)
	}
}

// memGateway counts the syncs of a gateway that holds no items.
type memGateway struct {
	mu    sync.Mutex
	syncs []gwapi.SyncRequest
}

func (g *memGateway) Sync(_ context.Context, r gwapi.SyncRequest) (gwapi.SyncResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.syncs = append(g.syncs, r)
	return gwapi.SyncResponse{}, nil
}

func (g *memGateway) Ack(context.Context, gwapi.AckRequest) error { return nil }

func (g *memGateway) CloseIdleConnections() {}

func (g *memGateway) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.syncs)
}

// A round whose pull fails still runs the gateway sync and posts the status, and the status post
// ends its connection, so each round dials once.
func TestPullerNewHandshakeAfterFailedPull(t *testing.T) {
	gw := &memGateway{}
	h := newHarnessWith(t, 3, func(f *fx) (mgmtapi.SpecBundle, *State) {
		cur, _ := f.base()
		return firstBundle(f, rev(1, 2)), cur
	}, func(c *PullerConfig) { c.Gateway = gw })
	h.up.failGet.Store(true)
	h.p.cfg.Client = h.up.shipped()
	runRounds(t, h.p, h.clk)
	if n := h.up.hs.Load(); n != 3 {
		t.Fatalf("handshakes %d, want 3", n)
	}
	if n := gw.count(); n != 3 {
		t.Errorf("gateway syncs %d, want 3", n)
	}
	reps := h.up.got()
	if len(reps) != 3 {
		t.Fatalf("a failed pull posted %d reports, want 3", len(reps))
	}
	for _, r := range reps {
		if r.Gateway == nil {
			t.Error("status report without a gateway status")
		}
	}
}

func TestPullerRefusesUntrustedServers(t *testing.T) {
	f := newFx(t)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	clientCA := spiffetest.NewCA(t, "dev.env.poc.internal")
	client := clientCA.Source(t, "spiffe://dev.env.poc.internal/envd")
	want := spiffeid.RequireFromString("spiffe://mgmt.poc.internal/api")
	for name, serverCA := range map[string]*spiffetest.CA{
		"foreign_ca":         spiffetest.NewCA(t, "mgmt.poc.internal"),
		"other_trust_domain": spiffetest.NewCA(t, "other.poc.internal"),
	} {
		t.Run(name, func(t *testing.T) {
			id := "spiffe://mgmt.poc.internal/api"
			if name == "other_trust_domain" {
				id = "spiffe://other.poc.internal/api"
			}
			cfg := tlsconfig.MTLSServerConfig(serverCA.Source(t, id), clientCA.Bundle(), tlsconfig.AuthorizeAny())
			u := newUpstream(t, firstBundle(f, rev(1, 2)), cfg)
			clk := newClock(2)
			store := &memStore{}
			p := NewPuller(PullerConfig{Client: NewClient(cellproxy.ClientTLS(client, ca.Bundle(), want)), BaseURL: u.url,
				Env: testEnv, Keys: f.keys(), Store: store, Log: newLog(io.Discard), Now: clk.Now, Sleep: clk.Sleep})
			runRounds(t, p, clk)
			if len(store.saves()) != 0 || u.hits.Load() != 0 {
				t.Fatalf("saves %v, requests %d", store.saves(), u.hits.Load())
			}
		})
	}
}
