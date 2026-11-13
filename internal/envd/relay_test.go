package envd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

const (
	mgmtID = "spiffe://mgmt.poc.internal/api"
	gwID   = "spiffe://dev.env.poc.internal/cp/gateway"
	envdID = "spiffe://dev.env.poc.internal/envd"
)

type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (c *callLog) add(s string) {
	c.mu.Lock()
	c.calls = append(c.calls, s)
	c.mu.Unlock()
}

func (c *callLog) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

func (c *callLog) count(s string) int {
	n := 0
	for _, x := range c.all() {
		if x == s {
			n++
		}
	}
	return n
}

// fakeMgmt is a management plane on spiffetest TLS.
type fakeMgmt struct {
	log      *callLog
	mu       sync.Mutex
	bundle   mgmtapi.SpecBundle
	ops      mgmtapi.OpsBundle
	opsCode  int
	repCode  int
	statCode int
	decide   func(mgmtapi.ReportItem) mgmtapi.ItemOutcome
	specWait time.Duration
	opsWait  time.Duration
	batches  [][]byte
	statuses []mgmtapi.StatusReport
	srv      *http.Server
	url      string
}

func accepted(it mgmtapi.ReportItem) mgmtapi.ItemOutcome {
	return mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeAccepted}
}

func serveTLS(t *testing.T, h http.Handler, cfg *tls.Config) (*http.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, TLSConfig: cfg, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, "https://" + ln.Addr().String()
}

func newFakeMgmt(t *testing.T, cl *callLog, cfg *tls.Config, b mgmtapi.SpecBundle) *fakeMgmt {
	t.Helper()
	m := &fakeMgmt{log: cl, bundle: b, opsCode: 200, repCode: 200, statCode: 204, decide: accepted}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+mgmtapi.SpecPattern, func(w http.ResponseWriter, r *http.Request) {
		cl.add("spec")
		m.mu.Lock()
		wait := m.specWait
		m.mu.Unlock()
		time.Sleep(wait)
		m.mu.Lock()
		defer m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(m.bundle)
	})
	mux.HandleFunc("GET "+mgmtapi.OpsPattern, func(w http.ResponseWriter, r *http.Request) {
		cl.add("ops")
		m.mu.Lock()
		wait := m.opsWait
		m.mu.Unlock()
		time.Sleep(wait)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.opsCode != 200 {
			http.Error(w, "no", m.opsCode)
			return
		}
		_ = json.NewEncoder(w).Encode(m.ops)
	})
	mux.HandleFunc("POST "+mgmtapi.ReportsPattern, func(w http.ResponseWriter, r *http.Request) {
		cl.add("reports")
		raw, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.batches = append(m.batches, raw)
		code, decide := m.repCode, m.decide
		m.mu.Unlock()
		if code != 200 {
			http.Error(w, "no", code)
			return
		}
		var b mgmtapi.ReportBatch
		if err := json.Unmarshal(raw, &b); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var res mgmtapi.ReportResult
		for _, it := range b.Items {
			res.Outcomes = append(res.Outcomes, decide(it))
		}
		_ = json.NewEncoder(w).Encode(res)
	})
	mux.HandleFunc("POST "+mgmtapi.StatusPattern, func(w http.ResponseWriter, r *http.Request) {
		cl.add("status")
		var rep mgmtapi.StatusReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		m.statuses = append(m.statuses, rep)
		w.WriteHeader(m.statCode)
	})
	m.srv, m.url = serveTLS(t, mux, cfg)
	return m
}

func (m *fakeMgmt) set(f func(m *fakeMgmt)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

func (m *fakeMgmt) reports() []mgmtapi.StatusReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.statuses)
}

func (m *fakeMgmt) bodies() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.batches)
}

// fakeGateway is a gateway on spiffetest TLS.
type fakeGateway struct {
	log      *callLog
	mu       sync.Mutex
	items    []gwapi.OutItem
	status   mgmtapi.GatewayStatus
	syncCode int
	ackCode  int
	hs       atomic.Int32
	syncs    []gwapi.SyncRequest
	acks     []gwapi.AckRequest
	url      string
}

func newFakeGateway(t *testing.T, cl *callLog, cfg *tls.Config) *fakeGateway {
	t.Helper()
	g := &fakeGateway{log: cl, syncCode: 200, ackCode: 204}
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		g.hs.Add(1)
		return nil, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+gwapi.SyncPath, func(w http.ResponseWriter, r *http.Request) {
		cl.add("sync")
		var req gwapi.SyncRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		g.syncs = append(g.syncs, req)
		if g.syncCode != 200 {
			http.Error(w, "no", g.syncCode)
			return
		}
		_ = json.NewEncoder(w).Encode(gwapi.SyncResponse{Items: g.items, Status: g.status})
	})
	mux.HandleFunc("POST "+gwapi.AckPath, func(w http.ResponseWriter, r *http.Request) {
		cl.add("ack")
		var req gwapi.AckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		g.acks = append(g.acks, req)
		w.WriteHeader(g.ackCode)
	})
	_, g.url = serveTLS(t, mux, cfg)
	return g
}

func (g *fakeGateway) set(f func(g *fakeGateway)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f(g)
}

func (g *fakeGateway) seen() ([]gwapi.SyncRequest, []gwapi.AckRequest) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.syncs), slices.Clone(g.acks)
}

type rig struct {
	t     *testing.T
	f     *fx
	cl    *callLog
	mgmt  *fakeMgmt
	gw    *fakeGateway
	store *memStore
	clk   *clock
	logs  *syncBuffer
	read  *sdkmetric.ManualReader
	cfg   PullerConfig
	envCA *spiffetest.CA
}

// newRig starts a management plane and a gateway that both require the SVID of envd, and returns a
// puller config for them. The store starts with the base state, so the spec leg has a saved envelope.
func newRig(t *testing.T, rounds int) *rig {
	t.Helper()
	f := newFx(t)
	mgmtCA := spiffetest.NewCA(t, "mgmt.poc.internal")
	envCA := spiffetest.NewCA(t, "dev.env.poc.internal")
	cur, _ := f.base()
	cl := &callLog{}
	mcfg := tlsconfig.MTLSServerConfig(mgmtCA.Source(t, mgmtID), envCA.Bundle(), tlsconfig.AuthorizeAny())
	gcfg := tlsconfig.MTLSServerConfig(envCA.Source(t, gwID), envCA.Bundle(), tlsconfig.AuthorizeAny())
	r := &rig{t: t, f: f, cl: cl, store: &memStore{state: cur}, clk: newClock(rounds), logs: &syncBuffer{},
		read: sdkmetric.NewManualReader(), envCA: envCA}
	r.mgmt = newFakeMgmt(t, cl, mcfg, firstBundle(f, rev(1, 2)))
	r.gw = newFakeGateway(t, cl, gcfg)
	envd := envCA.Source(t, envdID)
	gwClient := NewClient(cellproxy.ClientTLS(envd, envCA.Bundle(), spiffeid.RequireFromString(gwID)))
	r.cfg = PullerConfig{
		Client:  NewClient(cellproxy.ClientTLS(envd, mgmtCA.Bundle(), spiffeid.RequireFromString(mgmtID))),
		BaseURL: r.mgmt.url, Env: testEnv, Keys: f.keys(), Store: r.store,
		Gateway: NewGatewayClient(gwClient, r.gw.url),
		Log:     newLog(r.logs), Meter: sdkmetric.NewMeterProvider(sdkmetric.WithReader(r.read)).Meter("test"),
		Now: r.clk.Now, Sleep: r.clk.Sleep,
	}
	return r
}

func (r *rig) run() *Puller {
	r.t.Helper()
	p := NewPuller(r.cfg)
	runRounds(r.t, p, r.clk)
	return p
}

func (r *rig) metric(name string) metricdata.Aggregation {
	r.t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.read.Collect(r.t.Context(), &rm); err != nil {
		r.t.Fatal(err)
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

func outItem(id string, kind, cell string, body string) gwapi.OutItem {
	it := gwapi.Item{Kind: kind, Cell: cell, Body: json.RawMessage(body), Token: "tok-" + id}
	if kind == gwapi.KindResult {
		it.OpID = "op-" + id
	}
	return gwapi.OutItem{ID: gwapi.ItemID(id), Item: it}
}

func hexID(n int) string { return fmt.Sprintf("%032x", n) }

func TestRoundRelaysOpsAndReports(t *testing.T) {
	r := newRig(t, 1)
	r.mgmt.set(func(m *fakeMgmt) {
		m.ops = mgmtapi.OpsBundle{Ops: []json.RawMessage{json.RawMessage(`{"payloadType":"op"}`)},
			Cells: []mgmtapi.CellInfo{{Name: "a", Nonce: "n1", Bound: true}}}
	})
	r.gw.set(func(g *fakeGateway) {
		g.items = []gwapi.OutItem{outItem(hexID(1), gwapi.KindResult, "a", `{"x":1}`), outItem(hexID(2), gwapi.KindStatus, "b", `{"y":2}`)}
		g.status = mgmtapi.GatewayStatus{Epoch: 7, OutboxItems: 2}
	})
	r.run()

	syncs, acks := r.gw.seen()
	if len(syncs) != 1 {
		t.Fatalf("syncs %d", len(syncs))
	}
	s := syncs[0]
	if !bytes.Equal(s.SpecEnvelope, r.store.state.SpecEnvelope) || len(s.Records) != len(r.store.state.Records) {
		t.Errorf("sync carries another spec or records")
	}
	for k, v := range r.store.state.Records {
		if !bytes.Equal(s.Records[k], v) {
			t.Errorf("record %s differs", k)
		}
	}
	if len(s.Ops) != 1 || string(s.Ops[0]) != `{"payloadType":"op"}` || len(s.Cells) != 1 || s.Cells[0].Nonce != "n1" {
		t.Errorf("sync ops %s cells %+v", s.Ops, s.Cells)
	}
	bodies := r.mgmt.bodies()
	if len(bodies) != 1 {
		t.Fatalf("report posts %d", len(bodies))
	}
	var b mgmtapi.ReportBatch
	if err := json.Unmarshal(bodies[0], &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 2 || b.Items[0].OpID != "op-"+hexID(1) || b.Items[1].OpID != "" || b.Items[0].ID != hexID(1) || b.Items[0].Kind != "result" || b.Items[0].Token != "tok-"+hexID(1) ||
		b.Items[1].Cell != "b" || string(b.Items[1].Body) != `{"y":2}` {
		t.Errorf("batch %+v", b)
	}
	if len(acks) != 1 || len(acks[0].Outcomes) != 2 || acks[0].Outcomes[0].ID != hexID(1) || acks[0].Outcomes[0].OpID != "op-"+hexID(1) || acks[0].Outcomes[1].Outcome != mgmtapi.OutcomeAccepted {
		t.Errorf("acks %+v", acks)
	}
	reps := r.mgmt.reports()
	if len(reps) != 1 || reps[0].Gateway == nil || reps[0].Gateway.Epoch != 7 {
		t.Fatalf("status reports %+v", reps)
	}
	g, ok := r.metric("envd.gateway.outbox").(metricdata.Gauge[int64])
	if !ok || len(g.DataPoints) != 1 || g.DataPoints[0].Value != 2 {
		t.Errorf("outbox gauge %+v", r.metric("envd.gateway.outbox"))
	}
}

func TestRoundIslandStillSyncsGateway(t *testing.T) {
	r := newRig(t, 2)
	r.gw.set(func(g *fakeGateway) {
		g.items = []gwapi.OutItem{outItem(hexID(1), gwapi.KindResult, "a", `{"x":1}`)}
		g.status = mgmtapi.GatewayStatus{Epoch: 3}
	})
	if err := r.mgmt.srv.Close(); err != nil {
		t.Fatal(err)
	}
	r.run()
	syncs, acks := r.gw.seen()
	if len(syncs) != 2 {
		t.Fatalf("syncs %d, want one each round", len(syncs))
	}
	for _, s := range syncs {
		if len(s.SpecEnvelope) == 0 || len(s.Ops) != 0 || len(s.Cells) != 0 || s.Ops == nil || s.Cells == nil {
			t.Errorf("island sync %+v", s)
		}
	}
	if len(acks) != 0 || r.cl.count("reports") != 0 {
		t.Errorf("an island round acknowledged %+v", acks)
	}
}

func TestRoundDoesNotAckOnReportFailure(t *testing.T) {
	for name, mutate := range map[string]func(m *fakeMgmt){
		"reports_500": func(m *fakeMgmt) { m.repCode = 500 },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 2)
			r.mgmt.set(mutate)
			r.gw.set(func(g *fakeGateway) {
				g.items = []gwapi.OutItem{outItem(hexID(1), gwapi.KindResult, "a", `{"x":1}`)}
			})
			r.run()
			if _, acks := r.gw.seen(); len(acks) != 0 {
				t.Fatalf("acks %+v", acks)
			}
			if name == "reports_500" && r.cl.count("reports") != 2 {
				t.Errorf("report posts %d, want one each round", r.cl.count("reports"))
			}
			if len(r.mgmt.reports()) != 2 {
				t.Errorf("status posts %d: a failed leg stopped the status leg", len(r.mgmt.reports()))
			}
			calls := r.cl.all()
			for i, c := range calls {
				if c == "ack" {
					t.Fatalf("ack at %d in %v", i, calls)
				}
			}
		})
	}
}

// An ops pull that fails does not stop the report leg: mgmtd verifies each item on its own.
func TestRoundReportsDespiteOpsFailure(t *testing.T) {
	r := newRig(t, 1)
	r.mgmt.set(func(m *fakeMgmt) { m.opsCode = 500 })
	r.gw.set(func(g *fakeGateway) {
		g.items = []gwapi.OutItem{outItem(hexID(1), gwapi.KindResult, "a", `{"x":1}`)}
	})
	r.run()
	_, acks := r.gw.seen()
	if r.cl.count("reports") != 1 || len(acks) != 1 || len(acks[0].Outcomes) != 1 {
		t.Fatalf("report posts %d, acks %+v", r.cl.count("reports"), acks)
	}
}

func TestRoundAcksEveryOutcome(t *testing.T) {
	r := newRig(t, 1)
	outcomes := []string{mgmtapi.OutcomeAccepted, mgmtapi.OutcomeDuplicate, mgmtapi.OutcomeUnknownOp, mgmtapi.OutcomeForgedSeen,
		mgmtapi.OutcomeRefused, mgmtapi.OutcomeRetry}
	var items []gwapi.OutItem
	for i := range outcomes {
		items = append(items, outItem(hexID(i+1), gwapi.KindResult, "a", fmt.Sprintf(`{"n":%d}`, i)))
	}
	r.gw.set(func(g *fakeGateway) { g.items = items })
	r.mgmt.set(func(m *fakeMgmt) {
		m.decide = func(it mgmtapi.ReportItem) mgmtapi.ItemOutcome {
			var n int
			_, _ = fmt.Sscanf(it.ID, "%032x", &n)
			o := mgmtapi.ItemOutcome{ID: it.ID, Outcome: outcomes[n-1]}
			switch o.Outcome {
			case mgmtapi.OutcomeRefused:
				o.Reason = mgmtapi.ReasonPayloadInvalid
			case mgmtapi.OutcomeRetry:
				o.Reason, o.Detail = mgmtapi.ReasonProofInvalid, "token_expired"
			}
			return o
		}
	})
	r.run()
	_, acks := r.gw.seen()
	if len(acks) != 1 || len(acks[0].Outcomes) != len(outcomes) {
		t.Fatalf("acks %+v", acks)
	}
	for i, o := range acks[0].Outcomes {
		if o.Outcome != outcomes[i] || o.ID != hexID(i+1) {
			t.Errorf("ack %d = %+v, want %s", i, o, outcomes[i])
		}
	}
	if o := acks[0].Outcomes[5]; o.Reason != mgmtapi.ReasonProofInvalid || o.Detail != "token_expired" {
		t.Errorf("retry outcome lost its reason: %+v", o)
	}
	sum, ok := r.metric("envd.relay.items").(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != len(outcomes) {
		t.Fatalf("relay counter %+v", r.metric("envd.relay.items"))
	}
	for _, dp := range sum.DataPoints {
		v, _ := dp.Attributes.Value("outcome")
		if dp.Value != 1 || !slices.Contains(outcomes, v.AsString()) {
			t.Errorf("data point %+v", dp)
		}
	}
}

// A mgmtd answer that names an ID that was not sent, or leaves one out, acknowledges only the items
// that it decided.
func TestRoundAcksOnlyDecidedItems(t *testing.T) {
	r := newRig(t, 1)
	r.gw.set(func(g *fakeGateway) {
		g.items = []gwapi.OutItem{outItem(hexID(1), gwapi.KindResult, "a", `{}`), outItem(hexID(2), gwapi.KindResult, "a", `{}`)}
	})
	r.mgmt.set(func(m *fakeMgmt) {
		m.decide = func(it mgmtapi.ReportItem) mgmtapi.ItemOutcome {
			if it.ID == hexID(2) {
				return mgmtapi.ItemOutcome{ID: hexID(99), Outcome: mgmtapi.OutcomeAccepted}
			}
			return accepted(it)
		}
	})
	r.run()
	_, acks := r.gw.seen()
	if len(acks) != 1 || len(acks[0].Outcomes) != 1 || acks[0].Outcomes[0].ID != hexID(1) {
		t.Fatalf("acks %+v", acks)
	}
}

// The body of an item reaches mgmtd with the bytes that celld signed, also when it holds < and &.
func TestReportBodyBytesReachMgmtdUnchanged(t *testing.T) {
	// Fields out of alphabetical order, an integer above 2^53 and HTML characters: a re-encode that
	// sorts keys, rounds numbers or drops the escapes changes these bytes.
	type resultBody struct {
		Z string `json:"z"`
		A uint64 `json:"a"`
		U string `json:"u"`
		M string `json:"m"`
	}
	body, err := json.Marshal(resultBody{Z: "a<b && c>d", A: 18446744073709551615, U: "\u2028", M: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(body, "<>&") || !bytes.Contains(body, []byte(`\u003c`)) || !bytes.Contains(body, []byte(`\u0026`)) ||
		bytes.Index(body, []byte(`"z"`)) > bytes.Index(body, []byte(`"a"`)) {
		t.Fatalf("control: Marshal output %s", body)
	}
	r := newRig(t, 1)
	r.gw.set(func(g *fakeGateway) {
		g.items = []gwapi.OutItem{outItem(hexID(1), gwapi.KindResult, "a", string(body))}
	})
	var got []byte
	r.mgmt.set(func(m *fakeMgmt) {
		m.decide = func(it mgmtapi.ReportItem) mgmtapi.ItemOutcome {
			got = bytes.Clone(it.Body)
			return accepted(it)
		}
	})
	r.run()
	if !bytes.Equal(got, body) {
		t.Fatalf("mgmtd got %s, celld signed %s", got, body)
	}
	if !bytes.Contains(r.mgmt.bodies()[0], body) {
		t.Errorf("the post does not hold the signed bytes: %s", r.mgmt.bodies()[0])
	}
}

func TestRoundBatchLimits(t *testing.T) {
	r := newRig(t, 1)
	var items []gwapi.OutItem
	for i := range 150 {
		items = append(items, outItem(hexID(i+1), gwapi.KindStatus, "a", `{}`))
	}
	r.gw.set(func(g *fakeGateway) { g.items = items })
	r.run()
	var b mgmtapi.ReportBatch
	if err := json.Unmarshal(r.mgmt.bodies()[0], &b); err != nil || len(b.Items) != MaxReportItems {
		t.Fatalf("items %d, err %v", len(b.Items), err)
	}
	_, acks := r.gw.seen()
	if len(acks) != 1 || len(acks[0].Outcomes) != MaxReportItems {
		t.Fatalf("acks %+v", acks)
	}

	big := strings.Repeat("x", 300<<10)
	var large []gwapi.OutItem
	for i := range 5 {
		large = append(large, outItem(hexID(i+1), gwapi.KindStatus, "a", `"`+big+`"`))
	}
	if got := batch(large); len(got.Items) != 3 {
		t.Errorf("a batch of 300 KiB items holds %d, want 3", len(got.Items))
	}
	raw, _ := json.Marshal(batch(large))
	if len(raw) > MaxReportBytes {
		t.Errorf("batch is %d bytes", len(raw))
	}
}

func TestGatewayClientRequiresGatewayID(t *testing.T) {
	envCA := spiffetest.NewCA(t, "dev.env.poc.internal")
	envd := envCA.Source(t, envdID)
	for name, serverID := range map[string]string{"gateway": gwID, "other_workload": "spiffe://dev.env.poc.internal/cp/other"} {
		t.Run(name, func(t *testing.T) {
			cl := &callLog{}
			g := newFakeGateway(t, cl, tlsconfig.MTLSServerConfig(envCA.Source(t, serverID), envCA.Bundle(), tlsconfig.AuthorizeAny()))
			c := NewGatewayClient(NewClient(cellproxy.ClientTLS(envd, envCA.Bundle(), spiffeid.RequireFromString(gwID))), g.url)
			_, err := c.Sync(t.Context(), gwapi.SyncRequest{})
			if name == "gateway" && err != nil {
				t.Fatalf("control: %v", err)
			}
			if name != "gateway" && (err == nil || cl.count("sync") != 0) {
				t.Fatalf("a server with another ID was accepted: err %v, syncs %d", err, cl.count("sync"))
			}
		})
	}
}

func TestGatewayClientBodyLimit(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"items":[],"status":{"storeError":"`)
		_, _ = io.WriteString(w, strings.Repeat("x", MaxGatewayBody))
		_, _ = io.WriteString(w, `"}}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c := NewGatewayClient(srv.Client(), srv.URL)
	if _, err := c.Sync(t.Context(), gwapi.SyncRequest{}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("sync of an oversize body: %v", err)
	}
}

// Every leg runs under its own deadline: the spec and ops legs use most of the round time, and the
// gateway sync and the status post still get a full deadline.
func TestRoundLegsHaveOwnDeadline(t *testing.T) {
	r := newRig(t, 1)
	r.cfg.RoundTimeout = 500 * time.Millisecond
	r.mgmt.set(func(m *fakeMgmt) {
		m.specWait, m.opsWait = 400*time.Millisecond, 300*time.Millisecond
		m.ops = mgmtapi.OpsBundle{Ops: []json.RawMessage{json.RawMessage(`{"o":1}`)}}
	})
	r.run()
	syncs, _ := r.gw.seen()
	if len(syncs) != 1 || len(syncs[0].Ops) != 1 {
		t.Fatalf("syncs %+v: the ops leg or the sync ran out of time", syncs)
	}
	if reps := r.mgmt.reports(); len(reps) != 1 || reps[0].Gateway == nil {
		t.Fatalf("status reports %+v", reps)
	}
}

// A slow gateway does not leave the status leg without time.
func TestRoundSlowGatewayStillReportsStatus(t *testing.T) {
	r := newRig(t, 1)
	r.cfg.RoundTimeout = 500 * time.Millisecond
	r.cfg.Gateway = slowGateway{d: 700 * time.Millisecond}
	r.run()
	if len(r.mgmt.reports()) != 1 {
		t.Fatalf("status posts %d after a slow gateway", len(r.mgmt.reports()))
	}
	if r.mgmt.reports()[0].Gateway != nil {
		t.Error("a failed sync reported a gateway status")
	}
}

type slowGateway struct{ d time.Duration }

func (s slowGateway) Sync(ctx context.Context, _ gwapi.SyncRequest) (gwapi.SyncResponse, error) {
	select {
	case <-ctx.Done():
		return gwapi.SyncResponse{}, ctx.Err()
	case <-time.After(s.d):
		return gwapi.SyncResponse{}, nil
	}
}
func (slowGateway) Ack(context.Context, gwapi.AckRequest) error { return nil }
func (slowGateway) CloseIdleConnections()                       {}

// bareGateway has no CloseIdleConnections.
type bareGateway struct{}

func (bareGateway) Sync(context.Context, gwapi.SyncRequest) (gwapi.SyncResponse, error) {
	return gwapi.SyncResponse{}, nil
}
func (bareGateway) Ack(context.Context, gwapi.AckRequest) error { return nil }

// A log line of a round carries trace_id, also in the gateway legs.
func TestRoundGatewayLogCarriesTraceID(t *testing.T) {
	r := newRig(t, 1)
	r.gw.set(func(g *fakeGateway) { g.syncCode = 500 })
	var out syncBuffer
	r.cfg.Log = telemetry.NewLogger(&out, slog.DiscardHandler)
	r.cfg.Tracer = sdktrace.NewTracerProvider().Tracer("test")
	r.run()
	var found bool
	for _, m := range out.lines() {
		if m["msg"] == "gateway sync failed" {
			found = true
			if id, _ := m["trace_id"].(string); len(id) != 32 || id == (trace.TraceID{}).String() {
				t.Errorf("line %v has no trace_id", m)
			}
		}
	}
	if !found {
		t.Fatalf("no gateway sync failure line in %v", out.lines())
	}
}

func hintCM(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "attest-hints", Namespace: "spire-system"}, Data: data}
}

func hintJSON(at time.Time) string { return `{"at":"` + at.UTC().Format(time.RFC3339) + `"}` }

func hintCells(h []mgmtapi.KeyHint) []string {
	var out []string
	for _, k := range h {
		out = append(out, k.Cell)
	}
	return out
}

func TestHintsForwardOnce(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC) // before the fake clock, which starts at 09:00
	kube := fake.NewClientset(hintCM(map[string]string{"dev-cell-1": hintJSON(t0)}))
	r := newRig(t, 4)
	r.cfg.Hints = NewConfigMapHints(kube, "spire-system", "attest-hints", newLog(io.Discard))
	// The second status post fails, so its hint stays pending for the third round.
	rounds := 0
	inner := r.cfg.Sleep
	r.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		rounds++
		switch rounds {
		case 1:
			cm, _ := kube.CoreV1().ConfigMaps("spire-system").Get(ctx, "attest-hints", metav1.GetOptions{})
			cm.Data["dev-cell-1"] = hintJSON(t0.Add(time.Minute))
			_, _ = kube.CoreV1().ConfigMaps("spire-system").Update(ctx, cm, metav1.UpdateOptions{})
			r.mgmt.set(func(m *fakeMgmt) { m.statCode = 500 })
		case 2:
			r.mgmt.set(func(m *fakeMgmt) { m.statCode = 204 })
		}
		return inner(ctx, d)
	}
	r.run()
	reps := r.mgmt.reports()
	if len(reps) != 4 {
		t.Fatalf("reports %d", len(reps))
	}
	want := [][]string{{"dev-cell-1"}, {"dev-cell-1"}, {"dev-cell-1"}, nil}
	for i, rep := range reps {
		if got := hintCells(rep.KeyHints); !slices.Equal(got, want[i]) {
			t.Errorf("report %d hints %v, want %v", i, got, want[i])
		}
	}
	if !reps[0].KeyHints[0].At.Equal(t0) || !reps[1].KeyHints[0].At.Equal(t0.Add(time.Minute)) || !reps[2].KeyHints[0].At.Equal(t0.Add(time.Minute)) {
		t.Errorf("hint times %+v", reps)
	}
}

func TestHintsMergeGatewayHints(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC) // before the fake clock, which starts at 09:00
	r := newRig(t, 3)
	r.gw.set(func(g *fakeGateway) {
		g.status = mgmtapi.GatewayStatus{KeyHints: []mgmtapi.KeyHint{{Cell: "dev-cell-1", At: t0}, {Cell: "Not A Label", At: t0}}}
	})
	r.run()
	reps := r.mgmt.reports()
	if len(reps) != 3 {
		t.Fatalf("reports %d", len(reps))
	}
	if got := hintCells(reps[0].KeyHints); !slices.Equal(got, []string{"dev-cell-1"}) {
		t.Errorf("first report hints %v", got)
	}
	for i := 1; i < 3; i++ {
		if len(reps[i].KeyHints) != 0 {
			t.Errorf("report %d repeats the gateway hint: %v", i, reps[i].KeyHints)
		}
	}
}

// A gateway hint and a ConfigMap hint for one cell go out as one hint, the newer one, and the
// mark covers both sources.
func TestHintsMergeUnderOneMark(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC) // before the fake clock, which starts at 09:00
	kube := fake.NewClientset(hintCM(map[string]string{"dev-cell-1": hintJSON(t0)}))
	r := newRig(t, 2)
	r.cfg.Hints = NewConfigMapHints(kube, "spire-system", "attest-hints", newLog(io.Discard))
	r.gw.set(func(g *fakeGateway) {
		g.status = mgmtapi.GatewayStatus{KeyHints: []mgmtapi.KeyHint{{Cell: "dev-cell-1", At: t0.Add(30 * time.Second)}}}
	})
	r.run()
	reps := r.mgmt.reports()
	if len(reps[0].KeyHints) != 1 || !reps[0].KeyHints[0].At.Equal(t0.Add(30*time.Second)) || len(reps[1].KeyHints) != 0 {
		t.Fatalf("hints %+v then %+v", reps[0].KeyHints, reps[1].KeyHints)
	}
}

func TestHintsIgnoreMalformed(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC) // before the fake clock, which starts at 09:00
	kube := fake.NewClientset(hintCM(map[string]string{
		"dev-cell-1":    hintJSON(t0),
		"Not_A_Label":   hintJSON(t0),
		"dev-cell-2":    `{"at":"yesterday"}`,
		"dev-cell-3":    `not json`,
		"dev-cell-4":    `{}`,
		"dev-cell-5":    `{"at":"` + strings.Repeat("0", 400) + `"}`,
		"-leading-dash": hintJSON(t0),
	}))
	var logs syncBuffer
	h := NewConfigMapHints(kube, "spire-system", "attest-hints", newLog(&logs))
	got, err := h.New(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Cell != "dev-cell-1" || !got[0].At.Equal(t0) {
		t.Fatalf("hints %+v", got)
	}
	h.Forwarded(got)
	if again, _ := h.New(t.Context()); len(again) != 0 {
		t.Errorf("a forwarded hint came back: %+v", again)
	}
	// A hint at the mark, or older, is not new.
	cm, _ := kube.CoreV1().ConfigMaps("spire-system").Get(t.Context(), "attest-hints", metav1.GetOptions{})
	cm.Data["dev-cell-1"] = hintJSON(t0.Add(-time.Second))
	_, _ = kube.CoreV1().ConfigMaps("spire-system").Update(t.Context(), cm, metav1.UpdateOptions{})
	if again, _ := h.New(t.Context()); len(again) != 0 {
		t.Errorf("an older hint came back: %+v", again)
	}
}

func TestEnsureHintsCreates(t *testing.T) {
	kube := fake.NewClientset()
	h := NewConfigMapHints(kube, "spire-system", "attest-hints", newLog(io.Discard))
	got, err := h.New(t.Context())
	if err != nil || len(got) != 0 {
		t.Fatalf("hints %+v, err %v", got, err)
	}
	cm, err := kube.CoreV1().ConfigMaps("spire-system").Get(t.Context(), "attest-hints", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("ConfigMap not created: %v", err)
	}
	if cm.Labels["poc.internal/made-by"] != "envd" || len(cm.Data) != 0 {
		t.Errorf("labels %v data %v", cm.Labels, cm.Data)
	}
	// An existing ConfigMap keeps its content and labels.
	kube = fake.NewClientset(hintCM(map[string]string{"dev-cell-1": hintJSON(time.Now())}))
	if got, err := NewConfigMapHints(kube, "spire-system", "attest-hints", newLog(io.Discard)).New(t.Context()); err != nil || len(got) != 1 {
		t.Fatalf("existing: %+v, %v", got, err)
	}
}

// Each round dials the gateway again, so the handshake uses the current SVID.
func TestRoundNewGatewayHandshakeEachRound(t *testing.T) {
	r := newRig(t, 3)
	r.run()
	if n := r.gw.hs.Load(); n != 3 {
		t.Fatalf("gateway handshakes %d, want 3", n)
	}
}

// A gateway client that cannot drop its connections is a start error, not a silent skip.
func TestRunRefusesGatewayWithoutCloseIdleConnections(t *testing.T) {
	r := newRig(t, 1)
	r.cfg.Gateway = bareGateway{}
	err := NewPuller(r.cfg).Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "CloseIdleConnections") {
		t.Fatalf("Run returned %v", err)
	}
	if r.cl.count("spec") != 0 {
		t.Error("a round ran")
	}
}

// A hint source that blocks until its context ends costs one deadline, not the round.
func TestRoundHintsReadHasOwnDeadline(t *testing.T) {
	r := newRig(t, 1)
	r.cfg.RoundTimeout = 300 * time.Millisecond
	r.cfg.Hints = stalledHints{}
	start := time.Now()
	r.run()
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("round took %v", took)
	}
	if reps := r.mgmt.reports(); len(reps) != 1 || len(reps[0].KeyHints) != 0 {
		t.Fatalf("status reports %+v", reps)
	}
}

type stalledHints struct{}

func (stalledHints) New(ctx context.Context) ([]mgmtapi.KeyHint, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (stalledHints) Forwarded([]mgmtapi.KeyHint) {}

// While no spec is accepted, neither the ops leg nor the sync runs, and one info line says so.
func TestRoundWithoutSpecSkipsOpsAndLogsOnce(t *testing.T) {
	r := newRig(t, 3)
	r.store.state = nil
	r.mgmt.set(func(m *fakeMgmt) {
		m.bundle = mgmtapi.SpecBundle{Spec: []byte(`{"payloadType":"x","payload":"","signatures":[]}`)}
	})
	r.run()
	if r.cl.count("ops") != 0 || r.cl.count("sync") != 0 {
		t.Errorf("calls %v", r.cl.all())
	}
	if n := r.logs.count("relay skipped: no accepted spec"); n != 1 {
		t.Errorf("skip log lines %d, want 1", n)
	}
}

// A hint in the future counts as now, goes out once, and does not silence later hints.
func TestHintsClampFutureTime(t *testing.T) {
	r := newRig(t, 3)
	now := r.clk.Now()
	kube := fake.NewClientset(hintCM(map[string]string{"dev-cell-1": hintJSON(now.Add(time.Hour))}))
	r.cfg.Hints = NewConfigMapHints(kube, "spire-system", "attest-hints", newLog(io.Discard))
	r.gw.set(func(g *fakeGateway) {
		g.status = mgmtapi.GatewayStatus{KeyHints: []mgmtapi.KeyHint{{Cell: "dev-cell-2", At: now.Add(2 * time.Hour)}}}
	})
	rounds := 0
	inner := r.cfg.Sleep
	r.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		rounds++
		if rounds == 2 {
			// A real hint, after the clamped one, still goes out.
			cm, _ := kube.CoreV1().ConfigMaps("spire-system").Get(ctx, "attest-hints", metav1.GetOptions{})
			cm.Data["dev-cell-3"] = hintJSON(r.clk.Now().Add(time.Second))
			_, _ = kube.CoreV1().ConfigMaps("spire-system").Update(ctx, cm, metav1.UpdateOptions{})
		}
		return inner(ctx, d)
	}
	r.run()
	reps := r.mgmt.reports()
	if len(reps) != 3 {
		t.Fatalf("reports %d", len(reps))
	}
	if got := hintCells(reps[0].KeyHints); !slices.Equal(got, []string{"dev-cell-1", "dev-cell-2"}) {
		t.Fatalf("first report hints %v", got)
	}
	for _, k := range reps[0].KeyHints {
		if k.At.After(now) {
			t.Errorf("hint %+v is in the future", k)
		}
	}
	if len(reps[1].KeyHints) != 0 {
		t.Errorf("a clamped hint went out again: %+v", reps[1].KeyHints)
	}
	if got := hintCells(reps[2].KeyHints); !slices.Equal(got, []string{"dev-cell-3"}) {
		t.Errorf("third report hints %v", got)
	}
}

// An item that mgmtd leaves without an outcome stays unacknowledged and is logged at debug level.
func TestRoundLogsItemWithoutOutcome(t *testing.T) {
	r := newRig(t, 1)
	r.cfg.Log = slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r.gw.set(func(g *fakeGateway) {
		g.items = []gwapi.OutItem{outItem(hexID(1), gwapi.KindResult, "a", `{}`), outItem(hexID(2), gwapi.KindResult, "a", `{}`)}
	})
	r.mgmt.set(func(m *fakeMgmt) {
		m.decide = func(it mgmtapi.ReportItem) mgmtapi.ItemOutcome {
			if it.ID == hexID(2) {
				return mgmtapi.ItemOutcome{ID: hexID(1), Outcome: mgmtapi.OutcomeDuplicate}
			}
			return accepted(it)
		}
	})
	r.run()
	var found bool
	for _, l := range r.logs.lines() {
		if l["msg"] == "report item has no outcome" && l["item"] == hexID(2) && l["level"] == "DEBUG" {
			found = true
		}
	}
	if !found {
		t.Errorf("no debug line for the item without an outcome: %v", r.logs.lines())
	}
}
