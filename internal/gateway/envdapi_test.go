package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

type envdFixture struct {
	e      *gwEnv
	url    string
	client *http.Client
	envd   spiffeid.ID
}

type envdSetup struct {
	streams func() map[string]int
	refuse  func() map[string]mgmtapi.BindRefusal
	hints   func() []mgmtapi.KeyHint
}

func newEnvdFixture(t *testing.T, e *gwEnv, s envdSetup) *envdFixture {
	t.Helper()
	id, _ := spiffeid.FromString(envdID)
	var opts []EnvdOption
	if s.hints != nil {
		opts = append(opts, WithKeyHints(s.hints))
	}
	h := NewEnvdHandler(e.st, e.g.keys(), id, s.streams, s.refuse, nil, opts...)
	tlsCfg := EnvdServerTLS(e.ca.Source(t, gwSPIFFE), e.ca.Bundle(), id)
	srv := NewEnvdServer(h, tlsCfg, nil)
	ln := ListenEnvd(listenDual(t), tlsCfg)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	f := &envdFixture{e: e, url: "https://127.0.0.1:" + port, envd: id}
	f.client = f.clientFor(t, envdID)
	return f
}

func (f *envdFixture) clientFor(t *testing.T, id string) *http.Client {
	t.Helper()
	cfg := f.e.clientTLS(staticSource{f.e.ca.SVID(t, id)})
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (f *envdFixture) post(t *testing.T, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	resp, err := f.client.Post(f.url+path, "application/json", rd)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *gwEnv) syncRequest(ops [][]byte, cells []mgmtapi.CellInfo) gwapi.SyncRequest {
	b := e.bundle()
	req := gwapi.SyncRequest{SpecEnvelope: b.spec, Records: b.records, Cells: cells}
	for _, o := range ops {
		req.Ops = append(req.Ops, o)
	}
	return req
}

func decodeSync(t *testing.T, code int, body []byte) gwapi.SyncResponse {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("sync status %d: %s", code, body)
	}
	var resp gwapi.SyncResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestEnvdAPIOnlyEnvd(t *testing.T) {
	e := newGwEnv(t)
	f := newEnvdFixture(t, e, envdSetup{})
	// A client of another identity does not complete the handshake.
	other := f.clientFor(t, celld1)
	if resp, err := other.Post(f.url+gwapi.SyncPath, "application/json", strings.NewReader("{}")); err == nil {
		resp.Body.Close()
		t.Fatalf("a cell client reached the envd API with status %d", resp.StatusCode)
	}
	// The handler checks the peer again from the TLS state of each request.
	h := NewEnvdHandler(e.st, e.g.keys(), f.envd, nil, nil, nil)
	leafOf := func(id string) *x509.Certificate { return e.ca.SVID(t, id).Certificates[0] }
	for name, tlsState := range map[string]*tls.ConnectionState{
		"no_tls":       nil,
		"no_cert":      {},
		"other_peer":   {PeerCertificates: []*x509.Certificate{leafOf(celld1)}},
		"gateway_peer": {PeerCertificates: []*x509.Certificate{leafOf(gwSPIFFE)}},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, gwapi.SyncPath, strings.NewReader("{}"))
			req.TLS = tlsState
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var d mgmtapi.Denied
			if rec.Code != http.StatusForbidden || json.Unmarshal(rec.Body.Bytes(), &d) != nil || d.Error != mgmtapi.DeniedError || len(d.RequestID) != 16 {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
		})
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafOf(envdID)}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown route gave %d", rec.Code)
	}
}

func TestSyncEnqueuesAndReturnsItems(t *testing.T) {
	e := newGwEnv(t)
	f := newEnvdFixture(t, e, envdSetup{})
	ctx := context.Background()
	if _, err := e.st.Append(ctx, resultItem(cell1, opID(9))); err != nil {
		t.Fatal(err)
	}
	cells := []mgmtapi.CellInfo{{Name: cell1, Nonce: "n1", NonceExpiresAt: time.Now().Add(time.Hour), Bound: true}}
	req := e.syncRequest([][]byte{e.opEnvelope(1, cell1), e.opEnvelope(2, cell1), e.opEnvelope(3, cell2)}, cells)
	code, body := f.post(t, gwapi.SyncPath, req)
	resp := decodeSync(t, code, body)
	if len(resp.Items) != 1 || resp.Items[0].OpID != opID(9) || resp.Items[0].Kind != gwapi.KindResult {
		t.Fatalf("items %+v", resp.Items)
	}
	if resp.Status.Queued[cell1] != 2 || resp.Status.Queued[cell2] != 1 || resp.Status.Epoch != e.st.Epoch() ||
		resp.Status.SyncedAt.IsZero() || resp.Status.OutboxItems != 1 || resp.Status.Records[cell1] != rev(1, 1) {
		t.Fatalf("status %+v", resp.Status)
	}
	if latest, _, ok, _ := e.st.CellInfo(ctx, cell1); !ok || latest.Nonce != "n1" {
		t.Fatalf("cell info %+v, %v", latest, ok)
	}
	// The same sync again adds nothing, and the unacked item comes again.
	code, body = f.post(t, gwapi.SyncPath, req)
	resp = decodeSync(t, code, body)
	if resp.Status.Queued[cell1] != 2 || len(resp.Items) != 1 {
		t.Fatalf("second sync: %+v", resp)
	}
	// A bad envelope is skipped, and the good one still counts.
	bad := e.syncRequest([][]byte{[]byte(`{"payload":"x"}`), e.opEnvelope(4, cell1)}, nil)
	code, body = f.post(t, gwapi.SyncPath, bad)
	if resp = decodeSync(t, code, body); resp.Status.Queued[cell1] != 3 {
		t.Fatalf("queued %+v", resp.Status.Queued)
	}
}

// An empty list is no information for that round: it never withdraws anything.
func TestSyncEmptyListsWithdrawNothing(t *testing.T) {
	e := newGwEnv(t)
	f := newEnvdFixture(t, e, envdSetup{})
	cells := []mgmtapi.CellInfo{{Name: cell1, Nonce: "n1", NonceExpiresAt: time.Now().Add(time.Hour)}}
	code, body := f.post(t, gwapi.SyncPath, e.syncRequest([][]byte{e.opEnvelope(1, cell1)}, cells))
	decodeSync(t, code, body)
	code, body = f.post(t, gwapi.SyncPath, e.syncRequest(nil, nil))
	resp := decodeSync(t, code, body)
	if resp.Status.Queued[cell1] != 1 {
		t.Fatalf("an empty op list withdrew an operation: %+v", resp.Status.Queued)
	}
	if latest, _, ok, _ := e.st.CellInfo(context.Background(), cell1); !ok || latest.Nonce != "n1" {
		t.Fatalf("an empty cell list withdrew the nonce: %+v %v", latest, ok)
	}
	var raw bytes.Buffer
	raw.WriteString(`{"specEnvelope":`)
	b := e.bundle()
	raw.Write(b.spec)
	raw.WriteString(`,"records":`)
	rj, _ := json.Marshal(b.records)
	raw.Write(rj)
	raw.WriteString(`,"ops":null,"cells":null}`)
	code, body = f.post(t, gwapi.SyncPath, raw.Bytes())
	decodeSync(t, code, body)
}

func TestSyncRefusesForeignRecords(t *testing.T) {
	e := newGwEnv(t)
	f := newEnvdFixture(t, e, envdSetup{})
	// A spec and records signed by another key.
	foreign := newSigner(t)
	foreign.jwks = e.g.jwks
	fb := foreign.bundle(rev(1, 5), map[string]spec.Revision{cell1: rev(1, 5)})
	code, body := f.post(t, gwapi.SyncPath, gwapi.SyncRequest{SpecEnvelope: fb.spec, Records: fb.records})
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), mgmtapi.ReasonSignatureInvalid) {
		t.Fatalf("foreign key: %d %s", code, body)
	}
	// A record that the spec does not index.
	b := e.bundle()
	extra := newSigner(t)
	extra.priv, extra.pub = e.g.priv, e.g.pub
	eb := extra.bundle(rev(1, 5), map[string]spec.Revision{"dev-cell-3": rev(1, 5)})
	recs := map[string]json.RawMessage{"dev-cell-3": eb.records["dev-cell-3"]}
	for k, v := range b.records {
		recs[k] = v
	}
	code, body = f.post(t, gwapi.SyncPath, gwapi.SyncRequest{SpecEnvelope: b.spec, Records: recs})
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), mgmtapi.ReasonRecordUnindexed) {
		t.Fatalf("unindexed record: %d %s", code, body)
	}
	// A refused sync enqueues nothing.
	code, body = f.post(t, gwapi.SyncPath, gwapi.SyncRequest{SpecEnvelope: fb.spec, Records: fb.records, Ops: []json.RawMessage{e.opEnvelope(1, cell1)}})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d %s", code, body)
	}
	if n, _ := e.st.Depth(context.Background(), cell1); n != 0 {
		t.Fatalf("a refused sync enqueued %d operations", n)
	}
}

func TestSyncBodyLimitsAndShape(t *testing.T) {
	e := newGwEnv(t)
	f := newEnvdFixture(t, e, envdSetup{})
	code, body := f.post(t, gwapi.SyncPath, bytes.Repeat([]byte(" "), 4<<20+1))
	if code != http.StatusBadRequest || !strings.Contains(string(body), "body_too_large") {
		t.Fatalf("a body of 4 MiB and 1 byte: %d %s", code, body)
	}
	if code, body = f.post(t, gwapi.SyncPath, []byte(`{"specEnvelope":"e30=","records":{},"ops":[],"cells":[],"extra":1}`)); code != http.StatusBadRequest {
		t.Fatalf("an unknown member: %d %s", code, body)
	}
	if code, body = f.post(t, gwapi.AckPath, bytes.Repeat([]byte(" "), 4<<20+1)); code != http.StatusBadRequest {
		t.Fatalf("an ack body of 4 MiB and 1 byte: %d %s", code, body)
	}
	if resp, err := f.client.Get(f.url + gwapi.SyncPath); err != nil || resp.StatusCode == http.StatusOK {
		t.Fatalf("GET on the sync path: %v %v", resp, err)
	}
}

func TestAckStoresOutcomes(t *testing.T) {
	e := newGwEnv(t)
	f := newEnvdFixture(t, e, envdSetup{})
	ctx := context.Background()
	bindID, err := e.st.Append(ctx, gwapi.Item{Kind: gwapi.KindBind, Cell: cell1, Body: json.RawMessage(`{}`), Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	resID, err := e.st.Append(ctx, resultItem(cell1, opID(1)))
	if err != nil {
		t.Fatal(err)
	}
	code, body := f.post(t, gwapi.SyncPath, e.syncRequest(nil, nil))
	if resp := decodeSync(t, code, body); len(resp.Items) != 2 {
		t.Fatalf("items %+v", resp.Items)
	}
	ack := gwapi.AckRequest{Outcomes: []mgmtapi.ItemOutcome{
		{ID: string(bindID), Outcome: mgmtapi.OutcomeAccepted, Bind: &mgmtapi.BindResponse{Status: mgmtapi.StatusBound}},
		{ID: string(resID), Outcome: mgmtapi.OutcomeDuplicate},
		{ID: strings.Repeat("0", 32), Outcome: mgmtapi.OutcomeAccepted},
	}}
	if code, body = f.post(t, gwapi.AckPath, ack); code != http.StatusNoContent {
		t.Fatalf("ack status %d %s", code, body)
	}
	o, ok, err := e.st.Outcome(ctx, cell1, bindID)
	if err != nil || !ok || o.Outcome != mgmtapi.OutcomeAccepted || o.Bind == nil || o.Bind.Status != mgmtapi.StatusBound {
		t.Fatalf("bind outcome %+v, %v, %v", o, ok, err)
	}
	finals, _, err := e.st.FinalOutcomes(ctx, cell1, 0)
	if err != nil || len(finals) != 1 || finals[0].OpID != opID(1) || finals[0].Outcome != mgmtapi.OutcomeDuplicate {
		t.Fatalf("final outcomes %+v, %v", finals, err)
	}
	code, body = f.post(t, gwapi.SyncPath, e.syncRequest(nil, nil))
	if resp := decodeSync(t, code, body); len(resp.Items) != 0 || resp.Items == nil {
		t.Fatalf("items after the ack: %+v", resp.Items)
	}
}

func TestSyncStatusHasStreams(t *testing.T) {
	e := newGwEnv(t)
	at := time.Date(2026, 11, 14, 1, 2, 3, 0, time.UTC)
	f := newEnvdFixture(t, e, envdSetup{
		streams: func() map[string]int { return map[string]int{cell1: 2} },
		refuse: func() map[string]mgmtapi.BindRefusal {
			return map[string]mgmtapi.BindRefusal{cell2: {Reason: "token_invalid", RequestID: "0123456789abcdef", At: at}}
		},
		hints: func() []mgmtapi.KeyHint { return []mgmtapi.KeyHint{{Cell: cell1, At: at}} },
	})
	code, body := f.post(t, gwapi.SyncPath, e.syncRequest(nil, nil))
	st := decodeSync(t, code, body).Status
	if st.Streams[cell1] != 2 {
		t.Fatalf("streams %+v", st.Streams)
	}
	if r := st.LastBindRefusal[cell2]; r.Reason != "token_invalid" || r.RequestID != "0123456789abcdef" || !r.At.Equal(at) {
		t.Fatalf("last bind refusal %+v", st.LastBindRefusal)
	}
	if len(st.KeyHints) != 1 || st.KeyHints[0].Cell != cell1 {
		t.Fatalf("key hints %+v", st.KeyHints)
	}
}

// The hint from a refused hello reaches envd through the next sync.
func TestHelloHintRidesTheSyncStatus(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{})
	f := newEnvdFixture(t, e, envdSetup{streams: h.Streams, hints: h.TakeHints})
	c := e.open(addr, cell1, openOpts{})
	defer c.close()
	other := kubetoken.NewSigner(t, "unknown-kid", jose.ES256)
	tok := other.Token(t, kubetoken.Claims{Issuer: cell1Iss, Namespace: testNS, ServiceAccount: testSA, PodName: "p", PodUID: "u",
		NodeName: "n", Audience: []string{proof.HelloAudience(cell1, c.binding())}})
	c.send(gwapi.Frame{Type: gwapi.TypeHello, Token: tok})
	c.expect(gwapi.TypeRefused)
	code, body := f.post(t, gwapi.SyncPath, e.syncRequest(nil, nil))
	if st := decodeSync(t, code, body).Status; len(st.KeyHints) != 1 || st.KeyHints[0].Cell != cell1 {
		t.Fatalf("key hints %+v", st.KeyHints)
	}
	code, body = f.post(t, gwapi.SyncPath, e.syncRequest(nil, nil))
	if st := decodeSync(t, code, body).Status; len(st.KeyHints) != 0 {
		t.Fatalf("the hint came twice: %+v", st.KeyHints)
	}
}
