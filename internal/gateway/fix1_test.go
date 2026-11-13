package gateway

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// ---- C-1

func TestRaiseEpochRefusesWhatWraps(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	base := f.s.Epoch()
	for _, seen := range []uint64{math.MaxUint64, math.MaxInt64, math.MaxInt64 - 1} {
		if err := f.s.RaiseEpoch(ctx, op.Fence{Epoch: seen}); err == nil {
			t.Fatalf("RaiseEpoch(%d) did not refuse", seen)
		}
		if f.s.Epoch() != base {
			t.Fatalf("RaiseEpoch(%d) moved the epoch to %d", seen, f.s.Epoch())
		}
	}
	f.reopen()
	if f.s.Epoch() != base {
		t.Fatalf("a refused raise changed the stored epoch: %d, want %d", f.s.Epoch(), base)
	}
	if err := f.s.RaiseEpoch(ctx, op.Fence{Epoch: math.MaxInt64 - 2}); err != nil || f.s.Epoch() != math.MaxInt64-1 {
		t.Fatalf("the highest allowed value: %v, epoch %d", err, f.s.Epoch())
	}
}

func TestStreamHelloFenceBounded(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	base := e.st.Epoch()
	other := e.join(addr, cell2, "uid-other")
	defer other.close()
	for _, bad := range []uint64{math.MaxUint64, math.MaxInt64 - 1, uint64(time.Now().Add(48 * time.Hour).Unix())} {
		c := e.open(addr, cell1, openOpts{pod: "uid-evil"})
		c.hello(op.Fence{Epoch: bad, Counter: 1})
		f := c.expect(gwapi.TypeRefused)
		c.close()
		if f.Reason != mgmtapi.ReasonPayloadInvalid {
			t.Fatalf("hello with epoch %d: refused %+v", bad, f)
		}
		if got := e.st.Epoch(); got != base {
			t.Fatalf("hello with epoch %d moved the epoch to %d", bad, got)
		}
	}
	// The next lease of the other cell keeps its epoch, and an honest hello still works.
	e.enqueue(1, cell2)
	other.send(gwapi.Frame{Type: gwapi.TypeClaim})
	var lease gwapi.Frame
	for lease.Type != gwapi.TypeLease {
		f, err := other.recv(frameWait)
		if err != nil {
			t.Fatal(err)
		}
		lease = f
	}
	if lease.Fence.Epoch != base {
		t.Fatalf("fence epoch %d, want %d", lease.Fence.Epoch, base)
	}
	c := e.open(addr, cell2, openOpts{pod: "uid-honest"})
	defer c.close()
	c.hello(lease.Fence)
	c.expect(gwapi.TypeWelcome)
}

// ---- I-1

func h2Dial(t *testing.T, e *gwEnv, addr string) (*tls.Conn, error) {
	t.Helper()
	cfg := e.clientTLS(e.ca.Source(t, celld1))
	c, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: cfg}).Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*tls.Conn), nil
}

// A client that completes the HTTP/2 preface and opens no stream is closed after 5 s.
func TestStreamH2PrefaceWithoutRequestReleased(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	start := time.Now()
	var conns []*http2.ClientConn
	for i := 0; i < 4; i++ {
		tc, err := h2Dial(t, e, addr)
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		cc, err := (&http2.Transport{}).NewClientConn(tc)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, cc)
	}
	time.Sleep(6 * time.Second)
	for i, cc := range conns {
		if !cc.State().Closed {
			t.Fatalf("connection %d is still open %v after an HTTP/2 preface and no request", i+1, time.Since(start))
		}
	}
	c := e.open(addr, cell1, openOpts{pod: "uid-good"})
	c.hello(op.Fence{})
	c.expect(gwapi.TypeWelcome)
}

// ---- I-2

func TestOutboxPerCellByteCap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for range 200 {
		f.appendItem(item(gwapi.KindStatus, cell1, "", 100<<10))
	}
	var bytes int
	if err := f.s.db.QueryRowContext(ctx, `SELECT coalesce(sum(size), 0) FROM outbox WHERE cell = ?`, cell1).Scan(&bytes); err != nil {
		t.Fatal(err)
	}
	if bytes > 16<<20 {
		t.Fatalf("one cell holds %d bytes of the outbox, the cap is 16 MiB", bytes)
	}
	if bytes < 15<<20 {
		t.Fatalf("one cell holds only %d bytes", bytes)
	}
}

func TestOutboxResultDisplacesStatusOfTheBiggestCell(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.s.maxBytes = 2400
	var ids []gwapi.ItemID
	for range 3 {
		ids = append(ids, f.appendItem(item(gwapi.KindStatus, cell1, "", 400)))
	}
	keep := f.appendItem(item(gwapi.KindStatus, "dev-cell-3", "", 400))
	res := f.appendItem(item(gwapi.KindResult, cell2, opID(1), 900))
	got, _ := f.s.Peek(ctx, 20, 1<<20)
	have := map[gwapi.ItemID]bool{}
	for _, it := range got {
		have[it.ID] = true
	}
	if !have[res] || !have[keep] || have[ids[0]] || !have[ids[1]] || !have[ids[2]] {
		t.Fatalf("outbox %+v: want the oldest status of the biggest cell displaced and nothing else", got)
	}
	// A status item of a cell with nothing to displace is still refused, and results are never dropped.
	if _, err := f.s.Append(ctx, item(gwapi.KindStatus, "dev-cell-4", "", 2500)); err == nil {
		t.Fatal("a status item that does not fit was stored")
	}
	if !func() bool {
		g, _ := f.s.Peek(ctx, 20, 1<<20)
		for _, it := range g {
			if it.ID == res {
				return true
			}
		}
		return false
	}() {
		t.Fatal("a result was dropped")
	}
}

// ---- I-3

func (e *gwEnv) applyRevoked(rev uint64, revoked bool) {
	e.t.Helper()
	sp := spec.Spec{Env: e.g.env, Revision: spec.Revision{Epoch: 1, Counter: rev}, Retired: []spec.Retired{}}
	recs := map[string]json.RawMessage{}
	for _, name := range []string{cell1, cell2} {
		c := record.Cell{Name: name, Env: e.g.env, Issuer: "https://" + name + ".example", JWKS: e.g.jwks,
			Subjects: []record.Subject{{Namespace: testNS, ServiceAccount: testSA}}, Revoked: revoked && name == cell1, Epoch: 1, Counter: rev}
		env, _ := record.Sign(c, e.g.priv)
		_, payload, _ := record.VerifyWithPayload(env, e.g.keys())
		recs[name] = env
		sp.Cells = append(sp.Cells, spec.Entry{Name: name, Revision: spec.Revision{Epoch: 1, Counter: rev}, RecordSHA256: spec.RecordDigest(payload)})
	}
	senv, err := spec.Sign(sp, e.g.priv)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.st.ApplySync(context.Background(), senv, recs, e.g.keys()); err != nil {
		e.t.Fatal(err)
	}
}

func TestStreamEndsWhenCellRevoked(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	e.enqueue(1, cell1)
	c := e.join(addr, cell1, "uid-a")
	other := e.join(addr, cell2, "uid-b")
	e.applyRevoked(2, true)
	c.send(gwapi.Frame{Type: gwapi.TypeClaim})
	start := time.Now()
	for {
		f, err := c.recv(3 * time.Second)
		if err != nil {
			t.Fatalf("no refusal after the revocation: %v", err)
		}
		if f.Type == gwapi.TypeLease {
			t.Fatalf("a lease after the revocation: %+v", f)
		}
		if f.Type == gwapi.TypeRefused {
			if f.Reason != gwapi.ReasonCellRevoked || time.Since(start) > 2*time.Second {
				t.Fatalf("refused %+v after %v", f, time.Since(start))
			}
			break
		}
	}
	if !c.ended(frameWait) {
		t.Fatal("the stream of a revoked cell stays open")
	}
	other.send(gwapi.Frame{Type: gwapi.TypePing})
	other.expect(gwapi.TypePong)
}

// ---- m-2, m-3

func TestSyncRefusesOtherEnv(t *testing.T) {
	e := newGwEnv(t)
	// A store that has seen no spec yet, so the stored env cannot refuse the spec.
	fresh, err := Open(context.Background(), filepath.Join(t.TempDir(), "fresh.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	e.st = fresh
	f := newEnvdFixture(t, e, envdSetup{}, WithEnv("dev"))
	other := *e.g
	other.env = "prod"
	b := other.bundle(rev(1, 9), map[string]spec.Revision{cell1: rev(1, 9)})
	code, body := f.post(t, gwapi.SyncPath, gwapi.SyncRequest{SpecEnvelope: b.spec, Records: b.records})
	if code != 422 || !strings.Contains(string(body), mgmtapi.ReasonEnvMismatch) {
		t.Fatalf("a spec of another env: %d %s", code, body)
	}
	code, body = f.post(t, gwapi.SyncPath, e.syncRequest(nil, nil))
	decodeSync(t, code, body)
}

func TestSyncSkipsAnEnvelopeThatCannotBeLeased(t *testing.T) {
	e := newGwEnv(t)
	logs := &lockedBuf{}
	f := newEnvdFixture(t, e, envdSetup{log: slog.New(slog.NewJSONHandler(logs, nil))})
	big := func(n int, pad int) json.RawMessage {
		payload, _ := json.Marshal(map[string]any{"id": opID(n), "cell": cell1, "keyEpoch": 1, "pad": strings.Repeat("x", pad)})
		env, _ := json.Marshal(map[string]any{"payloadType": op.PayloadType, "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{}})
		return env
	}
	req := e.syncRequest([][]byte{e.opEnvelope(1, cell1)}, nil)
	req.Ops = append(req.Ops, big(2, 70<<10))
	code, body := f.post(t, gwapi.SyncPath, req)
	if resp := decodeSync(t, code, body); resp.Status.Queued[cell1] != 1 {
		t.Fatalf("queued %+v, want only the small operation", resp.Status.Queued)
	}
	if !strings.Contains(logs.String(), "sync_op_too_large") {
		t.Fatalf("no sync_op_too_large line in %q", logs.String())
	}
}

// ---- m-5

func TestBindSourceMismatchIsNotTheLastRefusal(t *testing.T) {
	b := newBindFx(t, BindConfig{}, nil, nil)
	code, body := b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, "n9", nil))
	requireDenied(t, code, body)
	code, body = b.fromCell2(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, "n1", nil))
	requireDenied(t, code, body)
	if r := b.lastReason(cell1); r != gwapi.ReasonNonceInvalid {
		t.Fatalf("last refusal of cell-1 is %q, want nonce_invalid", r)
	}
}
