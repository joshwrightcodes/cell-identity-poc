package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

type operator struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newOperator(t *testing.T) operator {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return operator{pub, priv}
}

func (o operator) keys() []ed25519.PublicKey { return []ed25519.PublicKey{o.pub} }

// entry signs a revocation of cell for env dev against record revision r.
func (o operator) entry(t *testing.T, cell string, r spec.Revision) json.RawMessage {
	t.Helper()
	return o.entryEnv(t, "dev", cell, r)
}

func (o operator) entryEnv(t *testing.T, env, cell string, r spec.Revision) json.RawMessage {
	t.Helper()
	raw, err := revoke.Sign(revoke.Entry{ID: "0123456789abcdef", Env: env, Cell: cell, Record: r, IssuedAt: time.Now().UTC()}, o.priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func overlaid(t *testing.T, s *Store, cell string) bool {
	t.Helper()
	ok, err := s.Overlaid(context.Background(), cell)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func (e *gwEnv) revoke(op operator, cells ...string) {
	e.t.Helper()
	var list []json.RawMessage
	for _, c := range cells {
		list = append(list, op.entry(e.t, c, rev(1, 1)))
	}
	if err := e.st.SetRevocations(context.Background(), list, op.keys(), "dev"); err != nil {
		e.t.Fatal(err)
	}
}

func TestStreamOverlayCellRefused(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	e.revoke(newOperator(t), cell1)
	c := e.open(addr, cell1, openOpts{})
	if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonCellRevoked {
		t.Fatalf("refused %+v", f)
	}
	if c2 := e.open(addr, cell2, openOpts{}); c2.status != http.StatusOK {
		t.Fatalf("an unrevoked cell got status %d", c2.status)
	}
}

func TestStreamEndsOnOverlay(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	c := e.join(addr, cell1, "uid-a")
	other := e.join(addr, cell2, "uid-b")
	e.revoke(newOperator(t), cell1)
	f, err := c.recv(2*pollEvery + time.Second)
	if err != nil || f.Type != gwapi.TypeRefused || f.Reason != gwapi.ReasonCellRevoked {
		t.Fatalf("frame %+v, %v", f, err)
	}
	if !c.ended(frameWait) {
		t.Fatal("the stream of an overlaid cell stays open")
	}
	other.send(gwapi.Frame{Type: gwapi.TypePing})
	other.expect(gwapi.TypePong)
}

func TestClaimOverlayCellNoLease(t *testing.T) {
	e := newGwEnv(t)
	e.enqueue(1, cell1)
	e.enqueue(2, cell2)
	e.revoke(newOperator(t), cell1)
	l, err := e.st.ClaimLive(context.Background(), cell1, "pod")
	if !errors.Is(err, ErrCellNotLive) || l != nil {
		t.Fatalf("claim of an overlaid cell: %+v, %v", l, err)
	}
	if l, err := e.st.ClaimLive(context.Background(), cell2, "pod"); err != nil || l == nil {
		t.Fatalf("claim of another cell: %+v, %v", l, err)
	}
}

func TestBindOverlayCellRefused(t *testing.T) {
	b := newBindFx(t, BindConfig{}, nil, nil)
	b.e.revoke(newOperator(t), cell1)
	code, body := b.fromCell1(http.MethodGet, gwapi.NoncePath(cell1), nil)
	requireDenied(t, code, body)
	if got := b.lastReason(cell1); got != gwapi.ReasonCellRevoked {
		t.Fatalf("nonce refusal %q", got)
	}
	code, body = b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, "n1", nil))
	requireDenied(t, code, body)
	if got := b.lastReason(cell1); got != gwapi.ReasonCellRevoked {
		t.Fatalf("bind refusal %q", got)
	}
	if code, _ := b.fromCell2(http.MethodGet, gwapi.NoncePath(cell2), nil); code != http.StatusOK {
		t.Fatalf("nonce of another cell: %d", code)
	}
}

func TestOverlayUnsignedIgnored(t *testing.T) {
	e := newGwEnv(t)
	good, other := newOperator(t), newOperator(t)
	list := []json.RawMessage{
		other.entry(t, cell1, rev(1, 1)),
		good.entryEnv(t, "prod", cell1, rev(1, 1)),
		json.RawMessage(`{"payloadType":"x"}`),
		good.entry(t, "dev-cell-9", rev(1, 1)),
	}
	if err := e.st.SetRevocations(context.Background(), list, good.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if overlaid(t, e.st, cell1) || overlaid(t, e.st, cell2) {
		t.Fatal("an unsigned or foreign entry holds a cell")
	}
	if !strings.Contains(e.logs.String(), "revocation_refused") {
		t.Fatalf("no refusal logged: %s", e.logs.String())
	}
}

func TestOverlayStaleNewEntryIgnored(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	e.applyRevoked(3, false)
	if err := e.st.SetRevocations(context.Background(), []json.RawMessage{op.entry(t, cell1, rev(1, 2))}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if overlaid(t, e.st, cell1) {
		t.Fatal("a stale entry holds the cell")
	}
}

func TestOverlaySurvivesRestart(t *testing.T) {
	f := newFixture(t)
	op := newOperator(t)
	ctx := context.Background()
	if err := f.s.SetRevocations(ctx, []json.RawMessage{op.entry(t, cell1, rev(1, 1))}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if overlaid(t, f.s, cell1) {
		t.Fatal("the overlay answers before its keys are known")
	}
	if err := f.s.SetRevocations(ctx, nil, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if !overlaid(t, f.s, cell1) {
		t.Fatal("the overlay is lost after a restart")
	}
	// Other keys verify nothing, so the stored envelope does not hold the cell.
	f.reopen()
	if err := f.s.SetRevocations(ctx, nil, newOperator(t).keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if overlaid(t, f.s, cell1) {
		t.Fatal("a stored envelope holds a cell under keys that did not sign it")
	}
}

func TestOverlaySettle(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	ctx := context.Background()
	e.revoke(op, cell1, cell2)
	// An empty list clears nothing.
	if err := e.st.SetRevocations(ctx, []json.RawMessage{}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if !overlaid(t, e.st, cell1) || !overlaid(t, e.st, cell2) {
		t.Fatal("an empty list cleared the overlay")
	}
	// A newer record that is not revoked keeps the entry.
	e.applyRevoked(2, false)
	if err := e.st.SetRevocations(ctx, nil, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if !overlaid(t, e.st, cell1) {
		t.Fatal("a newer unrevoked record cleared the entry")
	}
	// A spec that revokes the cell clears it, and the other cell stays.
	e.applyRevoked(3, true)
	if err := e.st.SetRevocations(ctx, nil, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if overlaid(t, e.st, cell1) || !overlaid(t, e.st, cell2) {
		t.Fatalf("after the revoking spec: cell1 %v, cell2 %v", overlaid(t, e.st, cell1), overlaid(t, e.st, cell2))
	}
	if n := e.st.OverlayCount(); n != 1 {
		t.Fatalf("overlay count %d", n)
	}
}

func TestOverlayRetiredCellClears(t *testing.T) {
	f := newFixture(t)
	g := newSigner(t)
	op := newOperator(t)
	ctx := context.Background()
	if err := f.apply(g, g.bundle(rev(1, 1), map[string]spec.Revision{cell1: rev(1, 1), cell2: rev(1, 1)})); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetRevocations(ctx, []json.RawMessage{op.entry(t, cell1, rev(1, 1))}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if err := f.apply(g, g.bundle(rev(1, 2), map[string]spec.Revision{cell2: rev(1, 1)}, spec.Retired{Name: cell1, Revision: rev(1, 1)})); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetRevocations(ctx, nil, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if overlaid(t, f.s, cell1) {
		t.Fatal("a retired cell stays in the overlay")
	}
}

func TestSyncCarriesRevocations(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	f := newEnvdFixture(t, e, envdSetup{}, WithOperatorKeys(op.keys()), WithEnv("dev"))
	req := e.syncRequest(nil, []mgmtapi.CellInfo{})
	req.Revocations = []json.RawMessage{op.entry(t, cell1, rev(1, 1))}
	code, body := f.post(t, gwapi.SyncPath, req)
	decodeSync(t, code, body)
	if !overlaid(t, e.st, cell1) || overlaid(t, e.st, cell2) {
		t.Fatal("the sync did not hold exactly cell 1")
	}
	code, body = f.post(t, gwapi.SyncPath, e.syncRequest(nil, nil))
	decodeSync(t, code, body)
	if !overlaid(t, e.st, cell1) {
		t.Fatal("a sync without revocations cleared the overlay")
	}
}

func TestSyncIgnoresRevocationsWithoutKeys(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	f := newEnvdFixture(t, e, envdSetup{}, WithEnv("dev"))
	req := e.syncRequest(nil, nil)
	req.Revocations = []json.RawMessage{op.entry(t, cell1, rev(1, 1))}
	code, body := f.post(t, gwapi.SyncPath, req)
	decodeSync(t, code, body)
	if overlaid(t, e.st, cell1) {
		t.Fatal("a gateway with no operator keys holds an overlay")
	}
}
