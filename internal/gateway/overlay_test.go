package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
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
	if overlaid(t, e.st, cell1) || overlaid(t, e.st, cell2) || e.st.OverlayCount() != 0 {
		t.Fatalf("an unsigned, foreign or unknown-cell entry holds a cell: %d held", e.st.OverlayCount())
	}
	if !strings.Contains(e.logs.String(), "revocation_refused") {
		t.Fatalf("no refusal logged: %s", e.logs.String())
	}
}

// A stale entry that envd still lists stays. A stale entry that envd no longer lists goes.
func TestOverlayStaleEntryFollowsEnvdList(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	ctx := context.Background()
	entry := op.entry(t, cell1, rev(1, 1))
	e.applyRevoked(3, false)
	if err := e.st.SetRevocations(ctx, []json.RawMessage{entry}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if !overlaid(t, e.st, cell1) {
		t.Fatal("an entry that envd lists was dropped as stale")
	}
	if err := e.st.SetRevocations(ctx, []json.RawMessage{entry}, op.keys(), "dev"); err != nil || !overlaid(t, e.st, cell1) {
		t.Fatalf("a second sync with the entry dropped it: %v", err)
	}
	if strings.Contains(e.logs.String(), "revocation_settled") {
		t.Fatalf("an entry that envd lists was logged as settled: %s", e.logs.String())
	}
	if err := e.st.SetRevocations(ctx, []json.RawMessage{}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if overlaid(t, e.st, cell1) {
		t.Fatal("a stale entry that envd no longer lists stays")
	}
	if !strings.Contains(e.logs.String(), "revocation_settled") {
		t.Fatalf("no revocation_settled line: %s", e.logs.String())
	}
}

// The gateway misses the revoked revision, the owner unrevokes, and the next sync brings the new
// record and an empty list.
func TestOverlaySkippedRevokedRevisionClears(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	e.revoke(op, cell1)
	e.applyRevoked(3, false)
	if err := e.st.SetRevocations(context.Background(), []json.RawMessage{}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if overlaid(t, e.st, cell1) {
		t.Fatal("a cell that a newer verified record unrevoked stays overlaid")
	}
}

// A restart keeps an entry that is stale against the stored record. The next sync of envd decides.
func TestOverlayRestoreKeepsStaleUntilEnvdSync(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	ctx := context.Background()
	e.revoke(op, cell1, cell2)
	e.applyRevoked(2, false)
	if err := e.st.RestoreRevocations(ctx, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if e.st.OverlayCount() != 2 {
		t.Fatalf("%d entries after the restore, want 2", e.st.OverlayCount())
	}
	if err := e.st.SetRevocations(ctx, []json.RawMessage{}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if e.st.OverlayCount() != 0 {
		t.Fatalf("%d stale entries survive an empty list of envd", e.st.OverlayCount())
	}
}

func TestOverlayUnknownCellRefused(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	if err := e.st.SetRevocations(context.Background(), []json.RawMessage{op.entry(t, "dev-cell-9", rev(1, 1))}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if e.st.OverlayCount() != 0 || overlaid(t, e.st, "dev-cell-9") {
		t.Fatal("an entry for a cell with no record is held")
	}
}

func names16(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("dev-cell-%02d", i+1)
	}
	return out
}

// bundleOf signs a spec at revision sr with one record at rr for each name.
func (g *signer) bundleOf(sr, rr spec.Revision, names []string) bundle {
	g.t.Helper()
	b := bundle{records: map[string]json.RawMessage{}}
	sp := spec.Spec{Env: g.env, Revision: sr, Retired: []spec.Retired{}}
	for _, name := range names {
		c := record.Cell{Name: name, Env: g.env, Issuer: "https://" + name + ".example", JWKS: g.jwks,
			Subjects: []record.Subject{{Namespace: "ns", ServiceAccount: "sa"}}, Epoch: rr.Epoch, Counter: rr.Counter}
		env, err := record.Sign(c, g.priv)
		if err != nil {
			g.t.Fatal(err)
		}
		_, payload, err := record.VerifyWithPayload(env, g.keys())
		if err != nil {
			g.t.Fatal(err)
		}
		b.records[name] = env
		sp.Cells = append(sp.Cells, spec.Entry{Name: name, Revision: rr, RecordSHA256: spec.RecordDigest(payload)})
	}
	env, err := spec.Sign(sp, g.priv)
	if err != nil {
		g.t.Fatal(err)
	}
	b.spec = env
	return b
}

// Orphan entries that envd let go do not starve new entries at the cap.
func TestOverlayOrphansDoNotStarveNewEntries(t *testing.T) {
	f := newFixture(t)
	g := newSigner(t)
	op := newOperator(t)
	ctx := context.Background()
	names := names16(revoke.MaxHeld + 1)
	if err := f.apply(g, g.bundleOf(rev(1, 1), rev(1, 1), names)); err != nil {
		t.Fatal(err)
	}
	var list []json.RawMessage
	for _, n := range names[:revoke.MaxHeld] {
		list = append(list, op.entry(t, n, rev(1, 1)))
	}
	if err := f.s.SetRevocations(ctx, list, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if f.s.OverlayCount() != revoke.MaxHeld {
		t.Fatalf("held %d, want %d", f.s.OverlayCount(), revoke.MaxHeld)
	}
	if err := f.apply(g, g.bundleOf(rev(1, 3), rev(1, 3), names)); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetRevocations(ctx, []json.RawMessage{op.entry(t, names[revoke.MaxHeld], rev(1, 3))}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if !overlaid(t, f.s, names[revoke.MaxHeld]) || f.s.OverlayCount() != 1 {
		t.Fatalf("orphans hold slots: %d held, new entry held %v", f.s.OverlayCount(), overlaid(t, f.s, names[revoke.MaxHeld]))
	}
}

func TestOverlayInputCapped(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	valid := op.entry(t, cell1, rev(1, 1))
	junk := json.RawMessage(`{}`)
	var byCount []json.RawMessage
	for range maxSyncEntries {
		byCount = append(byCount, junk)
	}
	byCount = append(byCount, valid)
	huge := json.RawMessage(`"` + strings.Repeat("x", maxSyncBytes) + `"`)
	for name, list := range map[string][]json.RawMessage{"count": byCount, "bytes": {huge, valid}} {
		if err := e.st.SetRevocations(context.Background(), list, op.keys(), "dev"); err != nil {
			t.Fatal(name, err)
		}
		if overlaid(t, e.st, cell1) {
			t.Fatalf("%s: an entry beyond the cap is held", name)
		}
	}
	if !strings.Contains(e.logs.String(), "input_capped") {
		t.Fatalf("no input_capped in the summary: %s", e.logs.String())
	}
}

func TestOverlayRefusalSummaryLoggedOnChange(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	bad := []json.RawMessage{json.RawMessage(`{"payloadType":"x"}`)}
	for range 50 {
		if err := e.st.SetRevocations(context.Background(), bad, op.keys(), "dev"); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(e.logs.String(), "revocation_refused"); n != 1 {
		t.Fatalf("%d summary lines for 50 identical syncs", n)
	}
}

func TestOverlayCorruptStoreStarts(t *testing.T) {
	f := newFixture(t)
	op := newOperator(t)
	if _, err := f.s.db.Exec(`INSERT INTO meta (key, value) VALUES ('revocations', 'not json')`); err != nil {
		t.Fatal(err)
	}
	if err := f.s.RestoreRevocations(context.Background(), op.keys(), "dev"); err != nil {
		t.Fatalf("a corrupt stored value stops the gateway: %v", err)
	}
	if !strings.Contains(f.logs.String(), "revocation_store_corrupt") {
		t.Fatalf("no log of the corrupt value: %s", f.logs.String())
	}
}

func TestSyncRefusedSpecStillAppliesRevocations(t *testing.T) {
	e := newGwEnv(t)
	op := newOperator(t)
	e.applyRevoked(2, false)
	f := newEnvdFixture(t, e, envdSetup{}, WithOperatorKeys(op.keys()), WithEnv("dev"))
	req := e.syncRequest(nil, nil) // revision 1.1 is below the stored 1.2
	req.Revocations = []json.RawMessage{op.entry(t, cell1, rev(1, 2))}
	code, _ := f.post(t, gwapi.SyncPath, req)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want the spec refusal", code)
	}
	if !overlaid(t, e.st, cell1) {
		t.Fatal("a refused spec held back a signed revocation")
	}
}

func TestOverlaySurvivesRestart(t *testing.T) {
	f := newFixture(t)
	g := newSigner(t)
	op := newOperator(t)
	ctx := context.Background()
	if err := f.apply(g, g.bundle(rev(1, 1), map[string]spec.Revision{cell1: rev(1, 1)})); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetRevocations(ctx, []json.RawMessage{op.entry(t, cell1, rev(1, 1))}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if overlaid(t, f.s, cell1) {
		t.Fatal("the overlay answers before its keys are known")
	}
	if err := f.s.RestoreRevocations(ctx, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if !overlaid(t, f.s, cell1) {
		t.Fatal("the overlay is lost after a restart")
	}
	// Other keys verify nothing, so the stored envelope does not hold the cell.
	f.reopen()
	if err := f.s.RestoreRevocations(ctx, newOperator(t).keys(), "dev"); err != nil {
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
	// A newer record that is not revoked keeps an entry that envd still lists.
	e.applyRevoked(2, false)
	if err := e.st.SetRevocations(ctx, []json.RawMessage{op.entry(t, cell1, rev(1, 1)), op.entry(t, cell2, rev(1, 1))}, op.keys(), "dev"); err != nil {
		t.Fatal(err)
	}
	if !overlaid(t, e.st, cell1) {
		t.Fatal("a newer unrevoked record cleared the entry")
	}
	// A spec that revokes the cell clears it, and the other cell stays.
	e.applyRevoked(3, true)
	if err := e.st.SetRevocations(ctx, []json.RawMessage{op.entry(t, cell2, rev(1, 1))}, op.keys(), "dev"); err != nil {
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
	if err := f.s.RestoreRevocations(ctx, op.keys(), "dev"); err != nil {
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
