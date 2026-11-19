package mgmt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

type opKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newOpKey(t *testing.T) opKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return opKey{pub: pub, priv: priv}
}

// revokeRig binds every cell of a plane that pins keys, and gives the plane the report of the
// signed revision.
func revokeRig(t *testing.T, mod func(*Config), cells ...string) *rig {
	t.Helper()
	r := newRig(t, cells...)
	if mod != nil {
		r.mod = mod
		r.restart(nil)
	}
	for _, c := range r.intent.Cells {
		r.mustBind(c.Name, r.signers[c.Name], mgmtapi.StatusBound)
	}
	r.release()
	return r
}

func withKeys(keys ...opKey) func(*Config) {
	return func(c *Config) {
		for _, k := range keys {
			c.OperatorKeys = append(c.OperatorKeys, k.pub)
		}
	}
}

func (r *rig) entry(k opKey, id, env, cell string, record spec.Revision) json.RawMessage {
	r.t.Helper()
	raw, err := revoke.Sign(revoke.Entry{ID: id, Env: env, Cell: cell, Record: record, IssuedAt: r.clk.Now()}, k.priv)
	if err != nil {
		r.t.Fatal(err)
	}
	return raw
}

func (r *rig) recRev(cell string) spec.Revision {
	r.t.Helper()
	return spec.RecordRevision(r.verifyRecord(cell))
}

func (r *rig) report(applied spec.Revision, entries ...json.RawMessage) {
	r.plane.Report(mgmtapi.StatusReport{Applied: applied, LocalRevocations: entries})
}

func (r *rig) state() *State { return r.plane.snap.Load().st }

// logLines returns the log lines with message msg.
func (r *rig) logLines(msg string) []map[string]any {
	r.t.Helper()
	r.logs.mu.Lock()
	text := r.logs.buf.String()
	r.logs.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(text, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// refusedWith reports whether an adoption_refused line names the entry ID and the reason.
func (r *rig) refusedWith(id, reason string) bool {
	for _, l := range r.logLines("adoption_refused") {
		if l["entry_id"] == id && l["reason"] == reason {
			return true
		}
	}
	return false
}

func next(rv spec.Revision) spec.Revision {
	return spec.Revision{Epoch: rv.Epoch, Counter: rv.Counter + 1}
}

func (r *rig) mustRevoke(cell string, want RevokeResult) {
	r.t.Helper()
	got, err := r.plane.Revoke(r.t.Context(), cell)
	if err != nil || got != want {
		r.t.Fatalf("Revoke(%s) = %+v, %v; want %+v", cell, got, err, want)
	}
}

func revokeAdmin(t *testing.T, p *Plane, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	NewAdminHandler(p, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("%s: body %q", path, rec.Body.String())
	}
	return rec.Code, m
}

func TestRevokeSignsRevision(t *testing.T) {
	var mu sync.Mutex
	var published map[string]json.RawMessage
	var publishedKey ed25519.PublicKey
	r := revokeRig(t, func(c *Config) {
		c.OnRecords = func(records map[string]json.RawMessage, pub ed25519.PublicKey) {
			mu.Lock()
			defer mu.Unlock()
			published, publishedKey = records, pub
		}
	}, cell1, cell2)
	before := r.status().Signed
	want := next(before)
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: want})

	if s := r.verifySpec(); s.Revision != want {
		t.Fatalf("spec %v, want %v", s.Revision, want)
	}
	if c := r.verifyRecord(cell1); !c.Revoked || spec.RecordRevision(c) != want {
		t.Fatalf("record of %s: %+v", cell1, c)
	}
	if c := r.verifyRecord(cell2); c.Revoked {
		t.Fatalf("record of %s is revoked", cell2)
	}
	mu.Lock()
	reg, err := record.Verify(published[cell1], []ed25519.PublicKey{publishedKey})
	mu.Unlock()
	if err != nil || !reg.Revoked {
		t.Fatalf("the published record of %s: %+v, %v", cell1, reg, err)
	}
	if cs := cellStatus(r.status(), cell1); !cs.Revoked || cs.RevokedBy != mgmtapi.RevocationSourceAdmin {
		t.Fatalf("status of %s: revoked %v by %q", cell1, cs.Revoked, cs.RevokedBy)
	}
	if cs := cellStatus(r.status(), cell2); cs.Revoked || cs.RevokedBy != "" {
		t.Fatalf("status of %s: revoked %v by %q", cell2, cs.Revoked, cs.RevokedBy)
	}
	st := r.state()
	if st.LastRevocation != want || len(st.Revocations) != 1 {
		t.Fatalf("mirror %+v, last revocation %v", st.Revocations, st.LastRevocation)
	}
	ev := st.Revocations[0]
	if ev.Cell != cell1 || ev.Revision != want || ev.Kind != mgmtapi.RevocationRevoke || ev.Source != mgmtapi.RevocationSourceAdmin ||
		ev.EntryID != "" || ev.OperatorKeySHA256 != "" || !ev.At.Equal(r.clk.Now()) {
		t.Fatalf("event %+v", ev)
	}

	// Every later record of the cell stays revoked: after a restart, and after a key rotation.
	r.restart(nil)
	if !r.verifyRecord(cell1).Revoked {
		t.Fatal("a restart cleared the revoke")
	}
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	if c := r.verifyRecord(cell1); !c.Revoked || c.Epoch != 2 {
		t.Fatalf("record after a rotation: %+v", c)
	}
	if r.verifyRecord(cell2).Revoked {
		t.Fatal("a rotation revoked another cell")
	}
}

func TestRevokeOnePerRevision(t *testing.T) {
	r := revokeRig(t, nil, cell1, cell2, cell3)
	first := next(r.status().Signed)
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: first})
	r.mustRevoke(cell2, RevokeResult{Cell: cell2, Queued: true})
	r.mustRevoke(cell3, RevokeResult{Cell: cell3, Queued: true})
	if got := r.status().Signed; got != first {
		t.Fatalf("a queued revoke signed %v", got)
	}
	if r.verifyRecord(cell2).Revoked || r.verifyRecord(cell3).Revoked {
		t.Fatal("a queued revoke reached a record")
	}

	// A report below the revision of the first revoke releases nothing.
	r.report(rev(first.Epoch, first.Counter-1))
	if got := r.status().Signed; got != first {
		t.Fatalf("a report below the first revoke signed %v", got)
	}
	r.report(first)
	second := next(first)
	if s := r.verifySpec(); s.Revision != second || !r.verifyRecord(cell2).Revoked || r.verifyRecord(cell3).Revoked {
		t.Fatalf("after the report of %v: spec %v, %s revoked %v, %s revoked %v", first, s.Revision,
			cell2, r.verifyRecord(cell2).Revoked, cell3, r.verifyRecord(cell3).Revoked)
	}
	// Two reports of one revision release one revoke.
	r.report(first)
	if got := r.status().Signed; got != second {
		t.Fatalf("a second report of %v signed %v", first, got)
	}
	r.report(second)
	if s := r.verifySpec(); s.Revision != next(second) || !r.verifyRecord(cell3).Revoked {
		t.Fatalf("after the report of %v: spec %v", second, s.Revision)
	}
	if st := r.state(); len(st.PendingRevokes) != 0 || st.LastRevocation != next(second) || len(st.Revocations) != 3 {
		t.Fatalf("pending %+v, last %v, mirror %d", st.PendingRevokes, st.LastRevocation, len(st.Revocations))
	}

	// After a restart the plane knows no applied revision, so a revoke waits for a report.
	r2 := revokeRig(t, nil, cell1, cell2)
	r2.restart(nil)
	signed := r2.status().Signed
	r2.mustRevoke(cell1, RevokeResult{Cell: cell1, Queued: true})
	if r2.status().Signed != signed {
		t.Fatal("a revoke signed before any report after a restart")
	}
	r2.report(signed)
	if !r2.verifyRecord(cell1).Revoked {
		t.Fatal("the report did not release the queued revoke")
	}
}

func TestRevokeUnknownCell(t *testing.T) {
	r := newRig(t, cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.release()
	seq := r.status().Seq
	for _, cell := range []string{"no-such-cell", cell2} {
		if _, err := r.plane.Revoke(t.Context(), cell); ReasonOf(err) != mgmtapi.ReasonNotBound {
			t.Errorf("Revoke(%s): %v", cell, err)
		}
	}
	if code, m := revokeAdmin(t, r.plane, "/revoke/"+cell2); code != http.StatusNotFound || m["reason"] != mgmtapi.ReasonNotBound {
		t.Errorf("POST /revoke/%s: %d %v", cell2, code, m)
	}
	if r.status().Seq != seq {
		t.Fatal("a refused revoke saved the state")
	}
}

func TestRevokeAgain(t *testing.T) {
	r := revokeRig(t, nil, cell1, cell2)
	first := next(r.status().Signed)
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: first})
	seq := r.status().Seq
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: first, Already: true})
	r.mustRevoke(cell2, RevokeResult{Cell: cell2, Queued: true})
	seq++
	r.mustRevoke(cell2, RevokeResult{Cell: cell2, Queued: true, Already: true})
	if st := r.state(); st.Seq != seq || len(st.PendingRevokes) != 1 || len(st.Revocations) != 1 {
		t.Fatalf("seq %d (want %d), pending %+v, mirror %+v", st.Seq, seq, st.PendingRevokes, st.Revocations)
	}
	code, m := revokeAdmin(t, r.plane, "/revoke/"+cell1)
	if code != http.StatusOK || m["already"] != true || m["cell"] != cell1 {
		t.Fatalf("POST /revoke/%s: %d %v", cell1, code, m)
	}
}

func TestUnrevokeConnectedOnly(t *testing.T) {
	r := revokeRig(t, nil, cell1, cell2)
	revoked := next(r.status().Signed)
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: revoked})

	// envd has not applied the revoke.
	if _, err := r.plane.Unrevoke(t.Context(), cell1); ReasonOf(err) != mgmtapi.ReasonNotConnected {
		t.Fatalf("Unrevoke with applied behind: %v", err)
	}
	if code, m := revokeAdmin(t, r.plane, "/unrevoke/"+cell1); code != http.StatusConflict || m["reason"] != mgmtapi.ReasonNotConnected {
		t.Fatalf("POST /unrevoke/%s: %d %v", cell1, code, m)
	}
	// envd applied it, and then fell silent for more than 2 minutes.
	r.report(revoked)
	r.clk.Advance(2*time.Minute + time.Second)
	if _, err := r.plane.Unrevoke(t.Context(), cell1); ReasonOf(err) != mgmtapi.ReasonNotConnected {
		t.Fatalf("Unrevoke with no report in 2 minutes: %v", err)
	}
	if r.status().Signed != revoked {
		t.Fatal("a refused un-revoke signed")
	}

	r.report(revoked)
	r.clk.Advance(2 * time.Minute)
	got, err := r.plane.Unrevoke(t.Context(), cell1)
	want := next(revoked)
	if err != nil || got != (RevokeResult{Cell: cell1, Revision: want}) {
		t.Fatalf("Unrevoke while connected: %+v, %v", got, err)
	}
	if c := r.verifyRecord(cell1); c.Revoked || spec.RecordRevision(c) != want {
		t.Fatalf("record after the un-revoke: %+v", c)
	}
	if cs := cellStatus(r.status(), cell1); cs.Revoked || cs.RevokedBy != "" {
		t.Fatalf("status after the un-revoke: %+v", cs)
	}
	st := r.state()
	ev := st.Revocations[len(st.Revocations)-1]
	if len(st.Revocations) != 2 || ev.Kind != mgmtapi.RevocationUnrevoke || ev.Source != mgmtapi.RevocationSourceAdmin || ev.Revision != want || ev.Cell != cell1 {
		t.Fatalf("mirror %+v", st.Revocations)
	}
	if st.LastRevocation != revoked {
		t.Fatalf("an un-revoke moved the last revocation to %v", st.LastRevocation)
	}
}

func TestUnrevokeOverlayHeld(t *testing.T) {
	k := newOpKey(t)
	r := revokeRig(t, withKeys(k), cell1, cell2)
	revoked := next(r.status().Signed)
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: revoked})
	held := r.entry(k, "00112233445566aa", "dev", cell1, revoked)
	r.report(revoked, held)
	if _, err := r.plane.Unrevoke(t.Context(), cell1); ReasonOf(err) != mgmtapi.ReasonOverlayHeld {
		t.Fatalf("Unrevoke while envd holds an entry: %v", err)
	}
	if code, m := revokeAdmin(t, r.plane, "/unrevoke/"+cell1); code != http.StatusConflict || m["reason"] != mgmtapi.ReasonOverlayHeld {
		t.Fatalf("POST /unrevoke/%s: %d %v", cell1, code, m)
	}
	// envd holds what it holds, so an entry that the pins of the plane do not verify holds too.
	r.report(revoked, r.entry(newOpKey(t), "00112233445566bb", "dev", cell1, revoked))
	if _, err := r.plane.Unrevoke(t.Context(), cell1); ReasonOf(err) != mgmtapi.ReasonOverlayHeld {
		t.Fatalf("Unrevoke while envd holds an entry of another key: %v", err)
	}
	if r.status().Signed != revoked {
		t.Fatal("a refused un-revoke signed")
	}
	// envd settled the entry.
	r.report(revoked)
	if _, err := r.plane.Unrevoke(t.Context(), cell1); err != nil {
		t.Fatalf("Unrevoke after envd settled the entry: %v", err)
	}
}

func TestUnrevokeNotRevoked(t *testing.T) {
	r := revokeRig(t, nil, cell1, cell2)
	seq := r.status().Seq
	if _, err := r.plane.Unrevoke(t.Context(), cell1); ReasonOf(err) != mgmtapi.ReasonNotRevoked {
		t.Fatalf("Unrevoke of a cell that is not revoked: %v", err)
	}
	if code, m := revokeAdmin(t, r.plane, "/unrevoke/"+cell1); code != http.StatusConflict || m["reason"] != mgmtapi.ReasonNotRevoked {
		t.Fatalf("POST /unrevoke/%s: %d %v", cell1, code, m)
	}
	if _, err := r.plane.Unrevoke(t.Context(), "no-such-cell"); ReasonOf(err) != mgmtapi.ReasonNotBound {
		t.Fatalf("Unrevoke of an unknown cell: %v", err)
	}
	// A revoke that waits in the queue is not a revoked record.
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 1)})
	r.mustRevoke(cell2, RevokeResult{Cell: cell2, Queued: true})
	if _, err := r.plane.Unrevoke(t.Context(), cell2); ReasonOf(err) != mgmtapi.ReasonNotRevoked {
		t.Fatalf("Unrevoke of a queued revoke: %v", err)
	}
	if st := r.state(); st.Seq != seq+1 || len(st.PendingRevokes) != 1 {
		t.Fatalf("seq %d, pending %+v", st.Seq, st.PendingRevokes)
	}
}

func TestAdoptVerifiedEntry(t *testing.T) {
	k1, k2 := newOpKey(t), newOpKey(t)
	r := revokeRig(t, withKeys(k1, k2), cell1, cell2)
	signed := r.status().Signed
	id := "0123456789abcdef"
	r.report(signed, r.entry(k2, id, "dev", cell2, r.recRev(cell2)))

	want := next(signed)
	if c := r.verifyRecord(cell2); !c.Revoked || spec.RecordRevision(c) != want {
		t.Fatalf("record of %s: %+v", cell2, c)
	}
	if r.verifyRecord(cell1).Revoked {
		t.Fatalf("%s is revoked", cell1)
	}
	st := r.state()
	if len(st.Revocations) != 1 || len(st.PendingRevokes) != 0 || st.LastRevocation != want {
		t.Fatalf("mirror %+v, pending %+v, last %v", st.Revocations, st.PendingRevokes, st.LastRevocation)
	}
	ev := st.Revocations[0]
	if ev.Cell != cell2 || ev.Kind != mgmtapi.RevocationRevoke || ev.Source != mgmtapi.RevocationSourceOperator ||
		ev.EntryID != id || ev.OperatorKeySHA256 != revoke.KeySHA256(k2.pub) || ev.Revision != want {
		t.Fatalf("event %+v", ev)
	}
	if cs := cellStatus(r.status(), cell2); !cs.Revoked || cs.RevokedBy != mgmtapi.RevocationSourceOperator {
		t.Fatalf("status of %s: %+v", cell2, cs)
	}
}

func TestAdoptRefusesUnsigned(t *testing.T) {
	k1, stranger := newOpKey(t), newOpKey(t)
	r := revokeRig(t, withKeys(k1), cell1, cell2)
	seq, signed := r.status().Seq, r.status().Signed
	rec1 := r.recRev(cell1)
	foreign := r.entry(stranger, "1111111111111111", "dev", cell1, rec1)
	otherEnv := r.entry(k1, "2222222222222222", "prod", cell2, rec1)
	tampered := []byte(strings.Replace(string(r.entry(k1, "3333333333333333", "dev", cell1, rec1)), `"sig":"`, `"sig":"AAAA`, 1))
	r.report(signed, foreign, json.RawMessage(`{"junk":true}`), otherEnv, tampered)
	r.report(signed, foreign)

	st := r.state()
	if st.Seq != seq || len(st.PendingRevokes) != 0 || len(st.Revocations) != 0 {
		t.Fatalf("seq %d (want %d), pending %+v, mirror %+v", st.Seq, seq, st.PendingRevokes, st.Revocations)
	}
	if r.verifyRecord(cell1).Revoked || r.verifyRecord(cell2).Revoked {
		t.Fatal("a refused entry revoked a cell")
	}
	if !r.refusedWith("2222222222222222", mgmtapi.ReasonRevocationInvalid) {
		t.Fatalf("no adoption_refused line for the entry of another env: %v", r.logLines("adoption_refused"))
	}
	if !r.refusedWith("1111111111111111", mgmtapi.ReasonRevocationInvalid) {
		t.Fatalf("no adoption_refused line for the entry of an unknown key: %v", r.logLines("adoption_refused"))
	}
	if n := len(r.logLines("adoption_refused")); n > 4 {
		t.Fatalf("%d adoption_refused lines for 4 entries in 2 reports; want them rate limited", n)
	}

	// A plane with no operator key adopts nothing and says so once.
	bare := revokeRig(t, nil, cell1, cell2)
	signed = bare.status().Signed
	good := bare.entry(k1, "4444444444444444", "dev", cell1, bare.recRev(cell1))
	bare.report(signed, good)
	bare.report(signed, good)
	if bare.verifyRecord(cell1).Revoked || len(bare.state().PendingRevokes) != 0 {
		t.Fatal("a plane with no operator key adopted an entry")
	}
	if n := len(bare.logLines("operator_keys_absent")); n != 1 {
		t.Fatalf("%d operator_keys_absent lines, want 1", n)
	}
}

func TestAdoptIdempotent(t *testing.T) {
	k := newOpKey(t)
	r := revokeRig(t, withKeys(k), cell1, cell2)
	signed := r.status().Signed
	behind := rev(signed.Epoch, signed.Counter-1)
	e := r.entry(k, "5555555555555555", "dev", cell1, r.recRev(cell1))
	for range 3 {
		r.report(behind, e, e, e)
	}
	st := r.state()
	if len(st.PendingRevokes) != 1 || st.Last != signed {
		t.Fatalf("pending %+v, signed %v", st.PendingRevokes, st.Last)
	}
	if p := st.PendingRevokes[0]; p.Cell != cell1 || p.Source != mgmtapi.RevocationSourceOperator || p.EntryID != "5555555555555555" || p.OperatorKeySHA256 != revoke.KeySHA256(k.pub) {
		t.Fatalf("pending %+v", p)
	}
	r.report(signed, e)
	want := next(signed)
	if c := r.verifyRecord(cell1); !c.Revoked || spec.RecordRevision(c) != want {
		t.Fatalf("record %+v", c)
	}
	seq := r.status().Seq
	for range 3 {
		r.report(signed, e)
		r.report(want, e)
	}
	if st := r.state(); st.Seq != seq || len(st.Revocations) != 1 || len(st.PendingRevokes) != 0 || st.Last != want {
		t.Fatalf("seq %d (want %d), mirror %+v, pending %+v, last %v", st.Seq, seq, st.Revocations, st.PendingRevokes, st.Last)
	}
}

func TestAdoptRefusesStale(t *testing.T) {
	k := newOpKey(t)
	r := revokeRig(t, withKeys(k), cell1, cell2)
	signed := r.status().Signed
	cur := r.recRev(cell2)
	stale := r.entry(k, "6666666666666666", "dev", cell2, rev(cur.Epoch, cur.Counter-1))
	r.report(signed, stale)
	if r.verifyRecord(cell2).Revoked || len(r.state().PendingRevokes) != 0 || r.status().Signed != signed {
		t.Fatal("a stale entry was adopted")
	}
	if !r.refusedWith("6666666666666666", mgmtapi.ReasonRevocationStale) {
		t.Fatalf("no adoption_refused line with revocation_stale: %v", r.logLines("adoption_refused"))
	}
	// An entry at the current record revision is adopted.
	r.report(signed, r.entry(k, "6666666666666667", "dev", cell2, cur))
	if !r.verifyRecord(cell2).Revoked {
		t.Fatal("a current entry was not adopted")
	}
}

func TestAdoptRefusesAfterUnrevoke(t *testing.T) {
	k := newOpKey(t)
	r := revokeRig(t, withKeys(k), cell1, cell2)
	const id = "7777777777777777"
	first := r.entry(k, id, "dev", cell1, r.recRev(cell1))
	r.report(r.status().Signed, first)
	revoked := r.status().Signed
	if !r.verifyRecord(cell1).Revoked {
		t.Fatal("setup: the entry was not adopted")
	}
	// envd settled the entry, so it holds none, and the operator un-revokes the cell.
	r.report(revoked)
	if _, err := r.plane.Unrevoke(t.Context(), cell1); err != nil {
		t.Fatal(err)
	}
	unrevoked := r.status().Signed
	r.report(unrevoked)
	seq := r.status().Seq

	// The same entry ID at the current record revision is not stale, and the mirror refuses it.
	again := r.entry(k, id, "dev", cell1, unrevoked)
	r.report(unrevoked, again)
	if r.verifyRecord(cell1).Revoked || len(r.state().PendingRevokes) != 0 || r.status().Seq != seq {
		t.Fatal("an entry of an un-revoked ID was adopted")
	}
	if !r.refusedWith(id, reasonEntryUnrevoked) {
		t.Fatalf("no adoption_refused line with %s: %v", reasonEntryUnrevoked, r.logLines("adoption_refused"))
	}
	// A replay of the first entry is refused too.
	r.report(unrevoked, first)
	if r.verifyRecord(cell1).Revoked || r.status().Seq != seq {
		t.Fatal("a replayed entry was adopted")
	}
}

func TestRestorePastRevocation(t *testing.T) {
	r := newRig(t, cell1, cell2, cell3)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	r.release()
	revoked := next(r.status().Signed)
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: revoked})
	r.mustBind(cell3, r.signers[cell3], mgmtapi.StatusBound)
	seq := r.status().Seq

	err := r.plane.Restore(revoked.Counter - 1)
	if !errors.Is(err, ErrRestorePastRevocation) || ReasonOf(err) != mgmtapi.ReasonRestorePastRevocation {
		t.Fatalf("restore below the last revocation: %v", err)
	}
	if code, m := revokeAdmin(t, r.plane, "/restore/1"); code != http.StatusConflict || m["reason"] != mgmtapi.ReasonRestorePastRevocation {
		t.Fatalf("POST /restore/1: %d %v", code, m)
	}
	if st := r.status(); st.Seq != seq || st.RestoreActive {
		t.Fatalf("a refused restore changed the state: %+v", st)
	}
	// The revision of the revoke itself holds the revoke.
	if err := r.plane.Restore(revoked.Counter); err != nil {
		t.Fatalf("restore to the revoke: %v", err)
	}
	if s := r.verifySpec(); s.Revision != revoked || !r.verifyRecord(cell1).Revoked {
		t.Fatalf("served %v", s.Revision)
	}
	if err := r.plane.Restore(0); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreBetweenRevokeAndUnrevoke(t *testing.T) {
	r := revokeRig(t, nil, cell1, cell2)
	revoked := next(r.status().Signed)
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: revoked})
	r.report(revoked)
	if _, err := r.plane.Unrevoke(t.Context(), cell1); err != nil {
		t.Fatal(err)
	}
	if err := r.plane.Restore(revoked.Counter); err != nil {
		t.Fatalf("restore to the revoke: %v", err)
	}
	if s := r.verifySpec(); s.Revision != revoked || !r.verifyRecord(cell1).Revoked {
		t.Fatalf("served %v", s.Revision)
	}
	// An un-revoke and a revoke both change a record, so both wait for the end of the restore.
	if _, err := r.plane.Revoke(t.Context(), cell2); ReasonOf(err) != mgmtapi.ReasonRestoreActive {
		t.Fatalf("Revoke during a restore: %v", err)
	}
}

func TestStateWithoutRevocationsLoads(t *testing.T) {
	r := revokeRig(t, nil, cell1, cell2)
	path := filepath.Join(r.dir, "state.json")
	var raw map[string]any
	if err := json.Unmarshal(r.stateBytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"revocations", "lastRevocation", "pendingRevokes"} {
		if _, ok := raw[k]; ok {
			t.Errorf("a state with no revocation holds %q", k)
		}
	}
	for name, c := range raw["cells"].(map[string]any) {
		if _, ok := c.(map[string]any)["revoked"]; ok {
			t.Errorf("cell %s holds revoked", name)
		}
	}
	// A state that an M8 plane saved has none of the fields.
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	r.restart(nil)
	st := r.state()
	if st.Revocations != nil || st.PendingRevokes != nil || st.LastRevocation != (spec.Revision{}) || st.Cells[cell1].Revoked {
		t.Fatalf("loaded %+v", st)
	}
	signed := r.status().Signed
	r.report(signed)
	r.mustRevoke(cell1, RevokeResult{Cell: cell1, Revision: next(signed)})
	if st := r.state(); !st.Cells[cell1].Revoked || st.LastRevocation != next(signed) || len(st.Revocations) != 1 {
		t.Fatalf("after a revoke: %+v", st)
	}
}
