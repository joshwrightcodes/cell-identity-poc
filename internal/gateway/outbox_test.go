package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

func ackAccepted(ids ...gwapi.ItemID) []mgmtapi.ItemOutcome {
	var out []mgmtapi.ItemOutcome
	for _, id := range ids {
		out = append(out, mgmtapi.ItemOutcome{ID: string(id), Outcome: mgmtapi.OutcomeAccepted})
	}
	return out
}

func item(kind, cell, op string, size int) gwapi.Item {
	body, _ := json.Marshal(map[string]string{"p": strings.Repeat("x", size)})
	return gwapi.Item{Kind: kind, Cell: cell, OpID: op, Body: body, Token: "tok"}
}

func (f *fixture) appendItem(it gwapi.Item) gwapi.ItemID {
	f.t.Helper()
	id, err := f.s.Append(context.Background(), it)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func TestOutboxCapDropsStatusFirst(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.s.maxItems = 4
	s1 := f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	r1 := f.appendItem(item(gwapi.KindResult, cell1, opID(1), 1))
	s2 := f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	r2 := f.appendItem(item(gwapi.KindResult, cell1, opID(2), 1))
	// The oldest item is a status; the next arrival in arrival order would be the result r1.
	r3 := f.appendItem(item(gwapi.KindResult, cell1, opID(3), 1))
	got, _ := f.s.Peek(ctx, 100, 1<<20)
	want := []gwapi.ItemID{r1, r2, r3, s2}
	if len(got) != len(want) {
		t.Fatalf("outbox holds %d items, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("item %d is %s, want %s (s1 %s)", i, got[i].ID, want[i], s1)
		}
	}
	// A new status drops the oldest status, not a result that is older than it.
	f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	got, _ = f.s.Peek(ctx, 100, 1<<20)
	if len(got) != 4 || got[0].ID != r1 || got[1].ID != r2 {
		t.Fatalf("outbox after a second drop: %+v", got)
	}
	st, _ := f.s.Stats(ctx)
	if st.Dropped != 2 || !st.DroppedAt.Equal(t0) || st.OutboxItems != 4 {
		t.Fatalf("stats %+v", st)
	}
}

func TestOutboxResultsNeverDropped(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.s.maxItems = 3
	r1 := f.appendItem(item(gwapi.KindResult, cell1, opID(1), 1))
	f.appendItem(item(gwapi.KindResult, cell1, opID(2), 1))
	f.appendItem(item(gwapi.KindResult, cell1, opID(3), 1))
	for _, kind := range []string{gwapi.KindResult, gwapi.KindStatus} {
		if _, err := f.s.Append(ctx, item(kind, cell1, opID(4), 1)); !errors.Is(err, gwapi.ErrOverloaded) {
			t.Fatalf("%s into a full outbox of results: %v", kind, err)
		}
	}
	got, _ := f.s.Peek(ctx, 100, 1<<20)
	if len(got) != 3 || got[0].ID != r1 {
		t.Fatalf("results were dropped: %+v", got)
	}
	if st, _ := f.s.Stats(ctx); st.Dropped != 0 {
		t.Fatalf("dropped %d, want 0", st.Dropped)
	}
	// A status of another cell may not drop this cell's items, and a full byte budget counts too.
	g := newFixture(t)
	g.s.maxBytes = 3000
	g.appendItem(item(gwapi.KindResult, cell1, opID(1), 2000))
	if _, err := g.s.Append(ctx, item(gwapi.KindResult, cell1, opID(2), 2000)); !errors.Is(err, gwapi.ErrOverloaded) {
		t.Fatalf("byte cap: %v", err)
	}
}

func TestOutboxPerCellShare(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.s.perCell = 3
	for n := range 3 {
		f.appendItem(item(gwapi.KindResult, cell1, opID(n+1), 1))
	}
	if _, err := f.s.Append(ctx, item(gwapi.KindResult, cell1, opID(9), 1)); !errors.Is(err, gwapi.ErrOverloaded) {
		t.Fatalf("a fourth item of one cell: %v", err)
	}
	// Another cell still has room, and a status of cell 1 cannot drop an item of cell 2.
	for n := range 3 {
		f.appendItem(item(gwapi.KindStatus, cell2, "", 1+n))
	}
	f.appendItem(item(gwapi.KindStatus, cell2, "", 5))
	if st, _ := f.s.Stats(ctx); st.OutboxItems != 6 || st.Dropped != 1 {
		t.Fatalf("stats %+v: the full cell drops only its own status", st)
	}
}

func TestOutboxAckDeletes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.appendItem(item(gwapi.KindResult, cell1, opID(1), 1))
	b := f.appendItem(item(gwapi.KindResult, cell1, opID(2), 1))
	c := f.appendItem(item(gwapi.KindBind, cell2, "", 1))
	outs := []mgmtapi.ItemOutcome{
		{ID: string(a), Outcome: mgmtapi.OutcomeAccepted},
		{ID: string(c), Outcome: mgmtapi.OutcomeRetry, Reason: "proof_invalid"},
		{ID: string(gwapi.NewItemID()), Outcome: mgmtapi.OutcomeAccepted},
	}
	if err := f.s.Ack(ctx, outs); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Ack(ctx, outs); err != nil {
		t.Fatalf("a second ack of the same outcomes: %v", err)
	}
	left, _ := f.s.Peek(ctx, 10, 1<<20)
	if len(left) != 1 || left[0].ID != b {
		t.Fatalf("outbox after ack: %+v", left)
	}
	o, ok, err := f.s.Outcome(ctx, cell1, a)
	if err != nil || !ok || o.Outcome != mgmtapi.OutcomeAccepted || o.OpID != opID(1) {
		t.Fatalf("outcome of a: %+v, %v, %v", o, ok, err)
	}
	if o, ok, _ := f.s.Outcome(ctx, cell2, c); !ok || o.Outcome != mgmtapi.OutcomeRetry || o.Reason != "proof_invalid" {
		t.Fatalf("retry outcome of the bind: %+v, %v", o, ok)
	}
	if _, ok, _ := f.s.Outcome(ctx, cell1, b); ok {
		t.Fatal("an unacked item has an outcome")
	}
}

func TestOutcomeOnlyForOwnCell(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := f.appendItem(item(gwapi.KindBind, cell1, "", 1))
	if err := f.s.Ack(ctx, ackAccepted(id)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.s.Outcome(ctx, cell2, id); ok {
		t.Fatal("cell 2 read the outcome of a cell 1 item")
	}
	if _, ok, _ := f.s.Outcome(ctx, cell1, id); !ok {
		t.Fatal("cell 1 cannot read its own outcome")
	}
}

func TestBindInboxPerCellCap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var ids []gwapi.ItemID
	for range 4 {
		ids = append(ids, f.appendItem(item(gwapi.KindBind, cell1, "", 1)))
	}
	if _, err := f.s.Append(ctx, item(gwapi.KindBind, cell1, "", 1)); !errors.Is(err, gwapi.ErrOverloaded) {
		t.Fatalf("a fifth pending bind: %v", err)
	}
	f.appendItem(item(gwapi.KindBind, cell2, "", 1))
	f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	if err := f.s.Ack(ctx, ackAccepted(ids[0])); err != nil {
		t.Fatal(err)
	}
	f.appendItem(item(gwapi.KindBind, cell1, "", 1))
}

func TestPeekStaysUnder900KiB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for n := range 150 {
		f.appendItem(item(gwapi.KindResult, cell1, opID(n+1), 10<<10))
	}
	for _, c := range []struct{ items, bytes int }{{1000, 10 << 20}, {50, 10 << 20}, {1000, 100 << 10}} {
		got, err := f.s.Peek(ctx, c.items, c.bytes)
		if err != nil {
			t.Fatal(err)
		}
		enc, _ := json.Marshal(got)
		limit := min(c.bytes, 900<<10)
		if len(got) > min(c.items, 100) || len(enc) > limit+2+len(got) {
			t.Fatalf("Peek(%d, %d) gave %d items and %d bytes", c.items, c.bytes, len(got), len(enc))
		}
		if len(got) < 2 {
			t.Fatalf("Peek(%d, %d) gave %d items", c.items, c.bytes, len(got))
		}
	}
	got, _ := f.s.Peek(ctx, 1000, 10<<20)
	if len(got) < 80 || len(got) > 100 {
		t.Fatalf("default batch has %d items, want the byte budget to cut it near 87", len(got))
	}
	one, err := f.s.Peek(ctx, 5, 10)
	if err != nil || len(one) != 1 {
		t.Fatalf("an item over the byte budget still goes alone: %d, %v", len(one), err)
	}
}

func TestFinalOutcomesCursor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r1 := f.appendItem(item(gwapi.KindResult, cell1, opID(1), 1))
	r2 := f.appendItem(item(gwapi.KindResult, cell1, opID(2), 1))
	st := f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	b := f.appendItem(item(gwapi.KindBind, cell1, "", 1))
	o := f.appendItem(item(gwapi.KindResult, cell2, opID(3), 1))
	outs := []mgmtapi.ItemOutcome{
		{ID: string(r1), Outcome: mgmtapi.OutcomeAccepted},
		{ID: string(r2), Outcome: mgmtapi.OutcomeRetry},
		{ID: string(st), Outcome: mgmtapi.OutcomeAccepted},
		{ID: string(b), Outcome: mgmtapi.OutcomeAccepted},
		{ID: string(o), Outcome: mgmtapi.OutcomeAccepted},
	}
	if err := f.s.Ack(ctx, outs); err != nil {
		t.Fatal(err)
	}
	got, cur, err := f.s.FinalOutcomes(ctx, cell1, 0)
	if err != nil || len(got) != 2 || got[0].OpID != opID(1) || got[1].OpID != opID(2) || cur <= 0 {
		t.Fatalf("first read %+v, %d, %v: want the two results of cell 1 only", got, cur, err)
	}
	again, cur2, _ := f.s.FinalOutcomes(ctx, cell1, cur)
	if len(again) != 0 || cur2 != cur {
		t.Fatalf("a read after the cursor gave %+v, %d", again, cur2)
	}
	// FinalOutcomes deletes nothing: a new stream reads both outcomes again.
	fresh, _, _ := f.s.FinalOutcomes(ctx, cell1, 0)
	if len(fresh) != 2 {
		t.Fatalf("second stream read %+v, want both outcomes", fresh)
	}
	// ForgetRetries drops the retry outcomes of that cell up to the cursor, and only those.
	if err := f.s.ForgetRetries(ctx, cell2, cur); err != nil {
		t.Fatal(err)
	}
	if fresh, _, _ = f.s.FinalOutcomes(ctx, cell1, 0); len(fresh) != 2 {
		t.Fatalf("a forget for another cell removed outcomes: %+v", fresh)
	}
	if err := f.s.ForgetRetries(ctx, cell1, cur-1); err != nil {
		t.Fatal(err)
	}
	if fresh, _, _ = f.s.FinalOutcomes(ctx, cell1, 0); len(fresh) != 2 {
		t.Fatalf("a forget below the cursor removed the retry: %+v", fresh)
	}
	if err := f.s.ForgetRetries(ctx, cell1, cur); err != nil {
		t.Fatal(err)
	}
	fresh, _, _ = f.s.FinalOutcomes(ctx, cell1, 0)
	if len(fresh) != 1 || fresh[0].Outcome != mgmtapi.OutcomeAccepted {
		t.Fatalf("after ForgetRetries %+v, want only the final outcome", fresh)
	}
	r3 := f.appendItem(item(gwapi.KindResult, cell1, opID(4), 1))
	if err := f.s.Ack(ctx, ackAccepted(r3)); err != nil {
		t.Fatal(err)
	}
	next, cur3, _ := f.s.FinalOutcomes(ctx, cell1, cur)
	if len(next) != 1 || next[0].OpID != opID(4) || cur3 <= cur {
		t.Fatalf("read after a new ack: %+v, %d", next, cur3)
	}
	if _, ok, _ := f.s.Outcome(ctx, cell1, b); !ok {
		t.Fatal("a bind outcome is still readable by ID")
	}
}

func TestOutboxStatusDropStaysInCell(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.s.maxItems = 3
	for range 3 {
		f.appendItem(item(gwapi.KindStatus, cell2, "", 1))
	}
	// A status item of another cell is refused. A result of another cell displaces the oldest
	// status item of the cell with the most bytes.
	if _, err := f.s.Append(ctx, item(gwapi.KindStatus, cell1, "", 1)); !errors.Is(err, gwapi.ErrOverloaded) {
		t.Fatalf("status of cell 1 into an outbox full of cell 2 status items: %v", err)
	}
	if got, _ := f.s.Peek(ctx, 10, 1<<20); len(got) != 3 {
		t.Fatalf("outbox holds %d items, want the 3 status items of cell 2", len(got))
	}
	f.appendItem(item(gwapi.KindResult, cell1, opID(1), 1))
	got, _ := f.s.Peek(ctx, 10, 1<<20)
	if len(got) != 3 || got[0].Kind != gwapi.KindResult {
		t.Fatalf("outbox after a result of cell 1: %+v", got)
	}
}

func TestOutboxRefusalRollsBackDrops(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.s.maxBytes = 2500
	s1 := f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	r1 := f.appendItem(item(gwapi.KindResult, cell1, opID(1), 2000))
	if _, err := f.s.Append(ctx, item(gwapi.KindResult, cell1, opID(2), 2000)); !errors.Is(err, gwapi.ErrOverloaded) {
		t.Fatalf("a result that needs more than the status item frees: %v", err)
	}
	got, _ := f.s.Peek(ctx, 10, 1<<20)
	if len(got) != 2 || got[0].ID != r1 || got[1].ID != s1 {
		t.Fatalf("outbox %+v: the refusal must not keep the drop", got)
	}
	if st, _ := f.s.Stats(ctx); st.Dropped != 0 {
		t.Fatalf("dropped %d, want 0", st.Dropped)
	}
}

func TestPeekOrder(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s1 := f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	t1 := f.appendItem(item(gwapi.KindStatus, cell2, "", 1))
	r1 := f.appendItem(item(gwapi.KindResult, cell1, opID(1), 1))
	s2 := f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	b1 := f.appendItem(item(gwapi.KindBind, cell2, "", 1))
	s3 := f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
	r2 := f.appendItem(item(gwapi.KindResult, cell2, opID(2), 1))
	// The newest status of each cell is s3 and t1. The rest follow by seq.
	want := []gwapi.ItemID{b1, r1, r2, t1, s3, s1, s2}
	got, err := f.s.Peek(ctx, 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("Peek gave %d items, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("item %d is %s %s, want %s", i, got[i].Kind, got[i].ID, want[i])
		}
	}
}

func TestPeekOrderKeepsLimits(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for n := range 120 {
		f.appendItem(item(gwapi.KindStatus, cell1, "", 1))
		f.appendItem(item(gwapi.KindResult, cell2, opID(n+1), 1))
	}
	got, err := f.s.Peek(ctx, 1000, 10<<20)
	if err != nil || len(got) != MaxPeekItems {
		t.Fatalf("Peek gave %d items, err %v", len(got), err)
	}
	for _, it := range got {
		if it.Kind != gwapi.KindResult {
			t.Fatalf("a %s item came before the results", it.Kind)
		}
	}
	small, err := f.s.Peek(ctx, 3, 10<<20)
	if err != nil || len(small) != 3 {
		t.Fatalf("Peek(3) gave %d items, err %v", len(small), err)
	}
	one, err := f.s.Peek(ctx, 5, 10)
	if err != nil || len(one) != 1 || one[0].Kind != gwapi.KindResult {
		t.Fatalf("byte budget: %+v, %v", one, err)
	}
}
