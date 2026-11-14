package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const cell1, cell2 = "dev-cell-1", "dev-cell-2"

func TestRaiseEpochAboveSeenFence(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	base := f.s.Epoch()
	if err := f.s.RaiseEpoch(ctx, op.Fence{Epoch: base - 1, Counter: 99}); err != nil {
		t.Fatal(err)
	}
	if f.s.Epoch() != base {
		t.Fatalf("a lower seen epoch moved the epoch to %d", f.s.Epoch())
	}
	if err := f.s.RaiseEpoch(ctx, op.Fence{Epoch: base + 10, Counter: 5}); err != nil {
		t.Fatal(err)
	}
	if f.s.Epoch() != base+11 {
		t.Fatalf("epoch %d, want one above the seen epoch %d", f.s.Epoch(), base+11)
	}
	f.enqueue(1, cell1)
	l, err := f.s.Claim(ctx, cell1, "pod")
	if err != nil || l == nil || l.Fence.Epoch != base+11 {
		t.Fatalf("claim after raise: %+v, %v", l, err)
	}
	f.reopen()
	if f.s.Epoch() != base+11 {
		t.Fatalf("epoch after reopen %d, want %d", f.s.Epoch(), base+11)
	}
	st, err := f.s.Stats(ctx)
	if err != nil || st.Epoch != base+11 || !st.EpochChangedAt.Equal(t0) {
		t.Fatalf("stats %+v, %v", st, err)
	}
}

func TestQueueClaimOrderAndDedupe(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for n := 1; n <= 3; n++ {
		f.enqueue(n, cell1)
	}
	f.enqueue(9, cell2)
	if id, added, err := f.s.Enqueue(ctx, cell1, f.opEnv(opID(2), cell1, 1)); err == nil || added || id != opID(2) {
		t.Fatalf("other bytes, same epoch: %q, %v, %v", id, added, err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 3 {
		t.Fatalf("depth %d, want 3", d)
	}
	var last op.Fence
	for n := 1; n <= 3; n++ {
		l, err := f.s.Claim(ctx, cell1, "pod-a")
		if err != nil || l == nil {
			t.Fatalf("claim %d: %v, %v", n, l, err)
		}
		if l.OpID != opID(n) {
			t.Fatalf("claim %d returned op %s, want the oldest", n, l.OpID)
		}
		if last.Compare(l.Fence) >= 0 {
			t.Fatalf("fence %v does not rise above %v", l.Fence, last)
		}
		if !l.Until.Equal(t0.Add(60 * time.Second)) {
			t.Fatalf("lease until %v", l.Until)
		}
		last = l.Fence
	}
	if l, err := f.s.Claim(ctx, cell1, "pod-a"); l != nil || err != nil {
		t.Fatalf("claim of a drained cell: %v, %v", l, err)
	}
	l, err := f.s.Claim(ctx, cell2, "pod-b")
	if err != nil || l == nil || l.OpID != opID(9) || last.Compare(l.Fence) >= 0 {
		t.Fatalf("other cell claim %+v, %v: fence must stay global", l, err)
	}
	st, err := f.s.Stats(ctx)
	if err != nil || st.Queued[cell1] != 3 || st.MostClaimed[cell1].Count != 1 {
		t.Fatalf("stats %+v, %v", st, err)
	}
}

func TestQueueLeaseExpiryNewFence(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	a, _ := f.s.Claim(ctx, cell1, "pod-a")
	f.clk.Advance(59 * time.Second)
	if l, _ := f.s.Claim(ctx, cell1, "pod-b"); l != nil {
		t.Fatal("a live lease was claimed again")
	}
	f.clk.Advance(2 * time.Second)
	b, err := f.s.Claim(ctx, cell1, "pod-b")
	if err != nil || b == nil || b.OpID != a.OpID || b.ID != a.ID {
		t.Fatalf("claim after expiry: %+v, %v", b, err)
	}
	if b.Fence.Compare(a.Fence) <= 0 {
		t.Fatalf("fence %v after expiry, want above %v", b.Fence, a.Fence)
	}
	// The first holder finishes late, with the old fence, under the live lease of the second.
	_, err = f.s.CompleteWithItem(ctx, cell1, a.ID, resultItem(cell1, a.OpID), a.Fence)
	if !errors.Is(err, gwapi.ErrLeaseLost) {
		t.Fatalf("late completion: %v, want lease lost", err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 1 {
		t.Fatalf("depth %d after a lost lease, want the row still open", d)
	}
	if st, _ := f.s.Stats(ctx); st.MostClaimed[cell1].Count != 2 {
		t.Fatalf("claim count %+v, want 2", st.MostClaimed)
	}
	if _, err := f.s.CompleteWithItem(ctx, cell1, b.ID, resultItem(cell1, b.OpID), b.Fence); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 0 {
		t.Fatalf("depth %d after the live holder finished", d)
	}
}

func TestQueueConcurrentClaimsDistinct(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const n = 12
	for i := 1; i <= n; i++ {
		f.enqueue(i, cell1)
	}
	var wg sync.WaitGroup
	leases := make([]*Lease, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := f.s.Claim(ctx, cell1, "pod")
			if err != nil {
				t.Error(err)
			}
			leases[i] = l
		}()
	}
	wg.Wait()
	ops, fences := map[string]bool{}, map[op.Fence]bool{}
	for _, l := range leases {
		if l == nil {
			t.Fatal("a claim got no item")
		}
		if ops[l.OpID] || fences[l.Fence] {
			t.Fatalf("duplicate claim or fence: %+v", l)
		}
		ops[l.OpID], fences[l.Fence] = true, true
	}
	if l, _ := f.s.Claim(ctx, cell1, "pod"); l != nil {
		t.Fatal("more claims than items")
	}
}

func TestQueueSurvivesReopen(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	f.enqueue(2, cell1)
	a, _ := f.s.Claim(ctx, cell1, "pod")
	if _, err := f.s.CompleteWithItem(ctx, cell1, a.ID, resultItem(cell1, a.OpID), a.Fence); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if d, _ := f.s.Depth(ctx, cell1); d != 1 {
		t.Fatalf("depth %d after reopen, want 1", d)
	}
	b, _ := f.s.Claim(ctx, cell1, "pod")
	if b == nil || b.OpID != opID(2) || b.Fence.Compare(a.Fence) <= 0 {
		t.Fatalf("claim after reopen %+v: the fence counter must continue above %v", b, a.Fence)
	}
	if items, _ := f.s.Peek(ctx, 10, 1<<20); len(items) != 1 {
		t.Fatalf("outbox has %d items after reopen, want 1", len(items))
	}
}

func TestEnqueueReplacesHigherKeyEpoch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cell := cell1
	if _, added, err := f.s.Enqueue(ctx, cell, f.opEnv(opID(1), cell, 1)); err != nil || !added {
		t.Fatal(added, err)
	}
	f.s.Claim(ctx, cell, "pod")
	e2 := f.opEnv(opID(1), cell, 2)
	if _, added, err := f.s.Enqueue(ctx, cell, e2); err != nil || added {
		t.Fatalf("replacement: added %v, %v", added, err)
	}
	f.clk.Advance(61 * time.Second)
	b, _ := f.s.Claim(ctx, cell, "pod")
	if string(b.Envelope) != string(e2) {
		t.Fatal("the queued item did not take the epoch-2 bytes")
	}
	// Replace while leased keeps the fence: a lease taken now and replaced afterwards.
	c := f.opEnv(opID(2), cell, 1)
	f.s.Enqueue(ctx, cell, c)
	l, _ := f.s.Claim(ctx, cell, "pod")
	if _, _, err := f.s.Enqueue(ctx, cell, f.opEnv(opID(2), cell, 3)); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.s.Depth(ctx, cell); d != 2 {
		t.Fatalf("depth %d, want 2: a replacement adds no row", d)
	}
	if again, _ := f.s.Claim(ctx, cell, "pod-2"); again != nil {
		t.Fatalf("the replacement dropped the live lease: %+v", again)
	}
	older := op.Fence{Epoch: l.Fence.Epoch, Counter: l.Fence.Counter - 1}
	if _, err := f.s.CompleteWithItem(ctx, cell, l.ID, resultItem(cell, l.OpID), older); !errors.Is(err, gwapi.ErrLeaseLost) {
		t.Fatalf("the replacement dropped the fence: a lower fence gave %v", err)
	}
	if _, err := f.s.CompleteWithItem(ctx, cell, l.ID, resultItem(cell, l.OpID), l.Fence); err != nil {
		t.Fatalf("the holder of the replaced item keeps its fence: %v", err)
	}
	// A lower key epoch never replaces.
	if _, _, err := f.s.Enqueue(ctx, cell, f.opEnv(opID(1), cell, 1)); !errors.Is(err, gwapi.ErrEnvelopeConflict) {
		t.Fatalf("lower epoch: %v", err)
	}
	// A done item takes no replacement either.
	if _, err := f.s.CompleteWithItem(ctx, cell, b.ID, resultItem(cell, b.OpID), b.Fence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Enqueue(ctx, cell, f.opEnv(opID(1), cell, 9)); !errors.Is(err, gwapi.ErrEnvelopeConflict) {
		t.Fatalf("done item: %v", err)
	}
}

func TestEnqueueConflictSameEpoch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	e1 := f.opEnv(opID(1), cell1, 2)
	if _, _, err := f.s.Enqueue(ctx, cell1, e1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Enqueue(ctx, cell1, f.opEnv(opID(1), cell1, 2)); !errors.Is(err, gwapi.ErrEnvelopeConflict) {
		t.Fatalf("same epoch, other bytes: %v", err)
	}
	if id, added, err := f.s.Enqueue(ctx, cell1, e1); err != nil || added || id != opID(1) {
		t.Fatalf("same bytes: %q, %v, %v", id, added, err)
	}
	if _, _, err := f.s.Enqueue(ctx, cell2, e1); err == nil {
		t.Fatal("an envelope for another cell was queued")
	}
	if _, _, err := f.s.Enqueue(ctx, cell1, []byte("junk")); err == nil {
		t.Fatal("junk was queued")
	}
}

func TestEnqueueReplayRequeuesDone(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	a, _ := f.s.Claim(ctx, cell1, "pod")
	if _, err := f.s.CompleteWithItem(ctx, cell1, a.ID, resultItem(cell1, a.OpID), a.Fence); err != nil {
		t.Fatal(err)
	}
	if l, _ := f.s.Claim(ctx, cell1, "pod"); l != nil {
		t.Fatal("a done item was claimed")
	}
	if _, err := f.s.EnqueueReplay(ctx, cell1, f.opEnv(opID(1), cell1, 1)); err != nil {
		t.Fatal(err)
	}
	b, _ := f.s.Claim(ctx, cell1, "pod")
	if b == nil || b.OpID != opID(1) {
		t.Fatalf("replay did not requeue: %+v", b)
	}
}

func TestEnqueueReplayOtherCellKeepsRow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, _, err := f.s.Enqueue(ctx, cell1, f.opEnv(opID(7), cell1, 1)); err != nil {
		t.Fatal(err)
	}
	a, _ := f.s.Claim(ctx, cell1, "pod")
	if _, err := f.s.EnqueueReplay(ctx, cell2, f.opEnv(opID(7), cell2, 1)); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 1 {
		t.Fatalf("cell 1 depth %d, want its row kept", d)
	}
	if d, _ := f.s.Depth(ctx, cell2); d != 1 {
		t.Fatalf("cell 2 depth %d, want 1", d)
	}
	if _, err := f.s.CompleteWithItem(ctx, cell1, a.ID, resultItem(cell1, a.OpID), a.Fence); err != nil {
		t.Fatalf("the cell 1 lease still holds: %v", err)
	}
}

func TestCompleteWithItemAtomic(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	a, _ := f.s.Claim(ctx, cell1, "pod")
	id, err := f.s.CompleteWithItem(ctx, cell1, a.ID, resultItem(cell1, a.OpID), a.Fence)
	if err != nil || !id.Valid() {
		t.Fatalf("complete: %q, %v", id, err)
	}
	items, _ := f.s.Peek(ctx, 10, 1<<20)
	if len(items) != 1 || items[0].ID != id || items[0].Kind != gwapi.KindResult || items[0].OpID != a.OpID {
		t.Fatalf("outbox %+v, want the appended result", items)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 0 {
		t.Fatal("row not done")
	}
	// A full outbox refuses the result and leaves the row open: nothing half-done.
	g := newFixture(t)
	g.s.maxItems = 0
	g.enqueue(1, cell1)
	b, _ := g.s.Claim(ctx, cell1, "pod")
	if _, err := g.s.CompleteWithItem(ctx, cell1, b.ID, resultItem(cell1, b.OpID), b.Fence); !errors.Is(err, gwapi.ErrOverloaded) {
		t.Fatalf("full outbox: %v", err)
	}
	if d, _ := g.s.Depth(ctx, cell1); d != 1 {
		t.Fatal("the row was marked done without its result")
	}
	if _, err := f.s.CompleteWithItem(ctx, cell2, a.ID, resultItem(cell1, a.OpID), a.Fence); err == nil {
		t.Fatal("an item of another cell was accepted")
	}
}

func TestCompleteResendAppendsOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	a, _ := f.s.Claim(ctx, cell1, "pod")
	if _, err := f.s.CompleteWithItem(ctx, cell1, "", resultItem(cell1, a.OpID), a.Fence); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 1 {
		t.Fatal("a resend marked the row done")
	}
	if items, _ := f.s.Peek(ctx, 10, 1<<20); len(items) != 1 {
		t.Fatalf("%d items, want the resent result", len(items))
	}
}

func TestCompleteEmptyOpIDByLease(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	a, _ := f.s.Claim(ctx, cell1, "pod")
	it := resultItem(cell1, "")
	if _, err := f.s.CompleteWithItem(ctx, cell1, a.ID, it, a.Fence); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 1 {
		t.Fatal("a result with an empty OpID marked the row done")
	}
	f.clk.Advance(ForgedHold - time.Second)
	if l, _ := f.s.Claim(ctx, cell1, "pod"); l != nil {
		t.Fatalf("the row was claimable inside the hold: %+v", l)
	}
	f.clk.Advance(2 * time.Second)
	l, _ := f.s.Claim(ctx, cell1, "pod")
	if l == nil || l.OpID != a.OpID || l.Fence.Compare(a.Fence) <= 0 {
		t.Fatalf("after the hold the row gave %+v, want the same op under a higher fence", l)
	}
}

func TestEnqueueNotifies(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c1, stop1 := f.n.Subscribe(cell1)
	defer stop1()
	c2, stop2 := f.n.Subscribe(cell2)
	defer stop2()
	e1 := f.opEnv(opID(1), cell1, 1)
	if _, _, err := f.s.Enqueue(ctx, cell1, e1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c1:
	default:
		t.Fatal("the subscriber of the cell got no signal")
	}
	select {
	case <-c2:
		t.Fatal("another cell's subscriber got a signal")
	default:
	}
	if _, _, err := f.s.Enqueue(ctx, cell1, e1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c1:
		t.Fatal("a known item gave a signal")
	default:
	}
	if _, _, err := f.s.Enqueue(ctx, cell1, f.opEnv(opID(1), cell1, 2)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c1:
	default:
		t.Fatal("a replacement gave no signal")
	}
	if _, err := f.s.EnqueueReplay(ctx, cell1, f.opEnv(opID(1), cell1, 2)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c1:
	default:
		t.Fatal("a replay gave no signal")
	}
}

func TestPruneDone(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	a, _ := f.s.Claim(ctx, cell1, "pod")
	id, err := f.s.CompleteWithItem(ctx, cell1, a.ID, resultItem(cell1, a.OpID), a.Fence)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.Ack(ctx, ackAccepted(id)); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(9*time.Minute + 59*time.Second)
	if err := f.s.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.s.Outcome(ctx, cell1, id); !ok {
		t.Fatal("outcome pruned before 10 minutes")
	}
	f.clk.Advance(2 * time.Second)
	if err := f.s.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.s.Outcome(ctx, cell1, id); ok {
		t.Fatal("outcome kept after 10 minutes")
	}
	f.clk.Advance(24*time.Hour - 11*time.Minute)
	f.s.Prune(ctx)
	if _, added, _ := f.s.Enqueue(ctx, cell1, f.opEnv(opID(1), cell1, 1)); added {
		t.Fatal("a done item was pruned before 24 h")
	}
	f.clk.Advance(time.Minute)
	f.s.Prune(ctx)
	if _, added, err := f.s.Enqueue(ctx, cell1, f.opEnv(opID(1), cell1, 1)); err != nil || !added {
		t.Fatalf("a done item older than 24 h was kept: %v, %v", added, err)
	}
}

func TestCompleteLeaseFromOtherStore(t *testing.T) {
	ctx := context.Background()
	a := newFixture(t)
	a.enqueue(1, cell1)
	la, _ := a.s.Claim(ctx, cell1, "pod")
	// The store is wiped and made again: row 1 now holds another operation of the same cell.
	b := newFixture(t)
	b.enqueue(2, cell1)
	if _, err := b.s.CompleteWithItem(ctx, cell1, la.ID, resultItem(cell1, la.OpID), la.Fence); err != nil {
		t.Fatal(err)
	}
	// A result with no op ID cannot be told apart by the op ID guard: the store ID alone must refuse it.
	if _, err := b.s.CompleteWithItem(ctx, cell1, la.ID, resultItem(cell1, ""), la.Fence); err != nil {
		t.Fatal(err)
	}
	lb, _ := b.s.Claim(ctx, cell1, "pod")
	if lb == nil || lb.OpID != opID(2) {
		t.Fatalf("a lease of another store file marked the new row done: %+v", lb)
	}
	if items, _ := b.s.Peek(ctx, 10, 1<<20); len(items) != 2 {
		t.Fatalf("the resent results were not appended: %d items", len(items))
	}
}

func TestCompleteOtherOpIDIsResend(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	l, _ := f.s.Claim(ctx, cell1, "pod")
	if _, err := f.s.CompleteWithItem(ctx, cell1, l.ID, resultItem(cell1, opID(77)), l.Fence); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 1 {
		t.Fatal("a result for another op ID marked the row done")
	}
}

func TestCompleteUnparsableLeaseIsResend(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	f.s.Claim(ctx, cell1, "pod")
	for _, id := range []string{"x", "1", f.s.storeID + ".x", "."} {
		if _, err := f.s.CompleteWithItem(ctx, cell1, id, resultItem(cell1, ""), op.Fence{Epoch: 1 << 40, Counter: 1}); err != nil {
			t.Fatalf("lease %q: %v", id, err)
		}
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 1 {
		t.Fatal("an unparsable lease marked a row done")
	}
	if !strings.Contains(f.logs.String(), `"msg":"lease_id_invalid"`) || !strings.Contains(f.logs.String(), cell1) {
		t.Fatalf("no warn log for an unparsable lease: %s", f.logs.String())
	}
}

func TestCompleteOtherCellRow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell2)
	l2, _ := f.s.Claim(ctx, cell2, "pod")
	high := op.Fence{Epoch: l2.Fence.Epoch + 1, Counter: 1 << 40}
	if _, err := f.s.CompleteWithItem(ctx, cell1, l2.ID, resultItem(cell1, ""), high); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.s.Depth(ctx, cell2); d != 1 {
		t.Fatal("a pod of cell 1 completed a row of cell 2")
	}
}

func TestQueueLateCompletionExpiredLease(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	a, _ := f.s.Claim(ctx, cell1, "pod-a")
	f.clk.Advance(61 * time.Second)
	b, _ := f.s.Claim(ctx, cell1, "pod-b")
	f.clk.Advance(61 * time.Second)
	if b.Fence.Compare(a.Fence) <= 0 {
		t.Fatal("test setup: fence did not rise")
	}
	if _, err := f.s.CompleteWithItem(ctx, cell1, a.ID, resultItem(cell1, a.OpID), a.Fence); err != nil {
		t.Fatalf("a result under an expired lease of a higher fence: %v", err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 0 {
		t.Fatal("the late result did not mark the row done")
	}
}

func TestClaimReadsEpochInTransaction(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enqueue(1, cell1)
	old := f.s.Epoch()
	if err := f.s.RaiseEpoch(ctx, op.Fence{Epoch: old + 5}); err != nil {
		t.Fatal(err)
	}
	// The window between the commit of RaiseEpoch and the memory update: memory holds the old epoch.
	f.s.epoch.Store(old)
	l, _ := f.s.Claim(ctx, cell1, "pod")
	if l == nil || l.Fence.Epoch != old+6 {
		t.Fatalf("claim fence %+v, want epoch %d", l, old+6)
	}
}

// A key rotation re-signs an open op under a key that the cell does not pin yet. The cell refuses it
// with an empty OpID. After the cell trusts the new key, the gateway delivers the re-signed op
// again, and the cell verifies it and ends it.
func TestRotationKeepsResignedOp(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	oldEnv := f.opEnv(opID(7), cell1, 1)
	if _, added, err := f.s.Enqueue(ctx, cell1, oldEnv); err != nil || !added {
		t.Fatal(added, err)
	}
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub := newPriv.Public().(ed25519.PublicKey)
	o, _, err := op.Verify(oldEnv, []ed25519.PublicKey{f.pub})
	if err != nil {
		t.Fatal(err)
	}
	o.KeyEpoch = 2
	newEnv, err := op.Sign(o, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Enqueue(ctx, cell1, newEnv); err != nil {
		t.Fatal(err)
	}
	l, err := f.s.Claim(ctx, cell1, "pod-a")
	if err != nil || l == nil || !bytes.Equal(l.Envelope, newEnv) {
		t.Fatalf("claim %+v, %v: want the re-signed envelope", l, err)
	}
	if _, _, err := op.Verify(l.Envelope, []ed25519.PublicKey{f.pub}); !errors.Is(err, record.ErrSignature) {
		t.Fatalf("old pin: %v", err)
	}
	pid, _, _, _ := op.Peek(l.Envelope)
	body, _ := json.Marshal(op.Result{PeekedID: pid, Cell: cell1, Outcome: op.OutcomeRefused,
		Reason: op.ReasonSignatureInvalid, Fence: l.Fence, EnvelopeSHA256: op.EnvelopeSHA256(l.Envelope)})
	it := gwapi.Item{Kind: gwapi.KindResult, Cell: cell1, Body: body, Token: "tok"}
	if _, err := f.s.CompleteWithItem(ctx, cell1, l.ID, it, l.Fence); err != nil {
		t.Fatal(err)
	}

	f.clk.Advance(ForgedHold + time.Second)
	if _, added, err := f.s.Enqueue(ctx, cell1, newEnv); err != nil || added {
		t.Fatalf("sync again: added %v, %v", added, err)
	}
	l2, err := f.s.Claim(ctx, cell1, "pod-b")
	if err != nil || l2 == nil || !bytes.Equal(l2.Envelope, newEnv) {
		t.Fatalf("after the hold: %+v, %v; want the re-signed op", l2, err)
	}
	if _, _, err := op.Verify(l2.Envelope, []ed25519.PublicKey{f.pub, newPub}); err != nil {
		t.Fatalf("the cell does not accept the re-signed op: %v", err)
	}
	done := gwapi.Item{Kind: gwapi.KindResult, Cell: cell1, OpID: o.ID, Body: body, Token: "tok"}
	if _, err := f.s.CompleteWithItem(ctx, cell1, l2.ID, done, l2.Fence); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.s.Depth(ctx, cell1); d != 0 {
		t.Fatal("the applied op is still open")
	}
}
