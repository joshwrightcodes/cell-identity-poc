package e2e

// The pure rules of the store-loss test: the read count of the sampler and the comparison time of Argo CD. This file has no build tag.

import (
	"testing"
	"time"
)

// m9StoreMinReads is the fewest reads that make the sampler a proof: one at the start and one at the stop.
const m9StoreMinReads = 2

// m9StoreReadsEnough reports whether the sampler read often enough to prove that nothing was pruned.
func m9StoreReadsEnough(reads int) bool { return reads >= m9StoreMinReads }

// m9StoreComparedAfter reports whether a comparison of Argo CD (whole seconds) is surely not older than the refill. The refill time is cut
// up to the next whole second, so a comparison in the same second as the refill does not count.
func m9StoreComparedAfter(reconciled, refilledAt time.Time) bool {
	up := refilledAt.Truncate(time.Second)
	if up.Before(refilledAt) {
		up = up.Add(time.Second)
	}
	return !reconciled.Before(up)
}

func TestStoreReadsEnough(t *testing.T) {
	for reads, want := range map[int]bool{0: false, 1: false, 2: true, 7: true} {
		if got := m9StoreReadsEnough(reads); got != want {
			t.Errorf("%d reads: got %v, want %v", reads, got, want)
		}
	}
}

func TestStoreComparedAfter(t *testing.T) {
	refill := time.Date(2026, 11, 22, 20, 59, 49, 497e6, time.UTC)
	for name, c := range map[string]struct {
		rec  time.Time
		want bool
	}{
		"same second as the refill": {time.Date(2026, 11, 22, 20, 59, 49, 0, time.UTC), false},
		"next second":               {time.Date(2026, 11, 22, 20, 59, 50, 0, time.UTC), true},
		"earlier":                   {time.Date(2026, 11, 22, 20, 59, 40, 0, time.UTC), false},
		"much later":                {time.Date(2026, 11, 22, 21, 2, 0, 0, time.UTC), true},
		"zero time":                 {time.Time{}, false},
	} {
		if got := m9StoreComparedAfter(c.rec, refill); got != c.want {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
	whole := time.Date(2026, 11, 22, 20, 59, 49, 0, time.UTC)
	if !m9StoreComparedAfter(whole, whole) {
		t.Errorf("a comparison at the refill second on a whole-second refill must count")
	}
}
