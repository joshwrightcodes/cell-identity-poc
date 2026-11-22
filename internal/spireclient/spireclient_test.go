package spireclient

import (
	"testing"
	"time"
)

func TestStrategyGrowsAndCaps(t *testing.T) {
	b := Strategy{Rand: func() float64 { return 0 }}.NewBackoff()
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second}
	for i, w := range want {
		if got := b.Next(); got != w {
			t.Fatalf("step %d: got %v, want %v", i, got, w)
		}
	}
	b.Reset()
	if got := b.Next(); got != InitialDelay {
		t.Fatalf("after Reset: got %v, want %v", got, InitialDelay)
	}
}

func TestStrategyJitterStaysInBounds(t *testing.T) {
	b := Strategy{}.NewBackoff()
	for i := 0; i < 200; i++ {
		d := b.Next()
		if d < InitialDelay || d > MaxDelay*12/10 {
			t.Fatalf("step %d: %v outside [%v, %v]", i, d, InitialDelay, MaxDelay*12/10)
		}
		if i%50 == 49 {
			b.Reset()
		}
	}
}
