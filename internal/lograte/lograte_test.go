package lograte

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestAllowsOneEventPerKeyAndWindow(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := New(10*time.Second, 4, c.now)
	if _, ok, n, _ := l.Allow("a"); !ok || n != 0 {
		t.Fatalf("first event: ok %v, suppressed %d", ok, n)
	}
	for range 99 {
		c.t = c.t.Add(10 * time.Millisecond)
		if _, ok, _, _ := l.Allow("a"); ok {
			t.Fatal("an event inside the window is allowed")
		}
	}
	if _, ok, _, _ := l.Allow("b"); !ok {
		t.Fatal("another key is limited by the first")
	}
	c.t = c.t.Add(10 * time.Second)
	if _, ok, n, _ := l.Allow("a"); !ok || n != 99 {
		t.Fatalf("event after the window: ok %v, suppressed %d, want 99", ok, n)
	}
}

func TestNewKeysShareOneKeyWhenFull(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := New(10*time.Second, 4, c.now)
	allowed := 0
	for i := range 54 {
		key, ok, _, _ := l.Allow(fmt.Sprint(i))
		if ok {
			allowed++
		}
		if i >= 4 && key != Overflow {
			t.Fatalf("key %d is counted as %q, want %q", i, key, Overflow)
		}
	}
	if allowed != 5 {
		t.Fatalf("%d events allowed, want 4 keys and one overflow event", allowed)
	}
	c.t = c.t.Add(10 * time.Second)
	_, ok, _, held := l.Allow("new")
	if !ok || len(held) != 1 || held[0] != (Held{Key: Overflow, Suppressed: 49}) {
		t.Fatalf("after the window: ok %v, held %v, want the 49 overflow events", ok, held)
	}
}

func TestKeepsCountsUntilItReportsThem(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := New(10*time.Second, 2, c.now)
	for range 5 {
		l.Allow("a")
	}
	l.Allow("b")
	c.t = c.t.Add(time.Minute)
	_, _, _, held := l.Allow("c")
	if len(held) != 1 || held[0] != (Held{Key: "a", Suppressed: 4}) {
		t.Fatalf("held %v, want a with 4", held)
	}
}
