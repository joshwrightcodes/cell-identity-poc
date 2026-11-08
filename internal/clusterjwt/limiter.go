package clusterjwt

import (
	"sync"
	"time"
)

// limiter is an in-memory token bucket for each key. Attest charges it only after a token validates.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perSecond float64, burst int, now func() time.Time) *limiter {
	return &limiter{rate: perSecond, burst: float64(burst), now: now, buckets: map[string]*bucket{}}
}

// allow takes one slot for key. It returns false when the bucket is empty.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gate caps the challenges in flight for each key.
type gate struct {
	mu  sync.Mutex
	max int
	n   map[string]int
}

func newGate(max int) *gate { return &gate{max: max, n: map[string]int{}} }

// acquire takes one in-flight slot for key. It returns false at the cap.
func (g *gate) acquire(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n[key] >= g.max {
		return false
	}
	g.n[key]++
	return true
}

func (g *gate) release(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n[key]--; g.n[key] <= 0 {
		delete(g.n, key)
	}
}

func (g *gate) count(key string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n[key]
}
