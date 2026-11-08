package clusterjwt

import (
	"sync"
	"time"
)

// limiter is an in-memory token bucket for each key. It holds one bucket for each known cell.
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
