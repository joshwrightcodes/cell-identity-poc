// Package lograte limits repeated log lines, so a peer or a failing exporter cannot flood the
// logs.
package lograte

import (
	"sync"
	"time"
)

// Overflow is the key that new keys share once the limiter holds its maximum number of keys.
const Overflow = "overflow"

// Held is a key whose window ended with events that the limiter held back.
type Held struct {
	Key        string
	Suppressed int
}

// Limiter allows one event for each key in each window, and counts the events that it holds back.
type Limiter struct {
	window time.Duration
	max    int
	now    func() time.Time

	mu   sync.Mutex
	seen map[string]*state
}

type state struct {
	last       time.Time
	suppressed int
}

// New returns a limiter that remembers at most max keys, plus Overflow.
func New(window time.Duration, max int, now func() time.Time) *Limiter {
	return &Limiter{window: window, max: max, now: now, seen: map[string]*state{}}
}

// Allow reports whether to log an event for key. counted is the key that counts the event: key,
// or Overflow when the limiter is full. suppressed is the number of events of counted that the
// limiter held back since its last allowed event. held lists keys that the limiter forgot to make
// room, with their held-back events, so the caller can log those counts now.
func (l *Limiter) Allow(key string) (counted string, ok bool, suppressed int, held []Held) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	st, found := l.seen[key]
	if !found && len(l.seen) >= l.max {
		held = l.prune(now)
		if len(l.seen) >= l.max {
			key = Overflow
			st, found = l.seen[key]
		}
	}
	if found && now.Sub(st.last) < l.window {
		st.suppressed++
		return key, false, 0, held
	}
	if found {
		suppressed = st.suppressed
	}
	l.seen[key] = &state{last: now}
	return key, true, suppressed, held
}

// prune forgets every key whose window has ended, and returns those with held-back events.
func (l *Limiter) prune(now time.Time) []Held {
	var held []Held
	for key, st := range l.seen {
		if now.Sub(st.last) < l.window {
			continue
		}
		if st.suppressed > 0 {
			held = append(held, Held{Key: key, Suppressed: st.suppressed})
		}
		delete(l.seen, key)
	}
	return held
}
