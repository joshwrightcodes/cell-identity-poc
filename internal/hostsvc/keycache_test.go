package hostsvc

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// gatedFacts counts lookups and blocks each one until gate closes or the lookup context ends.
type gatedFacts struct {
	gate    chan struct{}
	calls   atomic.Int32
	current atomic.Int32
	max     atomic.Int32
	fail    atomic.Bool
}

func newGatedFacts() *gatedFacts { return &gatedFacts{gate: make(chan struct{})} }

func (g *gatedFacts) facts(ctx context.Context, cluster string) (Facts, error) {
	g.calls.Add(1)
	cur := g.current.Add(1)
	defer g.current.Add(-1)
	for {
		m := g.max.Load()
		if cur <= m || g.max.CompareAndSwap(m, cur) {
			break
		}
	}
	select {
	case <-g.gate:
	case <-ctx.Done():
		return Facts{}, ctx.Err()
	}
	if g.fail.Load() {
		return Facts{}, errors.New("docker is down")
	}
	return Facts{Name: cluster, Issuer: "https://" + cluster + ".issuer.poc.internal", JWKS: json.RawMessage(`{"keys":[]}`)}, nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestKeyCacheBoundsConcurrency(t *testing.T) {
	g := newGatedFacts()
	c := NewKeyCache(g.facts, KeyTTL, KeyMaxInFlight, nil)
	clusters := []string{"a", "b", "c", "d", "e"}
	var wg sync.WaitGroup
	for _, name := range clusters {
		wg.Go(func() {
			if _, err := c.Get(context.Background(), name); err != nil {
				t.Errorf("Get(%s): %v", name, err)
			}
		})
	}
	waitFor(t, "two lookups to start", func() bool { return g.current.Load() == 2 })
	time.Sleep(100 * time.Millisecond)
	if got := g.current.Load(); got != 2 {
		t.Errorf("%d lookups at once while blocked, want 2", got)
	}
	close(g.gate)
	wg.Wait()
	if got := g.max.Load(); got != 2 {
		t.Errorf("most lookups at once = %d, want 2", got)
	}
	if got := g.calls.Load(); got != 5 {
		t.Errorf("lookups = %d, want 5", got)
	}
}

func TestKeyCacheLookupDeadline(t *testing.T) {
	g := newGatedFacts()
	c := NewKeyCache(g.facts, KeyTTL, KeyMaxInFlight, nil)
	if c.lookupTimeout != 10*time.Second {
		t.Fatalf("lookup deadline = %v, want 10s", c.lookupTimeout)
	}
	c.lookupTimeout = 30 * time.Millisecond
	start := time.Now()
	_, err := c.Get(context.Background(), "a")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get error = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Get took %v", time.Since(start))
	}
	close(g.gate)
	if _, err := c.Get(context.Background(), "a"); err != nil {
		t.Fatalf("next Get: %v", err)
	}
	if got := g.calls.Load(); got != 2 {
		t.Errorf("lookups = %d, want 2: the failed lookup must not be cached", got)
	}
}

func TestKeyCacheErrorIsNotCached(t *testing.T) {
	g := newGatedFacts()
	close(g.gate)
	g.fail.Store(true)
	c := NewKeyCache(g.facts, KeyTTL, KeyMaxInFlight, nil)
	if _, err := c.Get(context.Background(), "a"); err == nil {
		t.Fatal("want an error")
	}
	g.fail.Store(false)
	if _, err := c.Get(context.Background(), "a"); err != nil {
		t.Fatalf("Get after recovery: %v", err)
	}
	if got := g.calls.Load(); got != 2 {
		t.Errorf("lookups = %d, want 2", got)
	}
}

func TestKeyCacheCallerCancelKeepsLookup(t *testing.T) {
	g := newGatedFacts()
	c := NewKeyCache(g.facts, KeyTTL, KeyMaxInFlight, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := c.Get(ctx, "a"); errc <- err }()
	waitFor(t, "the lookup to start", func() bool { return g.calls.Load() == 1 })
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Get error = %v", err)
	}
	close(g.gate)
	if _, err := c.Get(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if got := g.calls.Load(); got != 1 {
		t.Errorf("lookups = %d, want 1: the second caller joins the first lookup", got)
	}
}

func TestKeyCacheRefusesIncompleteFacts(t *testing.T) {
	c := NewKeyCache(func(context.Context, string) (Facts, error) { return Facts{Name: "a"}, nil }, KeyTTL, 1, nil)
	if _, err := c.Get(context.Background(), "a"); err == nil {
		t.Fatal("want an error for facts with no issuer and no keys")
	}
}

func TestKeyCacheConstructorPanics(t *testing.T) {
	for name, f := range map[string]func(){
		"no slots": func() { NewKeyCache(nil, KeyTTL, 0, nil) },
		"no ttl":   func() { NewKeyCache(nil, 0, 1, nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}
