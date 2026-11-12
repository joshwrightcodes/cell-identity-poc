package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// Settings of the key cache of the host service.
const (
	KeyTTL           = 60 * time.Second
	KeyLookupTimeout = 10 * time.Second
	KeyMaxInFlight   = 2
)

// KeyCache keeps the keys of each cluster for a short time. One lookup runs for a cluster at a
// time, and a caller that arrives meanwhile waits for it. At most a fixed number of lookups run at
// once, and each lookup has a deadline. A failed lookup is not kept.
type KeyCache struct {
	facts         func(ctx context.Context, cluster string) (Facts, error)
	ttl           time.Duration
	now           func() time.Time
	lookupTimeout time.Duration
	slots         chan struct{}

	mu      sync.Mutex
	entries map[string]cachedKeys
	flights map[string]*flight
}

type cachedKeys struct {
	keys mgmtapi.ClusterKeys
	at   time.Time
}

type flight struct {
	done chan struct{}
	keys mgmtapi.ClusterKeys
	err  error
}

// NewKeyCache returns a cache over facts. It panics when maxInFlight is below 1 or ttl is not
// positive, because each is a fixed setting of the caller. A nil now means time.Now.
func NewKeyCache(facts func(ctx context.Context, cluster string) (Facts, error), ttl time.Duration, maxInFlight int, now func() time.Time) *KeyCache {
	if maxInFlight < 1 || ttl <= 0 {
		panic("hostsvc: key cache needs a positive ttl and at least one lookup slot")
	}
	if now == nil {
		now = time.Now
	}
	return &KeyCache{
		facts: facts, ttl: ttl, now: now, lookupTimeout: KeyLookupTimeout,
		slots:   make(chan struct{}, maxInFlight),
		entries: map[string]cachedKeys{}, flights: map[string]*flight{},
	}
}

// Get returns the keys of cluster. A cancelled ctx ends the wait of this caller only, and the
// lookup goes on for the other callers.
func (c *KeyCache) Get(ctx context.Context, cluster string) (mgmtapi.ClusterKeys, error) {
	c.mu.Lock()
	if e, ok := c.entries[cluster]; ok && c.now().Sub(e.at) < c.ttl {
		c.mu.Unlock()
		return e.keys, nil
	}
	f, joined := c.flights[cluster]
	if !joined {
		f = &flight{done: make(chan struct{})}
		c.flights[cluster] = f
		go c.lookup(cluster, f)
	}
	c.mu.Unlock()
	select {
	case <-f.done:
		return f.keys, f.err
	case <-ctx.Done():
		return mgmtapi.ClusterKeys{}, ctx.Err()
	}
}

// lookup runs one lookup under the slot limit and the deadline, then publishes the result.
func (c *KeyCache) lookup(cluster string, f *flight) {
	keys, err := c.fetch(cluster)
	c.mu.Lock()
	if err == nil {
		c.entries[cluster] = cachedKeys{keys: keys, at: c.now()}
	}
	if c.flights[cluster] == f {
		delete(c.flights, cluster)
	}
	f.keys, f.err = keys, err
	c.mu.Unlock()
	close(f.done)
}

func (c *KeyCache) fetch(cluster string) (keys mgmtapi.ClusterKeys, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("lookup of %s panicked: %v", cluster, r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), c.lookupTimeout)
	defer cancel()
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return mgmtapi.ClusterKeys{}, fmt.Errorf("wait for a lookup slot: %w", ctx.Err())
	}
	f, err := c.facts(ctx, cluster)
	if err != nil {
		return mgmtapi.ClusterKeys{}, err
	}
	if f.Issuer == "" || len(f.JWKS) == 0 {
		return mgmtapi.ClusterKeys{}, errors.New("facts of the cluster have no issuer or no keys")
	}
	return mgmtapi.ClusterKeys{Name: cluster, Issuer: f.Issuer, JWKS: f.JWKS}, nil
}
