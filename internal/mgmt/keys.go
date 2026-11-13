package mgmt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// maxNewKeys is the most keys that one update may add to a cell.
const maxNewKeys = 2

// maxKeys is the most keys that a record holds. A cluster normally publishes one or two.
const maxKeys = 8

type keyInfo struct {
	id  string
	kid string
	key jose.JSONWebKey
}

// parseKeys returns the usable public keys of a key set, in order of identity. A key is usable when
// it has a key ID and the validator accepts its algorithm. Keys compare by kid and thumbprint.
func parseKeys(jwks json.RawMessage) []keyInfo {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []keyInfo
	for _, raw := range set.Keys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(raw); err != nil || !k.Valid() || !k.IsPublic() || k.KeyID == "" {
			continue
		}
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			if pub.N.BitLen() < 2048 {
				continue
			}
		case *ecdsa.PublicKey:
			if pub.Curve != elliptic.P256() {
				continue
			}
		default:
			continue
		}
		thumb, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			continue
		}
		id := k.KeyID + ":" + base64.RawURLEncoding.EncodeToString(thumb)
		if !seen[id] {
			seen[id] = true
			out = append(out, keyInfo{id: id, kid: k.KeyID, key: k})
		}
	}
	slices.SortFunc(out, func(a, b keyInfo) int { return strings.Compare(a.id, b.id) })
	return out
}

func encodeKeys(ks []keyInfo) (json.RawMessage, error) {
	set := jose.JSONWebKeySet{}
	for _, k := range ks {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.key.Key, KeyID: k.key.KeyID, Algorithm: k.key.Algorithm, Use: k.key.Use})
	}
	return json.Marshal(set)
}

func kidsOf(jwks json.RawMessage) []string {
	ks := parseKeys(jwks)
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, k.kid)
	}
	return out
}

type keyDiff struct{ added, removed, common int }

func diffKeys(old, fresh []keyInfo) keyDiff {
	have := map[string]bool{}
	for _, k := range old {
		have[k.id] = true
	}
	var d keyDiff
	now := map[string]bool{}
	for _, k := range fresh {
		now[k.id] = true
		if have[k.id] {
			d.common++
		} else {
			d.added++
		}
	}
	for _, k := range old {
		if !now[k.id] {
			d.removed++
		}
	}
	return d
}

type keyCache struct {
	mu sync.Mutex
	m  map[string]*cacheEntry
}

type cacheEntry struct {
	sem  chan struct{}
	keys mgmtapi.ClusterKeys
	at   time.Time
	ok   bool
}

func (c *keyCache) entry(cell string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[cell]
	if e == nil {
		e = &cacheEntry{sem: make(chan struct{}, 1)}
		c.m[cell] = e
	}
	return e
}

type fetchMode int

// refetchGap is the shortest time between two fetches that a token with an unknown key ID forces.
const refetchGap = 10 * time.Second

// cachedKeys returns the keys of a cell, the time of the fetch and whether they came from the cache.
// One fetch per cell is in flight at a time, and no lock of the plane is held.
func (p *Plane) cachedKeys(ctx context.Context, cell string, mode fetchMode) (keys mgmtapi.ClusterKeys, at time.Time, cached bool, err error) {
	e := p.cache.entry(cell)
	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		return keys, at, false, refuse(mgmtapi.ReasonIssuerUnavailable, "key_source")
	}
	defer func() { <-e.sem }()
	now := p.cfg.Now()
	age := now.Sub(e.at)
	fresh := e.ok && age >= 0 && age < p.cfg.KeyCacheTTL
	switch mode {
	case fetchRefetch:
		fresh = fresh && age < refetchGap
	case fetchFresh:
		fresh = false
	}
	if fresh {
		return e.keys, e.at, true, nil
	}
	keys, err = p.cfg.Keys.Keys(ctx, cell)
	if err != nil {
		return keys, at, false, keySourceError(err)
	}
	e.keys, e.at, e.ok = keys, now, true
	return keys, now, false, nil
}

// gapActive reports whether a key update for cs would fall inside KeyUpdateGap of the last key
// update. A key check that changes nothing does not start the gap.
func (p *Plane) gapActive(cs *CellState, now time.Time) bool {
	return !cs.KeysUpdatedAt.IsZero() && now.Sub(cs.KeysUpdatedAt) < p.cfg.KeyUpdateGap
}

func (p *Plane) cellRecord(cell string, issuer string, jwks json.RawMessage) record.Cell {
	return record.Cell{
		Name: cell, Env: p.cfg.Intent.Env, Issuer: issuer, JWKS: jwks,
		Subjects: []record.Subject{p.cfg.Intent.BindSubject},
	}
}

const (
	// fetchCached serves a fetch within KeyCacheTTL of the last one from the cache.
	fetchCached fetchMode = iota
	// fetchRefetch also bypasses the cache when the last fetch is older than refetchGap.
	fetchRefetch
	// fetchFresh always asks the key source.
	fetchFresh
)
