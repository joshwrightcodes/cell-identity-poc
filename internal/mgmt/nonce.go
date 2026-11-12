package mgmt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

const (
	nonceRandLen = 16
	nonceBodyLen = nonceRandLen + 8
	nonceLen     = nonceBodyLen + sha256.Size
)

// Nonces makes and checks bind nonces. A nonce is the random bytes, the expiry and an HMAC over the
// cell, so issuing keeps no state. Only a consumed nonce is kept, until its expiry.
type Nonces struct {
	now func() time.Time
	ttl time.Duration

	mu        sync.Mutex
	key, prev []byte
	keyAt     time.Time
	prevUntil time.Time
	every     time.Duration
	epoch     int
	consumed  map[string]int64
}

// NewNonces makes a nonce set with a key from crypto/rand.
func NewNonces(now func() time.Time, ttl time.Duration) (*Nonces, error) {
	if now == nil || ttl <= 0 {
		return nil, errors.New("nonces need a clock and a positive lifetime")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &Nonces{now: now, ttl: ttl, key: key, keyAt: now(), consumed: map[string]int64{}}, nil
}

// WithKeyEvery makes the set replace its key every d. The previous key stays valid for one
// lifetime. A zero d never replaces the key.
func (n *Nonces) WithKeyEvery(d time.Duration) *Nonces {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.every = d
	return n
}

func (n *Nonces) rotateLocked(now time.Time) {
	if n.every <= 0 || now.Before(n.keyAt.Add(n.every)) {
		return
	}
	next := make([]byte, 32)
	if _, err := rand.Read(next); err != nil {
		return
	}
	n.prev, n.prevUntil = n.key, now.Add(n.ttl)
	n.key, n.keyAt = next, now
	n.epoch++
}

func mac(key []byte, cell string, body []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(cell))
	h.Write(body)
	return h.Sum(nil)
}

// Issue returns a new nonce for cell and its expiry.
func (n *Nonces) Issue(cell string) (string, time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	n.rotateLocked(now)
	exp := now.Add(n.ttl).Unix()
	raw := make([]byte, nonceLen)
	_, _ = rand.Read(raw[:nonceRandLen])
	binary.BigEndian.PutUint64(raw[nonceRandLen:nonceBodyLen], uint64(exp))
	copy(raw[nonceBodyLen:], mac(n.key, cell, raw[:nonceBodyLen]))
	return base64.RawURLEncoding.EncodeToString(raw), time.Unix(exp, 0)
}

// Check verifies the HMAC and the expiry of nonce for cell. It keeps no state.
func (n *Nonces) Check(cell, nonce string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, err := n.checkLocked(cell, nonce)
	return err
}

func (n *Nonces) checkLocked(cell, nonce string) (int64, error) {
	now := n.now()
	n.rotateLocked(now)
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != nonceLen {
		return 0, refuse(mgmtapi.ReasonNonceInvalid, "malformed")
	}
	body, got := raw[:nonceBodyLen], raw[nonceBodyLen:]
	ok := hmac.Equal(got, mac(n.key, cell, body))
	if !ok && n.prev != nil && now.Before(n.prevUntil) {
		ok = hmac.Equal(got, mac(n.prev, cell, body))
	}
	if !ok {
		return 0, refuse(mgmtapi.ReasonNonceInvalid, "bad_mac")
	}
	exp := int64(binary.BigEndian.Uint64(body[nonceRandLen:]))
	if now.Unix() > exp {
		return 0, refuse(mgmtapi.ReasonNonceInvalid, "expired")
	}
	return exp, nil
}

// Consume checks nonce and marks it as used. It fails with nonce_invalid when the nonce was
// consumed before. The set drops entries after their expiry.
func (n *Nonces) Consume(cell, nonce string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	exp, err := n.checkLocked(cell, nonce)
	if err != nil {
		return err
	}
	if _, used := n.consumed[nonce]; used {
		return refuse(mgmtapi.ReasonNonceInvalid, "consumed")
	}
	now := n.now().Unix()
	for k, e := range n.consumed {
		if now > e {
			delete(n.consumed, k)
		}
	}
	n.consumed[nonce] = exp
	return nil
}

// Used reports whether nonce was consumed and has not expired.
func (n *Nonces) Used(nonce string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, used := n.consumed[nonce]
	return used
}

func (n *Nonces) consumedLen() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.consumed)
}

func (n *Nonces) keyEpoch() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.epoch
}
