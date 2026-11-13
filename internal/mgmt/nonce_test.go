package mgmt

import (
	"encoding/base64"
	"testing"
	"time"
)

func nonceReason(err error) (string, string) {
	r := ReasonOf(err)
	var d string
	if e, ok := err.(*Error); ok {
		d = e.Detail
	}
	return r, d
}

func TestNonces(t *testing.T) {
	clk := &fakeClock{now: time.Now()}
	n, err := NewNonces(clk.Now, 120*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	nonce, exp := n.Issue("dev-cell-1")
	if want := clk.Now().Add(120 * time.Second); !exp.Equal(want.Truncate(time.Second)) && !exp.Equal(want) {
		t.Fatalf("expiry %v, want about %v", exp, want)
	}
	if err := n.Check("dev-cell-1", nonce); err != nil {
		t.Fatalf("fresh nonce: %v", err)
	}

	if r, d := nonceReason(n.Check("dev-cell-2", nonce)); r != "nonce_invalid" || d != "bad_mac" {
		t.Fatalf("other cell: %s/%s", r, d)
	}

	raw, _ := base64.RawURLEncoding.DecodeString(nonce)
	raw[3] ^= 1
	if r, d := nonceReason(n.Check("dev-cell-1", base64.RawURLEncoding.EncodeToString(raw))); r != "nonce_invalid" || d != "bad_mac" {
		t.Fatalf("changed byte: %s/%s", r, d)
	}
	for _, bad := range []string{"", "AAAA", "!!!!"} {
		if r, d := nonceReason(n.Check("dev-cell-1", bad)); r != "nonce_invalid" || d != "malformed" {
			t.Fatalf("malformed %q: %s/%s", bad, r, d)
		}
	}

	if err := n.Consume("dev-cell-1", nonce); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if r, d := nonceReason(n.Consume("dev-cell-1", nonce)); r != "nonce_invalid" || d != "consumed" {
		t.Fatalf("second consume: %s/%s", r, d)
	}

	other, _ := n.Issue("dev-cell-1")
	clk.Advance(121 * time.Second)
	if r, d := nonceReason(n.Check("dev-cell-1", other)); r != "nonce_invalid" || d != "expired" {
		t.Fatalf("after 121 s: %s/%s", r, d)
	}
	if r, _ := nonceReason(n.Consume("dev-cell-1", other)); r != "nonce_invalid" {
		t.Fatal("an expired nonce is consumed")
	}
}

func TestNoncesStatelessIssue(t *testing.T) {
	clk := &fakeClock{now: time.Now()}
	n, _ := NewNonces(clk.Now, 120*time.Second)
	for range 5000 {
		n.Issue("dev-cell-1")
	}
	if got := n.consumedLen(); got != 0 {
		t.Fatalf("issuing keeps %d entries", got)
	}
}

func TestNoncesDropConsumedAfterExpiry(t *testing.T) {
	clk := &fakeClock{now: time.Now()}
	n, _ := NewNonces(clk.Now, 120*time.Second)
	for range 10 {
		nonce, _ := n.Issue("dev-cell-1")
		if err := n.Consume("dev-cell-1", nonce); err != nil {
			t.Fatal(err)
		}
	}
	if n.consumedLen() != 10 {
		t.Fatalf("consumed set holds %d, want 10", n.consumedLen())
	}
	clk.Advance(121 * time.Second)
	nonce, _ := n.Issue("dev-cell-1")
	if err := n.Consume("dev-cell-1", nonce); err != nil {
		t.Fatal(err)
	}
	if n.consumedLen() != 1 {
		t.Fatalf("consumed set holds %d after expiry, want 1", n.consumedLen())
	}
}

func TestNonceKeyRotation(t *testing.T) {
	clk := &fakeClock{now: time.Now()}
	n, _ := NewNonces(clk.Now, 120*time.Second)
	n = n.WithKeyEvery(60 * time.Second)

	clk.Advance(59 * time.Second)
	nonce, _ := n.Issue("dev-cell-1")
	clk.Advance(2 * time.Second)
	if err := n.Check("dev-cell-1", nonce); err != nil {
		t.Fatalf("a nonce issued just before the key change: %v", err)
	}
	if n.keyEpoch() < 1 {
		t.Fatal("the key did not change")
	}

	clk.Advance(120 * time.Second)
	if r, _ := nonceReason(n.Check("dev-cell-1", nonce)); r != "nonce_invalid" {
		t.Fatal("the nonce passes one more NonceTTL after the key change")
	}

	fast, _ := NewNonces(clk.Now, 120*time.Second)
	fast = fast.WithKeyEvery(30 * time.Second)
	old, _ := fast.Issue("dev-cell-1")
	clk.Advance(31 * time.Second)
	if err := fast.Check("dev-cell-1", old); err != nil {
		t.Fatalf("after one key change: %v", err)
	}
	clk.Advance(31 * time.Second)
	if r, d := nonceReason(fast.Check("dev-cell-1", old)); r != "nonce_invalid" || d != "bad_mac" {
		t.Fatalf("after two key changes: %s/%s", r, d)
	}
}
