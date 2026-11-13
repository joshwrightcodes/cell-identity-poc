package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

func TestExecuteRefuses(t *testing.T) {
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tests := []struct {
		name    string
		build   func(r *rig) []byte
		outcome string
		reason  string
		peeked  bool
	}{
		{"forged_key", func(r *rig) []byte {
			env, _ := op.Sign(r.operation(testKind, `{}`), otherPriv)
			return env
		}, op.OutcomeRefused, op.ReasonSignatureInvalid, true},
		{"tampered", func(r *rig) []byte {
			o := r.operation(testKind, `{}`)
			env := r.sign(o)
			// change one byte of the signed payload text: swap the first "cell-1" in the base64 is
			// not stable, so re-encode a payload that differs and keep the old signature
			other := r.operation(testKind, `{}`)
			other.ID = o.ID
			other.Kind = "demo.append"
			env2 := r.sign(other)
			return spliceSignature(env, env2)
		}, op.OutcomeRefused, op.ReasonSignatureInvalid, true},
		{"unsigned", func(r *rig) []byte {
			return stripSignatures(r.sign(r.operation(testKind, `{}`)))
		}, op.OutcomeRefused, op.ReasonSignatureInvalid, true},
		{"spec_envelope", func(r *rig) []byte {
			return []byte(`{"payloadType":"application/vnd.poc.spec+json","payload":"e30=","signatures":[]}`)
		}, op.OutcomeRefused, op.ReasonPayloadInvalid, false},
		{"other_cell", func(r *rig) []byte {
			o := r.operation(testKind, `{}`)
			o.Cell = "cell-2"
			return r.sign(o)
		}, op.OutcomeRefused, op.ReasonWrongTarget, false},
		{"other_env", func(r *rig) []byte {
			o := r.operation(testKind, `{}`)
			o.Env = "prod"
			return r.sign(o)
		}, op.OutcomeRefused, op.ReasonEnvMismatch, false},
		{"expired", func(r *rig) []byte {
			o := r.operation(testKind, `{}`)
			o.IssuedAt = r.clock.Now().Add(-time.Hour)
			o.ExpiresAt = r.clock.Now().Add(-time.Minute)
			return r.sign(o)
		}, op.OutcomeExpired, "", false},
		{"future_issued", func(r *rig) []byte {
			o := r.operation(testKind, `{}`)
			o.IssuedAt = r.clock.Now().Add(time.Hour)
			o.ExpiresAt = o.IssuedAt.Add(time.Hour)
			return r.sign(o)
		}, op.OutcomeRefused, op.ReasonPayloadInvalid, false},
		{"unknown_kind", func(r *rig) []byte {
			return r.sign(r.operation("demo.delete", `{}`))
		}, op.OutcomeRefused, op.ReasonKindUnknown, false},
		{"bad_demo_args", func(r *rig) []byte {
			return r.sign(r.operation(op.KindDemoAppend, `{"line":""}`))
		}, op.OutcomeRefused, op.ReasonPayloadInvalid, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			e := r.executor("uid-a")
			env := tc.build(r)
			res := e.Execute(context.Background(), env, op.Fence{Epoch: 1, Counter: 1})
			if res.Outcome != tc.outcome || res.Reason != tc.reason {
				t.Fatalf("result = %s/%s, want %s/%s", res.Outcome, res.Reason, tc.outcome, tc.reason)
			}
			if res.EnvelopeSHA256 != op.EnvelopeSHA256(env) {
				t.Errorf("EnvelopeSHA256 = %q", res.EnvelopeSHA256)
			}
			pre := tc.reason == op.ReasonSignatureInvalid || tc.name == "spec_envelope"
			if pre && res.OpID != "" {
				t.Errorf("OpID = %q before the signature passes", res.OpID)
			}
			if !pre && res.OpID == "" {
				t.Errorf("OpID is empty after the signature passes")
			}
			if tc.peeked && res.PeekedID == "" {
				t.Errorf("PeekedID is empty")
			}
			if !tc.peeked && res.PeekedID != "" {
				t.Errorf("PeekedID = %q", res.PeekedID)
			}
			if n := r.cnt.count(); n != 0 {
				t.Errorf("effect ran %d times", n)
			}
			if _, err := r.client.CoreV1().ConfigMaps(DefaultNamespace).Get(context.Background(), demoLogName, metav1.GetOptions{}); err == nil {
				t.Errorf("demo-log exists")
			}
			if got := len(r.records()); got != 0 {
				t.Errorf("%d op records exist", got)
			}
		})
	}
}

// TestExecuteClockBounds covers each side of the expiry and of the allowed future skew.
func TestExecuteClockBounds(t *testing.T) {
	tests := []struct {
		name    string
		issued  time.Duration // relative to the executor clock
		expires time.Duration
		outcome string
		reason  string
	}{
		{"expires_1ns_after_now", -time.Minute, time.Nanosecond, op.OutcomeApplied, ""},
		{"expires_at_now", -time.Minute, 0, op.OutcomeExpired, ""},
		{"expires_1ns_before_now", -time.Minute, -time.Nanosecond, op.OutcomeExpired, ""},
		{"issued_at_max_skew", op.MaxSkew, op.MaxSkew + time.Minute, op.OutcomeApplied, ""},
		{"issued_1ns_past_max_skew", op.MaxSkew + time.Nanosecond, op.MaxSkew + time.Minute, op.OutcomeRefused, op.ReasonPayloadInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			o := r.operation(testKind, `{}`)
			now := r.clock.Now()
			o.IssuedAt, o.ExpiresAt = now.Add(tc.issued), now.Add(tc.expires)
			res := r.executor("uid-a").Execute(context.Background(), r.sign(o), op.Fence{Epoch: 1, Counter: 1})
			if res.Outcome != tc.outcome || res.Reason != tc.reason {
				t.Fatalf("result = %s/%s, want %s/%s", res.Outcome, res.Reason, tc.outcome, tc.reason)
			}
			want := 0
			if tc.outcome == op.OutcomeApplied {
				want = 1
			}
			if n := r.cnt.count(); n != want {
				t.Errorf("effect ran %d times, want %d", n, want)
			}
		})
	}
}

func TestExecuteTwoKeys(t *testing.T) {
	r := newRig(t)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	e := r.executor("uid-a", func(c *Config) { c.Keys = []ed25519.PublicKey{r.pub, pub2} })
	for i, key := range []ed25519.PrivateKey{r.priv, priv2} {
		env, err := op.Sign(r.operation(testKind, `{}`), key)
		if err != nil {
			t.Fatal(err)
		}
		res := e.Execute(context.Background(), env, op.Fence{Epoch: 1, Counter: uint64(i + 1)})
		if res.Outcome != op.OutcomeApplied {
			t.Fatalf("key %d: %s/%s", i, res.Outcome, res.Reason)
		}
	}
	if n := r.cnt.count(); n != 2 {
		t.Fatalf("count = %d", n)
	}
}
