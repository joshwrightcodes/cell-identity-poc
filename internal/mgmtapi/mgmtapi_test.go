package mgmtapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

func TestBindAudience(t *testing.T) {
	if got := BindAudience("dev-cell-1", "n1"); got != "mgmt-bind/dev-cell-1/n1" {
		t.Fatalf("got %q", got)
	}
}

func TestPaths(t *testing.T) {
	for got, want := range map[string]string{
		SpecPath("dev"):         "/v1/envs/dev/spec",
		StatusPath("dev"):       "/v1/envs/dev/status",
		NoncePath("dev-cell-1"): "/v1/cells/dev-cell-1/nonce",
		BindPath("dev-cell-1"):  "/v1/cells/dev-cell-1/bind",
		KeysPath("dev-cell-1"):  "/v1/clusters/dev-cell-1/keys",
		KeysPath("a/../b c"):    "/v1/clusters/a%2F..%2Fb%20c/keys",
		NoncePath("x?y=1#frag"): "/v1/cells/x%3Fy=1%23frag/nonce",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestWireJSONNames(t *testing.T) {
	at := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		v    any
		keys []string
	}{
		{SpecBundle{Spec: json.RawMessage(`{}`), Records: map[string]json.RawMessage{"a": json.RawMessage(`{}`)}}, []string{"spec", "records"}},
		{NonceResponse{Nonce: "n", Audience: "a", ExpiresAt: at, Bound: true}, []string{"nonce", "audience", "expiresAt", "bound"}},
		{BindRequest{Nonce: "n", Token: "t"}, []string{"nonce", "token"}},
		{BindResponse{Status: StatusBound, Record: spec.Revision{Epoch: 1, Counter: 2}}, []string{"status", "record"}},
		{StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}, LastRefusal: &Refusal{Reason: ReasonRevisionOld, At: at}, StoreError: "x"},
			[]string{"applied", "lastRefusal", "storeError"}},
		{Refusal{Reason: "r", Revision: spec.Revision{Epoch: 1, Counter: 1}, At: at}, []string{"reason", "revision", "at"}},
		{Denied{Error: "denied", RequestID: "0123456789abcdef"}, []string{"error", "request_id"}},
		{ClusterKeys{Name: "n", Issuer: "i", JWKS: json.RawMessage(`{}`)}, []string{"name", "issuer", "jwks"}},
	} {
		raw, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if len(m) != len(tc.keys) {
			t.Errorf("%T encodes %s, want keys %v", tc.v, raw, tc.keys)
		}
		for _, k := range tc.keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%T lacks key %q in %s", tc.v, k, raw)
			}
		}
	}
}

func TestStatusReportOmitsEmptyFields(t *testing.T) {
	raw, _ := json.Marshal(StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}})
	if strings.Contains(string(raw), "lastRefusal") || strings.Contains(string(raw), "storeError") {
		t.Fatalf("got %s", raw)
	}
}

func TestReasonStringsAreDistinct(t *testing.T) {
	all := []string{
		ReasonSignatureInvalid, ReasonPayloadInvalid, ReasonEnvMismatch, ReasonRevisionOld, ReasonRevisionConflict,
		ReasonRecordInvalid, ReasonRecordUnindexed, ReasonRecordOld, ReasonRecordConflict, ReasonTooManyInvalidated,
		ReasonStoreFailed, ReasonStateUnverifiable, ReasonSpecInvalid,
		ReasonCellUnknown, ReasonNonceInvalid, ReasonTokenInvalid, ReasonIssuerUntrusted, ReasonIssuerUnavailable,
		ReasonKeysUntrusted, ReasonRateLimited, ReasonRestoreActive, ReasonNotBound, ReasonConflict,
	}
	want := []string{
		"signature_invalid", "payload_invalid", "env_mismatch", "revision_old", "revision_conflict",
		"record_invalid", "record_unindexed", "record_old", "record_conflict", "too_many_invalidated",
		"store_failed", "state_unverifiable", "spec_invalid",
		"cell_unknown", "nonce_invalid", "token_invalid", "issuer_untrusted", "issuer_unavailable",
		"keys_untrusted", "rate_limited", "restore_active", "not_bound", "conflict",
	}
	seen := map[string]bool{}
	for i, r := range all {
		if r != want[i] {
			t.Errorf("constant %d = %q, want %q", i, r, want[i])
		}
		if seen[r] {
			t.Errorf("duplicate %q", r)
		}
		seen[r] = true
	}
}

func TestKeyErrorAs(t *testing.T) {
	inner := errors.New("dial failed")
	var err error = &KeyError{Reason: ReasonIssuerUnavailable, Err: inner}
	wrapped := fmt.Errorf("read keys: %w", err)
	var ke *KeyError
	if !errors.As(wrapped, &ke) || ke.Reason != ReasonIssuerUnavailable {
		t.Fatalf("errors.As failed: %v", wrapped)
	}
	if !errors.Is(wrapped, inner) {
		t.Fatal("Unwrap must reach the cause")
	}
	if !strings.Contains(ke.Error(), ReasonIssuerUnavailable) {
		t.Fatalf("Error() = %q", ke.Error())
	}
	if (&KeyError{Reason: ReasonIssuerUntrusted}).Error() == "" {
		t.Fatal("Error() must not be empty without a cause")
	}
}
