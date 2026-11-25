package mgmtapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

func TestBindAudience(t *testing.T) {
	if got := BindAudience("dev-cell-1", "n1"); got != "mgmt-bind/dev-cell-1/n1" {
		t.Fatalf("got %q", got)
	}
}

func TestPaths(t *testing.T) {
	for got, want := range map[string]string{
		SpecPath("dev"):        "/v1/envs/dev/spec",
		StatusPath("dev"):      "/v1/envs/dev/status",
		KeysPath("dev-cell-1"): "/v1/clusters/dev-cell-1/keys",
		KeysPath("a/../b c"):   "/v1/clusters/a%2F..%2Fb%20c/keys",
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
		ReasonProofMissing, ReasonProofInvalid, ReasonStale, ReasonStore, ReasonInternal,
		ReasonStepInvalid, ReasonStepUnindexed,
		ReasonAlreadyRequested, ReasonNotRequested, ReasonBootstrapInvalid, ReasonStepOpen, ReasonNoStep,
		ReasonTooManyCells, ReasonTestDigestOnly,
		ReasonHostsvcUntrusted, ReasonHostsvcUnavailable, ReasonHostsvcDenied, ReasonHostsvcBusy,
		ReasonRecordNotApplied, ReasonNoStatus, ReasonStatusStale, ReasonStatusInFuture, ReasonKeysFailed,
	}
	want := []string{
		"signature_invalid", "payload_invalid", "env_mismatch", "revision_old", "revision_conflict",
		"record_invalid", "record_unindexed", "record_old", "record_conflict", "too_many_invalidated",
		"store_failed", "state_unverifiable", "spec_invalid",
		"cell_unknown", "nonce_invalid", "token_invalid", "issuer_untrusted", "issuer_unavailable",
		"keys_untrusted", "rate_limited", "restore_active", "not_bound", "conflict",
		"proof_missing", "proof_invalid", "stale", "store", "internal",
		"step_invalid", "step_unindexed",
		"already_requested", "not_requested", "bootstrap_invalid", "step_open", "no_step",
		"too_many_cells", "test_digest_only",
		"hostsvc_untrusted", "hostsvc_unavailable", "hostsvc_denied", "hostsvc_busy",
		"record_not_applied", "no_status", "status_stale", "status_in_future", "keys_failed",
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

func TestPatternsMatchPathHelpers(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		path    func(string) string
	}{
		{SpecPattern, SpecPath}, {StatusPattern, StatusPath},
		{KeysPattern, KeysPath}, {OpsPattern, OpsPath}, {ReportsPattern, ReportsPath}, {StepPattern, StepPath},
	} {
		for _, value := range []string{"dev-cell-1", "a b", "x/y", "q?z"} {
			var got string
			mux := http.NewServeMux()
			mux.HandleFunc(tc.pattern, func(w http.ResponseWriter, r *http.Request) {
				for _, name := range []string{"env", "cell", "cluster", "id"} {
					if v := r.PathValue(name); v != "" {
						got = v
					}
				}
			})
			req := httptest.NewRequest(http.MethodGet, tc.path(value), nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if got != value {
				t.Errorf("%s with %q: PathValue %q (status %d)", tc.pattern, value, got, rec.Code)
			}
		}
	}
}

func TestDeniedError(t *testing.T) {
	raw, _ := json.Marshal(Denied{Error: DeniedError, RequestID: "0123456789abcdef"})
	if string(raw) != `{"error":"denied","request_id":"0123456789abcdef"}` {
		t.Fatalf("got %s", raw)
	}
}

func TestOpsWireNames(t *testing.T) {
	at := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		v    any
		keys []string
	}{
		{CellInfo{Name: "c", Nonce: "n", NonceExpiresAt: at, Bound: true}, []string{"name", "nonce", "nonceExpiresAt", "bound"}},
		{OpsBundle{Ops: []json.RawMessage{json.RawMessage(`{}`)}, Cells: []CellInfo{{Name: "c"}}}, []string{"ops", "cells"}},
		{ReportItem{ID: "i", Cell: "c", Kind: "result", OpID: "o", Body: json.RawMessage(`{}`), Token: "t"}, []string{"id", "cell", "kind", "opId", "body", "token"}},
		{ReportBatch{Items: []ReportItem{{ID: "i"}}}, []string{"items"}},
		{ItemOutcome{ID: "i", OpID: "o", Outcome: OutcomeAccepted, Reason: "r", Detail: "d", RequestID: "q", Bind: &BindResponse{Status: StatusBound}},
			[]string{"id", "opId", "outcome", "reason", "detail", "requestId", "bind"}},
		{ReportResult{Outcomes: []ItemOutcome{{ID: "i"}}}, []string{"outcomes"}},
		{KeyHint{Cell: "c", At: at}, []string{"cell", "at"}},
		{ClaimInfo{OpID: "o", Count: 2}, []string{"opId", "count"}},
		{BindRefusal{Reason: "r", RequestID: "q", At: at}, []string{"reason", "requestId", "at"}},
		{GatewayStatus{
			Epoch: 1, SyncedAt: at, OldestOutboxAt: at, EpochChangedAt: at, DroppedAt: at, RecordOldAt: at,
			OutboxItems: 1, Dropped: 1, RecordOld: 1, Queued: map[string]int{"c": 1}, Streams: map[string]int{"c": 1},
			MostClaimed: map[string]ClaimInfo{"c": {}}, Records: map[string]spec.Revision{"c": {}},
			LastBindRefusal: map[string]BindRefusal{"c": {}}, KeyHints: []KeyHint{{Cell: "c"}}, StoreError: "x",
		}, []string{
			"epoch", "syncedAt", "oldestOutboxAt", "epochChangedAt", "droppedAt", "recordOldAt", "outboxItems",
			"dropped", "recordOld", "queued", "streams", "mostClaimed", "records", "lastBindRefusal", "keyHints", "storeError",
		}},
		{StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}, KeyHints: []KeyHint{{Cell: "c", At: at}}, Gateway: &GatewayStatus{Epoch: 1}},
			[]string{"applied", "keyHints", "gateway"}},
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

func TestStatusReportOmitsGatewayFieldsWhenEmpty(t *testing.T) {
	raw, _ := json.Marshal(StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}})
	if strings.Contains(string(raw), "keyHints") || strings.Contains(string(raw), "gateway") {
		t.Fatalf("got %s", raw)
	}
}

func TestOpsPaths(t *testing.T) {
	if got := OpsPath("dev"); got != "/v1/envs/dev/ops" {
		t.Errorf("OpsPath %q", got)
	}
	if got := ReportsPath("a b"); got != "/v1/envs/a%20b/reports" {
		t.Errorf("ReportsPath %q", got)
	}
}

func TestItemOutcomeStrings(t *testing.T) {
	outcomes := map[string]string{
		OutcomeAccepted: "accepted", OutcomeDuplicate: "duplicate", OutcomeUnknownOp: "unknown_op",
		OutcomeForgedSeen: "forged_seen", OutcomeRefused: "refused", OutcomeRetry: "retry",
	}
	for got, want := range outcomes {
		if got != want {
			t.Errorf("outcome %q, want %q", got, want)
		}
	}
	if len(outcomes) != 6 {
		t.Errorf("two outcome constants share a string: %v", outcomes)
	}
}

func TestOpsBundleNoPlaneKey(t *testing.T) {
	raw, _ := json.Marshal(OpsBundle{Ops: []json.RawMessage{json.RawMessage(`{}`)}})
	if strings.Contains(string(raw), "planeBundle") {
		t.Fatalf("got %s", raw)
	}
	raw, _ = json.Marshal(OpsBundle{PlaneBundle: json.RawMessage(`{"payloadType":"x"}`)})
	if !strings.Contains(string(raw), `"planeBundle":{"payloadType":"x"}`) {
		t.Fatalf("got %s", raw)
	}
}

func TestStatusReportNoPlaneKeys(t *testing.T) {
	raw, _ := json.Marshal(StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}})
	if strings.Contains(string(raw), "planeBundle") {
		t.Fatalf("got %s", raw)
	}
	raw, _ = json.Marshal(StatusReport{
		PlaneBundle:       &op.Result{Cell: "dev-cp", Outcome: op.OutcomeApplied},
		PlaneBundleStatus: &op.BundleStatus{State: "healthy"},
	})
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["planeBundle"]; !ok {
		t.Errorf("no planeBundle in %s", raw)
	}
	if _, ok := m["planeBundleStatus"]; !ok {
		t.Errorf("no planeBundleStatus in %s", raw)
	}
}

func TestBundleWireNames(t *testing.T) {
	at := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		v    any
		keys []string
	}{
		{BundleSignResult{}, []string{"opId", "version", "contentSHA256", "rootDigest", "envelope", "sigstoreBundle"}},
		{TargetBundle{IssuedAt: at, ExpiresAt: at}, []string{"opId", "version", "contentSHA256", "rootDigest", "components", "issuedAt", "expiresAt", "served"}},
		{TargetBundle{IssuedAt: at, Result: &op.Result{}}, []string{"opId", "version", "contentSHA256", "rootDigest", "components", "issuedAt", "expiresAt", "served", "result"}},
	} {
		raw, _ := json.Marshal(tc.v)
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if len(m) != len(tc.keys) {
			t.Errorf("%T encodes %s", tc.v, raw)
		}
		for _, k := range tc.keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%T lacks %q in %s", tc.v, k, raw)
			}
		}
	}
	res, err := json.Marshal(BundleSignResult{Envelope: json.RawMessage(`{"payloadType":"x"}`), SigstoreBundle: json.RawMessage(`{"mediaType":"y"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var obj struct {
		Envelope       map[string]string `json:"envelope"`
		SigstoreBundle map[string]string `json:"sigstoreBundle"`
	}
	if err := json.Unmarshal(res, &obj); err != nil || obj.Envelope["payloadType"] != "x" || obj.SigstoreBundle["mediaType"] != "y" {
		t.Errorf("envelope and sigstoreBundle must encode as JSON objects: %s, %v", res, err)
	}
	if ReasonBundleOpen != "bundle_open" {
		t.Errorf("ReasonBundleOpen is %q", ReasonBundleOpen)
	}
}

func TestStatusReportNoRevocationKey(t *testing.T) {
	raw, _ := json.Marshal(StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}})
	if string(raw) != `{"applied":{"epoch":1,"counter":1}}` {
		t.Fatalf("got %s", raw)
	}
	raw, _ = json.Marshal(StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}, LocalRevocations: []json.RawMessage{}})
	if strings.Contains(string(raw), "localRevocations") {
		t.Fatalf("an empty list encodes: %s", raw)
	}
	raw, _ = json.Marshal(StatusReport{LocalRevocations: []json.RawMessage{json.RawMessage(`{"payloadType":"x"}`)}})
	if !strings.Contains(string(raw), `"localRevocations":[{"payloadType":"x"}]`) {
		t.Fatalf("got %s", raw)
	}
}

func TestRevocationWireNames(t *testing.T) {
	at := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		v    any
		keys []string
	}{
		{RevocationEvent{Cell: "c", Revision: spec.Revision{Epoch: 1, Counter: 2}, Kind: RevocationRevoke, Source: RevocationSourceAdmin, At: at},
			[]string{"cell", "revision", "kind", "source", "at"}},
		{RevocationEvent{Cell: "c", Revision: spec.Revision{Epoch: 1, Counter: 2}, Kind: RevocationRevoke, Source: RevocationSourceOperator,
			EntryID: "0123456789abcdef", OperatorKeySHA256: strings.Repeat("a", 64), At: at},
			[]string{"cell", "revision", "kind", "source", "entryId", "operatorKeySHA256", "at"}},
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
	if RevocationRevoke != "revoke" || RevocationUnrevoke != "unrevoke" || RevocationSourceAdmin != "admin" || RevocationSourceOperator != "operator" {
		t.Error("revocation kinds or sources")
	}
}

func TestRevocationReasons(t *testing.T) {
	got := []string{
		ReasonRevocationInvalid, ReasonRevocationStale, ReasonRevocationUnknownCell, ReasonRevocationOverflow,
		ReasonNotConnected, ReasonNotRevoked, ReasonOverlayHeld, ReasonRestorePastRevocation,
	}
	want := []string{
		"revocation_invalid", "revocation_stale", "revocation_unknown_cell", "revocation_overflow",
		"not_connected", "not_revoked", "overlay_held", "restore_past_revocation",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("constant %d = %q, want %q", i, got[i], want[i])
		}
	}
	// Every other Reason constant of the package, from the source, must differ from the new ones.
	fset := token.NewFileSet()
	dir, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, de := range dir {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".go") || strings.HasSuffix(de.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, de.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	seen := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if !strings.HasPrefix(name.Name, "Reason") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok {
						continue
					}
					v, _ := strconv.Unquote(lit.Value)
					if prev, dup := seen[v]; dup {
						t.Errorf("%s and %s share %q", prev, name.Name, v)
					}
					seen[v] = name.Name
				}
			}
		}
	}
	if len(seen) < 50 {
		t.Fatalf("found only %d reason constants", len(seen))
	}
	for _, r := range want[:4] {
		if name, dup := seen[r]; dup {
			t.Errorf("%s shares %q with a revocation reason", name, r)
		}
	}
}

func TestEntryUnrevoked(t *testing.T) {
	rev := func(c uint64) spec.Revision { return spec.Revision{Epoch: 2, Counter: c} }
	adopted := RevocationEvent{Cell: "dev-cell-2", Revision: rev(5), Kind: RevocationRevoke, Source: RevocationSourceOperator, EntryID: "000000000000000a"}
	undo := RevocationEvent{Cell: "dev-cell-2", Revision: rev(6), Kind: RevocationUnrevoke, Source: RevocationSourceAdmin}
	for _, tc := range []struct {
		name   string
		events []RevocationEvent
		cell   string
		id     string
		want   bool
	}{
		{"revoked_then_unrevoked", []RevocationEvent{adopted, undo}, "dev-cell-2", "000000000000000a", true},
		{"unrevoke_listed_first", []RevocationEvent{undo, adopted}, "dev-cell-2", "000000000000000a", true},
		{"revoked_only", []RevocationEvent{adopted}, "dev-cell-2", "000000000000000a", false},
		{"unrevoke_before_revoke", []RevocationEvent{adopted, {Cell: "dev-cell-2", Revision: rev(4), Kind: RevocationUnrevoke}}, "dev-cell-2", "000000000000000a", false},
		{"unrevoke_at_same_revision", []RevocationEvent{adopted, {Cell: "dev-cell-2", Revision: rev(5), Kind: RevocationUnrevoke}}, "dev-cell-2", "000000000000000a", false},
		{"unrevoke_other_cell", []RevocationEvent{adopted, {Cell: "dev-cell-1", Revision: rev(6), Kind: RevocationUnrevoke}}, "dev-cell-2", "000000000000000a", false},
		{"other_id", []RevocationEvent{adopted, undo}, "dev-cell-2", "000000000000000b", false},
		{"id_of_other_cell", []RevocationEvent{adopted, undo}, "dev-cell-1", "000000000000000a", false},
		{"admin_revoke_has_no_id", []RevocationEvent{{Cell: "dev-cell-2", Revision: rev(5), Kind: RevocationRevoke, Source: RevocationSourceAdmin}, undo}, "dev-cell-2", "", false},
		{"unrevoke_with_the_id", []RevocationEvent{{Cell: "dev-cell-2", Revision: rev(6), Kind: RevocationUnrevoke, EntryID: "000000000000000a"}}, "dev-cell-2", "000000000000000a", false},
		{"no_events", nil, "dev-cell-2", "000000000000000a", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EntryUnrevoked(tc.events, tc.cell, tc.id); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
