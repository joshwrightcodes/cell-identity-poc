package gwapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
)

func TestFrameRoundTrip(t *testing.T) {
	body := json.RawMessage(`{"line":"a<b&c","n":1}`)
	until := time.Unix(1_800_000_000, 0).UTC()
	in := []Frame{
		{Type: TypeHello, Token: "tok", Pod: "celld-0", LastFence: op.Fence{Epoch: 3, Counter: 9}},
		{Type: TypeWelcome, Cap: 2, Queued: 5},
		{Type: TypeClaim, LeaseID: "l1", OpID: "o1"},
		{Type: TypeLease, LeaseID: "l1", OpID: "o1", Fence: op.Fence{Epoch: 3, Counter: 10}, Envelope: json.RawMessage(`{"payloadType":"x"}`), Until: until},
		{Type: TypeNone}, {Type: TypeWork}, {Type: TypeFinal, OpID: "o1", Outcome: op.OutcomeApplied},
		{Type: TypeResult, OpID: "o1", Outcome: op.OutcomeApplied, Item: &Item{Kind: KindResult, Cell: "c", OpID: "o1", Body: body, Token: "t"}},
		{Type: TypeStatus, Item: &Item{Kind: KindStatus, Cell: "c", Body: body, Token: "t"}},
		{Type: TypeAck}, {Type: TypeRetry, Reason: ReasonOverloaded}, {Type: TypeRefused, Reason: ReasonReplicaCap},
		{Type: TypePing}, {Type: TypePong},
	}
	var buf bytes.Buffer
	for _, f := range in {
		if err := Encode(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	dec := NewDecoder(&buf)
	for i, want := range in {
		got, err := dec.Decode()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(got)
		if !bytes.Equal(a, b) {
			t.Fatalf("frame %d: got %s, want %s", i, b, a)
		}
		if want.Item != nil && !bytes.Equal(got.Item.Body, want.Item.Body) {
			t.Fatalf("frame %d: item body changed from %s to %s", i, want.Item.Body, got.Item.Body)
		}
	}
	if _, err := dec.Decode(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last frame: %v", err)
	}
}

func TestGwapiDecoderLimit(t *testing.T) {
	big := `{"type":"hello","token":"` + strings.Repeat("a", MaxFrame) + `"}` + "\n"
	if _, err := NewDecoder(strings.NewReader(big)).Decode(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a frame above the limit: %v", err)
	}
	// A line with no newline must not make the decoder buffer without bound.
	endless := io.MultiReader(strings.NewReader(`{"type":"hello","token":"`), neverEnding{})
	if _, err := NewDecoder(endless).Decode(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("an endless line: %v", err)
	}
	pad := strings.Repeat("a", MaxFrame-len(`{"type":"hello","token":""}`)-1)
	ok := `{"type":"hello","token":"` + pad + `"}` + "\n"
	if len(ok) != MaxFrame {
		t.Fatalf("test frame is %d bytes", len(ok))
	}
	if _, err := NewDecoder(strings.NewReader(ok)).Decode(); err != nil {
		t.Fatalf("a frame at the limit: %v", err)
	}
}

type neverEnding struct{}

func (neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestFramesStrict(t *testing.T) {
	for name, line := range map[string]string{
		"unknown_type":  `{"type":"bogus"}`,
		"missing_type":  `{"token":"x"}`,
		"unknown_field": `{"type":"ping","extra":1}`,
		"duplicate":     `{"type":"ping","type":"pong"}`,
		"trailing":      `{"type":"ping"} {"type":"ping"}`,
		"not_json":      `ping`,
		"wrong_kind":    `{"type":"result","item":{"kind":"bogus","cell":"c","body":{},"token":"t"}}`,
		"item_unknown":  `{"type":"result","item":{"kind":"result","cell":"c","body":{},"token":"t","x":1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewDecoder(strings.NewReader(line + "\n")).Decode(); err == nil {
				t.Fatal("decoded")
			}
		})
	}
	if _, err := NewDecoder(strings.NewReader(`{"type":"ping"}` + "\n")).Decode(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDecoder(strings.NewReader(`{"type":"ping"}`)).Decode(); err != nil {
		t.Fatalf("a last frame with no newline: %v", err)
	}
}

type flushRecorder struct {
	bytes.Buffer
	flushes int
	writes  int
}

func (f *flushRecorder) Flush() { f.flushes++ }
func (f *flushRecorder) Write(p []byte) (int, error) {
	f.writes++
	return f.Buffer.Write(p)
}

func TestEncodeFlushes(t *testing.T) {
	var rec flushRecorder
	var _ http.Flusher = &rec
	for i := 0; i < 3; i++ {
		if err := Encode(&rec, Frame{Type: TypePing}); err != nil {
			t.Fatal(err)
		}
	}
	if rec.flushes != 3 || rec.writes != 3 {
		t.Fatalf("flushes %d, writes %d, want 3 and 3", rec.flushes, rec.writes)
	}
	var plain bytes.Buffer
	if err := Encode(&plain, Frame{Type: TypePing}); err != nil {
		t.Fatalf("a writer with no Flush: %v", err)
	}
	h := httptest.NewRecorder()
	if err := Encode(h, Frame{Type: TypePing}); err != nil || !h.Flushed {
		t.Fatalf("recorder flushed %v, err %v", h.Flushed, err)
	}
	if err := Encode(&plain, Frame{Type: "bogus"}); err == nil {
		t.Fatal("Encode wrote a frame with an unknown type")
	}
	if err := Encode(&plain, Frame{Type: TypeHello, Token: strings.Repeat("a", MaxFrame)}); err == nil {
		t.Fatal("Encode wrote a frame above the limit")
	}
}

func TestSentinelReasons(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{ErrLeaseLost, ReasonLeaseLost}, {ErrOverloaded, ReasonOverloaded}, {ErrEnvelopeConflict, ReasonEnvelopeConflict},
	} {
		if got := ReasonOf(fmt.Errorf("claim: %w", tc.err)); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.err, got, tc.want)
		}
	}
	if got := ReasonOf(errors.New("other")); got != "" {
		t.Errorf("unknown error: %q", got)
	}
	if got := ReasonOf(nil); got != "" {
		t.Errorf("nil: %q", got)
	}
}

func TestGatewayReasons(t *testing.T) {
	want := []string{
		"cell_unknown", "cell_revoked", "hello_timeout", "proof_missing", "proof_invalid", "replica_cap", "superseded",
		"reauth", "source_mismatch", "nonce_invalid", "token_invalid", "overloaded", "lease_lost", "record_old", "envelope_conflict",
	}
	got := []string{
		ReasonCellUnknown, ReasonCellRevoked, ReasonHelloTimeout, ReasonProofMissing, ReasonProofInvalid, ReasonReplicaCap,
		ReasonSuperseded, ReasonReauth, ReasonSourceMismatch, ReasonNonceInvalid, ReasonTokenInvalid, ReasonOverloaded,
		ReasonLeaseLost, ReasonRecordOld, ReasonEnvelopeConflict,
	}
	seen := map[string]bool{}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("constant %d = %q, want %q", i, got[i], want[i])
		}
		if seen[got[i]] {
			t.Errorf("duplicate %q", got[i])
		}
		seen[got[i]] = true
	}
	for _, p := range [][2]string{
		{ReasonCellUnknown, mgmtapi.ReasonCellUnknown}, {ReasonNonceInvalid, mgmtapi.ReasonNonceInvalid},
		{ReasonTokenInvalid, mgmtapi.ReasonTokenInvalid}, {ReasonProofMissing, mgmtapi.ReasonProofMissing},
		{ReasonProofInvalid, mgmtapi.ReasonProofInvalid}, {ReasonLeaseLost, op.ReasonLeaseLost},
	} {
		if p[0] != p[1] {
			t.Errorf("%q differs from %q", p[0], p[1])
		}
	}
}

func TestFrameTypeValues(t *testing.T) {
	want := []string{"hello", "welcome", "claim", "lease", "none", "work", "result", "status", "ack", "final", "retry", "refused", "ping", "pong"}
	got := []string{
		TypeHello, TypeWelcome, TypeClaim, TypeLease, TypeNone, TypeWork, TypeResult, TypeStatus, TypeAck, TypeFinal,
		TypeRetry, TypeRefused, TypePing, TypePong,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("type %d = %q, want %q", i, got[i], want[i])
		}
	}
	if KindResult != "result" || KindStatus != "status" || KindBind != "bind" {
		t.Error("item kinds")
	}
}

func TestNotifier(t *testing.T) {
	n := NewNotifier()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			n.Notify("c")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Notify blocked with no reader")
	}

	ch, cancel := n.Subscribe("c")
	n.Notify("c")
	n.Notify("c")
	n.Notify("c")
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("no signal")
	}
	select {
	case <-ch:
		t.Fatal("three notifies gave two signals")
	default:
	}
	n.Notify("other")
	select {
	case <-ch:
		t.Fatal("a notify for another cell woke the subscriber")
	default:
	}
	ch2, cancel2 := n.Subscribe("c")
	n.Notify("c")
	for _, c := range []<-chan struct{}{ch, ch2} {
		select {
		case <-c:
		case <-time.After(3 * time.Second):
			t.Fatal("a subscriber missed the signal")
		}
	}
	cancel()
	cancel()
	n.Notify("c")
	select {
	case <-ch:
		t.Fatal("a cancelled subscriber got a signal")
	default:
	}
	select {
	case <-ch2:
	case <-time.After(3 * time.Second):
		t.Fatal("the other subscriber lost its signal")
	}
	cancel2()
}

func TestBindResultFor(t *testing.T) {
	for name, tc := range map[string]struct {
		in   mgmtapi.ItemOutcome
		want BindResult
	}{
		"bound":            {mgmtapi.ItemOutcome{Outcome: mgmtapi.OutcomeAccepted, Bind: &mgmtapi.BindResponse{Status: mgmtapi.StatusBound}}, BindResult{Status: "bound"}},
		"already_bound":    {mgmtapi.ItemOutcome{Outcome: mgmtapi.OutcomeAccepted, Bind: &mgmtapi.BindResponse{Status: mgmtapi.StatusAlreadyBound}}, BindResult{Status: "already_bound"}},
		"keys_updated":     {mgmtapi.ItemOutcome{Outcome: mgmtapi.OutcomeAccepted, Bind: &mgmtapi.BindResponse{Status: mgmtapi.StatusKeysUpdated}}, BindResult{Status: "keys_updated"}},
		"denied":           {mgmtapi.ItemOutcome{Outcome: mgmtapi.OutcomeRefused, RequestID: "r1"}, BindResult{Status: "denied", RequestID: "r1"}},
		"pending":          {mgmtapi.ItemOutcome{Outcome: mgmtapi.OutcomeRetry}, BindResult{Status: "pending"}},
		"accepted_no_bind": {mgmtapi.ItemOutcome{Outcome: mgmtapi.OutcomeAccepted}, BindResult{Status: "pending"}},
		"unknown_outcome":  {mgmtapi.ItemOutcome{Outcome: "bogus"}, BindResult{Status: "pending"}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := BindResultFor(tc.in); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestItemID(t *testing.T) {
	a, b := NewItemID(), NewItemID()
	if a == b || !a.Valid() || !b.Valid() {
		t.Fatalf("ids %q %q", a, b)
	}
	for _, bad := range []string{"", strings.Repeat("a", 31), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("a", 33)} {
		if ItemID(bad).Valid() {
			t.Errorf("%q is valid", bad)
		}
		if _, err := ParseItemID(bad); err == nil {
			t.Errorf("ParseItemID accepted %q", bad)
		}
	}
	var out OutItem
	if err := json.Unmarshal([]byte(`{"id":"`+string(a)+`","kind":"result","cell":"c","body":{},"token":"t"}`), &out); err != nil || out.ID != a || out.Kind != KindResult {
		t.Fatalf("OutItem %+v %v", out, err)
	}
	raw, _ := json.Marshal(OutItem{ID: a, Item: Item{Kind: KindBind, Cell: "c", Body: json.RawMessage(`{}`), Token: "t"}})
	if !strings.Contains(string(raw), `"id":"`+string(a)+`"`) || !strings.Contains(string(raw), `"kind":"bind"`) {
		t.Fatalf("OutItem encodes %s", raw)
	}
}

func TestSyncAndAckWireNames(t *testing.T) {
	at := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		v    any
		keys []string
	}{
		{SyncRequest{SpecEnvelope: json.RawMessage(`{}`), Records: map[string]json.RawMessage{"c": json.RawMessage(`{}`)}, Ops: []json.RawMessage{json.RawMessage(`{}`)}, Cells: []mgmtapi.CellInfo{{Name: "c"}}},
			[]string{"specEnvelope", "records", "ops", "cells"}},
		{SyncResponse{Items: []OutItem{{ID: NewItemID()}}, Status: mgmtapi.GatewayStatus{Epoch: 1, SyncedAt: at}}, []string{"items", "status"}},
		{AckRequest{Outcomes: []mgmtapi.ItemOutcome{{ID: "i"}}}, []string{"outcomes"}},
		{BindAccepted{ID: NewItemID()}, []string{"id"}},
		{BindResult{Status: "denied", RequestID: "r"}, []string{"status", "requestId"}},
		{Frame{Type: TypeLease, Token: "t", Reason: "r", Pod: "p", LeaseID: "l", OpID: "o", Outcome: "x", Cap: 1, Queued: 1,
			Fence: op.Fence{Epoch: 1}, LastFence: op.Fence{Epoch: 1}, Envelope: json.RawMessage(`{}`), Until: at, Item: &Item{Kind: "result"}},
			[]string{"type", "token", "reason", "pod", "leaseId", "opId", "outcome", "cap", "queued", "fence", "lastFence", "envelope", "until", "item"}},
		{Item{Kind: "result", Cell: "c", OpID: "o", Body: json.RawMessage(`{}`), Token: "t"}, []string{"kind", "cell", "opId", "body", "token"}},
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
	raw, _ := json.Marshal(Frame{Type: TypePing})
	if string(raw) != `{"type":"ping"}` {
		t.Errorf("a bare frame encodes %s", raw)
	}
}

func TestPathsAndPatterns(t *testing.T) {
	if StreamPath("dev-cell-1") != "/v1/cells/dev-cell-1/stream" || NoncePath("c") != "/v1/cells/c/nonce" ||
		BindPath("c") != "/v1/cells/c/bind" || BindResultPath("c", "abc") != "/v1/cells/c/bind/abc" ||
		SyncPath != "/v1/sync" || AckPath != "/v1/ack" {
		t.Fatal("path values")
	}
	if StreamPath("a b") != "/v1/cells/a%20b/stream" || BindResultPath("a/b", "x y") != "/v1/cells/a%2Fb/bind/x%20y" {
		t.Fatalf("paths do not escape: %q %q", StreamPath("a b"), BindResultPath("a/b", "x y"))
	}
	for _, tc := range []struct {
		pattern string
		path    string
		cell    string
		id      string
	}{
		{StreamPattern, StreamPath("dev-cell-1"), "dev-cell-1", ""},
		{BindResultPattern, BindResultPath("dev-cell-1", "0123"), "dev-cell-1", "0123"},
	} {
		var cell, id string
		mux := http.NewServeMux()
		mux.HandleFunc(tc.pattern, func(w http.ResponseWriter, r *http.Request) {
			cell, id = r.PathValue("cell"), r.PathValue("id")
		})
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.path, nil))
		if cell != tc.cell || id != tc.id {
			t.Errorf("%s: cell %q id %q", tc.pattern, cell, id)
		}
	}
}

// TestReportBodyBytesSurviveEveryHop makes a body the way celld does, with json.Marshal, and checks
// that the proof audience input is the same on the celld side, after the stream, and after the
// json.Marshal of ReportBatch, OutItem and SyncResponse on the envd side.
func TestReportBodyBytesSurviveEveryHop(t *testing.T) {
	body, err := json.Marshal(op.Result{OpID: "o1", Cell: "dev-cell-1", Outcome: op.OutcomeApplied, Reason: "a<b & c > d", EnvelopeSHA256: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`\u003c`)) || !bytes.Contains(body, []byte(`\u0026`)) {
		t.Fatalf("test body has no escapes: %s", body)
	}
	want := proof.ReportAudience("dev-cell-1", KindResult, body)

	var buf bytes.Buffer
	if err := Encode(&buf, Frame{Type: TypeResult, Item: &Item{Kind: KindResult, Cell: "dev-cell-1", Body: body, Token: "t"}}); err != nil {
		t.Fatal(err)
	}
	f, err := NewDecoder(&buf).Decode()
	if err != nil {
		t.Fatal(err)
	}
	if got := proof.ReportAudience("dev-cell-1", KindResult, f.Item.Body); got != want {
		t.Fatalf("after the stream: %s", f.Item.Body)
	}

	out := OutItem{ID: NewItemID(), Item: *f.Item}
	rawSync, err := json.Marshal(SyncResponse{Items: []OutItem{out}})
	if err != nil {
		t.Fatal(err)
	}
	var sync SyncResponse
	if err := json.Unmarshal(rawSync, &sync); err != nil {
		t.Fatal(err)
	}
	if got := proof.ReportAudience("dev-cell-1", KindResult, sync.Items[0].Body); got != want {
		t.Fatalf("after SyncResponse: %s", sync.Items[0].Body)
	}

	rawBatch, err := json.Marshal(mgmtapi.ReportBatch{Items: []mgmtapi.ReportItem{{
		ID: string(out.ID), Cell: out.Cell, Kind: out.Kind, Body: sync.Items[0].Body, Token: out.Token,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var batch mgmtapi.ReportBatch
	if err := json.Unmarshal(rawBatch, &batch); err != nil {
		t.Fatal(err)
	}
	if got := proof.ReportAudience("dev-cell-1", KindResult, batch.Items[0].Body); got != want {
		t.Fatalf("after ReportBatch: %s", batch.Items[0].Body)
	}
}

func TestProofReasonsMatch(t *testing.T) {
	for _, tc := range []struct{ name, proofs, gw, mgmt string }{
		{"missing", proof.ReasonMissing, ReasonProofMissing, mgmtapi.ReasonProofMissing},
		{"invalid", proof.ReasonInvalid, ReasonProofInvalid, mgmtapi.ReasonProofInvalid},
	} {
		if tc.proofs != tc.gw || tc.proofs != tc.mgmt {
			t.Errorf("%s differs: %q %q %q", tc.name, tc.proofs, tc.gw, tc.mgmt)
		}
	}
}
