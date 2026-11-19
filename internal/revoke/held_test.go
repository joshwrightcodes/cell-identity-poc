package revoke

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

func cellRecord(name string, epoch, counter uint64, revoked bool) record.Cell {
	return record.Cell{Name: name, Env: "dev", Epoch: epoch, Counter: counter, Revoked: revoked}
}

// entryFor signs an entry for cell that names the record revision epoch.counter.
func entryFor(t *testing.T, key ed25519.PrivateKey, id, env, cell string, epoch, counter uint64) []byte {
	t.Helper()
	e := testEntry()
	e.ID, e.Env, e.Cell, e.Record = id, env, cell, spec.Revision{Epoch: epoch, Counter: counter}
	out, err := Sign(e, key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAdmitRules(t *testing.T) {
	key, other := testKey(t, 1), testKey(t, 2)
	keys := []ed25519.PublicKey{pub(key)}
	records := map[string]record.Cell{
		"dev-cell-1": cellRecord("dev-cell-1", 2, 5, false),
		"dev-cell-2": cellRecord("dev-cell-2", 2, 5, false),
	}
	full := Held{}
	for i := range MaxHeld {
		full[fmt.Sprintf("held-%02d", i)] = []byte(`{}`)
	}
	payloadOther, err := record.SignEnvelope(record.PayloadType, []byte(`{}`), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		held   Held
		in     []byte
		reason string
		detail string
		cell   string
	}{
		{name: "accepted_equal", in: entryFor(t, key, "00000000000000a1", "dev", "dev-cell-2", 2, 5)},
		{name: "accepted_above", in: entryFor(t, key, "00000000000000a2", "dev", "dev-cell-2", 2, 9)},
		{name: "accepted_next_epoch", in: entryFor(t, key, "00000000000000a3", "dev", "dev-cell-2", 3, 1)},
		{name: "accepted_last_slot", held: withoutOne(full), in: entryFor(t, key, "00000000000000a4", "dev", "dev-cell-2", 2, 5)},
		{name: "signature", in: entryFor(t, other, "00000000000000b1", "dev", "dev-cell-2", 2, 5), reason: ReasonInvalid, detail: DetailSignature},
		{name: "decode", in: []byte(`{"payloadType":`), reason: ReasonInvalid, detail: DetailDecode},
		{name: "decode_payload", in: signBody(t, `{"id":"x"}`, key), reason: ReasonInvalid, detail: DetailDecode},
		{name: "payload_type", in: payloadOther, reason: ReasonInvalid, detail: DetailDecode},
		{name: "env", in: entryFor(t, key, "00000000000000b2", "prod", "dev-cell-2", 2, 5), reason: ReasonInvalid, detail: DetailEnv, cell: "dev-cell-2"},
		{name: "unknown_cell", in: entryFor(t, key, "00000000000000b3", "dev", "dev-cell-9", 2, 5), reason: ReasonUnknownCell, cell: "dev-cell-9"},
		{name: "stale", in: entryFor(t, key, "00000000000000b4", "dev", "dev-cell-2", 2, 4), reason: ReasonStale, cell: "dev-cell-2"},
		{name: "stale_epoch", in: entryFor(t, key, "00000000000000b5", "dev", "dev-cell-2", 1, 9), reason: ReasonStale, cell: "dev-cell-2"},
		{name: "overflow", held: full, in: entryFor(t, key, "00000000000000b6", "dev", "dev-cell-2", 2, 5), reason: ReasonOverflow, cell: "dev-cell-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(tc.held)
			got, refusals := Admit(tc.held, [][]byte{tc.in}, keys, "dev", records)
			if len(tc.held) != before {
				t.Error("Admit changes its input")
			}
			if tc.reason == "" {
				if len(refusals) != 0 {
					t.Fatalf("refusals %+v", refusals)
				}
				if _, ok := got["dev-cell-2"]; !ok || len(got) != before+1 {
					t.Fatalf("held %d entries, dev-cell-2 held %v", len(got), ok)
				}
				if _, err := Verify(got["dev-cell-2"], keys); err != nil {
					t.Errorf("held envelope: %v", err)
				}
				return
			}
			if len(got) != before {
				t.Errorf("held %d entries, want %d", len(got), before)
			}
			if len(refusals) != 1 {
				t.Fatalf("refusals %+v", refusals)
			}
			r := refusals[0]
			if r.Reason != tc.reason || r.Detail != tc.detail || r.Cell != tc.cell {
				t.Errorf("refusal %+v, want reason %q detail %q cell %q", r, tc.reason, tc.detail, tc.cell)
			}
			if tc.cell != "" && len(r.ID) != 16 {
				t.Errorf("refusal ID %q", r.ID)
			}
			if tc.cell == "" && r.ID != "" {
				t.Errorf("an unverified entry gives ID %q", r.ID)
			}
		})
	}
}

func withoutOne(h Held) Held {
	out := Held{}
	for k, v := range h {
		out[k] = v
	}
	delete(out, "held-00")
	return out
}

func TestAdmitKeepsFirst(t *testing.T) {
	key := testKey(t, 1)
	keys := []ed25519.PublicKey{pub(key)}
	records := map[string]record.Cell{"dev-cell-2": cellRecord("dev-cell-2", 1, 3, false)}
	first := entryFor(t, key, "000000000000000a", "dev", "dev-cell-2", 1, 3)
	second := entryFor(t, key, "000000000000000b", "dev", "dev-cell-2", 1, 4)

	h, refusals := Admit(nil, [][]byte{first, second}, keys, "dev", records)
	if len(refusals) != 0 || len(h) != 1 {
		t.Fatalf("held %d, refusals %+v", len(h), refusals)
	}
	if e, _ := Verify(h["dev-cell-2"], keys); e.ID != "000000000000000a" {
		t.Errorf("held ID %q", e.ID)
	}
	h2, refusals := Admit(h, [][]byte{second, first}, keys, "dev", records)
	if len(refusals) != 0 || len(h2) != 1 {
		t.Fatalf("held %d, refusals %+v", len(h2), refusals)
	}
	if e, _ := Verify(h2["dev-cell-2"], keys); e.ID != "000000000000000a" {
		t.Errorf("held ID %q after a second round", e.ID)
	}
	full := Held{"dev-cell-2": h["dev-cell-2"]}
	for i := range MaxHeld - 1 {
		full[fmt.Sprintf("held-%02d", i)] = []byte(`{}`)
	}
	if _, refusals := Admit(full, [][]byte{second}, keys, "dev", records); len(refusals) != 0 {
		t.Errorf("a second entry for a held cell at the cap gives %+v", refusals)
	}
}

func TestSettleDropsOnRevokedOrRetired(t *testing.T) {
	key := testKey(t, 1)
	h := Held{
		"dev-cell-1": entryFor(t, key, "0000000000000001", "dev", "dev-cell-1", 1, 3),
		"dev-cell-2": entryFor(t, key, "0000000000000002", "dev", "dev-cell-2", 1, 3),
		"dev-cell-3": entryFor(t, key, "0000000000000003", "dev", "dev-cell-3", 1, 3),
	}
	records := map[string]record.Cell{
		"dev-cell-1": cellRecord("dev-cell-1", 1, 4, true),
		"dev-cell-3": cellRecord("dev-cell-3", 1, 3, false),
	}
	got := Settle(h, records, map[string]bool{"dev-cell-2": true})
	if len(h) != 3 {
		t.Error("Settle changes its input")
	}
	if len(got) != 1 || got["dev-cell-3"] == nil {
		t.Errorf("held after settle: %v", slices.Sorted(maps.Keys(got)))
	}
	if got := Settle(Held{"dev-cell-1": h["dev-cell-1"]}, map[string]record.Cell{"dev-cell-1": cellRecord("dev-cell-1", 1, 3, true)}, nil); len(got) != 0 {
		t.Error("a revoked record at the named revision keeps the entry")
	}
}

func TestSettleKeepsOnUnrelatedRevision(t *testing.T) {
	key := testKey(t, 1)
	h := Held{"dev-cell-2": entryFor(t, key, "0000000000000002", "dev", "dev-cell-2", 1, 3)}
	for _, rec := range []record.Cell{
		cellRecord("dev-cell-2", 1, 3, false),
		cellRecord("dev-cell-2", 1, 4, false),
		cellRecord("dev-cell-2", 2, 1, false),
	} {
		got := Settle(h, map[string]record.Cell{"dev-cell-2": rec}, map[string]bool{"dev-cell-1": true})
		if len(got) != 1 {
			t.Errorf("record %d.%d drops the entry", rec.Epoch, rec.Counter)
		}
	}
	if got := Settle(h, nil, nil); len(got) != 1 {
		t.Error("a cell with no record drops the entry")
	}
}

func TestHeldEnvelopesSorted(t *testing.T) {
	key := testKey(t, 1)
	h := Held{}
	for _, c := range []string{"dev-cell-3", "dev-cell-1", "dev-cell-2"} {
		h[c] = entryFor(t, key, "0000000000000001", "dev", c, 1, 1)
	}
	var cells []string
	for _, raw := range h.Envelopes() {
		e, err := Verify(raw, []ed25519.PublicKey{pub(key)})
		if err != nil {
			t.Fatal(err)
		}
		cells = append(cells, e.Cell)
	}
	if !slices.Equal(cells, []string{"dev-cell-1", "dev-cell-2", "dev-cell-3"}) {
		t.Errorf("order %v", cells)
	}
	raw, err := json.Marshal(h.Envelopes())
	if err != nil {
		t.Fatal(err)
	}
	var back []json.RawMessage
	if err := json.Unmarshal(raw, &back); err != nil || len(back) != 3 {
		t.Errorf("envelopes do not encode as a JSON array: %v", err)
	}
	if got := Held(nil).Envelopes(); got == nil || len(got) != 0 {
		t.Errorf("an empty overlay gives %v", got)
	}
}

func TestReasonValues(t *testing.T) {
	got := []string{ReasonInvalid, ReasonStale, ReasonUnknownCell, ReasonOverflow, DetailSignature, DetailDecode, DetailEnv}
	want := []string{"revocation_invalid", "revocation_stale", "revocation_unknown_cell", "revocation_overflow", "signature", "decode", "env"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
}
