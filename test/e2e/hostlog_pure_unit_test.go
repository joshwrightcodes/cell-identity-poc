package e2e

import (
	"slices"
	"testing"
	"time"
)

// TestReasonsSince: a refusal from before the cut-off does not count, one at or after it does, and a record with no valid time never counts
// when a cut-off is set.
func TestReasonsSince(t *testing.T) {
	cut := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return cut.Add(d).Format(time.RFC3339Nano) }
	recs := []map[string]any{
		{"time": at(-time.Second), "reason": "bootstrap_mismatch"},
		{"time": at(0), "reason": "step_unindexed"},
		{"time": at(time.Second), "reason": "bootstrap_mismatch"},
		{"time": "garbage", "reason": "signature_invalid"},
		{"time": at(2 * time.Second)},
	}
	if got, want := reasonsSince(recs, cut), []string{"step_unindexed", "bootstrap_mismatch"}; !slices.Equal(got, want) {
		t.Errorf("with a cut-off the reasons are %v, want %v", got, want)
	}
	if got := reasonsSince(recs[:1], cut); len(got) != 0 {
		t.Errorf("a refusal before the cut-off gave %v, want none", got)
	}
	if got, want := reasonsSince(recs, time.Time{}), []string{"bootstrap_mismatch", "step_unindexed", "bootstrap_mismatch", "signature_invalid"}; !slices.Equal(got, want) {
		t.Errorf("with no cut-off the reasons are %v, want %v", got, want)
	}
}
