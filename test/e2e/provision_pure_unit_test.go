package e2e

import (
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
)

// TestFreshRefusal: the rogue-token case starts its window 2 s before its injection, and the no-token case polls every 2 s, so the
// refusal of the first case can lie inside the window of the second. The second case must wait for a refusal newer than the first.
func TestFreshRefusal(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	first := &mgmt.ItemRefusal{Kind: "status", Reason: "not_bound", At: t0}
	secondInjected := t0.Add(-time.Second) // the window of the second case reaches back before the first refusal
	if freshRefusal(first, "status", "not_bound", secondInjected, first.At) {
		t.Error("the refusal of the first case counts for the second case")
	}
	if freshRefusal(first, "status", "not_bound", secondInjected, time.Time{}) != true {
		t.Error("with no previous refusal, the old window accepts the first refusal (the false pass that prev prevents)")
	}
	next := &mgmt.ItemRefusal{Kind: "status", Reason: "not_bound", At: t0.Add(3 * time.Second)}
	if !freshRefusal(next, "status", "not_bound", secondInjected, first.At) {
		t.Error("a newer refusal does not count")
	}
	if freshRefusal(&mgmt.ItemRefusal{Kind: "result", Reason: "not_bound", At: next.At}, "status", "not_bound", secondInjected, first.At) ||
		freshRefusal(nil, "status", "not_bound", secondInjected, first.At) {
		t.Error("a refusal of another kind, or none, counts")
	}
}

// TestLastAttempts: a retry adds a second header for a stage, and the order check reads the last attempt of each stage.
func TestLastAttempts(t *testing.T) {
	secs := []stageSection{{stage: "creating", cluster: "c"}, {stage: "admitting", cluster: "dev-cp", lines: []string{"first"}},
		{stage: "admitting", cluster: "dev-cp", lines: []string{"second"}}, {stage: "bootstrapping", cluster: "c"}}
	got := lastAttempts(secs)
	if len(got) != 3 || got[0].stage != "creating" || got[1].stage != "admitting" || got[1].lines[0] != "second" || got[2].stage != "bootstrapping" {
		t.Fatalf("lastAttempts = %+v", got)
	}
}
