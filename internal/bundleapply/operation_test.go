package bundleapply

import (
	"errors"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// syncOf returns an e.sync function that gives the operation of fn for app at rev, and a sync that
// succeeds at once for every other Application.
func syncOf(app, rev string, fn func(now time.Time) (string, time.Time)) func(root, a, r string, now time.Time) (string, time.Time) {
	return func(_, a, r string, now time.Time) (string, time.Time) {
		if a == app && r == rev {
			return fn(now)
		}
		return "Succeeded", now
	}
}

// TestApplyCountsOnlyASyncAfterTheMove checks that an Application counts as applied only through a
// sync operation of Argo CD that succeeded at the wanted revision and started after the tag move.
// Sync status, health and revision alone do not count: after a sync that the harness guard denied,
// Argo CD can report Synced while it applied nothing. An Application whose revision did not change
// starts no sync, so the sync that applied its revision before the move counts while no other
// operation ran.
func TestApplyCountsOnlyASyncAfterTheMove(t *testing.T) {
	v2 := bundle.Version{Epoch: 1, Counter: 2}
	for _, tc := range []struct {
		name string
		op   func(now time.Time) (string, time.Time)
	}{
		{"no sync", func(time.Time) (string, time.Time) { return "", time.Time{} }},
		{"sync from before the move", func(now time.Time) (string, time.Time) { return "Succeeded", now.Add(-time.Hour) }},
		{"failed sync", func(now time.Time) (string, time.Time) { return "Failed", now }},
		{"running sync", func(now time.Time) (string, time.Time) { return "Running", now }},
		// The first poll after the move runs one poll interval (5 s) after it.
		{"sync 20 s before the move", func(now time.Time) (string, time.Time) { return "Succeeded", now.Add(-25 * time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, a, b := twoSets(t)
			e.sync = syncOf("apps-sample", b.digests()["apps-sample"], tc.op)
			wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "timeout:apps-sample:Synced/Healthy")
			e.assertRolledBackTo(t, a, v2)
		})
	}
	// Argo CD writes startedAt in whole seconds, so a sync that starts in the second of the move can show
	// a start before it.
	t.Run("sync in the second of the move", func(t *testing.T) {
		e, _, b := twoSets(t)
		e.clk.Advance(700 * time.Millisecond)
		e.sync = syncOf("apps-sample", b.digests()["apps-sample"], func(now time.Time) (string, time.Time) {
			return "Succeeded", now.Add(-5*time.Second + 200*time.Millisecond).Truncate(time.Second)
		})
		wantOutcome(t, e.apply("opB", b), op.OutcomeApplied, "", "")
	})
	// A sync of another revision in the same second as the last sync before the move is another operation.
	t.Run("sync from before the move in the second of the last sync", func(t *testing.T) {
		e, a, b := twoSets(t)
		e.clk.Advance(time.Hour)
		last := e.ops["apps-sample"].started
		e.sync = syncOf("apps-sample", b.digests()["apps-sample"], func(time.Time) (string, time.Time) { return "Succeeded", last })
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "timeout:apps-sample:Synced/Healthy")
		e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
	})
	t.Run("unchanged component", func(t *testing.T) {
		e, a, _ := twoSets(t)
		b := e.set(2, []spec{
			{"apps-sample", "apps-demo", cmap("apps-demo", "app", "b")},
			{"network-policy", "cell-system", cmap("cell-system", "np", "a")},
		})
		if b.digests()["network-policy"] != a.digests()["network-policy"] {
			t.Fatal("the test set changes network-policy")
		}
		e.clk.Advance(time.Hour)
		before := *e.ops["network-policy"]
		wantOutcome(t, e.apply("opB", b), op.OutcomeApplied, "", "")
		if got := *e.ops["network-policy"]; got != before {
			t.Fatalf("network-policy ran the sync %+v, want none", got)
		}
	})
	t.Run("same components, higher version", func(t *testing.T) {
		e, a, _ := twoSets(t)
		again := e.set(2, std("a"))
		if again.root.Digest != a.root.Digest {
			t.Fatal("two sets with the same components give two roots")
		}
		e.clk.Advance(time.Hour)
		before := *e.ops["root"]
		wantOutcome(t, e.apply("opA2", again), op.OutcomeApplied, "", "")
		if got := *e.ops["root"]; got != before {
			t.Fatalf("root ran the sync %+v, want none", got)
		}
	})
}

// TestApplyDegradedNeedsACountedSync checks that the early end of a wait on Degraded follows the same
// rule as health: an Application that shows Synced and Degraded at the wanted revision with no sync
// after the move has not applied the set, so only the deadline ends the wait for it.
func TestApplyDegradedNeedsACountedSync(t *testing.T) {
	e, a, b := twoSets(t)
	e.sync = syncOf("apps-sample", b.digests()["apps-sample"], func(time.Time) (string, time.Time) { return "", time.Time{} })
	e.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app == "apps-sample" {
			return "Synced", "Degraded"
		}
		return "Synced", "Healthy"
	}
	wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "timeout:apps-sample:Synced/Degraded")
	e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
}

// TestApplyRollbackTerminatesRunningSyncs checks the rollback of a set whose sync still runs. Argo CD
// fails a sync with a Degraded wave and retries the same revision, and it starts no other sync while an
// operation runs. So the rollback terminates the running operation of root and of each child of the
// set, and the good root then syncs.
func TestApplyRollbackTerminatesRunningSyncs(t *testing.T) {
	v2 := bundle.Version{Epoch: 1, Counter: 2}
	// childStuck makes apps-sample retry the revision of b: its sync runs until the engine terminates it.
	// The root Application takes the health of its children.
	childStuck := func(e *env, b built) {
		rev := b.digests()["apps-sample"]
		e.sync = syncOf("apps-sample", rev, func(now time.Time) (string, time.Time) { return "Running", now })
		e.health = func(_, app string) (string, string) {
			if o := e.ops["apps-sample"]; o == nil || o.rev != rev {
				return "Synced", "Healthy"
			}
			switch app {
			case "apps-sample":
				return "OutOfSync", "Degraded"
			case "root":
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
	}
	t.Run("child retries the failed revision", func(t *testing.T) {
		e, a, b := twoSets(t)
		childStuck(e, b)
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "timeout:apps-sample:OutOfSync/Degraded")
		e.assertRolledBackTo(t, a, v2)
		if !slices.Equal(e.terminated, []string{"apps-sample"}) {
			t.Fatalf("terminated %v, want apps-sample", e.terminated)
		}
		if o := e.ops["apps-sample"]; o.phase != "Succeeded" || o.rev != a.digests()["apps-sample"] {
			t.Fatalf("apps-sample shows the operation %+v, want a sync of the good revision", o)
		}
	})
	t.Run("root retries the failed root", func(t *testing.T) {
		e, a, b := twoSets(t)
		e.sync = syncOf("root", b.root.Digest, func(now time.Time) (string, time.Time) { return "Running", now })
		e.health = func(root, app string) (string, string) {
			switch {
			case app == "apps-sample" && root == b.root.Digest:
				return "Synced", "Degraded"
			case app == "root" && e.ops["root"].rev == b.root.Digest:
				return "OutOfSync", "Degraded"
			}
			return "Synced", "Healthy"
		}
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
		e.assertRolledBackTo(t, a, v2)
		if !slices.Equal(e.terminated, []string{"root"}) {
			t.Fatalf("terminated %v, want root", e.terminated)
		}
		if o := e.ops["root"]; o.phase != "Succeeded" || o.rev != a.root.Digest {
			t.Fatalf("root shows the operation %+v, want a sync of the good root", o)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		e, a, b := twoSets(t)
		childStuck(e, b)
		e.conflicts = 1
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "timeout:apps-sample:OutOfSync/Degraded")
		e.assertRolledBackTo(t, a, v2)
		if !slices.Equal(e.terminated, []string{"apps-sample"}) || len(e.terminateRVs) != 2 || slices.Contains(e.terminateRVs, "") {
			t.Fatalf("terminated %v with the resource versions %q, want apps-sample after one conflict, each patch with a resource version", e.terminated, e.terminateRVs)
		}
	})
	t.Run("no running operation", func(t *testing.T) {
		e, a, b := twoSets(t)
		e.health = func(root, app string) (string, string) {
			if root == b.root.Digest && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "apps-sample:Synced/Degraded")
		e.assertRolledBackTo(t, a, v2)
		if len(e.terminateRVs) != 0 {
			t.Fatalf("the engine sent %d terminate patches, want none", len(e.terminateRVs))
		}
	})
}

// TestApplyRollbackCountsOnlyASyncAfterTheRollbackMove checks that the rollback wait judges root and the
// children by the rule of the health wait: a sync of the good revision that started after the tag moved
// back, or, for an Application that never left the good revision, the sync that applied it before.
func TestApplyRollbackCountsOnlyASyncAfterTheRollbackMove(t *testing.T) {
	degraded := func(e *env, b built) {
		e.health = func(root, app string) (string, string) {
			if root == b.root.Digest && app == "apps-sample" {
				return "Synced", "Degraded"
			}
			return "Synced", "Healthy"
		}
	}
	for _, tc := range []struct {
		name, app string
		op        func(now time.Time) (string, time.Time)
	}{
		{"child with no sync", "apps-sample", func(time.Time) (string, time.Time) { return "", time.Time{} }},
		{"root sync from before the move", "root", func(now time.Time) (string, time.Time) { return "Succeeded", now.Add(-time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, a, b := twoSets(t)
			degraded(e, b)
			rev := a.root.Digest
			if tc.app != "root" {
				rev = a.digests()[tc.app]
			}
			// The Application synced the failed set, so the sync that applied the good revision before is not its last.
			moved := false
			e.sync = func(root, app, r string, now time.Time) (string, time.Time) {
				if moved && app == tc.app && r == rev {
					return tc.op(now)
				}
				return "Succeeded", now
			}
			e.hook = func(int) { moved = moved || e.currentRoot() == b.root.Digest }
			wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "rollback_unhealthy")
		})
	}
	t.Run("child that never left the good revision", func(t *testing.T) {
		e, a, b := twoSets(t)
		e.sync = syncOf("apps-sample", b.digests()["apps-sample"], func(time.Time) (string, time.Time) { return "", time.Time{} })
		before := *e.ops["apps-sample"]
		wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "timeout:apps-sample:Synced/Healthy")
		e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
		if got := *e.ops["apps-sample"]; got != before {
			t.Fatalf("apps-sample shows the operation %+v, want the sync of set A %+v", got, before)
		}
	})
}

// TestApplyReadBeforeTheMoveFails checks that the engine does not move the tag when it cannot read the
// Applications before the move: without that read no sync from before the move can count, so the wait
// would roll back a set that changes only some components. The caller tries the operation again.
func TestApplyReadBeforeTheMoveFails(t *testing.T) {
	e := newEnv(t)
	b := e.set(1, std("v1"))
	lists := 0
	e.dyn.PrependReactor("list", "applications", func(k8stesting.Action) (bool, runtime.Object, error) {
		lists++
		return lists == 1, nil, errors.New("the API server is not reachable")
	})
	if _, err := e.a.Apply(t.Context(), "op1", tTarget, b.att); err == nil {
		t.Fatal("an apply with no read of the Applications succeeded")
	}
	if got := e.currentRoot(); got != e.boot.root.Digest {
		t.Fatalf("tag current = %s, want the bootstrap root", got)
	}
	wantOutcome(t, e.apply("op1", b), op.OutcomeApplied, "", "")
}

// TestApplyRollbackKeepsASyncOfTheGoodRevision checks that the rollback does not terminate a sync that
// already runs for the good revision, and that this sync counts when it succeeds, though it started
// before the tag moved back: it is the same operation that ran before the move, for the same revision.
func TestApplyRollbackKeepsASyncOfTheGoodRevision(t *testing.T) {
	e, a, _ := twoSets(t)
	b := e.set(2, []spec{
		{"apps-sample", "apps-demo", cmap("apps-demo", "app", "a")},
		{"network-policy", "cell-system", cmap("cell-system", "np", "b")},
	})
	rev := a.digests()["apps-sample"]
	if b.digests()["apps-sample"] != rev {
		t.Fatal("the test set changes apps-sample")
	}
	// apps-sample runs a sync of its revision, for example a self-heal, from before set B arrives.
	e.ops["apps-sample"] = &simOp{"Running", rev, e.clk.Now().Add(-time.Second)}
	e.health = func(root, app string) (string, string) {
		if root == b.root.Digest && app == "network-policy" {
			return "Synced", "Degraded"
		}
		return "Synced", "Healthy"
	}
	e.hook = func(int) {
		if o := e.ops["apps-sample"]; e.currentRoot() == a.root.Digest && o.phase == "Running" {
			o.phase = "Succeeded"
		}
	}
	wantOutcome(t, e.apply("opB", b), op.OutcomeRolledBack, op.ReasonUnhealthy, "network-policy:Synced/Degraded")
	e.assertRolledBackTo(t, a, bundle.Version{Epoch: 1, Counter: 2})
	if len(e.terminated) != 0 {
		t.Fatalf("terminated %v, want none", e.terminated)
	}
}
