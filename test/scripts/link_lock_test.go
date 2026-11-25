package scripts

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLinkReleasesItsLock: cell:link takes the lock of its cluster and releases it on every exit. link.sh sets its own EXIT trap, which
// must keep the release.
func TestLinkReleasesItsLock(t *testing.T) {
	t.Parallel()
	lock := func(root string) string { return filepath.Join(root, "build", "locks", "management.lock") }
	t.Run("after a passing link", func(t *testing.T) {
		root, calls := linkOnlyRoot(t)
		if out, log, err := runLink(t, root, calls, "LINK_ONLY=mgmt-api"); err != nil {
			t.Fatalf("link.sh failed: %v\n%s\n%s", err, out, log)
		}
		if _, err := os.Stat(lock(root)); err == nil {
			t.Fatal("a passing link left build/locks/management.lock")
		}
	})
	t.Run("after a failing link", func(t *testing.T) {
		root, calls := linkOnlyRoot(t)
		if _, _, err := runLink(t, root, calls, "STUB_FAIL_APPLY=central-view"); err == nil {
			t.Fatal("link.sh passed with a failing apply")
		}
		if _, err := os.Stat(lock(root)); err == nil {
			t.Fatal("a failing link left build/locks/management.lock")
		}
	})
}
