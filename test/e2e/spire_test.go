//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	spireCluster   = "dev-cp"
	spireNamespace = "spire-system"
	spireServerPod = "spire-server-0"
	spireSocket    = "/run/spire/sockets/api.sock"
	spireBinary    = "/opt/spire/bin/spire-server"
	spireApp       = "spire-server"
	spireTD        = "dev.env.poc.internal"
	// The controller manager gives each entry that it creates the ID poc.<uuid>.
	spireEntryIDPrefix = "poc."
	// No real entry uses this path. The test checks that before it adds an entry.
	spireTestPath   = "/m2-test/"
	entryWait       = 4 * time.Minute
	forwardWait     = 30 * time.Second
	statefulsetWait = 3 * time.Minute
)

func TestM2ServerHealthy(t *testing.T) {
	waitFor(t, "StatefulSet spire-server Ready with every replica updated", statefulsetWait, func() (bool, string) {
		out, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "statefulset", "spire-server", "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var sts struct {
			Spec   struct{ Replicas int } `json:"spec"`
			Status struct {
				ReadyReplicas   int    `json:"readyReplicas"`
				UpdatedReplicas int    `json:"updatedReplicas"`
				CurrentRevision string `json:"currentRevision"`
				UpdateRevision  string `json:"updateRevision"`
			} `json:"status"`
		}
		if err := json.Unmarshal([]byte(out), &sts); err != nil {
			return false, fmt.Sprintf("decode StatefulSet: %v", err)
		}
		s := sts.Status
		seen := fmt.Sprintf("replicas %d, ready %d, updated %d, revision %s of %s",
			sts.Spec.Replicas, s.ReadyReplicas, s.UpdatedReplicas, s.CurrentRevision, s.UpdateRevision)
		return sts.Spec.Replicas > 0 && s.ReadyReplicas == sts.Spec.Replicas &&
			s.UpdatedReplicas == sts.Spec.Replicas && s.CurrentRevision == s.UpdateRevision, seen
	})

	out, err := spireServer(t, "healthcheck", "-socketPath", spireSocket)
	if err != nil {
		t.Fatalf("spire-server healthcheck through %s: want success, got %v\noutput: %s", spireSocket, err, out)
	}
	if strings.TrimSpace(out) != "Server is healthy." {
		t.Fatalf("spire-server healthcheck: want %q, got %q", "Server is healthy.", out)
	}
}

// TestM2EntriesReconcile adds a ClusterStaticEntry to ConfigMap spire-entries through a signed bundle set of dev-cp: the live set with a
// changed spire-server bundle. It checks that the entry reaches the SPIRE server, serves the live set again, and checks that the entry
// is gone and that the state root is the original one.
func TestM2EntriesReconcile(t *testing.T) {
	run := randomHex(t, 6)
	spiffeID := fmt.Sprintf("spiffe://%s%sentries-reconcile/%s", spireTD, spireTestPath, run)
	parentID := fmt.Sprintf("spiffe://%s%sparent", spireTD, spireTestPath)

	m8WaitNoOpen(t, spireCluster)
	if used := entriesUnder(t, spireTestPath); len(used) > 0 {
		t.Fatalf("want no entry under spiffe://%s%s before the test, got %v. %s", spireTD, spireTestPath, used, repairHint)
	}
	if st := m8State(t, spireCluster); st.Source != "signed" {
		t.Fatalf("the bundle state of %s has source %q, want signed", spireCluster, st.Source)
	}
	m8RestoreOnFailure(t, spireCluster)
	t.Cleanup(func() {
		if left := entriesUnder(t, spireTestPath); len(left) > 0 {
			t.Errorf("want no entry under spiffe://%s%s after the test, got %v. %s", spireTD, spireTestPath, left, repairHint)
		}
	})

	live := m8LiveSet(t, spireCluster)
	origSpire := m8LiveDigest(live, spireApp)
	if origSpire == "" {
		t.Fatalf("the live set of %s has no component %s", spireCluster, spireApp)
	}
	origRoot := m8State(t, spireCluster).Root.Digest
	t.Logf("original root bundle %s, spire-server bundle %s", origRoot, origSpire)

	// A spire-server bundle whose ConfigMap spire-entries holds one test entry.
	entry := fmt.Sprintf(`apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterStaticEntry
metadata:
  name: m2-test-entry
spec:
  spiffeID: %s
  parentID: %s
  selectors: ["m2test:run:%s"]
`, spiffeID, parentID, run)
	objs := m8Objects(t, m8LiveManifests(t, spireCluster, spireApp, origSpire))
	edited := false
	for _, o := range objs {
		meta, _ := o["metadata"].(map[string]any)
		if o["kind"] != "ConfigMap" || meta["name"] != "spire-entries" || meta["namespace"] != spireNamespace {
			continue
		}
		data, _ := o["data"].(map[string]any)
		if data == nil {
			data = map[string]any{}
			o["data"] = data
		}
		data["m2-test-entry.yaml"] = entry
		edited = true
	}
	if !edited {
		t.Fatalf("the live bundle %s of %s has no ConfigMap %s/spire-entries", spireApp, spireCluster, spireNamespace)
	}
	testSpire := m8PushBundle(t, spireCluster, spireApp, m8Render(t, objs))
	if testSpire == origSpire {
		t.Fatalf("the edited spire-server bundle has the digest %s of the live one", testSpire)
	}

	_, tb := m8Offer(t, spireCluster, m8WithDigest(live, spireApp, 0, spireNamespace, testSpire), m8SetWait)
	m8WantResult(t, tb.Result, op.OutcomeApplied, "", "")
	t.Logf("applied the set with spire-server bundle %s", testSpire)

	var id string
	waitFor(t, "entry "+spiffeID+" in spire-server entry show", entryWait, func() (bool, string) {
		entries, err := showEntries(t, spiffeID)
		if err != nil {
			return false, err.Error()
		}
		if len(entries) != 1 {
			return false, fmt.Sprintf("%d entries: %v", len(entries), entries)
		}
		id = entries[0].ID
		return true, ""
	})
	if !strings.HasPrefix(id, spireEntryIDPrefix) {
		t.Fatalf("entry %s: want an ID with prefix %q, got %q", spiffeID, spireEntryIDPrefix, id)
	}
	t.Logf("entry %s has ID %s", spiffeID, id)

	_, tb = m8Offer(t, spireCluster, live, m8SetWait)
	m8WantResult(t, tb.Result, op.OutcomeApplied, "", "")
	waitFor(t, "no entry "+spiffeID+" in spire-server entry show after the restore", entryWait, func() (bool, string) {
		entries, err := showEntries(t, spiffeID)
		if err != nil {
			return false, err.Error()
		}
		return len(entries) == 0, fmt.Sprintf("%d entries: %v", len(entries), entries)
	})
	if got := m8State(t, spireCluster).Root.Digest; got != origRoot {
		t.Errorf("the state root of %s is %s after the restore, want the original %s", spireCluster, got, origRoot)
	}
}

type spireEntry struct {
	ID       string `json:"id"`
	SPIFFEID struct {
		TrustDomain string `json:"trust_domain"`
		Path        string `json:"path"`
	} `json:"spiffe_id"`
}

func (e spireEntry) String() string {
	return fmt.Sprintf("%s=spiffe://%s%s", e.ID, e.SPIFFEID.TrustDomain, e.SPIFFEID.Path)
}

// spireServer runs the spire-server binary in the server container and returns its standard output.
func spireServer(t *testing.T, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"-n", spireNamespace, "exec", spireServerPod, "-c", "spire-server", "--", spireBinary}, args...)
	return kubectl(t, spireCluster, "", full...)
}

// showEntries returns the entries with a SPIFFE ID, or every entry when spiffeID is empty.
func showEntries(t *testing.T, spiffeID string) ([]spireEntry, error) {
	t.Helper()
	args := []string{"entry", "show", "-socketPath", spireSocket, "-output", "json"}
	if spiffeID != "" {
		args = append(args, "-spiffeID", spiffeID)
	}
	out, err := spireServer(t, args...)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Entries []spireEntry `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("decode entry show output %q: %w", out, err)
	}
	return resp.Entries, nil
}

// entriesUnder returns the entries whose SPIFFE ID path starts with prefix.
func entriesUnder(t *testing.T, prefix string) []spireEntry {
	t.Helper()
	all, err := showEntries(t, "")
	if err != nil {
		t.Fatalf("spire-server entry show: %v", err)
	}
	var out []spireEntry
	for _, e := range all {
		if e.SPIFFEID.TrustDomain == spireTD && strings.HasPrefix(e.SPIFFEID.Path, prefix) {
			out = append(out, e)
		}
	}
	return out
}

// waitFor polls check every two seconds until it returns true. After the timeout it fails the test
// with what it waited for and what the last check saw.
func waitFor(t *testing.T, what string, timeout time.Duration, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, seen := check()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s, last saw: %s", timeout, what, seen)
		}
		time.Sleep(2 * time.Second)
	}
}

// lockedBuffer is a buffer that one goroutine writes while another reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// publishedDigests reads build/<cluster>/published.env, which scripts/publish.sh writes.
func publishedDigests(t *testing.T, cluster string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../build", cluster, "published.env"))
	if err != nil {
		t.Fatalf("read the published digests of %s: %v. Run: CELL=%s mise run cell:up", cluster, err, cluster)
	}
	out := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if name, digest, ok := strings.Cut(line, "="); ok {
			out[name] = digest
		}
	}
	return out
}

// runTool runs a pinned tool with extra environment variables and returns standard output.
func runTool(t *testing.T, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
