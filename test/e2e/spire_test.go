//go:build e2e

package e2e

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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
	argoSyncWait    = 4 * time.Minute
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

// TestM2EntriesReconcile adds a ClusterStaticEntry to ConfigMap spire-entries through the publish
// path: a new spire-server bundle in the bundle store, and a new root bundle that pins it. It then
// restores the original root bundle, which removes the entry again.
func TestM2EntriesReconcile(t *testing.T) {
	store := forwardBundleStore(t)
	run := randomHex(t, 6)
	spiffeID := fmt.Sprintf("spiffe://%s%sentries-reconcile/%s", spireTD, spireTestPath, run)
	parentID := fmt.Sprintf("spiffe://%s%sparent", spireTD, spireTestPath)

	if used := entriesUnder(t, spireTestPath); len(used) > 0 {
		t.Fatalf("want no entry under spiffe://%s%s before the test, got %v", spireTD, spireTestPath, used)
	}

	rootRef := store + "/bundles/root"
	spireRef := store + "/bundles/" + spireApp
	origRoot := orasResolve(t, rootRef+":current")
	origSpireTag := orasResolve(t, spireRef+":current")
	origSpire := appTargetRevision(t, spireApp)
	if !strings.HasPrefix(origSpire, "sha256:") {
		t.Fatalf("Application %s: want a targetRevision that pins a digest, got %q", spireApp, origSpire)
	}
	t.Logf("original root bundle %s, spire-server bundle %s (tag current %s)", origRoot, origSpire, origSpireTag)

	restored := false
	restore := func(t *testing.T) {
		t.Helper()
		if !restored {
			orasTag(t, rootRef+"@"+origRoot, "current")
			orasTag(t, spireRef+"@"+origSpireTag, "current")
			refreshRoot(t)
			restored = true
		}
		waitApps(t, origRoot, origSpire)
	}
	t.Cleanup(func() {
		restore(t)
		if left := entriesUnder(t, spireTestPath); len(left) > 0 {
			t.Errorf("want no entry under spiffe://%s%s after the test, got %v", spireTD, spireTestPath, left)
		}
	})

	// A spire-server bundle whose ConfigMap spire-entries holds one test entry.
	spireDir := orasPull(t, spireRef+"@"+origSpire)
	manifests := filepath.Join(spireDir, "manifests.yaml")
	entry := fmt.Sprintf(`apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterStaticEntry
metadata:
  name: m2-test-entry
spec:
  spiffeID: %s
  parentID: %s
  selectors: ["m2test:run:%s"]
`, spiffeID, parentID, run)
	selectEntries := `select(.kind == "ConfigMap" and .metadata.name == "spire-entries" and .metadata.namespace == "spire-system")`
	runTool(t, []string{"ENTRY=" + entry}, "yq", "-i", "("+selectEntries+` | .data["m2-test-entry.yaml"]) = strenv(ENTRY)`, manifests)
	if out := runTool(t, nil, "yq", selectEntries+` | .data | keys | join(",")`, manifests); !strings.Contains(out, "m2-test-entry.yaml") {
		t.Fatalf("edited spire-server bundle: want key m2-test-entry.yaml in ConfigMap spire-entries, got keys %q", out)
	}
	testSpire := orasPush(t, spireDir, spireRef+":current")

	// A root bundle that pins the test spire-server bundle.
	rootDir := orasPull(t, rootRef+"@"+origRoot)
	app := filepath.Join(rootDir, spireApp+".yaml")
	runTool(t, []string{"DIGEST=" + testSpire}, "yq", "-i", `.spec.source.targetRevision = strenv(DIGEST)`, app)
	if out := strings.TrimSpace(runTool(t, nil, "yq", ".spec.source.targetRevision", app)); out != testSpire {
		t.Fatalf("edited root bundle: want %s to pin %s, got %q", app, testSpire, out)
	}
	testRoot := orasPush(t, rootDir, rootRef+":current")
	refreshRoot(t)
	t.Logf("published test root bundle %s with spire-server bundle %s", testRoot, testSpire)
	waitApps(t, testRoot, testSpire)

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

	restore(t)
	waitFor(t, "no entry "+spiffeID+" in spire-server entry show after the restore", entryWait, func() (bool, string) {
		entries, err := showEntries(t, spiffeID)
		if err != nil {
			return false, err.Error()
		}
		return len(entries) == 0, fmt.Sprintf("%d entries: %v", len(entries), entries)
	})
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

type argoApp struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Source struct {
			TargetRevision string `json:"targetRevision"`
		} `json:"source"`
	} `json:"spec"`
	Status struct {
		Sync struct {
			Status   string `json:"status"`
			Revision string `json:"revision"`
		} `json:"sync"`
		Health struct {
			Status string `json:"status"`
		} `json:"health"`
	} `json:"status"`
}

func (a argoApp) String() string {
	return fmt.Sprintf("%s %s/%s at %s (target %s)", a.Metadata.Name, a.Status.Sync.Status, a.Status.Health.Status,
		a.Status.Sync.Revision, a.Spec.Source.TargetRevision)
}

func argoApps(t *testing.T) ([]argoApp, error) {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", "argocd", "get", "applications", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []argoApp `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("decode Applications: %w", err)
	}
	return list.Items, nil
}

func appTargetRevision(t *testing.T, name string) string {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", "argocd", "get", "application", name, "-o", "jsonpath={.spec.source.targetRevision}")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// waitApps waits until the root Application has synced root, the spire-server Application pins and
// has synced spire, and every Application is Synced and Healthy.
func waitApps(t *testing.T, root, spire string) {
	t.Helper()
	what := fmt.Sprintf("root at %s, %s at %s, and every Application Synced and Healthy", root, spireApp, spire)
	waitFor(t, what, argoSyncWait, func() (bool, string) {
		apps, err := argoApps(t)
		if err != nil {
			return false, err.Error()
		}
		var bad []string
		for _, a := range apps {
			want := ""
			switch a.Metadata.Name {
			case "root":
				want = root
			case spireApp:
				want = spire
			}
			if a.Status.Sync.Status != "Synced" || a.Status.Health.Status != "Healthy" ||
				(want != "" && a.Status.Sync.Revision != want) ||
				(a.Metadata.Name == spireApp && a.Spec.Source.TargetRevision != spire) {
				bad = append(bad, a.String())
			}
		}
		if len(apps) == 0 {
			bad = append(bad, "no Applications")
		}
		return len(bad) == 0, strings.Join(bad, "; ")
	})
}

func refreshRoot(t *testing.T) {
	t.Helper()
	if _, err := kubectl(t, spireCluster, "", "-n", "argocd", "annotate", "application", "root",
		"argocd.argoproj.io/refresh=hard", "--overwrite"); err != nil {
		t.Fatal(err)
	}
}

var forwardLine = regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:(\d+) -> 5000$`)

// forwardBundleStore starts a port-forward to the bundle store of dev-cp on a free local port. It
// returns the store address and stops the forward when the test ends.
func forwardBundleStore(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("kubectl", "--context", "kind-"+spireCluster, "-n", "cell-system",
		"port-forward", "--address", "127.0.0.1", "svc/bundle-store", ":5000")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the port-forward to the bundle store: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	port := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if m := forwardLine.FindStringSubmatch(s.Text()); m != nil {
				port <- m[1]
				break
			}
		}
		for s.Scan() {
		}
	}()
	var addr string
	select {
	case p := <-port:
		addr = "127.0.0.1:" + p
	case <-time.After(forwardWait):
		t.Fatalf("waited %s for the port-forward to the bundle store to print its local port, stderr: %s", forwardWait, stderr.String())
	}
	waitFor(t, "HTTP 200 from http://"+addr+"/v2/", forwardWait, func() (bool, string) {
		resp, err := http.Get("http://" + addr + "/v2/")
		if err != nil {
			return false, err.Error()
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK, resp.Status
	})
	return addr
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

func orasResolve(t *testing.T, ref string) string {
	t.Helper()
	d := strings.TrimSpace(runTool(t, nil, "oras", "resolve", "--plain-http", ref))
	if !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("oras resolve %s: want a sha256 digest, got %q", ref, d)
	}
	return d
}

func orasPull(t *testing.T, ref string) string {
	t.Helper()
	dir := t.TempDir()
	runTool(t, nil, "oras", "pull", "--plain-http", "--output", dir, ref)
	return dir
}

// orasPush pushes dir as one bundle, the way scripts/publish.sh does, and returns its digest.
func orasPush(t *testing.T, dir, ref string) string {
	t.Helper()
	cmd := exec.Command("oras", "push", "--plain-http", "--format", "json", ref, ".")
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oras push %s: %v: %s", ref, err, stderr.String())
	}
	var res struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(out, &res); err != nil || !strings.HasPrefix(res.Digest, "sha256:") {
		t.Fatalf("oras push %s: want JSON with a sha256 digest, got %q: %v", ref, out, err)
	}
	return res.Digest
}

func orasTag(t *testing.T, ref, tag string) {
	t.Helper()
	runTool(t, nil, "oras", "tag", "--plain-http", ref, tag)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
