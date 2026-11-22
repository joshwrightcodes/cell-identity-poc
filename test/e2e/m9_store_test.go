//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	m9StoreCell = "dev-cell-1"
	m9StorePod  = "bundle-store-0"
	m9StorePVC  = "data-bundle-store-0"
	// m9StoreBreadcrumb tells gate:m9:repair that this test may have left the bundle store of m9StoreCell empty, or an Application not
	// Synced. The test writes it before the first delete and removes it only after the cleanup saw the store and every Application back.
	m9StoreBreadcrumb = "../../build/gate/m9-store-lost"
	// m9StoreHold is the hold of the cell island. The timer of the partition tool removes the rules after the hold plus 15 minutes, and the
	// test heals earlier. The island must outlast the loss, the new pod and the refill (three minutes after the pod is Ready).
	m9StoreHold = 15 * time.Minute
	// m9StorePodWait bounds the wait for the new pod and the new volume.
	m9StorePodWait = 5 * time.Minute
	// m9StoreRefillWait is the time from the new pod Ready to the refilled store and the Application root back at the root of the state.
	m9StoreRefillWait = 3 * time.Minute
	// m9StoreSampleEvery is the time between two reads of the UIDs during the island.
	m9StoreSampleEvery = 10 * time.Second
)

// m9UIDs maps "<kind>/<namespace>/<name>" to the UID of every Application of argocd and every Deployment of the cluster, except the
// objects that carry the e2e label.
type m9UIDs map[string]string

// m9ReadUIDs reads the UIDs of the Applications and of the Deployments of the cell. It uses no t.Fatal, so the sampler can call it from its
// own goroutine.
func m9ReadUIDs(t *testing.T, cluster string) (m9UIDs, error) {
	t.Helper()
	uids := m9UIDs{}
	for _, q := range []struct {
		kind string
		args []string
	}{
		{"application", []string{"-n", "argocd", "get", "applications", "-o", "json"}},
		{"deployment", []string{"get", "deployments", "-A", "-o", "json"}},
	} {
		out, err := kubectl(t, cluster, "", q.args...)
		if err != nil {
			return nil, err
		}
		var list struct {
			Items []struct {
				Metadata struct {
					Name      string            `json:"name"`
					Namespace string            `json:"namespace"`
					UID       string            `json:"uid"`
					Labels    map[string]string `json:"labels"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			return nil, fmt.Errorf("decode the %ss of %s: %w", q.kind, cluster, err)
		}
		for _, it := range list.Items {
			if it.Metadata.Labels["cell.poc.internal/e2e"] == "true" {
				continue
			}
			uids[q.kind+"/"+it.Metadata.Namespace+"/"+it.Metadata.Name] = it.Metadata.UID
		}
	}
	return uids, nil
}

// m9UIDChanges lists each object of before that is gone or has another UID in after.
func m9UIDChanges(before, after m9UIDs) []string {
	var out []string
	for k, uid := range before {
		switch got, ok := after[k]; {
		case !ok:
			out = append(out, k+" is gone")
		case got != uid:
			out = append(out, fmt.Sprintf("%s has the UID %s, was %s", k, got, uid))
		}
	}
	slices.Sort(out)
	return out
}

// m9UIDSampler reads the UIDs every m9StoreSampleEvery until stop is called, and keeps every change against the baseline. A read that
// fails is not a change: the API of the cell stays reachable during the island, and the final read in the subtest has the last word.
type m9UIDSampler struct {
	mu      sync.Mutex
	changes map[string]bool
	reads   int
	stop    chan struct{}
	done    chan struct{}
}

func m9StartSampler(t *testing.T, cluster string, base m9UIDs) *m9UIDSampler {
	s := &m9UIDSampler{changes: map[string]bool{}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			select {
			case <-s.stop:
				return
			case <-time.After(m9StoreSampleEvery):
			}
			now, err := m9ReadUIDs(t, cluster)
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.reads++
			for _, c := range m9UIDChanges(base, now) {
				s.changes[c] = true
			}
			s.mu.Unlock()
		}
	}()
	return s
}

// Stop ends the sampler and returns the number of reads and the sorted changes.
func (s *m9UIDSampler) Stop() (int, []string) {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	var ch []string
	for c := range s.changes {
		ch = append(ch, c)
	}
	slices.Sort(ch)
	return s.reads, ch
}

// m9Pod is what the test reads of the pod bundle-store-0.
type m9Pod struct {
	UID      string
	Ready    bool
	Deleting bool
	Claim    string
}

func m9ReadStorePod(t *testing.T) (m9Pod, bool, error) {
	t.Helper()
	out, err := kubectl(t, m9StoreCell, "", "-n", m8CellStoreNS, "get", "pod", m9StorePod, "--ignore-not-found", "-o", "json")
	if err != nil {
		return m9Pod{}, false, err
	}
	if strings.TrimSpace(out) == "" {
		return m9Pod{}, false, nil
	}
	var p struct {
		Metadata struct {
			UID               string  `json:"uid"`
			DeletionTimestamp *string `json:"deletionTimestamp"`
		} `json:"metadata"`
		Spec struct {
			Volumes []struct {
				PVC *struct {
					ClaimName string `json:"claimName"`
				} `json:"persistentVolumeClaim"`
			} `json:"volumes"`
		} `json:"spec"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		return m9Pod{}, false, err
	}
	res := m9Pod{UID: p.Metadata.UID, Deleting: p.Metadata.DeletionTimestamp != nil}
	for _, c := range p.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			res.Ready = true
		}
	}
	for _, v := range p.Spec.Volumes {
		if v.PVC != nil && v.PVC.ClaimName == m9StorePVC {
			res.Claim = v.PVC.ClaimName
		}
	}
	return res, true, nil
}

// m9ReadStorePVC returns the UID of the claim and whether it is being deleted, or "" when it does not exist.
func m9ReadStorePVC(t *testing.T) (uid string, deleting bool, err error) {
	t.Helper()
	out, err := kubectl(t, m9StoreCell, "", "-n", m8CellStoreNS, "get", "pvc", m9StorePVC, "--ignore-not-found", "-o", "jsonpath={.metadata.uid} {.metadata.deletionTimestamp}")
	if err != nil {
		return "", false, err
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return "", false, nil
	}
	return f[0], len(f) > 1, nil
}

// m9StoreMissing reports what the in-cluster store lacks: the root manifest by digest and by the tag current, and each component manifest
// by digest. It reads through a port-forward to the registry in the pod, which takes no token. An empty slice means the store holds all.
func m9StoreMissing(t *testing.T, addr string, rootDigest string, comps map[string]string) []string {
	t.Helper()
	var missing []string
	if s := m8StoreHead(t, addr, "bundles/root", rootDigest); s != 200 {
		missing = append(missing, fmt.Sprintf("bundles/root@%s (%d)", rootDigest, s))
	}
	if s := m8StoreHead(t, addr, "bundles/root", tagCurrentName); s != 200 {
		missing = append(missing, fmt.Sprintf("bundles/root:%s (%d)", tagCurrentName, s))
	}
	for name, d := range comps {
		if s := m8StoreHead(t, addr, "bundles/"+name, d); s != 200 {
			missing = append(missing, fmt.Sprintf("bundles/%s@%s (%d)", name, d, s))
		}
	}
	slices.Sort(missing)
	return missing
}

// tagCurrentName is the tag that the engine moves to the root manifest of the state, and that the Application root follows.
const tagCurrentName = "current"

// m9CelldRefillLine returns the time of the first log line of celld that holds store_refilled and the root digest, at or after since.
func m9CelldRefillLine(t *testing.T, since time.Time, rootDigest string) (time.Time, string, bool) {
	t.Helper()
	for _, p := range celldPods(t, m9StoreCell) {
		out, err := kubectl(t, m9StoreCell, "", "-n", celldNamespace, "logs", p.Metadata.Name, "-c", celldContainer, "--timestamps", "--since-time="+since.UTC().Format(time.RFC3339))
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(out, "\n") {
			if !strings.Contains(line, "store_refilled") || !strings.Contains(line, rootDigest) {
				continue
			}
			stamp, _, _ := strings.Cut(line, " ")
			ts, err := time.Parse(time.RFC3339Nano, stamp)
			if err != nil || ts.Before(since) {
				continue
			}
			return ts, line, true
		}
	}
	return time.Time{}, "", false
}

// m9AppView reports the sync status, the health and the comparison error of an Application, and the time of its last comparison.
func m9AppView(t *testing.T, name string) (sync, health, revision string, reconciled time.Time, compErr bool) {
	t.Helper()
	app := m8Application(t, m9StoreCell, name)
	st, _ := app["status"].(map[string]any)
	if conds, ok := st["conditions"].([]any); ok {
		for _, c := range conds {
			if m, ok := c.(map[string]any); ok && m["type"] == "ComparisonError" {
				compErr = true
			}
		}
	}
	reconciled, _ = time.Parse(time.RFC3339, m8Field(app, "status", "reconciledAt"))
	return m8Field(app, "status", "sync", "status"), m8Field(app, "status", "health", "status"), m8Field(app, "status", "sync", "revision"), reconciled, compErr
}

// m9WriteStoreBreadcrumb records that the store of the cell may be lost, with the identity of the volume before the loss.
func m9WriteStoreBreadcrumb(t *testing.T, pvcUID, podUID string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(m9StoreBreadcrumb), 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("cluster %s\nnamespace %s\npvc %s uid %s\npod %s uid %s\nrepair: mise run gate:m9:repair, then check each Application of %s and the store with: mise run cell:verify (CELL=%s)\n",
		m9StoreCell, m8CellStoreNS, m9StorePVC, pvcUID, m9StorePod, podUID, m9StoreCell, m9StoreCell)
	if err := os.WriteFile(m9StoreBreadcrumb, []byte(body), 0o644); err != nil {
		t.Fatalf("write the breadcrumb %s: %v", m9StoreBreadcrumb, err)
	}
}

// m9RestoreStore is the cleanup of the test. It runs after the heal (t.Cleanup runs last in, first out, and the test registers it before
// the cut). It deletes only the pod and the claim that the test named, and only when the claim is still Terminating. It brings the pod
// back, lets the refill fill the store for two minutes, signs the live set when the store is still short, hard-refreshes each Application
// that is not Synced and Healthy, and waits until every Application that was Synced and Healthy before the loss is back. Each failure is
// an error of the test, and the breadcrumb stays.
func m9RestoreStore(t *testing.T, cut func() *linkCut, wasGood []string) {
	t.Helper()
	if c := cut(); c != nil {
		c.Heal(t)
	}
	// A failure between the delete of the claim and the delete of the pod leaves the claim Terminating under a running pod.
	if _, deleting, err := m9ReadStorePVC(t); err == nil && deleting {
		if _, err := kubectl(t, m9StoreCell, "", "-n", m8CellStoreNS, "delete", "pod", m9StorePod, "--wait=false"); err != nil {
			t.Errorf("delete %s to release the claim: %v", m9StorePod, err)
		}
	}
	waitFor(t, m9StorePod+" Ready with an existing claim", m9StorePodWait, func() (bool, string) {
		p, ok, err := m9ReadStorePod(t)
		pvc, deleting, perr := m9ReadStorePVC(t)
		return err == nil && perr == nil && ok && p.Ready && !p.Deleting && pvc != "" && !deleting, fmt.Sprintf("pod %+v found %v, pvc %q deleting %v (%v, %v)", p, ok, pvc, deleting, err, perr)
	})
	st := m8State(t, m9StoreCell)
	addr, _ := m8ForwardStore(t, m9StoreCell)
	var missing []string
	deadline := time.Now().Add(2 * time.Minute)
	for {
		missing = m9StoreMissing(t, addr, st.Root.Digest, st.Components)
		if len(missing) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if len(missing) > 0 {
		t.Logf("the store still lacks %v after the refill window. Signing the live set of %s to fill it", missing, m9StoreCell)
		waitValid(t, []string{m9StoreCell}, 10*time.Minute)
		signed := m8Sign(t, m9StoreCell, m8LiveSet(t, m9StoreCell), true)
		if res := m8Wait(t, m9StoreCell, signed.OpID, m8SetWait); res.Result == nil || (res.Result.Outcome != op.OutcomeApplied && res.Result.Outcome != op.OutcomeAlreadyApplied) {
			t.Errorf("the repair set of %s ended %+v, want applied", m9StoreCell, res.Result)
		}
		st = m8State(t, m9StoreCell)
		if left := m9StoreMissing(t, addr, st.Root.Digest, st.Components); len(left) > 0 {
			t.Errorf("the store of %s still lacks %v after the repair set", m9StoreCell, left)
		}
	}
	// An Application that Argo CD has not compared since the source came back shows its old status. A hard refresh asks for a comparison
	// and syncs nothing.
	for _, name := range wasGood {
		if sync, health, _, _, _ := m9AppView(t, name); sync == "Synced" && health == "Healthy" {
			continue
		}
		if out, err := kubectl(t, m9StoreCell, "", "-n", "argocd", "annotate", "application", name, "argocd.argoproj.io/refresh=hard", "--overwrite"); err != nil {
			t.Errorf("hard refresh of %s: %v\n%s", name, err, out)
		}
	}
	var last []string
	deadline = time.Now().Add(5 * time.Minute)
	for {
		last = last[:0]
		for _, name := range wasGood {
			if sync, health, _, _, _ := m9AppView(t, name); sync != "Synced" || health != "Healthy" {
				last = append(last, fmt.Sprintf("%s is %s/%s", name, sync, health))
			}
		}
		if len(last) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if len(last) > 0 {
		t.Errorf("after the cleanup these Applications of %s are not Synced and Healthy: %v. The breadcrumb %s stays. Run: mise run gate:m9:repair", m9StoreCell, last, m9StoreBreadcrumb)
		return
	}
	if t.Failed() {
		return
	}
	if err := os.Remove(m9StoreBreadcrumb); err != nil && !os.IsNotExist(err) {
		t.Errorf("remove the breadcrumb %s: %v", m9StoreBreadcrumb, err)
	}
}

// TestM9StoreLostDuringCellIsland (verify rows 3 and 12, plan row 756), on dev-cell-1: the cell is cut from dev-cp, the claim
// data-bundle-store-0 and the pod bundle-store-0 are deleted, and the StatefulSet makes the pod again with an empty volume. Nothing is
// scaled, because the Application of cell-system would undo a scale. The refill of celld, which runs from the mirror and needs no link to
// dev-cp, puts the root, the components and the tag current back. No Application and no Deployment is replaced. After the heal the cell
// is valid and the next signed set is applied.
//
// Argo CD keeps the status of an Application for 180 seconds while its OCI source is gone, and then shows Unknown. The test therefore
// never takes Synced as proof by itself: the store must answer for every digest, celld must log store_refilled after the delete, and
// Argo CD must have compared root after that log line. It never waits for a sync operation.
func TestM9StoreLostDuringCellIsland(t *testing.T) {
	cell := m9StoreCell
	base, err := m9ReadUIDs(t, cell)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) == 0 {
		t.Fatalf("%s shows no Application and no Deployment", cell)
	}
	st := m8State(t, cell)
	if st.Source != "signed" || st.State != "healthy" || st.Root.Digest == "" || len(st.Components) == 0 {
		t.Fatalf("the bundle state of %s is %s/%s with the root %q, want signed/healthy with a root and components. The refill skips any other state. Run: mise run bundle -- publish --target %s --wait", cell, st.Source, st.State, st.Root.Digest, cell)
	}
	var wasGood []string
	for key := range base {
		name, ok := strings.CutPrefix(key, "application/argocd/")
		if !ok {
			continue
		}
		if sync, health, _, _, _ := m9AppView(t, name); sync == "Synced" && health == "Healthy" {
			wasGood = append(wasGood, name)
		}
	}
	slices.Sort(wasGood)
	if !slices.Contains(wasGood, "root") {
		t.Fatalf("the Application root of %s is not Synced and Healthy before the test. Wait, or run: mise run cell:verify (CELL=%s)", cell, cell)
	}
	pod, ok, err := m9ReadStorePod(t)
	if err != nil || !ok || !pod.Ready || pod.Claim != m9StorePVC {
		t.Fatalf("%s/%s of %s is %+v (found %v, error %v), want Ready with the claim %s", m8CellStoreNS, m9StorePod, cell, pod, ok, err, m9StorePVC)
	}
	pvcUID, deleting, err := m9ReadStorePVC(t)
	if err != nil || pvcUID == "" || deleting {
		t.Fatalf("the claim %s of %s has the UID %q, deleting %v (error %v), want a live claim", m9StorePVC, cell, pvcUID, deleting, err)
	}
	// The store must hold everything before the loss, so that a refill is the only way back.
	preAddr, _ := m8ForwardStore(t, cell)
	if missing := m9StoreMissing(t, preAddr, st.Root.Digest, st.Components); len(missing) > 0 {
		t.Fatalf("the store of %s lacks %v before the test. Run: mise run bundle -- publish --target %s --wait", cell, missing, cell)
	}

	// The breadcrumb and the cleanup come before the cut and before the first delete. The cleanup heals the cut that cutLink registers
	// later, because t.Cleanup runs last in, first out.
	m9WriteStoreBreadcrumb(t, pvcUID, pod.UID)
	var cut *linkCut
	getCut := func() *linkCut { return cut }
	t.Cleanup(func() { m9RestoreStore(t, getCut, wasGood) })
	sampler := m9StartSampler(t, cell, base)
	t.Cleanup(func() { sampler.Stop() })

	cut = cutLink(t, cell, cpClusterName, "both", m9StoreHold)
	t.Logf("%s is cut from %s until %s", cell, cpClusterName, cut.Until.Format(time.RFC3339))

	// Only the claim and the pod of the bundle store of this cell, by name. The claim waits for the pod because of its protection
	// finalizer, so the StatefulSet makes both again once the pod is gone.
	lostAt := time.Now()
	if out, err := kubectl(t, cell, "", "-n", m8CellStoreNS, "delete", "pvc", m9StorePVC, "--wait=false"); err != nil {
		t.Fatalf("delete the claim: %v\n%s", err, out)
	}
	if out, err := kubectl(t, cell, "", "-n", m8CellStoreNS, "delete", "pod", m9StorePod, "--wait=false"); err != nil {
		t.Fatalf("delete the pod: %v\n%s", err, out)
	}
	var readyAt time.Time
	waitFor(t, m9StorePod+" Ready with a new claim UID", m9StorePodWait, func() (bool, string) {
		p, found, err := m9ReadStorePod(t)
		uid, del, perr := m9ReadStorePVC(t)
		good := err == nil && perr == nil && found && p.Ready && !p.Deleting && p.UID != pod.UID && p.Claim == m9StorePVC && uid != "" && uid != pvcUID && !del
		return good, fmt.Sprintf("pod %+v found %v (old %s), claim %q deleting %v (old %s) (%v, %v)", p, found, pod.UID, uid, del, pvcUID, err, perr)
	})
	readyAt = time.Now()
	t.Logf("the new pod is Ready %s after the delete", readyAt.Sub(lostAt).Round(time.Second))

	t.Run("refilled", func(t *testing.T) {
		addr, _ := m8ForwardStore(t, cell)
		deadline := readyAt.Add(m9StoreRefillWait)
		var seen string
		for {
			refilledAt, line, found := m9CelldRefillLine(t, lostAt, st.Root.Digest)
			missing := m9StoreMissing(t, addr, st.Root.Digest, st.Components)
			sync, health, rev, reconciled, compErr := m9AppView(t, "root")
			seen = fmt.Sprintf("log found %v, the store lacks %v, root is %s/%s at %s (comparison error %v, compared %s)", found, missing, sync, health, rev, compErr, reconciled.Format(time.RFC3339))
			t.Log(seen)
			// Synced inside the first 180 seconds is the old status and proves nothing. The comparison must follow the refill.
			if found && len(missing) == 0 && sync == "Synced" && health == "Healthy" && rev == st.Root.Digest && !compErr && !reconciled.Before(refilledAt) {
				t.Logf("celld logged store_refilled at %s: %s", refilledAt.Format(time.RFC3339), line)
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("waited %s after the new pod was Ready for the refill of %s: %s", m9StoreRefillWait, cell, seen)
			}
			time.Sleep(5 * time.Second)
		}
	})

	t.Run("nothing_pruned", func(t *testing.T) {
		reads, changes := sampler.Stop()
		if reads == 0 {
			t.Errorf("the sampler made no read during the island, so it proves nothing")
		}
		if len(changes) > 0 {
			t.Errorf("during the island, an Application or a Deployment was replaced or removed: %v", changes)
		}
		now, err := m9ReadUIDs(t, cell)
		if err != nil {
			t.Fatal(err)
		}
		if ch := m9UIDChanges(base, now); len(ch) > 0 {
			t.Errorf("after the refill, an Application or a Deployment is not the one from before the loss: %v", ch)
		}
		t.Logf("%d reads of %d objects, no change", reads, len(base))
	})

	t.Run("after_reconnect", func(t *testing.T) {
		cut.Heal(t)
		waitValid(t, []string{cell}, 10*time.Minute)
		signed := m8Sign(t, cell, m8LiveSet(t, cell), true)
		res := m8Wait(t, cell, signed.OpID, m8SetWait)
		if res.Result.Outcome != op.OutcomeApplied {
			t.Fatalf("the next signed set of %s ended %+v, want applied", cell, *res.Result)
		}
		now, err := m9ReadUIDs(t, cell)
		if err != nil {
			t.Fatal(err)
		}
		if ch := m9UIDChanges(base, now); len(ch) > 0 {
			t.Errorf("after the reconnect, an Application or a Deployment is not the one from before the loss: %v", ch)
		}
		if missing := m9StoreMissing(t, addrOrForward(t, cell), m8State(t, cell).Root.Digest, m8State(t, cell).Components); len(missing) > 0 {
			t.Errorf("the store of %s lacks %v after the signed set", cell, missing)
		}
	})
}

// addrOrForward opens a new port-forward to the registry of the current pod of the store of the cell. The pod of an earlier forward may
// be a pod that was replaced.
func addrOrForward(t *testing.T, cell string) string {
	t.Helper()
	addr, _ := m8ForwardStore(t, cell)
	return addr
}
