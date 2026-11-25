//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	// m9ptCut is how long each one-way cut of TestM9OneWayPartitions lasts.
	m9ptCut = 3 * time.Minute
	// m9ptTimer is the hold that the partition tool gets for the cut. The test heals the cut itself, and the timer in the node removes
	// the rules at the hold plus 15 minutes if the test dies first.
	m9ptTimer = 5 * time.Minute
	// m9ptDetectWait bounds the detection of a cut on each side. celld pings every 10 s with a read idle limit of 15 s and a ping timeout of
	// 10 s, and the gateway ends a stream after 30 s of no frame and pings after 30 s of silence with a timeout of 10 s.
	m9ptDetectWait = 2 * time.Minute
	// m9ptFastRecover is the time from a heal to the celld stream when the hold is below half the SVID lifetime: no agent of the cell lost its SVID.
	m9ptFastRecover = 90 * time.Second
	// m9ptSlowRecover is the re-attestation bound of 10 minutes, for a hold of at least half the lifetime (at 1m the agents of the cell lose their SVIDs).
	m9ptSlowRecover = 10 * time.Minute
	// m9ptSample is the interval of the restart watch.
	m9ptSample = 15 * time.Second
	// m9ptSkew is the skew that the pass rule allows between the SVID expiry and the first restart of a spire-agent container.
	m9ptSkew = time.Minute
	// m9ptRotationWait is the wait of TestM9KeyRotatedDuringEnvironmentIsland beyond half the SVID lifetime.
	m9ptRotationWait = 5 * time.Minute
	// m9ptIslandMargin is the time that the environment island holds beyond the wait, so that no timer of the tool ends it first.
	m9ptIslandMargin = 10 * time.Minute
)

// m9ptClusters are the clusters that the pass rule watches.
var m9ptClusters = []string{"dev-cp", "dev-cell-1", "dev-cell-2"}

// m9ptLiveTTL returns the live SVID lifetime of dev-cp (agent_ttl) from mise run svid-ttl -- show.
func m9ptLiveTTL(t *testing.T) time.Duration {
	t.Helper()
	out, err := miseRun(t, 2*time.Minute, nil, "svid-ttl", "--", "show")
	if err != nil {
		t.Fatalf("mise run svid-ttl -- show: %v\n%s", err, out)
	}
	var res struct {
		Live *string `json:"live"`
	}
	if err := json.Unmarshal([]byte(m9ptLastLine(out)), &res); err != nil || res.Live == nil {
		t.Fatalf("svid-ttl -- show printed %q, want a JSON line with live", out)
	}
	ttl, err := time.ParseDuration(*res.Live)
	if err != nil || ttl <= 0 {
		t.Fatalf("the live agent_ttl %q is no duration: %v", *res.Live, err)
	}
	return ttl
}

func m9ptLastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// m9ptPod is the part of a pod that the pass rule reads.
type m9ptPod struct {
	Cluster, Namespace, Name, UID string
	// Restarts is the restart count of each container, init containers included.
	Restarts map[string]int
}

func (p m9ptPod) key() string { return p.Cluster + "/" + p.Namespace + "/" + p.Name }

// m9ptSnapshot lists the pods of dev-cp, dev-cell-1 and dev-cell-2, except pods with the e2e label and pods in a namespace with it. It
// returns an error and no test failure, so the restart watch can run it from a goroutine.
func m9ptSnapshot(t *testing.T) (map[string]m9ptPod, error) {
	t.Helper()
	snap := map[string]m9ptPod{}
	for _, c := range m9ptClusters {
		nsOut, err := kubectl(t, c, "", "get", "namespaces", "-l", testNamespaceLabel, "-o", "name")
		if err != nil {
			return nil, err
		}
		testNS := map[string]bool{}
		for _, n := range strings.Fields(nsOut) {
			testNS[strings.TrimPrefix(n, "namespace/")] = true
		}
		out, err := kubectl(t, c, "", "get", "pods", "-A", "-o", "json")
		if err != nil {
			return nil, err
		}
		type status struct {
			Name         string `json:"name"`
			RestartCount int    `json:"restartCount"`
		}
		var list struct {
			Items []struct {
				Metadata struct {
					Name, Namespace, UID string
					Labels               map[string]string
					DeletionTimestamp    *string                 `json:"deletionTimestamp"`
					OwnerReferences      []struct{ Kind string } `json:"ownerReferences"`
				} `json:"metadata"`
				Status struct {
					Phase                 string   `json:"phase"`
					ContainerStatuses     []status `json:"containerStatuses"`
					InitContainerStatuses []status `json:"initContainerStatuses"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			return nil, fmt.Errorf("decode the pods of %s: %w", c, err)
		}
		for _, it := range list.Items {
			if _, ok := it.Metadata.Labels[testNamespaceLabel]; ok || testNS[it.Metadata.Namespace] {
				continue
			}
			if it.Metadata.DeletionTimestamp != nil || it.Status.Phase == "Succeeded" || it.Status.Phase == "Failed" ||
				slices.ContainsFunc(it.Metadata.OwnerReferences, func(o struct{ Kind string }) bool { return o.Kind == "Job" }) {
				continue
			}
			p := m9ptPod{Cluster: c, Namespace: it.Metadata.Namespace, Name: it.Metadata.Name, UID: it.Metadata.UID, Restarts: map[string]int{}}
			for _, s := range slices.Concat(it.Status.InitContainerStatuses, it.Status.ContainerStatuses) {
				p.Restarts[s.Name] = s.RestartCount
			}
			snap[p.key()] = p
		}
	}
	return snap, nil
}

func m9ptMustSnapshot(t *testing.T) map[string]m9ptPod {
	t.Helper()
	snap, err := m9ptSnapshot(t)
	if err != nil {
		t.Fatalf("list the pods for the pass rule: %v", err)
	}
	return snap
}

// m9ptWatch samples the pods every m9ptSample, and records when a restart count first rose above its value at the start. The kubelet
// keeps only the last termination, so the sample is the only record of the first restart of a crash loop.
type m9ptWatch struct {
	mu     sync.Mutex
	first  map[string]time.Time
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
	errors int
}

func m9ptStartWatch(t *testing.T, base map[string]m9ptPod) *m9ptWatch {
	t.Helper()
	w := &m9ptWatch{first: map[string]time.Time{}, stop: make(chan struct{}), done: make(chan struct{})}
	t.Cleanup(w.Stop)
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.stop:
				return
			case <-time.After(m9ptSample):
			}
			snap, err := m9ptSnapshot(t)
			w.mu.Lock()
			if err != nil {
				w.errors++
			}
			now := time.Now()
			for key, b := range base {
				for container, n := range snap[key].Restarts {
					id := key + "/" + container
					if _, seen := w.first[id]; !seen && n > b.Restarts[container] {
						w.first[id] = now
					}
				}
			}
			w.mu.Unlock()
		}
	}()
	return w
}

// Stop ends the watch and waits for its goroutine. It is safe to call twice.
func (w *m9ptWatch) Stop() {
	w.once.Do(func() { close(w.stop) })
	<-w.done
}

// Errors returns the number of samples that failed.
func (w *m9ptWatch) Errors() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.errors
}

func (w *m9ptWatch) firstRise(key, container string) time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.first[key+"/"+container]
}

// m9ptAgentExpiry returns the latest SVID expiry of each pod UID that the SPIRE server of dev-cp lists, from the agent IDs
// (/spire/agent/cluster_jwt/<cell>/<pod uid>/<hash> and /spire/agent/k8s_psat/<cluster>/pod/<pod uid>). A banned agent does not count. The
// field is x509svid_expires_at, Unix seconds as a quoted string.
func m9ptAgentExpiry(t *testing.T) (map[string]time.Time, error) {
	t.Helper()
	out, err := spireServerIn(t, spireCluster, "agent", "list", "-socketPath", spireSocket, "-output", "json")
	if err != nil {
		return nil, err
	}
	var res struct {
		Agents []struct {
			ID struct {
				Path string `json:"path"`
			} `json:"id"`
			Expires json.RawMessage `json:"x509svid_expires_at"`
			Banned  bool            `json:"banned"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		return nil, fmt.Errorf("decode agent list: %w", err)
	}
	got := map[string]time.Time{}
	for _, a := range res.Agents {
		if a.Banned {
			continue
		}
		secs, err := strconv.ParseInt(strings.Trim(string(a.Expires), `"`), 10, 64)
		if err != nil {
			continue
		}
		parts := strings.Split(a.ID.Path, "/")
		var uid string
		switch {
		case len(parts) == 7 && parts[3] == "cluster_jwt":
			uid = parts[5]
		case len(parts) == 7 && parts[3] == "k8s_psat" && parts[5] == "pod":
			uid = parts[6]
		default:
			continue
		}
		if at := time.Unix(secs, 0); at.After(got[uid]) {
			got[uid] = at
		}
	}
	return got, nil
}

// m9ptAgentIDs returns the IDs of the live agents that carry a pod UID in their path, sorted.
func m9ptAgentIDs(t *testing.T, uid string) ([]string, error) {
	t.Helper()
	out, err := spireServerIn(t, spireCluster, "agent", "list", "-socketPath", spireSocket, "-output", "json")
	if err != nil {
		return nil, err
	}
	var res struct {
		Agents []struct {
			ID struct {
				Path string `json:"path"`
			} `json:"id"`
			Banned bool `json:"banned"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		return nil, fmt.Errorf("decode agent list: %w", err)
	}
	var ids []string
	for _, a := range res.Agents {
		if !a.Banned && strings.Contains(a.ID.Path, "/"+uid+"/") {
			ids = append(ids, a.ID.Path)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// m9ptPassRule applies the pass rule "no pod restarts" to a window: base is the snapshot at its start, final the one at its end, and
// cutCell the cell that was cut from dev-cp from cutStart to cutEnd. Each pod of base must keep its UID. Every container other than
// spire-agent keeps its restart count. A spire-agent container may restart only in cutCell, only when the cut lasted longer than the
// remaining lifetime of its SVID at the cut (expiry), and never before that SVID expired, with a skew of m9ptSkew. It returns the
// violations and the record of each spire-agent restart.
func m9ptPassRule(base, final map[string]m9ptPod, w *m9ptWatch, cutCell string, cutStart, cutEnd time.Time, expiry map[string]time.Time) (violations, restarts []string) {
	for _, key := range slices.Sorted(func(yield func(string) bool) {
		for k := range base {
			if !yield(k) {
				return
			}
		}
	}) {
		b := base[key]
		f, ok := final[key]
		if !ok {
			violations = append(violations, fmt.Sprintf("%s is gone, it had the UID %s", key, b.UID))
			continue
		}
		if f.UID != b.UID {
			violations = append(violations, fmt.Sprintf("%s has the UID %s, it had %s", key, f.UID, b.UID))
			continue
		}
		for container, n := range f.Restarts {
			delta := n - b.Restarts[container]
			if delta <= 0 {
				continue
			}
			if container != "spire-agent" {
				violations = append(violations, fmt.Sprintf("%s: the container %s restarted %d times", key, container, delta))
				continue
			}
			first := w.firstRise(key, container)
			restarts = append(restarts, fmt.Sprintf("%s: spire-agent restarted %d times, the first seen at %s", key, delta, first.Format(time.RFC3339)))
			exp, known := expiry[b.UID]
			switch {
			case b.Cluster != cutCell:
				violations = append(violations, fmt.Sprintf("%s: spire-agent restarted %d times in %s, which no cut touched. Its SVIDs renew", key, delta, b.Cluster))
			case !known:
				violations = append(violations, fmt.Sprintf("%s: spire-agent restarted, and the SPIRE server listed no SVID expiry for the pod at the cut", key))
			case cutEnd.Sub(cutStart) <= exp.Sub(cutStart):
				violations = append(violations, fmt.Sprintf("%s: spire-agent restarted, although the cut of %s is not longer than the %s that its SVID had left at the cut",
					key, cutEnd.Sub(cutStart).Round(time.Second), exp.Sub(cutStart).Round(time.Second)))
			case first.IsZero():
				violations = append(violations, fmt.Sprintf("%s: spire-agent restarted, and the watch sampled no restart time, so the check against the SVID expiry %s is not possible", key, exp.Format(time.RFC3339)))
			case first.Before(exp.Add(-m9ptSkew)):
				violations = append(violations, fmt.Sprintf("%s: spire-agent restarted at %s, before its SVID expired at %s (skew %s)",
					key, first.Format(time.RFC3339), exp.Format(time.RFC3339), m9ptSkew))
			}
		}
	}
	return violations, restarts
}

// m9ptEcho sends one request from client to echo in a cluster every 3 s, until the returned function is called. The function returns the
// number of requests, the number of failures and the last failure. It uses no t.Fatal, so it is safe in a goroutine.
func m9ptEcho(t *testing.T, cluster string) func() (total, failed int, last string) {
	t.Helper()
	var mu sync.Mutex
	var total, failed int
	var last string
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	end := func() { once.Do(func() { close(stop) }); <-done }
	t.Cleanup(end)
	go func() {
		defer close(done)
		for {
			_, err := kubectl(t, cluster, "", "-n", "apps-demo", "exec", "deploy/client", "-c", "curl", "--", "curl", "-s", "-f", "-o", "/dev/null", "--max-time", "10", "http://echo/hostname")
			mu.Lock()
			total++
			if err != nil {
				failed++
				last = time.Now().Format(time.RFC3339) + ": " + err.Error()
			}
			mu.Unlock()
			select {
			case <-stop:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
	return func() (int, int, string) {
		end()
		mu.Lock()
		defer mu.Unlock()
		return total, failed, last
	}
}

// m9ptGatewayLog returns the cellgw log of the gateway in dev-cp since a time.
func m9ptGatewayLog(t *testing.T, since time.Time) (string, error) {
	t.Helper()
	return kubectl(t, spireCluster, "", "-n", gatewayNamespace, "logs", gatewayPod, "-c", "cellgw", "--since-time="+since.UTC().Format(time.RFC3339))
}

// m9ptCelldLog returns the celld log of the Running celld pod of a cell since a time.
func m9ptCelldLog(t *testing.T, cell string, since time.Time) (string, error) {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+celldDeployment, "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return "", err
	}
	names := strings.Fields(out)
	if len(names) == 0 {
		return "", fmt.Errorf("no celld pod in %s", cell)
	}
	return podLog(t, cell, names[0], celldContainer, since)
}

// m9ptSettled waits until the cell is quiet: a Running celld pod with every container Ready, and one stream at the gateway.
func m9ptSettled(t *testing.T, cell string) {
	t.Helper()
	waitFor(t, cell+" to hold one Ready celld pod and a stream at the gateway", 5*time.Minute, func() (bool, string) {
		pods := celldPods(t, cell)
		if len(pods) != 1 || pods[0].Status.Phase != "Running" {
			return false, fmt.Sprintf("%d celld pods", len(pods))
		}
		for _, c := range pods[0].Status.ContainerStatuses {
			if !c.Ready {
				return false, "container " + c.Name + " is not Ready"
			}
		}
		s := gwStatus(t)
		return s.Streams[cell] >= 1, fmt.Sprintf("streams %v", s.Streams)
	})
}

// m9ptDrops counts the packets that the DROP rules of a cut hold in each chain of the node of a cluster, and the rules in each chain, for
// both IP families. The rules of one tag sit in FORWARD and OUTPUT for the direction out, and in FORWARD and INPUT for in.
//
// The third result holds, for each chain, the source and destination column of each rule as "source>destination".
func m9ptDrops(t *testing.T, cluster, tag string) (packets, rules map[string]int, ends map[string][]string, err error) {
	t.Helper()
	packets, rules, ends = map[string]int{}, map[string]int{}, map[string][]string{}
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, chain := range []string{"FORWARD", "INPUT", "OUTPUT"} {
			out, err := dockerExec(t, cluster+"-control-plane", "", tool, "-nvxL", chain)
			if err != nil {
				return nil, nil, nil, err
			}
			for line := range strings.SplitSeq(out, "\n") {
				if !strings.Contains(line, tag) {
					continue
				}
				f := strings.Fields(line)
				n, perr := strconv.Atoi(f[0])
				if perr != nil || len(f) < 9 {
					return nil, nil, nil, fmt.Errorf("the rule %q has no packet count or no address columns", line)
				}
				ends[chain] = append(ends[chain], f[7]+">"+f[8])
				packets[chain] += n
				rules[chain]++
			}
		}
	}
	return packets, rules, ends, nil
}

// TestM9OneWayPartitions cuts one direction of the link between dev-cell-1 and dev-cp for 3 minutes, first out (packets from the cell to
// dev-cp dropped), then in (packets from dev-cp to the cell dropped). A one-way DROP stops TCP both ways, so each subtest checks the cut
// on each side and the recovery. The failure message of each check names the direction.
//
// Per subtest, with the cut in place:
//   - the DROP rules sit only in the chains of the direction, and their counters show dropped packets;
//   - celld logs "stream ended" within m9ptDetectWait, and the gateway logs stream_closed of the cell within it;
//   - a rotation of the operator key is refused before any secret read (canary commands);
//   - echo traffic in the cell fails no request.
//
// After the heal: celld holds a stream at the gateway within 90 s when the cut is shorter than half the SVID lifetime (1h), else within
// the re-attestation bound of 10 minutes (1m, where the agents of the cell lose their SVIDs). The gateway log of the window holds no
// replica_cap refusal. The pass rule holds over each subtest and over the test (UIDs and containers other than spire-agent): at 1h no pod restarts, and at 1m only the spire-agent containers of the cut
// cell restart, after their SVIDs expired.
func TestM9OneWayPartitions(t *testing.T) {
	const cell = rejectCell
	ttl := m9ptLiveTTL(t)
	t.Logf("the live SVID lifetime of dev-cp is %s", ttl)
	m9ptSettled(t, cell)
	start := m9ptMustSnapshot(t)
	for _, dir := range []string{"out", "in"} {
		t.Run(dir, func(t *testing.T) { m9ptOneWay(t, cell, dir, ttl) })
	}
	t.Run("rotation_refused_in_cell_cut", m9ptCellCutRefusal)
	// The pass rule over the whole test: no pod of the start is replaced, and no container other than spire-agent restarts, also between
	// the windows of the two subtests. The restarts of spire-agent are judged per window, with its cut.
	final := m9ptMustSnapshot(t)
	for key, b := range start {
		f, ok := final[key]
		switch {
		case !ok:
			t.Errorf("pass rule over the test: %s is gone, it had the UID %s", key, b.UID)
		case f.UID != b.UID:
			t.Errorf("pass rule over the test: %s has the UID %s, it had %s", key, f.UID, b.UID)
		default:
			for container, n := range f.Restarts {
				if container != "spire-agent" && n > b.Restarts[container] {
					t.Errorf("pass rule over the test: %s: the container %s restarted %d times", key, container, n-b.Restarts[container])
				}
			}
		}
	}
}

func m9ptOneWay(t *testing.T, cell, dir string, ttl time.Duration) {
	t.Helper()
	what := map[string]string{
		"out": "direction out (packets from " + cell + " to " + spireCluster + " dropped)",
		"in":  "direction in (packets from " + spireCluster + " to " + cell + " dropped)",
	}[dir]
	m9ptSettled(t, cell)

	base := m9ptMustSnapshot(t)
	expiry, err := m9ptAgentExpiry(t)
	if err != nil {
		t.Fatalf("list the agents of the SPIRE server: %v", err)
	}
	watch := m9ptStartWatch(t, base)
	echoStop := m9ptEcho(t, cell)

	cut := cutLink(t, cell, spireCluster, dir, m9ptTimer)
	cutStart := time.Now()
	since := cutStart.Add(-logMargin)
	t.Logf("%s: the cut %s is in place on %s until %s", what, cut.Tag, cut.Node, cut.Until.Format(time.RFC3339))

	// The rules of the direction, and only those.
	wantChains := map[string][]string{"out": {"FORWARD", "OUTPUT"}, "in": {"FORWARD", "INPUT"}}[dir]
	otherChain := map[string]string{"out": "INPUT", "in": "OUTPUT"}[dir]
	_, rules, ends, err := m9ptDrops(t, cell, cut.Tag)
	if err != nil {
		t.Fatalf("%s: read the rules of the cut: %v", what, err)
	}
	for _, c := range wantChains {
		if rules[c] == 0 {
			t.Errorf("%s: the chain %s of %s holds no rule of the cut %s", what, c, cut.Node, cut.Tag)
		}
	}
	if rules[otherChain] != 0 {
		t.Errorf("%s: the chain %s of %s holds %d rules of the cut %s, and a one-way cut must not put a rule there", what, otherChain, cut.Node, rules[otherChain], cut.Tag)
	}

	// The address of dev-cp is the destination of each rule for out, and the source for in.
	v4, v6 := nodeAddrs(t, spireCluster)
	for _, c := range wantChains {
		for _, e := range ends[c] {
			src, dst, _ := strings.Cut(e, ">")
			peer := dst
			if dir == "in" {
				peer = src
			}
			if peer != v4 && peer != v6 {
				t.Errorf("%s: a rule of the cut %s in %s matches %s, want the address of %s (%s or %s) as the %s", what, cut.Tag, c, e, spireCluster, v4, v6,
					map[string]string{"out": "destination", "in": "source"}[dir])
			}
		}
	}
	// Detection on the side of the cell: celld ends its stream.
	waitFor(t, "celld in "+cell+" to log 'stream ended' after the cut of "+what, m9ptDetectWait, func() (bool, string) {
		logs, err := m9ptCelldLog(t, cell, since)
		if err != nil {
			return false, err.Error()
		}
		n := len(matching(logs, func(l logLine) bool { return l.str("msg") == "stream ended" && !lineTime(l).Before(cutStart) }))
		return n > 0, lastLines(logs, 2)
	})
	t.Logf("%s: DETECT_CELL_SECONDS=%.0f", what, time.Since(cutStart).Seconds())
	// Detection on the side of the gateway: it closes the stream of the cell.
	waitFor(t, "the gateway in "+spireCluster+" to log stream_closed of "+cell+" after the cut of "+what, m9ptDetectWait, func() (bool, string) {
		logs, err := m9ptGatewayLog(t, since)
		if err != nil {
			return false, err.Error()
		}
		n := len(matching(logs, func(l logLine) bool {
			return l.str("msg") == "stream_closed" && l.str("cell") == cell && !lineTime(l).Before(cutStart)
		}))
		return n > 0, fmt.Sprintf("streams %v", m9ptStreams(t))
	})
	t.Logf("%s: DETECT_GATEWAY_SECONDS=%.0f", what, time.Since(cutStart).Seconds())
	packets, _, _, err := m9ptDrops(t, cell, cut.Tag)
	if err != nil {
		t.Fatalf("%s: read the counters of the cut: %v", what, err)
	}
	dropped := 0
	for _, c := range wantChains {
		dropped += packets[c]
	}
	if dropped == 0 {
		t.Errorf("%s: the DROP rules of the cut %s in %v of %s dropped no packet, so the cut did not act in that direction", what, cut.Tag, wantChains, cut.Node)
	}
	t.Logf("%s: the rules dropped %d packets (%v)", what, dropped, packets)

	// A rotation of the operator key must refuse while the cut stands, and must read nothing from the secret manager.
	m9ptRotationRefused(t, "the cut of "+what, "a cut of the partition tool is in place")

	// Hold the cut for its full length.
	if wait := m9ptCut - time.Since(cutStart); wait > 0 {
		time.Sleep(wait)
	}
	cut.Heal(t)
	if !cut.healed {
		t.Fatalf("%s: the cut %s is not healed. Run: mise run partition -- heal --all", what, cut.Tag)
	}
	healedAt := time.Now()
	cutLen := healedAt.Sub(cutStart)

	// Recovery: celld streams again.
	bound := m9ptSlowRecover
	if cutLen < ttl/2 {
		bound = m9ptFastRecover
	}
	t.Logf("%s: the cut lasted %s, the SVID lifetime is %s, so the stream must return within %s", what, cutLen.Round(time.Second), ttl, bound)
	var reopenedAt time.Time
	waitFor(t, "the gateway to log stream_open of "+cell+" within "+bound.String()+" of the heal of "+what, bound, func() (bool, string) {
		logs, err := m9ptGatewayLog(t, healedAt.Add(-logMargin))
		if err != nil {
			return false, err.Error()
		}
		for _, l := range matching(logs, func(l logLine) bool { return l.str("msg") == "stream_open" && l.str("cell") == cell }) {
			reopenedAt = lineTime(l)
			break
		}
		s := gwStatus(t)
		return !reopenedAt.IsZero() && s.Streams[cell] >= 1, fmt.Sprintf("streams %v", s.Streams)
	})
	t.Logf("%s: STREAM_BACK_SECONDS=%.0f after the heal", what, reopenedAt.Sub(healedAt).Seconds())

	logs, err := m9ptGatewayLog(t, since)
	if err != nil {
		t.Fatalf("%s: read the gateway log: %v", what, err)
	}
	if strings.Contains(logs, "replica_cap") {
		t.Errorf("%s: the gateway log of the window holds a replica_cap refusal: %v", what,
			matching(logs, func(l logLine) bool { return strings.Contains(fmt.Sprint(l), "replica_cap") }))
	}
	total, failed, last := echoStop()
	if failed > 0 {
		t.Errorf("%s: %d of %d echo requests in %s failed during the window, want none. Last: %s", what, failed, total, cell, last)
	}
	t.Logf("%s: %d echo requests, %d failed", what, total, failed)

	// The pass rule over the window, after the cell is quiet again.
	m9ptSettled(t, cell)
	watch.Stop()
	if n := watch.Errors(); n > 0 {
		t.Logf("%s: %d samples of the restart watch failed", what, n)
	}
	violations, restarts := m9ptPassRule(base, m9ptMustSnapshot(t), watch, cell, cutStart, healedAt, expiry)
	for _, r := range restarts {
		t.Logf("%s: RESTART %s", what, r)
	}
	for _, v := range violations {
		t.Errorf("%s: pass rule: %s", what, v)
	}
	if ttl >= time.Hour && len(restarts) > 0 {
		t.Errorf("%s: at an SVID lifetime of %s no pod may restart, and these restarted: %v", what, ttl, restarts)
	}
}

// m9ptStreams returns the stream counts of the gateway for a failure message, and the error text when the status is unreadable.
func m9ptStreams(t *testing.T) any {
	t.Helper()
	out, err := gwCtlErr("", "status")
	if err != nil {
		return err.Error()
	}
	var s gatewayStatus
	if json.Unmarshal([]byte(out), &s) != nil {
		return out
	}
	return s.Streams
}

// m9ptCanary runs mise run operator:rotate-key with canary commands in place of the secret manager, and returns the output and the error.
// Each canary command touches its own marker file and fails, so a rotation that reaches the secret manager leaves a marker, and cannot
// write a key. POC_ENVRC_LOCAL=/dev/null keeps the script from reading the real settings. The test never runs a real rotation.
func m9ptCanary(t *testing.T, args ...string) (out string, readMarker, writeMarker bool, err error) {
	t.Helper()
	dir := t.TempDir()
	read, write := filepath.Join(dir, "secret-read"), filepath.Join(dir, "secret-write")
	env := []string{
		"POC_SECRET_READ_CMD=touch '" + read + "'; echo 'canary read' >&2; exit 1",
		"POC_SECRET_WRITE_CMD=touch '" + write + "'; echo 'canary write' >&2; exit 1",
		"POC_OPERATOR_KEY=m9-canary",
		"POC_ENVRC_LOCAL=/dev/null",
	}
	run := append([]string{"operator:rotate-key"}, args...)
	if len(args) > 0 {
		run = append([]string{"operator:rotate-key", "--"}, args...)
	}
	out, err = miseRun(t, 5*time.Minute, env, run...)
	_, rerr := os.Stat(read)
	_, werr := os.Stat(write)
	return out, rerr == nil, werr == nil, err
}

// m9ptRotationRefused checks that a rotation of the operator key refuses, with one of the reasons in want, and before any secret read:
// neither canary command ran, and the script printed no rotated line. A refusal for another reason fails the check.
func m9ptRotationRefused(t *testing.T, why string, want ...string) string {
	t.Helper()
	out, read, write, err := m9ptCanary(t)
	if read || write {
		t.Errorf("%s: operator:rotate-key ran the canary secret command (read %v, write %v) before it refused:\n%s", why, read, write, out)
	}
	if err == nil || strings.Contains(out, `"rotated":true`) {
		t.Fatalf("%s: operator:rotate-key must refuse, and it ended with err %v:\n%s", why, err, out)
	}
	if !slices.ContainsFunc(want, func(w string) bool { return strings.Contains(out, w) }) {
		t.Errorf("%s: operator:rotate-key refused for another reason, want one of %q:\n%s", why, want, out)
	}
	return out
}

// m9ptCellCutRefusal: a rotation of the operator key refuses while a cut of the partition tool exists, before it reads
// the secret manager. The cut is between dev-cell-1 and dev-cell-2, which carries no flow of the control plane, so the environment stays
// connected and the cut is the only reason. Canary commands stand in for the secret manager, and a marker file shows any call.
func m9ptCellCutRefusal(t *testing.T) {
	t.Helper()
	cutLink(t, "dev-cell-1", "dev-cell-2", "both", 5*time.Minute)
	out := m9ptRotationRefused(t, "a cut of the partition tool", "a cut of the partition tool is in place")
	t.Logf("refused: %s", m9ptLastLine(out))
	m9ptRotationRefusedEmergency(t)
}

func m9ptRotationRefusedEmergency(t *testing.T) {
	t.Helper()
	out, read, write, err := m9ptCanary(t, "--emergency")
	if read || write {
		t.Errorf("the emergency rotation ran the canary secret command (read %v, write %v) before it refused:\n%s", read, write, out)
	}
	if err == nil || !strings.Contains(out, "a cut of the partition tool is in place") {
		t.Errorf("operator:rotate-key -- --emergency must refuse a cut, and it ended with err %v:\n%s", err, out)
	}
}

// m9ptWhoami returns the IDs and the expiry that cell-proxy of the mesh-view tunnel pod of a cell prints, and the pod UID.
func m9ptWhoami(t *testing.T, cell string) (ids []string, expires time.Time, uid string, err error) {
	t.Helper()
	pod, uid := readyPodIn(t, cell, meshNamespace, tunnelName)
	out, err := kubectl(t, cell, "", "-n", meshNamespace, "exec", pod, "-c", "cell-proxy", "--", "/ko-app/cell-proxy", "whoami")
	if err != nil {
		return nil, time.Time{}, uid, err
	}
	var got struct {
		IDs       []string `json:"ids"`
		ExpiresAt string   `json:"expiresAt"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		return nil, time.Time{}, uid, fmt.Errorf("whoami printed %q: %w", out, err)
	}
	expires, err = time.Parse(time.RFC3339, got.ExpiresAt)
	if err != nil {
		return nil, time.Time{}, uid, fmt.Errorf("whoami expiresAt %q: %w", got.ExpiresAt, err)
	}
	return got.IDs, expires, uid, nil
}

// TestM9KeyRotatedDuringEnvironmentIsland cuts dev-cp from management (the environment island), then rotates the service account key of
// dev-cell-1 with rotateAPIKey. The island cuts only the link from dev-cp to management, and mgmtd reads the keys of a cell through the host
// service on the Mac, so mgmtd can still learn the new key (its periodic key check runs every 15 minutes, connected or not). The record
// that envd holds in dev-cp lists the old key only until the island ends.
//   - new_pods_wait: an attestprobe gets unknown_kid, and still gets it at the end of the island.
//   - running_keep_ids: the celld agent keeps its agent ID and its pod, and the expiry of its SVID in spire-server agent list moves forward
//     after the key change, and so does the expiresAt of the SVID of the mesh-view tunnel. The wait is at most half the lifetime plus 5
//     minutes, and the island holds until then. The agent renews about every half lifetime, so at 1m it renews more than once in that
//     wait. The test requires at least one renewal, and no step back.
//   - operator_rotation_refused: with mgmtd no longer connected, a rotation of the operator key refuses before any secret read.
//   - confirmed_on_reconnect: mgmtd has updated the record, inside the island through its periodic check (at 1h the island lasts longer
//     than the 15 minutes of the check) or after the heal through the hint path. After the heal envd and the gateway hold the new
//     record, and the probe attests, within 5 minutes of the heal.
//
// The cleanup repairAPIServer replaces the pods that carry a token of the test key, so the test claims no pass rule. The heal of the
// island is deferred right after the cut, so it runs before every cleanup, also after a t.Fatal, and so before the repair, which needs a
// connected environment.
func TestM9KeyRotatedDuringEnvironmentIsland(t *testing.T) {
	const cell = rejectCell
	ttl := m9ptLiveTTL(t)
	wait := ttl/2 + m9ptRotationWait
	t.Logf("the live SVID lifetime is %s, so the island waits at most %s", ttl, wait)

	// A key check first: the record holds the keys that the API server publishes, and the periodic check is 15 minutes away.
	checked := requireCurrentRecord(t, cell)
	m9ptSettled(t, cell)
	pods := celldPods(t, cell)
	celldUID := pods[0].Metadata.UID
	agentIDs, err := m9ptAgentIDs(t, celldUID)
	if err != nil || len(agentIDs) == 0 {
		t.Fatalf("the SPIRE server lists no agent for the celld pod %s of %s: %v", celldUID, cell, err)
	}
	_, _, tunnelUID, err := m9ptWhoami(t, cell)
	if err != nil {
		t.Fatalf("cell-proxy whoami in the tunnel pod of %s: %v", cell, err)
	}
	before := cellStatusOf(t, cell)
	if len(before.Kids) != 1 {
		t.Fatalf("the record of %s lists the key IDs %v, want one", cell, before.Kids)
	}
	waitRegistryAtCleanup(t)

	island := cutLink(t, spireCluster, mgmtCluster, "both", wait+m9ptIslandMargin)
	defer island.Heal(t)
	since := time.Now().Add(-logMargin)
	t.Logf("the environment island %s is in place until %s", island.Tag, island.Until.Format(time.RFC3339))
	waitUpdateGap(t, checked)

	oldKID, newKID := rotateAPIKey(t, cell)
	rotatedAt := time.Now()
	// The baselines of the renewal checks are read at the key change, before the first subtest.
	tunnelIDs0, tunnelExpiry0, _, err := m9ptWhoami(t, cell)
	if err != nil {
		t.Fatalf("cell-proxy whoami in the tunnel pod of %s: %v", cell, err)
	}
	agentExpiry0, err := m9ptAgentExpiry(t)
	if err != nil {
		t.Fatalf("list the agents: %v", err)
	}
	a0 := agentExpiry0[celldUID]
	if a0.IsZero() {
		t.Fatalf("the SPIRE server lists no SVID expiry for the celld pod %s", celldUID)
	}
	t.Logf("the API server of %s signs with %s and verifies %s too", cell, newKID, oldKID)

	t.Run("new_pods_wait", func(t *testing.T) {
		res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
		expectRefusal(t, res, cell, "unknown_kid", []string{newKID})
	})

	t.Run("running_keep_ids", func(t *testing.T) {
		var agentMoved, tunnelMoved bool
		var stepBack []string
		agentLast, tunnelLast := a0, tunnelExpiry0
		waitFor(t, "the SVID expiry of the celld agent and of the tunnel to move forward after the key change, with the island held", max(time.Until(rotatedAt.Add(wait)), 30*time.Second), func() (bool, string) {
			all, err := m9ptAgentExpiry(t)
			if err != nil {
				return false, err.Error()
			}
			got, listed := all[celldUID]
			if !listed {
				return false, "the SPIRE server lists no live agent for the celld pod " + celldUID
			}
			if got.Before(agentLast) {
				if len(stepBack) == 0 {
					stepBack = append(stepBack, fmt.Sprintf("the SVID expiry of the celld agent moved back, from %s to %s", agentLast, got))
				}
			} else if got.After(a0) {
				agentMoved, agentLast = true, got
			}
			ids, tunnelNow, _, err := m9ptWhoami(t, cell)
			if err != nil {
				return false, err.Error()
			}
			if !slices.Equal(ids, tunnelIDs0) {
				return false, fmt.Sprintf("the tunnel IDs are %v, were %v", ids, tunnelIDs0)
			}
			if tunnelNow.Before(tunnelLast) {
				if len(stepBack) < 2 {
					stepBack = append(stepBack, fmt.Sprintf("the expiresAt of the tunnel SVID moved back, from %s to %s", tunnelLast, tunnelNow))
				}
			} else if tunnelNow.After(tunnelExpiry0) {
				tunnelMoved, tunnelLast = true, tunnelNow
			}
			return agentMoved && tunnelMoved, fmt.Sprintf("agent expiry %s (was %s), tunnel expiry %s (was %s)", agentLast, a0, tunnelLast, tunnelExpiry0)
		})
		for _, m := range stepBack {
			t.Error(m)
		}
		t.Logf("RENEWED_SECONDS=%.0f after the key change", time.Since(rotatedAt).Seconds())
		ids, err := m9ptAgentIDs(t, celldUID)
		if err != nil {
			t.Fatalf("list the agents: %v", err)
		}
		if !slices.Equal(ids, agentIDs) {
			t.Errorf("the agent IDs of the celld pod %s are %v after the key change, and were %v before it", celldUID, ids, agentIDs)
		}
		logs, err := serverLog(t, since)
		if err != nil {
			t.Fatal(err)
		}
		if again := matching(logs, func(l logLine) bool {
			return l.str("msg") == attestDone && strings.Contains(l.str("agent_id"), "/"+celldUID+"/")
		}); len(again) > 0 {
			t.Errorf("the server attested the running celld pod again after the key change: %v", again)
		}
		if got := celldPods(t, cell); len(got) != 1 || got[0].Metadata.UID != celldUID {
			t.Errorf("the celld pod of %s is not the pod %s of the start", cell, celldUID)
		}
		if _, _, got, err := m9ptWhoami(t, cell); err != nil || got != tunnelUID {
			t.Errorf("the tunnel pod of %s has the UID %q (error %v), want %s", cell, got, err, tunnelUID)
		}
	})

	t.Run("new_pods_still_wait", func(t *testing.T) {
		if out, err := miseRun(t, m9CutBound, nil, "partition", "--", "list"); err != nil || !strings.Contains(out, island.Tag) {
			t.Fatalf("the environment island %s is not in place any more (error %v):\n%s", island.Tag, err, out)
		}
		res := runAttestProbe(t, probe{cell: cell, namespace: celldNamespace, account: celldAccount, variant: "good"})
		expectRefusal(t, res, cell, "unknown_kid", []string{newKID})
	})

	t.Run("operator_rotation_refused", func(t *testing.T) {
		// mgmtd counts the environment as connected for 2 minutes after the last report of envd, so the check waits for the cut to age.
		var out string
		waitFor(t, "operator:rotate-key to refuse because the environment is not connected", 5*time.Minute, func() (bool, string) {
			o, read, write, err := m9ptCanary(t)
			if read || write {
				t.Fatalf("operator:rotate-key ran the canary secret command (read %v, write %v) before it refused:\n%s", read, write, o)
			}
			if err == nil {
				t.Fatalf("operator:rotate-key must refuse during the environment island:\n%s", o)
			}
			out = o
			return strings.Contains(o, "needs a connected environment"), m9ptLastLine(o)
		})
		t.Logf("refused: %s", m9ptLastLine(out))
	})

	t.Run("confirmed_on_reconnect", func(t *testing.T) {
		// mgmtd may have updated the record already: its periodic key check ignores the connection of the environment.
		inIsland, _, err := keysUpdatedLines(t, since, cell)
		if err != nil {
			t.Fatalf("read the mgmtd log: %v", err)
		}
		island.Heal(t)
		if !island.healed {
			t.Fatalf("the environment island %s is not healed. Run: mise run partition -- heal --all", island.Tag)
		}
		healedAt := time.Now()
		deadline := healedAt.Add(healWait)
		var updated logLine
		for _, l := range inIsland {
			if updated == nil || lineTime(l).Before(lineTime(updated)) {
				updated = l
			}
		}
		if updated != nil && lineTime(updated).Before(healedAt) {
			if via := updated.str("via"); via != "periodic" {
				t.Errorf("mgmtd updated the record of %s inside the island through %q, want the periodic check, because the hint path needs dev-cp", cell, via)
			}
		} else {
			waitFor(t, "the mgmtd log to hold a key update of "+cell+" after the heal of the island", max(time.Until(deadline), 30*time.Second), func() (bool, string) {
				lines, _, err := keysUpdatedLines(t, since, cell)
				if err != nil {
					return false, err.Error()
				}
				if len(lines) == 0 {
					return false, "no keys_updated line yet"
				}
				updated = lines[0]
				return true, ""
			})
		}
		path := updated.str("msg")
		if via := updated.str("via"); via != "" {
			path += "/" + via
		}
		t.Logf("KEYS_UPDATED_BY=%s, %.0f s after the heal (negative: inside the island)", path, lineTime(updated).Sub(healedAt).Seconds())
		after := cellStatusOf(t, cell)
		if !slices.Contains(after.Kids, oldKID) || !slices.Contains(after.Kids, newKID) || !afterRevision(after.Record, before.Record) {
			t.Errorf("mgmtd holds the record of %s with the key IDs %v at %+v, want %s and %s at a revision after %+v", cell, after.Kids, after.Record, oldKID, newKID, before.Record)
		}
		// The dev-cp side takes the record: envd holds it, and the gateway holds its revision.
		waitFor(t, "envd and the gateway in dev-cp to hold the new record of "+cell+" within 5 minutes of the heal", max(time.Until(deadline), 30*time.Second), func() (bool, string) {
			_, cells, err := readLiveRecords(t)
			if err != nil {
				return false, err.Error()
			}
			c, ok := cells[cell]
			if !ok {
				return false, "cell-records holds no record of " + cell
			}
			kids, err := jwksKIDs(c.JWKS)
			if err != nil {
				return false, err.Error()
			}
			if !slices.Contains(kids, oldKID) || !slices.Contains(kids, newKID) {
				return false, fmt.Sprintf("envd holds the key IDs %v", kids)
			}
			want := spec.Revision{Epoch: c.Epoch, Counter: c.Counter}
			s := gwStatus(t)
			if got := s.Records[cell]; got != want {
				return false, fmt.Sprintf("the gateway holds %+v, envd holds %+v", got, want)
			}
			return true, ""
		})
		waitIssued(t, cell, max(time.Until(deadline), 30*time.Second))
	})
}
