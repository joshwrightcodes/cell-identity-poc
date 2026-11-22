//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const (
	islandCell        = "dev-cell-2" // the cell island: dev-cell-2 cut from dev-cp
	witnessCell       = "dev-cell-1" // stays connected, and is the witness of the environment island
	m9RestartPoll     = 10 * time.Second
	m9MinuteRetry     = 10 * time.Second
	m9ReattestWithin  = 10 * time.Minute
	m9ValidWithin     = 5 * time.Minute
	m9DrainWithin     = 10 * time.Minute
	m9ResultsWithin   = 10 * time.Minute
	m9TelemetryWithin = 30 * time.Minute
	// m9TelemetryFresh is the age that the newest sample of a cluster may have once telemetry flows again.
	m9TelemetryFresh = "now-3m"
)

// m9Finding is a problem that a goroutine of the run saw. The test reports it once, with the time of its first sight and its count.
type m9Finding struct {
	Text  string
	First time.Time
	Count int
}

// m9Op is one signed operation of the run.
type m9Op struct {
	Name     string
	Cell     string
	ID       string
	SignedAt time.Time
}

// m9Run is the state of one run of TestM9IslandsHold. The goroutines share it through mu.
type m9Run struct {
	t    *testing.T
	ttl  time.Duration
	plan m9Plan

	stop      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	opsWG     sync.WaitGroup
	envHealed chan struct{}

	sampler *sampler

	mu           sync.Mutex
	phase        string
	findings     []*m9Finding
	ops          []m9Op
	restartLog   map[string]int // pod key and container -> last restart count seen
	firstRst     map[string]time.Time
	restartSeen  []string
	whoamiErrs   []string
	envHealedOK  bool
	envHealedAt  time.Time
	outboxAtHeal int
	outboxOldest time.Time

	// The baseline, read before the first cut.
	base       map[string][]m9Pod
	baseApps   map[string]map[string]m9App
	baseState  map[string]bundleapply.State
	baseRecs   string
	baseGwRecs string
	baseTrust  m9Trust
	baseQueue  map[string]int

	cellCutAt  time.Time
	cellHealAt time.Time
	envCutAt   time.Time
	cutExpiry  map[string]time.Time       // agent SVID expiry at the cell cut, by pod key
	cutAgents  map[string]map[string]bool // every agent ID of a pod of the cut cell at the cut
	renewals   *m9Renewals
}

// m9Trust is what a run must leave as it was: the trust bundles of the SPIRE servers, and the issuer, the keys and the record revision of each
// cell at mgmtd.
type m9Trust struct {
	Bundles map[string]string
	Cells   map[string]string
}

func (r *m9Run) setPhase(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phase = p
	r.t.Logf("phase %s", p)
}

func (r *m9Run) phaseName() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.phase
}

// find records a problem. The same text counts once, and the test reports its first time and its count.
func (r *m9Run) find(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.findings {
		if f.Text == text {
			f.Count++
			return
		}
	}
	r.findings = append(r.findings, &m9Finding{Text: text, First: time.Now(), Count: 1})
	r.t.Logf("finding: %s", text)
}

func (r *m9Run) stopBackground() {
	r.stopOnce.Do(func() { close(r.stop) })
	r.wg.Wait()
	r.opsWG.Wait()
}

// sleepUntil waits until the time or until the run stops. It returns false when the run stopped.
func (r *m9Run) sleepUntil(at time.Time) bool {
	select {
	case <-r.stop:
		return false
	case <-time.After(time.Until(at)):
		return true
	}
}

func (r *m9Run) since(at time.Time) string { return time.Since(at).Round(time.Second).String() }

// TestM9IslandsHold holds both island levels for three SVID lifetimes. The cell island cuts dev-cell-2 from dev-cp. The environment island
// starts one minute later and cuts dev-cp from management (Controller call 2). dev-cell-1 stays connected to dev-cp and is the witness of the
// environment island.
//
// The pass rule: no pod is replaced, customer traffic keeps working, no container but spire-agent restarts, and a spire-agent restarts only in
// a cut cell after its SVID expired (R1, rows 749 and 750). Restarts of agent sidecars are allowed and recorded.
func TestM9IslandsHold(t *testing.T) {
	r := &m9Run{t: t, stop: make(chan struct{}), envHealed: make(chan struct{}), phase: "setup",
		restartLog: map[string]int{}, firstRst: map[string]time.Time{}}
	defer r.stopBackground()
	// The signed operations go final or closed even after a failure. Cleanups run last in, first out, and this one runs after the heals.
	t.Cleanup(func() { r.closeOps() })
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the run failed. If a cut or the SVID lifetime may be left over, run: mise run gate:m9:repair -- --check, then mise run gate:m9:repair. " +
				"The tags of the cuts are in build/gate/m9-cuts, and the samples are in build/gate/m9-samples.jsonl")
		}
	})

	conf, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "configmap", "spire-server", "-o", `jsonpath={.data.server\.conf}`)
	if err != nil {
		t.Fatalf("read server.conf of %s: %v", spireCluster, err)
	}
	r.ttl, err = time.ParseDuration(agentTTL(conf))
	if err != nil || r.ttl < 30*time.Second {
		t.Fatalf("the live agent_ttl of %s is %q, which is no lifetime of 30 s or more: %v", spireCluster, agentTTL(conf), err)
	}
	r.plan = m9PlanFor(r.ttl)
	if bad := r.plan.problems(m9MaxSignLead); len(bad) > 0 {
		t.Fatalf("the schedule for the lifetime %s does not fit the lifetime of an operation: %v", r.ttl, bad)
	}
	r.renewals = newM9Renewals(r.ttl/2 + 5*time.Minute)
	t.Logf("SVID lifetime %s: cell island %s, environment island %s, held operations at +%s and +%s after the environment cut, operation for %s at +%s after the cell cut",
		r.ttl, r.plan.CellHold, r.plan.EnvHold, r.plan.FirstOpAfter, r.plan.SecondOpAfter, islandCell, r.plan.CellOpAfter)

	r.sampler = startSampler(t, r.phaseName)
	r.readBaseline()

	// Sign the two operations for the witness cell before any cut. They stay in memory, and nothing writes them to a file.
	type held struct {
		name     string
		id       string
		envelope []byte
		signedAt time.Time
	}
	var helds []held
	for _, name := range []string{"held-1", "held-2"} {
		id, env, err := m9SignOp(witnessCell, "m9 island "+name+" "+randomHex(t, 3), m9OpTTL)
		if err != nil {
			t.Fatal(err)
		}
		helds = append(helds, held{name, id, env, time.Now()})
		r.addOp(m9Op{Name: name, Cell: witnessCell, ID: id, SignedAt: time.Now()})
	}

	// The cell island.
	cellCut := cutLink(t, islandCell, spireCluster, "both", r.plan.CellHold)
	r.cellCutAt = time.Now()
	if lead := r.cellCutAt.Sub(helds[0].signedAt); lead > m9MaxSignLead {
		t.Fatalf("%s passed between signing the held operations and the cell cut, over %s, so the second would expire before its enqueue", lead.Round(time.Second), m9MaxSignLead)
	}
	r.readCutExpiry()
	r.setPhase("cell-island")
	r.startWatchers()

	r.opsWG.Add(1)
	go r.runCellOp()

	// The environment island, one minute later.
	if !r.sleepUntil(r.cellCutAt.Add(r.plan.EnvCutAfter)) {
		return
	}
	envCut := cutLink(t, spireCluster, mgmtCluster, "both", r.plan.EnvHold)
	r.envCutAt = time.Now()
	r.setPhase("both-islands")
	r.opsWG.Add(1)
	go r.runHeldOps(helds[0].id, helds[0].envelope, helds[0].signedAt, helds[1].id, helds[1].envelope, helds[1].signedAt)
	r.wg.Add(1)
	go r.healEnvironmentAt(envCut)

	// The cell island ends at its hold. The goroutines go on in the environment island.
	if !r.sleepUntil(r.cellCutAt.Add(r.plan.CellHold)) {
		return
	}
	cellCut.Heal(t)
	r.cellHealAt = time.Now()
	r.setPhase("environment-island")
	t.Logf("healed the cell island of %s after %s", islandCell, r.since(r.cellCutAt))
	r.observeRestarts()

	cellID := r.opID("cell")
	t.Run("svids_lapse", r.subSVIDsLapse)
	t.Run("reattest", r.subReattest)
	t.Run("stream_back", func(t *testing.T) {
		waitFor(t, "a stream of "+islandCell+" at the gateway", m5Wait, func() (bool, string) {
			out, err := gwCtlErr("", "status")
			if err != nil {
				return false, err.Error()
			}
			var s mgmtapi.GatewayStatus
			if err := json.Unmarshal([]byte(out), &s); err != nil {
				return false, err.Error()
			}
			return s.Streams[islandCell] >= 1, fmt.Sprintf("streams %v", s.Streams)
		})
	})
	t.Run("queued_work", func(t *testing.T) {
		if cellID == "" {
			t.Fatalf("the operation for %s was never signed or enqueued: see the findings of the run", islandCell)
		}
		waitFor(t, "the operation "+cellID+" to be applied in "+islandCell, 5*time.Minute, func() (bool, string) {
			n := demoLogCount(t, islandCell, cellID)
			return n == 1, fmt.Sprintf("demo-log holds %d lines of it", n)
		})
		t.Logf("the record op-%s in %s is in the state %q", cellID, islandCell, opRecordState(t, islandCell, cellID))
	})

	// The environment island ends at its hold.
	select {
	case <-r.envHealed:
	case <-time.After(time.Until(r.envCutAt.Add(r.plan.EnvHold)) + 5*time.Minute):
		t.Fatal("the environment island did not heal within 5 minutes of its hold")
	}
	r.mu.Lock()
	healed := r.envHealedOK
	r.mu.Unlock()
	if !healed {
		t.Fatal("the environment island was not healed, so the reconnect checks cannot run. Run: mise run gate:m9:repair")
	}
	r.setPhase("reconnect")
	r.opsWG.Wait()

	t.Run("cells_valid", r.subCellsValid)
	t.Run("drain", r.subDrain)
	t.Run("results_recorded", r.subResultsRecorded)
	t.Run("no_trust_change", r.subNoTrustChange)
	t.Run("no_pod_restarts", r.subNoPodRestarts)
	t.Run("no_sleep", func(t *testing.T) {
		gaps := r.sampler.Gaps()
		var longest time.Duration
		for _, g := range gaps {
			longest = max(longest, g)
		}
		t.Logf("%d samples, longest gap %s", r.sampler.Count(), longest.Round(time.Second))
		if err := m9SleepGapError(gaps, m9SleepGap); err != nil {
			t.Error(err)
		}
	})
	t.Run("telemetry_resumes", r.subTelemetry)

	r.stopBackground()
	r.reportFindings()
	r.logQueues()
}

// addOp records a signed operation.
func (r *m9Run) addOp(o m9Op) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, o)
}

// opID returns the ID of the operation with the name, or "".
func (r *m9Run) opID(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.ops {
		if o.Name == name {
			return o.ID
		}
	}
	return ""
}

// closeOps closes every operation of the run that mgmtd still holds open, so that none is left for the cell to apply later.
func (r *m9Run) closeOps() {
	r.mu.Lock()
	ops := slices.Clone(r.ops)
	r.mu.Unlock()
	for _, o := range ops {
		out, err := mgmtCtlErr("op", "get", o.ID)
		if err != nil {
			r.t.Logf("could not read the operation %s: %v", o.ID, err)
			continue
		}
		var v opState
		if json.Unmarshal([]byte(out), &v) == nil && v.State == "final" {
			continue
		}
		if _, err := mgmtCtlErr("op", "close", o.ID); err != nil {
			r.t.Logf("could not close the operation %s: %v", o.ID, err)
		}
	}
}

// readBaseline records what the pass rule and the checks compare with. It runs before any cut, and it fails the test when the start is not
// healthy.
func (r *m9Run) readBaseline() {
	t := r.t
	t.Helper()
	r.base, r.baseApps, r.baseState, r.baseQueue = map[string][]m9Pod{}, map[string]map[string]m9App{}, map[string]bundleapply.State{}, map[string]int{}
	for _, c := range m9ClusterList() {
		pods, err := m9ListPods(t, c)
		if err != nil {
			t.Fatalf("read the pods of %s: %v", c, err)
		}
		r.base[c] = pods
		apps, err := m9ListApps(t, c)
		if err != nil {
			t.Fatalf("read the Applications of %s: %v", c, err)
		}
		r.baseApps[c] = apps
		st, err := m9ReadState(t, c)
		if err != nil {
			t.Fatalf("read the bundle state of %s: %v", c, err)
		}
		r.baseState[c] = st
		if bad := r.appProblems(c, apps, st, true); len(bad) > 0 {
			t.Fatalf("the Applications of %s are not Synced and Healthy at the state root before the cut: %v", c, bad)
		}
		if kb, err := m9QueueKB(c); err == nil {
			r.baseQueue[c] = kb
		} else {
			t.Logf("collector queue of %s: %v", c, err)
		}
	}
	var err error
	if r.baseRecs, err = m9RecordsCM(t); err != nil {
		t.Fatalf("read the records ConfigMap: %v", err)
	}
	if r.baseGwRecs, err = m9GatewayRecords(); err != nil {
		t.Fatalf("read the gateway status: %v", err)
	}
	if r.baseTrust, err = m9SnapTrust(t); err != nil {
		t.Fatalf("read the trust state: %v", err)
	}
	if err := m9EnvdReady(t); err != nil {
		t.Fatalf("envd is not Ready before the cut: %v", err)
	}
	if r.base[islandCell] == nil || len(r.base[witnessCell]) == 0 {
		t.Fatalf("no pods in %s or %s", islandCell, witnessCell)
	}
	t.Logf("baseline: %d, %d and %d pods in %v", len(r.base[spireCluster]), len(r.base[witnessCell]), len(r.base[islandCell]), m9ClusterList())
}

// readCutExpiry records the expiry of each agent SVID of the cell island, from spire-server agent list, and every agent ID of its pods. It
// reads right after the cut, because an agent cannot renew from then on, so the list holds the SVID that each agent has held since the cut.
func (r *m9Run) readCutExpiry() {
	t := r.t
	t.Helper()
	agents, err := m9AgentList(t)
	if err != nil {
		t.Fatalf("read the agent list at the cut: %v", err)
	}
	r.cutExpiry, r.cutAgents = map[string]time.Time{}, map[string]map[string]bool{}
	for key, a := range m9AgentsByPod(agents, r.base[islandCell]) {
		r.cutExpiry[key] = a.Expires
		ids := map[string]bool{}
		for _, p := range a.Paths {
			ids[p] = true
		}
		r.cutAgents[key] = ids
		t.Logf("agent SVID of %s expires %s, %s after the cut", key, a.Expires.Format(time.RFC3339), a.Expires.Sub(r.cellCutAt).Round(time.Second))
	}
	if len(r.cutExpiry) == 0 {
		t.Fatalf("spire-server agent list holds no agent of a pod of %s", islandCell)
	}
}

// startWatchers starts the minute checks and the restart observer. The minute checks end when the environment island is healed.
func (r *m9Run) startWatchers() {
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		for next := time.Now(); ; next = next.Add(time.Minute) {
			if !r.sleepUntil(next) {
				return
			}
			select {
			case <-r.envHealed:
				return
			default:
			}
			r.minuteChecks()
		}
	}()
	go func() {
		defer r.wg.Done()
		for {
			r.observeRestarts()
			if !r.sleepUntil(time.Now().Add(m9RestartPoll)) {
				return
			}
		}
	}()
}

// observeRestarts reads the pods of the three clusters and records each rise of a restart count, with the time of the last termination. A
// read every 10 seconds sees the first restart of a container that crash-loops under back-off, so the time is that of the first one.
func (r *m9Run) observeRestarts() {
	for _, c := range m9ClusterList() {
		pods, err := m9ListPods(r.t, c)
		if err != nil {
			continue
		}
		now := time.Now()
		r.mu.Lock()
		for _, p := range pods {
			for name, ct := range p.Containers {
				k := p.Key() + "/" + name
				prev, known := r.restartLog[k]
				if !known {
					if b := m9BaseContainer(r.base[c], p, name); b != nil {
						prev = b.Restarts
					} else {
						prev = ct.Restarts
					}
				}
				if ct.Restarts > prev {
					at := ct.Finished
					if at.IsZero() || at.After(now) {
						at = now
					}
					if _, ok := r.firstRst[k]; !ok {
						r.firstRst[k] = at
					}
					r.restartSeen = append(r.restartSeen, fmt.Sprintf("%s restarted at %s (count %d, seen %s)", k, at.UTC().Format(time.RFC3339), ct.Restarts, now.UTC().Format(time.RFC3339)))
				}
				r.restartLog[k] = ct.Restarts
			}
		}
		r.mu.Unlock()
	}
}

// m9BaseContainer returns the baseline state of a container of a pod with the same UID, or nil.
func m9BaseContainer(base []m9Pod, p m9Pod, name string) *m9Container {
	for _, b := range base {
		if b.Key() == p.Key() && b.UID == p.UID {
			if c, ok := b.Containers[name]; ok {
				return &c
			}
		}
	}
	return nil
}

// minuteChecks runs the checks of one minute, in both islands. Each failed check is read again after 10 seconds before it counts.
func (r *m9Run) minuteChecks() {
	retry := func(f func() []string) {
		bad := f()
		if len(bad) > 0 {
			if !r.sleepUntil(time.Now().Add(m9MinuteRetry)) {
				return
			}
			bad = f()
		}
		for _, b := range bad {
			r.find(b)
		}
	}
	t := r.t
	for _, c := range []string{witnessCell, islandCell} {
		retry(func() []string {
			if err := m9Echo(t, c); err != nil {
				return []string{fmt.Sprintf("customer traffic in %s failed: %v", c, m9Short(err.Error()))}
			}
			return nil
		})
	}
	for _, c := range m9ClusterList() {
		retry(func() []string {
			apps, err := m9ListApps(t, c)
			if err != nil {
				return []string{fmt.Sprintf("read the Applications of %s: %v", c, m9Short(err.Error()))}
			}
			st, err := m9ReadState(t, c)
			if err != nil {
				return []string{fmt.Sprintf("read the bundle state of %s: %v", c, m9Short(err.Error()))}
			}
			return r.appProblems(c, apps, st, false)
		})
	}
	retry(func() []string {
		if err := m9EnvdReady(t); err != nil {
			return []string{"envd is not Ready: " + m9Short(err.Error())}
		}
		return nil
	})
	retry(func() []string {
		var bad []string
		if got, err := m9RecordsCM(t); err != nil {
			bad = append(bad, "read the records ConfigMap: "+m9Short(err.Error()))
		} else if got != r.baseRecs {
			bad = append(bad, "the records ConfigMap spire-system/cell-records changed during the islands")
		}
		if got, err := m9GatewayRecords(); err != nil {
			bad = append(bad, "read the gateway status: "+m9Short(err.Error()))
		} else if got != r.baseGwRecs {
			bad = append(bad, fmt.Sprintf("the record revisions at the gateway changed from %s to %s", r.baseGwRecs, got))
		}
		return bad
	})
	r.renewalChecks()
	r.recordIslandCell()
}

// renewalChecks covers dev-cp and dev-cell-1 (row 749): the agent SVIDs and the SVID of the tunnel renew, so each has more than a quarter of the
// lifetime left, and each expiry moves forward at least once in half a lifetime plus 5 minutes.
func (r *m9Run) renewalChecks() {
	t := r.t
	now := time.Now()
	agents, err := m9AgentList(t)
	if err != nil {
		r.find("read the agent list: " + m9Short(err.Error()))
		return
	}
	for _, c := range []string{spireCluster, witnessCell} {
		pods, err := m9ListPods(t, c)
		if err != nil {
			r.find(fmt.Sprintf("read the pods of %s: %v", c, m9Short(err.Error())))
			continue
		}
		by := m9AgentsByPod(agents, pods)
		for _, key := range sortedKeys(by) {
			a := by[key]
			if !m9RemainingOK(a.Expires, now, r.ttl) {
				r.find(fmt.Sprintf("the agent SVID of %s has %s left, not above a quarter of the lifetime %s (row 749)", key, a.Expires.Sub(now).Round(time.Second), r.ttl))
			}
			if p := r.renewals.observe("agent "+key, a.Expires, now); p != "" {
				r.find("agent " + p + " (row 749)")
			}
		}
	}
	w := m9Whoami(t, witnessCell)
	switch exp, perr := time.Parse(time.RFC3339, w.ExpiresAt); {
	case w.Err != "":
		r.find(fmt.Sprintf("whoami of the tunnel in %s failed: %s (row 749)", witnessCell, w.Err))
	case perr != nil:
		r.find(fmt.Sprintf("whoami of the tunnel in %s gave the expiry %q", witnessCell, w.ExpiresAt))
	default:
		if !m9RemainingOK(exp, now, r.ttl) {
			r.find(fmt.Sprintf("the SVID of the tunnel in %s has %s left, not above a quarter of the lifetime %s (row 749)", witnessCell, exp.Sub(now).Round(time.Second), r.ttl))
		}
		if p := r.renewals.observe("whoami "+witnessCell, exp, now); p != "" {
			r.find(p + " (row 749)")
		}
	}
}

// recordIslandCell records, for dev-cell-2 (row 750, R1), each whoami error. The restarts come from the restart observer. None of it fails a
// check, because the design allows an agent that cannot renew to exit.
func (r *m9Run) recordIslandCell() {
	w := m9Whoami(r.t, islandCell)
	if w.Err == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.whoamiErrs = append(r.whoamiErrs, fmt.Sprintf("%s whoami of the tunnel in %s: %s", time.Now().UTC().Format(time.RFC3339), islandCell, w.Err))
}

// appProblems lists what is wrong with the Applications of a cluster at its bundle state. Each Application must be Synced and Healthy, and the
// component Applications must sit at the digests of the state root. With strict false, it also compares with the baseline: the same UIDs, the
// same state root, and no Application that went away.
func (r *m9Run) appProblems(cluster string, apps map[string]m9App, st bundleapply.State, baseline bool) []string {
	var bad []string
	for _, name := range sortedKeys(apps) {
		a := apps[name]
		if a.Sync != "Synced" || a.Health != "Healthy" {
			bad = append(bad, fmt.Sprintf("in %s, Application %s is %s/%s, want Synced/Healthy", cluster, name, a.Sync, a.Health))
		}
		if b, ok := r.baseApps[cluster][name]; ok && !baseline && b.UID != a.UID {
			bad = append(bad, fmt.Sprintf("in %s, Application %s has the UID %s, and it had %s", cluster, name, a.UID, b.UID))
		}
	}
	if !baseline {
		for name := range r.baseApps[cluster] {
			if _, ok := apps[name]; !ok {
				bad = append(bad, fmt.Sprintf("in %s, Application %s is gone", cluster, name))
			}
		}
		if b := r.baseState[cluster]; b.Root.Digest != st.Root.Digest {
			bad = append(bad, fmt.Sprintf("in %s, the state root changed from %s to %s", cluster, b.Root.Digest, st.Root.Digest))
		}
	}
	for _, name := range sortedKeys(st.Components) {
		if a, ok := apps[name]; !ok {
			bad = append(bad, fmt.Sprintf("in %s, the component %s has no Application", cluster, name))
		} else if a.Revision != st.Components[name] {
			bad = append(bad, fmt.Sprintf("in %s, Application %s is at %s, want the digest %s of the state root", cluster, name, a.Revision, st.Components[name]))
		}
	}
	if st.Root.Digest != "" {
		if a, ok := apps["root"]; ok && a.Revision != st.Root.Digest {
			bad = append(bad, fmt.Sprintf("in %s, Application root is at %s, want %s", cluster, a.Revision, st.Root.Digest))
		}
	}
	return bad
}

// runHeldOps enqueues the two operations that were signed before the cut, at their times after the environment cut, and waits for each result in
// the outbox of the gateway. The envelopes live in this goroutine only.
func (r *m9Run) runHeldOps(id1 string, env1 []byte, signed1 time.Time, id2 string, env2 []byte, signed2 time.Time) {
	defer r.opsWG.Done()
	for i, h := range []struct {
		id     string
		env    []byte
		signed time.Time
		after  time.Duration
	}{{id1, env1, signed1, r.plan.FirstOpAfter}, {id2, env2, signed2, r.plan.SecondOpAfter}} {
		if !r.sleepUntil(r.envCutAt.Add(h.after)) {
			return
		}
		if age := time.Since(h.signed); age >= m9OpTTL {
			r.find(fmt.Sprintf("held operation %d is %s old at its enqueue, and its lifetime is %s", i+1, age.Round(time.Second), m9OpTTL))
		}
		enqueued := time.Now()
		if err := m9Enqueue(witnessCell, h.env); err != nil {
			r.find(fmt.Sprintf("enqueue of held operation %d: %v", i+1, err))
			continue
		}
		r.t.Logf("enqueued held operation %d (%s) for %s %s after the environment cut", i+1, h.id, witnessCell, r.since(r.envCutAt))
		r.waitOutboxResult(h.id, enqueued)
	}
}

// waitOutboxResult waits up to 2 minutes for a result item of the operation in the outbox of the gateway. The environment island keeps it
// there, because envd cannot send it to mgmtd.
func (r *m9Run) waitOutboxResult(id string, since time.Time) {
	var last error
	for time.Now().Before(since.Add(m9ResultWait)) {
		items, err := m9Outbox()
		last = err
		if err == nil {
			for _, it := range items {
				if it.Kind == "result" && it.OpID == id {
					r.t.Logf("the result of %s reached the outbox %s after the enqueue", id, time.Since(since).Round(time.Second))
					return
				}
			}
		}
		if !r.sleepUntil(time.Now().Add(3 * time.Second)) {
			return
		}
	}
	r.find(fmt.Sprintf("no result of the operation %s in the outbox of the gateway within %s of its enqueue (last read error: %v)", id, m9ResultWait, last))
}

// runCellOp signs an operation for the cell island at its time after the cell cut and enqueues it. The cell applies it after the heal.
func (r *m9Run) runCellOp() {
	defer r.opsWG.Done()
	if !r.sleepUntil(r.cellCutAt.Add(r.plan.CellOpAfter)) {
		return
	}
	id, env, err := m9SignOp(islandCell, "m9 island cell "+randomHex(r.t, 3), m9OpTTL)
	if err != nil {
		r.find("sign the operation for the cell island: " + err.Error())
		return
	}
	r.addOp(m9Op{Name: "cell", Cell: islandCell, ID: id, SignedAt: time.Now()})
	if err := m9Enqueue(islandCell, env); err != nil {
		r.find("enqueue the operation for the cell island: " + err.Error())
		return
	}
	r.t.Logf("enqueued the operation %s for %s %s after the cell cut", id, islandCell, r.since(r.cellCutAt))
}

// healEnvironmentAt heals the environment island at its hold. The heal happens in this goroutine, so that the subtests of the cell island,
// which can take minutes, do not delay it.
func (r *m9Run) healEnvironmentAt(cut *linkCut) {
	defer r.wg.Done()
	defer close(r.envHealed)
	if !r.sleepUntil(r.envCutAt.Add(r.plan.EnvHold)) {
		return
	}
	cut.Heal(r.t)
	at := time.Now()
	n, oldest := 0, time.Time{}
	if items, err := m9Outbox(); err == nil {
		n = len(items)
		if n > 0 {
			oldest = items[0].At
		}
	}
	r.mu.Lock()
	r.envHealedOK, r.envHealedAt, r.outboxAtHeal, r.outboxOldest = true, at, n, oldest
	r.mu.Unlock()
	r.t.Logf("healed the environment island after %s, with %d items in the outbox", r.since(r.envCutAt), n)
}

func (r *m9Run) subSVIDsLapse(t *testing.T) {
	r.observeRestarts()
	pods, err := m9ListPods(t, islandCell)
	if err != nil {
		t.Fatalf("read the pods of %s: %v", islandCell, err)
	}
	hold := r.cellHealAt.Sub(r.cellCutAt)
	for _, b := range r.base[islandCell] {
		if _, ok := b.Containers[m9AgentContainer]; !ok {
			continue
		}
		key := b.Key()
		expiry, ok := r.cutExpiry[key]
		if !ok {
			t.Errorf("no agent SVID of %s was listed at the cut", key)
			continue
		}
		var count int
		for _, p := range pods {
			if p.Key() == key {
				count = p.Containers[m9AgentContainer].Restarts - b.Containers[m9AgentContainer].Restarts
			}
		}
		r.mu.Lock()
		first, restarted := r.firstRst[key+"/"+m9AgentContainer]
		r.mu.Unlock()
		remaining := expiry.Sub(r.cellCutAt)
		switch {
		case restarted:
			t.Logf("%s: the agent SVID expired %s after the cut, the first restart came at %s (%s after the expiry), %d restarts over the island", key,
				remaining.Round(time.Second), first.UTC().Format(time.RFC3339), first.Sub(expiry).Round(time.Second), count)
			if first.Before(expiry.Add(-m9Skew)) {
				t.Errorf("%s restarted at %s, %s before its SVID expired at %s", key, first.UTC().Format(time.RFC3339), expiry.Sub(first).Round(time.Second), expiry.UTC().Format(time.RFC3339))
			}
		case hold > remaining:
			t.Errorf("verify row 1 finding: the cell hold %s is above the remaining lifetime %s of the agent SVID of %s, and the agent did not restart. "+
				"The agent kept running without a valid SVID, or renewed through another path", hold.Round(time.Second), remaining.Round(time.Second), key)
		default:
			t.Logf("%s: the cell hold %s is not above the remaining lifetime %s, so no restart is expected", key, hold.Round(time.Second), remaining.Round(time.Second))
		}
	}
	t.Logf("restart counts of the pods of %s over the island:%s", islandCell, r.restartSummary(islandCell, pods))
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.whoamiErrs {
		t.Logf("%s", e)
	}
	for _, s := range r.restartSeen {
		t.Logf("%s", s)
	}
}

// restartSummary returns the restart count of spire-agent, cell-proxy and celld over the pods of a cluster, since the baseline.
func (r *m9Run) restartSummary(cluster string, pods []m9Pod) string {
	counts := map[string]int{}
	for _, b := range r.base[cluster] {
		for _, p := range pods {
			if p.Key() != b.Key() || p.UID != b.UID {
				continue
			}
			for name, ct := range p.Containers {
				if d := ct.Restarts - b.Containers[name].Restarts; d > 0 {
					counts[name] += d
				}
			}
		}
	}
	var sb strings.Builder
	for _, name := range []string{m9AgentContainer, "cell-proxy", "celld"} {
		fmt.Fprintf(&sb, " %s %d", name, counts[name])
		delete(counts, name)
	}
	for _, name := range sortedKeys(counts) {
		fmt.Fprintf(&sb, " %s %d", name, counts[name])
	}
	return sb.String()
}

func (r *m9Run) subReattest(t *testing.T) {
	// Each agent that restarted must attest again as a new agent ID. An agent that did not restart keeps its ID, which subtest svids_lapse reports.
	start := time.Now()
	readyAt := map[string]time.Duration{}
	waitFor(t, "every spire-agent of "+islandCell+" to be Ready with a new agent ID and a tunnel SVID in the future", m9ReattestWithin, func() (bool, string) {
		pods, err := m9ListPods(t, islandCell)
		if err != nil {
			return false, err.Error()
		}
		agents, err := m9AgentList(t)
		if err != nil {
			return false, err.Error()
		}
		by := m9AgentsByPod(agents, pods)
		var waiting []string
		now := time.Now()
		for _, p := range pods {
			ct, has := p.Containers[m9AgentContainer]
			if !has {
				continue
			}
			key := p.Key()
			if !ct.Ready {
				waiting = append(waiting, key+" not Ready")
				continue
			}
			if _, ok := readyAt[key]; !ok {
				readyAt[key] = time.Since(r.cellHealAt)
			}
			b := m9BaseContainer(r.base[islandCell], p, m9AgentContainer)
			if b == nil || ct.Restarts == b.Restarts {
				continue
			}
			a, ok := by[key]
			switch {
			case !ok || !a.Expires.After(now):
				waiting = append(waiting, key+" has no live agent")
			case r.cutAgents[key][a.Path]:
				waiting = append(waiting, key+" still has its old agent ID "+a.Path)
			}
		}
		if w := m9Whoami(t, islandCell); w.Err != "" {
			waiting = append(waiting, "whoami of the tunnel: "+w.Err)
		} else if exp, err := time.Parse(time.RFC3339, w.ExpiresAt); err != nil || !exp.After(now) {
			waiting = append(waiting, "whoami expiresAt "+w.ExpiresAt+" is not in the future")
		}
		return len(waiting) == 0, strings.Join(waiting, "; ")
	})
	for _, key := range sortedKeys(readyAt) {
		t.Logf("verify row 6: %s was Ready %s after the heal", key, readyAt[key].Round(time.Second))
	}
	t.Logf("every agent of %s was Ready with a new ID %s after the end of subtest svids_lapse", islandCell, time.Since(start).Round(time.Second))
}

func (r *m9Run) subCellsValid(t *testing.T) {
	waitFor(t, "both cells to be valid at mgmtd", m9ValidWithin, func() (bool, string) {
		st, err := m9MgmtStatus()
		if err != nil {
			return false, err.Error()
		}
		var seen []string
		valid := 0
		for _, c := range st.Cells {
			if c.Name == islandCell || c.Name == witnessCell {
				seen = append(seen, fmt.Sprintf("%s valid %v (%s)", c.Name, c.Valid, c.ValidReason))
				if c.Valid {
					valid++
				}
			}
		}
		return valid == 2, strings.Join(seen, ", ")
	})
}

// subDrain waits until no outbox item is older than the heal, and records the items, the refusals and the time (verify row 9).
func (r *m9Run) subDrain(t *testing.T) {
	r.mu.Lock()
	healedAt, atHeal, oldest := r.envHealedAt, r.outboxAtHeal, r.outboxOldest
	r.mu.Unlock()
	var items int
	waitFor(t, "no outbox item older than the heal", m9DrainWithin, func() (bool, string) {
		all, err := m9Outbox()
		if err != nil {
			return false, err.Error()
		}
		items = len(all)
		old := 0
		for _, it := range all {
			if it.At.Before(healedAt) {
				old++
			}
		}
		return old == 0, fmt.Sprintf("%d items, %d older than the heal", len(all), old)
	})
	t.Logf("verify row 9: %d items in the outbox at the heal (the oldest from %s), drained %s after it, %d items now", atHeal, oldest.UTC().Format(time.RFC3339),
		time.Since(healedAt).Round(time.Second), items)
	if st, err := m9MgmtStatus(); err == nil {
		if st.LastRefusal != nil {
			t.Logf("last refusal at mgmtd: %+v", *st.LastRefusal)
		}
		for _, c := range st.Cells {
			if c.LastRefusal != nil {
				t.Logf("last refusal of %s at mgmtd: kind %s, reason %s, at %s", c.Name, c.LastRefusal.Kind, c.LastRefusal.Reason, c.LastRefusal.At.UTC().Format(time.RFC3339))
			}
		}
	}
}

func (r *m9Run) subResultsRecorded(t *testing.T) {
	r.mu.Lock()
	ops := slices.Clone(r.ops)
	r.mu.Unlock()
	if len(ops) != 3 {
		t.Fatalf("the run signed %d operations, want 3 (two held for %s, one for %s)", len(ops), witnessCell, islandCell)
	}
	for _, o := range ops {
		waitFor(t, "the operation "+o.Name+" ("+o.ID+") to be applied at mgmtd", m9ResultsWithin, func() (bool, string) {
			out, err := mgmtCtlErr("op", "get", o.ID)
			if err != nil {
				return false, err.Error()
			}
			var v opState
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				return false, err.Error()
			}
			return v.Final == op.OutcomeApplied, fmt.Sprintf("state %q final %q", v.State, v.Final)
		})
		if n := demoLogCount(t, o.Cell, o.ID); n != 1 {
			t.Errorf("demo-log of %s holds %d lines of the operation %s, want 1", o.Cell, n, o.ID)
		}
	}
}

func (r *m9Run) subNoTrustChange(t *testing.T) {
	got, err := m9SnapTrust(t)
	if err != nil {
		t.Fatalf("read the trust state: %v", err)
	}
	for _, k := range sortedKeys(r.baseTrust.Bundles) {
		if got.Bundles[k] != r.baseTrust.Bundles[k] {
			t.Errorf("the trust bundle of the SPIRE server of %s changed", k)
		}
	}
	for _, k := range sortedKeys(r.baseTrust.Cells) {
		if got.Cells[k] != r.baseTrust.Cells[k] {
			t.Errorf("mgmtd shows %s as %q, and it showed %q before the islands", k, got.Cells[k], r.baseTrust.Cells[k])
		}
	}
	if recs, err := m9RecordsCM(t); err != nil {
		t.Errorf("read the records ConfigMap: %v", err)
	} else if recs != r.baseRecs {
		t.Error("the records ConfigMap spire-system/cell-records changed during the islands")
	}
}

// subNoPodRestarts is the pass rule. The baseline comes from before the cut.
func (r *m9Run) subNoPodRestarts(t *testing.T) {
	r.observeRestarts()
	in := m9PassInput{Cuts: map[string]m9Cut{islandCell: {Start: r.cellCutAt, End: r.cellHealAt}}, Expiry: r.cutExpiry, First: map[string]time.Time{}}
	r.mu.Lock()
	for k, at := range r.firstRst {
		in.First[k] = at
	}
	r.mu.Unlock()
	for _, c := range m9ClusterList() {
		in.Base = append(in.Base, r.base[c]...)
		pods, err := m9ListPods(t, c)
		if err != nil {
			t.Fatalf("read the pods of %s: %v", c, err)
		}
		in.End = append(in.End, pods...)
		t.Logf("restart counts in %s since the start:%s", c, r.restartSummary(c, pods))
	}
	for _, p := range evalM9PassRule(in) {
		t.Error(p)
	}
}

func (r *m9Run) subTelemetry(t *testing.T) {
	for _, c := range telemetryClusters {
		waitFor(t, "a sample of "+c+" newer than 3 minutes in Prometheus", m9TelemetryWithin, func() (bool, string) {
			s := promSamplesFrom(t, fmt.Sprintf(`up{k8s_cluster_name=%q}`, c), m9TelemetryFresh)
			return len(s) > 0, fmt.Sprintf("%d series with a point in the last 3 minutes", len(s))
		})
	}
}

// reportFindings fails the test for each problem that a goroutine saw.
func (r *m9Run) reportFindings() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.findings {
		r.t.Errorf("%s (first seen %s after the cell cut, %d times)", f.Text, f.First.Sub(r.cellCutAt).Round(time.Second), f.Count)
	}
}

// logQueues records the collector queue sizes at the start and at the end (verify row 10). Task 23 projects the growth to 24 hours.
func (r *m9Run) logQueues() {
	for _, c := range m9ClusterList() {
		end, err := m9QueueKB(c)
		if err != nil {
			r.t.Logf("collector queue of %s: %v", c, err)
			continue
		}
		r.t.Logf("verify row 10: the collector queue of %s was %d KiB before the islands and is %d KiB now", c, r.baseQueue[c], end)
	}
}

// m9Echo sends one request from client to echo in a cell, as echoTraffic does. It adds --fail, so an HTTP error of the mesh fails it too.
func m9Echo(t *testing.T, cluster string) error {
	t.Helper()
	_, err := kubectl(t, cluster, "", "-n", "apps-demo", "exec", "deploy/client", "-c", "curl", "--", "curl", "-sf", "-o", "/dev/null", "--max-time", "10", "http://echo/hostname")
	return err
}

// m9ReadState reads the bundle state of a target without failing the test.
func m9ReadState(t *testing.T, target string) (bundleapply.State, error) {
	t.Helper()
	var st bundleapply.State
	out, err := kubectl(t, target, "", "-n", m8StateNamespace(target), "get", "configmap", "bundle-state", "-o", `jsonpath={.data.state\.json}`)
	if err != nil {
		return st, err
	}
	if err := record.DecodeStrict([]byte(out), &st); err != nil {
		return st, fmt.Errorf("the bundle state of %s does not decode: %w", target, err)
	}
	return st, nil
}

// m9EnvdReady fails when a pod of envd in dev-cp is not Ready, or when there is none.
func m9EnvdReady(t *testing.T) error {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", "envd-system", "get", "pods", "-o", "json")
	if err != nil {
		return err
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct{ Type, Status string } `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return err
	}
	if len(list.Items) == 0 {
		return fmt.Errorf("no pod in envd-system")
	}
	for _, p := range list.Items {
		ready := false
		for _, c := range p.Status.Conditions {
			ready = ready || (c.Type == "Ready" && c.Status == "True")
		}
		if !ready {
			return fmt.Errorf("pod %s is not Ready", p.Metadata.Name)
		}
	}
	return nil
}

// m9RecordsCM returns the data of the records ConfigMap of dev-cp as JSON.
func m9RecordsCM(t *testing.T) (string, error) {
	t.Helper()
	return kubectl(t, spireCluster, "", "-n", spireNamespace, "get", "configmap", "cell-records", "-o", "jsonpath={.data}")
}

// m9GatewayRecords returns the record revision of each cell at the gateway, as JSON. It is the spec revision that the gateway holds.
func m9GatewayRecords() (string, error) {
	out, err := gwCtlErr("", "status")
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, m9Short(out))
	}
	var s mgmtapi.GatewayStatus
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return "", err
	}
	b, err := json.Marshal(s.Records)
	return string(b), err
}

// m9SnapTrust reads the trust bundles of the SPIRE servers of dev-cp and management, and the issuer, keys and record of each cell at mgmtd.
func m9SnapTrust(t *testing.T) (m9Trust, error) {
	t.Helper()
	tr := m9Trust{Bundles: map[string]string{}, Cells: map[string]string{}}
	for _, c := range []string{spireCluster, mgmtCluster} {
		out, err := spireServerIn(t, c, "bundle", "show", "-socketPath", spireSocket, "-format", "pem")
		if err != nil {
			return tr, fmt.Errorf("spire-server bundle show in %s: %w", c, err)
		}
		tr.Bundles[c] = out
	}
	st, err := m9MgmtStatus()
	if err != nil {
		return tr, err
	}
	for _, c := range st.Cells {
		kids := slices.Clone(c.Kids)
		slices.Sort(kids)
		tr.Cells[c.Name] = fmt.Sprintf("issuer %s, keys %v, record %v", c.Issuer, kids, c.Record)
	}
	return tr, nil
}
