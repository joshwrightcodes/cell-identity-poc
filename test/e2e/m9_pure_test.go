package e2e

// The pure part of the M9 islands test: the plan, the sampler core, the pass rule and the parsers. This file has no build tag and
// imports the standard library only, so the pure tests run with no cluster (go test -run 'TestSamplerFailsOnSleepGap|...' ./test/e2e/).

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// m9OpTTL is the lifetime of every operation that the islands test signs. It is op.MaxTTL.
	m9OpTTL = time.Hour
	// m9ResultWait bounds the wait for the result of an operation in the outbox of the gateway.
	m9ResultWait = 2 * time.Minute
	// m9MaxSignLead is the longest time that may pass between signing the two held operations and the cell cut. Signing takes seconds.
	m9MaxSignLead = 90 * time.Second
	// m9EnvCutAllowance is the time that the environment cut itself may take, bounded by the partition call.
	m9EnvCutAllowance = 2 * time.Minute
	// m9SleepGap is the longest gap between two samples that the run accepts.
	m9SleepGap = 2 * time.Minute
	// m9Skew is the clock skew that the pass rule allows between the expiry of an SVID and the restart of its agent.
	m9Skew = time.Minute
	// m9AgentContainer is the container name of the SPIRE agent sidecar.
	m9AgentContainer = "spire-agent"
	// m9E2ELabel marks the pods and namespaces that tests make. The pass rule leaves them out.
	m9E2ELabel = "cell.poc.internal/e2e"
)

// islandHold is the hold of the cell island: three SVID lifetimes plus a margin. The margin is 5 minutes for a lifetime of 30 minutes or
// more, else 1 minute. At 1h it is 3h05m.
func islandHold(ttl time.Duration) time.Duration {
	margin := time.Minute
	if ttl >= 30*time.Minute {
		margin = 5 * time.Minute
	}
	return 3*ttl + margin
}

// envIslandHold is the hold of the environment island: the cell hold plus 10 minutes. The environment island starts 1 minute after the
// cell island, so it ends 11 minutes after it (Controller call 2).
func envIslandHold(ttl time.Duration) time.Duration {
	return islandHold(ttl) + 10*time.Minute
}

// m9Plan is the schedule of the islands test. Offsets count from the start of the island that the field names.
type m9Plan struct {
	CellHold time.Duration
	EnvHold  time.Duration
	// EnvCutAfter is the start of the environment island, after the cell cut.
	EnvCutAfter time.Duration
	// FirstOpAfter and SecondOpAfter are the enqueue times of the two held operations for dev-cell-1, after the environment cut.
	FirstOpAfter  time.Duration
	SecondOpAfter time.Duration
	// CellOpAfter is the time at which the operation for dev-cell-2 is signed and enqueued, after the cell cut.
	CellOpAfter time.Duration
}

// m9PlanFor returns the schedule for an SVID lifetime. The second held operation goes in at min(55 minutes, environment hold minus
// 5 minutes), so that it stays inside its own lifetime of 1 hour and its result still has 2 minutes before the island ends. The operation
// for dev-cell-2 goes in at max(1 minute, cell hold minus 30 minutes), so that it waits at most 30 minutes for the heal.
func m9PlanFor(ttl time.Duration) m9Plan {
	p := m9Plan{CellHold: islandHold(ttl), EnvHold: envIslandHold(ttl), EnvCutAfter: time.Minute, FirstOpAfter: 2 * time.Minute}
	p.SecondOpAfter = min(55*time.Minute, p.EnvHold-5*time.Minute)
	p.CellOpAfter = max(time.Minute, p.CellHold-30*time.Minute)
	return p
}

// problems lists what is wrong with the schedule. An empty result means that each operation is enqueued inside its lifetime, in the island
// that it needs, and early enough for its result.
func (p m9Plan) problems(signLead time.Duration) []string {
	var bad []string
	// The held operations were signed signLead before the cell cut. The environment cut starts EnvCutAfter later and can take m9EnvCutAllowance.
	for name, after := range map[string]time.Duration{"first": p.FirstOpAfter, "second": p.SecondOpAfter} {
		if age := signLead + p.EnvCutAfter + m9EnvCutAllowance + after; age >= m9OpTTL {
			bad = append(bad, fmt.Sprintf("the %s held operation is %s old when it is enqueued, and its lifetime is %s", name, age, m9OpTTL))
		}
		if after+m9ResultWait > p.EnvHold {
			bad = append(bad, fmt.Sprintf("the %s held operation is enqueued %s into an environment island of %s, with no room for its result", name, after, p.EnvHold))
		}
	}
	if p.SecondOpAfter < p.FirstOpAfter {
		bad = append(bad, "the second held operation comes before the first")
	}
	if p.CellOpAfter < time.Minute || p.CellOpAfter >= p.CellHold {
		bad = append(bad, fmt.Sprintf("the operation for the cell island is enqueued %s into a cell island of %s", p.CellOpAfter, p.CellHold))
	}
	if wait := p.CellHold - p.CellOpAfter; wait >= m9OpTTL {
		bad = append(bad, fmt.Sprintf("the operation for the cell island waits %s for the heal, and its lifetime is %s", wait, m9OpTTL))
	}
	if p.EnvCutAfter+p.EnvHold <= p.CellHold {
		bad = append(bad, "the environment island ends before the cell island")
	}
	return bad
}

// sampler records the time of each sample. The test reads the gaps between them, and no check depends on when a sample was taken.
type sampler struct {
	mu       sync.Mutex
	times    []time.Time
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newSampler() *sampler {
	return &sampler{stop: make(chan struct{}), done: make(chan struct{})}
}

// note records that a sample was taken at the time. It keeps the wall time only: on macOS the monotonic clock stops while the Mac sleeps, so a
// gap of two monotonic readings would not show a sleep.
func (s *sampler) note(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.times = append(s.times, at.Round(0))
}

// Gaps returns the time between each two consecutive samples, in order.
func (s *sampler) Gaps() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gaps []time.Duration
	for i := 1; i < len(s.times); i++ {
		gaps = append(gaps, s.times[i].Sub(s.times[i-1]))
	}
	return gaps
}

// Count returns the number of samples.
func (s *sampler) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.times)
}

// m9SleepGapError returns an error when a gap is above the limit. A gap of exactly the limit is accepted. The error names mac_slept.
func m9SleepGapError(gaps []time.Duration, limit time.Duration) error {
	var over []string
	for i, g := range gaps {
		if g > limit {
			over = append(over, fmt.Sprintf("sample %d to %d: %s", i+1, i+2, g.Round(time.Second)))
		}
	}
	if len(over) == 0 {
		return nil
	}
	return fmt.Errorf("mac_slept: %d gaps above %s between two samples (%s). Run: mise run gate:m9:repair", len(over), limit, strings.Join(over, ", "))
}

// m9Container is the state of one container of a pod.
type m9Container struct {
	Restarts int
	// Finished is the end of the last termination of the container, or the zero time.
	Finished time.Time
	Ready    bool
}

// m9Pod is the part of a pod that the pass rule reads.
type m9Pod struct {
	Cluster    string
	Namespace  string
	Name       string
	UID        string
	Containers map[string]m9Container
}

// Key names the pod across clusters.
func (p m9Pod) Key() string { return p.Cluster + "/" + p.Namespace + "/" + p.Name }

// parseM9Pods reads the JSON of kubectl get pods -A. It leaves out pods with the e2e label, pods that a Job owns, pods that are deleted or
// finished, and it counts init containers too, because a native sidecar runs there.
func parseM9Pods(cluster, raw string) ([]m9Pod, error) {
	type status struct {
		Name         string `json:"name"`
		RestartCount int    `json:"restartCount"`
		Ready        bool   `json:"ready"`
		LastState    struct {
			Terminated *struct {
				FinishedAt time.Time `json:"finishedAt"`
			} `json:"terminated"`
		} `json:"lastState"`
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name              string            `json:"name"`
				Namespace         string            `json:"namespace"`
				UID               string            `json:"uid"`
				Labels            map[string]string `json:"labels"`
				DeletionTimestamp *string           `json:"deletionTimestamp"`
				OwnerReferences   []struct {
					Kind string `json:"kind"`
				} `json:"ownerReferences"`
			} `json:"metadata"`
			Status struct {
				Phase                 string   `json:"phase"`
				ContainerStatuses     []status `json:"containerStatuses"`
				InitContainerStatuses []status `json:"initContainerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, fmt.Errorf("the pod list of %s is no JSON: %w", cluster, err)
	}
	var pods []m9Pod
	for _, it := range list.Items {
		m := it.Metadata
		if _, e2e := m.Labels[m9E2ELabel]; e2e || m.DeletionTimestamp != nil || it.Status.Phase == "Succeeded" || it.Status.Phase == "Failed" {
			continue
		}
		if slices.ContainsFunc(m.OwnerReferences, func(o struct {
			Kind string `json:"kind"`
		}) bool {
			return o.Kind == "Job"
		}) {
			continue
		}
		p := m9Pod{Cluster: cluster, Namespace: m.Namespace, Name: m.Name, UID: m.UID, Containers: map[string]m9Container{}}
		for _, cs := range append(slices.Clone(it.Status.InitContainerStatuses), it.Status.ContainerStatuses...) {
			c := m9Container{Restarts: cs.RestartCount, Ready: cs.Ready}
			if cs.LastState.Terminated != nil {
				c.Finished = cs.LastState.Terminated.FinishedAt
			}
			p.Containers[cs.Name] = c
		}
		pods = append(pods, p)
	}
	return pods, nil
}

// m9SpireAgent is one entry of spire-server agent list.
type m9SpireAgent struct {
	Path    string
	Cluster string
	UID     string
	Expires time.Time
	Banned  bool
}

var (
	m9JWTAgent  = regexp.MustCompile(`^/spire/agent/cluster_jwt/([^/]+)/([^/]+)/`)
	m9PSATAgent = regexp.MustCompile(`^/spire/agent/k8s_psat/([^/]+)/pod/([^/]+)$`)
)

// parseM9Agents reads the JSON of spire-server agent list. It keeps the agents whose ID names a cluster and a pod UID. The server lists the
// expiry of the agent SVID as x509svid_expires_at, in Unix seconds, as a quoted string.
func parseM9Agents(raw string) ([]m9SpireAgent, error) {
	var res struct {
		Agents []struct {
			ID struct {
				Path string `json:"path"`
			} `json:"id"`
			Expires json.RawMessage `json:"x509svid_expires_at"`
			Banned  bool            `json:"banned"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return nil, fmt.Errorf("the agent list is no JSON: %w", err)
	}
	var out []m9SpireAgent
	for _, a := range res.Agents {
		var cluster, uid string
		if m := m9JWTAgent.FindStringSubmatch(a.ID.Path); m != nil {
			cluster, uid = m[1], m[2]
		} else if m := m9PSATAgent.FindStringSubmatch(a.ID.Path); m != nil {
			cluster, uid = m[1], m[2]
		} else {
			continue
		}
		secs, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(string(a.Expires)), `"`), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("the agent %s has the expiry %s, which is no Unix time", a.ID.Path, a.Expires)
		}
		out = append(out, m9SpireAgent{Path: a.ID.Path, Cluster: cluster, UID: uid, Expires: time.Unix(secs, 0).UTC(), Banned: a.Banned})
	}
	return out, nil
}

// m9PodAgent is the agent of one pod: the entry with the latest expiry, and every ID that the pod had. The server keeps the entry of an
// agent after its container restarted, so a pod can list several.
type m9PodAgent struct {
	Path    string
	Expires time.Time
	Paths   []string
}

// m9AgentsByPod maps each pod to its agent. An entry of a pod that no longer exists, and a banned entry, are left out.
func m9AgentsByPod(entries []m9SpireAgent, pods []m9Pod) map[string]m9PodAgent {
	podOf := map[[2]string]string{}
	for _, p := range pods {
		podOf[[2]string{p.Cluster, p.UID}] = p.Key()
	}
	out := map[string]m9PodAgent{}
	for _, e := range entries {
		key, ok := podOf[[2]string{e.Cluster, e.UID}]
		if !ok || e.Banned {
			continue
		}
		a := out[key]
		a.Paths = append(a.Paths, e.Path)
		if e.Expires.After(a.Expires) {
			a.Expires, a.Path = e.Expires, e.Path
		}
		out[key] = a
	}
	return out
}

// m9Renewals checks that an expiry moves forward at least once in maxStale. It remembers the last expiry of each key and the time at which it
// last grew. The first look at a key starts its clock.
type m9Renewals struct {
	maxStale time.Duration
	seen     map[string]m9Renewal
}

type m9Renewal struct{ expiry, advanced time.Time }

func newM9Renewals(maxStale time.Duration) *m9Renewals {
	return &m9Renewals{maxStale: maxStale, seen: map[string]m9Renewal{}}
}

// observe returns a problem when the expiry of key did not grow for longer than maxStale, and an empty string otherwise.
func (r *m9Renewals) observe(key string, expiry, now time.Time) string {
	prev, ok := r.seen[key]
	switch {
	case !ok || expiry.After(prev.expiry):
		r.seen[key] = m9Renewal{expiry: expiry, advanced: now}
		return ""
	case now.Sub(prev.advanced) > r.maxStale:
		r.seen[key] = m9Renewal{expiry: prev.expiry, advanced: now}
		return fmt.Sprintf("%s did not renew for %s, over %s (expiry %s)", key, now.Sub(prev.advanced).Round(time.Second), r.maxStale, prev.expiry.Format(time.RFC3339))
	}
	return ""
}

// m9RemainingOK reports whether the remaining lifetime of an SVID is above a quarter of the lifetime.
func m9RemainingOK(expiry, now time.Time, ttl time.Duration) bool {
	return expiry.Sub(now) > ttl/4
}

// m9Cut is the time window of one cell island.
type m9Cut struct{ Start, End time.Time }

// m9PassInput is the data of the pass rule "no pod restarts". Base was read before the first cut. Cuts holds the cells that were cut from
// dev-cp, by cluster. Expiry is the expiry of the agent SVID of each pod at the cut, by pod key. First is the time of the first restart of each
// container, by pod key, a slash and the container name.
type m9PassInput struct {
	Base, End []m9Pod
	Cuts      map[string]m9Cut
	Expiry    map[string]time.Time
	First     map[string]time.Time
}

// evalM9PassRule applies the pass rule of the M9 plan. For each pod at the start, the UID is unchanged at the end and every container other
// than spire-agent keeps its restart count. A spire-agent container may restart only in a cell that was cut from dev-cp for longer than the
// remaining lifetime of its SVID at the cut, and never before that SVID expired (one minute of skew allowed). Every other spire-agent keeps its
// restart count. It returns one line for each violation, sorted.
func evalM9PassRule(in m9PassInput) []string {
	end := map[string]m9Pod{}
	for _, p := range in.End {
		end[p.Key()] = p
	}
	var bad []string
	for _, b := range in.Base {
		e, ok := end[b.Key()]
		if !ok {
			bad = append(bad, fmt.Sprintf("pod %s is gone", b.Key()))
			continue
		}
		if e.UID != b.UID {
			bad = append(bad, fmt.Sprintf("pod %s was replaced: UID %s, then %s", b.Key(), b.UID, e.UID))
			continue
		}
		for name, bc := range b.Containers {
			ec, ok := e.Containers[name]
			delta := ec.Restarts - bc.Restarts
			switch {
			case !ok:
				bad = append(bad, fmt.Sprintf("container %s of pod %s is gone", name, b.Key()))
			case delta == 0:
			case name != m9AgentContainer:
				bad = append(bad, fmt.Sprintf("container %s of pod %s restarted %d times (restart count %d, then %d)", name, b.Key(), delta, bc.Restarts, ec.Restarts))
			default:
				bad = append(bad, m9AgentRestartProblem(b, delta, in)...)
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// m9AgentRestartProblem judges the restarts of one spire-agent container.
func m9AgentRestartProblem(p m9Pod, delta int, in m9PassInput) []string {
	cut, cutOK := in.Cuts[p.Cluster]
	if !cutOK {
		return []string{fmt.Sprintf("container %s of pod %s restarted %d times, and %s was not cut from dev-cp, so its SVID renews", m9AgentContainer, p.Key(), delta, p.Cluster)}
	}
	expiry, ok := in.Expiry[p.Key()]
	if !ok {
		return []string{fmt.Sprintf("container %s of pod %s restarted %d times, and the run recorded no expiry of its SVID at the cut", m9AgentContainer, p.Key(), delta)}
	}
	if hold, remaining := cut.End.Sub(cut.Start), expiry.Sub(cut.Start); hold <= remaining {
		return []string{fmt.Sprintf("container %s of pod %s restarted %d times, and the cut of %s lasted %s, not above the remaining lifetime of %s", m9AgentContainer, p.Key(), delta, p.Cluster, hold.Round(time.Second), remaining.Round(time.Second))}
	}
	first, ok := in.First[p.Key()+"/"+m9AgentContainer]
	if !ok {
		return []string{fmt.Sprintf("container %s of pod %s restarted %d times, and the run recorded no time for the first restart", m9AgentContainer, p.Key(), delta)}
	}
	if first.Before(expiry.Add(-m9Skew)) {
		return []string{fmt.Sprintf("container %s of pod %s restarted at %s, %s before its SVID expired at %s", m9AgentContainer, p.Key(), first.Format(time.RFC3339), expiry.Sub(first).Round(time.Second), expiry.Format(time.RFC3339))}
	}
	return nil
}

// ---- pure tests ----

// TestSamplerFailsOnSleepGap: a gap above 2 minutes between two samples fails the run with mac_slept, and a gap of exactly 2 minutes does not.
func TestSamplerFailsOnSleepGap(t *testing.T) {
	t0 := time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC)
	s := newSampler()
	for _, d := range []time.Duration{0, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute} {
		s.note(t0.Add(d))
	}
	gaps := s.Gaps()
	if want := []time.Duration{time.Minute, time.Minute, 2 * time.Minute, time.Minute}; !slices.Equal(gaps, want) {
		t.Fatalf("Gaps() = %v, want %v", gaps, want)
	}
	if err := m9SleepGapError(gaps, m9SleepGap); err != nil {
		t.Errorf("gaps up to exactly 2 minutes failed the run: %v", err)
	}
	s.note(t0.Add(5*time.Minute + 2*time.Minute + time.Second))
	err := m9SleepGapError(s.Gaps(), m9SleepGap)
	if err == nil || !strings.Contains(err.Error(), "mac_slept") {
		t.Errorf("a gap of 2 minutes and 1 second gave %v, want an error with mac_slept", err)
	}
	if err := m9SleepGapError(nil, m9SleepGap); err != nil {
		t.Errorf("no gaps failed the run: %v", err)
	}
}

// TestIslandHold: three lifetimes plus 5 minutes from 30 minutes, else plus 1 minute. The environment island holds 10 minutes longer.
func TestIslandHold(t *testing.T) {
	for _, c := range []struct {
		ttl, hold, env time.Duration
	}{
		{time.Minute, 4 * time.Minute, 14 * time.Minute},
		{29 * time.Minute, 88 * time.Minute, 98 * time.Minute},
		{30 * time.Minute, 95 * time.Minute, 105 * time.Minute},
		{time.Hour, 3*time.Hour + 5*time.Minute, 3*time.Hour + 15*time.Minute},
	} {
		if got := islandHold(c.ttl); got != c.hold {
			t.Errorf("islandHold(%s) = %s, want %s", c.ttl, got, c.hold)
		}
		if got := envIslandHold(c.ttl); got != c.env {
			t.Errorf("envIslandHold(%s) = %s, want %s", c.ttl, got, c.env)
		}
		if islandHold(c.ttl) <= 3*c.ttl {
			t.Errorf("islandHold(%s) is not above three lifetimes", c.ttl)
		}
	}
}

// TestIslandOpSchedule: the three enqueue times at 1m and at 1h, each inside the lifetime of its operation and inside its island.
func TestIslandOpSchedule(t *testing.T) {
	for _, c := range []struct {
		ttl                    time.Duration
		first, second, cellOp  time.Duration
		cellHold, envHold, env time.Duration
	}{
		{time.Minute, 2 * time.Minute, 9 * time.Minute, time.Minute, 4 * time.Minute, 14 * time.Minute, time.Minute},
		{time.Hour, 2 * time.Minute, 55 * time.Minute, 2*time.Hour + 35*time.Minute, 3*time.Hour + 5*time.Minute, 3*time.Hour + 15*time.Minute, time.Minute},
	} {
		t.Run(c.ttl.String(), func(t *testing.T) {
			p := m9PlanFor(c.ttl)
			if p.FirstOpAfter != c.first || p.SecondOpAfter != c.second || p.CellOpAfter != c.cellOp || p.CellHold != c.cellHold || p.EnvHold != c.envHold || p.EnvCutAfter != c.env {
				t.Errorf("m9PlanFor(%s) = %+v, want first %s, second %s, cell operation %s, holds %s and %s, environment cut after %s",
					c.ttl, p, c.first, c.second, c.cellOp, c.cellHold, c.envHold, c.env)
			}
			if bad := p.problems(m9MaxSignLead); len(bad) > 0 {
				t.Errorf("the schedule is not inside the lifetimes: %v", bad)
			}
		})
	}
	// A held operation signed too early, or enqueued too late, is a problem.
	p := m9PlanFor(time.Hour)
	if bad := p.problems(10 * time.Minute); len(bad) == 0 {
		t.Error("a sign lead of 10 minutes passes, so the second held operation would expire before the enqueue")
	}
	late := p
	late.SecondOpAfter = 58 * time.Minute
	if bad := late.problems(m9MaxSignLead); len(bad) == 0 {
		t.Error("a second operation at 58 minutes passes, and it is 62 minutes old")
	}
}

// TestPassRuleAgentRestarts: an agent restart before its SVID expiry fails, and one after it passes only in the cut cell.
func TestPassRuleAgentRestarts(t *testing.T) {
	t0 := time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC)
	pod := func(cluster string, agent, proxy int) m9Pod {
		return m9Pod{Cluster: cluster, Namespace: "mesh-view-system", Name: "mesh-view-0", UID: "u-" + cluster, Containers: map[string]m9Container{
			m9AgentContainer: {Restarts: agent}, "cell-proxy": {Restarts: proxy},
		}}
	}
	cell2 := pod("dev-cell-2", 0, 0).Key()
	cell1 := pod("dev-cell-1", 0, 0).Key()
	expiry := t0.Add(40 * time.Second)
	cuts := map[string]m9Cut{"dev-cell-2": {Start: t0, End: t0.Add(4 * time.Minute)}}
	input := func(end []m9Pod, first time.Time) m9PassInput {
		return m9PassInput{
			Base:   []m9Pod{pod("dev-cell-1", 0, 0), pod("dev-cell-2", 0, 0)},
			End:    end,
			Cuts:   cuts,
			Expiry: map[string]time.Time{cell2: expiry, cell1: expiry},
			First:  map[string]time.Time{cell2 + "/" + m9AgentContainer: first, cell1 + "/" + m9AgentContainer: first},
		}
	}
	for _, c := range []struct {
		name    string
		end     []m9Pod
		first   time.Time
		wantBad string
	}{
		{"no restart", []m9Pod{pod("dev-cell-1", 0, 0), pod("dev-cell-2", 0, 0)}, time.Time{}, ""},
		{"restart 15 s after expiry in the cut cell", []m9Pod{pod("dev-cell-1", 0, 0), pod("dev-cell-2", 3, 0)}, expiry.Add(15 * time.Second), ""},
		{"restart 30 s before expiry is inside the skew", []m9Pod{pod("dev-cell-1", 0, 0), pod("dev-cell-2", 1, 0)}, expiry.Add(-30 * time.Second), ""},
		{"restart 90 s before expiry", []m9Pod{pod("dev-cell-1", 0, 0), pod("dev-cell-2", 1, 0)}, expiry.Add(-90 * time.Second), "before its SVID expired"},
		{"restart after expiry in the cell that was not cut", []m9Pod{pod("dev-cell-1", 2, 0), pod("dev-cell-2", 0, 0)}, expiry.Add(15 * time.Second), "was not cut from dev-cp"},
		{"restart of cell-proxy in the cut cell", []m9Pod{pod("dev-cell-1", 0, 0), pod("dev-cell-2", 0, 1)}, expiry.Add(15 * time.Second), "container cell-proxy of pod dev-cell-2/mesh-view-system/mesh-view-0 restarted 1 times"},
		{"pod replaced", []m9Pod{pod("dev-cell-1", 0, 0), {Cluster: "dev-cell-2", Namespace: "mesh-view-system", Name: "mesh-view-0", UID: "other", Containers: map[string]m9Container{}}}, time.Time{}, "was replaced"},
		{"pod gone", []m9Pod{pod("dev-cell-1", 0, 0)}, time.Time{}, "is gone"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := evalM9PassRule(input(c.end, c.first))
			switch {
			case c.wantBad == "" && len(bad) > 0:
				t.Errorf("the pass rule failed: %v", bad)
			case c.wantBad != "" && !strings.Contains(strings.Join(bad, "\n"), c.wantBad):
				t.Errorf("the pass rule gave %v, want a line with %q", bad, c.wantBad)
			}
		})
	}
	t.Run("hold not above the remaining lifetime", func(t *testing.T) {
		in := input([]m9Pod{pod("dev-cell-1", 0, 0), pod("dev-cell-2", 1, 0)}, expiry.Add(15*time.Second))
		in.Cuts = map[string]m9Cut{"dev-cell-2": {Start: t0, End: t0.Add(30 * time.Second)}}
		if bad := evalM9PassRule(in); len(bad) == 0 {
			t.Error("an agent restarted in a cut shorter than the remaining lifetime of its SVID, and the pass rule accepted it")
		}
	})
	t.Run("no expiry recorded", func(t *testing.T) {
		in := input([]m9Pod{pod("dev-cell-1", 0, 0), pod("dev-cell-2", 1, 0)}, expiry.Add(15*time.Second))
		in.Expiry = nil
		if bad := evalM9PassRule(in); len(bad) == 0 {
			t.Error("a restart with no recorded expiry passed")
		}
	})
}

// TestM9PodsAndAgentsParse: the parsers keep what the pass rule needs and leave out test pods, Job pods and deleted pods.
func TestM9PodsAndAgentsParse(t *testing.T) {
	pods, err := parseM9Pods("dev-cell-2", `{"items":[
	 {"metadata":{"name":"a","namespace":"n","uid":"u1"},"status":{"phase":"Running",
	  "initContainerStatuses":[{"name":"spire-agent","restartCount":2,"ready":true,"lastState":{"terminated":{"finishedAt":"2026-11-22T01:00:40Z"}}}],
	  "containerStatuses":[{"name":"x","restartCount":0,"ready":true}]}},
	 {"metadata":{"name":"b","namespace":"n","uid":"u2","labels":{"cell.poc.internal/e2e":"true"}},"status":{"phase":"Running"}},
	 {"metadata":{"name":"c","namespace":"n","uid":"u3","ownerReferences":[{"kind":"Job"}]},"status":{"phase":"Running"}},
	 {"metadata":{"name":"d","namespace":"n","uid":"u4","deletionTimestamp":"2026-11-22T01:00:00Z"},"status":{"phase":"Running"}},
	 {"metadata":{"name":"e","namespace":"n","uid":"u5"},"status":{"phase":"Succeeded"}}]}`)
	if err != nil || len(pods) != 1 || pods[0].Name != "a" {
		t.Fatalf("parseM9Pods = %+v, %v, want only pod a", pods, err)
	}
	if c := pods[0].Containers[m9AgentContainer]; c.Restarts != 2 || !c.Ready || c.Finished.IsZero() {
		t.Errorf("the native sidecar container is %+v, want 2 restarts, Ready, with a finish time", c)
	}
	agents, err := parseM9Agents(`{"agents":[
	 {"id":{"path":"/spire/agent/cluster_jwt/dev-cell-2/u1/h1"},"x509svid_expires_at":"1000","banned":false},
	 {"id":{"path":"/spire/agent/cluster_jwt/dev-cell-2/u1/h2"},"x509svid_expires_at":"2000"},
	 {"id":{"path":"/spire/agent/k8s_psat/dev-cp/pod/u9"},"x509svid_expires_at":"3000"},
	 {"id":{"path":"/spire/agent/other"},"x509svid_expires_at":"1"}]}`)
	if err != nil || len(agents) != 3 {
		t.Fatalf("parseM9Agents = %+v, %v, want 3 agents", agents, err)
	}
	by := m9AgentsByPod(agents, pods)
	if a := by[pods[0].Key()]; a.Path != "/spire/agent/cluster_jwt/dev-cell-2/u1/h2" || len(a.Paths) != 2 || a.Expires.Unix() != 2000 {
		t.Errorf("m9AgentsByPod = %+v, want the entry with the latest expiry and both IDs", by)
	}
	if len(by) != 1 {
		t.Errorf("m9AgentsByPod lists %d pods, want 1, because the agent of pod u9 has no pod in the list", len(by))
	}
}

// TestM9Renewals: an expiry that does not grow for longer than the limit is a problem, and a renewal resets the clock.
func TestM9Renewals(t *testing.T) {
	t0 := time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC)
	r := newM9Renewals(35 * time.Second)
	exp := t0.Add(time.Minute)
	if p := r.observe("a", exp, t0); p != "" {
		t.Fatalf("the first look gave %q", p)
	}
	if p := r.observe("a", exp, t0.Add(30*time.Second)); p != "" {
		t.Errorf("30 s with no renewal gave %q, want none under 35 s", p)
	}
	if p := r.observe("a", exp, t0.Add(40*time.Second)); p == "" {
		t.Error("40 s with no renewal gave no problem")
	}
	if p := r.observe("a", exp.Add(time.Minute), t0.Add(41*time.Second)); p != "" {
		t.Errorf("a renewal gave %q", p)
	}
	if !m9RemainingOK(t0.Add(16*time.Second), t0, time.Minute) || m9RemainingOK(t0.Add(15*time.Second), t0, time.Minute) {
		t.Error("the quarter of a 1 minute lifetime is 15 s, and the remaining time must be above it")
	}
}

// TestSamplerKeepsWallTime: a stored sample time has no monotonic reading. On macOS the monotonic clock stops while the Mac sleeps, so a gap
// from two monotonic readings would hide a sleep. Two wall times 20 minutes apart give a gap of 20 minutes.
func TestSamplerKeepsWallTime(t *testing.T) {
	s := newSampler()
	now := time.Now()
	if !strings.Contains(now.String(), " m=") {
		t.Skip("this clock gives no monotonic reading, so there is nothing to strip")
	}
	s.note(now)
	s.note(time.Unix(now.Unix()+20*60, 0))
	for i, at := range s.times {
		if strings.Contains(at.String(), " m=") {
			t.Errorf("sample time %d is %s, with a monotonic reading", i, at)
		}
	}
	if gaps := s.Gaps(); len(gaps) != 1 || gaps[0] < 19*time.Minute || gaps[0] > 21*time.Minute {
		t.Errorf("Gaps() = %v, want one gap of about 20 minutes", gaps)
	}
	if err := m9SleepGapError(s.Gaps(), m9SleepGap); err == nil {
		t.Error("a gap of 20 minutes passed the sleep check")
	}
}

// m9GwSnap is the part of the gateway status that the islands run compares. Records is the JSON of the record revision of each cell.
type m9GwSnap struct {
	Epoch   uint64
	Records string
}

// m9GwChange returns the finding for a change of the gateway between base and got, or "". A change of the record revisions is a change of trust. The
// gateway raises its fence epoch by design, on a hello after an applied operation, so the epoch may grow by at most one for each of the ops operations
// that the run applied since the baseline. It may not fall.
func m9GwChange(base, got m9GwSnap, ops int) string {
	if got.Records != base.Records {
		return fmt.Sprintf("the record revisions at the gateway changed from %s to %s", base.Records, got.Records)
	}
	if got.Epoch < base.Epoch {
		return fmt.Sprintf("the fence epoch at the gateway fell from %d to %d", base.Epoch, got.Epoch)
	}
	if got.Epoch-base.Epoch > uint64(max(ops, 0)) {
		return fmt.Sprintf("the fence epoch at the gateway grew from %d to %d, more than the %d operations that the run applied", base.Epoch, got.Epoch, ops)
	}
	return ""
}

func TestM9GwChange(t *testing.T) {
	base := m9GwSnap{Epoch: 100, Records: `{"a":{"Epoch":1,"Seq":45}}`}
	for _, c := range []struct {
		name string
		got  m9GwSnap
		ops  int
		bad  bool
	}{
		{"same", base, 0, false},
		{"epoch raised once for an op", m9GwSnap{101, base.Records}, 1, false},
		{"epoch raised three times for three ops", m9GwSnap{103, base.Records}, 3, false},
		{"epoch raised with no op", m9GwSnap{101, base.Records}, 0, true},
		{"epoch raised past the ops", m9GwSnap{104, base.Records}, 3, true},
		{"epoch reset to a store time", m9GwSnap{1794952246, base.Records}, 3, true},
		{"epoch fell", m9GwSnap{99, base.Records}, 3, true},
		{"records changed", m9GwSnap{100, `{"a":{"Epoch":1,"Seq":46}}`}, 3, true},
		{"records and epoch changed", m9GwSnap{101, `{}`}, 3, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := m9GwChange(base, c.got, c.ops); (got != "") != c.bad {
				t.Fatalf("finding %q, want a finding: %v", got, c.bad)
			}
		})
	}
}
