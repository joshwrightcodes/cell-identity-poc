//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

const (
	// m9SamplesFile gets one JSON line each minute while the islands test runs. It holds no secret. gate:m9 and the operator read it after
	// a failed run.
	m9SamplesFile = "../../build/gate/m9-samples.jsonl"
	// m9SampleEvery is the time between two samples, counted from the start of one sample to the start of the next.
	m9SampleEvery = time.Minute
	// m9Clusters are the clusters that the islands test watches.
	m9Clusters = "dev-cp dev-cell-1 dev-cell-2"
)

// m9ClusterList returns the clusters that the islands test watches.
func m9ClusterList() []string { return strings.Fields(m9Clusters) }

// m9PodBrief is the pod entry of a sample line: the UID and the containers that restarted.
type m9PodBrief struct {
	UID      string         `json:"uid"`
	Restarts map[string]int `json:"restarts,omitempty"`
}

// m9WhoamiResult is what cell-proxy whoami of a tunnel pod said: the expiry of its SVID, or the error.
type m9WhoamiResult struct {
	ExpiresAt string `json:"expiresAt,omitempty"`
	Err       string `json:"err,omitempty"`
}

// m9GatewaySample is the part of the gateway status that a sample keeps.
type m9GatewaySample struct {
	Streams        map[string]int `json:"streams"`
	OutboxItems    int            `json:"outboxItems"`
	OldestOutboxAt string         `json:"oldestOutboxAt,omitempty"`
}

// m9SampleLine is one line of the samples file.
type m9SampleLine struct {
	Time    string                           `json:"time"`
	Phase   string                           `json:"phase"`
	Pods    map[string]map[string]m9PodBrief `json:"pods,omitempty"`
	Apps    map[string]map[string]string     `json:"apps,omitempty"`
	Whoami  map[string]m9WhoamiResult        `json:"whoami,omitempty"`
	Agents  map[string]map[string]string     `json:"agents,omitempty"`
	Gateway *m9GatewaySample                 `json:"gateway,omitempty"`
	QueueKB map[string]int                   `json:"collectorQueueKB,omitempty"`
	Errors  []string                         `json:"errors,omitempty"`
}

// startSampler starts a goroutine that writes one line each minute to build/gate/m9-samples.jsonl and logs a short line each minute. It
// takes the first sample at once. phase names the phase of the run for each line. The sampler records the time of each sample, and Gaps
// returns the gaps. It never fails the test: a read that fails goes into the errors of the line. The cleanup of the test stops it.
func startSampler(t *testing.T, phase func() string) *sampler {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(m9SamplesFile), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(m9SamplesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	s := newSampler()
	go func() {
		defer close(s.done)
		defer f.Close()
		next := time.Now()
		for {
			at := time.Now().Round(0)
			s.note(at)
			line := collectM9Sample(t, at, phase())
			if b, err := json.Marshal(line); err == nil {
				if _, err := f.Write(append(b, '\n')); err != nil {
					t.Logf("sampler: write %s: %v", m9SamplesFile, err)
				}
			}
			t.Logf("sample %s phase %s: gateway %s, %d read errors", at.Format("15:04:05"), line.Phase, m9GatewayBrief(line.Gateway), len(line.Errors))
			next = next.Add(m9SampleEvery)
			if next.Before(time.Now()) {
				next = time.Now()
			}
			select {
			case <-s.stop:
				return
			case <-time.After(time.Until(next)):
			}
		}
	}()
	t.Cleanup(s.Stop)
	return s
}

// Stop ends the sampler and waits for its goroutine. It is safe to call twice.
func (s *sampler) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
}

func m9GatewayBrief(g *m9GatewaySample) string {
	if g == nil {
		return "unread"
	}
	return fmt.Sprintf("%d outbox items, streams %v", g.OutboxItems, g.Streams)
}

// collectM9Sample reads one line. Each read stands alone, and a read that fails adds a text to Errors.
func collectM9Sample(t *testing.T, at time.Time, phase string) m9SampleLine {
	line := m9SampleLine{Time: at.UTC().Format(time.RFC3339), Phase: phase, Pods: map[string]map[string]m9PodBrief{}, Apps: map[string]map[string]string{},
		Whoami: map[string]m9WhoamiResult{}, Agents: map[string]map[string]string{}, QueueKB: map[string]int{}}
	fail := func(what string, err error) { line.Errors = append(line.Errors, what+": "+m9Short(err.Error())) }
	agents, agentErr := m9AgentList(t)
	if agentErr != nil {
		fail("agent list", agentErr)
	}
	for _, c := range m9ClusterList() {
		pods, err := m9ListPods(t, c)
		if err != nil {
			fail("pods of "+c, err)
		} else {
			brief := map[string]m9PodBrief{}
			for _, p := range pods {
				b := m9PodBrief{UID: p.UID}
				for name, ct := range p.Containers {
					if ct.Restarts > 0 {
						if b.Restarts == nil {
							b.Restarts = map[string]int{}
						}
						b.Restarts[name] = ct.Restarts
					}
				}
				brief[p.Namespace+"/"+p.Name] = b
			}
			line.Pods[c] = brief
			if agentErr == nil {
				exp := map[string]string{}
				for key, a := range m9AgentsByPod(agents, pods) {
					exp[key] = a.Expires.UTC().Format(time.RFC3339)
				}
				line.Agents[c] = exp
			}
		}
		if apps, err := m9ListApps(t, c); err != nil {
			fail("applications of "+c, err)
		} else {
			states := map[string]string{}
			for name, a := range apps {
				states[name] = a.Sync + "/" + a.Health
			}
			line.Apps[c] = states
		}
		if kb, err := m9QueueKB(c); err != nil {
			fail("collector queue of "+c, err)
		} else {
			line.QueueKB[c] = kb
		}
	}
	for _, c := range []string{"dev-cell-1", "dev-cell-2"} {
		line.Whoami[c] = m9Whoami(t, c)
	}
	if out, err := gwCtlErr("", "status"); err != nil {
		fail("gateway status", fmt.Errorf("%w: %s", err, out))
	} else {
		var s mgmtapi.GatewayStatus
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			fail("gateway status", err)
		} else {
			g := &m9GatewaySample{Streams: s.Streams, OutboxItems: s.OutboxItems}
			if !s.OldestOutboxAt.IsZero() {
				g.OldestOutboxAt = s.OldestOutboxAt.UTC().Format(time.RFC3339)
			}
			line.Gateway = g
		}
	}
	return line
}

// m9Short cuts a text to one line of at most 200 bytes.
func m9Short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// m9ListPods returns the pods of a cluster that the pass rule counts.
func m9ListPods(t *testing.T, cluster string) ([]m9Pod, error) {
	t.Helper()
	out, err := kubectl(t, cluster, "", "get", "pods", "-A", "-o", "json")
	if err != nil {
		return nil, err
	}
	return parseM9Pods(cluster, out)
}

// m9AgentList returns the agents that the SPIRE server of dev-cp lists.
func m9AgentList(t *testing.T) ([]m9SpireAgent, error) {
	t.Helper()
	out, err := spireServerIn(t, spireCluster, "agent", "list", "-socketPath", spireSocket, "-output", "json")
	if err != nil {
		return nil, err
	}
	return parseM9Agents(out)
}

// m9App is the state of one Argo CD Application.
type m9App struct {
	UID, Sync, Health, Revision string
}

// m9ListApps returns the Applications of a cluster by name, without the probe Applications of the M8 tests.
func m9ListApps(t *testing.T, cluster string) (map[string]m9App, error) {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "applications", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("the application list of %s is no JSON: %w", cluster, err)
	}
	apps := map[string]m9App{}
	for _, it := range list.Items {
		name := m8Field(it, "metadata", "name")
		if strings.HasPrefix(name, "m8-") {
			continue
		}
		apps[name] = m9App{UID: m8Field(it, "metadata", "uid"), Sync: m8Field(it, "status", "sync", "status"),
			Health: m8Field(it, "status", "health", "status"), Revision: m8Field(it, "status", "sync", "revision")}
	}
	return apps, nil
}

// m9Whoami runs cell-proxy whoami in the mesh-view tunnel of a cell. The tunnel keeps no liveness probe on it, so the answer is an error while
// the agent of the pod is down, and the run records it.
func m9Whoami(t *testing.T, cluster string) m9WhoamiResult {
	t.Helper()
	pod, err := kubectl(t, cluster, "", "-n", meshNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+tunnelName, "-o", "jsonpath={.items[0].metadata.name}")
	if err != nil || strings.TrimSpace(pod) == "" {
		return m9WhoamiResult{Err: m9Short(fmt.Sprintf("no tunnel pod: %v", err))}
	}
	out, err := kubectl(t, cluster, "", "-n", meshNamespace, "exec", strings.TrimSpace(pod), "-c", "cell-proxy", "--", "/ko-app/cell-proxy", "whoami")
	if err != nil {
		return m9WhoamiResult{Err: m9Short(err.Error())}
	}
	var got struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil || got.ExpiresAt == "" {
		return m9WhoamiResult{Err: m9Short(fmt.Sprintf("whoami printed %q", out))}
	}
	return m9WhoamiResult{ExpiresAt: got.ExpiresAt}
}

// m9QueueKB returns the size in KiB of the queue volume of the collector of a cluster. The collector image has no shell, so du runs in the
// node container, on the directory that the local path provisioner made for the claim queue-otel-collector-0.
func m9QueueKB(cluster string) (int, error) {
	out, err := command("", "docker", "exec", cluster+"-control-plane", "sh", "-c",
		"du -sk /var/local-path-provisioner/*_"+obsNamespace+"_queue-otel-collector-0 2>/dev/null | cut -f1 | head -1")
	if err != nil {
		return 0, err
	}
	kb, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("du printed %q", out)
	}
	return kb, nil
}

// m9OutboxItem is one item of the outbox of the gateway.
type m9OutboxItem struct {
	ID   string    `json:"id"`
	Cell string    `json:"cell"`
	Kind string    `json:"kind"`
	OpID string    `json:"opId"`
	At   time.Time `json:"at"`
}

// m9Outbox returns the items of the outbox of the gateway, oldest first.
func m9Outbox() ([]m9OutboxItem, error) {
	out, err := gwCtlErr("", "outbox")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, m9Short(out))
	}
	var res struct {
		Items []m9OutboxItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		return nil, fmt.Errorf("cellgw ctl outbox is no list: %w", err)
	}
	return res.Items, nil
}

// m9SignOp signs an operation of kind demo.append for a cell through mgmtd and records it without serving it. It returns the ID and the DSSE
// envelope. The envelope stays in memory: nothing writes it to a file or a log.
func m9SignOp(cell, line string, ttl time.Duration) (id string, envelope []byte, err error) {
	out, err := mgmtCtlErr("op", "sign", "--cell", cell, "--line", line, "--ttl", ttl.String())
	if err != nil {
		return "", nil, fmt.Errorf("mgmt -- op sign for %s: %w", cell, err)
	}
	var v opState
	if err := json.Unmarshal([]byte(out), &v); err != nil || v.ID == "" || len(v.Envelope) == 0 {
		return "", nil, fmt.Errorf("mgmt -- op sign for %s gave no operation with an envelope", cell)
	}
	return v.ID, []byte(v.Envelope), nil
}

// m9Enqueue puts a signed envelope into the queue of the gateway for a cell.
func m9Enqueue(cell string, envelope []byte) error {
	out, err := gwCtlErr(string(envelope), "enqueue", "--cell", cell)
	if err != nil {
		return fmt.Errorf("gw -- enqueue --cell %s: %w: %s", cell, err, m9Short(out))
	}
	if !strings.HasPrefix(out, "{") {
		return fmt.Errorf("gw -- enqueue --cell %s printed %q, want one JSON line", cell, m9Short(out))
	}
	return nil
}

// m9MgmtStatus returns the status that mgmtd prints, with the error of the read.
func m9MgmtStatus() (mgmt.Status, error) {
	var s mgmt.Status
	out, err := mgmtCtlErr("status")
	if err != nil {
		return s, fmt.Errorf("mgmt -- status: %w: %s", err, m9Short(out))
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return s, fmt.Errorf("mgmt -- status is no status object: %w", err)
	}
	return s, nil
}

// sortedKeys returns the keys of a map in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
