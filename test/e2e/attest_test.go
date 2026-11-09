//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	celldNamespace  = "cell-identity-system"
	celldDeployment = "celld"
	celldContainer  = "celld"
	// The brief allows two minutes from the start of a new pod to the first SVID.
	celldSVIDWait = 2 * time.Minute
	// SPIRE v1.15.5 logs this line after a successful AttestAgent call (pkg/server/api/agent/v1/service.go).
	attestDone = "Agent attestation request completed"
	newPodWait = 2 * time.Minute
)

// TestM2CelldGetsSVID replaces the celld pod in each cell. The new pod must log its X.509 SVID
// within two minutes, and the SPIRE server log must hold an agent ID with the UID of that pod.
func TestM2CelldGetsSVID(t *testing.T) {
	for _, cell := range clustersWith(t, agentCellSet) {
		t.Run(cell, func(t *testing.T) {
			t.Parallel()
			pod := replaceCelldPod(t, cell)
			waitCelldSVID(t, cell, pod)

			agentID := regexp.MustCompile(`spiffe://` + regexp.QuoteMeta(spireTD) + `/spire/agent/cluster_jwt/` +
				regexp.QuoteMeta(cell) + `/` + regexp.QuoteMeta(pod.Metadata.UID) + `/[0-9a-f]{32}`)
			waitFor(t, "SPIRE server line "+attestDone+" for an agent ID like "+agentID.String(), forwardWait, func() (bool, string) {
				logs, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "logs", spireServerPod, "-c", "spire-server", "--since=10m")
				if err != nil {
					return false, err.Error()
				}
				// A server container restart moves the earlier lines to the previous log.
				if prev, err := kubectl(t, spireCluster, "", "-n", spireNamespace, "logs", spireServerPod, "-c", "spire-server", "--previous", "--since=10m"); err == nil {
					logs = prev + logs
				}
				if id := attestedAgentID(logs, agentID); id != "" {
					t.Logf("server issued agent ID %s", id)
					return true, ""
				}
				return false, fmt.Sprintf("no %q line with a matching agent_id in %d log bytes", attestDone, len(logs))
			})
		})
	}
}

type podInfo struct {
	Metadata struct {
		Name              string  `json:"name"`
		UID               string  `json:"uid"`
		CreationTimestamp string  `json:"creationTimestamp"`
		DeletionTimestamp *string `json:"deletionTimestamp"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Name         string `json:"name"`
			ContainerID  string `json:"containerID"`
			RestartCount int    `json:"restartCount"`
			Ready        bool   `json:"ready"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

// replaceCelldPod deletes every celld pod in a cell and returns the new Running pod.
func replaceCelldPod(t *testing.T, cell string) podInfo {
	t.Helper()
	// Every live pod at this point is old. A pod that is already terminating never counts as new,
	// because celldPods skips pods with a deletion timestamp. So only a pod that the ReplicaSet
	// creates after this listing can pass the wait below.
	old := map[string]bool{}
	for _, p := range celldPods(t, cell) {
		old[p.Metadata.UID] = true
		if _, err := kubectl(t, cell, "", "-n", celldNamespace, "delete", "pod", p.Metadata.Name, "--wait=false"); err != nil {
			t.Fatal(err)
		}
	}
	var pod podInfo
	waitFor(t, "a new Running celld pod in "+cell, newPodWait, func() (bool, string) {
		var seen []string
		for _, p := range celldPods(t, cell) {
			if !old[p.Metadata.UID] && p.Status.Phase == "Running" {
				pod = p
				return true, ""
			}
			seen = append(seen, fmt.Sprintf("%s %s (old %t)", p.Metadata.Name, p.Status.Phase, old[p.Metadata.UID]))
		}
		return false, fmt.Sprintf("pods: %v", seen)
	})
	t.Logf("new celld pod %s, UID %s", pod.Metadata.Name, pod.Metadata.UID)
	return pod
}

// waitCelldSVID waits until the celld container of the pod logs its X.509 SVID.
func waitCelldSVID(t *testing.T, cell string, pod podInfo) {
	t.Helper()
	want := fmt.Sprintf("spiffe://%s/cell/%s/celld", spireTD, cell)
	waitFor(t, "celld log line with SPIFFE ID "+want, celldSVIDWait, func() (bool, string) {
		logs, err := kubectl(t, cell, "", "-n", celldNamespace, "logs", pod.Metadata.Name, "-c", celldContainer)
		if err != nil {
			return false, err.Error()
		}
		ids := celldSPIFFEIDs(logs)
		for _, id := range ids {
			if id == want {
				return true, ""
			}
		}
		return false, fmt.Sprintf("SPIFFE IDs %v in %d log bytes: %s", ids, len(logs), lastLines(logs, 5))
	})
}

// celldPods returns the celld pods that are not being deleted.
func celldPods(t *testing.T, cell string) []podInfo {
	t.Helper()
	out, err := kubectl(t, cell, "", "-n", celldNamespace, "get", "pods", "-l", "app.kubernetes.io/name="+celldDeployment, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []podInfo `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("decode pods: %v", err)
	}
	var live []podInfo
	for _, p := range list.Items {
		if p.Metadata.DeletionTimestamp == nil {
			live = append(live, p)
		}
	}
	return live
}

// attestedAgentID returns the agent_id of the first JSON log line that reports a completed
// attestation and whose agent_id matches re in full.
func attestedAgentID(logs string, re *regexp.Regexp) string {
	full := regexp.MustCompile("^" + re.String() + "$")
	for line := range strings.SplitSeq(logs, "\n") {
		var rec struct {
			Msg     string `json:"msg"`
			AgentID string `json:"agent_id"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == attestDone && full.MatchString(rec.AgentID) {
			return rec.AgentID
		}
	}
	return ""
}

// celldSPIFFEIDs returns the spiffe_id of every JSON log line that has one.
func celldSPIFFEIDs(logs string) []string {
	var ids []string
	for line := range strings.SplitSeq(logs, "\n") {
		var rec struct {
			SPIFFEID string `json:"spiffe_id"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.SPIFFEID != "" {
			ids = append(ids, rec.SPIFFEID)
		}
	}
	return ids
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
