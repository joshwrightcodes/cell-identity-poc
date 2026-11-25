//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// m9CutsFile lists the tag of each link cut that a test made, one tag on each line. The test writes the tag before the cut, so
	// gate:m9:repair can run partition -- heal --all after an aborted run.
	m9CutsFile = "../../build/gate/m9-cuts"
	// m9CutBound bounds one mise run partition call.
	m9CutBound = 2 * time.Minute
)

// linkCut is one cut between two kind clusters, made by scripts/partition.sh.
type linkCut struct {
	// Tag is the comment of every rule of the cut, gate-m9-cut-<8 hex>.
	Tag string
	// Node is the node container that holds the rules.
	Node string
	// Until is the time at which the hold ends, from the clock of the node.
	Until  time.Time
	healed bool
}

// cutLink cuts the traffic of from to to, in the direction both, out or in, for hold. It writes the tag to build/gate/m9-cuts first, runs
// mise run partition (the task of the operator and the helper share scripts/partition.sh), and registers the heal in t.Cleanup. The caller
// measures nothing here: how long a client takes to recover after a heal is for the caller to assert.
func cutLink(t *testing.T, from, to, direction string, hold time.Duration) *linkCut {
	t.Helper()
	minutes := int((hold + time.Minute - 1) / time.Minute)
	tag := "gate-m9-cut-" + randomHex(t, 4)
	if err := os.MkdirAll(filepath.Dir(m9CutsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(m9CutsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, werr := f.WriteString(tag + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		t.Fatalf("record the cut %s: %v", tag, werr)
	}
	c := &linkCut{Tag: tag}
	// The cleanup is registered before the cut, so a cut that fails midway is healed too.
	t.Cleanup(func() { c.Heal(t) })
	out, err := miseRun(t, m9CutBound, nil, "partition", "--", "cut", "--from", from, "--to", to, "--direction", direction, "--hold", strconv.Itoa(minutes), "--tag", tag)
	if err != nil {
		t.Fatalf("cut %s from %s (%s): %v\n%s", from, to, direction, err, out)
	}
	res := lastJSONLine(t, out)
	if res["tag"] != tag {
		t.Fatalf("partition printed %v, want one JSON line for %s", res, tag)
	}
	c.Node, _ = res["node"].(string)
	until, _ := res["until"].(string)
	c.Until, _ = time.Parse(time.RFC3339, until)
	return c
}

// Heal deletes the rules of the cut. It is safe to call twice, and the cleanup of cutLink calls it too.
func (c *linkCut) Heal(t *testing.T) {
	t.Helper()
	if c.healed {
		return
	}
	out, err := miseRun(t, m9CutBound, nil, "partition", "--", "heal", "--tag", c.Tag)
	if err != nil {
		t.Errorf("heal the cut %s: %v\n%s\nRun: mise run partition -- heal --all", c.Tag, err, out)
		return
	}
	c.healed = true
}

// nodeAddrs returns the IPv4 and the IPv6 address of <cluster>-control-plane on the network kind. v6 is empty when the node has none.
func nodeAddrs(t *testing.T, cluster string) (v4, v6 string) {
	t.Helper()
	get := func(field string) string {
		format := `{{with index .NetworkSettings.Networks "kind"}}{{.` + field + `}}{{end}}`
		out, err := exec.Command("docker", "inspect", "-f", format, cluster+"-control-plane").Output()
		if err != nil {
			t.Fatalf("docker inspect %s-control-plane: %v", cluster, err)
		}
		return strings.TrimSpace(string(out))
	}
	v4, v6 = get("IPAddress"), get("GlobalIPv6Address")
	if v4 == "" {
		t.Fatalf("%s-control-plane has no IPv4 address on the network kind", cluster)
	}
	return v4, v6
}
