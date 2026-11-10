//go:build e2e

package e2e

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

// maxClockSkew bounds the difference between the clocks of this Mac and each node. The tests
// compare Mac times with log times of the nodes.
const maxClockSkew = time.Second

// TestMain checks the clusters before any test runs. The build step of scripts/gate.sh runs no
// test, so it skips the checks.
func TestMain(m *testing.M) {
	flag.Parse()
	run := ""
	if f := flag.Lookup("test.run"); f != nil {
		run = f.Value.String()
	}
	if run != "^$" {
		if err := precheck(run); err != nil {
			fmt.Fprintf(os.Stderr, "e2e precheck failed: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func precheck(run string) error {
	topo, err := topology.Load(topologyPath)
	if err != nil {
		return fmt.Errorf("load topology: %w", err)
	}
	for _, c := range topo.Clusters {
		if err := checkClock(c.Name + "-control-plane"); err != nil {
			return err
		}
	}
	// The other checks concern the M2 and M3 tests only, so a run of the M1 tests alone skips them.
	if run == "" || strings.Contains(run, "M3") {
		if err := precheckM3(); err != nil {
			return err
		}
	}
	if run != "" && !strings.Contains(run, "M2") {
		return nil
	}
	if pocEnv == "" {
		return errors.New("cells/common.env sets no POC_ENV")
	}
	// A run that ended before its cleanups can leave the API server of dev-cell-1 with the test key,
	// and dev-cp with test bundles.
	if out, err := command("", "bash", "../../scripts/gate-m2-repair.sh", "--check"); err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	// The renewal tests need SVIDs of 1m. scripts/gate.sh checks the same before gate:m2.
	{
		conf, err := command("", "kubectl", "--context", "kind-"+spireCluster, "-n", spireNamespace, "get", "configmap", "spire-server",
			"-o", `jsonpath={.data.server\.conf}`)
		if err != nil {
			return fmt.Errorf("read the server config of %s: %w\n%s", spireCluster, err, conf)
		}
		if ttl := agentTTL(conf); ttl != "1m" {
			return fmt.Errorf("the SPIRE server in %s sets agent_ttl %q, and the renewal tests need 1m. "+
				"Set SPIRE_SVID_TTL=1m in cells/dev-cp.env, then run: CELL=dev-cp mise run cell:up", spireCluster, ttl)
		}
	}
	for _, cell := range topo.WithComponent(agentCellSet) {
		// A run that ended before its cleanup can leave probe objects in the harness namespace, where
		// cell:verify reports them. Each one carries the probe label.
		if out, err := command("", "kubectl", "--context", "kind-"+cell, "-n", celldNamespace, "delete",
			"jobs,networkpolicies,secrets", "-l", probeLabel, "--ignore-not-found", "--wait=true", "--timeout=120s"); err != nil {
			return fmt.Errorf("remove leftover probe objects in %s: %w\n%s", cell, err, out)
		} else if strings.Contains(out, "deleted") {
			fmt.Fprintf(os.Stderr, "removed leftover probe objects in %s: %s\n", cell, strings.TrimSpace(out))
		}
		if _, err := command("", "kubectl", "--context", "kind-"+cell, "-n", celldNamespace, "get", "rolebinding", tokenBinding); err != nil {
			return fmt.Errorf("%s has no RoleBinding %s, which an interrupted renewal test removes. Run: CELL=%s mise run cell:up", cell, tokenBinding, cell)
		}
	}
	return nil
}

// precheckM3 checks that the management plane has its SPIRE server, and that its link phase ran.
// The clock check above covers every cluster.
func precheckM3() error {
	if out, err := command("", "kubectl", "--context", "kind-"+mgmtCluster, "-n", spireNamespace, "get", "statefulset", "spire-server", "-o", "name"); err != nil {
		return fmt.Errorf("%s has no SPIRE server. Run: CELL=%s mise run cell:up\n%s", mgmtCluster, mgmtCluster, out)
	}
	if out, err := command("", "kubectl", "--context", "kind-"+mgmtCluster, "-n", viewNamespace, "get", "deployment", principalName, "-o", "name"); err != nil {
		return fmt.Errorf("%s has no Deployment %s, so its link phase has not run. Run: CELL=%s mise run cell:link\n%s", mgmtCluster, principalName, mgmtCluster, out)
	}
	return nil
}

// agentTTL returns the value of agent_ttl in a SPIRE server config.
func agentTTL(conf string) string {
	for line := range strings.SplitSeq(conf, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "agent_ttl = "); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// checkClock compares the clock of a node with the clock of this Mac, at the midpoint of the call.
func checkClock(node string) error {
	before := time.Now()
	out, err := command("", "docker", "exec", node, "date", "+%s.%N")
	after := time.Now()
	if err != nil {
		return fmt.Errorf("read the clock of %s: %w\n%s", node, err, out)
	}
	secs, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
	if err != nil {
		return fmt.Errorf("parse the clock of %s from %q: %w", node, out, err)
	}
	mid := before.Add(after.Sub(before) / 2)
	skew := time.Duration((secs - float64(mid.UnixNano())/1e9) * float64(time.Second))
	if math.Abs(float64(skew)) > float64(maxClockSkew) {
		return fmt.Errorf("the clock of %s differs from this Mac by %s, over %s. Sync the clock of the VM: "+
			"mise x -- colima ssh --profile poc -- sudo systemctl restart systemd-timesyncd. "+
			"If the skew stays, mise run vm:down && mise run vm:up restarts the VM, and the clusters then need mise run harness:down and mise run harness:up",
			node, skew, maxClockSkew)
	}
	return nil
}

// command runs a command with a bounded time and returns standard output and standard error.
func command(stdin, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kubectlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() != nil {
		return string(out), fmt.Errorf("%s %s: timed out after %s: %w", name, strings.Join(args, " "), kubectlTimeout, err)
	}
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}
