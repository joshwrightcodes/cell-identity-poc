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
	if f := flag.Lookup("test.run"); f == nil || f.Value.String() != "^$" {
		if err := precheck(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e precheck failed: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func precheck() error {
	topo, err := topology.Load(topologyPath)
	if err != nil {
		return fmt.Errorf("load topology: %w", err)
	}
	for _, c := range topo.Clusters {
		if err := checkClock(c.Name + "-control-plane"); err != nil {
			return err
		}
	}
	// A run that ended before its cleanups can leave the API server of dev-cell-1 with the test key,
	// and dev-cp with test bundles.
	if out, err := command("", "bash", "../../scripts/gate-m2-repair.sh", "--check"); err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
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
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	if ctx.Err() != nil {
		return string(out), errors.New(name + " timed out")
	}
	return string(out), nil
}
