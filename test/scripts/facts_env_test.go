package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// factsRun runs scripts/facts.sh for dev-cell-1 in a temporary root with a stub kubectl and yq. The node address is NODE_IP. It returns the path of
// build/dev-cell-1/facts.env.
func factsRun(t *testing.T, root, nodeIP string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "facts.sh"))
	cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cell-1", "NODE_IP=" + nodeIP}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("facts.sh: %v\n%s", err, out)
	}
	return filepath.Join(root, "build", "dev-cell-1", "facts.env")
}

// TestFactsEnvChangesOnlyWithAFact: facts.env is an input of the render, and the publish refuses a bundle that is older than its inputs, so a run
// that reads the same facts must keep the file and its time. A changed fact replaces the file.
func TestFactsEnvChangesOnlyWithAFact(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "bash")
	root := t.TempDir()
	copyFiles(t, root, "scripts")
	copyFiles(t, root, "cells")
	copyFiles(t, root, "components/lib")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	kubectl := `#!/usr/bin/env bash
case "$*" in
  *"get configmap kubeadm-config"*) echo cluster-config ;;
  *"get nodes"*) printf '%s ' "$NODE_IP" ;;
  *"get endpointslices"*"addresses[0]"*) printf '10.0.0.1 ' ;;
  *"get endpointslices"*) echo 6443 ;;
  *"get service kubernetes"*) echo 10.96.0.1 ;;
  *"get service kube-dns"*) echo 10.96.0.10 ;;
esac
`
	yq := "#!/usr/bin/env bash\ncase \"$*\" in *clusters*) echo base-cell ;; *podSubnet*) echo 10.244.0.0/16 ;; *) echo 10.96.0.0/12 ;; esac\n"
	for name, body := range map[string]string{"kubectl": kubectl, "yq": yq} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file := factsRun(t, root, "172.18.0.3")
	first, _ := os.ReadFile(file)
	if !strings.Contains(string(first), "NODE_IPS='172.18.0.3'") {
		t.Fatalf("facts.env is %q", first)
	}
	old := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	// The same facts keep the file.
	factsRun(t, root, "172.18.0.3")
	if info, _ := os.Stat(file); !info.ModTime().Equal(old) {
		t.Errorf("a run with the same facts changed the file (mtime %s, want %s)", info.ModTime(), old)
	}
	// A changed fact replaces it.
	factsRun(t, root, "172.18.0.9")
	got, _ := os.ReadFile(file)
	info, _ := os.Stat(file)
	if !strings.Contains(string(got), "NODE_IPS='172.18.0.9'") || !info.ModTime().After(old) {
		t.Errorf("a changed fact did not replace the file: %q (mtime %s)", got, info.ModTime())
	}
	if left, _ := filepath.Glob(filepath.Join(root, "build", "dev-cell-1", ".facts.env.*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}
