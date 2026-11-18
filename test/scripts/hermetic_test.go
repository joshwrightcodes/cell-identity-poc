package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// realPATH is PATH before the canaries. realTool uses it.
var realPATH = os.Getenv("PATH")

// canaryCommands are the commands that reach a cluster, the VM or the tools of the harness. A script test must never run the real one.
var canaryCommands = []string{"kind", "docker", "colima", "ssh", "limactl", "kubectl", "mise"}

// TestMain puts a canary for each command of canaryCommands at the front of PATH for every test of this package. A test puts its own stubs
// before that PATH, so a stub wins. A command with no stub reaches the canary, which prints the command, its arguments and the name of this file, and
// exits with status 1. A test that needs the command adds a stub. No test of this package may run a real cluster command.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "script-canaries-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, name := range canaryCommands {
		body := fmt.Sprintf("#!/bin/sh\necho \"canary: a test ran the real command '%s $*'. Add a stub for %s to the test (see hermetic_test.go)\" >&2\nexit 1\n", name, name)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	// Every other tool that a test needs (go, jq, yq, bash) still resolves from the rest of PATH.
	os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// withLive returns the stubs with the kind and docker stubs of liveStubs added. A script that calls live_cells needs both.
func withLive(stubs map[string]string) map[string]string {
	out := map[string]string{}
	for name, body := range liveStubs {
		out[name] = body
	}
	for name, body := range stubs {
		out[name] = body
	}
	return out
}

// pkiMise stands in for mise in a test whose script runs only `mise run pki -- ...`. The task is the local program cmd/pkigen, which reads
// PEM text and touches no cluster. The script runs it from the root of the repository.
const pkiMise = `#!/usr/bin/env bash
[[ "$1 $2 $3" == "run pki --" ]] || { echo "unexpected mise call: $*" >&2; exit 2; }
shift 3
GOFLAGS=-mod=readonly exec go run ./cmd/pkigen "$@"
`

// useRealTool links the real program name into dir, for a test that runs it against a fake local API server or a file, never against a
// cluster of this Mac. The test must also point the program at its own fake, for example through KUBECONFIG and HOME.
func useRealTool(t *testing.T, dir, name string) {
	t.Helper()
	old := os.Getenv("PATH")
	os.Setenv("PATH", realPATH)
	path, err := exec.LookPath(name)
	os.Setenv("PATH", old)
	if err != nil {
		t.Skipf("%s is not installed: %v", name, err)
	}
	if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}
