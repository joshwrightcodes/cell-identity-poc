// Command cluster-jwt-agent is the SPIRE agent half of the cluster_jwt NodeAttestor.
//
// With no arguments it runs as an external SPIRE plugin. SPIRE starts it and speaks gRPC to it
// over go-plugin, and the plugin logs through the SPIRE logger. With the argument "install <dir>"
// it copies its own binary into dir, so that an init container in a distroless image can hand
// the plugin to the SPIRE agent container.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
)

const binaryName = "cluster-jwt-agent"

func main() {
	if len(os.Args) > 1 {
		os.Exit(runCLI(os.Args[1:], os.Stdout, os.Executable))
	}
	p := clusterjwt.NewAgent()
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// runCLI runs the install subcommand. On failure it writes one compact JSON error line to w.
func runCLI(args []string, w io.Writer, executable func() (string, error)) int {
	if err := cli(args, executable); err != nil {
		slog.New(slog.NewJSONHandler(w, nil)).Error(binaryName+" failed", "error", err.Error())
		return 1
	}
	return 0
}

func cli(args []string, executable func() (string, error)) error {
	if len(args) == 0 || args[0] != "install" {
		return errors.New("usage: " + binaryName + " install <dir>")
	}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("usage: %s install <dir>: %w", binaryName, err)
	}
	if fs.NArg() != 1 {
		return errors.New("usage: " + binaryName + " install <dir>")
	}
	src, err := executable()
	if err != nil {
		return fmt.Errorf("find own binary: %w", err)
	}
	return install(src, fs.Arg(0))
}

// install copies src to dir/cluster-jwt-agent with mode 0755. It writes a temporary file in dir
// and renames it, so a reader never sees a partial binary. It fails when dir is not writable.
func install(src, dir string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer in.Close()
	tmp, err := os.CreateTemp(dir, "."+binaryName+"-*")
	if err != nil {
		return fmt.Errorf("write to %s: %w", dir, err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy binary: %w", err)
	}
	if err = tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("make binary executable: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close copy: %w", err)
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, binaryName)); err != nil {
		return fmt.Errorf("place binary: %w", err)
	}
	return nil
}
