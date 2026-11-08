// Package install implements the "install <dir>" subcommand of the plugin binaries. The command
// copies the running binary into a directory, so that an init container in a distroless image can
// hand the plugin to the SPIRE container.
package install

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// Run runs the install subcommand for the binary called name. On failure it writes one compact
// JSON error line to w and returns 1.
func Run(name string, args []string, w io.Writer, executable func() (string, error)) int {
	if err := run(name, args, executable); err != nil {
		slog.New(slog.NewJSONHandler(w, nil)).Error(name+" failed", "error", err.Error())
		return 1
	}
	return 0
}

func run(name string, args []string, executable func() (string, error)) error {
	usage := "usage: " + name + " install <dir>"
	if len(args) == 0 || args[0] != "install" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%s: %w", usage, err)
	}
	if fs.NArg() != 1 {
		return errors.New(usage)
	}
	src, err := executable()
	if err != nil {
		return fmt.Errorf("find own binary: %w", err)
	}
	return install(name, src, fs.Arg(0))
}

// install copies src to dir/name with mode 0555. It writes a temporary file in dir and renames it,
// so a reader never sees a partial binary. It fails when dir is not writable.
func install(name, src, dir string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer in.Close()
	tmp, err := os.CreateTemp(dir, "."+name+"-*")
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
	if err = tmp.Chmod(0o555); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("make binary executable: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close copy: %w", err)
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("place binary: %w", err)
	}
	return nil
}
