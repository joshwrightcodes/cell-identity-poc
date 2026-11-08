// Command hostsvc creates, describes and deletes the harness clusters.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

func main() {
	slog.SetDefault(newLogger(os.Args[1:], os.Stdout))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("hostsvc failed", "error", err)
		os.Exit(1)
	}
}

// newLogger sends the progress logs of up and down to stdout. The facts command keeps stdout
// for its JSON, so its logs go to stderr.
func newLogger(args []string, stdout io.Writer) *slog.Logger {
	if len(args) > 0 && (args[0] == "up" || args[0] == "down") {
		return slog.New(slog.NewTextHandler(stdout, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hostsvc up|down [--only <name>] | facts --cluster <name>  [--topology <file>]")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	topoPath := fs.String("topology", "harness/topology.yaml", "topology file")
	only := fs.String("only", "", "act on this cluster only (up, down)")
	name := fs.String("cluster", "", "cluster name (facts)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	topo, err := topology.Load(*topoPath)
	if err != nil {
		return err
	}
	svc := hostsvc.New(hostsvc.NewKindRuntime(), topo)

	names := func() []string {
		if *only != "" {
			return []string{*only}
		}
		var out []string
		for _, c := range topo.Clusters {
			out = append(out, c.Name)
		}
		return out
	}

	switch cmd {
	case "up":
		for _, n := range names() {
			if _, err := svc.Up(ctx, n); err != nil {
				return err
			}
		}
	case "down":
		for _, n := range names() {
			if err := svc.Down(ctx, n); err != nil {
				return err
			}
		}
	case "facts":
		if *name == "" {
			return fmt.Errorf("facts needs --cluster")
		}
		f, err := svc.Facts(ctx, *name)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(f)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}
