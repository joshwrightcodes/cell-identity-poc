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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := execute(ctx, os.Args[1:], os.Stdout)
	stop()
	os.Exit(code)
}

// execute runs one command and returns the exit code. Every log line is compact JSON on stdout.
// A failure is one JSON error line on stdout, so the facts command prints only data on success.
func execute(ctx context.Context, args []string, stdout io.Writer) int {
	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	slog.SetDefault(logger)
	if err := run(ctx, args, stdout); err != nil {
		logger.Error("hostsvc failed", "error", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
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
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(f)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}
