// Command hostsvc creates, describes and deletes the harness clusters.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		slog.Error("hostsvc failed", "error", err)
		os.Exit(1)
	}
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
