// Command dashgen writes the Grafana dashboards, the alert rules and the provider file of the PoC
// from package internal/dashboards.
//
//	dashgen --out <dir>
//	dashgen --check <dir>
//
// --out writes every file under dir and removes dashboard files that no board owns. --check
// writes nothing. It prints the path of each file under dir that differs from the generated
// output, one path on each line, and exits with status 1. Every other failure is one JSON error
// line on standard output and exit status 1. A usage error has exit status 2.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/dashboards"
)

const (
	name      = "dashgen"
	exitUsage = 2
)

func main() { os.Exit(execute(os.Args[1:], os.Stdout)) }

func execute(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "write the generated files under this directory")
	check := fs.String("check", "", "print each file under this directory that differs from the generated output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*out == "") == (*check == "") {
		cli.Fail(stdout, name, errors.New("give exactly one of --out <dir> and --check <dir>"))
		return exitUsage
	}
	if *out != "" {
		return cli.Run(stdout, name, func(io.Writer) error { return dashboards.Write(*out) })
	}
	var diff []string
	code := cli.Run(stdout, name, func(io.Writer) error {
		var err error
		diff, err = dashboards.Diff(*check)
		return err
	})
	if code != 0 {
		return code
	}
	for _, f := range diff {
		fmt.Fprintln(stdout, f)
	}
	if len(diff) > 0 {
		return 1
	}
	return 0
}
