// Command recordgen prints a ConfigMap that holds a test-signed cell record and its public key.
// The signing key is random, lives in memory and is never written.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

const envName = "dev"

type subjects []record.Subject

func (s *subjects) String() string { return fmt.Sprint([]record.Subject(*s)) }

func (s *subjects) Set(v string) error {
	ns, sa, ok := strings.Cut(v, "/")
	if !ok || ns == "" || sa == "" || strings.Contains(sa, "/") {
		return fmt.Errorf("subject %q must be <namespace>/<serviceaccount>", v)
	}
	*s = append(*s, record.Subject{Namespace: ns, ServiceAccount: sa})
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, nil); err != nil {
		fmt.Fprintln(os.Stderr, "recordgen failed:", err)
		os.Exit(1)
	}
}

func hostsvcFacts(topologyPath string) func(string) (hostsvc.Facts, error) {
	return func(cluster string) (hostsvc.Facts, error) {
		topo, err := topology.Load(topologyPath)
		if err != nil {
			return hostsvc.Facts{}, fmt.Errorf("load topology: %w", err)
		}
		return hostsvc.New(hostsvc.NewKindRuntime(), topo).Facts(context.Background(), cluster)
	}
}

func run(args []string, w io.Writer, facts func(string) (hostsvc.Facts, error)) error {
	fs := flag.NewFlagSet("recordgen", flag.ContinueOnError)
	cluster := fs.String("cluster", "", "cluster to read facts from")
	topologyPath := fs.String("topology", "harness/topology.yaml", "topology file")
	var subs subjects
	fs.Var(&subs, "subject", "allowed subject as <namespace>/<serviceaccount>, repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cluster == "" {
		return errors.New("--cluster is required")
	}
	if facts == nil {
		facts = hostsvcFacts(*topologyPath)
	}
	f, err := facts(*cluster)
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	env, err := record.Sign(record.Cell{
		Name: f.Name, Env: envName, Issuer: f.Issuer, JWKS: f.JWKS,
		Subjects: subs, Epoch: 1, Counter: 1,
	}, priv)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, `apiVersion: v1
kind: ConfigMap
metadata:
  name: cell-record-%s
data:
  record.dsse.json: %q
  signer.pub: %q
`, f.Name, env, base64.StdEncoding.EncodeToString(pub))
	return err
}
