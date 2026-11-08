// Command recordgen prints a ConfigMap that holds a test-signed cell record and its public key.
// The signing key is random, lives in memory and is never written.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
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
	if err := run(os.Args[1:], os.Stdout, hostsvcFacts); err != nil {
		fmt.Fprintln(os.Stderr, "recordgen failed:", err)
		os.Exit(1)
	}
}

func hostsvcFacts(cluster string) (hostsvc.Facts, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("go", "run", "./cmd/hostsvc", "facts", "--cluster", cluster)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return hostsvc.Facts{}, fmt.Errorf("hostsvc facts: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	var f hostsvc.Facts
	if err := json.Unmarshal(out.Bytes(), &f); err != nil {
		return hostsvc.Facts{}, fmt.Errorf("decode facts: %w", err)
	}
	return f, nil
}

func run(args []string, w io.Writer, facts func(string) (hostsvc.Facts, error)) error {
	fs := flag.NewFlagSet("recordgen", flag.ContinueOnError)
	cluster := fs.String("cluster", "", "cluster to read facts from")
	var subs subjects
	fs.Var(&subs, "subject", "allowed subject as <namespace>/<serviceaccount>, repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cluster == "" {
		return errors.New("--cluster is required")
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
