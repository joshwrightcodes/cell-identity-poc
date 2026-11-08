// Command pkigen prints the CA certificates for a SPIFFE trust domain.
//
//	pkigen root [--trust-domain <td>] [--days 365]
//	pkigen intermediate [--trust-domain <td>] [--days 30] < root bundle
//	pkigen cert < bundle
//	pkigen key < bundle
//
// root prints a bundle for a new self-signed root CA. intermediate reads a root bundle on stdin and
// prints a bundle for a new intermediate CA that the root signs. A bundle is two PEM blocks in this
// order: "EC PRIVATE KEY" (SEC 1), then "CERTIFICATE". cert and key read a bundle on stdin and print
// only its certificate or only its key. Every key is ECDSA P-256 and every certificate has the URI SAN spiffe://<td>.
// The intermediate has no path length limit, because the SPIRE server CA sits below it.
// NotBefore is one minute before the current time. intermediate refuses a root whose URI SAN is not
// spiffe://<td> for the --trust-domain value.
//
// Keys exist only in memory and on stdout. On failure the command prints one JSON error line on
// stdout and exits 1. No error message carries key material.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"regexp"
	"time"
)

const (
	defaultTrustDomain = "dev.env.poc.internal"
	organization       = "cell-identity-poc"
	maxInput           = 1 << 20
	// backdate moves NotBefore into the past, so a peer with a slightly slow clock accepts a new certificate.
	backdate  = time.Minute
	keyBlock  = "EC PRIVATE KEY"
	certBlock = "CERTIFICATE"
)

// trustDomainRE is the SPIFFE trust domain grammar: lowercase letters, digits, dots, dashes and underscores.
var trustDomainRE = regexp.MustCompile(`^[a-z0-9._-]{1,255}$`)

func main() {
	os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, time.Now))
}

// execute runs one command. On failure it writes one compact JSON error line to stdout and returns 1.
func execute(args []string, stdin io.Reader, stdout io.Writer, now func() time.Time) int {
	var out bytes.Buffer
	if err := run(args, stdin, &out, now); err != nil {
		slog.New(slog.NewJSONHandler(stdout, nil)).Error("pkigen failed", "error", err.Error())
		return 1
	}
	if _, err := stdout.Write(out.Bytes()); err != nil {
		return 1
	}
	return 0
}

func run(args []string, stdin io.Reader, stdout io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return errors.New("usage: pkigen root|intermediate|cert|key [--trust-domain <td>] [--days <n>]")
	}
	cmd := args[0]
	defaultDays := map[string]int{"root": 365, "intermediate": 30, "cert": 0, "key": 0}
	days, known := defaultDays[cmd]
	if !known {
		return fmt.Errorf("unknown command %q", cmd)
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	td := defaultTrustDomain
	issues := cmd == "root" || cmd == "intermediate"
	if issues {
		fs.StringVar(&td, "trust-domain", defaultTrustDomain, "SPIFFE trust domain")
		fs.IntVar(&days, "days", days, "validity in days")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%s: %w", cmd, err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s: unexpected argument %q", cmd, fs.Arg(0))
	}
	if issues {
		if days < 1 {
			return errors.New("--days must be at least 1")
		}
		if !trustDomainRE.MatchString(td) {
			return fmt.Errorf("trust domain %q is not a valid SPIFFE trust domain", td)
		}
	}

	switch cmd {
	case "root":
		key, cert, err := issue(td, days, now(), nil, nil)
		if err != nil {
			return err
		}
		return writeBundle(stdout, key, cert)
	case "intermediate":
		parentKey, parent, err := readBundle(stdin)
		if err != nil {
			return err
		}
		if want := "spiffe://" + td; len(parent.URIs) != 1 || parent.URIs[0].String() != want {
			return fmt.Errorf("the root URI SAN is %v, want %s from --trust-domain", parent.URIs, want)
		}
		key, cert, err := issue(td, days, now(), parentKey, parent)
		if err != nil {
			return err
		}
		return writeBundle(stdout, key, cert)
	case "cert":
		_, cert, err := readBundle(stdin)
		if err != nil {
			return err
		}
		return pem.Encode(stdout, &pem.Block{Type: certBlock, Bytes: cert.Raw})
	default:
		key, _, err := readBundle(stdin)
		if err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return errors.New("encode private key")
		}
		return pem.Encode(stdout, &pem.Block{Type: keyBlock, Bytes: der})
	}
}

// issue creates a CA key and certificate. With a nil parent, the certificate is self-signed.
func issue(td string, days int, now time.Time, parentKey *ecdsa.PrivateKey, parent *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}
	start := now.UTC().Truncate(time.Second)
	name := td + " root CA"
	if parent != nil {
		name = td + " intermediate CA"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{organization}, CommonName: name},
		NotBefore:             start.Add(-backdate),
		NotAfter:              start.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: td}},
	}
	signer := key
	if parent == nil {
		parent = tmpl
	} else {
		if tmpl.NotAfter.After(parent.NotAfter) {
			return nil, nil, fmt.Errorf("the intermediate would outlive the root, which expires at %s", parent.NotAfter.Format(time.RFC3339))
		}
		signer = parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse new certificate: %w", err)
	}
	return key, cert, nil
}

func writeBundle(w io.Writer, key *ecdsa.PrivateKey, cert *x509.Certificate) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return errors.New("encode private key")
	}
	if err := pem.Encode(w, &pem.Block{Type: keyBlock, Bytes: der}); err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{Type: certBlock, Bytes: cert.Raw})
}

// readBundle reads exactly two PEM blocks from r: a CA key, then its certificate.
// Its errors name the block type and never include block contents.
func readBundle(r io.Reader) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(data) > maxInput {
		return nil, nil, fmt.Errorf("stdin is larger than %d bytes", maxInput)
	}
	var blocks []*pem.Block
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	switch {
	case len(blocks) == 0:
		return nil, nil, errors.New("stdin holds no PEM block, want a bundle of EC PRIVATE KEY then CERTIFICATE")
	case len(bytes.TrimSpace(rest)) != 0:
		return nil, nil, errors.New("stdin has trailing data after the PEM blocks")
	case len(blocks) != 2:
		return nil, nil, fmt.Errorf("stdin holds %d PEM blocks, want two PEM blocks: EC PRIVATE KEY then CERTIFICATE", len(blocks))
	case blocks[0].Type != keyBlock:
		return nil, nil, fmt.Errorf("first PEM block is %q, want %q", blocks[0].Type, keyBlock)
	case blocks[1].Type != certBlock:
		return nil, nil, fmt.Errorf("second PEM block is %q, want %q", blocks[1].Type, certBlock)
	}
	key, err := x509.ParseECPrivateKey(blocks[0].Bytes)
	if err != nil {
		return nil, nil, errors.New("first PEM block is not a valid EC private key")
	}
	cert, err := x509.ParseCertificate(blocks[1].Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("second PEM block is not a valid certificate: %w", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New("the private key does not match the certificate")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, nil, errors.New("the certificate is not a CA")
	}
	return key, cert, nil
}
