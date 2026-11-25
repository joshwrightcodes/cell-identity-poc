// Package trustmetrics reports the expiry of the CA certificates that a binary holds or trusts.
//
// The gauge trust.ca.not_after has one series for each certificate, labelled by trust domain, CA
// class, a short SHA-256 digest of the DER and the source of the certificate. One digest for each
// trust domain across all sources means that every copy of a root agrees.
package trustmetrics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Sources of a chain.
const (
	SourceSVID   = "svid"
	SourceBundle = "bundle"
)

// Classes of a CA certificate.
const (
	ClassIssuing      = "issuing"
	ClassIntermediate = "intermediate"
	ClassRoot         = "root"
)

// digestLen is the number of hex digits of the SHA-256 digest in the sha256 attribute.
const digestLen = 16

// Chain holds the certificates of one source in one trust domain. For source "svid" the first
// certificate is the leaf and the rest run from the issuer to the root.
type Chain struct {
	TrustDomain, Source string
	Certs               []*x509.Certificate
}

// Register adds the gauge trust.ca.not_after to m. Each collection calls read and reports the
// Unix time of NotAfter for each CA certificate. A source with no chain reports no series.
func Register(m metric.Meter, read func() []Chain) error {
	_, err := m.Int64ObservableGauge("trust.ca.not_after",
		metric.WithUnit("s"),
		metric.WithDescription("Unix time at which a CA certificate of a trust domain expires"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, c := range read() {
				for _, p := range points(c) {
					o.Observe(p.notAfter, metric.WithAttributes(
						attribute.String("trust_domain", c.TrustDomain),
						attribute.String("ca", p.class),
						attribute.String("sha256", p.digest),
						attribute.String("source", c.Source)))
				}
			}
			return nil
		}))
	if err != nil {
		return fmt.Errorf("create gauge: %w", err)
	}
	return nil
}

type point struct {
	class, digest string
	notAfter      int64
}

func points(c Chain) []point {
	certs := c.Certs
	if c.Source == SourceSVID && len(certs) > 0 {
		certs = certs[1:]
	}
	out := make([]point, 0, len(certs))
	for i, cert := range certs {
		sum := sha256.Sum256(cert.Raw)
		out = append(out, point{class(c.Source, i, cert), hex.EncodeToString(sum[:])[:digestLen], cert.NotAfter.Unix()})
	}
	return out
}

// class names the role of the certificate at index i of the chain without its leaf.
func class(source string, i int, cert *x509.Certificate) string {
	switch {
	case source != SourceSVID || selfSigned(cert):
		return ClassRoot
	case i == 0:
		return ClassIssuing
	default:
		return ClassIntermediate
	}
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

// FileChain reads the PEM certificates of path. It returns no chain when the file is missing,
// holds no certificate or holds a certificate that does not parse, as the binaries refuse such a
// file. A bad file never fails a metric collection.
func FileChain(trustDomain, source, path string) []Chain {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil
	}
	return []Chain{{TrustDomain: trustDomain, Source: source, Certs: certs}}
}

// SVIDChain returns the chain of an X.509 SVID, or no chain when the SVID is nil or empty.
func SVIDChain(trustDomain string, certs []*x509.Certificate) []Chain {
	if len(certs) == 0 {
		return nil
	}
	return []Chain{{TrustDomain: trustDomain, Source: SourceSVID, Certs: certs}}
}

// SourceChains returns the chain of the SVID in src and, when src also holds trust bundles, the
// bundle of the trust domain of that SVID. It returns no chain while src holds no SVID.
func SourceChains(src x509svid.Source) []Chain {
	svid, err := src.GetX509SVID()
	if err != nil || svid == nil {
		return nil
	}
	td := svid.ID.TrustDomain()
	chains := SVIDChain(td.String(), svid.Certificates)
	if bs, ok := src.(x509bundle.Source); ok {
		if b, err := bs.GetX509BundleForTrustDomain(td); err == nil && b != nil && len(b.X509Authorities()) > 0 {
			chains = append(chains, Chain{TrustDomain: td.String(), Source: SourceBundle, Certs: b.X509Authorities()})
		}
	}
	return chains
}
