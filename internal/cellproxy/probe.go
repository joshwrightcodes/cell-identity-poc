package cellproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Probe makes one TLS handshake with addr, with no client certificate, and returns the ID of the
// server. It accepts only the exact ID expect, chained to peer, as ClientTLS does. A refused
// server gives a *PeerError.
func Probe(ctx context.Context, addr string, peer x509bundle.Source, expect spiffeid.ID) (spiffeid.ID, error) {
	d := net.Dialer{Timeout: dialTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return spiffeid.ID{}, err
	}
	conn := tls.Client(raw, probeTLS(peer, expect))
	defer func() { _ = conn.Close() }()
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		return spiffeid.ID{}, err
	}
	if err := requireH2(conn); err != nil {
		return spiffeid.ID{}, err
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return spiffeid.ID{}, errors.New("server sent no certificate")
	}
	return x509svid.IDFromCert(certs[0])
}
