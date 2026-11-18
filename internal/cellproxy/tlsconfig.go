package cellproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// ClientTLS presents the SVID of svids and accepts only a server with the exact ID expect that
// chains to peer. Peer trust comes only from peer, never from the bundles of svids.
func ClientTLS(svids x509svid.Source, peer x509bundle.Source, expect spiffeid.ID) *tls.Config {
	return pin(tlsconfig.MTLSClientConfig(svids, peer, exactID(expect)))
}

// ProbeTLS is ClientTLS with no client certificate.
func ProbeTLS(peer x509bundle.Source, expect spiffeid.ID) *tls.Config {
	return pin(tlsconfig.TLSClientConfig(peer, exactID(expect)))
}

// ServerTLS requires a client SVID that chains to peer, matches allow, names a valid source and
// passes the registry. It logs each refused peer as "peer refused", with the reason, the remote
// address and the ID. The server issues no session tickets, so every connection runs these checks.
func ServerTLS(svids x509svid.Source, peer x509bundle.Source, allow *regexp.Regexp, reg RegistrySource, log *slog.Logger) *tls.Config {
	base := pin(tlsconfig.MTLSServerConfig(svids, peer, allowed(allow, reg)))
	// The client must still send a certificate: pin refuses an empty chain as no_client_cert.
	// RequestClientCert lets that refusal reach the verify callback, which logs it.
	base.ClientAuth = tls.RequestClientCert
	base.SessionTicketsDisabled = true
	// VerifyConnection runs on every handshake, also when a caller replaces the verify callback.
	base.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return &PeerError{Reason: NoClientCert, Err: errors.New("peer sent no certificate")}
		}
		return nil
	}
	refusals := newRefusalLog(log)
	verify := base.VerifyPeerCertificate
	cfg := base.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		remote := hello.Conn.RemoteAddr().String()
		c := base.Clone()
		c.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			err := verify(raw, chains)
			var pe *PeerError
			if errors.As(err, &pe) {
				refusals.write("peer refused", pe.Reason, remote, pe.ID, pe.Err)
			}
			return err
		}
		return c, nil
	}
	return cfg
}

// exactID is the authorizer of every client side.
func exactID(expect spiffeid.ID) tlsconfig.Authorizer {
	return func(id spiffeid.ID, _ [][]*x509.Certificate) error {
		if id != expect {
			return &PeerError{Reason: PeerNotAllowed, ID: id.String(), Err: fmt.Errorf("server ID %s is not %s", id, expect)}
		}
		return nil
	}
}

func allowed(allow *regexp.Regexp, reg RegistrySource) tlsconfig.Authorizer {
	return func(id spiffeid.ID, _ [][]*x509.Certificate) error {
		refuse := func(format string, args ...any) error {
			return &PeerError{Reason: PeerNotAllowed, ID: id.String(), Err: fmt.Errorf(format, args...)}
		}
		if !allow.MatchString(id.String()) {
			return refuse("client ID %s does not match %s", id, allow)
		}
		src, err := ParseSource(id)
		if err != nil {
			return refuse("client ID %s: %w", id, err)
		}
		if !reg.Current().Allows(src) {
			return refuse("client ID %s has no valid record", id)
		}
		return nil
	}
}

// pin limits the config to TLS 1.3 and ALPN h2. It refuses an empty chain as no_client_cert, and
// marks every other verify error that the authorizer did not raise as an untrusted peer.
func pin(cfg *tls.Config) *tls.Config {
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos = []string{"h2"}
	verify := cfg.VerifyPeerCertificate
	cfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return &PeerError{Reason: NoClientCert, Err: errors.New("peer sent no certificate")}
		}
		err := verify(raw, chains)
		if err == nil || ReasonOf(err) != "" {
			return err
		}
		return &PeerError{Reason: PeerUntrusted, ID: leafID(raw), Err: err}
	}
	return cfg
}

// leafID returns the unverified ID of the first certificate, for logs only.
func leafID(raw [][]byte) string {
	if len(raw) == 0 {
		return ""
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return ""
	}
	id, err := x509svid.IDFromCert(cert)
	if err != nil {
		return ""
	}
	return id.String()
}
