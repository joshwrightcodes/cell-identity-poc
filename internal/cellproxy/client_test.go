package cellproxy

import (
	"crypto/tls"
	"net"
	"regexp"
	"slices"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func spiffeIDOf(s string) spiffeid.ID { return spiffeid.RequireFromString(s) }

// handshake dials addr with cfg and returns the handshake error.
func handshake(t *testing.T, addr string, cfg *tls.Config) error {
	t.Helper()
	c := tls.Client(dialTCP(t, addr), cfg)
	defer func() { _ = c.Close() }()
	return c.HandshakeContext(t.Context())
}

func TestClientRefusesWrongServerID(t *testing.T) {
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	cfg := ClientTLS(source(env.svid(t, agentID1)), mgmt.bundle(), spiffeIDOf(principalID))
	cases := []struct {
		name string
		addr string
		want Reason
	}{
		{"other management ID", serveTLS(t, mgmt.svid(t, "spiffe://mgmt.poc.internal/telemetry")), PeerNotAllowed},
		{"environment CA", serveTLS(t, env.svid(t, agentID2)), PeerUntrusted},
		{"principal", serveTLS(t, mgmt.svid(t, principalID)), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := handshake(t, c.addr, cfg)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if got := ReasonOf(err); got != c.want {
				t.Fatalf("got reason %q (%v), want %q", got, err, c.want)
			}
		})
	}
}

func TestClientTrustsOnlyPeerBundleFile(t *testing.T) {
	mgmt, env, attacker := newCA(t, mgmtTD), newCA(t, envTD), newCA(t, mgmtTD)
	peer, err := x509bundle.Load(mgmt.td, mgmt.bundleFile(t))
	if err != nil {
		t.Fatal(err)
	}
	// The SVID source also holds a bundle for the management trust domain, with the attacker root.
	own := source(env.svid(t, agentID1), env.bundle(), attacker.bundle())
	addr := serveTLS(t, attacker.svid(t, principalID))
	if got := ReasonOf(handshake(t, addr, ClientTLS(own, peer, spiffeIDOf(principalID)))); got != PeerUntrusted {
		t.Fatalf("got reason %q, want %q", got, PeerUntrusted)
	}
	if err := handshake(t, serveTLS(t, mgmt.svid(t, principalID)), ClientTLS(own, peer, spiffeIDOf(principalID))); err != nil {
		t.Fatalf("the real principal fails: %v", err)
	}
}

func TestTLSConfigPinsVersionAndALPN(t *testing.T) {
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	client := ClientTLS(source(env.svid(t, agentID1)), mgmt.bundle(), spiffeIDOf(principalID))
	server := ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(viewPattern), testRegistry(t), jsonLog(&syncBuffer{}))
	for name, cfg := range map[string]*tls.Config{"client": client, "server": server} {
		if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
			t.Errorf("%s versions %x to %x, want TLS 1.3 only", name, cfg.MinVersion, cfg.MaxVersion)
		}
		if !slices.Equal(cfg.NextProtos, []string{"h2"}) {
			t.Errorf("%s NextProtos %v, want [h2]", name, cfg.NextProtos)
		}
	}
	if server.ClientAuth == tls.NoClientCert || server.VerifyPeerCertificate == nil || server.GetConfigForClient == nil {
		t.Errorf("server ClientAuth %v, want a client certificate that the config verifies", server.ClientAuth)
	}
	if !server.SessionTicketsDisabled {
		t.Error("the server issues session tickets, so a resumed handshake would skip the checks")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }(c)
		}
	}()
	old := &tls.Config{
		// The test checks the version only, and an SVID has no DNS name to verify.
		Certificates: []tls.Certificate{tlsCert(env.svid(t, agentID1))}, InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2"},
	}
	if err := handshake(t, ln.Addr().String(), old); err == nil {
		t.Fatal("a TLS 1.2 client completed the handshake")
	}
	if err := handshake(t, ln.Addr().String(), client); err != nil {
		t.Fatalf("a TLS 1.3 client fails: %v", err)
	}
}
